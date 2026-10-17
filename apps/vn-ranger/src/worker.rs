//! The background scan and the one-shot elevated scan.
//!
//! A scan can take seconds, so it never runs on the thread that draws the window. The
//! elevated copy is deliberately a separate short-lived process: the window that asked
//! for it stays unelevated, and the privileged code path ends when the report is
//! written.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use vnr_core::watch::{Debounce, FileTouch};
use vnr_core::{Change, ChangeKind, EventKind, ProcessFact, Snapshot, TimelineEvent};

/// How often the process table is polled.
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How long a path must stay quiet before it is hashed.
pub const DEBOUNCE_QUIET: Duration = Duration::from_millis(500);

/// How often the watcher thread looks at its clock and its channels.
const TICK: Duration = Duration::from_millis(100);

/// One message from a worker to the window.
pub enum ScanMessage {
    /// The current step, for the status line.
    Progress(&'static str),
    /// A finished snapshot.
    Done(Box<Snapshot>),
    /// A failure a person can act on.
    Failed(String),
    /// The person stopped the scan between collectors.
    Cancelled,
}

/// Run an ordinary scan on a background thread.
pub fn spawn_scan(ctx: egui::Context, cancelled: Arc<AtomicBool>) -> Receiver<ScanMessage> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let snapshot = vnr_native::scan(
            &|progress| {
                if let vnr_native::ScanProgress::Started(label) = progress {
                    send(&sender, ScanMessage::Progress(label));
                    ctx.request_repaint();
                }
            },
            &|| cancelled.load(Ordering::Relaxed),
        );
        match snapshot {
            Some(snapshot) => send(&sender, ScanMessage::Done(Box::new(snapshot))),
            None => send(&sender, ScanMessage::Cancelled),
        }
        ctx.request_repaint();
    });
    receiver
}

/// Ask the operating system to run the elevated copy, wait for it, then read its
/// report. The caller has already shown the consent screen; this function only asks
/// the platform.
pub fn spawn_elevated_scan(ctx: egui::Context) -> Receiver<ScanMessage> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let output = vnr_native::paths::data_dir().join("elevated-scan.json");
        send(&sender, ScanMessage::Progress("Waiting for Windows consent"));
        ctx.request_repaint();
        match vnr_native::elevation::run_elevated_scan(&output) {
            Ok(()) => match std::fs::read_to_string(&output)
                .ok()
                .and_then(|text| serde_json::from_str::<Snapshot>(&text).ok())
            {
                Some(snapshot) => send(&sender, ScanMessage::Done(Box::new(snapshot))),
                None => send(
                    &sender,
                    ScanMessage::Failed(
                        "The administrator scan finished, but its report could not be read.".to_owned(),
                    ),
                ),
            },
            Err(error) => send(&sender, ScanMessage::Failed(error)),
        }
        ctx.request_repaint();
    });
    receiver
}

fn send(sender: &Sender<ScanMessage>, message: ScanMessage) {
    // A closed receiver means the window is gone; dropping the message is the
    // correct outcome, not an error to report.
    let _ = sender.send(message);
}

/// One message from the watcher to the window.
pub enum WatchMessage {
    /// The newest process poll. `reason` is set when the table could not be read.
    Processes {
        /// Every process this account could see.
        items: Vec<ProcessFact>,
        /// Why the poll is incomplete, when it is.
        reason: Option<String>,
        /// Seconds since the Unix epoch when the poll finished.
        at_unix: u64,
    },
    /// Things that changed since the previous message.
    Events(Vec<TimelineEvent>),
    /// The folders being watched; both lists are empty when the watcher is off.
    Watching {
        /// The folders the operating system accepted.
        roots: Vec<String>,
        /// The folders it refused, with a reason.
        skipped: Vec<String>,
    },
    /// The watcher could not start on this platform or in this account.
    WatchFailed(String),
}

/// The process poll and the file watcher, running on one background thread.
///
/// The thread never touches the interface directly: it sends messages and asks for a
/// repaint. Dropping the service stops the thread and the watcher with it.
pub struct WatchService {
    receiver: Receiver<WatchMessage>,
    stop: Arc<AtomicBool>,
    poll: Arc<AtomicBool>,
    watch: Arc<AtomicBool>,
    stopped: AtomicBool,
    thread: Option<thread::JoinHandle<()>>,
}

impl WatchService {
    /// Start the poll and the watcher, both enabled.
    #[must_use]
    pub fn start(ctx: egui::Context) -> Self {
        let (sender, receiver) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let poll = Arc::new(AtomicBool::new(true));
        let watch = Arc::new(AtomicBool::new(true));
        let thread = {
            let stop = Arc::clone(&stop);
            let poll = Arc::clone(&poll);
            let watch = Arc::clone(&watch);
            thread::spawn(move || run(&sender, &ctx, &stop, &poll, &watch))
        };
        Self {
            receiver,
            stop,
            poll,
            watch,
            stopped: AtomicBool::new(false),
            thread: Some(thread),
        }
    }

    /// Turn the process poll on or off.
    pub fn set_poll(&self, enabled: bool) {
        self.poll.store(enabled, Ordering::Relaxed);
    }

    /// Turn the file watcher on or off.
    pub fn set_watch(&self, enabled: bool) {
        self.watch.store(enabled, Ordering::Relaxed);
    }

    /// Take the next message, if there is one.
    ///
    /// A closed channel is reported once rather than dropped: a watcher thread that died
    /// must not look like a machine where nothing is happening.
    #[must_use]
    pub fn try_recv(&self) -> Option<WatchMessage> {
        match self.receiver.try_recv() {
            Ok(message) => Some(message),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                if self.stopped.swap(true, Ordering::Relaxed) {
                    None
                } else {
                    Some(WatchMessage::WatchFailed(
                        "The background watcher stopped unexpectedly. The window still shows the last poll; reopen ranger to start it again."
                            .to_owned(),
                    ))
                }
            }
        }
    }
}

impl Drop for WatchService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            // The thread wakes at least every TICK, so the join is short unless a file
            // hash is in progress; a bounded wait is better than a leaked watcher.
            let _ = thread.join();
        }
    }
}

fn run(
    sender: &Sender<WatchMessage>,
    ctx: &egui::Context,
    stop: &AtomicBool,
    poll_on: &AtomicBool,
    watch_on: &AtomicBool,
) {
    let mut poller = vnr_native::collect::processes::Poller::new();
    let (signatures, _) = vnr_native::signatures::load();
    let mut hasher = vnr_native::hash::Hasher::new(false, false);
    let (raw_sender, raw_receiver) = mpsc::channel::<vnr_native::watch::WatchEvent>();
    let mut debounce = Debounce::new(u64::try_from(DEBOUNCE_QUIET.as_millis()).unwrap_or(u64::MAX));
    let mut watcher: Option<vnr_native::watch::WatchHandle> = None;
    let mut watch_failed = false;
    let mut previous: Option<Vec<ProcessFact>> = None;
    let started = Instant::now();
    let mut next_poll = started;

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }

        if watch_on.load(Ordering::Relaxed) {
            if watcher.is_none() && !watch_failed {
                let mut roots = vnr_native::paths::watch_roots();
                for extra in vnr_native::store::load_watch_roots() {
                    let path = std::path::PathBuf::from(extra);
                    if path.is_dir() && !roots.contains(&path) {
                        roots.push(path);
                    }
                }
                match vnr_native::watch::start(&roots, raw_sender.clone()) {
                    Ok(started) => {
                        let roots: Vec<String> = started
                            .watching
                            .iter()
                            .map(|path| path.display().to_string())
                            .collect();
                        let skipped: Vec<String> = started
                            .skipped
                            .iter()
                            .map(|(path, reason)| format!("{}: {reason}", path.display()))
                            .collect();
                        watcher = Some(started.handle);
                        log::info!(
                            "file watcher started on {} folder(s), {} skipped",
                            roots.len(),
                            skipped.len()
                        );
                        send_watch(sender, WatchMessage::Watching { roots, skipped });
                    }
                    Err(reason) => {
                        watch_failed = true;
                        send_watch(sender, WatchMessage::WatchFailed(reason));
                    }
                }
                ctx.request_repaint();
            }
        } else {
            watch_failed = false;
            if watcher.take().is_some() {
                debounce.clear();
                send_watch(
                    sender,
                    WatchMessage::Watching {
                        roots: Vec::new(),
                        skipped: Vec::new(),
                    },
                );
                ctx.request_repaint();
            }
        }

        if poll_on.load(Ordering::Relaxed) && Instant::now() >= next_poll {
            let now = now_unix();
            let (items, reason) = match poller.poll() {
                vnr_native::collect::Outcome::Items(items) => (items, None),
                vnr_native::collect::Outcome::Partial { items, reason } => (items, Some(reason)),
                vnr_native::collect::Outcome::Unavailable { reason } => (Vec::new(), Some(reason)),
            };
            let readable = !items.is_empty();
            let polled = items.len();
            let mut events = Vec::new();
            if readable {
                if let Some(previous_items) = previous.as_ref() {
                    events.extend(
                        vnr_core::diff_processes(previous_items, &items)
                            .iter()
                            .map(|change| event_from(change, now, &mut hasher, &signatures)),
                    );
                }
                previous = Some(items.clone());
            }
            // An empty table is not evidence that every process ended, so it neither
            // produces events nor replaces the list the next poll is compared against.
            log::debug!("polled {polled} process(es)");
            send_watch(
                sender,
                WatchMessage::Processes {
                    items,
                    reason,
                    at_unix: now,
                },
            );
            if !events.is_empty() {
                log::debug!(
                    "process poll produced {} change(s) at {} process(es)",
                    events.len(),
                    polled
                );
                send_watch(sender, WatchMessage::Events(events));
            }
            next_poll = Instant::now() + POLL_INTERVAL;
            ctx.request_repaint();
        } else if !poll_on.load(Ordering::Relaxed) {
            previous = None;
        }

        let now_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        while let Ok(event) = raw_receiver.try_recv() {
            debounce.note(event.path.to_string_lossy().into_owned(), now_ms, event.touch);
        }
        let events: Vec<TimelineEvent> = debounce
            .ready(now_ms)
            .into_iter()
            .filter_map(|(path, touch)| file_event(&path, touch, now_unix()))
            .collect();
        if !events.is_empty() {
            log::debug!("watched files produced {} event(s)", events.len());
            send_watch(sender, WatchMessage::Events(events));
            ctx.request_repaint();
        }

        thread::sleep(TICK);
    }
}

fn send_watch(sender: &Sender<WatchMessage>, message: WatchMessage) {
    let _ = sender.send(message);
}

fn event_from(
    change: &Change,
    at_unix: u64,
    hasher: &mut vnr_native::hash::Hasher,
    signatures: &vnr_core::SignatureSet,
) -> TimelineEvent {
    let kind = match change.kind {
        ChangeKind::New => EventKind::ProcessStarted,
        ChangeKind::Gone => EventKind::ProcessStopped,
        ChangeKind::Changed => EventKind::ProcessChanged,
    };
    let mut detail = change.detail.clone();
    // A new process's binary is hashed and matched against the local database, so the
    // event says what the file is rather than only what it is called. The cap and the
    // per-path cache are what keep this off the critical path.
    if kind == EventKind::ProcessStarted
        && let Some(path) = change.path.as_deref()
    {
        match hasher.digest(Path::new(path)) {
            Some(digests) => {
                detail.push_str(&format!(" · sha256 {}", digests.sha256));
                if let Some(signature) = signatures.lookup(&digests.sha256).and_then(|found| found.first()) {
                    detail.push_str(&format!(" · matches {}", signature.name));
                }
            }
            None => detail.push_str(" · not hashed: over the 64 MB cap or unreadable"),
        }
    }
    TimelineEvent::new(
        at_unix,
        kind,
        change.subject.clone(),
        detail,
        change.source.clone(),
    )
}

fn file_event(path: &str, touch: FileTouch, at_unix: u64) -> Option<TimelineEvent> {
    let path = Path::new(path);
    // A path renamed away between the event and this check is no longer a file to
    // describe; saying "unreadable" about a file that is gone would be noise.
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let kind = match touch {
        FileTouch::Appeared => EventKind::FileAppeared,
        FileTouch::Changed => EventKind::FileChanged,
    };
    let detail = match vnr_native::hash::digest_file(path, false, false) {
        Some(digests) => format!("{} bytes · sha256 {}", digests.size, digests.sha256),
        None if metadata.len() > vnr_native::hash::MAX_HASH_BYTES => {
            format!("{} bytes · not hashed: above the 64 MB cap", metadata.len())
        }
        None => format!("{} bytes · not hashed: unreadable", metadata.len()),
    };
    Some(TimelineEvent::new(
        at_unix,
        kind,
        path.display().to_string(),
        detail,
        "watch",
    ))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
