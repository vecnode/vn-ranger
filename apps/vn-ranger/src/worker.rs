//! The background scan and the one-shot elevated scan.
//!
//! A scan can take seconds, so it never runs on the thread that draws the window. The
//! elevated copy is deliberately a separate short-lived process: the window that asked
//! for it stays unelevated, and the privileged code path ends when the report is
//! written.

use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use vnr_core::Snapshot;

/// One message from a worker to the window.
pub enum ScanMessage {
    /// The current step, for the status line.
    Progress(&'static str),
    /// A finished snapshot.
    Done(Box<Snapshot>),
    /// A failure a person can act on.
    Failed(String),
}

/// Run an ordinary scan on a background thread.
pub fn spawn_scan(ctx: egui::Context) -> Receiver<ScanMessage> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let snapshot = vnr_native::scan(&|progress| {
            if let vnr_native::ScanProgress::Started(label) = progress {
                send(&sender, ScanMessage::Progress(label));
                ctx.request_repaint();
            }
        });
        send(&sender, ScanMessage::Done(Box::new(snapshot)));
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
