//! The tray: an icon for a window that is still there.
//!
//! One crate covers the three desktops (`tray-icon`), with one menu and one event queue, so
//! there is no per-platform module here and nothing to drift. On Linux the crate's `ksni`
//! feature is what is compiled: a StatusNotifierItem over the session bus, with no GTK3 and
//! no `libappindicator` (§8). On Windows and macOS it is the platform's own status area.
//!
//! The tray is a second door to four things, and every one of them is a control the window
//! already has: open, scan now, pause the schedule, quit. It never gets a fifth.
//!
//! A tray is optional. Where the desktop has no status area — a bare session, a container,
//! a Linux machine with no StatusNotifier host — the application runs without one and says
//! so in Settings rather than pretending an icon is somewhere.

use std::sync::{Arc, Mutex};

use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

/// The mark the tray shows: the bare crystal, white linework, ember inlay.
///
/// The same bytes the window icon uses. A tile would be a black square in a tray, which is
/// the one place a 16-pixel silhouette matters most.
pub const ICON: &[u8] = include_bytes!("../../../assets/logo/vn-ranger-white.rgba");

/// The icon is square and this many pixels on a side.
pub const ICON_SIZE: u32 = 64;

/// What a person asked for from the tray.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// Raise the window.
    Open,
    /// Start a scan now, if one is not already running.
    ScanNow,
    /// Postpone the next scheduled scan by an hour, or end a postponement.
    Pause,
    /// Close the application.
    Quit,
}

impl Command {
    /// The menu, in the order it is drawn.
    ///
    /// One list, built once and mapped back from the ids the menu returns, so the order and
    /// the meaning cannot disagree.
    pub const ALL: [Command; 4] = [Command::Open, Command::ScanNow, Command::Pause, Command::Quit];

    /// What the menu says for this command.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Open => "Open vn-ranger",
            Self::ScanNow => "Scan now",
            Self::Pause => "Pause for an hour",
            Self::Quit => "Quit",
        }
    }

    /// What the pause item says once the schedule is already postponed.
    #[must_use]
    pub fn paused_label(self) -> &'static str {
        match self {
            Self::Pause => "Resume scheduled scans",
            other => other.label(),
        }
    }
}

/// A tray that is on screen, and the queue of what has been clicked.
pub struct Tray {
    /// Held for as long as the icon should exist: dropping it removes the icon.
    _icon: TrayIcon,
    /// The pause item, kept so its label can follow the scheduler.
    pause_item: Option<MenuItem>,
    /// What the menu has reported since the last poll.
    queue: Arc<Mutex<Vec<Command>>>,
}

impl std::fmt::Debug for Tray {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Tray").finish_non_exhaustive()
    }
}

impl Tray {
    /// Put the icon in the status area, or say why it could not be.
    ///
    /// `wake` is called on every click, and is how the interface is asked to draw a frame:
    /// an egui window that nobody is touching is otherwise asleep. The tray keeps no
    /// knowledge of egui, which is why this is a callback rather than a context.
    pub fn start(rgba: Vec<u8>, size: u32, wake: impl Fn() + Send + Sync + 'static) -> Result<Self, String> {
        let menu = Menu::new();
        let mut ids = Vec::with_capacity(Command::ALL.len());
        let mut pause_item = None;
        for command in Command::ALL {
            let item = MenuItem::new(command.label(), true, None);
            ids.push((item.id().clone(), command));
            if command == Command::Pause {
                pause_item = Some(item.clone());
            }
            menu.append(&item)
                .map_err(|error| format!("the tray menu was refused: {error}"))?;
        }

        let queue: Arc<Mutex<Vec<Command>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&queue);
        let mapping = ids.clone();
        // Set before the icon is built, so a click cannot arrive before there is a queue to
        // put it in. The handler replaces the channel: this is the only listener there is.
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            if let Some((_, command)) = mapping.iter().find(|(id, _)| *id == event.id)
                && let Ok(mut queue) = sink.lock()
            {
                queue.push(*command);
            }
            wake();
        }));

        let icon = Icon::from_rgba(rgba, size, size)
            .map_err(|error| format!("the tray icon was refused: {error}"))?;
        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            // The menu is the whole interface, so a left click is the menu rather than a
            // second, undocumented way to open the window.
            .with_menu_on_left_click(true)
            .with_tooltip("vn-ranger · a quiet ranger for your machine")
            .with_icon(icon)
            .build()
            .map_err(|error| format!("the tray icon could not be created: {error}"))?;

        Ok(Self {
            _icon: icon,
            pause_item,
            queue,
        })
    }

    /// Everything clicked since the last call.
    #[must_use]
    pub fn poll(&self) -> Vec<Command> {
        let Ok(mut queue) = self.queue.lock() else {
            return Vec::new();
        };
        std::mem::take(&mut *queue)
    }

    /// Say whether the schedule is postponed, so the pause item reads as what it will do.
    pub fn set_paused(&self, paused: bool) {
        if let Some(item) = &self.pause_item {
            item.set_text(Command::Pause.paused_label_or(paused));
        }
    }
}

impl Command {
    /// The pause item's text, given the schedule.
    fn paused_label_or(self, paused: bool) -> &'static str {
        if paused { self.paused_label() } else { self.label() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_menu_is_the_four_things_the_window_can_also_do() {
        assert_eq!(Command::ALL.len(), 4);
        let labels: Vec<&str> = Command::ALL.iter().map(|command| command.label()).collect();
        assert_eq!(
            labels,
            vec!["Open vn-ranger", "Scan now", "Pause for an hour", "Quit"]
        );
    }

    #[test]
    fn the_pause_item_says_which_way_it_will_go() {
        assert_eq!(Command::Pause.label(), "Pause for an hour");
        assert_eq!(Command::Pause.paused_label(), "Resume scheduled scans");
        assert_eq!(Command::Pause.paused_label_or(true), "Resume scheduled scans");
        assert_eq!(Command::Pause.paused_label_or(false), "Pause for an hour");
        assert_eq!(
            Command::ScanNow.paused_label(),
            "Scan now",
            "only the pause item changes with the schedule"
        );
    }

    #[test]
    fn the_icon_is_a_square_of_unmultiplied_rgba() {
        let expected = (ICON_SIZE * ICON_SIZE * 4) as usize;
        assert_eq!(ICON.len(), expected, "egui and tray-icon take the same shape");
        // The corner is transparent and the spine is white: this is the bare mark, not the
        // application tile, which would be ink at the edge.
        assert_eq!(&ICON[3..4], &[0_u8]);
        let middle = ((ICON_SIZE * ICON_SIZE / 2 + ICON_SIZE / 2) * 4) as usize;
        assert_eq!(&ICON[middle..middle + 3], &[255, 255, 255]);
    }
}
