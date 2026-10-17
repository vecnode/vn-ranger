//! vn-ranger â€” a quiet, local-only system ranger.
//!
//! The binary opens one window and owns the world the interface draws. It also has a
//! headless mode, used twice: by the person from a terminal, and by the short-lived
//! elevated copy that writes one snapshot and exits.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![allow(unreachable_pub)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod worker;

use std::path::{Path, PathBuf};

/// The window's starting size.
const STARTING_SIZE: [f32; 2] = [1180.0, 780.0];

/// The smallest the window may be made before the layout stops reflowing.
const MINIMUM_SIZE: [f32; 2] = [920.0, 600.0];

/// The application's mark for the window: the crystal on the suite's ink tile.
///
/// The tile, not the bare mark. It is what the interface draws beside the name and what
/// Windows and macOS show in a title bar, and its ink fill is what keeps a white crystal
/// readable on a light title bar as well as a dark one (`assets/logo/BRAND.md`).
const ICON: &[u8] = include_bytes!("../../../assets/logo/vn-ranger-app.rgba");

/// The icon is square and this many pixels on a side.
const ICON_SIZE: u32 = 64;

fn main() -> eframe::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    // The elevated copy is one operation: it scans and writes one snapshot. It does not
    // touch the journal, because a privileged process writing to the user's data
    // directory is exactly the kind of standing privilege Â§6.9 refuses.
    if let Some(path) = arg_value("--elevated-scan") {
        write_headless_report(&path, false);
        return Ok(());
    }
    if let Some(path) = arg_value("--report") {
        write_headless_report(&path, true);
        return Ok(());
    }

    // A login launch carries `--background`: the window belongs in the status area rather
    // than on top of whatever the person just opened.
    let background = std::env::args_os().any(|argument| argument.to_string_lossy() == "--background");

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(format!("vn-ranger {}", env!("CARGO_PKG_VERSION")))
            .with_app_id("vn-ranger")
            .with_inner_size(STARTING_SIZE)
            .with_min_inner_size(MINIMUM_SIZE)
            .with_icon(egui::IconData {
                rgba: ICON.to_vec(),
                width: ICON_SIZE,
                height: ICON_SIZE,
            }),
        ..Default::default()
    };

    eframe::run_native(
        "vn-ranger",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, background)))),
    )
}

fn write_headless_report(path: &Path, record: bool) {
    let Some(snapshot) = vnr_native::scan(&|_| {}, &|| false) else {
        eprintln!("vn-ranger: the scan was cancelled");
        std::process::exit(1);
    };
    if let Err(error) = vnr_native::store::write_json(&snapshot, path) {
        eprintln!("vn-ranger: could not write {}: {error}", path.display());
        std::process::exit(1);
    }
    if !record {
        return;
    }
    let mut journal = match vnr_native::journal::Journal::open() {
        Ok(journal) => journal,
        Err(error) => {
            eprintln!("vn-ranger: the scan finished, but the journal could not be opened: {error}");
            return;
        }
    };
    let draft = vnr_core::Draft::event("scan").with_reason(&format!(
        "headless report to {} Â· {} processes Â· {} startup items Â· {} listeners Â· {} packages",
        path.display(),
        snapshot.processes.len(),
        snapshot.autoruns.len(),
        snapshot.listeners.len(),
        snapshot.packages.len()
    ));
    if let Err(error) = journal.record_synced(draft) {
        eprintln!("vn-ranger: the scan finished, but the journal could not be written: {error}");
    }
}

fn arg_value(flag: &str) -> Option<PathBuf> {
    let mut arguments = std::env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        if argument.to_string_lossy() == flag {
            return arguments.next().map(PathBuf::from);
        }
    }
    None
}
