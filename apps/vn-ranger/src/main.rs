//! vn-ranger — a quiet, local-only system ranger.
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

/// The application's mark, as unmultiplied RGBA.
const ICON: &[u8] = include_bytes!("../../../assets/logo/vn-ranger-app.rgba");

/// The icon is square and this many pixels on a side.
const ICON_SIZE: u32 = 64;

fn main() -> eframe::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    if let Some(path) = arg_value("--elevated-scan").or_else(|| arg_value("--report")) {
        write_headless_report(&path);
        return Ok(());
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("vn-ranger")
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
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}

fn write_headless_report(path: &Path) {
    let snapshot = vnr_native::scan(&|_| {});
    if let Err(error) = vnr_native::store::write_json(&snapshot, path) {
        eprintln!("vn-ranger: could not write {}: {error}", path.display());
        std::process::exit(1);
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
