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
mod packs;
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
    // directory is exactly the kind of standing privilege §6.9 refuses.
    if let Some(path) = arg_value("--elevated-scan") {
        write_headless_report(&path, false);
        return Ok(());
    }
    if let Some(path) = arg_value("--report") {
        write_headless_report(&path, true);
        return Ok(());
    }
    // A Sigma rule becomes a pack file that still has to be signed before ranger will load
    // it. The importer writes; the author signs; ranger verifies. No step here is skipped.
    if let Some(path) = arg_value("--sigma") {
        import_sigma(&path);
        return Ok(());
    }

    // One window per data directory. A second launch does not open a second window: it asks
    // the running one to come forward and exits.
    let instance = match vnr_native::instance::acquire() {
        Ok(guard) => Some(guard),
        Err(vnr_native::instance::LockError::Running(message)) => {
            eprintln!("vn-ranger: {message}");
            record_startup(&message);
            if vnr_native::instance::wake().is_ok() {
                eprintln!("vn-ranger: the running window has been asked to come forward");
            }
            return Ok(());
        }
        Err(vnr_native::instance::LockError::Unwritable(reason)) => {
            // A lock is an optimisation, not a precondition. Opening without one is better
            // than not opening, and the window says what happened.
            eprintln!("vn-ranger: {reason}");
            record_startup(&reason);
            None
        }
    };
    // A wake file from a crash must not raise a window nobody asked for.
    vnr_native::instance::clear_stale_wake();

    // A login launch carries `--background`: the window belongs in the status area rather
    // than on top of whatever the person just opened.
    let background = std::env::args_os().any(|argument| argument.to_string_lossy() == "--background");
    // One line a minute for a resident run: this is what the budgets in the plan are
    // measured on, so it is a flag rather than something the product does unasked.
    let soak = arg_value("--soak");

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
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, background, instance, soak)))),
    )
}

/// Convert one Sigma rule into a pack file beside it, and say what did and did not map.
///
/// The output is a pack, not an active rule set: it has no signature, so the Packs view will
/// list it as refused until its author signs it. That is the whole point of the footnote —
/// an import is a translation a person checks, not an adoption.
fn import_sigma(path: &Path) {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("vn-ranger: could not read {}: {error}", path.display());
            std::process::exit(1);
        }
    };
    let import = match vnr_core::sigma::import(&text) {
        Ok(import) => import,
        Err(problem) => {
            eprintln!("vn-ranger: {} was refused: {problem}", path.display());
            std::process::exit(1);
        }
    };
    let stem = path.file_stem().map_or_else(
        || "imported".to_owned(),
        |stem| stem.to_string_lossy().into_owned(),
    );
    let id = format!("imported.{stem}");
    let pack = import.pack(&id, "1");
    let out = path.with_file_name(format!("{stem}.pack.json"));
    let bytes = match serde_json::to_vec_pretty(&pack_to_wire(&pack)) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("vn-ranger: could not serialise the pack: {error}");
            std::process::exit(1);
        }
    };
    if let Err(error) = std::fs::write(&out, &bytes) {
        eprintln!("vn-ranger: could not write {}: {error}", out.display());
        std::process::exit(1);
    }
    println!(
        "vn-ranger: {} rule(s) mapped, {} skipped",
        import.rules.len(),
        import.skipped.len()
    );
    for skipped in &import.skipped {
        println!("  skipped {}: {}", skipped.title, skipped.reason);
    }
    println!("vn-ranger: wrote {}", out.display());
    println!("vn-ranger: it is not active until it is signed; ranger never signs anything");
}

/// The wire shape a pack file has, written from a validated pack.
fn pack_to_wire(pack: &vnr_core::pack::Pack) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = pack
        .rules
        .iter()
        .map(|rule| {
            let predicates: Vec<serde_json::Value> = rule
                .matches
                .all
                .iter()
                .map(|predicate| {
                    serde_json::json!({
                        "field": predicate.field,
                        "op": predicate.operator.id(),
                        "value": predicate.value,
                    })
                })
                .collect();
            serde_json::json!({
                "id": rule.id,
                "title": rule.title,
                "severity": match rule.severity {
                    vnr_core::Severity::Attention => "attention",
                    vnr_core::Severity::Notice => "notice",
                    vnr_core::Severity::Info => "info",
                },
                "confidence": match rule.confidence {
                    vnr_core::Confidence::Observed => "observed",
                    vnr_core::Confidence::Likely => "likely",
                    vnr_core::Confidence::Possible => "possible",
                },
                "technique": rule.technique,
                "match": {
                    "subject": rule.matches.subject.map(vnr_core::fields::Subject::id),
                    "all": predicates,
                },
                "why": rule.why,
                "benign": rule.benign,
                "remediation": rule.remediation,
            })
        })
        .collect();
    serde_json::json!({
        "schema": vnr_core::pack::SCHEMA,
        "pack": {
            "id": pack.header.id,
            "version": pack.header.version,
            "title": pack.header.title,
        },
        "rules": rules,
    })
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
        "headless report to {} · {} processes · {} startup items · {} listeners · {} packages",
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

/// Leave a line where a person can find it when there is no window to say it in.
///
/// A release build on Windows is a window-subsystem binary: it has no console, so an
/// `eprintln!` at startup goes nowhere. A failure that leaves no trace is the one thing this
/// program must never do, so it writes beside its own data.
fn record_startup(problem: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let line = format!(
        "{} vn-ranger {}: {problem}\n",
        vnr_core::time::format_utc(now),
        env!("CARGO_PKG_VERSION")
    );
    let path = vnr_native::paths::data_dir().join("startup.log");
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        use std::io::Write;
        let _ = file.write_all(line.as_bytes());
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
