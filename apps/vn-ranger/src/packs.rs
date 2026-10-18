//! The shell's side of rule packs: loading the active one, and drawing the list.
//!
//! A pack that cannot load is a sentence, not a failure: the built-in rules keep running and
//! the reason is on screen with the fingerprint and the file it is about. Nothing here stops
//! a scan, and nothing here writes anything except through the store's journaled activation.

use vnr_core::pack::Pack;
use vnr_core::rules::builtin_ids;
use vnr_native::pack::{self, Keys, store};

/// What the shell needs to know about the rules that are not compiled in.
pub struct Loaded {
    /// The active pack, when one loaded.
    pub pack: Option<Pack>,
    /// The trusted keys, as they were when the pack was loaded.
    pub keys: Keys,
    /// Why the pack named by the record did not load, when it did not.
    pub problem: Option<String>,
}

/// Read the trust store and load the active pack, recording the built-in one on first run.
///
/// A first launch has no record. Rather than run with no pack and a notice nobody reads, the
/// pack compiled into the build is recorded as active — which is a real activation, with its
/// journal entry, and not a special case the interface has to know about.
pub fn load(journal: &mut vnr_native::journal::Journal) -> Loaded {
    let directory = pack::directory();
    let builtin = builtin_ids();
    let keys = match Keys::load(&directory) {
        Ok(keys) => keys,
        Err(problem) => {
            return Loaded {
                pack: None,
                keys: Keys::default(),
                problem: Some(problem),
            };
        }
    };
    match store::record(&directory) {
        Ok(Some(_)) => match store::load_active(&directory, builtin, &keys) {
            Ok(Some(loaded)) => Loaded {
                pack: Some(loaded.pack),
                keys,
                problem: None,
            },
            Ok(None) => Loaded {
                pack: None,
                keys,
                problem: None,
            },
            Err(problem) => Loaded {
                pack: None,
                keys,
                problem: Some(format!(
                    "The active rule pack could not be loaded, so only the built-in rules are running: {problem}"
                )),
            },
        },
        Ok(None) => match store::activate_embedded(&directory, builtin, journal, now_unix()) {
            Ok(loaded) => Loaded {
                pack: Some(loaded.pack),
                keys,
                problem: None,
            },
            Err(problem) => Loaded {
                pack: None,
                keys,
                problem: Some(format!("The built-in rule pack could not be recorded: {problem}")),
            },
        },
        Err(problem) => Loaded {
            pack: None,
            keys,
            problem: Some(problem),
        },
    }
}

/// Build the view the Packs page draws.
#[must_use]
pub fn view(keys: &Keys, active: Option<&Pack>) -> vnr_ui::Packs {
    let directory = pack::directory();
    let mut view = vnr_ui::Packs {
        directory: directory.display().to_string(),
        can_roll_back: store::previous(&directory).ok().flatten().is_some(),
        ..vnr_ui::Packs::default()
    };
    let record = store::record(&directory).ok().flatten();
    view.signed_by = record.as_ref().and_then(|record| record.fingerprint.clone());

    if let Some(pack) = active {
        view.active = Some(vnr_ui::PackRow {
            id: pack.header.id.clone(),
            version: pack.header.version.clone(),
            title: pack.header.title.clone(),
            rules: pack.rules.len(),
            path: if record.as_ref().is_some_and(|record| record.fingerprint.is_none()) {
                String::new()
            } else {
                record
                    .as_ref()
                    .map(|_| "one of the packs below".to_owned())
                    .unwrap_or_default()
            },
            active: true,
            signed: record.as_ref().is_some_and(|record| record.fingerprint.is_some()),
            status: match &view.signed_by {
                Some(fingerprint) => format!("Signed by {fingerprint}"),
                None => "Built into ranger".to_owned(),
            },
        });
    }

    let builtin = builtin_ids();
    let mut signed_by: Vec<(String, usize)> = Vec::new();
    for candidate in store::candidates(&directory) {
        let name = candidate
            .path
            .file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
        let (row, fingerprint) = match store::inspect(&candidate.path, builtin, keys) {
            Ok((pack, fingerprint)) => {
                let active_now = record.as_ref().is_some_and(|record| {
                    record.fingerprint.is_some()
                        && record.id == pack.header.id
                        && record.version == pack.header.version
                });
                (
                    vnr_ui::PackRow {
                        id: pack.header.id.clone(),
                        version: pack.header.version.clone(),
                        title: pack.header.title.clone(),
                        rules: pack.rules.len(),
                        path: candidate.path.display().to_string(),
                        active: active_now,
                        signed: true,
                        status: format!("Signed by {fingerprint}"),
                    },
                    Some(fingerprint),
                )
            }
            Err(problem) => (
                vnr_ui::PackRow {
                    id: name.clone(),
                    version: String::new(),
                    title: name,
                    rules: 0,
                    path: candidate.path.display().to_string(),
                    active: false,
                    signed: candidate.signed,
                    status: problem.replace('\n', " "),
                },
                None,
            ),
        };
        if let Some(fingerprint) = fingerprint {
            match signed_by.iter_mut().find(|(known, _)| *known == fingerprint) {
                Some((_, count)) => *count += 1,
                None => signed_by.push((fingerprint, 1)),
            }
        }
        view.installed.push(row);
    }

    view.keys = keys
        .keys
        .iter()
        .map(|stored| vnr_ui::KeyRow {
            fingerprint: stored.fingerprint.clone(),
            added: vnr_core::time::format_utc(stored.added_at_unix),
            packs: signed_by
                .iter()
                .find(|(fingerprint, _)| *fingerprint == stored.fingerprint)
                .map_or(0, |(_, count)| *count),
        })
        .collect();
    view
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
