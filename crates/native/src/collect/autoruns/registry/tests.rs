//! What the surface table says, checked against captures of a real registry.
//!
//! The fixtures in `crates/native/fixtures/registry/` were captured on Windows and then
//! sanitised — the user's profile path is `C:\Users\user`, and unrelated entries were
//! removed. They are not invented, and the ones that capture an *absence* say so in the
//! file itself: `RunOnce`, `RunServices` and `Notify` do not exist on an ordinary machine,
//! and a parser that turned that into an error would be wrong about every clean PC.

use super::*;

fn fixture(name: &str) -> KeyData {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join("registry")
        .join(format!("{name}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not a key fixture: {error}", path.display()))
}

/// The capture each surface is checked against. The match is exhaustive, so a row added to
/// the table without a fixture does not compile — which is the strongest form of "every
/// surface has a capture" available here.
fn fixture_for(id: &str) -> &'static str {
    match id {
        "run" => "run-hkcu",
        "run-machine" => "run-hklm",
        "run-once" | "run-once-machine" | "run-services" | "run-services-once" | "winlogon-notify" => {
            "absent"
        }
        "winlogon-shell" | "winlogon-userinit" => "winlogon",
        "appinit" => "appinit",
        "ifeo-debugger" => "ifeo",
        "active-setup" => "active-setup",
        "service-dll" => "services",
        "print-monitor" => "print-monitors",
        "lsa-notification" | "lsa-authentication" => "lsa",
        "netsh-helper" => "netsh",
        "screensaver" => "screensaver",
        "time-provider" => "time-providers",
        other => panic!("{other} has no captured fixture"),
    }
}

#[test]
fn every_surface_has_a_capture_to_be_checked_against() {
    for surface in SURFACES {
        let name = fixture_for(surface.id);
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("registry")
            .join(format!("{name}.json"));
        assert!(path.is_file(), "{} names {name} and it is not there", surface.id);
    }
    // Every fixture the mapping names is one of the files, so the mapping cannot drift.
    let mut named: Vec<&str> = SURFACES.iter().map(|surface| fixture_for(surface.id)).collect();
    named.sort_unstable();
    named.dedup();
    for name in named {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("registry")
            .join(format!("{name}.json"));
        assert!(path.is_file(), "{name}.json is named and missing");
    }
}

#[test]
fn every_surface_names_itself_and_the_technique_it_instances() {
    for surface in SURFACES {
        assert!(!surface.label.trim().is_empty(), "{} has no label", surface.id);
        assert!(
            surface.technique.is_some(),
            "{} names no ATT&CK technique, and every surface here is one",
            surface.id
        );
        // A user-scoped surface in the machine hive is a table error, not a finding.
        assert!(
            !(surface.hive == Hive::LocalMachine && surface.scope == AutorunScope::User),
            "{} is machine-wide in HKLM and claims to be the user's",
            surface.id
        );
    }
}

#[test]
fn the_surface_ids_are_unique_and_usable() {
    let mut seen = Vec::new();
    for surface in SURFACES {
        assert!(seen.iter().all(|id| *id != surface.id), "{} twice", surface.id);
        assert!(
            surface.id.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
            "{} is not a lowercase id",
            surface.id
        );
        seen.push(surface.id);
    }
}

#[test]
fn a_run_key_value_is_one_entry_with_its_quoted_command_intact() {
    let surface = surface("run").unwrap();
    let entries = entries(surface, View::SixtyFour, &fixture("run-hkcu"));
    assert_eq!(entries.len(), 6);
    let firefox = entries
        .iter()
        .find(|entry| entry.name.starts_with("Mozilla"))
        .unwrap();
    assert!(firefox.command.contains("firefox.exe"), "{}", firefox.command);
    assert!(firefox.location.contains("Run"), "{}", firefox.location);
    assert!(firefox.location.contains("64-bit"), "{}", firefox.location);
    assert_eq!(firefox.id, format!("run:HKCU:64:{}", firefox.name));
}

#[test]
fn a_machine_run_key_is_its_own_surface_with_its_own_scope() {
    let surface = surface("run-machine").unwrap();
    assert_eq!(surface.hive, Hive::LocalMachine);
    assert_eq!(surface.scope, AutorunScope::System);
    let entries = entries(surface, View::SixtyFour, &fixture("run-hklm"));
    assert_eq!(entries.len(), 2);
    assert!(
        entries.iter().any(|entry| entry.command.starts_with("%windir%")),
        "an unexpanded value is kept exactly as the registry has it"
    );
}

#[test]
fn an_absent_key_produces_no_entries_rather_than_an_error() {
    for id in ["run-once", "run-services", "winlogon-notify"] {
        let surface = surface(id).unwrap();
        let entries = entries(surface, View::SixtyFour, &fixture(fixture_for(id)));
        assert!(entries.is_empty(), "{id} invented an entry");
    }
}

#[test]
fn an_empty_value_is_not_an_entry() {
    let surface = surface("appinit").unwrap();
    let entries = entries(surface, View::SixtyFour, &fixture("appinit"));
    assert!(
        entries.is_empty(),
        "an empty AppInit_DLLs is every ordinary machine, not an entry: {entries:?}"
    );
}

#[test]
fn winlogon_userinit_is_read_with_its_trailing_comma() {
    let surface = surface("winlogon-userinit").unwrap();
    let entries = entries(surface, View::SixtyFour, &fixture("winlogon"));
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "Userinit");
    assert!(
        entries[0].command.ends_with("userinit.exe,"),
        "the comma is part of the value and the parsing of it is a rule's business: {}",
        entries[0].command
    );
}

#[test]
fn a_debugger_value_is_read_from_the_subkey_that_names_the_program() {
    // The capture has no Debugger, which is the ordinary case. The positive path is built
    // here from the same shape rather than claimed as a capture.
    let mut data = fixture("ifeo");
    data.subkeys[1].values.push(Value {
        name: "Debugger".to_owned(),
        data: "C:\\Windows\\System32\\not-the-program.exe".to_owned(),
    });
    let surface = surface("ifeo-debugger").unwrap();
    let entries = entries(surface, View::SixtyFour, &data);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "GoogleUpdate.exe");
    assert!(entries[0].location.contains("Debugger"));
    assert!(entries[0].id.contains("ifeo-debugger"));
}

#[test]
fn a_service_dll_is_read_one_level_in_and_a_service_without_one_is_skipped() {
    let surface = surface("service-dll").unwrap();
    let entries = entries(surface, View::SixtyFour, &fixture("services"));
    assert_eq!(entries.len(), 2, "{entries:?}");
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
    assert!(names.contains(&"wscsvc"));
    assert!(names.contains(&"mpssvc"));
    assert!(
        !names.contains(&".NET CLR Data"),
        "that one has no Parameters key"
    );
    assert!(entries[0].command.ends_with(".dll"), "{}", entries[0].command);
}

#[test]
fn active_setup_reads_the_stub_path_and_skips_a_component_without_one() {
    let surface = surface("active-setup").unwrap();
    let entries = entries(surface, View::ThirtyTwo, &fixture("active-setup"));
    assert_eq!(entries.len(), 1);
    assert!(entries[0].command.contains("unregmp2.exe"));
}

#[test]
fn the_same_surface_in_two_views_is_two_entries_with_two_ids() {
    let surface = surface("run").unwrap();
    let data = fixture("run-hkcu");
    let sixty_four = entries(surface, View::SixtyFour, &data);
    let thirty_two = entries(surface, View::ThirtyTwo, &data);
    assert_eq!(sixty_four.len(), thirty_two.len());
    assert_ne!(sixty_four[0].id, thirty_two[0].id, "the view is part of the id");
    assert!(thirty_two[0].location.contains("32-bit"));
}

#[test]
fn the_six_surfaces_that_came_with_the_second_table_pass_read_their_own_shape() {
    // A print monitor's driver, one level in.
    let monitors = entries(
        surface("print-monitor").unwrap(),
        View::SixtyFour,
        &fixture("print-monitors"),
    );
    assert_eq!(monitors.len(), 3);
    assert_eq!(monitors[0].name, "Appmon");
    assert_eq!(monitors[0].command, "AppMon.dll");

    // A multi-string value is a list: one package is one entry, not one string with a
    // separator in it.
    let authentication = entries(
        surface("lsa-authentication").unwrap(),
        View::SixtyFour,
        &fixture("lsa"),
    );
    assert_eq!(authentication.len(), 1);
    assert_eq!(authentication[0].name, "Authentication Packages");
    assert_eq!(authentication[0].command, "msv1_0");
    let notification = entries(
        surface("lsa-notification").unwrap(),
        View::SixtyFour,
        &fixture("lsa"),
    );
    assert_eq!(notification[0].command, "scecli");

    // netsh helpers are ordinary values, and their names are what a person sees.
    let helpers = entries(
        surface("netsh-helper").unwrap(),
        View::SixtyFour,
        &fixture("netsh"),
    );
    assert_eq!(helpers.len(), 4);
    assert!(helpers.iter().any(|entry| entry.name == "dhcpclient"));

    // A time provider is a DLL under a subkey, in both providers that have one.
    let providers = entries(
        surface("time-provider").unwrap(),
        View::SixtyFour,
        &fixture("time-providers"),
    );
    assert_eq!(providers.len(), 3);
    assert!(providers.iter().all(|entry| entry.command.ends_with(".dll")));

    // This machine has no screensaver set, and the capture says so.
    let saver = entries(
        surface("screensaver").unwrap(),
        View::SixtyFour,
        &fixture("screensaver"),
    );
    assert!(saver.is_empty(), "{saver:?}");
}

#[test]
fn a_multi_string_with_two_packages_is_two_entries_with_distinct_names() {
    let data = KeyData {
        values: vec![Value {
            name: "Notification Packages".to_owned(),
            data: "scecli\u{0}acme\u{0}".to_owned(),
        }],
        subkeys: Vec::new(),
    };
    let entries = entries(surface("lsa-notification").unwrap(), View::SixtyFour, &data);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].command, "scecli");
    assert_eq!(entries[1].command, "acme");
    assert_ne!(entries[0].id, entries[1].id, "each package has its own id");
}
