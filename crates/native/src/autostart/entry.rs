//! The text of each autostart entry, built without touching the machine.
//!
//! Three formats, three rules, and one property they share: they are strings a person can
//! read before they are strings a system will run. Building them here, with no IO, is what
//! lets every host test all three — a Windows machine checks the macOS plist and the Linux
//! desktop file, so a quoting mistake is caught by the suite rather than by the person
//! whose login breaks.

use std::path::Path;

/// The value Windows stores under `HKCU\...\Run`.
///
/// A quoted path, then the flag. Quoted because a program under `C:\Program Files` has a
/// space in it, and an unquoted command line is a command somebody else can complete.
#[must_use]
pub(super) fn run_value(exe: &Path) -> String {
    format!("\"{}\" --background", exe.display())
}

/// The `LaunchAgent` plist, as XML.
///
/// `ProgramArguments` rather than a `Program` string: an array has no quoting rules to get
/// wrong, and `RunAtLoad` is the whole mechanism. `KeepAlive` is deliberately absent — a
/// resident ranger that is restarted every time it exits is a watchdog, and the plan says
/// there is no watchdog.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[must_use]
pub(super) fn launch_agent(label: &str, exe: &Path) -> String {
    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\">\n",
            "<dict>\n",
            "  <key>Label</key>\n",
            "  <string>{label}</string>\n",
            "  <key>ProgramArguments</key>\n",
            "  <array>\n",
            "    <string>{exe}</string>\n",
            "    <string>--background</string>\n",
            "  </array>\n",
            "  <key>RunAtLoad</key>\n",
            "  <true/>\n",
            "  <key>ProcessType</key>\n",
            "  <string>Interactive</string>\n",
            "</dict>\n",
            "</plist>\n"
        ),
        label = xml_escape(label),
        exe = xml_escape(&exe.display().to_string()),
    )
}

/// One `[Desktop Entry]`, the freedesktop way.
///
/// `Exec` needs its own quoting: a path with a space must be quoted *inside* the value,
/// and a desktop-file parser is not a shell. `X-GNOME-Autostart-enabled` is what the GNOME
/// session actually reads; the others ignore it, which is why it is not the only line.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[must_use]
pub(super) fn desktop_entry(exe: &Path, name: &str) -> String {
    format!(
        concat!(
            "[Desktop Entry]\n",
            "Type=Application\n",
            "Name={name}\n",
            "Comment=A quiet ranger for your machine\n",
            "Exec=\"{exe}\" --background\n",
            "Terminal=false\n",
            "X-GNOME-Autostart-enabled=true\n"
        ),
        name = name,
        exe = exe.display(),
    )
}

/// Escape the five characters XML reserves.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exe() -> std::path::PathBuf {
        std::path::PathBuf::from("/opt/vn ranger/vn-ranger")
    }

    #[test]
    fn the_windows_value_quotes_the_path_and_asks_for_the_background() {
        let value = run_value(&exe());
        assert_eq!(value, "\"/opt/vn ranger/vn-ranger\" --background");
        assert!(
            value.starts_with('"') && value.contains("\" --background"),
            "an unquoted path with a space is a command somebody else can finish"
        );
    }

    #[test]
    fn the_launch_agent_parses_as_a_plist_without_a_watchdog() {
        let text = launch_agent("dev.vecnode.ranger", &exe());
        let value: plist::Value = plist::from_bytes(text.as_bytes()).unwrap();
        let dict = value.as_dictionary().unwrap();
        assert_eq!(
            dict.get("Label").and_then(plist::Value::as_string),
            Some("dev.vecnode.ranger")
        );
        assert_eq!(
            dict.get("RunAtLoad").and_then(plist::Value::as_boolean),
            Some(true)
        );
        assert!(
            dict.get("KeepAlive").is_none(),
            "restarting ranger whenever it exits would be a watchdog"
        );
        let arguments = dict
            .get("ProgramArguments")
            .and_then(plist::Value::as_array)
            .expect("an array of arguments");
        assert_eq!(
            arguments
                .iter()
                .filter_map(plist::Value::as_string)
                .collect::<Vec<_>>(),
            vec!["/opt/vn ranger/vn-ranger", "--background"]
        );
    }

    #[test]
    fn a_label_or_a_path_cannot_close_the_xml_early() {
        let text = launch_agent("a</string><script>", Path::new("/x<&>\"'"));
        let value: plist::Value = plist::from_bytes(text.as_bytes()).unwrap();
        let dict = value.as_dictionary().unwrap();
        assert_eq!(
            dict.get("Label").and_then(plist::Value::as_string),
            Some("a</string><script>"),
            "the escape round-trips, it does not truncate"
        );
    }

    #[test]
    fn the_desktop_entry_is_the_minimum_a_session_reads() {
        let text = desktop_entry(&exe(), "vn-ranger");
        assert!(text.starts_with("[Desktop Entry]\n"));
        assert!(text.contains("Type=Application\n"));
        assert!(text.contains("Name=vn-ranger\n"));
        assert!(text.contains("Exec=\"/opt/vn ranger/vn-ranger\" --background\n"));
        assert!(text.contains("Terminal=false\n"));
        assert!(text.contains("X-GNOME-Autostart-enabled=true\n"));
        assert!(
            !text.contains("X-GNOME-Autostart-Delay"),
            "the entry does not invent a delay the person did not ask for"
        );
    }
}
