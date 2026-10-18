//! Reading one scheduled task's XML.
//!
//! A task is one XML file. The schema has hundreds of elements and this reads the few that
//! decide whether something runs and what it runs: the task's own path, its action, the
//! account it runs as, whether it is enabled, whether it is hidden, and which triggers it
//! has. Everything else is left to the file.
//!
//! The reader is `quick-xml`, which the plist reader already pulls in, rather than a scanner
//! written here: task XML is machine-written and unremarkable, but "unremarkable XML" is
//! exactly the assumption a hand-written extractor gets wrong on the one file that matters.
//!
//! A file that is not a task is an error with the line, not a guess: half a task read is a
//! fact nobody can check.

use quick_xml::Reader;
use quick_xml::events::Event;

/// The most interesting part of a `<Trigger>`: which kind of trigger it is.
pub const TRIGGERS: [&str; 9] = [
    "LogonTrigger",
    "BootTrigger",
    "TimeTrigger",
    "CalendarTrigger",
    "DailyTrigger",
    "WeeklyTrigger",
    "MonthlyTrigger",
    "RegistrationTrigger",
    "IdleTrigger",
];

/// What one task file says that ranger needs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Task {
    /// The task's own path, such as `\Microsoft\Windows\Defrag\ScheduledDefrag`.
    pub uri: String,
    /// The program the task runs.
    pub command: Option<String>,
    /// Its arguments.
    pub arguments: Option<String>,
    /// Its working directory.
    pub working_directory: Option<String>,
    /// The account it runs as, which is often a SID.
    pub user: Option<String>,
    /// Who the file says registered it.
    pub author: Option<String>,
    /// Whether the task is enabled. A task with no `Enabled` element is enabled.
    pub enabled: bool,
    /// Whether the task hides itself from the Task Scheduler's own list.
    pub hidden: bool,
    /// The trigger elements it has, by element name.
    pub triggers: Vec<String>,
}

impl Task {
    /// The command line, as a person reads it.
    #[must_use]
    pub fn command_line(&self) -> String {
        match (&self.command, &self.arguments) {
            (Some(command), Some(arguments)) if !arguments.trim().is_empty() => {
                format!("{} {}", command.trim(), arguments.trim())
            }
            (Some(command), _) => command.trim().to_owned(),
            _ => String::new(),
        }
    }
}

/// Read a task file.
pub fn parse(xml: &str) -> Result<Task, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut task = Task {
        enabled: true,
        ..Task::default()
    };
    // The stack of open elements, so a `<UserId>` inside `<Principals>` is not confused with
    // a `<UserId>` inside a trigger.
    let mut stack: Vec<String> = Vec::new();
    let mut saw_task = false;
    loop {
        match reader.read_event() {
            Ok(Event::Start(start)) => {
                let name = local_name(start.name().as_ref());
                if name == "Task" {
                    saw_task = true;
                }
                if TRIGGERS.contains(&name.as_str()) {
                    // A trigger is named inside `<Triggers>`; one task may have several.
                    if !stack.iter().any(|open| open == "Triggers") {
                        stack.push(name);
                        continue;
                    }
                    if !task.triggers.contains(&name) {
                        task.triggers.push(name.clone());
                    }
                }
                stack.push(name);
            }
            Ok(Event::Text(text)) => {
                let Some(current) = stack.last() else {
                    continue;
                };
                let value = text
                    .decode()
                    .map_err(|error| format!("line {}: {error}", reader.buffer_position()))?
                    .into_owned();
                if value.trim().is_empty() {
                    continue;
                }
                // Several elements mean different things under different parents: a
                // `<UserId>` under `<Trigger>` is who a trigger fires for, and an
                // `<Enabled>` under a trigger is whether that trigger is on. The account a
                // task runs as is the one under `<Principal>`, and the switch that governs
                // the task is the one under `<Settings>` — so the parent decides.
                let inside = |parent: &str| stack.iter().any(|open| open == parent);
                match current.as_str() {
                    "URI" => task.uri = value,
                    "Command" => task.command = Some(value),
                    "Arguments" => task.arguments = Some(value),
                    "WorkingDirectory" => task.working_directory = Some(value),
                    "Author" => task.author = Some(value),
                    "UserId" if inside("Principal") && task.user.is_none() => {
                        task.user = Some(value);
                    }
                    "Enabled" if inside("Settings") => {
                        task.enabled = !value.eq_ignore_ascii_case("false");
                    }
                    "Hidden" if inside("Settings") => {
                        task.hidden = value.eq_ignore_ascii_case("true");
                    }
                    _ => {}
                }
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Eof) => break,
            Err(error) => {
                return Err(format!("line {}: {error}", reader.buffer_position()));
            }
            Ok(_) => {}
        }
    }
    if !saw_task {
        return Err("this file is not a task: it has no <Task> element".to_owned());
    }
    if task.uri.trim().is_empty() {
        return Err("this task has no <URI>, so there is nothing to name it by".to_owned());
    }
    Ok(task)
}

/// The element's name without its namespace, which is what the schema's own words are.
fn local_name(name: &[u8]) -> String {
    let text = String::from_utf8_lossy(name);
    text.rsplit(':').next().unwrap_or(&text).to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join("tasks")
            .join(name);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
    }

    #[test]
    fn a_captured_task_reads_its_action_and_its_account() {
        let task = parse(&fixture("scheduled-defrag.xml")).unwrap();
        assert_eq!(task.uri, r"\Microsoft\Windows\Defrag\ScheduledDefrag");
        assert_eq!(task.command.as_deref(), Some(r"%windir%\system32\defrag.exe"));
        assert_eq!(task.arguments.as_deref(), Some("-c -h -o -$"));
        assert_eq!(task.user.as_deref(), Some("S-1-5-18"));
        assert!(task.enabled);
        assert!(!task.hidden);
        assert!(
            task.triggers.is_empty(),
            "this task's own <Triggers /> is empty, which is what the capture says: {:?}",
            task.triggers
        );
    }

    #[test]
    fn a_hidden_on_logon_task_is_read_as_hidden_and_on_logon() {
        // The shape of a hidden task with an `onlogon` trigger. The real capture of that
        // shape is owed with the macOS and Linux ones; this is the parser's test, labelled
        // as a constructed document rather than as a capture.
        let xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>Acme Ltd</Author>
    <URI>\Acme\Updater</URI>
    <SecurityDescriptor>D:(A;;FA;;;BA)</SecurityDescriptor>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>user</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>DESKTOP\user</UserId>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\user\AppData\Local\Acme\updater.exe</Command>
      <Arguments>--quiet</Arguments>
      <WorkingDirectory>C:\Users\user\AppData\Local\Acme</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"#;
        let task = parse(xml).unwrap();
        assert_eq!(task.uri, r"\Acme\Updater");
        assert!(task.hidden, "the task hides itself from the scheduler's list");
        assert_eq!(task.triggers, vec!["LogonTrigger"]);
        assert_eq!(task.user.as_deref(), Some(r"DESKTOP\user"));
        assert_eq!(task.author.as_deref(), Some("Acme Ltd"));
        assert_eq!(
            task.command_line(),
            r"C:\Users\user\AppData\Local\Acme\updater.exe --quiet"
        );
        assert_eq!(
            task.working_directory.as_deref(),
            Some(r"C:\Users\user\AppData\Local\Acme")
        );
    }

    #[test]
    fn a_disabled_task_is_read_as_disabled() {
        let xml = r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\Acme\Off</URI></RegistrationInfo>
  <Settings><Enabled>false</Enabled></Settings>
  <Actions><Exec><Command>a.exe</Command></Exec></Actions>
</Task>"#;
        let task = parse(xml).unwrap();
        assert!(!task.enabled);
        assert_eq!(task.command_line(), "a.exe");
    }

    #[test]
    fn a_file_that_is_not_a_task_is_an_error_rather_than_an_empty_fact() {
        assert!(parse("not xml at all").is_err());
        assert!(
            parse(r#"<html><body>hello</body></html>"#)
                .unwrap_err()
                .contains("no <Task>")
        );
        assert!(
            parse(r#"<Task><Settings><Enabled>true</Enabled></Settings></Task>"#)
                .unwrap_err()
                .contains("<URI>")
        );
    }

    #[test]
    fn a_task_with_no_action_reads_as_a_task_with_no_command() {
        let xml = r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\Acme\Empty</URI></RegistrationInfo>
  <Actions />
</Task>"#;
        let task = parse(xml).unwrap();
        assert_eq!(task.command_line(), "");
        assert!(task.command.is_none());
    }
}
