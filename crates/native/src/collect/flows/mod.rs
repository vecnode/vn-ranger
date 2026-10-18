//! Connections the machine is holding, with the process that holds each one.
//!
//! A listener is a socket waiting; a connection is a socket talking. The operating system's
//! own table is the source, so this is flow-level only: no packet is captured, no name is
//! resolved, and no query leaves the machine (`docs/PLAN-0.1.7.md` §4.3).

use vnr_core::FlowFact;

/// How many connections one scan will report.
///
/// A busy development machine can hold thousands; a person reads tens. The cap is a fact the
/// status carries when it bites, so a truncated list is never mistaken for the whole table.
pub const MAX_FLOWS: usize = 2_000;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::collect;

#[cfg(all(unix, not(target_os = "macos")))]
mod linux;

#[cfg(all(unix, not(target_os = "macos")))]
pub use linux::collect;

#[cfg(target_os = "macos")]
/// macOS connections are not collected yet.
pub fn collect(_process_names: &std::collections::HashMap<u32, String>) -> crate::collect::Outcome<FlowFact> {
    crate::collect::Outcome::Unavailable {
        reason: "Connections are not collected on macOS yet: the socket table needs a \
                 privileged call this build has no safe wrapper for."
            .to_owned(),
    }
}

#[cfg(not(any(windows, unix)))]
/// A platform this build does not collect yet.
pub fn collect(_process_names: &std::collections::HashMap<u32, String>) -> crate::collect::Outcome<FlowFact> {
    crate::collect::Outcome::Unavailable {
        reason: "Connections are not collected on this platform yet.".to_owned(),
    }
}

/// Put connections in the order a person reads them: by process, then by the other end.
pub(crate) fn sort_and_cap(flows: &mut Vec<FlowFact>) -> bool {
    flows.sort_by(|a, b| {
        a.process
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .cmp(&b.process.as_deref().unwrap_or("").to_lowercase())
            .then_with(|| a.remote_addr.cmp(&b.remote_addr))
            .then_with(|| a.remote_port.cmp(&b.remote_port))
            .then_with(|| a.local_port.cmp(&b.local_port))
    });
    flows.dedup_by(|a, b| {
        a.protocol == b.protocol
            && a.local_addr == b.local_addr
            && a.local_port == b.local_port
            && a.remote_addr == b.remote_addr
            && a.remote_port == b.remote_port
            && a.pid == b.pid
    });
    if flows.len() > MAX_FLOWS {
        flows.truncate(MAX_FLOWS);
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use vnr_core::Protocol;

    fn flow(process: &str, remote: &str, port: u16, local: u16) -> FlowFact {
        FlowFact {
            protocol: Protocol::Tcp,
            local_addr: "192.168.1.10".to_owned(),
            local_port: local,
            remote_addr: remote.to_owned(),
            remote_port: port,
            state: "ESTABLISHED".to_owned(),
            pid: Some(1),
            process: Some(process.to_owned()),
            bytes: None,
        }
    }

    #[test]
    fn duplicates_of_one_socket_are_one_fact_and_the_order_is_stable() {
        let mut flows = vec![
            flow("beta.exe", "203.0.113.9", 443, 51000),
            flow("alpha.exe", "198.51.100.1", 80, 51001),
            flow("beta.exe", "203.0.113.9", 443, 51000),
        ];
        let capped = sort_and_cap(&mut flows);
        assert!(!capped);
        assert_eq!(flows.len(), 2);
        assert_eq!(flows[0].process.as_deref(), Some("alpha.exe"));
        assert_eq!(flows[1].process.as_deref(), Some("beta.exe"));
    }

    #[test]
    fn a_table_over_the_cap_says_so_rather_than_growing() {
        let mut flows: Vec<FlowFact> = (0..(MAX_FLOWS + 5))
            .map(|index| flow("x", "203.0.113.9", 443, u16::try_from(index % 60000).unwrap_or(1)))
            .collect();
        assert!(sort_and_cap(&mut flows));
        assert_eq!(flows.len(), MAX_FLOWS);
    }
}
