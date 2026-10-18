//! Connections on Linux, from `/proc/net/tcp` and `/proc/net/tcp6`.
//!
//! A socket in `/proc` is an inode, and the pid that holds it is a directory of file
//! descriptors. The two tables are read at slightly different times, so a socket can arrive
//! without an owner: it is reported with no pid rather than dropped, because the owner being
//! unknown is itself a fact.

use std::collections::HashMap;
use std::net::IpAddr;

use vnr_core::{FlowFact, Protocol};

use crate::collect::Outcome;
use crate::collect::listeners::linux::{parse_address, socket_owners};

use super::sort_and_cap;

/// TCP states that are not a connection to somewhere.
const LISTEN: u32 = 0x0a;
const TIME_WAIT: u32 = 0x06;

/// Read every connected TCP socket this account can see.
#[must_use]
pub fn collect(process_names: &HashMap<u32, String>) -> Outcome<FlowFact> {
    let owners = socket_owners();
    let mut flows = Vec::new();
    let mut readable = false;
    for (path, ipv6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        readable = true;
        for line in text.lines().skip(1) {
            let Some(flow) = parse_line(line, ipv6, &owners, process_names) else {
                continue;
            };
            flows.push(flow);
        }
    }
    if !readable {
        return Outcome::Unavailable {
            reason: "Neither /proc/net/tcp nor /proc/net/tcp6 could be read.".to_owned(),
        };
    }
    let capped = sort_and_cap(&mut flows);
    if capped {
        return Outcome::Partial {
            items: flows,
            reason: format!(
                "This machine holds more than {} connections; the table was cut there.",
                super::MAX_FLOWS
            ),
        };
    }
    Outcome::Items(flows)
}

/// One line of the table, when it describes a connection this scanner can report.
fn parse_line(
    line: &str,
    ipv6: bool,
    owners: &HashMap<u64, u32>,
    process_names: &HashMap<u32, String>,
) -> Option<FlowFact> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }
    let (local_addr, local_port) = split_address(fields[1], ipv6)?;
    let (remote_addr, remote_port) = split_address(fields[2], ipv6)?;
    let state = u32::from_str_radix(fields[3], 16).ok()?;
    if state == LISTEN || state == TIME_WAIT || remote_port == 0 {
        return None;
    }
    let inode: u64 = fields[9].parse().ok()?;
    let pid = owners.get(&inode).copied();
    Some(FlowFact {
        protocol: Protocol::Tcp,
        local_addr: local_addr.to_string(),
        local_port,
        remote_addr: remote_addr.to_string(),
        remote_port,
        state: state_label(state).to_owned(),
        pid,
        process: pid.and_then(|pid| process_names.get(&pid).cloned()),
        bytes: None,
    })
}

/// `/proc` writes `0100007F:01BB`, which is an address and a port in one field.
fn split_address(field: &str, ipv6: bool) -> Option<(IpAddr, u16)> {
    let (address, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    Some((parse_address(address, ipv6)?, port))
}

/// The state in the word the rest of the program uses.
fn state_label(state: u32) -> &'static str {
    match state {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECEIVED",
        0x04 => "FIN_WAIT_1",
        0x05 => "FIN_WAIT_2",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0b => "CLOSING",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_proc_line_becomes_a_connection_with_its_owner() {
        let mut owners = HashMap::new();
        owners.insert(4242, 7);
        let mut names = HashMap::new();
        names.insert(7, "agent".to_owned());
        let line = "  1: 0100007F:1F90 5DB8D822:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 20 4 30 10 -1";
        let flow = parse_line(line, false, &owners, &names).unwrap();
        assert_eq!(flow.local_addr, "127.0.0.1");
        assert_eq!(flow.local_port, 8080);
        assert_eq!(flow.remote_addr, "34.216.184.93");
        assert_eq!(flow.remote_port, 443);
        assert_eq!(flow.state, "ESTABLISHED");
        assert_eq!(flow.pid, Some(7));
        assert_eq!(flow.process.as_deref(), Some("agent"));
    }

    #[test]
    fn a_listener_and_a_closing_socket_are_not_connections() {
        let owners = HashMap::new();
        let names = HashMap::new();
        let listen = "  0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0000000000000000 100 0 0 10 0";
        assert!(parse_line(listen, false, &owners, &names).is_none());
        let time_wait = "  0: 0100007F:1F90 0100007F:1F91 06 00000000:00000000 03:00000000 00000000     0        0 2222 1 0000000000000000 0 0 0 0 0";
        assert!(parse_line(time_wait, false, &owners, &names).is_none());
    }

    #[test]
    fn a_connection_with_no_named_owner_is_still_a_fact() {
        let owners = HashMap::new();
        let names = HashMap::new();
        let line = "  2: 0100007F:1F90 5DB8D822:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 20 4 30 10 -1";
        let flow = parse_line(line, false, &owners, &names).unwrap();
        assert_eq!(flow.pid, None);
        assert_eq!(flow.process, None);
    }
}
