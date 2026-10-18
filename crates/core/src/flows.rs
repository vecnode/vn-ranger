//! Connection facts: what this machine is talking to, and as which process.
//!
//! A [`crate::ListenerFact`] is a socket waiting for something; a [`FlowFact`] is a socket
//! with a peer. Ranger gets these from the operating system's own connection table, sampled
//! when a scan runs. It never captures a packet, never resolves a name and never sends a
//! query: the remote end is an address because that is what the machine holds
//! (`docs/PLAN-0.1.7.md` §4.3).
//!
//! The export is Zeek's `conn.log` shape because every blue team already has a parser for
//! it. The columns a sample cannot fill are `-`, which is Zeek's own "unknown", rather than
//! zero — a zero would be a measurement this program did not make.

use std::fmt::Write as _;

use crate::model::{FlowFact, Protocol};

/// The header Zeek writes before its fields, so the file is self-describing.
pub const ZEEK_HEADER: &str = "#separator \\x09\n\
#set_separator\t,\n\
#empty_field\t(empty)\n\
#unset_field\t-\n\
#path\tconn\n";

/// The columns of a `conn.log`, in Zeek's order.
pub const ZEEK_FIELDS: [&str; 21] = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
];

/// One connection as a `conn.log` row.
///
/// `ts` is when the row was observed, because a sample does not know when the connection
/// started; `duration` is therefore unknown. `local_orig` and `local_resp` are `T` and `F`:
/// the ranger reads this machine's table, so the origin end is the local one by definition.
#[must_use]
pub fn zeek_row(flow: &FlowFact, observed_at: u64) -> String {
    let proto = match flow.protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };
    let bytes = flow
        .bytes
        .map_or_else(|| "-".to_owned(), |bytes| bytes.to_string());
    let fields = [
        observed_at.to_string(),
        "-".to_owned(),
        flow.local_addr.clone(),
        flow.local_port.to_string(),
        flow.remote_addr.clone(),
        flow.remote_port.to_string(),
        proto.to_owned(),
        "-".to_owned(),
        "-".to_owned(),
        bytes.clone(),
        bytes,
        state_label(&flow.state),
        "T".to_owned(),
        "F".to_owned(),
        "0".to_owned(),
        "-".to_owned(),
        "-".to_owned(),
        "-".to_owned(),
        "-".to_owned(),
        "-".to_owned(),
        "-".to_owned(),
    ];
    fields.join("\t")
}

/// A whole export, header first.
#[must_use]
pub fn zeek(flows: &[FlowFact], observed_at: u64) -> String {
    let mut out = String::from(ZEEK_HEADER);
    out.push_str("#fields\t");
    out.push_str(&ZEEK_FIELDS.join("\t"));
    out.push('\n');
    for flow in flows {
        let _ = writeln!(out, "{}", zeek_row(flow, observed_at));
    }
    out
}

/// A connection state in the abbreviation a `conn.log` uses.
///
/// An unmapped state keeps the platform's word rather than being forced into a letter: a
/// wrong letter is worse than a word a parser will pass through.
fn state_label(state: &str) -> String {
    match state.trim().to_ascii_uppercase().as_str() {
        "ESTABLISHED" => "SF".to_owned(),
        "SYN_SENT" | "SYN_RECEIVED" => "S0".to_owned(),
        "CLOSE_WAIT" | "FIN_WAIT_1" | "FIN_WAIT_2" | "CLOSING" | "LAST_ACK" | "TIME_WAIT" => "S1".to_owned(),
        other => other.to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(protocol: Protocol, remote: &str, port: u16, state: &str, bytes: Option<u64>) -> FlowFact {
        FlowFact {
            protocol,
            local_addr: "192.168.1.10".to_owned(),
            local_port: 51000,
            remote_addr: remote.to_owned(),
            remote_port: port,
            state: state.to_owned(),
            pid: Some(42),
            process: Some("agent.exe".to_owned()),
            bytes,
        }
    }

    #[test]
    fn a_row_has_one_field_per_column_even_when_the_facts_are_unknown() {
        let row = zeek_row(
            &flow(Protocol::Tcp, "203.0.113.9", 443, "ESTABLISHED", None),
            1_700_000_000,
        );
        let columns: Vec<&str> = row.split('\t').collect();
        assert_eq!(columns.len(), ZEEK_FIELDS.len());
        assert_eq!(columns[0], "1700000000");
        assert_eq!(columns[2], "192.168.1.10");
        assert_eq!(columns[3], "51000");
        assert_eq!(columns[4], "203.0.113.9");
        assert_eq!(columns[5], "443");
        assert_eq!(columns[6], "tcp");
        assert_eq!(columns[9], "-", "an unknown byte count is not zero");
        assert_eq!(columns[11], "SF");
        assert_eq!(columns[12], "T");
        assert_eq!(columns[13], "F");
    }

    #[test]
    fn a_known_byte_count_is_printed_and_a_state_keeps_its_word() {
        let row = zeek_row(
            &flow(Protocol::Udp, "198.51.100.4", 53, "ESTABLISHED", Some(512)),
            10,
        );
        let columns: Vec<&str> = row.split('\t').collect();
        assert_eq!(columns[9], "512");
        assert_eq!(columns[10], "512");
        assert_eq!(columns[6], "udp");
        let odd = zeek_row(&flow(Protocol::Tcp, "192.0.2.1", 8080, "NONE", None), 10);
        let columns: Vec<&str> = odd.split('\t').collect();
        assert_eq!(columns[11], "none", "an unmapped state is not guessed at");
    }

    #[test]
    fn an_export_is_a_header_and_one_line_per_connection() {
        let flows = vec![
            flow(Protocol::Tcp, "203.0.113.9", 443, "ESTABLISHED", None),
            flow(Protocol::Tcp, "203.0.113.10", 80, "SYN_SENT", None),
        ];
        let text = zeek(&flows, 1);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 6 + 2, "five header lines and a fields line");
        assert!(text.starts_with("#separator"));
        assert!(lines[5].starts_with("#fields\tts\tuid\tid.orig_h"));
        assert!(lines[6].ends_with("SF\tT\tF\t0\t-\t-\t-\t-\t-\t-"));
    }

    #[test]
    fn an_empty_export_is_still_a_valid_file() {
        let text = zeek(&[], 1);
        assert!(text.contains("#fields"));
        assert_eq!(text.lines().count(), 6);
    }
}
