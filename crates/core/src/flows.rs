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

/// A steady rhythm in a process's connections: the shape a beacon has.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Beacon {
    /// How many times the connection was seen.
    pub contacts: usize,
    /// The middle interval between contacts, in seconds.
    pub interval_s: u64,
    /// The coefficient of variation of the intervals: smaller is steadier.
    pub jitter: f64,
}

/// The fewest contacts a rhythm can be read from.
pub const MIN_CONTACTS: usize = 6;
/// The shortest interval a beacon can have, in seconds.
pub const MIN_INTERVAL_S: u64 = 20;
/// The longest interval a beacon can have, in seconds (two hours).
pub const MAX_INTERVAL_S: u64 = 7_200;
/// How much the intervals may vary and still count as one rhythm.
pub const MAX_JITTER: f64 = 0.15;

/// Whether a series of observations is one steady rhythm, and what that rhythm is.
///
/// A pure function of the times: sorted, differences taken, the middle interval read, and
/// the spread of the intervals compared with the middle. A scheduled client looks exactly
/// like this, which is why a finding that uses it names the client as the benign case
/// before it names anything else (`docs/PLAN-0.1.7.md` §4.3).
#[must_use]
pub fn beacon(observed: &[u64]) -> Option<Beacon> {
    if observed.len() < MIN_CONTACTS {
        return None;
    }
    let mut times = observed.to_vec();
    times.sort_unstable();
    times.dedup();
    if times.len() < MIN_CONTACTS {
        return None;
    }
    let mut intervals: Vec<f64> = times
        .windows(2)
        .filter_map(|pair| match pair {
            [earlier, later] if later > earlier => Some((later - earlier) as f64),
            _ => None,
        })
        .collect();
    if intervals.len() < MIN_CONTACTS - 1 {
        return None;
    }
    intervals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = intervals[intervals.len() / 2];
    if !(MIN_INTERVAL_S as f64..=MAX_INTERVAL_S as f64).contains(&median) {
        return None;
    }
    let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
    if mean <= 0.0 {
        return None;
    }
    let variance = intervals
        .iter()
        .map(|interval| (interval - mean) * (interval - mean))
        .sum::<f64>()
        / intervals.len() as f64;
    let jitter = variance.sqrt() / mean;
    if jitter > MAX_JITTER {
        return None;
    }
    Some(Beacon {
        contacts: times.len(),
        interval_s: median.round().max(0.0) as u64,
        jitter,
    })
}

/// How many connections one sampler remembers at a time.
pub const MAX_SERIES: usize = 2_000;

/// How many observations one connection keeps. Enough for a rhythm, small enough that a
/// long-running window does not grow without a bound.
pub const MAX_OBSERVATIONS: usize = 64;

/// A bounded memory of when each connection was seen, so a rhythm can be read from more
/// than one sample.
///
/// Time is a parameter, as everywhere in this crate: the caller decides what "now" is, and
/// the sampler only remembers. It is deliberately not a clock and not a thread.
#[derive(Clone, Debug, Default)]
pub struct Sampler {
    series: std::collections::BTreeMap<String, Vec<u64>>,
}

impl Sampler {
    /// An empty sampler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that a connection exists at `now`.
    ///
    /// A key that would take the sampler past [`MAX_SERIES`] is dropped rather than kept,
    /// and the oldest series goes first, so memory follows the recent table rather than the
    /// whole day's traffic.
    pub fn observe(&mut self, key: &str, now: u64) {
        if !self.series.contains_key(key)
            && self.series.len() >= MAX_SERIES
            && let Some(oldest) = self.series.keys().next().cloned()
        {
            self.series.remove(&oldest);
        }
        let series = self.series.entry(key.to_owned()).or_default();
        if series.last() == Some(&now) {
            return;
        }
        series.push(now);
        if series.len() > MAX_OBSERVATIONS {
            let excess = series.len() - MAX_OBSERVATIONS;
            series.drain(..excess);
        }
    }

    /// The rhythm this connection is on, when it is on one.
    #[must_use]
    pub fn beacon(&self, key: &str) -> Option<Beacon> {
        self.series.get(key).and_then(|series| beacon(series))
    }

    /// How many connections are being remembered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.series.len()
    }

    /// Whether nothing is remembered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.series.is_empty()
    }

    /// Forget one connection, when it has gone.
    pub fn forget(&mut self, key: &str) {
        self.series.remove(key);
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

    #[test]
    fn a_steady_rhythm_is_a_beacon_and_a_noisy_one_is_not() {
        let steady: Vec<u64> = (0..10).map(|index| 1_700_000_000 + index * 60).collect();
        assert_eq!(steady.len(), 10);
        let found = beacon(&steady).expect("a 60 s rhythm is a beacon");
        assert_eq!(found.interval_s, 60);
        assert_eq!(found.contacts, 10);
        assert!(found.jitter < 0.01);

        let noisy: Vec<u64> = vec![
            1_700_000_000,
            1_700_000_030,
            1_700_000_120,
            1_700_000_150,
            1_700_000_240,
            1_700_000_300,
        ];
        assert!(beacon(&noisy).is_none(), "a wobbling series is not a rhythm");
    }

    #[test]
    fn a_beacon_needs_contacts_inside_the_interval_window() {
        assert!(beacon(&[1, 61, 121, 181, 241]).is_none(), "five is too few");
        let slow: Vec<u64> = (0..8).map(|index| 1_700_000_000 + index * 20).collect();
        assert!(beacon(&slow).is_some(), "20 s is the shortest interval");
        let too_slow: Vec<u64> = (0..8).map(|index| 1_700_000_000 + index * 7_201).collect();
        assert!(beacon(&too_slow).is_none(), "two hours is the longest");
        let duplicates = vec![1_700_000_000; 8];
        assert!(beacon(&duplicates).is_none(), "one instant is not a series");
    }

    #[test]
    fn unsorted_observations_are_sorted_before_they_are_read() {
        let mut times: Vec<u64> = (0..8).map(|index| 1_700_000_000 + index * 30).collect();
        times.reverse();
        assert!(beacon(&times).is_some());
        let mut jittered = times.clone();
        jittered[0] += 1;
        let found = beacon(&jittered).expect("one second of drift is still a rhythm");
        assert!((found.jitter - 0.005).abs() < 0.01, "{}", found.jitter);
    }

    #[test]
    fn a_sampler_turns_repeated_observations_into_a_rhythm() {
        let mut sampler = Sampler::new();
        for step in 0..8 {
            sampler.observe("agent.exe>203.0.113.9:443", 1_700_000_000 + step * 60);
        }
        let found = sampler.beacon("agent.exe>203.0.113.9:443").expect("a rhythm");
        assert_eq!(found.interval_s, 60);
        assert_eq!(found.contacts, 8);
        assert!(sampler.beacon("another").is_none());
        assert_eq!(sampler.len(), 1);
        sampler.forget("agent.exe>203.0.113.9:443");
        assert!(sampler.is_empty());
    }

    #[test]
    fn one_instant_recorded_twice_is_still_one_contact() {
        let mut sampler = Sampler::new();
        for _ in 0..10 {
            sampler.observe("x", 5);
        }
        assert!(sampler.beacon("x").is_none());
    }

    #[test]
    fn a_series_stops_growing_at_its_bound_and_the_sampler_stops_remembering() {
        let mut sampler = Sampler::new();
        for step in 0..(MAX_OBSERVATIONS + 20) {
            sampler.observe("x", u64::try_from(step).unwrap_or(0) * 60);
        }
        let found = sampler.beacon("x").expect("the tail is still a rhythm");
        assert_eq!(found.contacts, MAX_OBSERVATIONS);
        for index in 0..(MAX_SERIES + 5) {
            sampler.observe(&format!("k{index}"), 1);
        }
        assert_eq!(sampler.len(), MAX_SERIES, "the oldest series is dropped");
    }
}
