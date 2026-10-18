//! Listening sockets on Linux, from `/proc`.
//!
//! `/proc/net/tcp` gives the socket table and `/proc/<pid>/fd` gives the inode-to-pid
//! map. Both are read as text, so the collector needs no C library and no unsafe call.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use vnr_core::{ListenerFact, Protocol};

use crate::collect::Outcome;

/// Read TCP listeners and unconnected UDP binds.
#[must_use]
pub fn collect(process_names: &HashMap<u32, String>) -> Outcome<ListenerFact> {
    let owners = socket_owners();
    let mut items = Vec::new();
    let mut seen = HashSet::new();
    let mut read_any = false;
    for (path, protocol) in [
        ("/proc/net/tcp", Protocol::Tcp),
        ("/proc/net/tcp6", Protocol::Tcp),
        ("/proc/net/udp", Protocol::Udp),
        ("/proc/net/udp6", Protocol::Udp),
    ] {
        let Ok(body) = std::fs::read_to_string(path) else {
            continue;
        };
        read_any = true;
        for line in body.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let Some((address_hex, port_hex)) = fields[1].split_once(':') else {
                continue;
            };
            let Ok(port) = u16::from_str_radix(port_hex, 16) else {
                continue;
            };
            if port == 0 {
                continue;
            }
            if protocol == Protocol::Tcp && fields[3] != "0A" {
                continue;
            }
            if protocol == Protocol::Udp {
                let Some((_, remote_port)) = fields[2].split_once(':') else {
                    continue;
                };
                if remote_port != "0000" {
                    continue;
                }
            }
            let Some(address) = parse_address(address_hex, path.ends_with('6')) else {
                continue;
            };
            let inode = fields[9].parse::<u64>().ok();
            let pid = inode.and_then(|inode| owners.get(&inode).copied());
            let identity = format!("{protocol:?}|{address}|{port}|{pid:?}");
            if !seen.insert(identity) {
                continue;
            }
            items.push(ListenerFact {
                protocol,
                address: address.to_string(),
                port,
                pid,
                process: pid.and_then(|pid| process_names.get(&pid).cloned()),
                state: if protocol == Protocol::Tcp {
                    "LISTEN".to_owned()
                } else {
                    "UNCONN".to_owned()
                },
                public: address.is_unspecified() || !address.is_loopback(),
            });
        }
    }
    if !read_any && !Path::new("/proc/net/tcp").exists() {
        return Outcome::Unavailable {
            reason: "The /proc socket table is not readable on this system.".to_owned(),
        };
    }
    Outcome::Items(items)
}

pub(crate) fn parse_address(hex: &str, ipv6: bool) -> Option<IpAddr> {
    if ipv6 {
        if hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (index, chunk) in hex.as_bytes().chunks(8).enumerate() {
            let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        if hex.len() != 8 {
            return None;
        }
        let word = u32::from_str_radix(hex, 16).ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(word.to_le_bytes())))
    }
}

pub(crate) fn socket_owners() -> HashMap<u64, u32> {
    let mut owners = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return owners;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let Some(rest) = target.to_str().and_then(|text| text.strip_prefix("socket:[")) else {
                continue;
            };
            let Some(inode) = rest.strip_suffix(']').and_then(|text| text.parse::<u64>().ok()) else {
                continue;
            };
            owners.entry(inode).or_insert(pid);
        }
    }
    owners
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_little_endian() {
        assert_eq!(
            parse_address("0100007F", false),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            parse_address("00000000", false),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );
    }

    #[test]
    fn rejects_a_malformed_address() {
        assert_eq!(parse_address("zzzz", false), None);
        assert_eq!(parse_address("0100", false), None);
    }
}
