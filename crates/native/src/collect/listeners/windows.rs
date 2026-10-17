//! Listening sockets on Windows, from the IP helper API via `netstat2`.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info};
use vnr_core::{ListenerFact, Protocol};

use crate::collect::Outcome;

/// Read TCP listeners and unconnected UDP binds.
#[must_use]
pub fn collect(process_names: &HashMap<u32, String>) -> Outcome<ListenerFact> {
    let families = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let protocols = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets = match get_sockets_info(families, protocols) {
        Ok(sockets) => sockets,
        Err(error) => {
            return Outcome::Unavailable {
                reason: format!("The Windows socket table could not be read: {error}"),
            };
        }
    };
    let mut items = Vec::new();
    let mut seen = HashSet::new();
    for socket in sockets {
        match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) if tcp.state == TcpState::Listen => push(
                &mut items,
                &mut seen,
                Protocol::Tcp,
                tcp.local_addr,
                tcp.local_port,
                &socket.associated_pids,
                process_names,
                "LISTEN",
            ),
            ProtocolSocketInfo::Udp(udp) if udp.local_port != 0 => push(
                &mut items,
                &mut seen,
                Protocol::Udp,
                udp.local_addr,
                udp.local_port,
                &socket.associated_pids,
                process_names,
                "UNCONN",
            ),
            _ => {}
        }
    }
    Outcome::Items(items)
}

#[allow(clippy::too_many_arguments)]
fn push(
    items: &mut Vec<ListenerFact>,
    seen: &mut HashSet<String>,
    protocol: Protocol,
    address: IpAddr,
    port: u16,
    pids: &[u32],
    process_names: &HashMap<u32, String>,
    state: &str,
) {
    let public = address.is_unspecified() || !address.is_loopback();
    let owners: Vec<Option<u32>> = if pids.is_empty() {
        vec![None]
    } else {
        pids.iter().copied().map(Some).collect()
    };
    for pid in owners {
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
            state: state.to_owned(),
            public,
        });
    }
}
