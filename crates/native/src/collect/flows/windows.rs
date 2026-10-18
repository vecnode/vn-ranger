//! Connections on Windows, from the IP helper API via `netstat2`.
//!
//! The table is read once per scan. `associated_pids` is the operating system's own answer
//! to "who holds this socket", and a socket nobody is named for is still reported — with no
//! pid — because "this account cannot see the owner" is a state, not an empty list.

use std::collections::HashMap;

use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info};
use vnr_core::{FlowFact, Protocol};

use crate::collect::Outcome;

use super::sort_and_cap;

/// Read every connected TCP socket on this machine.
#[must_use]
pub fn collect(process_names: &HashMap<u32, String>) -> Outcome<FlowFact> {
    let families = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let sockets = match get_sockets_info(families, ProtocolFlags::TCP) {
        Ok(sockets) => sockets,
        Err(error) => {
            return Outcome::Unavailable {
                reason: format!("The Windows connection table could not be read: {error}"),
            };
        }
    };
    let mut flows = Vec::new();
    for socket in sockets {
        let ProtocolSocketInfo::Tcp(tcp) = socket.protocol_socket_info else {
            continue;
        };
        if tcp.state == TcpState::Listen || tcp.state == TcpState::DeleteTcb || tcp.remote_port == 0 {
            continue;
        }
        let state = format!("{:?}", tcp.state).to_ascii_uppercase();
        let owners: Vec<Option<u32>> = if socket.associated_pids.is_empty() {
            vec![None]
        } else {
            socket.associated_pids.iter().copied().map(Some).collect()
        };
        for pid in owners {
            flows.push(FlowFact {
                protocol: Protocol::Tcp,
                local_addr: tcp.local_addr.to_string(),
                local_port: tcp.local_port,
                remote_addr: tcp.remote_addr.to_string(),
                remote_port: tcp.remote_port,
                state: state.clone(),
                pid,
                process: pid.and_then(|pid| process_names.get(&pid).cloned()),
                bytes: None,
            });
        }
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
