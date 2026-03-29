//! NAT application logic
//!
//! Applies NAT actions (DNAT, SNAT, Masquerade, Redirect, Tproxy) to PacketState.

use crate::model::nat::NatAction;
use crate::model::packet::PacketState;

/// NAT 액션을 PacketState에 적용
pub fn apply_nat(
    nat_action: &NatAction,
    state: &mut PacketState,
    interfaces: &[crate::model::interface::Interface],
) {
    match nat_action {
        NatAction::Dnat { addr, port } => {
            if !state.dnat_applied {
                state.original_dst_ip = state.dst_ip;
                state.original_dst_port = state.dst_port;
            }
            if let Some(a) = addr {
                state.dst_ip = Some(*a);
            }
            // ICMP has no ports — only set port for port-based protocols
            if state.has_ports() {
                if let Some(p) = port {
                    state.dst_port = Some(*p);
                }
            }
            state.dnat_applied = true;
        }
        NatAction::Snat { addr, port } => {
            if !state.snat_applied {
                state.original_src_ip = state.src_ip;
                state.original_src_port = state.src_port;
            }
            if let Some(a) = addr {
                state.src_ip = Some(*a);
            }
            if state.has_ports() {
                if let Some(p) = port {
                    state.src_port = Some(*p);
                }
            }
            state.snat_applied = true;
        }
        NatAction::Masquerade { port } => {
            // Use egress interface's IP address matching packet's address family
            if !state.snat_applied {
                state.original_src_ip = state.src_ip;
                state.original_src_port = state.src_port;
            }
            if let Some(egress_name) = &state.egress_if {
                let masq_ip = crate::model::interface::find_interface_ip(interfaces, egress_name, state.src_ip);
                if let Some(ip) = masq_ip {
                    state.src_ip = Some(ip);
                }
            }
            if state.has_ports() {
                if let Some(p) = port {
                    state.src_port = Some(*p);
                }
            }
            state.snat_applied = true;
        }
        NatAction::Redirect { port } => {
            // REDIRECT changes dst to local address on ingress interface
            if !state.dnat_applied {
                state.original_dst_ip = state.dst_ip;
                state.original_dst_port = state.dst_port;
            }
            // Use ingress interface's IP matching packet's address family
            let local_ip = crate::model::interface::find_interface_ip(interfaces, &state.ingress_if, state.dst_ip);
            if let Some(ip) = local_ip {
                state.dst_ip = Some(ip);
            }
            if state.has_ports() {
                if let Some(p) = port {
                    state.dst_port = Some(*p);
                }
            }
            state.dnat_applied = true;
        }
        NatAction::Tproxy { addr, port, mark } => {
            if !state.dnat_applied {
                state.original_dst_ip = state.dst_ip;
                state.original_dst_port = state.dst_port;
            }
            if let Some(a) = addr {
                state.dst_ip = Some(*a);
            }
            if state.has_ports() {
                state.dst_port = Some(*port);
            }
            if let Some(m) = mark {
                state.mark = *m;
            }
            state.dnat_applied = true;
            state.tproxy_applied = true;
        }
    }
}
