//! 시뮬레이션 오케스트레이터
//!
//! Scenario를 받아 Linux 커널 ingress 패킷 처리 경로를 순서대로 실행하고
//! SimulationResult를 반환한다.
//!
//! 파이프라인 순서:
//!   NIC → XDP → tc ingress → conntrack lookup →
//!   PREROUTING (raw→mangle→nat/DNAT) →
//!   Routing Decision →
//!     LOCAL: INPUT chains → LOCAL_DELIVERY
//!     FORWARD: FORWARD chains → POSTROUTING (SNAT/MASQ) → FORWARDED
//!
//! sysctl 파라미터가 다음에 영향:
//!   - ip_forward: 포워딩 허용 여부
//!   - route_localnet: 127.0.0.0/8 라우팅 허용
//!   - rp_filter: Reverse Path 필터링
//!   - icmp_echo_ignore_all: ICMP echo 무시

use std::net::IpAddr;

use crate::model::interface::{find_interface, Interface, InterfaceKind};
use crate::model::packet::{EtherType, IpProtocol, PacketState};
use crate::model::scenario::Scenario;
use crate::model::sysctl::{RpFilterMode, SysctlConfig};
use crate::pipeline::{self, PipelineContext, StageResult};
use crate::trace::{
    FinalVerdict, PipelineStage, SimulationResult, StageDecision,
};

/// 시뮬레이션 실행
pub fn run(scenario: &Scenario) -> SimulationResult {
    let mut ctx = PipelineContext::from_scenario(scenario);
    let sysctl = &scenario.sysctl;

    // --- Stage 0: Interface validation ---
    {
        // (a) Interface existence check
        let ingress_iface = find_interface(&scenario.interfaces, &ctx.packet.ingress_if);
        match ingress_iface {
            None => {
                ctx.record_info_step(
                    PipelineStage::InterfaceCheck,
                    "ingress interface check",
                    StageDecision::Drop {
                        reason: "Unknown ingress interface".to_string(),
                    },
                    format!(
                        "Ingress interface '{}' does not exist in scenario interfaces",
                        ctx.packet.ingress_if
                    ),
                );
                return ctx.finalize(FinalVerdict::Drop);
            }
            Some(iface) => {
                // (b) Interface state check
                if !iface.is_up() {
                    ctx.record_info_step(
                        PipelineStage::InterfaceCheck,
                        "ingress interface state check",
                        StageDecision::Drop {
                            reason: "Ingress interface is down".to_string(),
                        },
                        format!(
                            "Ingress interface '{}' is in DOWN state — packets cannot be received",
                            ctx.packet.ingress_if
                        ),
                    );
                    return ctx.finalize(FinalVerdict::Drop);
                }

                // (c) Physical NIC ingress frame size check
                if matches!(iface.kind, InterfaceKind::Physical) {
                    if let Some(pkt_len) = ctx.packet.packet_length {
                        let l2_max_frame = iface.mtu.saturating_add(18).max(9216);
                        if pkt_len > l2_max_frame {
                            ctx.record_info_step(
                                PipelineStage::InterfaceCheck,
                                "physical NIC frame size check",
                                StageDecision::Drop {
                                    reason: format!(
                                        "Frame too large for physical NIC (max={})",
                                        l2_max_frame
                                    ),
                                },
                                format!(
                                    "Packet length {} exceeds physical NIC '{}' max receive frame size {} \
                                     (MTU={} + 18 L2 overhead, min 9216 jumbo). \
                                     Physical NICs drop oversized frames at driver level.",
                                    pkt_len, ctx.packet.ingress_if, l2_max_frame, iface.mtu
                                ),
                            );
                            return ctx.finalize(FinalVerdict::Drop);
                        }
                    }
                }
            }
        }
    }

    // --- Stage 1: XDP ---
    {
        let state_before = ctx.packet.clone();
        let result = pipeline::xdp::execute(&scenario.xdp, &mut ctx.packet);
        ctx.record_step(PipelineStage::Xdp, &state_before, &result);
        match &result.decision {
            StageDecision::Drop { .. } => {
                return ctx.finalize(FinalVerdict::Drop);
            }
            StageDecision::Redirect { target } => {
                let verdict = if *target == ctx.packet.ingress_if {
                    FinalVerdict::Tx
                } else {
                    FinalVerdict::Redirect
                };
                return ctx.finalize(verdict);
            }
            _ => {}
        }
    }

    // --- Bridge member check (after XDP, before L3 processing) ---
    if let Some(ingress_iface) = find_interface(&scenario.interfaces, &ctx.packet.ingress_if) {
        if let Some(master) = &ingress_iface.master {
            ctx.record_info_step(
                PipelineStage::InterfaceCheck,
                "bridge member detection",
                StageDecision::Continue,
                format!(
                    "Interface '{}' is a member of bridge '{}'.",
                    ctx.packet.ingress_if, master
                ),
            );

            if !sysctl.bridge_nf_call_iptables {
                ctx.record_info_step(
                    PipelineStage::BridgeForward,
                    "bridge L2 forwarding",
                    StageDecision::Continue,
                    format!(
                        "bridge_nf_call_iptables=0: packet forwarded at L2 by bridge '{}' \
                         without passing through IP netfilter stack.",
                        master
                    ),
                );
                return ctx.finalize(FinalVerdict::Forwarded);
            }
            // bridge_nf_call_iptables=true: continue with normal IP stack
        }
    }

    // --- ARP processing (after XDP, before L2 bypass) ---
    if matches!(ctx.packet.ethertype, EtherType::Arp) {
        let arp_conf = sysctl.get_interface_conf(&ctx.packet.ingress_if);
        if arp_conf.arp_ignore >= 1 {
            let target_ip = scenario.packet.arp.as_ref().and_then(|a| a.target_ip);
            let mut should_drop = false;
            let mut explain = String::new();

            if let Some(tip) = target_ip {
                let iface_has_ip = find_interface(&scenario.interfaces, &ctx.packet.ingress_if)
                    .map(|iface| iface.addresses.iter().any(|a| a.ip == tip))
                    .unwrap_or(false);

                if !iface_has_ip {
                    should_drop = true;
                    explain = format!(
                        "arp_ignore={}: ARP target IP {} is not configured on ingress interface '{}' — ARP reply suppressed",
                        arp_conf.arp_ignore, tip, ctx.packet.ingress_if
                    );
                } else if arp_conf.arp_ignore >= 2 {
                    let sender_ip = scenario.packet.arp.as_ref().and_then(|a| a.sender_ip);
                    if let Some(sip) = sender_ip {
                        let same_subnet = find_interface(&scenario.interfaces, &ctx.packet.ingress_if)
                            .map(|iface| {
                                iface.addresses.iter().any(|a| is_same_subnet(&a.ip, &sip, a.prefix_len))
                            })
                            .unwrap_or(false);
                        if !same_subnet {
                            should_drop = true;
                            explain = format!(
                                "arp_ignore={}: ARP sender IP {} is not in the same subnet as any address on '{}' — ARP reply suppressed",
                                arp_conf.arp_ignore, sip, ctx.packet.ingress_if
                            );
                        }
                    }
                }
            }

            if should_drop {
                ctx.record_info_step(
                    PipelineStage::ArpProcess,
                    "arp_ignore check",
                    StageDecision::Drop {
                        reason: format!("ARP reply suppressed by arp_ignore={}", arp_conf.arp_ignore),
                    },
                    explain,
                );
                return ctx.finalize(FinalVerdict::Drop);
            }
        }
    }

    // L2-only 패킷은 XDP 이후 netfilter/routing 건너뛰기
    if ctx.packet.ethertype.is_l2_only() {
        ctx.record_info_step(
            PipelineStage::L2Bypass,
            "L2 bypass",
            StageDecision::LocalDelivery,
            format!(
                "L2-only packet ({}) — bypasses netfilter and routing.",
                ctx.packet.ethertype
            ),
        );
        return ctx.finalize(FinalVerdict::LocalDelivery);
    }

    // --- Stage 2: tc ingress ---
    {
        let state_before = ctx.packet.clone();
        let result = pipeline::tc_ingress::execute(&ctx.packet);
        ctx.record_step(PipelineStage::TcIngress, &state_before, &result);
    }

    // --- Stage 3-4: PREROUTING (split into raw → conntrack → mangle/nat) ---
    {
        let all_prerouting_chains = pipeline::collect_chains_for_hook(
            &scenario.netfilter,
            &crate::model::netfilter::NfHook::Prerouting,
        );
        let all_table_chains = pipeline::collect_all_chains_in_tables(&scenario.netfilter);

        let (raw_chains, post_ct_chains): (Vec<_>, Vec<_>) =
            all_prerouting_chains.into_iter().partition(|c| c.priority <= -200);

        // (a) Evaluate RAW chains (before conntrack)
        if !raw_chains.is_empty() {
            let state_before = ctx.packet.clone();
            let result = pipeline::evaluate_chains_subset(
                &raw_chains,
                "PREROUTING_RAW",
                &mut ctx.packet,
                &scenario.interfaces,
                &all_table_chains,
            );
            ctx.record_step(PipelineStage::PreRoutingRaw, &state_before, &result);
            if let Some(verdict) = terminal_verdict(&result.decision) {
                return ctx.finalize(verdict);
            }
        }

        // (b) Conntrack lookup (after raw, before mangle/nat)
        ctx.record_info_step(
            PipelineStage::ConntrackIn,
            "conntrack lookup",
            StageDecision::Continue,
            format!(
                "Conntrack lookup: packet classified as ct_state={} (user-declared)",
                ctx.packet.ct_state
            ),
        );

        // (c) Evaluate post-conntrack chains (mangle, nat, etc.)
        {
            let state_before = ctx.packet.clone();
            let result = pipeline::evaluate_chains_subset(
                &post_ct_chains,
                "PREROUTING",
                &mut ctx.packet,
                &scenario.interfaces,
                &all_table_chains,
            );
            ctx.record_step(PipelineStage::PreRouting, &state_before, &result);
            // TPROXY: do NOT return Stolen — packet continues through routing → INPUT
            if ctx.packet.tproxy_applied {
                // TPROXY sets mark and dst, packet continues through normal routing path
            } else if let Some(verdict) = terminal_verdict(&result.decision) {
                return ctx.finalize(verdict);
            }
        }
    }

    // --- sysctl: rp_filter (Reverse Path Filtering) ---
    if let Some(drop_result) = check_rp_filter(
        sysctl, &ctx.packet, &scenario.ip_rules, &scenario.routing_tables, &scenario.interfaces,
    ) {
        ctx.record_info_step(
            PipelineStage::RpFilter,
            "rp_filter check",
            drop_result.decision.clone(),
            drop_result.explain.clone(),
        );
        return ctx.finalize(FinalVerdict::Drop);
    }

    // --- sysctl: route_localnet check ---
    if let Some(dst) = ctx.packet.dst_ip {
        if is_loopback(&dst) && !sysctl.is_route_localnet(&ctx.packet.ingress_if) {
            ctx.record_info_step(
                PipelineStage::RoutingDecision,
                "route_localnet check",
                StageDecision::Drop {
                    reason: "Destination is loopback but route_localnet is disabled".to_string(),
                },
                format!(
                    "Packet destination {} is in loopback range. \
                     net.ipv4.conf.{}.route_localnet=0 (disabled). \
                     Enable route_localnet to allow DNAT to 127.0.0.1.",
                    dst, ctx.packet.ingress_if
                ),
            );
            return ctx.finalize(FinalVerdict::Drop);
        }
    }

    // --- Stage 5: Routing Decision ---
    let routing_decision = {
        let state_before = ctx.packet.clone();
        let result = pipeline::routing::execute(
            &scenario.ip_rules,
            &scenario.routing_tables,
            &scenario.interfaces,
            &mut ctx.packet,
        );
        ctx.record_step(PipelineStage::RoutingDecision, &state_before, &result);
        result.decision.clone()
    };

    match &routing_decision {
        StageDecision::LocalDelivery => {
            // --- sysctl: icmp_echo_ignore_all ---
            if sysctl.icmp_echo_ignore_all()
                && ctx.packet.protocol.is_icmp()
                && is_icmp_echo_request(&ctx.packet)
            {
                ctx.record_info_step(
                    PipelineStage::LocalInput,
                    "icmp_echo_ignore_all",
                    StageDecision::Drop {
                        reason: "ICMP echo ignored by icmp_echo_ignore_all=1".to_string(),
                    },
                    "net.ipv4.icmp_echo_ignore_all=1 — all ICMP echo requests silently dropped",
                );
                return ctx.finalize(FinalVerdict::Drop);
            }

            // --- Stage 6a: INPUT chains ---
            {
                let state_before = ctx.packet.clone();
                let result = pipeline::local_input::execute(&scenario.netfilter, &mut ctx.packet, &scenario.interfaces);
                ctx.record_step(PipelineStage::LocalInput, &state_before, &result);
                if let Some(verdict) = terminal_verdict(&result.decision) {
                    return ctx.finalize(verdict);
                }
            }
            ctx.finalize(FinalVerdict::LocalDelivery)
        }
        StageDecision::ForwardTo { .. } => {
            // --- (d) Egress interface existence + state check ---
            if let Some(ref egress_name) = ctx.packet.egress_if {
                match find_interface(&scenario.interfaces, egress_name) {
                    None => {
                        ctx.record_info_step(
                            PipelineStage::InterfaceCheck,
                            "egress interface check",
                            StageDecision::Drop {
                                reason: "Unknown egress interface".to_string(),
                            },
                            format!(
                                "Egress interface '{}' does not exist in scenario interfaces",
                                egress_name
                            ),
                        );
                        return ctx.finalize(FinalVerdict::Drop);
                    }
                    Some(egress_iface) if !egress_iface.is_up() => {
                        ctx.record_info_step(
                            PipelineStage::InterfaceCheck,
                            "egress interface state check",
                            StageDecision::Drop {
                                reason: "Egress interface is down".to_string(),
                            },
                            format!(
                                "Egress interface '{}' is in DOWN state — packet cannot be forwarded",
                                egress_name
                            ),
                        );
                        return ctx.finalize(FinalVerdict::Drop);
                    }
                    _ => {} // exists and up
                }
            }

            // --- sysctl: ip_forward check ---
            if !sysctl.is_forwarding_enabled(&ctx.packet.ingress_if) {
                ctx.record_info_step(
                    PipelineStage::Forward,
                    "ip_forward disabled",
                    StageDecision::Drop {
                        reason: "IP forwarding disabled".to_string(),
                    },
                    format!(
                        "net.ipv4.ip_forward=0 — packet requires forwarding but forwarding is disabled on {}",
                        ctx.packet.ingress_if
                    ),
                );
                return ctx.finalize(FinalVerdict::Drop);
            }

            // --- Stage 6b: FORWARD chains ---
            {
                let state_before = ctx.packet.clone();
                let result = pipeline::forward::execute(&scenario.netfilter, &mut ctx.packet, &scenario.interfaces);
                ctx.record_step(PipelineStage::Forward, &state_before, &result);
                if let Some(verdict) = terminal_verdict(&result.decision) {
                    return ctx.finalize(verdict);
                }
            }

            // --- Stage 7: POSTROUTING ---
            {
                let state_before = ctx.packet.clone();
                let result = pipeline::postrouting::execute(&scenario.netfilter, &mut ctx.packet, &scenario.interfaces);
                ctx.record_step(PipelineStage::PostRouting, &state_before, &result);
                if let Some(verdict) = terminal_verdict(&result.decision) {
                    return ctx.finalize(verdict);
                }
            }

            // --- (e) MTU check ---
            if let Some(ref egress_name) = ctx.packet.egress_if {
                if let Some(egress_iface) = find_interface(&scenario.interfaces, egress_name) {
                    let mtu = egress_iface.mtu;
                    if let Some(pkt_len) = ctx.packet.packet_length {
                        if pkt_len > mtu {
                            if ctx.packet.df_flag {
                                ctx.record_info_step(
                                    PipelineStage::MtuCheck,
                                    "MTU exceeded with DF flag",
                                    StageDecision::Drop {
                                        reason: "Packet exceeds MTU and DF flag is set (ICMP Fragmentation Needed would be sent)".to_string(),
                                    },
                                    format!(
                                        "Packet length {} exceeds egress interface '{}' MTU {} and DF (Don't Fragment) flag is set. \
                                         Kernel would send ICMP Fragmentation Needed (Type 3, Code 4) back to sender.",
                                        pkt_len, egress_name, mtu
                                    ),
                                );
                                return ctx.finalize(FinalVerdict::Drop);
                            } else {
                                ctx.record_info_step(
                                    PipelineStage::MtuCheck,
                                    "MTU exceeded, fragmentation needed",
                                    StageDecision::Continue,
                                    format!(
                                        "Packet length {} exceeds egress interface '{}' MTU {}. \
                                         Packet would be fragmented before transmission.",
                                        pkt_len, egress_name, mtu
                                    ),
                                );
                            }
                        }
                    } else {
                        // packet_length unknown — record informational step
                        ctx.record_info_step(
                            PipelineStage::MtuCheck,
                            "MTU check skipped",
                            StageDecision::Continue,
                            "MTU check skipped: packet length not specified",
                        );
                    }
                }
            }

            // --- Stage 8: conntrack confirm ---
            ctx.record_info_step(
                PipelineStage::ConntrackConfirm,
                "conntrack confirm",
                StageDecision::Continue,
                "Conntrack entry confirmed for forwarded packet",
            );

            ctx.finalize(FinalVerdict::Forwarded)
        }
        StageDecision::Drop { .. } => {
            ctx.finalize(FinalVerdict::Drop)
        }
        StageDecision::Reject { .. } => {
            ctx.finalize(FinalVerdict::Rejected)
        }
        StageDecision::Stolen => {
            ctx.finalize(FinalVerdict::Tproxy)
        }
        StageDecision::Redirect { .. } => {
            ctx.finalize(FinalVerdict::Redirect)
        }
        _ => {
            ctx.finalize(FinalVerdict::Drop)
        }
    }
}

/// Reverse Path Filter 검사
fn check_rp_filter(
    sysctl: &SysctlConfig,
    state: &PacketState,
    ip_rules: &[crate::model::policy_routing::IpRule],
    routing_tables: &[crate::model::routing::RoutingTable],
    interfaces: &[Interface],
) -> Option<StageResult> {
    let mode = sysctl.rp_filter_mode(&state.ingress_if);
    if matches!(mode, RpFilterMode::Off) {
        return None;
    }

    let src_ip = match state.src_ip {
        Some(ip) => ip,
        None => return None, // L2-only, skip
    };

    // src_ip에 대해 역방향 라우팅 조회
    let reverse_result = pipeline::routing::reverse_path_lookup(
        ip_rules, routing_tables, interfaces, &src_ip,
    );

    match mode {
        RpFilterMode::Strict => {
            // strict: 역라우팅 결과의 egress가 ingress와 같아야 함
            match reverse_result {
                Some(egress_if) if egress_if == state.ingress_if => None,
                Some(egress_if) => Some(StageResult::drop(
                    format!("rp_filter strict: reverse route for {} via {} != ingress {}", src_ip, egress_if, state.ingress_if),
                    format!(
                        "Reverse path filter (strict): source {} would be routed via {}, but arrived on {}. \
                         Set net.ipv4.conf.{}.rp_filter=0 to disable.",
                        src_ip, egress_if, state.ingress_if, state.ingress_if
                    ),
                )),
                None => Some(StageResult::drop(
                    format!("rp_filter strict: no reverse route for {}", src_ip),
                    format!(
                        "Reverse path filter (strict): no route found for source {}. \
                         Set net.ipv4.conf.{}.rp_filter=0 to disable.",
                        src_ip, state.ingress_if
                    ),
                )),
            }
        }
        RpFilterMode::Loose => {
            // loose: 어떤 인터페이스든 역라우팅 가능하면 통과
            match reverse_result {
                Some(_) => None,
                None => Some(StageResult::drop(
                    format!("rp_filter loose: no reverse route for {}", src_ip),
                    format!(
                        "Reverse path filter (loose): no route found for source {}. \
                         Set net.ipv4.conf.{}.rp_filter=0 to disable.",
                        src_ip, state.ingress_if
                    ),
                )),
            }
        }
        RpFilterMode::Off => None,
    }
}

fn is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn is_icmp_echo_request(state: &PacketState) -> bool {
    match state.protocol {
        IpProtocol::Icmp => state.icmp_type == Some(8),
        IpProtocol::Icmpv6 => state.icmp_type == Some(128),
        _ => false,
    }
}

/// 두 IP가 같은 서브넷에 있는지 확인
fn is_same_subnet(a: &IpAddr, b: &IpAddr, prefix_len: u8) -> bool {
    match (a, b) {
        (IpAddr::V4(a4), IpAddr::V4(b4)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0u32
            } else {
                !0u32 << (32 - prefix_len)
            };
            let a_bits = u32::from(*a4);
            let b_bits = u32::from(*b4);
            (a_bits & mask) == (b_bits & mask)
        }
        (IpAddr::V6(a6), IpAddr::V6(b6)) => {
            if prefix_len > 128 {
                return false;
            }
            let a_bits = u128::from(*a6);
            let b_bits = u128::from(*b6);
            let mask = if prefix_len == 0 {
                0u128
            } else {
                !0u128 << (128 - prefix_len)
            };
            (a_bits & mask) == (b_bits & mask)
        }
        _ => false, // different families
    }
}

fn terminal_verdict(decision: &StageDecision) -> Option<FinalVerdict> {
    match decision {
        StageDecision::Drop { .. } => Some(FinalVerdict::Drop),
        StageDecision::Reject { .. } => Some(FinalVerdict::Rejected),
        StageDecision::Stolen => Some(FinalVerdict::Tproxy),
        StageDecision::Redirect { .. } => Some(FinalVerdict::Redirect),
        _ => None,
    }
}

/// 로컬 발신 패킷 시뮬레이션 (OUTPUT 경로)
///
/// 파이프라인:
///   OUTPUT chains (raw → conntrack → mangle → filter → nat)
///   → Routing Decision (post-OUTPUT)
///   → POSTROUTING chains
///   → egress MTU check
///   → conntrack confirm
///   → SENT
pub fn run_output(scenario: &Scenario) -> SimulationResult {
    let mut ctx = PipelineContext::from_scenario(scenario);

    // --- Stage 1: OUTPUT chains ---
    {
        let all_output_chains = pipeline::collect_chains_for_hook(
            &scenario.netfilter,
            &crate::model::netfilter::NfHook::Output,
        );
        let all_table_chains = pipeline::collect_all_chains_in_tables(&scenario.netfilter);

        // Split: raw (priority <= -200) vs post-conntrack
        let (raw_chains, post_ct_chains): (Vec<_>, Vec<_>) =
            all_output_chains.into_iter().partition(|c| c.priority <= -200);

        // (a) RAW chains
        if !raw_chains.is_empty() {
            let state_before = ctx.packet.clone();
            let result = pipeline::evaluate_chains_subset(
                &raw_chains,
                "OUTPUT_RAW",
                &mut ctx.packet,
                &scenario.interfaces,
                &all_table_chains,
            );
            ctx.record_step(PipelineStage::Output, &state_before, &result);
            if let Some(verdict) = terminal_verdict(&result.decision) {
                return ctx.finalize(verdict);
            }
        }

        // (b) Conntrack
        ctx.record_info_step(
            PipelineStage::ConntrackIn,
            "conntrack lookup (output)",
            StageDecision::Continue,
            format!(
                "Conntrack lookup for locally-originated packet: ct_state={} (user-declared)",
                ctx.packet.ct_state
            ),
        );

        // (c) Post-conntrack OUTPUT chains (mangle, filter, nat)
        {
            let state_before = ctx.packet.clone();
            let result = pipeline::evaluate_chains_subset(
                &post_ct_chains,
                "OUTPUT",
                &mut ctx.packet,
                &scenario.interfaces,
                &all_table_chains,
            );
            ctx.record_step(PipelineStage::Output, &state_before, &result);
            if let Some(verdict) = terminal_verdict(&result.decision) {
                return ctx.finalize(verdict);
            }
        }
    }

    // --- Stage 2: Routing Decision (post-OUTPUT) ---
    {
        let state_before = ctx.packet.clone();
        let result = pipeline::routing::execute(
            &scenario.ip_rules,
            &scenario.routing_tables,
            &scenario.interfaces,
            &mut ctx.packet,
        );
        ctx.record_step(PipelineStage::RoutingDecision, &state_before, &result);

        match &result.decision {
            StageDecision::Drop { .. } => {
                return ctx.finalize(FinalVerdict::Drop);
            }
            StageDecision::Reject { .. } => {
                return ctx.finalize(FinalVerdict::Rejected);
            }
            _ => {}
        }
    }

    // --- Stage 3: POSTROUTING chains ---
    {
        let state_before = ctx.packet.clone();
        let result =
            pipeline::postrouting::execute(&scenario.netfilter, &mut ctx.packet, &scenario.interfaces);
        ctx.record_step(PipelineStage::PostRouting, &state_before, &result);
        if let Some(verdict) = terminal_verdict(&result.decision) {
            return ctx.finalize(verdict);
        }
    }

    // --- Stage 4: Egress MTU check ---
    if let Some(ref egress_name) = ctx.packet.egress_if {
        if let Some(egress_iface) = find_interface(&scenario.interfaces, egress_name) {
            let mtu = egress_iface.mtu;
            if let Some(pkt_len) = ctx.packet.packet_length {
                if pkt_len > mtu {
                    if ctx.packet.df_flag {
                        ctx.record_info_step(
                            PipelineStage::MtuCheck,
                            "MTU exceeded with DF flag",
                            StageDecision::Drop {
                                reason: "Packet exceeds MTU and DF flag is set".to_string(),
                            },
                            format!(
                                "Packet length {} exceeds egress interface '{}' MTU {} and DF flag is set.",
                                pkt_len, egress_name, mtu
                            ),
                        );
                        return ctx.finalize(FinalVerdict::Drop);
                    } else {
                        ctx.record_info_step(
                            PipelineStage::MtuCheck,
                            "MTU exceeded, fragmentation needed",
                            StageDecision::Continue,
                            format!(
                                "Packet length {} exceeds egress interface '{}' MTU {}. \
                                 Packet would be fragmented before transmission.",
                                pkt_len, egress_name, mtu
                            ),
                        );
                    }
                }
            }
        }
    }

    // --- Stage 5: Conntrack confirm ---
    ctx.record_info_step(
        PipelineStage::ConntrackConfirm,
        "conntrack confirm",
        StageDecision::Continue,
        "Conntrack entry confirmed for locally-originated packet",
    );

    ctx.finalize(FinalVerdict::Sent)
}
