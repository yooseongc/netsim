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

use crate::model::scenario::Scenario;
use crate::pipeline::{self, PipelineContext};
use crate::pipeline::context::StageOutcome;
use crate::pipeline::stages;
use crate::trace::{
    FinalVerdict, PipelineStage, SimulationResult, StageDecision,
};

/// 시뮬레이션 실행
pub fn run(scenario: &Scenario) -> SimulationResult {
    let mut ctx = PipelineContext::from_scenario(scenario);

    // --- Stage 0: Interface validation ---
    if let StageOutcome::Terminal(v) = stages::interface_check::check_ingress(&mut ctx) {
        return ctx.finalize(v);
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
    if let StageOutcome::Terminal(v) = stages::bridge::check_bridge(&mut ctx) {
        return ctx.finalize(v);
    }

    // --- ARP processing (after XDP, before L2 bypass) ---
    if let StageOutcome::Terminal(v) = stages::arp::process_arp(&mut ctx) {
        return ctx.finalize(v);
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
    if let StageOutcome::Terminal(v) = stages::sysctl_checks::check_rp_filter(&mut ctx) {
        return ctx.finalize(v);
    }

    // --- sysctl: route_localnet check ---
    if let StageOutcome::Terminal(v) = stages::sysctl_checks::check_route_localnet(&mut ctx) {
        return ctx.finalize(v);
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
            if let StageOutcome::Terminal(v) = stages::sysctl_checks::check_icmp_echo_ignore(&mut ctx) {
                return ctx.finalize(v);
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
            if let StageOutcome::Terminal(v) = stages::sysctl_checks::check_egress_interface(&mut ctx) {
                return ctx.finalize(v);
            }

            // --- sysctl: ip_forward check ---
            if let StageOutcome::Terminal(v) = stages::sysctl_checks::check_ip_forward(&mut ctx) {
                return ctx.finalize(v);
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
            if let StageOutcome::Terminal(v) = stages::mtu_check::check_mtu(&mut ctx) {
                return ctx.finalize(v);
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
    if let StageOutcome::Terminal(v) = stages::mtu_check::check_mtu_output(&mut ctx) {
        return ctx.finalize(v);
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

fn terminal_verdict(decision: &StageDecision) -> Option<FinalVerdict> {
    match decision {
        StageDecision::Drop { .. } => Some(FinalVerdict::Drop),
        StageDecision::Reject { .. } => Some(FinalVerdict::Rejected),
        StageDecision::Stolen => Some(FinalVerdict::Tproxy),
        StageDecision::Redirect { .. } => Some(FinalVerdict::Redirect),
        _ => None,
    }
}
