use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::model::packet::PacketState;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SimulationResult {
    pub id: String,
    pub verdict: FinalVerdict,
    pub summary: SimulationSummary,
    pub trace: Vec<TraceStep>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FinalVerdict {
    Drop,
    LocalDelivery,
    Forwarded,
    Redirect,
    Tx,
    Rejected,
    Blackhole,
    Tproxy,
}

impl std::fmt::Display for FinalVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FinalVerdict::Drop => write!(f, "DROP"),
            FinalVerdict::LocalDelivery => write!(f, "LOCAL_DELIVERY"),
            FinalVerdict::Forwarded => write!(f, "FORWARDED"),
            FinalVerdict::Redirect => write!(f, "REDIRECT"),
            FinalVerdict::Tx => write!(f, "TX"),
            FinalVerdict::Rejected => write!(f, "REJECTED"),
            FinalVerdict::Blackhole => write!(f, "BLACKHOLE"),
            FinalVerdict::Tproxy => write!(f, "TPROXY"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SimulationSummary {
    pub verdict: FinalVerdict,
    pub egress_interface: Option<String>,
    pub next_hop: Option<IpAddr>,
    pub matched_rules: Vec<MatchedRuleRef>,
    pub nat_applied: bool,
    pub total_steps: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TraceStep {
    pub seq: u32,
    pub stage: PipelineStage,
    pub description: String,
    pub state_before: PacketState,
    pub state_after: PacketState,
    pub state_changes: Vec<StateChange>,
    pub matched_rules: Vec<MatchedRuleRef>,
    pub decision: StageDecision,
    pub explain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PipelineStage {
    /// 인터페이스 검증 (존재, 상태, 브릿지 멤버 등)
    InterfaceCheck,
    /// ARP 처리 (arp_ignore 등)
    ArpProcess,
    /// L2-only 패킷 바이패스 (ARP, STP 등이 netfilter/routing 건너뜀)
    L2Bypass,
    Xdp,
    /// Reverse Path Filter (sysctl rp_filter)
    RpFilter,
    TcIngress,
    ConntrackIn,
    PreRouting,
    RoutingDecision,
    LocalInput,
    Forward,
    PostRouting,
    /// MTU 검사
    MtuCheck,
    ConntrackConfirm,
}

impl std::fmt::Display for PipelineStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineStage::InterfaceCheck => write!(f, "INTERFACE_CHECK"),
            PipelineStage::ArpProcess => write!(f, "ARP_PROCESS"),
            PipelineStage::L2Bypass => write!(f, "L2_BYPASS"),
            PipelineStage::Xdp => write!(f, "XDP"),
            PipelineStage::RpFilter => write!(f, "RP_FILTER"),
            PipelineStage::TcIngress => write!(f, "TC_INGRESS"),
            PipelineStage::ConntrackIn => write!(f, "CONNTRACK_IN"),
            PipelineStage::PreRouting => write!(f, "PREROUTING"),
            PipelineStage::RoutingDecision => write!(f, "ROUTING"),
            PipelineStage::LocalInput => write!(f, "INPUT"),
            PipelineStage::Forward => write!(f, "FORWARD"),
            PipelineStage::PostRouting => write!(f, "POSTROUTING"),
            PipelineStage::MtuCheck => write!(f, "MTU_CHECK"),
            PipelineStage::ConntrackConfirm => write!(f, "CONNTRACK_CONFIRM"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StageDecision {
    Continue,
    Drop { reason: String },
    /// REJECT — 패킷 거부 (ICMP unreachable 응답 전송)
    Reject { reason: String },
    Accept,
    Stolen,
    Redirect { target: String },
    LocalDelivery,
    ForwardTo { egress_if: String, next_hop: Option<IpAddr> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MatchedRuleRef {
    pub source: RuleSource,
    pub table: String,
    pub chain: String,
    pub rule_index: usize,
    pub rule_summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuleSource {
    Nftables,
    Iptables,
    Xdp,
    Routing,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateChange {
    pub field: String,
    pub from: String,
    pub to: String,
}

/// PacketState 간 diff를 계산
pub fn compute_state_changes(before: &PacketState, after: &PacketState) -> Vec<StateChange> {
    let mut changes = Vec::new();

    // L2 fields
    if before.vlan_id != after.vlan_id {
        changes.push(StateChange {
            field: "vlan_id".to_string(),
            from: format!("{:?}", before.vlan_id),
            to: format!("{:?}", after.vlan_id),
        });
    }
    if before.src_mac != after.src_mac {
        changes.push(StateChange {
            field: "src_mac".to_string(),
            from: format!("{:?}", before.src_mac),
            to: format!("{:?}", after.src_mac),
        });
    }
    if before.dst_mac != after.dst_mac {
        changes.push(StateChange {
            field: "dst_mac".to_string(),
            from: format!("{:?}", before.dst_mac),
            to: format!("{:?}", after.dst_mac),
        });
    }

    // L3 fields
    if before.src_ip != after.src_ip {
        changes.push(StateChange {
            field: "src_ip".to_string(),
            from: format!("{:?}", before.src_ip),
            to: format!("{:?}", after.src_ip),
        });
    }
    if before.dst_ip != after.dst_ip {
        changes.push(StateChange {
            field: "dst_ip".to_string(),
            from: format!("{:?}", before.dst_ip),
            to: format!("{:?}", after.dst_ip),
        });
    }
    if before.src_port != after.src_port {
        changes.push(StateChange {
            field: "src_port".to_string(),
            from: format!("{:?}", before.src_port),
            to: format!("{:?}", after.src_port),
        });
    }
    if before.dst_port != after.dst_port {
        changes.push(StateChange {
            field: "dst_port".to_string(),
            from: format!("{:?}", before.dst_port),
            to: format!("{:?}", after.dst_port),
        });
    }
    if before.mark != after.mark {
        changes.push(StateChange {
            field: "mark".to_string(),
            from: format!("0x{:x}", before.mark),
            to: format!("0x{:x}", after.mark),
        });
    }
    if before.ct_mark != after.ct_mark {
        changes.push(StateChange {
            field: "ct_mark".to_string(),
            from: format!("0x{:x}", before.ct_mark),
            to: format!("0x{:x}", after.ct_mark),
        });
    }
    if before.ct_state != after.ct_state {
        changes.push(StateChange {
            field: "ct_state".to_string(),
            from: before.ct_state.to_string(),
            to: after.ct_state.to_string(),
        });
    }
    if before.egress_if != after.egress_if {
        changes.push(StateChange {
            field: "egress_if".to_string(),
            from: format!("{:?}", before.egress_if),
            to: format!("{:?}", after.egress_if),
        });
    }
    if before.ttl != after.ttl {
        changes.push(StateChange {
            field: "ttl".to_string(),
            from: before.ttl.to_string(),
            to: after.ttl.to_string(),
        });
    }
    if before.dscp != after.dscp {
        changes.push(StateChange {
            field: "dscp".to_string(),
            from: before.dscp.to_string(),
            to: after.dscp.to_string(),
        });
    }
    if before.dnat_applied != after.dnat_applied {
        changes.push(StateChange {
            field: "dnat_applied".to_string(),
            from: before.dnat_applied.to_string(),
            to: after.dnat_applied.to_string(),
        });
    }
    if before.snat_applied != after.snat_applied {
        changes.push(StateChange {
            field: "snat_applied".to_string(),
            from: before.snat_applied.to_string(),
            to: after.snat_applied.to_string(),
        });
    }
    if before.protocol != after.protocol {
        changes.push(StateChange {
            field: "protocol".to_string(),
            from: before.protocol.to_string(),
            to: after.protocol.to_string(),
        });
    }
    if before.icmp_type != after.icmp_type {
        changes.push(StateChange {
            field: "icmp_type".to_string(),
            from: format!("{:?}", before.icmp_type),
            to: format!("{:?}", after.icmp_type),
        });
    }
    if before.icmp_code != after.icmp_code {
        changes.push(StateChange {
            field: "icmp_code".to_string(),
            from: format!("{:?}", before.icmp_code),
            to: format!("{:?}", after.icmp_code),
        });
    }

    changes
}
