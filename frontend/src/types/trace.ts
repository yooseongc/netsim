export interface SimulationResponse {
  simulation_id: string;
  status: 'completed' | 'error';
  result: SimulationResult;
}

export interface SimulationResult {
  id: string;
  verdict: FinalVerdict;
  summary: SimulationSummary;
  trace: TraceStep[];
  created_at: string;
}

export interface SimulationSummary {
  verdict: FinalVerdict;
  egress_interface: string | null;
  next_hop: string | null;
  matched_rules: MatchedRuleRef[];
  nat_applied: boolean;
  total_steps: number;
}

export type FinalVerdict =
  | 'drop'
  | 'local_delivery'
  | 'forwarded'
  | 'redirect'
  | 'tx'
  | 'rejected'
  | 'blackhole'
  | 'tproxy'
  | 'sent';

export interface TraceStep {
  seq: number;
  stage: PipelineStage;
  description: string;
  state_before: PacketState;
  state_after: PacketState;
  state_changes: StateChange[];
  matched_rules: MatchedRuleRef[];
  decision: StageDecision;
  explain: string;
}

export type PipelineStage =
  | 'interface_check'
  | 'arp_process'
  | 'l2_bypass'
  | 'xdp'
  | 'rp_filter'
  | 'tc_ingress'
  | 'conntrack_in'
  | 'pre_routing'
  | 'routing_decision'
  | 'local_input'
  | 'forward'
  | 'post_routing'
  | 'mtu_check'
  | 'conntrack_confirm'
  | 'pre_routing_raw'
  | 'bridge_forward'
  | 'output'
  | 'br_nf_prerouting'
  | 'br_nf_forward'
  | 'br_nf_postrouting'
  | 'loopback_delivery'
  | 'reroute'
  | 'bridge_fdb_lookup'
  | 'arp_resolve'
  | 'l2_rewrite';

export interface PacketState {
  ethertype: string;
  vlan_id: number | null;
  src_mac: string | null;
  dst_mac: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string;
  mark: number;
  ct_mark: number;
  ct_state: string;
  ingress_if: string;
  egress_if: string | null;
  ttl: number;
  dscp: number;
  icmp_type: number | null;
  icmp_code: number | null;
  tcp_flags: { syn: boolean; ack: boolean; fin: boolean; rst: boolean; psh: boolean; urg: boolean } | null;
  arp_op: number | null;
  packet_length: number | null;
  df_flag: boolean;
  dnat_applied: boolean;
  snat_applied: boolean;
  tproxy_applied: boolean;
  original_dst_ip: string | null;
  original_dst_port: number | null;
  original_src_ip: string | null;
  original_src_port: number | null;
}

export type StageDecision =
  | { type: 'continue' }
  | { type: 'drop'; reason: string }
  | { type: 'reject'; reason: string }
  | { type: 'accept' }
  | { type: 'stolen' }
  | { type: 'redirect'; target: string }
  | { type: 'local_delivery' }
  | { type: 'forward_to'; egress_if: string; next_hop: string | null };

export interface MatchedRuleRef {
  source: RuleSource;
  table: string;
  chain: string;
  rule_index: number;
  rule_summary: string;
}

export type RuleSource = 'nftables' | 'iptables' | 'xdp' | 'routing';

export interface StateChange {
  field: string;
  from: string;
  to: string;
}
