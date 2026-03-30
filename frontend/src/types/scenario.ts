// =============================================================================
// Types matching Rust backend serde serialization (source of truth)
// =============================================================================

// --- Address / Interface ---

export type AddressScope = 'global' | 'link' | 'host';

export interface InterfaceAddress {
  ip: string;        // IpAddr serialized as string
  prefix_len: number;
  scope?: AddressScope; // #[serde(default)] -> "global"
}

export type InterfaceState = 'up' | 'down';

// InterfaceKind: externally-tagged enum with rename_all = "lowercase"
// Simple variants serialize as strings, Other(String) as {"other": "..."}
export type InterfaceKind =
  | 'loopback'
  | 'physical'
  | 'veth'
  | 'bridge'
  | 'vlan'
  | 'bond'
  | 'tun'
  | 'tap'
  | 'wireguard'
  | { other: string };

export interface Interface {
  name: string;
  index: number;
  mac?: string | null;
  addresses?: InterfaceAddress[];       // #[serde(default)] Vec
  mtu?: number;                         // #[serde(default = "default_mtu")] -> 1500
  state?: InterfaceState;               // #[serde(default)] -> "up"
  kind?: InterfaceKind;                 // #[serde(default)] -> "physical"

  // Virtual interface relationships
  veth_peer?: string | null;
  bridge_members?: string[];
  master?: string | null;
  vlan_parent?: string | null;
  vlan_id?: number | null;
  bond_members?: string[];
}

// --- Routing ---

export type RouteScope = 'global' | 'link' | 'host' | 'nowhere';

export type RouteType =
  | 'unicast'
  | 'local'
  | 'broadcast'
  | 'blackhole'
  | 'unreachable'
  | 'prohibit'
  | 'throw';

export interface Route {
  destination: string;  // IpNet -> "10.0.0.0/24"
  gateway?: string | null;
  dev?: string | null;
  src?: string | null;
  metric?: number;      // #[serde(default)] -> 0
  scope?: RouteScope;
  route_type?: RouteType;
  mtu?: number | null;
}

export interface RoutingTable {
  id: number;
  name?: string | null;
  routes?: Route[];
}

// --- Policy Routing ---

export interface PortRange {
  start: number;
  end: number;
}

export interface RuleSelector {
  from?: string | null;   // IpNet
  to?: string | null;
  fwmark?: number | null;
  fwmask?: number | null;
  iif?: string | null;
  oif?: string | null;
  tos?: number | null;
  ipproto?: number | null;  // u8 in Rust
  sport?: PortRange | null;
  dport?: PortRange | null;
}

// RuleAction: externally-tagged enum with rename_all = "lowercase"
// Lookup(u32) -> {"lookup": 42}
// Blackhole -> "blackhole"
export type RuleAction =
  | { lookup: number }
  | 'blackhole'
  | 'unreachable'
  | 'prohibit';

export interface IpRule {
  priority: number;
  selector?: RuleSelector;  // #[serde(default)]
  action: RuleAction;
}

// --- Netfilter ---

export type NfFamily = 'ip' | 'ip6' | 'inet' | 'bridge' | 'arp';

export type NfChainType = 'filter' | 'nat' | 'route' | 'mangle';

export type NfHook = 'prerouting' | 'input' | 'forward' | 'output' | 'postrouting';

export type NfVerdict = 'accept' | 'drop' | 'reject' | 'queue' | 'continue';

// --- NfMatch: internally tagged with #[serde(tag = "type", rename_all = "snake_case")] ---

export type IpField = 'saddr' | 'daddr' | 'protocol' | 'version' | 'length' | 'dscp' | 'ttl';

export type TransportProto = 'tcp' | 'udp' | 'icmp' | 'icmpv6';

export type TransportField = 'sport' | 'dport' | 'flags' | 'icmp_type' | 'icmp_code';

export type MatchOp = 'eq' | 'neq' | 'lt' | 'gt' | 'lte' | 'gte' | 'in';

export type MetaKey = 'mark' | 'protocol' | 'length' | 'iifname' | 'oifname' | 'skuid' | 'nfproto' | 'l4proto';

export type CtKey = 'state' | 'mark' | 'status' | 'direction' | 'expiration';

export type NfMatch =
  | { type: 'ip'; field: IpField; op: MatchOp; value: string }
  | { type: 'transport'; protocol: TransportProto; field: TransportField; op: MatchOp; value: string }
  | { type: 'iif'; name: string }
  | { type: 'oif'; name: string }
  | { type: 'meta'; key: MetaKey; op: MatchOp; value: string }
  | { type: 'ct'; key: CtKey; op: MatchOp; value: string }
  | { type: 'mark'; op: MatchOp; value: number; mask?: number | null };

// --- NatAction: internally tagged with #[serde(tag = "type", rename_all = "lowercase")] ---

export type NatAction =
  | { type: 'dnat'; addr?: string | null; port?: number | null }
  | { type: 'snat'; addr?: string | null; port?: number | null }
  | { type: 'masquerade'; port?: number | null }
  | { type: 'redirect'; port?: number | null }
  | { type: 'tproxy'; addr?: string | null; port: number; mark?: number | null };

// --- NfAction: internally tagged with #[serde(tag = "type", rename_all = "snake_case")] ---

export type NfAction =
  | { type: 'verdict'; verdict: NfVerdict }
  | { type: 'nat'; action: NatAction }
  | { type: 'set_mark'; value: number; mask?: number | null }
  | { type: 'log'; prefix?: string | null; level?: number | null }
  | { type: 'counter' }
  | { type: 'jump'; target: string }
  | { type: 'goto'; target: string }
  | { type: 'return' };

export interface NfRule {
  handle?: number | null;   // u64 in Rust, number in JS (safe for typical values)
  comment?: string | null;
  matches?: NfMatch[];      // #[serde(default)]
  action: NfAction;
}

export interface NfChain {
  name: string;
  chain_type?: NfChainType | null;
  hook?: NfHook | null;
  priority?: number | null;   // i32
  policy?: NfVerdict | null;
  rules?: NfRule[];
}

export interface NfTable {
  family: NfFamily;
  name: string;
  chains?: NfChain[];
}

export interface NftablesRuleset {
  tables?: NfTable[];
}

export interface IptablesChain {
  name: string;
  policy?: NfVerdict | null;
  rules?: NfRule[];
}

export interface IptablesTable {
  name: string;
  chains?: IptablesChain[];
}

export interface IptablesRuleset {
  tables?: IptablesTable[];
}

export interface NetfilterConfig {
  nftables?: NftablesRuleset | null;
  iptables?: IptablesRuleset | null;
}

// --- XDP ---

export type XdpMode = 'generic' | 'native' | 'offload';

// XdpAction: externally-tagged enum with rename_all = "lowercase"
// Simple variants -> string, Redirect{target_if} -> {"redirect": {"target_if": "..."}}
export type XdpAction =
  | 'pass'
  | 'drop'
  | 'tx'
  | { redirect: { target_if: string } }
  | 'aborted';

export interface XdpRule {
  matches?: NfMatch[];       // reuses NfMatch, #[serde(default)]
  action: XdpAction;
  comment?: string | null;
}

export interface XdpProgram {
  interface: string;
  mode?: XdpMode;            // #[serde(default)] -> "generic"
  rules?: XdpRule[];
  default_action?: XdpAction; // #[serde(default)] -> "pass"
}

export interface XdpConfig {
  programs?: XdpProgram[];
}

// --- Packet ---

export type ConntrackState = 'new' | 'established' | 'related' | 'invalid' | 'untracked';

// EtherType: externally-tagged enum with rename_all = "lowercase"
export type EtherType =
  | 'ipv4'
  | 'ipv6'
  | 'arp'
  | 'vlan'
  | 'stp'
  | 'lldp'
  | { other: number };

// IpProtocol: externally-tagged enum with rename_all = "lowercase"
export type IpProtocol =
  | 'tcp'
  | 'udp'
  | 'icmp'
  | 'icmpv6'
  | 'vrrp'
  | 'ospf'
  | 'gre'
  | 'esp'
  | 'ah'
  | 'sctp'
  | { other: number };

export interface TcpFlags {
  syn?: boolean;
  ack?: boolean;
  fin?: boolean;
  rst?: boolean;
  psh?: boolean;
  urg?: boolean;
}

export interface ArpFields {
  operation: number;
  sender_mac?: string | null;
  sender_ip?: string | null;
  target_mac?: string | null;
  target_ip?: string | null;
}

export interface PacketDef {
  ingress_interface: string;
  ethertype?: EtherType;          // #[serde(default)] -> "ipv4"
  vlan_id?: number | null;
  src_mac?: string | null;
  dst_mac?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  protocol?: IpProtocol;          // #[serde(default)] -> "tcp"
  src_port?: number | null;
  dst_port?: number | null;
  tcp_flags?: TcpFlags | null;
  icmp_type?: number | null;
  icmp_code?: number | null;
  arp?: ArpFields | null;
  packet_length?: number | null;
  df_flag?: boolean;              // #[serde(default)] -> false
  dscp?: number | null;
  ttl?: number | null;
  initial_mark?: number;          // #[serde(default)] -> 0
  initial_ct_mark?: number;       // #[serde(default)] -> 0
  conntrack_state?: ConntrackState; // #[serde(default)] -> "new"
}

// --- Sysctl ---

export type RpFilterMode = 'off' | 'strict' | 'loose';

export interface Ipv4Sysctl {
  ip_forward?: boolean;                    // default true
  icmp_echo_ignore_all?: boolean;          // default false
  icmp_echo_ignore_broadcasts?: boolean;   // default true
  tcp_syncookies?: boolean;                // default true
}

export interface Ipv6Sysctl {
  forwarding?: boolean;  // default true
}

export interface InterfaceSysctl {
  forwarding?: boolean | null;
  route_localnet?: boolean;
  rp_filter?: RpFilterMode;
  accept_local?: boolean;
  send_redirects?: boolean;
  log_martians?: boolean;
  proxy_arp?: boolean;
  proxy_arp_pvlan?: boolean;
  arp_ignore?: number;
  arp_announce?: number;
  arp_filter?: boolean;
}

export interface SysctlConfig {
  ipv4?: Ipv4Sysctl;
  ipv6?: Ipv6Sysctl;
  interface_conf?: Record<string, InterfaceSysctl>;
  bridge_nf_call_iptables?: boolean;
  bridge_nf_call_ip6tables?: boolean;
  bridge_nf_call_arptables?: boolean;
}

// --- Scenario (top-level) ---

export interface Scenario {
  version?: string;              // #[serde(default)] -> "1.0"
  name: string;
  description?: string | null;
  interfaces?: Interface[];      // #[serde(default)]
  routing_tables?: RoutingTable[];
  ip_rules?: IpRule[];
  netfilter?: NetfilterConfig;   // #[serde(default)]
  xdp?: XdpConfig;
  sysctl?: SysctlConfig;
  packet: PacketDef;
  topology?: Topology | null;
  neighbors?: NeighborEntry[];
  bridge_fdb?: FdbEntry[];
}

// --- Endpoint Role Model ---

export type EndpointRole =
  | 'local_client'
  | 'remote_client'
  | 'local_server'
  | 'remote_server'
  | 'local_proxy'
  | 'local_tproxy';

export interface Endpoint {
  role: EndpointRole;
  name: string;
  ip: string;
  port?: number | null;
  interface?: string | null;
  position?: { x: number; y: number } | null;
}

export interface TrafficFlow {
  name: string;
  source: string;
  destination: string;
  protocol?: string | null;
  description?: string | null;
}

export interface Topology {
  endpoints?: Endpoint[];
  flows?: TrafficFlow[];
  node_positions?: Record<string, { x: number; y: number }>;
}

// --- Validation (frontend-only) ---

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

// --- Neighbor / ARP Table ---

export type NeighborState = 'permanent' | 'reachable' | 'stale' | 'delay' | 'probe' | 'failed' | 'incomplete';

export interface NeighborEntry {
  ip: string;
  mac: string;
  interface: string;
  state?: NeighborState;
}

// --- Bridge FDB ---

export interface FdbEntry {
  mac: string;
  port: string;
  vlan?: number | null;
  is_static?: boolean;
}

// --- Import ---

export interface ImportParseRequest {
  ip_addr?: string | null;
  ip_rule?: string | null;
  ip_route?: string | null;
  nft_list_ruleset?: string | null;
  iptables_save?: string | null;
}

export interface ImportApplyRequest extends ImportParseRequest {
  merge_strategy?: 'replace' | 'merge';
}

export interface ImportValidationReport {
  parsed_ok: string[];
  partial: string[];
  unsupported: string[];
}

export interface ImportResponse {
  scenario: Partial<Scenario>;
  validation: ImportValidationReport;
}
