import type {
  PacketDef,
  EtherType,
  IpProtocol,
  ConntrackState,
  TcpFlags,
} from '@/types/scenario';

const inputClass =
  'w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400';
const selectClass = inputClass;
const labelClass = 'mb-1 block text-sm font-medium text-gray-700';

const ETHERTYPES: { value: string; label: string }[] = [
  { value: 'ipv4', label: 'IPv4' },
  { value: 'ipv6', label: 'IPv6' },
  { value: 'arp', label: 'ARP' },
  { value: 'vlan', label: 'VLAN' },
  { value: 'stp', label: 'STP' },
  { value: 'lldp', label: 'LLDP' },
];

const PROTOCOLS: { value: string; label: string }[] = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'icmp', label: 'ICMP' },
  { value: 'icmpv6', label: 'ICMPv6' },
  { value: 'sctp', label: 'SCTP' },
  { value: 'vrrp', label: 'VRRP' },
  { value: 'ospf', label: 'OSPF' },
  { value: 'gre', label: 'GRE' },
  { value: 'esp', label: 'ESP' },
  { value: 'ah', label: 'AH' },
];

const CT_STATES: ConntrackState[] = ['new', 'established', 'related', 'invalid', 'untracked'];

const TCP_FLAG_NAMES: (keyof TcpFlags)[] = ['syn', 'ack', 'fin', 'rst', 'psh', 'urg'];

interface PacketEditorProps {
  packet: PacketDef;
  onChange: (packet: PacketDef) => void;
  interfaceNames: string[];
}

export function PacketEditor({ packet, onChange, interfaceNames }: PacketEditorProps) {
  const update = (patch: Partial<PacketDef>) => onChange({ ...packet, ...patch });

  const handleIngressChange = (ifName: string) => {
    update({ ingress_interface: ifName });
  };

  const etherStr = typeof packet.ethertype === 'string' ? packet.ethertype : 'ipv4';
  const protoStr = typeof packet.protocol === 'string' ? packet.protocol : 'tcp';
  const hasPorts = protoStr === 'tcp' || protoStr === 'udp' || protoStr === 'sctp';
  const isIcmp = protoStr === 'icmp' || protoStr === 'icmpv6';
  const isTcp = protoStr === 'tcp';
  const isArp = etherStr === 'arp';

  return (
    <div className="space-y-6">
      {/* L2 Section */}
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="border-b border-gray-200 px-4 py-3">
          <h3 className="text-sm font-semibold text-gray-900">Layer 2 — Ethernet</h3>
        </div>
        <div className="grid grid-cols-2 gap-4 p-4">
          <div>
            <label className={labelClass}>Ingress Interface *</label>
            {interfaceNames.length > 0 ? (
              <select
                value={packet.ingress_interface}
                onChange={(e) => handleIngressChange(e.target.value)}
                className={selectClass}
              >
                <option value="">— select —</option>
                {interfaceNames.map((n) => (
                  <option key={n} value={n}>{n}</option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                value={packet.ingress_interface}
                onChange={(e) => handleIngressChange(e.target.value)}
                className={inputClass}
                placeholder="eth0"
              />
            )}
          </div>

          <div>
            <label className={labelClass}>EtherType</label>
            <select
              value={etherStr}
              onChange={(e) => update({ ethertype: e.target.value as EtherType })}
              className={selectClass}
            >
              {ETHERTYPES.map((e) => (
                <option key={e.value} value={e.value}>{e.label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className={labelClass}>Source MAC</label>
            <input
              type="text"
              value={packet.src_mac ?? ''}
              onChange={(e) => update({ src_mac: e.target.value || null })}
              className={inputClass}
              placeholder="aa:bb:cc:dd:ee:ff"
            />
          </div>

          <div>
            <label className={labelClass}>Destination MAC</label>
            <input
              type="text"
              value={packet.dst_mac ?? ''}
              onChange={(e) => update({ dst_mac: e.target.value || null })}
              className={inputClass}
              placeholder="aa:bb:cc:dd:ee:ff"
            />
          </div>

          <div>
            <label className={labelClass}>VLAN ID</label>
            <input
              type="number"
              value={packet.vlan_id ?? ''}
              onChange={(e) => update({ vlan_id: e.target.value ? Number(e.target.value) : null })}
              className={inputClass}
              placeholder="100"
              min={0}
              max={4095}
            />
          </div>
        </div>
      </section>

      {/* L3 Section */}
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="border-b border-gray-200 px-4 py-3">
          <h3 className="text-sm font-semibold text-gray-900">Layer 3 — IP</h3>
        </div>
        <div className="grid grid-cols-2 gap-4 p-4">
          <div>
            <label className={labelClass}>Source IP</label>
            <input
              type="text"
              value={packet.src_ip ?? ''}
              onChange={(e) => update({ src_ip: e.target.value || null })}
              className={inputClass}
              placeholder="192.168.1.100"
            />
          </div>

          <div>
            <label className={labelClass}>Destination IP</label>
            <input
              type="text"
              value={packet.dst_ip ?? ''}
              onChange={(e) => update({ dst_ip: e.target.value || null })}
              className={inputClass}
              placeholder="10.0.0.2"
            />
          </div>

          <div>
            <label className={labelClass}>Protocol</label>
            <select
              value={protoStr}
              onChange={(e) => update({ protocol: e.target.value as IpProtocol })}
              className={selectClass}
            >
              {PROTOCOLS.map((p) => (
                <option key={p.value} value={p.value}>{p.label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className={labelClass}>TTL</label>
            <input
              type="number"
              value={packet.ttl ?? ''}
              onChange={(e) => update({ ttl: e.target.value ? Number(e.target.value) : null })}
              className={inputClass}
              placeholder="64"
              min={0}
              max={255}
            />
          </div>

          <div>
            <label className={labelClass}>DSCP</label>
            <input
              type="number"
              value={packet.dscp ?? ''}
              onChange={(e) => update({ dscp: e.target.value ? Number(e.target.value) : null })}
              className={inputClass}
              placeholder="0"
              min={0}
              max={63}
            />
          </div>

          <div>
            <label className={labelClass}>Packet Length</label>
            <input
              type="number"
              value={packet.packet_length ?? ''}
              onChange={(e) => update({ packet_length: e.target.value ? Number(e.target.value) : null })}
              className={inputClass}
              placeholder="64"
              min={1}
            />
          </div>

          <div className="flex items-center gap-2 pt-6">
            <input
              type="checkbox"
              id="df_flag"
              checked={packet.df_flag ?? false}
              onChange={(e) => update({ df_flag: e.target.checked })}
              className="h-4 w-4 rounded border-gray-300"
            />
            <label htmlFor="df_flag" className="text-sm text-gray-700">
              Don&apos;t Fragment (DF)
            </label>
          </div>
        </div>
      </section>

      {/* L4 Section */}
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="border-b border-gray-200 px-4 py-3">
          <h3 className="text-sm font-semibold text-gray-900">Layer 4 — Transport</h3>
        </div>
        <div className="grid grid-cols-2 gap-4 p-4">
          {hasPorts && (
            <>
              <div>
                <label className={labelClass}>Source Port</label>
                <input
                  type="number"
                  value={packet.src_port ?? ''}
                  onChange={(e) => update({ src_port: e.target.value ? Number(e.target.value) : null })}
                  className={inputClass}
                  placeholder="54321"
                  min={0}
                  max={65535}
                />
              </div>
              <div>
                <label className={labelClass}>Destination Port</label>
                <input
                  type="number"
                  value={packet.dst_port ?? ''}
                  onChange={(e) => update({ dst_port: e.target.value ? Number(e.target.value) : null })}
                  className={inputClass}
                  placeholder="80"
                  min={0}
                  max={65535}
                />
              </div>
            </>
          )}

          {isTcp && (
            <div className="col-span-2">
              <label className={labelClass}>TCP Flags</label>
              <div className="flex flex-wrap gap-3 mt-1">
                {TCP_FLAG_NAMES.map((flag) => (
                  <label key={flag} className="flex items-center gap-1.5 text-sm text-gray-700">
                    <input
                      type="checkbox"
                      checked={packet.tcp_flags?.[flag] ?? false}
                      onChange={(e) =>
                        update({
                          tcp_flags: {
                            ...(packet.tcp_flags ?? {}),
                            [flag]: e.target.checked,
                          },
                        })
                      }
                      className="h-4 w-4 rounded border-gray-300"
                    />
                    {flag.toUpperCase()}
                  </label>
                ))}
              </div>
            </div>
          )}

          {isIcmp && (
            <>
              <div>
                <label className={labelClass}>ICMP Type</label>
                <input
                  type="number"
                  value={packet.icmp_type ?? ''}
                  onChange={(e) => update({ icmp_type: e.target.value ? Number(e.target.value) : null })}
                  className={inputClass}
                  placeholder="8"
                  min={0}
                  max={255}
                />
              </div>
              <div>
                <label className={labelClass}>ICMP Code</label>
                <input
                  type="number"
                  value={packet.icmp_code ?? ''}
                  onChange={(e) => update({ icmp_code: e.target.value ? Number(e.target.value) : null })}
                  className={inputClass}
                  placeholder="0"
                  min={0}
                  max={255}
                />
              </div>
            </>
          )}

          {isArp && (
            <>
              <div>
                <label className={labelClass}>ARP Operation</label>
                <input
                  type="number"
                  value={packet.arp?.operation ?? ''}
                  onChange={(e) =>
                    update({
                      arp: {
                        ...(packet.arp ?? { operation: 1 }),
                        operation: Number(e.target.value) || 1,
                      },
                    })
                  }
                  className={inputClass}
                  placeholder="1 (request) / 2 (reply)"
                />
              </div>
              <div>
                <label className={labelClass}>Sender IP</label>
                <input
                  type="text"
                  value={packet.arp?.sender_ip ?? ''}
                  onChange={(e) =>
                    update({
                      arp: {
                        ...(packet.arp ?? { operation: 1 }),
                        sender_ip: e.target.value || null,
                      },
                    })
                  }
                  className={inputClass}
                  placeholder="10.0.0.1"
                />
              </div>
              <div>
                <label className={labelClass}>Target IP</label>
                <input
                  type="text"
                  value={packet.arp?.target_ip ?? ''}
                  onChange={(e) =>
                    update({
                      arp: {
                        ...(packet.arp ?? { operation: 1 }),
                        target_ip: e.target.value || null,
                      },
                    })
                  }
                  className={inputClass}
                  placeholder="10.0.0.2"
                />
              </div>
              <div>
                <label className={labelClass}>Sender MAC</label>
                <input
                  type="text"
                  value={packet.arp?.sender_mac ?? ''}
                  onChange={(e) =>
                    update({
                      arp: {
                        ...(packet.arp ?? { operation: 1 }),
                        sender_mac: e.target.value || null,
                      },
                    })
                  }
                  className={inputClass}
                  placeholder="aa:bb:cc:dd:ee:ff"
                />
              </div>
            </>
          )}
        </div>
      </section>

      {/* Conntrack / Marks */}
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="border-b border-gray-200 px-4 py-3">
          <h3 className="text-sm font-semibold text-gray-900">Conntrack &amp; Marks</h3>
        </div>
        <div className="grid grid-cols-2 gap-4 p-4">
          <div>
            <label className={labelClass}>Conntrack State</label>
            <select
              value={packet.conntrack_state ?? 'new'}
              onChange={(e) => update({ conntrack_state: e.target.value as ConntrackState })}
              className={selectClass}
            >
              {CT_STATES.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>

          <div>
            <label className={labelClass}>Initial Mark (fwmark)</label>
            <input
              type="number"
              value={packet.initial_mark ?? 0}
              onChange={(e) => update({ initial_mark: Number(e.target.value) || 0 })}
              className={inputClass}
              min={0}
            />
          </div>

          <div>
            <label className={labelClass}>Initial CT Mark</label>
            <input
              type="number"
              value={packet.initial_ct_mark ?? 0}
              onChange={(e) => update({ initial_ct_mark: Number(e.target.value) || 0 })}
              className={inputClass}
              min={0}
            />
          </div>
        </div>
      </section>
    </div>
  );
}
