import { useState } from 'react';
import { Plus, Pencil, Trash2, X, ChevronDown, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { Interface, InterfaceAddress, InterfaceState, InterfaceKind } from '@/types/scenario';

const inputClass =
  'w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400';
const selectClass = inputClass;
const labelClass = 'mb-1 block text-sm font-medium text-gray-700';

const IF_KINDS: { value: string; label: string }[] = [
  { value: 'physical', label: 'Physical' },
  { value: 'loopback', label: 'Loopback' },
  { value: 'veth', label: 'veth' },
  { value: 'bridge', label: 'Bridge' },
  { value: 'vlan', label: 'VLAN' },
  { value: 'bond', label: 'Bond' },
  { value: 'tun', label: 'TUN' },
  { value: 'tap', label: 'TAP' },
  { value: 'wireguard', label: 'WireGuard' },
];

function kindToString(k: InterfaceKind | undefined): string {
  if (!k) return 'physical';
  return typeof k === 'string' ? k : 'physical';
}

function randomMac(): string {
  // Generate a unicast, locally-administered MAC (02:xx:xx:xx:xx:xx)
  const hex = () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
  return `02:${hex()}:${hex()}:${hex()}:${hex()}:${hex()}`;
}

function randomPrivateSubnet(index: number): string {
  // Use 10.x.x.0/24 subnets, varying the second octet by index
  const octet2 = (index % 255) + 1;
  const octet3 = Math.floor(Math.random() * 255);
  return `10.${octet2}.${octet3}`;
}

const IF_NAME_POOL = ['eth0', 'eth1', 'eth2', 'eth3', 'ens33', 'ens34', 'ens160', 'enp0s3'];

function emptyInterface(index: number, existingNames: string[]): Interface {
  // Pick first unused name from pool, or fallback to eth{n}
  const usedNames = new Set(existingNames);
  const name = IF_NAME_POOL.find((n) => !usedNames.has(n)) ?? `eth${index}`;
  const subnet = randomPrivateSubnet(index);

  return {
    name,
    index,
    mac: randomMac(),
    mtu: 1500,
    state: 'up',
    kind: 'physical',
    addresses: [{ ip: `${subnet}.1`, prefix_len: 24, scope: 'global' }],
  };
}

interface InterfacesEditorProps {
  interfaces: Interface[];
  onChange: (interfaces: Interface[]) => void;
}

export function InterfacesEditor({ interfaces, onChange }: InterfacesEditorProps) {
  const [editingIdx, setEditingIdx] = useState<number | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState<Interface>(emptyInterface(interfaces.length + 1, interfaces.map((i) => i.name)));
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);
  const [addressInput, setAddressInput] = useState('');

  const openAdd = () => {
    setEditingIdx(null);
    setFormData(emptyInterface(interfaces.length + 1, interfaces.map((i) => i.name)));
    setAddressInput('');
    setShowForm(true);
  };

  const openEdit = (idx: number) => {
    setEditingIdx(idx);
    setFormData({ ...interfaces[idx] });
    setAddressInput('');
    setShowForm(true);
  };

  const handleDelete = (idx: number) => {
    onChange(interfaces.filter((_, i) => i !== idx));
  };

  const handleSave = () => {
    if (!formData.name.trim()) return;
    if (editingIdx !== null) {
      const updated = interfaces.map((iface, i) => (i === editingIdx ? formData : iface));
      onChange(updated);
    } else {
      onChange([...interfaces, formData]);
    }
    setShowForm(false);
  };

  const addAddress = () => {
    const trimmed = addressInput.trim();
    if (!trimmed) return;
    // Expect format: ip/prefix e.g. 10.0.0.1/24
    const parts = trimmed.split('/');
    const addr: InterfaceAddress = {
      ip: parts[0],
      prefix_len: parts[1] ? Number(parts[1]) : 24,
      scope: 'global',
    };
    setFormData({ ...formData, addresses: [...(formData.addresses ?? []), addr] });
    setAddressInput('');
  };

  const removeAddress = (addrIdx: number) => {
    setFormData({
      ...formData,
      addresses: (formData.addresses ?? []).filter((_, i) => i !== addrIdx),
    });
  };

  const updateBridgeMembers = (text: string) => {
    const members = text.split(',').map((s) => s.trim()).filter(Boolean);
    setFormData({ ...formData, bridge_members: members.length > 0 ? members : undefined });
  };

  const updateBondMembers = (text: string) => {
    const members = text.split(',').map((s) => s.trim()).filter(Boolean);
    setFormData({ ...formData, bond_members: members.length > 0 ? members : undefined });
  };

  return (
    <div className="space-y-4">
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
          <h3 className="text-sm font-semibold text-gray-900">
            Interfaces ({interfaces.length})
          </h3>
          <button
            onClick={openAdd}
            className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-gray-800 transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            Add
          </button>
        </div>

        {interfaces.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-gray-400">
            No interfaces defined. Click &quot;Add&quot; to create one.
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {interfaces.map((iface, idx) => (
              <div key={idx}>
                <div className="flex items-center gap-3 px-4 py-3">
                  <button
                    onClick={() => setExpandedIdx(expandedIdx === idx ? null : idx)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    {expandedIdx === idx
                      ? <ChevronDown className="h-4 w-4" />
                      : <ChevronRight className="h-4 w-4" />}
                  </button>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-gray-900 font-mono">{iface.name}</span>
                      <span className="text-xs text-gray-400">idx={iface.index}</span>
                      <span className={cn(
                        'rounded-full px-2 py-0.5 text-xs font-medium',
                        iface.state === 'up' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700',
                      )}>
                        {iface.state ?? 'up'}
                      </span>
                      <span className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-600">
                        {kindToString(iface.kind)}
                      </span>
                      <span className="text-xs text-gray-400">MTU {iface.mtu ?? 1500}</span>
                    </div>
                    <div className="text-xs text-gray-500 mt-0.5">
                      {(iface.addresses ?? []).map((a) => `${a.ip}/${a.prefix_len}`).join(', ') || 'No addresses'}
                    </div>
                  </div>
                  <div className="flex gap-1">
                    <button
                      onClick={() => openEdit(idx)}
                      className="rounded px-2 py-1 text-xs text-gray-500 hover:bg-gray-100 hover:text-gray-700"
                    >
                      <Pencil className="h-3 w-3" />
                    </button>
                    <button
                      onClick={() => handleDelete(idx)}
                      className="rounded px-2 py-1 text-xs text-red-400 hover:bg-red-50 hover:text-red-600"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </div>
                </div>

                {expandedIdx === idx && (
                  <div className="bg-gray-50 px-4 py-3 text-xs text-gray-600 space-y-1 border-t border-gray-100">
                    {iface.mac && <div><span className="font-medium">MAC:</span> {iface.mac}</div>}
                    {iface.veth_peer && <div><span className="font-medium">veth peer:</span> {iface.veth_peer}</div>}
                    {iface.master && <div><span className="font-medium">Master:</span> {iface.master}</div>}
                    {(iface.bridge_members ?? []).length > 0 && (
                      <div><span className="font-medium">Bridge members:</span> {iface.bridge_members!.join(', ')}</div>
                    )}
                    {iface.vlan_parent && (
                      <div><span className="font-medium">VLAN parent:</span> {iface.vlan_parent} (ID: {iface.vlan_id})</div>
                    )}
                    {(iface.bond_members ?? []).length > 0 && (
                      <div><span className="font-medium">Bond members:</span> {iface.bond_members!.join(', ')}</div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Interface Form Modal */}
      {showForm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-lg bg-white p-6 shadow-xl">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-900">
                {editingIdx !== null ? 'Edit Interface' : 'Add Interface'}
              </h3>
              <button
                onClick={() => setShowForm(false)}
                className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className={labelClass}>Name *</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className={inputClass}
                    placeholder="eth0"
                  />
                </div>
                <div>
                  <label className={labelClass}>Index *</label>
                  <input
                    type="number"
                    value={formData.index}
                    onChange={(e) => setFormData({ ...formData, index: Number(e.target.value) })}
                    className={inputClass}
                    min={1}
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div>
                  <label className={labelClass}>Kind</label>
                  <select
                    value={kindToString(formData.kind)}
                    onChange={(e) => setFormData({ ...formData, kind: e.target.value as InterfaceKind })}
                    className={selectClass}
                  >
                    {IF_KINDS.map((k) => (
                      <option key={k.value} value={k.value}>{k.label}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className={labelClass}>State</label>
                  <select
                    value={formData.state ?? 'up'}
                    onChange={(e) => setFormData({ ...formData, state: e.target.value as InterfaceState })}
                    className={selectClass}
                  >
                    <option value="up">Up</option>
                    <option value="down">Down</option>
                  </select>
                </div>
                <div>
                  <label className={labelClass}>MTU</label>
                  <input
                    type="number"
                    value={formData.mtu ?? 1500}
                    onChange={(e) => setFormData({ ...formData, mtu: Number(e.target.value) || 1500 })}
                    className={inputClass}
                    min={68}
                    max={65535}
                  />
                </div>
              </div>

              <div>
                <label className={labelClass}>MAC Address</label>
                <input
                  type="text"
                  value={formData.mac ?? ''}
                  onChange={(e) => setFormData({ ...formData, mac: e.target.value || null })}
                  className={inputClass}
                  placeholder="aa:bb:cc:dd:ee:ff"
                />
              </div>

              {/* Addresses */}
              <div>
                <label className={labelClass}>IP Addresses</label>
                <div className="space-y-1 mb-2">
                  {(formData.addresses ?? []).map((addr, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <span className="text-sm font-mono text-gray-700">
                        {addr.ip}/{addr.prefix_len}
                      </span>
                      <span className="text-xs text-gray-400">{addr.scope ?? 'global'}</span>
                      <button
                        onClick={() => removeAddress(i)}
                        className="rounded p-0.5 text-red-400 hover:bg-red-50 hover:text-red-600"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </div>
                  ))}
                </div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={addressInput}
                    onChange={(e) => setAddressInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addAddress(); } }}
                    className={inputClass}
                    placeholder="10.0.0.1/24"
                  />
                  <button
                    type="button"
                    onClick={addAddress}
                    className="rounded-md border border-gray-300 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50"
                  >
                    Add
                  </button>
                </div>
              </div>

              {/* Virtual relationships */}
              {kindToString(formData.kind) === 'veth' && (
                <div>
                  <label className={labelClass}>veth Peer</label>
                  <input
                    type="text"
                    value={formData.veth_peer ?? ''}
                    onChange={(e) => setFormData({ ...formData, veth_peer: e.target.value || null })}
                    className={inputClass}
                    placeholder="veth1"
                  />
                </div>
              )}

              {kindToString(formData.kind) === 'bridge' && (
                <div>
                  <label className={labelClass}>Bridge Members (comma-separated)</label>
                  <input
                    type="text"
                    value={(formData.bridge_members ?? []).join(', ')}
                    onChange={(e) => updateBridgeMembers(e.target.value)}
                    className={inputClass}
                    placeholder="eth0, eth1"
                  />
                </div>
              )}

              {kindToString(formData.kind) === 'vlan' && (
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className={labelClass}>VLAN Parent</label>
                    <input
                      type="text"
                      value={formData.vlan_parent ?? ''}
                      onChange={(e) => setFormData({ ...formData, vlan_parent: e.target.value || null })}
                      className={inputClass}
                      placeholder="eth0"
                    />
                  </div>
                  <div>
                    <label className={labelClass}>VLAN ID</label>
                    <input
                      type="number"
                      value={formData.vlan_id ?? ''}
                      onChange={(e) => setFormData({ ...formData, vlan_id: e.target.value ? Number(e.target.value) : null })}
                      className={inputClass}
                      min={1}
                      max={4094}
                    />
                  </div>
                </div>
              )}

              {kindToString(formData.kind) === 'bond' && (
                <div>
                  <label className={labelClass}>Bond Members (comma-separated)</label>
                  <input
                    type="text"
                    value={(formData.bond_members ?? []).join(', ')}
                    onChange={(e) => updateBondMembers(e.target.value)}
                    className={inputClass}
                    placeholder="eth0, eth1"
                  />
                </div>
              )}

              <div>
                <label className={labelClass}>Master Interface</label>
                <input
                  type="text"
                  value={formData.master ?? ''}
                  onChange={(e) => setFormData({ ...formData, master: e.target.value || null })}
                  className={inputClass}
                  placeholder="br0"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowForm(false)}
                  className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleSave}
                  className="rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white hover:bg-gray-800"
                >
                  {editingIdx !== null ? 'Update' : 'Add'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
