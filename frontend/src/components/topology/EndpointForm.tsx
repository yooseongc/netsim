import { useState, useEffect } from 'react';
import { X } from 'lucide-react';
import type { Endpoint, EndpointRole } from '@/types/scenario';

const roles: { value: EndpointRole; label: string }[] = [
  { value: 'local_client', label: 'Local Client' },
  { value: 'remote_client', label: 'Remote Client' },
  { value: 'local_server', label: 'Local Server' },
  { value: 'remote_server', label: 'Remote Server' },
  { value: 'local_proxy', label: 'Local Proxy' },
  { value: 'local_tproxy', label: 'Local TProxy' },
];

interface EndpointFormProps {
  endpoint?: Endpoint | null;
  onSave: (endpoint: Endpoint) => void;
  onCancel: () => void;
}

export function EndpointForm({ endpoint, onSave, onCancel }: EndpointFormProps) {
  const [name, setName] = useState('');
  const [role, setRole] = useState<EndpointRole>('remote_client');
  const [ip, setIp] = useState('');
  const [port, setPort] = useState('');
  const [iface, setIface] = useState('');

  useEffect(() => {
    if (endpoint) {
      setName(endpoint.name);
      setRole(endpoint.role);
      setIp(endpoint.ip);
      setPort(endpoint.port != null ? String(endpoint.port) : '');
      setIface(endpoint.interface ?? '');
    }
  }, [endpoint]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !ip.trim()) return;
    onSave({
      name: name.trim(),
      role,
      ip: ip.trim(),
      port: port ? Number(port) : null,
      interface: iface.trim() || null,
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-full max-w-md rounded-lg bg-white p-6 shadow-xl">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900">
            {endpoint ? 'Edit Endpoint' : 'Add Endpoint'}
          </h3>
          <button onClick={onCancel} className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600">
            <X className="h-5 w-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400"
              placeholder="e.g. web-client"
            />
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as EndpointRole)}
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400"
            >
              {roles.map((r) => (
                <option key={r.value} value={r.value}>{r.label}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">IP Address</label>
            <input
              type="text"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              required
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400"
              placeholder="e.g. 10.0.0.1"
            />
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Port (optional)</label>
            <input
              type="number"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              min={1}
              max={65535}
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400"
              placeholder="e.g. 80"
            />
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Interface (optional)</label>
            <input
              type="text"
              value={iface}
              onChange={(e) => setIface(e.target.value)}
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400"
              placeholder="e.g. eth0"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onCancel}
              className="rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white hover:bg-gray-800"
            >
              {endpoint ? 'Update' : 'Add'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
