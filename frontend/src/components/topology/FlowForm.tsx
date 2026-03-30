import { useState, useEffect } from 'react';
import { X } from 'lucide-react';
import type { TrafficFlow } from '@/types/scenario';

const protocols = ['tcp', 'udp', 'icmp'] as const;

interface FlowFormProps {
  flow?: TrafficFlow | null;
  endpointNames: string[];
  onSave: (flow: TrafficFlow) => void;
  onCancel: () => void;
}

export function FlowForm({ flow, endpointNames, onSave, onCancel }: FlowFormProps) {
  const [name, setName] = useState('');
  const [source, setSource] = useState('');
  const [destination, setDestination] = useState('');
  const [protocol, setProtocol] = useState('tcp');
  const [description, setDescription] = useState('');

  useEffect(() => {
    if (flow) {
      setName(flow.name);
      setSource(flow.source);
      setDestination(flow.destination);
      setProtocol(flow.protocol ?? 'tcp');
      setDescription(flow.description ?? '');
    } else if (endpointNames.length >= 2) {
      setSource(endpointNames[0]);
      setDestination(endpointNames[1]);
    } else if (endpointNames.length === 1) {
      setSource(endpointNames[0]);
    }
  }, [flow, endpointNames]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !source || !destination) return;
    onSave({
      name: name.trim(),
      source,
      destination,
      protocol: protocol || null,
      description: description.trim() || null,
    });
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-full max-w-md rounded-lg bg-white p-6 shadow-xl">
        <div className="mb-4 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900">
            {flow ? 'Edit Flow' : 'Add Flow'}
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
              placeholder="e.g. http-request"
            />
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Source</label>
            <select
              value={source}
              onChange={(e) => setSource(e.target.value)}
              required
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400"
            >
              <option value="">Select source...</option>
              {endpointNames.map((n) => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Destination</label>
            <select
              value={destination}
              onChange={(e) => setDestination(e.target.value)}
              required
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400"
            >
              <option value="">Select destination...</option>
              {endpointNames.map((n) => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Protocol</label>
            <select
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400"
            >
              {protocols.map((p) => (
                <option key={p} value={p}>{p.toUpperCase()}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-gray-700">Description (optional)</label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400"
              placeholder="e.g. HTTP request from client to server"
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
              {flow ? 'Update' : 'Add'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
