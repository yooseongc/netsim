import { useState } from 'react';
import { Plus, Pencil, Trash2, Play, Globe, Monitor, ArrowLeftRight } from 'lucide-react';
import type { Topology, Endpoint, TrafficFlow, EndpointRole } from '@/types/scenario';
import { cn } from '@/lib/utils';
import { EndpointForm } from './EndpointForm';
import { FlowForm } from './FlowForm';

const roleLabels: Record<EndpointRole, string> = {
  local_client: 'Local Client',
  remote_client: 'Remote Client',
  local_server: 'Local Server',
  remote_server: 'Remote Server',
  local_proxy: 'Local Proxy',
  local_tproxy: 'Local TProxy',
};

const roleColors: Record<EndpointRole, string> = {
  local_client: 'bg-blue-100 text-blue-800',
  remote_client: 'bg-green-100 text-green-800',
  local_server: 'bg-purple-100 text-purple-800',
  remote_server: 'bg-orange-100 text-orange-800',
  local_proxy: 'bg-amber-100 text-amber-800',
  local_tproxy: 'bg-cyan-100 text-cyan-800',
};

function getRoleIcon(role: EndpointRole) {
  if (role === 'remote_client' || role === 'remote_server') {
    return <Globe className="h-6 w-6" />;
  }
  if (role === 'local_proxy' || role === 'local_tproxy') {
    return <ArrowLeftRight className="h-6 w-6" />;
  }
  return <Monitor className="h-6 w-6" />;
}

function formatAddress(ep: Endpoint): string {
  if (ep.port != null) return `${ep.ip}:${ep.port}`;
  return ep.ip;
}

interface TopologyEditorProps {
  topology: Topology;
  onChange: (topology: Topology) => void;
  onSimulateFlow?: (flow: TrafficFlow) => void;
}

export function TopologyEditor({ topology, onChange, onSimulateFlow }: TopologyEditorProps) {
  const [editingEndpoint, setEditingEndpoint] = useState<Endpoint | null>(null);
  const [showEndpointForm, setShowEndpointForm] = useState(false);
  const [editingFlow, setEditingFlow] = useState<TrafficFlow | null>(null);
  const [showFlowForm, setShowFlowForm] = useState(false);

  const endpoints = topology.endpoints ?? [];
  const flows = topology.flows ?? [];
  const endpointNames = endpoints.map((e) => e.name);

  // -- Endpoint CRUD --
  const handleSaveEndpoint = (ep: Endpoint) => {
    let updated: Endpoint[];
    if (editingEndpoint) {
      updated = endpoints.map((e) => (e.name === editingEndpoint.name ? ep : e));
    } else {
      updated = [...endpoints, ep];
    }
    onChange({ ...topology, endpoints: updated });
    setShowEndpointForm(false);
    setEditingEndpoint(null);
  };

  const handleDeleteEndpoint = (name: string) => {
    onChange({
      ...topology,
      endpoints: endpoints.filter((e) => e.name !== name),
      flows: flows.filter((f) => f.source !== name && f.destination !== name),
    });
  };

  // -- Flow CRUD --
  const handleSaveFlow = (flow: TrafficFlow) => {
    let updated: TrafficFlow[];
    if (editingFlow) {
      updated = flows.map((f) => (f.name === editingFlow.name ? flow : f));
    } else {
      updated = [...flows, flow];
    }
    onChange({ ...topology, flows: updated });
    setShowFlowForm(false);
    setEditingFlow(null);
  };

  const handleDeleteFlow = (name: string) => {
    onChange({ ...topology, flows: flows.filter((f) => f.name !== name) });
  };

  return (
    <div className="space-y-6">
      {/* Endpoints Section */}
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
          <h3 className="text-sm font-semibold text-gray-900">Endpoints</h3>
          <button
            onClick={() => { setEditingEndpoint(null); setShowEndpointForm(true); }}
            className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-gray-800 transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            Add
          </button>
        </div>

        {endpoints.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-gray-400">
            No endpoints defined. Click "Add" to create one.
          </div>
        ) : (
          <div className="flex flex-wrap gap-3 p-4">
            {endpoints.map((ep) => (
              <div
                key={ep.name}
                className="flex w-48 flex-col rounded-lg border border-gray-200 p-3 hover:border-gray-300 transition-colors"
              >
                <div className={cn('mb-2 flex h-10 w-10 items-center justify-center rounded-lg', roleColors[ep.role])}>
                  {getRoleIcon(ep.role)}
                </div>
                <div className="mb-0.5 text-sm font-medium text-gray-900 truncate" title={ep.name}>
                  {ep.name}
                </div>
                <div className={cn('mb-1 inline-block self-start rounded-full px-2 py-0.5 text-xs font-medium', roleColors[ep.role])}>
                  {roleLabels[ep.role]}
                </div>
                <div className="mb-2 text-xs text-gray-500 truncate" title={formatAddress(ep)}>
                  {formatAddress(ep)}
                  {ep.interface && <span className="ml-1 text-gray-400">({ep.interface})</span>}
                </div>
                <div className="flex gap-1">
                  <button
                    onClick={() => { setEditingEndpoint(ep); setShowEndpointForm(true); }}
                    className="rounded px-2 py-1 text-xs text-gray-500 hover:bg-gray-100 hover:text-gray-700"
                  >
                    <Pencil className="h-3 w-3" />
                  </button>
                  <button
                    onClick={() => handleDeleteEndpoint(ep.name)}
                    className="rounded px-2 py-1 text-xs text-red-400 hover:bg-red-50 hover:text-red-600"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Flows Section */}
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
          <h3 className="text-sm font-semibold text-gray-900">Traffic Flows</h3>
          <button
            onClick={() => { setEditingFlow(null); setShowFlowForm(true); }}
            disabled={endpoints.length < 2}
            className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-gray-800 disabled:opacity-40 transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            Add
          </button>
        </div>

        {flows.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-gray-400">
            {endpoints.length < 2
              ? 'Add at least two endpoints to define traffic flows.'
              : 'No flows defined. Click "Add" to create one.'}
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {flows.map((flow) => (
              <div key={flow.name} className="flex items-center gap-3 px-4 py-3">
                <span className="text-gray-400 text-sm font-medium select-none">&rarr;</span>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-gray-900">{flow.name}</div>
                  <div className="text-xs text-gray-500 truncate">
                    {flow.source} &rarr; {flow.destination}
                    {flow.protocol && (
                      <span className="ml-2 rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-600">
                        {flow.protocol}
                      </span>
                    )}
                    {flow.description && (
                      <span className="ml-2 text-gray-400">{flow.description}</span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => { setEditingFlow(flow); setShowFlowForm(true); }}
                    className="rounded px-2 py-1 text-xs text-gray-500 hover:bg-gray-100 hover:text-gray-700"
                  >
                    <Pencil className="h-3 w-3" />
                  </button>
                  <button
                    onClick={() => handleDeleteFlow(flow.name)}
                    className="rounded px-2 py-1 text-xs text-red-400 hover:bg-red-50 hover:text-red-600"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                  {onSimulateFlow && (
                    <button
                      onClick={() => onSimulateFlow(flow)}
                      className="inline-flex items-center gap-1 rounded-md bg-green-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-green-700 transition-colors"
                    >
                      <Play className="h-3 w-3" />
                      Simulate
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* Modals */}
      {showEndpointForm && (
        <EndpointForm
          endpoint={editingEndpoint}
          onSave={handleSaveEndpoint}
          onCancel={() => { setShowEndpointForm(false); setEditingEndpoint(null); }}
        />
      )}

      {showFlowForm && (
        <FlowForm
          flow={editingFlow}
          endpointNames={endpointNames}
          onSave={handleSaveFlow}
          onCancel={() => { setShowFlowForm(false); setEditingFlow(null); }}
        />
      )}
    </div>
  );
}
