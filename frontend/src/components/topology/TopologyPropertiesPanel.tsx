import { X, Pencil, Trash2, Play, Globe, Monitor, ArrowLeftRight, Network } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { Endpoint, TrafficFlow, EndpointRole, Interface as IFace } from '@/types/scenario';

const roleLabels: Record<EndpointRole, string> = {
  local_client: 'Local Client',
  remote_client: 'Remote Client',
  local_server: 'Local Server',
  remote_server: 'Remote Server',
  local_proxy: 'Local Proxy',
  local_tproxy: 'Local TProxy',
};

const roleBadgeColors: Record<EndpointRole, string> = {
  local_client: 'bg-blue-100 text-blue-700',
  remote_client: 'bg-green-100 text-green-700',
  local_server: 'bg-purple-100 text-purple-700',
  remote_server: 'bg-orange-100 text-orange-700',
  local_proxy: 'bg-amber-100 text-amber-700',
  local_tproxy: 'bg-cyan-100 text-cyan-700',
};

function getRoleIcon(role: EndpointRole) {
  if (role === 'remote_client' || role === 'remote_server') return <Globe className="h-4 w-4" />;
  if (role === 'local_proxy' || role === 'local_tproxy') return <ArrowLeftRight className="h-4 w-4" />;
  return <Monitor className="h-4 w-4" />;
}

interface PropertiesPanelProps {
  selectedEndpoint?: Endpoint | null;
  selectedFlow?: TrafficFlow | null;
  selectedInterface?: IFace | null;
  onEditEndpoint?: (ep: Endpoint) => void;
  onDeleteEndpoint?: (name: string) => void;
  onEditFlow?: (flow: TrafficFlow) => void;
  onDeleteFlow?: (name: string) => void;
  onDeleteInterface?: (name: string) => void;
  onSimulateFlow?: (flow: TrafficFlow) => void;
  onClose: () => void;
}

export function TopologyPropertiesPanel({
  selectedEndpoint,
  selectedFlow,
  selectedInterface,
  onEditEndpoint,
  onDeleteEndpoint,
  onEditFlow,
  onDeleteFlow,
  onDeleteInterface,
  onSimulateFlow,
  onClose,
}: PropertiesPanelProps) {
  if (!selectedEndpoint && !selectedFlow && !selectedInterface) return null;

  return (
    <div className="w-72 border-l border-gray-200 bg-white flex flex-col">
      <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
        <h3 className="text-sm font-semibold text-gray-900">Properties</h3>
        <button onClick={onClose} className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600">
          <X className="h-4 w-4" />
        </button>
      </div>

      {/* Endpoint */}
      {selectedEndpoint && (
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          <div className="flex items-center gap-2">
            {getRoleIcon(selectedEndpoint.role)}
            <span className={cn('rounded-full px-2 py-0.5 text-xs font-medium', roleBadgeColors[selectedEndpoint.role])}>
              {roleLabels[selectedEndpoint.role]}
            </span>
          </div>
          <div className="space-y-2">
            <Field label="Name" value={selectedEndpoint.name} />
            <Field label="IP Address" value={`${selectedEndpoint.ip}${selectedEndpoint.port != null ? `:${selectedEndpoint.port}` : ''}`} mono />
            {selectedEndpoint.interface && <Field label="Interface" value={selectedEndpoint.interface} mono />}
          </div>
          <div className="flex gap-2 pt-2">
            <ActionButton icon={<Pencil className="h-3 w-3" />} label="Edit" onClick={() => onEditEndpoint?.(selectedEndpoint)} />
            <ActionButton icon={<Trash2 className="h-3 w-3" />} label="Delete" danger onClick={() => onDeleteEndpoint?.(selectedEndpoint.name)} />
          </div>
        </div>
      )}

      {/* Interface */}
      {selectedInterface && (
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-indigo-500" />
            <span className="rounded-full bg-indigo-100 px-2 py-0.5 text-xs font-medium text-indigo-700">
              Interface
            </span>
            <span className={cn(
              'rounded-full px-1.5 py-0.5 text-[9px] font-medium ml-auto',
              (selectedInterface.state ?? 'up') === 'up' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700',
            )}>
              {(selectedInterface.state ?? 'up').toUpperCase()}
            </span>
          </div>
          <div className="space-y-2">
            <Field label="Name" value={selectedInterface.name} mono />
            <Field label="Index" value={String(selectedInterface.index)} />
            <Field label="MTU" value={String(selectedInterface.mtu ?? 1500)} />
            {selectedInterface.mac && <Field label="MAC" value={selectedInterface.mac} mono />}
            {selectedInterface.kind && typeof selectedInterface.kind === 'string' && (
              <Field label="Kind" value={selectedInterface.kind} />
            )}
            <div>
              <div className="text-xs text-gray-500">Addresses</div>
              {(selectedInterface.addresses ?? []).length > 0 ? (
                (selectedInterface.addresses ?? []).map((a, i) => (
                  <div key={i} className="text-sm font-mono text-gray-900">{a.ip}/{a.prefix_len}</div>
                ))
              ) : (
                <div className="text-sm text-gray-400 italic">none</div>
              )}
            </div>
            {selectedInterface.veth_peer && <Field label="veth peer" value={selectedInterface.veth_peer} mono />}
            {(selectedInterface.bridge_members ?? []).length > 0 && (
              <Field label="Bridge members" value={selectedInterface.bridge_members!.join(', ')} />
            )}
          </div>
          <div className="text-xs text-gray-400 italic pt-2">
            Edit interfaces in the Interfaces tab.
          </div>
          <div className="flex gap-2">
            <ActionButton icon={<Trash2 className="h-3 w-3" />} label="Remove" danger onClick={() => onDeleteInterface?.(selectedInterface.name)} />
          </div>
        </div>
      )}

      {/* Flow */}
      {selectedFlow && (
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          <div className="space-y-2">
            <Field label="Flow Name" value={selectedFlow.name} />
            <Field label="Direction" value={`${selectedFlow.source} → ${selectedFlow.destination}`} />
            {selectedFlow.protocol && <Field label="Protocol" value={selectedFlow.protocol.toUpperCase()} mono />}
            {selectedFlow.description && <Field label="Description" value={selectedFlow.description} />}
          </div>
          <div className="flex gap-2 pt-2">
            <ActionButton icon={<Pencil className="h-3 w-3" />} label="Edit" onClick={() => onEditFlow?.(selectedFlow)} />
            <ActionButton icon={<Trash2 className="h-3 w-3" />} label="Delete" danger onClick={() => onDeleteFlow?.(selectedFlow.name)} />
            {onSimulateFlow && (
              <button
                onClick={() => onSimulateFlow(selectedFlow)}
                className="inline-flex items-center gap-1.5 rounded-md bg-green-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-green-700"
              >
                <Play className="h-3 w-3" /> Simulate
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-xs text-gray-500">{label}</div>
      <div className={cn('text-sm text-gray-900', mono && 'font-mono')}>{value}</div>
    </div>
  );
}

function ActionButton({ icon, label, danger, onClick }: {
  icon: React.ReactNode;
  label: string;
  danger?: boolean;
  onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium',
        danger
          ? 'border-red-200 text-red-600 hover:bg-red-50'
          : 'border-gray-300 text-gray-700 hover:bg-gray-50',
      )}
    >
      {icon} {label}
    </button>
  );
}
