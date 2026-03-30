import { memo } from 'react';
import { Handle, Position, type NodeProps, type Node } from '@xyflow/react';
import { Globe, Monitor, ArrowLeftRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { Endpoint, EndpointRole } from '@/types/scenario';

const roleLabels: Record<EndpointRole, string> = {
  local_client: 'Local Client',
  remote_client: 'Remote Client',
  local_server: 'Local Server',
  remote_server: 'Remote Server',
  local_proxy: 'Local Proxy',
  local_tproxy: 'Local TProxy',
};

const roleBorderColors: Record<EndpointRole, string> = {
  local_client: 'border-t-blue-500',
  remote_client: 'border-t-green-500',
  local_server: 'border-t-purple-500',
  remote_server: 'border-t-orange-500',
  local_proxy: 'border-t-amber-500',
  local_tproxy: 'border-t-cyan-500',
};

const roleBgColors: Record<EndpointRole, string> = {
  local_client: 'bg-blue-50',
  remote_client: 'bg-green-50',
  local_server: 'bg-purple-50',
  remote_server: 'bg-orange-50',
  local_proxy: 'bg-amber-50',
  local_tproxy: 'bg-cyan-50',
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
  if (role === 'remote_client' || role === 'remote_server') {
    return <Globe className="h-3.5 w-3.5" />;
  }
  if (role === 'local_proxy' || role === 'local_tproxy') {
    return <ArrowLeftRight className="h-3.5 w-3.5" />;
  }
  return <Monitor className="h-3.5 w-3.5" />;
}

type EndpointNodeData = Endpoint & Record<string, unknown>;

function EndpointNodeComponent({ data, selected }: NodeProps<Node<EndpointNodeData>>) {
  const ep = data as Endpoint;

  return (
    <>
      <Handle type="target" position={Position.Left} className="!w-2 !h-2 !bg-gray-400 !border-[1.5px] !border-white" />

      <div
        className={cn(
          'w-[160px] rounded-lg border border-gray-200 border-t-[3px] bg-white shadow-sm transition-shadow',
          roleBorderColors[ep.role],
          selected && 'ring-2 ring-blue-500 shadow-md',
        )}
      >
        {/* Header */}
        <div className={cn('flex items-center gap-1 px-2 py-1 rounded-t-sm', roleBgColors[ep.role])}>
          {getRoleIcon(ep.role)}
          <span className={cn('rounded-full px-1 py-0.5 text-[9px] font-medium leading-none', roleBadgeColors[ep.role])}>
            {roleLabels[ep.role]}
          </span>
        </div>

        {/* Body */}
        <div className="px-2 py-1.5">
          <div className="text-xs font-semibold text-gray-900 truncate">{ep.name}</div>
          <div className="text-[10px] text-gray-600 font-mono">
            {ep.ip}{ep.port != null ? `:${ep.port}` : ''}
          </div>
          {ep.interface && (
            <div className="text-[9px] text-gray-400">
              {ep.interface}
            </div>
          )}
        </div>
      </div>

      <Handle type="source" position={Position.Right} className="!w-2 !h-2 !bg-gray-400 !border-[1.5px] !border-white" />
    </>
  );
}

export const EndpointNode = memo(EndpointNodeComponent);
