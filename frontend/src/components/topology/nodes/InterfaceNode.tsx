import { memo } from 'react';
import { Handle, Position, type NodeProps, type Node } from '@xyflow/react';
import { Network } from 'lucide-react';
import type { Interface } from '@/types/scenario';

type InterfaceNodeData = Interface & Record<string, unknown>;

function InterfaceNodeComponent({ data, selected }: NodeProps<Node<InterfaceNodeData>>) {
  const iface = data as Interface;
  const addresses = (iface.addresses ?? []).map((a) => `${a.ip}/${a.prefix_len}`);
  const isUp = (iface.state ?? 'up') === 'up';

  return (
    <>
      <Handle type="target" position={Position.Left} className="!w-2 !h-2 !bg-indigo-400 !border-[1.5px] !border-white" />

      <div
        className={`w-[140px] rounded-md border bg-white shadow-sm transition-shadow ${
          selected
            ? 'border-indigo-500 ring-2 ring-indigo-200 shadow-md'
            : 'border-gray-200'
        }`}
      >
        {/* Header */}
        <div className="flex items-center gap-1 bg-indigo-50 border-b border-indigo-100 rounded-t-md px-2 py-1">
          <Network className="h-3 w-3 text-indigo-500" />
          <span className="text-[10px] font-bold text-indigo-800 font-mono">{iface.name}</span>
          <span
            className={`ml-auto rounded-full px-1 py-0.5 text-[8px] font-medium leading-none ${
              isUp ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'
            }`}
          >
            {isUp ? 'UP' : 'DN'}
          </span>
        </div>

        {/* Body */}
        <div className="px-2 py-1">
          {addresses.length > 0 ? (
            addresses.map((addr, i) => (
              <div key={i} className="text-[10px] font-mono text-gray-700">{addr}</div>
            ))
          ) : (
            <div className="text-[10px] text-gray-400 italic">no addr</div>
          )}
          <div className="text-[9px] text-gray-400">
            MTU {iface.mtu ?? 1500}
            {iface.kind && typeof iface.kind === 'string' && iface.kind !== 'physical' && (
              <span className="ml-1 rounded bg-gray-100 px-0.5">{iface.kind}</span>
            )}
          </div>
        </div>
      </div>

      <Handle type="source" position={Position.Right} className="!w-2 !h-2 !bg-indigo-400 !border-[1.5px] !border-white" />
    </>
  );
}

export const InterfaceNode = memo(InterfaceNodeComponent);
