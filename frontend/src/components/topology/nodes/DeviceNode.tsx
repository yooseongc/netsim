import { memo } from 'react';
import { type NodeProps, type Node } from '@xyflow/react';
import { Server } from 'lucide-react';

interface DeviceNodeData {
  label: string;
  interfaceCount: number;
  routeCount: number;
  ruleCount: number;
  [key: string]: unknown;
}

function DeviceNodeComponent({ data }: NodeProps<Node<DeviceNodeData>>) {
  return (
    <div className="w-full h-full">
      {/* Header label bar at top */}
      <div className="flex items-center gap-1.5 bg-gray-800 rounded-t-lg px-3 py-1.5">
        <Server className="h-3 w-3 text-gray-300" />
        <span className="text-[10px] font-bold text-white">{data.label || 'Linux Host'}</span>
        <div className="flex items-center gap-2 ml-auto text-[9px] text-gray-400">
          <span>{data.interfaceCount} if</span>
          <span>{data.routeCount} rt</span>
          <span>{data.ruleCount} rl</span>
        </div>
      </div>
    </div>
  );
}

export const DeviceNode = memo(DeviceNodeComponent);
