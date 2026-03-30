import { memo } from 'react';
import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
  type EdgeProps,
  type Edge,
} from '@xyflow/react';
import type { TrafficFlow } from '@/types/scenario';

type FlowEdgeData = TrafficFlow & Record<string, unknown>;

function FlowEdgeComponent({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
  selected,
  markerEnd,
}: EdgeProps<Edge<FlowEdgeData>>) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const flow = data as TrafficFlow | undefined;

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          stroke: selected ? '#3b82f6' : '#94a3b8',
          strokeWidth: selected ? 2.5 : 1.5,
          strokeDasharray: '6 3',
        }}
      />
      <EdgeLabelRenderer>
        <div
          className="nodrag nopan pointer-events-auto"
          style={{
            position: 'absolute',
            transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
          }}
        >
          <div className="flex items-center gap-1 rounded-full bg-white border border-gray-200 px-2 py-0.5 shadow-sm">
            <span className="text-[10px] font-medium text-gray-700">
              {flow?.name ?? id}
            </span>
            {flow?.protocol && (
              <span className="rounded bg-gray-100 px-1 py-0.5 text-[9px] font-medium text-gray-500 uppercase">
                {flow.protocol}
              </span>
            )}
          </div>
        </div>
      </EdgeLabelRenderer>
    </>
  );
}

export const FlowEdge = memo(FlowEdgeComponent);
