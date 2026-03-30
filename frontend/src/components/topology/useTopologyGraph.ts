import { useCallback, useRef } from 'react';
import { type Node, type Edge, MarkerType } from '@xyflow/react';
import type { Topology, Endpoint, TrafficFlow } from '@/types/scenario';

export function topologyToNodes(endpoints: Endpoint[]): Node[] {
  return endpoints.map((ep, i) => ({
    id: ep.name,
    type: 'endpoint',
    position: ep.position ?? { x: i * 250, y: 100 },
    data: { ...ep } as Record<string, unknown>,
  }));
}

export function topologyToEdges(flows: TrafficFlow[]): Edge[] {
  return flows.map((flow) => ({
    id: flow.name,
    type: 'flow',
    source: flow.source,
    target: flow.destination,
    data: { ...flow } as Record<string, unknown>,
    markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16 },
    animated: true,
  }));
}

export function applyNodePositions(
  topology: Topology,
  nodes: Node[],
): Topology {
  const posMap = new Map<string, { x: number; y: number }>();
  for (const node of nodes) {
    posMap.set(node.id, { x: Math.round(node.position.x), y: Math.round(node.position.y) });
  }

  return {
    ...topology,
    endpoints: (topology.endpoints ?? []).map((ep) => ({
      ...ep,
      position: posMap.get(ep.name) ?? ep.position ?? null,
    })),
  };
}

export function useTopologyGraph() {
  const prevTopologyRef = useRef<Topology | null>(null);

  const needsLayout = useCallback((endpoints: Endpoint[]): boolean => {
    return endpoints.length > 0 && endpoints.every((ep) => !ep.position);
  }, []);

  const hasTopologyChanged = useCallback((topology: Topology): boolean => {
    const prev = prevTopologyRef.current;
    if (!prev) {
      prevTopologyRef.current = topology;
      return true;
    }

    const prevEps = prev.endpoints ?? [];
    const currEps = topology.endpoints ?? [];
    const prevFlows = prev.flows ?? [];
    const currFlows = topology.flows ?? [];

    if (prevEps.length !== currEps.length || prevFlows.length !== currFlows.length) {
      prevTopologyRef.current = topology;
      return true;
    }

    // Check if endpoint names or flow names changed
    const prevEpNames = new Set(prevEps.map((e) => e.name));
    const currEpNames = new Set(currEps.map((e) => e.name));
    const prevFlowNames = new Set(prevFlows.map((f) => f.name));
    const currFlowNames = new Set(currFlows.map((f) => f.name));

    const changed =
      currEps.some((e) => !prevEpNames.has(e.name)) ||
      prevEps.some((e) => !currEpNames.has(e.name)) ||
      currFlows.some((f) => !prevFlowNames.has(f.name)) ||
      prevFlows.some((f) => !currFlowNames.has(f.name));

    if (changed) {
      prevTopologyRef.current = topology;
    }
    return changed;
  }, []);

  return { topologyToNodes, topologyToEdges, applyNodePositions, needsLayout, hasTopologyChanged };
}
