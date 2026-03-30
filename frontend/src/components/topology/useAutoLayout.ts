import { useCallback } from 'react';
import { type Node, type Edge } from '@xyflow/react';
import dagre from '@dagrejs/dagre';

const NODE_WIDTH = 200;
const NODE_HEIGHT = 90;

export function useAutoLayout() {
  const computeLayout = useCallback(
    (nodes: Node[], edges: Edge[], direction: 'LR' | 'TB' = 'LR'): Node[] => {
      const g = new dagre.graphlib.Graph();
      g.setGraph({ rankdir: direction, nodesep: 80, ranksep: 150 });
      g.setDefaultEdgeLabel(() => ({}));

      for (const node of nodes) {
        g.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT });
      }
      for (const edge of edges) {
        g.setEdge(edge.source, edge.target);
      }

      dagre.layout(g);

      return nodes.map((node) => {
        const pos = g.node(node.id);
        return {
          ...node,
          position: {
            x: (pos as { x: number }).x - NODE_WIDTH / 2,
            y: (pos as { y: number }).y - NODE_HEIGHT / 2,
          },
        };
      });
    },
    [],
  );

  return { computeLayout };
}
