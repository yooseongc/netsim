import { useCallback, useEffect, useMemo, useState, useRef } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  type Connection,
  type NodeMouseHandler,
  type EdgeMouseHandler,
  type Node,
  type Edge,
  MarkerType,
  ReactFlowProvider,
  useReactFlow,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import type {
  Topology,
  Endpoint,
  TrafficFlow,
  EndpointRole,
  Interface as IFace,
} from '@/types/scenario';
import type { SimulationResult, TraceStep } from '@/types/trace';
import { EndpointNode } from './nodes/EndpointNode';
import { DeviceNode } from './nodes/DeviceNode';
import { InterfaceNode } from './nodes/InterfaceNode';
import { FlowEdge } from './edges/FlowEdge';
import { TopologyToolbar } from './TopologyToolbar';
import { TopologyPropertiesPanel } from './TopologyPropertiesPanel';
import { SimulationReplayBar } from './SimulationReplayBar';
import { EndpointForm } from './EndpointForm';
import { FlowForm } from './FlowForm';

const DEVICE_ID = '__device__';
const ifNodeId = (name: string) => `__if:${name}__`;

const nodeTypes = { endpoint: EndpointNode, device: DeviceNode, interface: InterfaceNode };
const edgeTypes = { flow: FlowEdge };

function isLocalRole(role: EndpointRole): boolean {
  return role === 'local_client' || role === 'local_server' || role === 'local_proxy' || role === 'local_tproxy';
}

// ── Compute device boundary size ──

function computeDeviceSize(interfaces: IFace[], localEndpoints: Endpoint[]): { width: number; height: number } {
  const cols = Math.max(interfaces.length, localEndpoints.length, 2);
  const width = Math.max(380, cols * 170 + 40);
  const height = Math.max(220, (interfaces.length > 0 ? 100 : 0) + (localEndpoints.length > 0 ? 110 : 0) + 60);
  return { width, height };
}

// ── Build nodes ──

function buildNodes(
  projectName: string,
  interfaces: IFace[],
  endpoints: Endpoint[],
  routeCount: number,
  ruleCount: number,
  positions: Record<string, { x: number; y: number }>,
): Node[] {
  const nodes: Node[] = [];
  const localEps = endpoints.filter((ep) => isLocalRole(ep.role));
  const remoteEps = endpoints.filter((ep) => !isLocalRole(ep.role));
  const { width, height } = computeDeviceSize(interfaces, localEps);

  // 1. Device boundary (group node)
  nodes.push({
    id: DEVICE_ID,
    type: 'device',
    position: positions[DEVICE_ID] ?? { x: 300, y: 100 },
    style: {
      width,
      height,
      background: 'rgba(249,250,251,0.85)',
      border: '2px dashed #9ca3af',
      borderRadius: 12,
      padding: 0,
    },
    data: {
      label: projectName || 'Linux Host',
      interfaceCount: interfaces.length,
      routeCount,
      ruleCount,
    } as Record<string, unknown>,
  });

  // 2. Interfaces → inside device (parentId)
  for (let i = 0; i < interfaces.length; i++) {
    const iface = interfaces[i];
    const id = ifNodeId(iface.name);
    nodes.push({
      id,
      type: 'interface',
      parentId: DEVICE_ID,
      extent: 'parent' as const,
      position: positions[id] ?? { x: 20 + i * 160, y: 40 },
      data: { ...iface } as Record<string, unknown>,
    });
  }

  // 3. Local endpoints → inside device
  for (let i = 0; i < localEps.length; i++) {
    const ep = localEps[i];
    nodes.push({
      id: ep.name,
      type: 'endpoint',
      parentId: DEVICE_ID,
      extent: 'parent' as const,
      position: ep.position ?? positions[ep.name] ?? { x: 20 + i * 180, y: height - 100 },
      data: { ...ep } as Record<string, unknown>,
    });
  }

  // 4. Remote endpoints → outside device
  const devicePos = positions[DEVICE_ID] ?? { x: 300, y: 100 };
  for (let i = 0; i < remoteEps.length; i++) {
    const ep = remoteEps[i];
    const isClient = ep.role === 'remote_client';
    const defaultX = isClient ? devicePos.x - 220 : devicePos.x + width + 60;
    const defaultY = devicePos.y + 40 + i * 100;
    nodes.push({
      id: ep.name,
      type: 'endpoint',
      position: ep.position ?? positions[ep.name] ?? { x: defaultX, y: defaultY },
      data: { ...ep } as Record<string, unknown>,
    });
  }

  return nodes;
}

// ── Build edges ──

function buildEdges(
  interfaces: IFace[],
  endpoints: Endpoint[],
  flows: TrafficFlow[],
): Edge[] {
  const edges: Edge[] = [];
  const ifNames = new Set(interfaces.map((i) => i.name));

  // Endpoint ↔ Interface connections
  for (const ep of endpoints) {
    if (ep.interface && ifNames.has(ep.interface)) {
      const ifId = ifNodeId(ep.interface);
      const isLocal = isLocalRole(ep.role);
      edges.push({
        id: `link:${ep.name}-${ep.interface}`,
        source: ep.name,
        target: ifId,
        type: 'default',
        style: {
          stroke: isLocal ? '#a5b4fc' : '#94a3b8',
          strokeWidth: 1.5,
          strokeDasharray: isLocal ? '6 3' : '4 2',
        },
        markerEnd: isLocal ? undefined : { type: MarkerType.ArrowClosed, width: 12, height: 12, color: '#94a3b8' },
      });
    }
  }

  // Traffic flow edges
  for (const flow of flows) {
    edges.push({
      id: flow.name,
      type: 'flow',
      source: flow.source,
      target: flow.destination,
      data: { ...flow } as Record<string, unknown>,
      markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16 },
      animated: true,
    });
  }

  return edges;
}

function collectPositions(nodes: Node[], endpoints: Endpoint[]): {
  nodePositions: Record<string, { x: number; y: number }>;
  endpointPositions: Map<string, { x: number; y: number }>;
} {
  const nodePositions: Record<string, { x: number; y: number }> = {};
  const endpointPositions = new Map<string, { x: number; y: number }>();
  const epNames = new Set(endpoints.map((e) => e.name));

  for (const node of nodes) {
    const pos = { x: Math.round(node.position.x), y: Math.round(node.position.y) };
    if (epNames.has(node.id)) {
      endpointPositions.set(node.id, pos);
    } else {
      nodePositions[node.id] = pos;
    }
  }
  return { nodePositions, endpointPositions };
}

// ── Main component ──

// ── Replay highlighting ──

const INGRESS_STAGES = new Set(['interface_check', 'arp_process', 'xdp', 'rp_filter', 'tc_ingress']);
const EGRESS_STAGES = new Set(['post_routing', 'mtu_check', 'conntrack_confirm']);

function getReplayHighlight(
  step: TraceStep | undefined,
  endpoints: Endpoint[],
): { highlightNodes: Set<string>; highlightEdges: Set<string>; phase: 'ingress' | 'device' | 'egress' | 'done' } {
  const highlightNodes = new Set<string>();
  const highlightEdges = new Set<string>();

  if (!step) return { highlightNodes, highlightEdges, phase: 'done' };

  const stage = step.stage;
  const ingressIf = step.state_before.ingress_if;
  const egressIf = step.state_after.egress_if;
  const decision = step.decision;

  // ── Phase 1: Ingress — packet arriving from outside into interface ──
  if (INGRESS_STAGES.has(stage)) {
    // Highlight ingress interface
    if (ingressIf) highlightNodes.add(ifNodeId(ingressIf));

    // Highlight source endpoint + edge (packet coming IN)
    for (const ep of endpoints) {
      if (ep.interface === ingressIf && !isLocalRole(ep.role)) {
        highlightNodes.add(ep.name);
        highlightEdges.add(`link:${ep.name}-${ingressIf}`);
      }
    }
    // Highlight traffic flow edges from this source
    for (const ep of endpoints) {
      if (ep.interface === ingressIf && !isLocalRole(ep.role)) {
        // find flows where this endpoint is source
        for (const ep2 of endpoints) {
          if (ep2.name !== ep.name) {
            // Any flow edge between them
            highlightEdges.add(`${ep.name}-to-${ep2.name}`);
          }
        }
      }
    }

    return { highlightNodes, highlightEdges, phase: 'ingress' };
  }

  // ── Phase 3: Egress — packet leaving device through interface ──
  if (EGRESS_STAGES.has(stage) || (decision.type === 'forward_to')) {
    highlightNodes.add(DEVICE_ID);

    // Highlight egress interface
    const outIf = decision.type === 'forward_to' ? decision.egress_if : egressIf;
    if (outIf) {
      highlightNodes.add(ifNodeId(outIf));
      // Highlight destination endpoint + edge (packet going OUT)
      for (const ep of endpoints) {
        if (ep.interface === outIf && !isLocalRole(ep.role)) {
          highlightNodes.add(ep.name);
          highlightEdges.add(`link:${ep.name}-${outIf}`);
        }
      }
    }

    // Also keep ingress visible
    if (ingressIf) highlightNodes.add(ifNodeId(ingressIf));

    return { highlightNodes, highlightEdges, phase: 'egress' };
  }

  // ── Phase 2: Device internal — packet being processed inside ──
  highlightNodes.add(DEVICE_ID);
  if (ingressIf) highlightNodes.add(ifNodeId(ingressIf));

  // On routing decision, also show egress interface
  if (stage === 'routing_decision' && egressIf) {
    highlightNodes.add(ifNodeId(egressIf));
  }

  // On local_delivery, highlight local endpoints
  if (decision.type === 'local_delivery') {
    for (const ep of endpoints) {
      if (isLocalRole(ep.role)) highlightNodes.add(ep.name);
    }
  }

  // On drop/reject, dim everything (only device highlighted)
  if (decision.type === 'drop' || decision.type === 'reject') {
    // Only device stays highlighted
  }

  return { highlightNodes, highlightEdges, phase: 'device' };
}

function applyReplayStyles(
  nodes: Node[],
  edges: Edge[],
  highlightNodes: Set<string>,
  highlightEdges: Set<string>,
  phase: string,
  verdict?: string,
): { styledNodes: Node[]; styledEdges: Edge[] } {
  // Phase colors: ingress=blue, device=purple, egress=amber
  let phaseColor = phase === 'ingress' ? '#3b82f6' : phase === 'egress' ? '#f59e0b' : '#8b5cf6';
  // Override with verdict color for terminal states
  if (verdict === 'drop' || verdict === 'rejected') phaseColor = '#ef4444';
  else if (verdict === 'local_delivery') phaseColor = '#22c55e';

  const styledNodes = nodes.map((node) => {
    if (highlightNodes.has(node.id)) {
      return {
        ...node,
        style: {
          ...node.style,
          boxShadow: `0 0 0 2px ${phaseColor}, 0 0 16px ${phaseColor}50`,
          transition: 'all 0.3s ease',
        },
      };
    }
    return {
      ...node,
      style: { ...node.style, opacity: 0.3, transition: 'all 0.3s ease' },
    };
  });

  const styledEdges = edges.map((edge) => {
    if (highlightEdges.has(edge.id)) {
      return {
        ...edge,
        animated: true,
        style: { ...edge.style, stroke: phaseColor, strokeWidth: 2.5 },
      };
    }
    return {
      ...edge,
      animated: false,
      style: { ...edge.style, opacity: 0.15 },
    };
  });

  return { styledNodes, styledEdges };
}

export interface TopologyCanvasProps {
  topology: Topology;
  onChange: (topology: Topology) => void;
  interfaces: IFace[];
  onChangeInterfaces: (interfaces: IFace[]) => void;
  projectName: string;
  routeCount: number;
  ruleCount: number;
  onSimulateFlow?: (flow: TrafficFlow) => void;
  simulationResult?: SimulationResult | null;
  onCloseReplay?: () => void;
  readOnly?: boolean;
}

function CanvasInner({
  topology,
  onChange,
  interfaces,
  onChangeInterfaces,
  projectName,
  routeCount,
  ruleCount,
  onSimulateFlow,
  simulationResult,
  onCloseReplay,
  readOnly,
}: TopologyCanvasProps) {
  const { fitView } = useReactFlow();

  const endpoints = useMemo(() => topology.endpoints ?? [], [topology.endpoints]);
  const flows = useMemo(() => topology.flows ?? [], [topology.flows]);
  const positions = useMemo(() => topology.node_positions ?? {}, [topology.node_positions]);
  const endpointNames = useMemo(() => endpoints.map((e) => e.name), [endpoints]);

  const initialNodes = useMemo(
    () => buildNodes(projectName, interfaces, endpoints, routeCount, ruleCount, positions),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );
  const initialEdges = useMemo(
    () => buildEdges(interfaces, endpoints, flows),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Replay state
  const [replayStep, setReplayStep] = useState(0);
  const isReplaying = !!simulationResult;

  // Compute replay-styled nodes/edges
  const displayNodes = useMemo(() => {
    if (!isReplaying || !simulationResult) return nodes;
    const step = simulationResult.trace[replayStep];
    const { highlightNodes, highlightEdges, phase } = getReplayHighlight(step, endpoints);
    const isTerminal = replayStep === simulationResult.trace.length - 1;
    const termVerdict = isTerminal ? simulationResult.verdict : undefined;
    return applyReplayStyles(nodes, edges, highlightNodes, highlightEdges, phase, termVerdict).styledNodes;
  }, [isReplaying, simulationResult, replayStep, nodes, edges, interfaces, endpoints]);

  const displayEdges = useMemo(() => {
    if (!isReplaying || !simulationResult) return edges;
    const step = simulationResult.trace[replayStep];
    const { highlightNodes, highlightEdges, phase } = getReplayHighlight(step, endpoints);
    const isTerminal = replayStep === simulationResult.trace.length - 1;
    const termVerdict = isTerminal ? simulationResult.verdict : undefined;
    return applyReplayStyles(nodes, edges, highlightNodes, highlightEdges, phase, termVerdict).styledEdges;
  }, [isReplaying, simulationResult, replayStep, nodes, edges, interfaces, endpoints]);

  // Reset replay step when result changes
  useEffect(() => {
    if (simulationResult) setReplayStep(0);
  }, [simulationResult]);

  // Selection
  const [selectedEndpoint, setSelectedEndpoint] = useState<Endpoint | null>(null);
  const [selectedFlow, setSelectedFlow] = useState<TrafficFlow | null>(null);
  const [selectedInterface, setSelectedInterface] = useState<IFace | null>(null);

  // Modals
  const [editingEndpoint, setEditingEndpoint] = useState<Endpoint | null>(null);
  const [showEndpointForm, setShowEndpointForm] = useState(false);
  const [presetRole, setPresetRole] = useState<EndpointRole | null>(null);
  const [editingFlow, setEditingFlow] = useState<TrafficFlow | null>(null);
  const [showFlowForm, setShowFlowForm] = useState(false);
  const [defaultFlowSource, setDefaultFlowSource] = useState<string | undefined>();
  const [defaultFlowDest, setDefaultFlowDest] = useState<string | undefined>();

  const internalChangeRef = useRef(false);
  const initialFitDoneRef = useRef(false);

  // Sync external → React Flow
  useEffect(() => {
    if (internalChangeRef.current) {
      internalChangeRef.current = false;
      return;
    }
    const newNodes = buildNodes(projectName, interfaces, endpoints, routeCount, ruleCount, positions);
    const newEdges = buildEdges(interfaces, endpoints, flows);
    setNodes(newNodes);
    setEdges(newEdges);

    if (!initialFitDoneRef.current && newNodes.length > 0) {
      initialFitDoneRef.current = true;
      setTimeout(() => fitView({ padding: 0.15 }), 100);
    }
  }, [projectName, interfaces, endpoints, flows, positions, routeCount, ruleCount, setNodes, setEdges, fitView]);

  // ── Persist positions ──

  const persistPositions = useCallback(
    (updatedNodes: Node[]) => {
      const { nodePositions, endpointPositions } = collectPositions(updatedNodes, endpoints);
      const updatedEndpoints = endpoints.map((ep) => ({
        ...ep,
        position: endpointPositions.get(ep.name) ?? ep.position,
      }));
      internalChangeRef.current = true;
      onChange({ ...topology, endpoints: updatedEndpoints, node_positions: nodePositions });
    },
    [endpoints, onChange, topology],
  );

  const onNodeDragStop = useCallback(
    (_: React.MouseEvent, _node: Node, draggedNodes: Node[]) => {
      setNodes((currentNodes) => {
        const updated = [...currentNodes];
        for (const dragged of draggedNodes) {
          const idx = updated.findIndex((n) => n.id === dragged.id);
          if (idx >= 0) updated[idx] = { ...updated[idx], position: dragged.position };
        }
        persistPositions(updated);
        return updated;
      });
    },
    [setNodes, persistPositions],
  );

  // ── Selection ──

  const clearSelection = useCallback(() => {
    setSelectedEndpoint(null);
    setSelectedFlow(null);
    setSelectedInterface(null);
  }, []);

  const onNodeClick: NodeMouseHandler = useCallback(
    (_, node) => {
      clearSelection();
      if (node.type === 'endpoint') {
        setSelectedEndpoint(endpoints.find((e) => e.name === node.id) ?? null);
      } else if (node.type === 'interface') {
        const ifName = node.id.replace(/^__if:|__$/g, '');
        setSelectedInterface(interfaces.find((i) => i.name === ifName) ?? null);
      }
    },
    [endpoints, interfaces, clearSelection],
  );

  const onEdgeClick: EdgeMouseHandler = useCallback(
    (_, edge) => {
      clearSelection();
      const flow = flows.find((f) => f.name === edge.id);
      if (flow) setSelectedFlow(flow);
    },
    [flows, clearSelection],
  );

  const onConnect = useCallback(
    (connection: Connection) => {
      if (!connection.source || !connection.target) return;
      const srcIsEp = endpoints.some((e) => e.name === connection.source);
      const tgtIsEp = endpoints.some((e) => e.name === connection.target);
      if (srcIsEp && tgtIsEp) {
        setDefaultFlowSource(connection.source);
        setDefaultFlowDest(connection.target);
        setEditingFlow(null);
        setShowFlowForm(true);
      }
    },
    [endpoints],
  );

  // ── CRUD ──

  const handleAddEndpoint = useCallback((role: EndpointRole) => {
    setPresetRole(role);
    setEditingEndpoint(null);
    setShowEndpointForm(true);
  }, []);

  const handleSaveEndpoint = useCallback(
    (ep: Endpoint) => {
      internalChangeRef.current = true;
      let updated: Endpoint[];
      if (editingEndpoint) {
        updated = endpoints.map((e) => (e.name === editingEndpoint.name ? ep : e));
      } else {
        updated = [...endpoints, ep];
      }
      onChange({ ...topology, endpoints: updated });
      setShowEndpointForm(false);
      setEditingEndpoint(null);
      setPresetRole(null);
    },
    [editingEndpoint, endpoints, onChange, topology],
  );

  const handleDeleteEndpoint = useCallback(
    (name: string) => {
      internalChangeRef.current = true;
      onChange({
        ...topology,
        endpoints: endpoints.filter((e) => e.name !== name),
        flows: flows.filter((f) => f.source !== name && f.destination !== name),
      });
      clearSelection();
    },
    [endpoints, flows, onChange, topology, clearSelection],
  );

  const handleSaveFlow = useCallback(
    (flow: TrafficFlow) => {
      internalChangeRef.current = true;
      let updated: TrafficFlow[];
      if (editingFlow) {
        updated = flows.map((f) => (f.name === editingFlow.name ? flow : f));
      } else {
        updated = [...flows, flow];
      }
      onChange({ ...topology, flows: updated });
      setShowFlowForm(false);
      setEditingFlow(null);
      setDefaultFlowSource(undefined);
      setDefaultFlowDest(undefined);
    },
    [editingFlow, flows, onChange, topology],
  );

  const handleDeleteFlow = useCallback(
    (name: string) => {
      internalChangeRef.current = true;
      onChange({ ...topology, flows: flows.filter((f) => f.name !== name) });
      clearSelection();
    },
    [flows, onChange, topology, clearSelection],
  );

  const handleDeleteInterface = useCallback(
    (name: string) => {
      onChangeInterfaces(interfaces.filter((i) => i.name !== name));
      clearSelection();
    },
    [interfaces, onChangeInterfaces, clearSelection],
  );

  const handleAutoLayout = useCallback(() => {
    const newNodes = buildNodes(projectName, interfaces, endpoints, routeCount, ruleCount, {});
    const newEdges = buildEdges(interfaces, endpoints, flows);
    setNodes(newNodes);
    setEdges(newEdges);
    persistPositions(newNodes);
    setTimeout(() => fitView({ padding: 0.15 }), 50);
  }, [projectName, interfaces, endpoints, flows, routeCount, ruleCount, setNodes, setEdges, persistPositions, fitView]);

  const onKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Delete' || e.key === 'Backspace') {
        if (selectedEndpoint) handleDeleteEndpoint(selectedEndpoint.name);
        else if (selectedFlow) handleDeleteFlow(selectedFlow.name);
        else if (selectedInterface) handleDeleteInterface(selectedInterface.name);
      }
      if (e.key === 'Escape') clearSelection();
    },
    [selectedEndpoint, selectedFlow, selectedInterface, handleDeleteEndpoint, handleDeleteFlow, handleDeleteInterface, clearSelection],
  );

  const showPanel = selectedEndpoint || selectedFlow || selectedInterface;

  return (
    <div className="flex h-full" onKeyDown={onKeyDown} tabIndex={0}>
      <div className="flex-1 relative">
        <ReactFlow
          nodes={displayNodes}
          edges={displayEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeDragStop={onNodeDragStop}
          onNodeClick={onNodeClick}
          onEdgeClick={onEdgeClick}
          onPaneClick={clearSelection}
          onConnect={onConnect}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          defaultEdgeOptions={{ animated: false }}
          proOptions={{ hideAttribution: true }}
          className="bg-gray-50"
        >
          <Background gap={20} size={1} color="#e5e7eb" />
          <Controls showInteractive={false} className="!shadow-md !border-gray-200" />
          <MiniMap nodeStrokeWidth={3} className="!shadow-md !border-gray-200" maskColor="rgba(0,0,0,0.08)" />
        </ReactFlow>

        <TopologyToolbar onAddEndpoint={handleAddEndpoint} onAutoLayout={handleAutoLayout} readOnly={readOnly} />

        {isReplaying && simulationResult && (
          <SimulationReplayBar
            result={simulationResult}
            currentStep={replayStep}
            onStepChange={setReplayStep}
            onClose={() => onCloseReplay?.()}
          />
        )}

        {interfaces.length === 0 && endpoints.length === 0 && !isReplaying && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <div className="text-center">
              <div className="text-sm text-gray-400">
                Add interfaces in the <strong>Interfaces</strong> tab, then add endpoints here.
              </div>
            </div>
          </div>
        )}
      </div>

      {showPanel && (
        <TopologyPropertiesPanel
          selectedEndpoint={selectedEndpoint}
          selectedFlow={selectedFlow}
          selectedInterface={selectedInterface}
          onEditEndpoint={(ep) => { setEditingEndpoint(ep); setPresetRole(null); setShowEndpointForm(true); }}
          onDeleteEndpoint={handleDeleteEndpoint}
          onEditFlow={(flow) => { setEditingFlow(flow); setDefaultFlowSource(undefined); setDefaultFlowDest(undefined); setShowFlowForm(true); }}
          onDeleteFlow={handleDeleteFlow}
          onDeleteInterface={handleDeleteInterface}
          onSimulateFlow={onSimulateFlow}
          onClose={clearSelection}
        />
      )}

      {showEndpointForm && (
        <EndpointForm
          endpoint={editingEndpoint ?? (presetRole ? { name: '', role: presetRole, ip: '' } as Endpoint : null)}
          onSave={handleSaveEndpoint}
          onCancel={() => { setShowEndpointForm(false); setEditingEndpoint(null); setPresetRole(null); }}
        />
      )}

      {showFlowForm && (
        <FlowForm
          flow={editingFlow}
          endpointNames={endpointNames}
          onSave={handleSaveFlow}
          onCancel={() => { setShowFlowForm(false); setEditingFlow(null); setDefaultFlowSource(undefined); setDefaultFlowDest(undefined); }}
          defaultSource={defaultFlowSource}
          defaultDestination={defaultFlowDest}
        />
      )}
    </div>
  );
}

export function TopologyCanvas(props: TopologyCanvasProps) {
  return (
    <ReactFlowProvider>
      <CanvasInner {...props} />
    </ReactFlowProvider>
  );
}
