import type { Topology, TrafficFlow, Interface as IFace } from '@/types/scenario';
import type { SimulationResult } from '@/types/trace';
import { TopologyCanvas } from './TopologyCanvas';

interface TopologyEditorProps {
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

export function TopologyEditor({
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
}: TopologyEditorProps) {
  return (
    <TopologyCanvas
      topology={topology}
      onChange={onChange}
      interfaces={interfaces}
      onChangeInterfaces={onChangeInterfaces}
      projectName={projectName}
      routeCount={routeCount}
      ruleCount={ruleCount}
      onSimulateFlow={onSimulateFlow}
      simulationResult={simulationResult}
      onCloseReplay={onCloseReplay}
      readOnly={readOnly}
    />
  );
}
