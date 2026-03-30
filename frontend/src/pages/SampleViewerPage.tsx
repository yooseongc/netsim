import { useEffect, useState, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Play, ArrowLeft, FlaskConical, Copy, ClipboardList } from 'lucide-react';
import { api } from '@/api/client';
import { cn } from '@/lib/utils';
import { SimulationResultDialog } from '@/components/trace/SimulationResultDialog';
import { TopologyEditor } from '@/components/topology/TopologyEditor';
import { PacketEditor } from '@/components/editors/PacketEditor';
import { InterfacesEditor } from '@/components/editors/InterfacesEditor';
import { RoutingEditor } from '@/components/editors/RoutingEditor';
import { RulesEditor } from '@/components/editors/RulesEditor';
import { XdpEditor } from '@/components/editors/XdpEditor';
import type { Scenario } from '@/types/scenario';
import type { SimulationResult } from '@/types/trace';
import jsYaml from 'js-yaml';

type EditorTab = 'topology' | 'packet' | 'interfaces' | 'routing' | 'rules' | 'xdp' | 'yaml';

const TABS: { key: EditorTab; label: string }[] = [
  { key: 'topology', label: 'Topology' },
  { key: 'packet', label: 'Packet' },
  { key: 'interfaces', label: 'Interfaces' },
  { key: 'routing', label: 'Routing' },
  { key: 'rules', label: 'Rules' },
  { key: 'xdp', label: 'XDP' },
  { key: 'yaml', label: 'YAML' },
];

const defaultPacket = {
  ingress_interface: '',
  ethertype: 'ipv4' as const,
  protocol: 'tcp' as const,
  conntrack_state: 'new' as const,
  initial_mark: 0,
  initial_ct_mark: 0,
};

export function SampleViewerPage() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const sampleName = name ?? '';

  const [scenario, setScenario] = useState<Scenario | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [simulationResult, setSimulationResult] = useState<SimulationResult | null>(null);
  const [copying, setCopying] = useState(false);
  const [showResultDialog, setShowResultDialog] = useState(false);
  const [activeTab, setActiveTab] = useState<EditorTab>('topology');
  const descriptionRef = useRef<string>('');

  useEffect(() => {
    setLoading(true);
    setError(null);
    api.getSample(sampleName)
      .then((s) => {
        setScenario(s);
        descriptionRef.current = s.description ?? '';
      })
      .catch((e) => setError(e instanceof Error ? e.message : 'Failed to load sample'))
      .finally(() => setLoading(false));
  }, [sampleName]);

  const handleRun = async () => {
    setRunning(true);
    setError(null);
    try {
      const result = await api.simulateSample(sampleName);
      setSimulationResult(result);
      setActiveTab('topology');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Simulation failed');
    } finally {
      setRunning(false);
    }
  };

  const handleCopyToProject = async () => {
    if (!scenario) return;
    setCopying(true);
    setError(null);
    try {
      const projectName = `${sampleName}-copy`;
      await api.createProject({ name: projectName, description: scenario.description ?? undefined });
      await api.saveScenario(projectName, scenario);
      navigate(`/projects/${encodeURIComponent(projectName)}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to copy');
    } finally {
      setCopying(false);
    }
  };

  // No-op change handlers (read-only)
  const noop = useCallback(() => {}, []);
  const noopAny = useCallback((_: unknown) => {}, []);

  const interfaceNames = (scenario?.interfaces ?? []).map((i) => i.name).filter(Boolean);
  const yamlText = scenario ? jsYaml.dump(scenario, { lineWidth: 120, noRefs: true }) : '';

  return (
    <div className="flex flex-col h-full max-w-5xl mx-auto p-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4 flex-shrink-0">
        <button
          onClick={() => navigate('/')}
          className="rounded p-1.5 text-gray-500 hover:bg-gray-100 transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
        </button>
        <FlaskConical className="h-5 w-5 text-indigo-500" />
        <h2 className="text-2xl font-bold text-gray-900">{sampleName}</h2>
        <span className="rounded-full bg-indigo-100 px-2.5 py-0.5 text-xs font-medium text-indigo-700">
          Sample (Read-only)
        </span>
      </div>

      {descriptionRef.current && (
        <div className="mb-3 rounded-md border border-indigo-200 bg-indigo-50 px-4 py-3 text-sm text-indigo-700 flex-shrink-0">
          {descriptionRef.current}
        </div>
      )}

      {error && (
        <div className="mb-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 flex-shrink-0">
          {error}
        </div>
      )}

      {/* Tab bar */}
      <div className="mb-3 flex border-b border-gray-200 overflow-x-auto flex-shrink-0">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={cn(
              'px-4 py-2 text-sm font-medium border-b-2 transition-colors -mb-px whitespace-nowrap',
              activeTab === tab.key
                ? 'border-gray-900 text-gray-900'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300',
            )}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Editor area */}
      {loading ? (
        <div className="flex-1 flex items-center justify-center text-gray-400">
          Loading sample...
        </div>
      ) : (
        <div className={cn(
          'flex-1 min-h-0',
          activeTab === 'topology' ? 'overflow-hidden' : 'overflow-y-auto',
        )}>
          {activeTab === 'topology' && scenario && (
            <TopologyEditor
              topology={scenario.topology ?? { endpoints: [], flows: [] }}
              onChange={noopAny as never}
              interfaces={scenario.interfaces ?? []}
              onChangeInterfaces={noopAny as never}
              projectName={sampleName}
              routeCount={(scenario.routing_tables ?? []).reduce((s, t) => s + (t.routes ?? []).length, 0)}
              ruleCount={(scenario.netfilter?.nftables?.tables ?? []).reduce(
                (s, t) => s + (t.chains ?? []).reduce((cs, c) => cs + (c.rules ?? []).length, 0),
                0,
              )}
              simulationResult={simulationResult}
              onCloseReplay={() => setSimulationResult(null)}
              readOnly
            />
          )}

          {activeTab === 'packet' && scenario && (
            <PacketEditor
              packet={scenario.packet ?? defaultPacket}
              onChange={noop as never}
              interfaceNames={interfaceNames}
            />
          )}

          {activeTab === 'interfaces' && scenario && (
            <InterfacesEditor
              interfaces={scenario.interfaces ?? []}
              onChange={noop as never}
            />
          )}

          {activeTab === 'routing' && scenario && (
            <RoutingEditor
              routingTables={scenario.routing_tables ?? []}
              ipRules={scenario.ip_rules ?? []}
              onChangeRoutingTables={noop as never}
              onChangeIpRules={noop as never}
              interfaceNames={interfaceNames}
            />
          )}

          {activeTab === 'rules' && scenario && (
            <RulesEditor
              netfilter={scenario.netfilter ?? { nftables: { tables: [] }, iptables: { tables: [] } }}
              onChange={noop as never}
            />
          )}

          {activeTab === 'xdp' && scenario && (
            <XdpEditor
              xdp={scenario.xdp ?? { programs: [] }}
              onChange={noop as never}
              interfaceNames={interfaceNames}
            />
          )}

          {activeTab === 'yaml' && (
            <div className="flex-1 flex flex-col min-h-0">
              <textarea
                value={yamlText}
                readOnly
                className="flex-1 min-h-[400px] w-full rounded-md border border-gray-300 bg-gray-50 p-4 font-mono text-sm text-gray-800 resize-y"
                spellCheck={false}
              />
            </div>
          )}
        </div>
      )}

      {/* Action bar */}
      <div className="mt-4 flex items-center gap-3 border-t pt-4 flex-shrink-0">
        <button
          onClick={() => void handleRun()}
          disabled={running || loading}
          className="inline-flex items-center gap-2 rounded-md bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50 transition-colors"
        >
          <Play className="h-4 w-4" />
          {running ? 'Running...' : 'Run Simulation'}
        </button>
        <button
          onClick={() => void handleCopyToProject()}
          disabled={copying || loading}
          className="inline-flex items-center gap-2 rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 transition-colors"
        >
          <Copy className="h-4 w-4" />
          {copying ? 'Copying...' : 'Copy to Project'}
        </button>
        {simulationResult && (
          <button
            onClick={() => setShowResultDialog(true)}
            className="inline-flex items-center gap-2 rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors"
          >
            <ClipboardList className="h-4 w-4" />
            View Result
          </button>
        )}
      </div>

      {showResultDialog && simulationResult && (
        <SimulationResultDialog
          result={simulationResult}
          onClose={() => setShowResultDialog(false)}
        />
      )}
    </div>
  );
}
