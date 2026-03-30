import { useEffect, useState, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Save, Play, ArrowLeft, FileDown, ClipboardList } from 'lucide-react';
import { SimulationResultDialog } from '@/components/trace/SimulationResultDialog';
import { api } from '@/api/client';
import { cn } from '@/lib/utils';
import type { SimulationResult } from '@/types/trace';
import { TopologyEditor } from '@/components/topology/TopologyEditor';
import { PacketEditor } from '@/components/editors/PacketEditor';
import { InterfacesEditor } from '@/components/editors/InterfacesEditor';
import { RoutingEditor } from '@/components/editors/RoutingEditor';
import { RulesEditor } from '@/components/editors/RulesEditor';
import { XdpEditor } from '@/components/editors/XdpEditor';
import type { Topology, Scenario, PacketDef, Interface, RoutingTable, IpRule, NetfilterConfig, XdpConfig } from '@/types/scenario';
import jsYaml from 'js-yaml';

type EditorTab = 'packet' | 'interfaces' | 'routing' | 'rules' | 'xdp' | 'yaml' | 'topology';

const TABS: { key: EditorTab; label: string }[] = [
  { key: 'topology', label: 'Topology' },
  { key: 'packet', label: 'Packet' },
  { key: 'interfaces', label: 'Interfaces' },
  { key: 'routing', label: 'Routing' },
  { key: 'rules', label: 'Rules' },
  { key: 'xdp', label: 'XDP' },
  { key: 'yaml', label: 'YAML' },
];

const defaultPacket: PacketDef = {
  ingress_interface: '',
  ethertype: 'ipv4',
  protocol: 'tcp',
  conntrack_state: 'new',
  initial_mark: 0,
  initial_ct_mark: 0,
};

function parseScenario(yamlText: string, projectName: string): Scenario {
  try {
    const parsed = jsYaml.load(yamlText) as Scenario | null;
    if (parsed && typeof parsed === 'object') {
      return {
        ...parsed,
        name: parsed.name ?? projectName,
        packet: parsed.packet ?? { ...defaultPacket },
      };
    }
  } catch {
    // invalid YAML
  }
  return {
    version: '1.0',
    name: projectName,
    interfaces: [],
    routing_tables: [],
    ip_rules: [],
    netfilter: { nftables: { tables: [] }, iptables: { tables: [] } },
    xdp: { programs: [] },
    packet: { ...defaultPacket },
    topology: { endpoints: [], flows: [] },
  };
}

function scenarioToYaml(scenario: Scenario): string {
  return jsYaml.dump(scenario, { lineWidth: 120, noRefs: true });
}

export function ScenarioEditorPage() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const [yaml, setYaml] = useState('');
  const [scenario, setScenario] = useState<Scenario | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState(false);
  const [simulationResult, setSimulationResult] = useState<SimulationResult | null>(null);
  const [showResultDialog, setShowResultDialog] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<EditorTab>('topology');

  const projectName = name ?? '';
  // Track whether the last change came from YAML textarea editing
  const yamlEditedRef = useRef(false);

  // ── Sync helpers ──

  const syncScenarioFromYaml = useCallback(
    (yamlText: string) => {
      setScenario(parseScenario(yamlText, projectName));
    },
    [projectName],
  );

  const syncYamlFromScenario = useCallback((s: Scenario) => {
    setYaml(scenarioToYaml(s));
  }, []);

  // ── Load ──

  const loadScenario = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const text = await api.getScenarioYaml(projectName);
      setYaml(text);
      syncScenarioFromYaml(text);
    } catch {
      setYaml('');
      setScenario(parseScenario('', projectName));
    } finally {
      setLoading(false);
    }
  }, [projectName, syncScenarioFromYaml]);

  useEffect(() => {
    void loadScenario();
  }, [loadScenario]);

  // ── Tab switching ──

  const handleTabChange = (tab: EditorTab) => {
    // When leaving YAML tab, sync parsed scenario from YAML text
    if (activeTab === 'yaml' && tab !== 'yaml') {
      syncScenarioFromYaml(yaml);
    }
    // When entering YAML tab, sync YAML text from scenario (if we weren't editing YAML)
    if (tab === 'yaml' && activeTab !== 'yaml' && scenario) {
      syncYamlFromScenario(scenario);
    }
    // Clear simulation result when leaving topology tab
    if (activeTab === 'topology' && tab !== 'topology') {
      setSimulationResult(null);
    }
    yamlEditedRef.current = false;
    setActiveTab(tab);
  };

  // ── Scenario section updates ──

  const updateScenarioField = <K extends keyof Scenario>(key: K, value: Scenario[K]) => {
    if (!scenario) return;
    const updated = { ...scenario, [key]: value };
    setScenario(updated);
    syncYamlFromScenario(updated);
  };

  const handleTopologyChange = (topo: Topology) => {
    updateScenarioField('topology', topo);
  };

  const handlePacketChange = (packet: PacketDef) => {
    updateScenarioField('packet', packet);
  };

  const handleInterfacesChange = (ifaces: Interface[]) => {
    updateScenarioField('interfaces', ifaces);
  };

  const handleRoutingTablesChange = (tables: RoutingTable[]) => {
    updateScenarioField('routing_tables', tables);
  };

  const handleIpRulesChange = (rules: IpRule[]) => {
    updateScenarioField('ip_rules', rules);
  };

  const handleNetfilterChange = (config: NetfilterConfig) => {
    updateScenarioField('netfilter', config);
  };

  const handleXdpChange = (config: XdpConfig) => {
    updateScenarioField('xdp', config);
  };

  const handleYamlChange = (text: string) => {
    setYaml(text);
    yamlEditedRef.current = true;
  };

  // ── Save / Run ──

  const handleSave = async () => {
    // If on YAML tab, sync scenario from YAML text first
    if (activeTab === 'yaml') {
      syncScenarioFromYaml(yaml);
    }
    setSaving(true);
    setError(null);
    setStatus(null);
    try {
      // Use the latest scenario state (may have just been synced)
      const toSave = activeTab === 'yaml' ? parseScenario(yaml, projectName) : scenario;
      if (toSave) {
        await api.saveScenario(projectName, toSave);
      }
      setStatus('Saved successfully');
      setTimeout(() => setStatus(null), 3000);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  const handleRun = async () => {
    setRunning(true);
    setError(null);
    setStatus(null);
    try {
      const toSave = activeTab === 'yaml' ? parseScenario(yaml, projectName) : scenario;
      if (toSave) {
        await api.saveScenario(projectName, toSave);
      }
      const response = await api.runSimulation(projectName);
      setSimulationResult(response.result);
      setActiveTab('topology'); // Switch to topology for visual replay
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Simulation failed');
    } finally {
      setRunning(false);
    }
  };

  // ── Derived data ──
  const interfaceNames = (scenario?.interfaces ?? []).map((i) => i.name).filter(Boolean);

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
        <h2 className="text-2xl font-bold text-gray-900">{projectName}</h2>
        <span className="text-sm text-gray-400">Scenario Editor</span>
      </div>

      {error && (
        <div className="mb-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      {status && (
        <div className="mb-3 rounded-md border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-700">
          {status}
        </div>
      )}

      {/* Tab bar */}
      <div className="mb-3 flex border-b border-gray-200 overflow-x-auto flex-shrink-0">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            onClick={() => handleTabChange(tab.key)}
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
          Loading scenario...
        </div>
      ) : (
        <div className={cn(
          'flex-1 min-h-0',
          activeTab === 'topology' ? 'overflow-hidden' : 'overflow-y-auto',
        )}>
          {activeTab === 'packet' && scenario && (
            <PacketEditor
              packet={scenario.packet ?? defaultPacket}
              onChange={handlePacketChange}
              interfaceNames={interfaceNames}
            />
          )}

          {activeTab === 'interfaces' && scenario && (
            <InterfacesEditor
              interfaces={scenario.interfaces ?? []}
              onChange={handleInterfacesChange}
            />
          )}

          {activeTab === 'routing' && scenario && (
            <RoutingEditor
              routingTables={scenario.routing_tables ?? []}
              ipRules={scenario.ip_rules ?? []}
              onChangeRoutingTables={handleRoutingTablesChange}
              onChangeIpRules={handleIpRulesChange}
              interfaceNames={interfaceNames}
            />
          )}

          {activeTab === 'rules' && scenario && (
            <RulesEditor
              netfilter={scenario.netfilter ?? { nftables: { tables: [] }, iptables: { tables: [] } }}
              onChange={handleNetfilterChange}
            />
          )}

          {activeTab === 'xdp' && scenario && (
            <XdpEditor
              xdp={scenario.xdp ?? { programs: [] }}
              onChange={handleXdpChange}
              interfaceNames={interfaceNames}
            />
          )}

          {activeTab === 'yaml' && (
            <div className="flex-1 flex flex-col min-h-0">
              <div className="text-xs text-gray-500 mb-2">
                Edit the scenario as YAML. Define interfaces, routing tables, netfilter rules, and the packet to simulate.
              </div>
              <textarea
                value={yaml}
                onChange={(e) => handleYamlChange(e.target.value)}
                className="flex-1 min-h-[400px] w-full rounded-md border border-gray-300 bg-white p-4 font-mono text-sm text-gray-800 focus:outline-none focus:ring-2 focus:ring-gray-400 resize-y"
                placeholder={`version: "1.0"
name: ${projectName}
interfaces:
  - name: eth0
    addresses: ["10.0.0.2/24"]
    mtu: 1500
    state: up
routing_tables:
  - id: 254
    name: main
    routes:
      - destination: "default"
        gateway: "10.0.0.1"
        dev: eth0
netfilter:
  nftables:
    tables: []
  iptables:
    tables: []
xdp:
  programs: []
packet:
  ingress_interface: eth0
  src_ip: "192.168.1.100"
  dst_ip: "10.0.0.2"
  protocol: tcp
  src_port: 54321
  dst_port: 80`}
                spellCheck={false}
              />
            </div>
          )}

          {activeTab === 'topology' && scenario && (
            <TopologyEditor
              topology={scenario.topology ?? { endpoints: [], flows: [] }}
              onChange={handleTopologyChange}
              interfaces={scenario.interfaces ?? []}
              onChangeInterfaces={handleInterfacesChange}
              projectName={projectName}
              routeCount={(scenario.routing_tables ?? []).reduce((s, t) => s + (t.routes ?? []).length, 0)}
              ruleCount={(scenario.netfilter?.nftables?.tables ?? []).reduce(
                (s, t) => s + (t.chains ?? []).reduce((cs, c) => cs + (c.rules ?? []).length, 0),
                0,
              )}
              simulationResult={simulationResult}
              onCloseReplay={() => setSimulationResult(null)}
            />
          )}
        </div>
      )}

      {/* Action bar */}
      <div className="mt-4 flex items-center gap-3 border-t pt-4 flex-shrink-0">
        <button
          onClick={() => void handleSave()}
          disabled={saving || loading}
          className="inline-flex items-center gap-2 rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 transition-colors"
        >
          <Save className="h-4 w-4" />
          {saving ? 'Saving...' : 'Save'}
        </button>
        <button
          onClick={() => navigate(`/projects/${encodeURIComponent(projectName)}/import`)}
          className="inline-flex items-center gap-2 rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors"
        >
          <FileDown className="h-4 w-4" />
          Import
        </button>
        <button
          onClick={() => void handleRun()}
          disabled={running || loading || !yaml.trim()}
          className="inline-flex items-center gap-2 rounded-md bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50 transition-colors"
        >
          <Play className="h-4 w-4" />
          {running ? 'Running...' : 'Run Simulation'}
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
