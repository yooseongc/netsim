import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Save, Play, ArrowLeft } from 'lucide-react';
import { api } from '@/api/client';
import { useSimulationResult } from '@/contexts/SimulationContext';
import { cn } from '@/lib/utils';
import { TopologyEditor } from '@/components/topology/TopologyEditor';
import type { Topology, Scenario } from '@/types/scenario';
import jsYaml from 'js-yaml';

type EditorTab = 'yaml' | 'topology';

export function ScenarioEditorPage() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const { setResult } = useSimulationResult();

  const [yaml, setYaml] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<EditorTab>('yaml');
  const [topology, setTopology] = useState<Topology>({ endpoints: [], flows: [] });

  const projectName = name ?? '';

  // Parse topology from YAML when switching to topology tab or on load
  const syncTopologyFromYaml = useCallback((yamlText: string) => {
    try {
      const parsed = jsYaml.load(yamlText) as Scenario | null;
      if (parsed?.topology) {
        setTopology({
          endpoints: parsed.topology.endpoints ?? [],
          flows: parsed.topology.flows ?? [],
        });
      } else {
        setTopology({ endpoints: [], flows: [] });
      }
    } catch {
      // YAML parse error -- keep existing topology state
    }
  }, []);

  // Merge topology back into YAML
  const syncYamlFromTopology = useCallback((topo: Topology) => {
    try {
      const parsed = (jsYaml.load(yaml) as Record<string, unknown>) ?? {};
      parsed.topology = {
        endpoints: topo.endpoints ?? [],
        flows: topo.flows ?? [],
      };
      const newYaml = jsYaml.dump(parsed, { lineWidth: 120, noRefs: true });
      setYaml(newYaml);
    } catch {
      // If YAML is invalid, create a minimal doc with topology
      const doc: Record<string, unknown> = {
        version: '1.0',
        name: projectName,
        topology: {
          endpoints: topo.endpoints ?? [],
          flows: topo.flows ?? [],
        },
      };
      setYaml(jsYaml.dump(doc, { lineWidth: 120, noRefs: true }));
    }
  }, [yaml, projectName]);

  const loadScenario = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const text = await api.getScenarioYaml(projectName);
      setYaml(text);
      syncTopologyFromYaml(text);
    } catch {
      // 404 means no scenario yet -- start with empty
      setYaml('');
    } finally {
      setLoading(false);
    }
  }, [projectName, syncTopologyFromYaml]);

  useEffect(() => {
    void loadScenario();
  }, [loadScenario]);

  const handleTabChange = (tab: EditorTab) => {
    if (tab === 'topology' && activeTab === 'yaml') {
      syncTopologyFromYaml(yaml);
    }
    setActiveTab(tab);
  };

  const handleTopologyChange = (topo: Topology) => {
    setTopology(topo);
    syncYamlFromTopology(topo);
  };

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setStatus(null);
    try {
      await api.saveScenarioYaml(projectName, yaml);
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
      // Save first, then run
      if (yaml.trim()) {
        await api.saveScenarioYaml(projectName, yaml);
      }
      const response = await api.runSimulation(projectName);
      setResult(response.result);
      navigate(`/projects/${encodeURIComponent(projectName)}/result`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Simulation failed');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="flex flex-col h-full max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
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
      <div className="mb-3 flex border-b border-gray-200">
        <button
          onClick={() => handleTabChange('yaml')}
          className={cn(
            'px-4 py-2 text-sm font-medium border-b-2 transition-colors -mb-px',
            activeTab === 'yaml'
              ? 'border-gray-900 text-gray-900'
              : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300',
          )}
        >
          YAML
        </button>
        <button
          onClick={() => handleTabChange('topology')}
          className={cn(
            'px-4 py-2 text-sm font-medium border-b-2 transition-colors -mb-px',
            activeTab === 'topology'
              ? 'border-gray-900 text-gray-900'
              : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300',
          )}
        >
          Topology
        </button>
      </div>

      {/* Editor area */}
      {loading ? (
        <div className="flex-1 flex items-center justify-center text-gray-400">
          Loading scenario...
        </div>
      ) : activeTab === 'yaml' ? (
        <div className="flex-1 flex flex-col min-h-0">
          <div className="text-xs text-gray-500 mb-2">
            Edit the scenario as YAML. Define interfaces, routing tables, netfilter rules, and the packet to simulate.
          </div>
          <textarea
            value={yaml}
            onChange={(e) => setYaml(e.target.value)}
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
      ) : (
        <div className="flex-1 min-h-0 overflow-y-auto">
          <TopologyEditor
            topology={topology}
            onChange={handleTopologyChange}
          />
        </div>
      )}

      {/* Action bar */}
      <div className="mt-4 flex items-center gap-3 border-t pt-4">
        <button
          onClick={() => void handleSave()}
          disabled={saving || loading}
          className="inline-flex items-center gap-2 rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 transition-colors"
        >
          <Save className="h-4 w-4" />
          {saving ? 'Saving...' : 'Save'}
        </button>
        <button
          onClick={() => void handleRun()}
          disabled={running || loading || !yaml.trim()}
          className="inline-flex items-center gap-2 rounded-md bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50 transition-colors"
        >
          <Play className="h-4 w-4" />
          {running ? 'Running...' : 'Run Simulation'}
        </button>
      </div>
    </div>
  );
}
