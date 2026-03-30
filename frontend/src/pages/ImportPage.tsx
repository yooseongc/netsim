import { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Eye, Upload, CheckCircle, AlertTriangle, XCircle } from 'lucide-react';
import { api } from '@/api/client';
import { cn } from '@/lib/utils';
import type { ImportParseRequest, ImportValidationReport } from '@/types/scenario';

const textareaClass =
  'w-full rounded-md border border-gray-300 bg-white p-3 font-mono text-xs text-gray-800 focus:outline-none focus:ring-2 focus:ring-gray-400 resize-y';

interface InputField {
  key: keyof ImportParseRequest;
  label: string;
  placeholder: string;
  command: string;
}

const INPUT_FIELDS: InputField[] = [
  {
    key: 'ip_addr',
    label: 'ip addr',
    placeholder: '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ...\n    inet 10.0.0.2/24 brd 10.0.0.255 scope global eth0',
    command: 'ip addr show',
  },
  {
    key: 'ip_rule',
    label: 'ip rule',
    placeholder: '0:\tfrom all lookup local\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default',
    command: 'ip rule show',
  },
  {
    key: 'ip_route',
    label: 'ip route',
    placeholder: 'default via 10.0.0.1 dev eth0\n10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.2',
    command: 'ip route show table all',
  },
  {
    key: 'nft_list_ruleset',
    label: 'nft list ruleset',
    placeholder: 'table inet filter {\n  chain input {\n    type filter hook input priority 0; policy accept;\n  }\n}',
    command: 'nft list ruleset',
  },
  {
    key: 'iptables_save',
    label: 'iptables-save',
    placeholder: '*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n-A FORWARD -i eth0 -o eth1 -j ACCEPT\nCOMMIT',
    command: 'iptables-save',
  },
];

export function ImportPage() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const projectName = name ?? '';

  const [inputs, setInputs] = useState<ImportParseRequest>({});
  const [validation, setValidation] = useState<ImportValidationReport | null>(null);
  const [mergeStrategy, setMergeStrategy] = useState<'replace' | 'merge'>('replace');
  const [previewing, setPreviewing] = useState(false);
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const hasInput = Object.values(inputs).some((v) => v && v.trim());

  const updateField = (key: keyof ImportParseRequest, value: string) => {
    setInputs({ ...inputs, [key]: value || null });
  };

  const handlePreview = async () => {
    setPreviewing(true);
    setError(null);
    setValidation(null);
    try {
      const result = await api.parseImport(inputs);
      setValidation(result.validation);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Preview failed');
    } finally {
      setPreviewing(false);
    }
  };

  const handleImport = async () => {
    setImporting(true);
    setError(null);
    setSuccess(null);
    try {
      const result = await api.applyImport(projectName, {
        ...inputs,
        merge_strategy: mergeStrategy,
      });
      setValidation(result.validation);
      setSuccess('Import completed successfully. Redirecting to editor...');
      setTimeout(() => {
        navigate(`/projects/${encodeURIComponent(projectName)}`);
      }, 1500);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Import failed');
    } finally {
      setImporting(false);
    }
  };

  return (
    <div className="flex flex-col h-full max-w-5xl mx-auto p-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <button
          onClick={() => navigate(`/projects/${encodeURIComponent(projectName)}`)}
          className="rounded p-1.5 text-gray-500 hover:bg-gray-100 transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
        </button>
        <h2 className="text-2xl font-bold text-gray-900">{projectName}</h2>
        <span className="text-sm text-gray-400">Import System Configuration</span>
      </div>

      {/* Description */}
      <div className="mb-4 rounded-md border border-blue-200 bg-blue-50 px-4 py-3 text-sm text-blue-700">
        Paste the output of Linux system commands below. Each field is optional — provide only what you have.
        Click <strong>Preview</strong> to validate, then <strong>Import to Project</strong> to apply.
      </div>

      {error && (
        <div className="mb-3 rounded-md border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      {success && (
        <div className="mb-3 rounded-md border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-700">
          {success}
        </div>
      )}

      {/* Input fields */}
      <div className="flex-1 min-h-0 overflow-y-auto space-y-4 mb-4">
        {INPUT_FIELDS.map((field) => (
          <section key={field.key} className="rounded-lg border border-gray-200 bg-white">
            <div className="flex items-center justify-between border-b border-gray-200 px-4 py-2">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-gray-900">{field.label}</h3>
                <code className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-500">
                  $ {field.command}
                </code>
              </div>
              {inputs[field.key] && (
                <button
                  onClick={() => updateField(field.key, '')}
                  className="text-xs text-gray-400 hover:text-gray-600"
                >
                  Clear
                </button>
              )}
            </div>
            <div className="p-3">
              <textarea
                value={inputs[field.key] ?? ''}
                onChange={(e) => updateField(field.key, e.target.value)}
                className={textareaClass}
                rows={4}
                placeholder={field.placeholder}
                spellCheck={false}
              />
            </div>
          </section>
        ))}

        {/* Validation Report */}
        {validation && (
          <section className="rounded-lg border border-gray-200 bg-white">
            <div className="border-b border-gray-200 px-4 py-3">
              <h3 className="text-sm font-semibold text-gray-900">Validation Report</h3>
            </div>
            <div className="p-4 space-y-3">
              {validation.parsed_ok.length > 0 && (
                <div>
                  <div className="flex items-center gap-1.5 mb-1">
                    <CheckCircle className="h-4 w-4 text-green-500" />
                    <span className="text-sm font-medium text-green-700">
                      Parsed OK ({validation.parsed_ok.length})
                    </span>
                  </div>
                  <ul className="ml-6 space-y-0.5">
                    {validation.parsed_ok.map((item, i) => (
                      <li key={i} className="text-xs text-gray-600">{item}</li>
                    ))}
                  </ul>
                </div>
              )}

              {validation.partial.length > 0 && (
                <div>
                  <div className="flex items-center gap-1.5 mb-1">
                    <AlertTriangle className="h-4 w-4 text-amber-500" />
                    <span className="text-sm font-medium text-amber-700">
                      Partial ({validation.partial.length})
                    </span>
                  </div>
                  <ul className="ml-6 space-y-0.5">
                    {validation.partial.map((item, i) => (
                      <li key={i} className="text-xs text-gray-600">{item}</li>
                    ))}
                  </ul>
                </div>
              )}

              {validation.unsupported.length > 0 && (
                <div>
                  <div className="flex items-center gap-1.5 mb-1">
                    <XCircle className="h-4 w-4 text-red-500" />
                    <span className="text-sm font-medium text-red-700">
                      Unsupported ({validation.unsupported.length})
                    </span>
                  </div>
                  <ul className="ml-6 space-y-0.5">
                    {validation.unsupported.map((item, i) => (
                      <li key={i} className="text-xs text-gray-600">{item}</li>
                    ))}
                  </ul>
                </div>
              )}

              {validation.parsed_ok.length === 0 &&
                validation.partial.length === 0 &&
                validation.unsupported.length === 0 && (
                <div className="text-sm text-gray-400">No results — provide input to parse.</div>
              )}
            </div>
          </section>
        )}
      </div>

      {/* Action bar */}
      <div className="flex items-center gap-3 border-t pt-4">
        <button
          onClick={() => void handlePreview()}
          disabled={!hasInput || previewing}
          className="inline-flex items-center gap-2 rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50 transition-colors"
        >
          <Eye className="h-4 w-4" />
          {previewing ? 'Parsing...' : 'Preview'}
        </button>

        <div className="flex items-center gap-2">
          <label className="text-sm text-gray-600">Strategy:</label>
          <select
            value={mergeStrategy}
            onChange={(e) => setMergeStrategy(e.target.value as 'replace' | 'merge')}
            className={cn(
              'rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400',
              mergeStrategy === 'merge' && 'text-blue-600',
            )}
          >
            <option value="replace">Replace (new scenario)</option>
            <option value="merge">Merge (extend existing)</option>
          </select>
        </div>

        <button
          onClick={() => void handleImport()}
          disabled={!hasInput || importing}
          className="inline-flex items-center gap-2 rounded-md bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700 disabled:opacity-50 transition-colors"
        >
          <Upload className="h-4 w-4" />
          {importing ? 'Importing...' : 'Import to Project'}
        </button>
      </div>
    </div>
  );
}
