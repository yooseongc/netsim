import { useState } from 'react';
import { Plus, Trash2, X, ChevronDown, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import type {
  NetfilterConfig,
  NfTable,
  NfChain,
  NfRule,
  NfMatch,
  NfAction,
  NfFamily,
  NfChainType,
  NfHook,
  NfVerdict,
  NatAction,
} from '@/types/scenario';

const inputClass =
  'w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400';
const smallSelectClass =
  'rounded border border-gray-300 px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-gray-400';

const FAMILIES: NfFamily[] = ['ip', 'ip6', 'inet', 'bridge', 'arp'];
const CHAIN_TYPES: NfChainType[] = ['filter', 'nat', 'route', 'mangle'];
const HOOKS: NfHook[] = ['prerouting', 'input', 'forward', 'output', 'postrouting'];
const VERDICTS: NfVerdict[] = ['accept', 'drop', 'reject', 'queue', 'continue'];

// ── Match helpers ──

function matchSummary(m: NfMatch): string {
  switch (m.type) {
    case 'ip': return `ip ${m.field} ${m.op} ${m.value}`;
    case 'transport': return `${m.protocol} ${m.field} ${m.op} ${m.value}`;
    case 'iif': return `iif "${m.name}"`;
    case 'oif': return `oif "${m.name}"`;
    case 'meta': return `meta ${m.key} ${m.op} ${m.value}`;
    case 'ct': return `ct ${m.key} ${m.op} ${m.value}`;
    case 'mark': return `mark ${m.op} ${m.value}${m.mask != null ? `/${m.mask}` : ''}`;
  }
}

function actionSummary(a: NfAction): string {
  switch (a.type) {
    case 'verdict': return a.verdict;
    case 'nat': return natSummary(a.action);
    case 'set_mark': return `mark=${a.value}${a.mask != null ? `/${a.mask}` : ''}`;
    case 'log': return `log${a.prefix ? ` "${a.prefix}"` : ''}`;
    case 'counter': return 'counter';
    case 'jump': return `jump ${a.target}`;
    case 'goto': return `goto ${a.target}`;
    case 'return': return 'return';
  }
}

function natSummary(n: NatAction): string {
  switch (n.type) {
    case 'dnat': return `dnat to ${n.addr ?? ''}${n.port != null ? `:${n.port}` : ''}`;
    case 'snat': return `snat to ${n.addr ?? ''}${n.port != null ? `:${n.port}` : ''}`;
    case 'masquerade': return `masquerade${n.port != null ? ` :${n.port}` : ''}`;
    case 'redirect': return `redirect${n.port != null ? ` :${n.port}` : ''}`;
    case 'tproxy': return `tproxy to ${n.addr ?? ''}:${n.port}`;
  }
}

// ── Match Editor ──

const MATCH_TYPES = ['ip', 'transport', 'iif', 'oif', 'meta', 'ct', 'mark'] as const;

function emptyMatch(): NfMatch {
  return { type: 'ip', field: 'saddr', op: 'eq', value: '' };
}

interface MatchEditorProps {
  match: NfMatch;
  onChange: (m: NfMatch) => void;
  onRemove: () => void;
}

function MatchEditor({ match, onChange, onRemove }: MatchEditorProps) {
  const handleTypeChange = (type: string) => {
    switch (type) {
      case 'ip': onChange({ type: 'ip', field: 'saddr', op: 'eq', value: '' }); break;
      case 'transport': onChange({ type: 'transport', protocol: 'tcp', field: 'dport', op: 'eq', value: '' }); break;
      case 'iif': onChange({ type: 'iif', name: '' }); break;
      case 'oif': onChange({ type: 'oif', name: '' }); break;
      case 'meta': onChange({ type: 'meta', key: 'mark', op: 'eq', value: '' }); break;
      case 'ct': onChange({ type: 'ct', key: 'state', op: 'eq', value: '' }); break;
      case 'mark': onChange({ type: 'mark', op: 'eq', value: 0 }); break;
    }
  };

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <select value={match.type} onChange={(e) => handleTypeChange(e.target.value)} className={smallSelectClass}>
        {MATCH_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
      </select>

      {match.type === 'ip' && (
        <>
          <select value={match.field} onChange={(e) => onChange({ ...match, field: e.target.value as never })} className={smallSelectClass}>
            {['saddr', 'daddr', 'protocol', 'version', 'length', 'dscp', 'ttl'].map((f) => <option key={f} value={f}>{f}</option>)}
          </select>
          <select value={match.op} onChange={(e) => onChange({ ...match, op: e.target.value as never })} className={smallSelectClass}>
            {['eq', 'neq', 'lt', 'gt', 'lte', 'gte', 'in'].map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input
            type="text" value={match.value}
            onChange={(e) => onChange({ ...match, value: e.target.value })}
            className="rounded border border-gray-300 px-2 py-1 text-xs w-36"
            placeholder="value"
          />
        </>
      )}

      {match.type === 'transport' && (
        <>
          <select value={match.protocol} onChange={(e) => onChange({ ...match, protocol: e.target.value as never })} className={smallSelectClass}>
            {['tcp', 'udp', 'icmp', 'icmpv6'].map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <select value={match.field} onChange={(e) => onChange({ ...match, field: e.target.value as never })} className={smallSelectClass}>
            {['sport', 'dport', 'flags', 'icmp_type', 'icmp_code'].map((f) => <option key={f} value={f}>{f}</option>)}
          </select>
          <select value={match.op} onChange={(e) => onChange({ ...match, op: e.target.value as never })} className={smallSelectClass}>
            {['eq', 'neq', 'lt', 'gt', 'lte', 'gte', 'in'].map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input
            type="text" value={match.value}
            onChange={(e) => onChange({ ...match, value: e.target.value })}
            className="rounded border border-gray-300 px-2 py-1 text-xs w-28"
            placeholder="value"
          />
        </>
      )}

      {(match.type === 'iif' || match.type === 'oif') && (
        <input
          type="text" value={match.name}
          onChange={(e) => onChange({ ...match, name: e.target.value })}
          className="rounded border border-gray-300 px-2 py-1 text-xs w-28"
          placeholder="interface"
        />
      )}

      {match.type === 'meta' && (
        <>
          <select value={match.key} onChange={(e) => onChange({ ...match, key: e.target.value as never })} className={smallSelectClass}>
            {['mark', 'protocol', 'length', 'iifname', 'oifname', 'skuid', 'nfproto', 'l4proto'].map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
          <select value={match.op} onChange={(e) => onChange({ ...match, op: e.target.value as never })} className={smallSelectClass}>
            {['eq', 'neq', 'lt', 'gt', 'lte', 'gte', 'in'].map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input
            type="text" value={match.value}
            onChange={(e) => onChange({ ...match, value: e.target.value })}
            className="rounded border border-gray-300 px-2 py-1 text-xs w-28"
            placeholder="value"
          />
        </>
      )}

      {match.type === 'ct' && (
        <>
          <select value={match.key} onChange={(e) => onChange({ ...match, key: e.target.value as never })} className={smallSelectClass}>
            {['state', 'mark', 'status', 'direction', 'expiration'].map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
          <select value={match.op} onChange={(e) => onChange({ ...match, op: e.target.value as never })} className={smallSelectClass}>
            {['eq', 'neq', 'lt', 'gt', 'lte', 'gte', 'in'].map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input
            type="text" value={match.value}
            onChange={(e) => onChange({ ...match, value: e.target.value })}
            className="rounded border border-gray-300 px-2 py-1 text-xs w-28"
            placeholder="value"
          />
        </>
      )}

      {match.type === 'mark' && (
        <>
          <select value={match.op} onChange={(e) => onChange({ ...match, op: e.target.value as never })} className={smallSelectClass}>
            {['eq', 'neq', 'lt', 'gt', 'lte', 'gte', 'in'].map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input
            type="number" value={match.value}
            onChange={(e) => onChange({ ...match, value: Number(e.target.value) })}
            className="rounded border border-gray-300 px-2 py-1 text-xs w-20"
            placeholder="0"
          />
          <input
            type="number" value={match.mask ?? ''}
            onChange={(e) => onChange({ ...match, mask: e.target.value ? Number(e.target.value) : null })}
            className="rounded border border-gray-300 px-2 py-1 text-xs w-20"
            placeholder="mask"
          />
        </>
      )}

      <button onClick={onRemove} className="rounded p-0.5 text-red-400 hover:bg-red-50 hover:text-red-600">
        <X className="h-3 w-3" />
      </button>
    </div>
  );
}

// ── Action Editor ──

const ACTION_TYPES = ['verdict', 'nat', 'set_mark', 'log', 'counter', 'jump', 'goto', 'return'] as const;
const NAT_TYPES = ['dnat', 'snat', 'masquerade', 'redirect', 'tproxy'] as const;

interface ActionEditorProps {
  action: NfAction;
  onChange: (a: NfAction) => void;
}

function ActionEditor({ action, onChange }: ActionEditorProps) {
  const handleTypeChange = (type: string) => {
    switch (type) {
      case 'verdict': onChange({ type: 'verdict', verdict: 'accept' }); break;
      case 'nat': onChange({ type: 'nat', action: { type: 'dnat', addr: '', port: null } }); break;
      case 'set_mark': onChange({ type: 'set_mark', value: 0 }); break;
      case 'log': onChange({ type: 'log' }); break;
      case 'counter': onChange({ type: 'counter' }); break;
      case 'jump': onChange({ type: 'jump', target: '' }); break;
      case 'goto': onChange({ type: 'goto', target: '' }); break;
      case 'return': onChange({ type: 'return' }); break;
    }
  };

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <select value={action.type} onChange={(e) => handleTypeChange(e.target.value)} className={smallSelectClass}>
        {ACTION_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
      </select>

      {action.type === 'verdict' && (
        <select value={action.verdict} onChange={(e) => onChange({ ...action, verdict: e.target.value as NfVerdict })} className={smallSelectClass}>
          {VERDICTS.map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
      )}

      {action.type === 'nat' && (
        <>
          <select
            value={action.action.type}
            onChange={(e) => {
              const natType = e.target.value;
              switch (natType) {
                case 'dnat': onChange({ type: 'nat', action: { type: 'dnat', addr: '', port: null } }); break;
                case 'snat': onChange({ type: 'nat', action: { type: 'snat', addr: '', port: null } }); break;
                case 'masquerade': onChange({ type: 'nat', action: { type: 'masquerade' } }); break;
                case 'redirect': onChange({ type: 'nat', action: { type: 'redirect' } }); break;
                case 'tproxy': onChange({ type: 'nat', action: { type: 'tproxy', port: 0 } }); break;
              }
            }}
            className={smallSelectClass}
          >
            {NAT_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>

          {(action.action.type === 'dnat' || action.action.type === 'snat' || action.action.type === 'tproxy') && (
            <input
              type="text"
              value={action.action.addr ?? ''}
              onChange={(e) => onChange({ type: 'nat', action: { ...action.action, addr: e.target.value || null } as NatAction })}
              className="rounded border border-gray-300 px-2 py-1 text-xs w-28"
              placeholder="address"
            />
          )}

          {'port' in action.action && (
            <input
              type="number"
              value={action.action.port ?? ''}
              onChange={(e) => onChange({ type: 'nat', action: { ...action.action, port: e.target.value ? Number(e.target.value) : null } as NatAction })}
              className="rounded border border-gray-300 px-2 py-1 text-xs w-20"
              placeholder="port"
            />
          )}
        </>
      )}

      {action.type === 'set_mark' && (
        <>
          <input
            type="number" value={action.value}
            onChange={(e) => onChange({ ...action, value: Number(e.target.value) })}
            className="rounded border border-gray-300 px-2 py-1 text-xs w-20"
            placeholder="value"
          />
          <input
            type="number" value={action.mask ?? ''}
            onChange={(e) => onChange({ ...action, mask: e.target.value ? Number(e.target.value) : null })}
            className="rounded border border-gray-300 px-2 py-1 text-xs w-20"
            placeholder="mask"
          />
        </>
      )}

      {action.type === 'log' && (
        <input
          type="text" value={action.prefix ?? ''}
          onChange={(e) => onChange({ ...action, prefix: e.target.value || null })}
          className="rounded border border-gray-300 px-2 py-1 text-xs w-36"
          placeholder="log prefix"
        />
      )}

      {(action.type === 'jump' || action.type === 'goto') && (
        <input
          type="text" value={action.target}
          onChange={(e) => onChange({ ...action, target: e.target.value })}
          className="rounded border border-gray-300 px-2 py-1 text-xs w-28"
          placeholder="chain name"
        />
      )}
    </div>
  );
}

// ── Rule Editor Row ──

interface RuleRowProps {
  rule: NfRule;
  onChange: (r: NfRule) => void;
  onRemove: () => void;
}

function RuleRow({ rule, onChange, onRemove }: RuleRowProps) {
  const [expanded, setExpanded] = useState(false);
  const matches = rule.matches ?? [];

  return (
    <div className="border border-gray-200 rounded-md bg-white">
      <div className="flex items-center gap-2 px-3 py-2">
        <button onClick={() => setExpanded(!expanded)} className="text-gray-400 hover:text-gray-600">
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </button>
        <div className="flex-1 text-xs font-mono text-gray-700 truncate">
          {matches.length > 0 && (
            <span className="text-gray-500">{matches.map(matchSummary).join(' && ')} → </span>
          )}
          <span className="font-medium">{actionSummary(rule.action)}</span>
          {rule.comment && <span className="ml-2 text-gray-400">// {rule.comment}</span>}
        </div>
        <button onClick={onRemove} className="rounded p-1 text-red-400 hover:bg-red-50 hover:text-red-600">
          <Trash2 className="h-3 w-3" />
        </button>
      </div>

      {expanded && (
        <div className="border-t border-gray-100 px-3 py-3 space-y-3 bg-gray-50">
          <div>
            <label className="text-xs font-medium text-gray-600 mb-1 block">Comment</label>
            <input
              type="text"
              value={rule.comment ?? ''}
              onChange={(e) => onChange({ ...rule, comment: e.target.value || null })}
              className={inputClass}
              placeholder="optional comment"
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-medium text-gray-600">Matches</label>
              <button
                onClick={() => onChange({ ...rule, matches: [...matches, emptyMatch()] })}
                className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-gray-700"
              >
                <Plus className="h-3 w-3" /> Add
              </button>
            </div>
            <div className="space-y-2">
              {matches.map((m, i) => (
                <MatchEditor
                  key={i}
                  match={m}
                  onChange={(updated) => {
                    const newMatches = matches.map((mm, ii) => (ii === i ? updated : mm));
                    onChange({ ...rule, matches: newMatches });
                  }}
                  onRemove={() => onChange({ ...rule, matches: matches.filter((_, ii) => ii !== i) })}
                />
              ))}
            </div>
          </div>

          <div>
            <label className="text-xs font-medium text-gray-600 mb-1 block">Action</label>
            <ActionEditor
              action={rule.action}
              onChange={(a) => onChange({ ...rule, action: a })}
            />
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Component ──

interface RulesEditorProps {
  netfilter: NetfilterConfig;
  onChange: (config: NetfilterConfig) => void;
}

export function RulesEditor({ netfilter, onChange }: RulesEditorProps) {
  const tables = netfilter.nftables?.tables ?? [];
  const [expandedTable, setExpandedTable] = useState<number | null>(null);
  const [expandedChain, setExpandedChain] = useState<string | null>(null);

  const updateTables = (newTables: NfTable[]) => {
    onChange({ ...netfilter, nftables: { ...netfilter.nftables, tables: newTables } });
  };

  // Table CRUD
  const addTable = () => {
    updateTables([...tables, { family: 'inet', name: 'filter', chains: [] }]);
  };

  const deleteTable = (idx: number) => {
    updateTables(tables.filter((_, i) => i !== idx));
  };

  const updateTable = (idx: number, patch: Partial<NfTable>) => {
    updateTables(tables.map((t, i) => (i === idx ? { ...t, ...patch } : t)));
  };

  // Chain CRUD
  const addChain = (tableIdx: number) => {
    const table = tables[tableIdx];
    const chain: NfChain = { name: 'chain_' + ((table.chains ?? []).length + 1), rules: [] };
    updateTable(tableIdx, { chains: [...(table.chains ?? []), chain] });
  };

  const deleteChain = (tableIdx: number, chainIdx: number) => {
    const table = tables[tableIdx];
    updateTable(tableIdx, { chains: (table.chains ?? []).filter((_, i) => i !== chainIdx) });
  };

  const updateChain = (tableIdx: number, chainIdx: number, patch: Partial<NfChain>) => {
    const table = tables[tableIdx];
    const chains = (table.chains ?? []).map((c, i) => (i === chainIdx ? { ...c, ...patch } : c));
    updateTable(tableIdx, { chains });
  };

  // Rule CRUD within a chain
  const addRule = (tableIdx: number, chainIdx: number) => {
    const table = tables[tableIdx];
    const chain = (table.chains ?? [])[chainIdx];
    const rule: NfRule = { matches: [], action: { type: 'verdict', verdict: 'accept' } };
    updateChain(tableIdx, chainIdx, { rules: [...(chain.rules ?? []), rule] });
  };

  const updateRule = (tableIdx: number, chainIdx: number, ruleIdx: number, rule: NfRule) => {
    const table = tables[tableIdx];
    const chain = (table.chains ?? [])[chainIdx];
    const rules = (chain.rules ?? []).map((r, i) => (i === ruleIdx ? rule : r));
    updateChain(tableIdx, chainIdx, { rules });
  };

  const deleteRule = (tableIdx: number, chainIdx: number, ruleIdx: number) => {
    const table = tables[tableIdx];
    const chain = (table.chains ?? [])[chainIdx];
    updateChain(tableIdx, chainIdx, { rules: (chain.rules ?? []).filter((_, i) => i !== ruleIdx) });
  };

  return (
    <div className="space-y-6">
      {/* nftables Section */}
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
          <h3 className="text-sm font-semibold text-gray-900">
            nftables ({tables.length} table{tables.length !== 1 ? 's' : ''})
          </h3>
          <button
            onClick={addTable}
            className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-gray-800 transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            Add Table
          </button>
        </div>

        {tables.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-gray-400">
            No nftables tables. Click &quot;Add Table&quot; to create one.
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {tables.map((table, tIdx) => (
              <div key={tIdx}>
                {/* Table header */}
                <div className="flex items-center gap-3 px-4 py-3">
                  <button
                    onClick={() => setExpandedTable(expandedTable === tIdx ? null : tIdx)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    {expandedTable === tIdx
                      ? <ChevronDown className="h-4 w-4" />
                      : <ChevronRight className="h-4 w-4" />}
                  </button>
                  <div className="flex items-center gap-2 flex-1">
                    <select
                      value={table.family}
                      onChange={(e) => updateTable(tIdx, { family: e.target.value as NfFamily })}
                      className={smallSelectClass}
                    >
                      {FAMILIES.map((f) => <option key={f} value={f}>{f}</option>)}
                    </select>
                    <input
                      type="text"
                      value={table.name}
                      onChange={(e) => updateTable(tIdx, { name: e.target.value })}
                      className="rounded border border-gray-200 px-2 py-1 text-sm font-medium w-32"
                    />
                    <span className="text-xs text-gray-400">
                      {(table.chains ?? []).length} chain(s)
                    </span>
                  </div>
                  <button
                    onClick={() => deleteTable(tIdx)}
                    className="rounded px-2 py-1 text-red-400 hover:bg-red-50 hover:text-red-600"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>

                {/* Chains */}
                {expandedTable === tIdx && (
                  <div className="border-t border-gray-100 bg-gray-50 px-4 py-3 space-y-3">
                    {(table.chains ?? []).map((chain, cIdx) => {
                      const chainKey = `${tIdx}-${cIdx}`;
                      const isExpanded = expandedChain === chainKey;
                      return (
                        <div key={cIdx} className="rounded-lg border border-gray-200 bg-white">
                          {/* Chain header */}
                          <div className="flex items-center gap-2 px-3 py-2">
                            <button
                              onClick={() => setExpandedChain(isExpanded ? null : chainKey)}
                              className="text-gray-400 hover:text-gray-600"
                            >
                              {isExpanded
                                ? <ChevronDown className="h-3.5 w-3.5" />
                                : <ChevronRight className="h-3.5 w-3.5" />}
                            </button>
                            <input
                              type="text"
                              value={chain.name}
                              onChange={(e) => updateChain(tIdx, cIdx, { name: e.target.value })}
                              className="rounded border border-gray-200 px-2 py-0.5 text-sm font-mono w-28"
                            />
                            <select
                              value={chain.chain_type ?? ''}
                              onChange={(e) => updateChain(tIdx, cIdx, { chain_type: (e.target.value || null) as NfChainType | null })}
                              className={smallSelectClass}
                            >
                              <option value="">— type —</option>
                              {CHAIN_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
                            </select>
                            <select
                              value={chain.hook ?? ''}
                              onChange={(e) => updateChain(tIdx, cIdx, { hook: (e.target.value || null) as NfHook | null })}
                              className={smallSelectClass}
                            >
                              <option value="">— hook —</option>
                              {HOOKS.map((h) => <option key={h} value={h}>{h}</option>)}
                            </select>
                            <input
                              type="number"
                              value={chain.priority ?? ''}
                              onChange={(e) => updateChain(tIdx, cIdx, { priority: e.target.value ? Number(e.target.value) : null })}
                              className="rounded border border-gray-200 px-2 py-0.5 text-xs w-16"
                              placeholder="prio"
                            />
                            <select
                              value={chain.policy ?? ''}
                              onChange={(e) => updateChain(tIdx, cIdx, { policy: (e.target.value || null) as NfVerdict | null })}
                              className={cn(
                                smallSelectClass,
                                chain.policy === 'drop' && 'text-red-600',
                                chain.policy === 'accept' && 'text-green-600',
                              )}
                            >
                              <option value="">— policy —</option>
                              {VERDICTS.map((v) => <option key={v} value={v}>{v}</option>)}
                            </select>
                            <span className="text-xs text-gray-400 flex-1">
                              {(chain.rules ?? []).length} rule(s)
                            </span>
                            <button
                              onClick={() => deleteChain(tIdx, cIdx)}
                              className="rounded p-1 text-red-400 hover:bg-red-50 hover:text-red-600"
                            >
                              <Trash2 className="h-3 w-3" />
                            </button>
                          </div>

                          {/* Rules */}
                          {isExpanded && (
                            <div className="border-t border-gray-100 px-3 py-2 space-y-2">
                              {(chain.rules ?? []).map((rule, rIdx) => (
                                <RuleRow
                                  key={rIdx}
                                  rule={rule}
                                  onChange={(r) => updateRule(tIdx, cIdx, rIdx, r)}
                                  onRemove={() => deleteRule(tIdx, cIdx, rIdx)}
                                />
                              ))}
                              <button
                                onClick={() => addRule(tIdx, cIdx)}
                                className="inline-flex items-center gap-1.5 rounded-md border border-dashed border-gray-300 px-3 py-1.5 text-xs text-gray-500 hover:border-gray-400 hover:text-gray-700"
                              >
                                <Plus className="h-3 w-3" />
                                Add Rule
                              </button>
                            </div>
                          )}
                        </div>
                      );
                    })}

                    <button
                      onClick={() => addChain(tIdx)}
                      className="inline-flex items-center gap-1.5 rounded-md border border-dashed border-gray-300 px-3 py-1.5 text-xs text-gray-500 hover:border-gray-400 hover:text-gray-700"
                    >
                      <Plus className="h-3 w-3" />
                      Add Chain
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
