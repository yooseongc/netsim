import { useState } from 'react';
import { Plus, Trash2, X, ChevronDown, ChevronRight } from 'lucide-react';
import type {
  XdpConfig,
  XdpProgram,
  XdpRule,
  XdpAction,
  XdpMode,
  NfMatch,
} from '@/types/scenario';

const inputClass =
  'w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400';
const selectClass = inputClass;
const smallSelectClass =
  'rounded border border-gray-300 px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-gray-400';

const XDP_MODES: XdpMode[] = ['generic', 'native', 'offload'];
const XDP_SIMPLE_ACTIONS = ['pass', 'drop', 'tx', 'aborted'] as const;

function xdpActionToString(a: XdpAction): string {
  if (typeof a === 'string') return a;
  if ('redirect' in a) return `redirect → ${a.redirect.target_if}`;
  return 'pass';
}

function matchSummary(m: NfMatch): string {
  switch (m.type) {
    case 'ip': return `ip ${m.field} ${m.op} ${m.value}`;
    case 'transport': return `${m.protocol} ${m.field} ${m.op} ${m.value}`;
    case 'iif': return `iif "${m.name}"`;
    case 'oif': return `oif "${m.name}"`;
    case 'meta': return `meta ${m.key} ${m.op} ${m.value}`;
    case 'ct': return `ct ${m.key} ${m.op} ${m.value}`;
    case 'mark': return `mark ${m.op} ${m.value}`;
  }
}

// ── XDP Action Editor ──

interface XdpActionEditorProps {
  action: XdpAction;
  onChange: (a: XdpAction) => void;
}

function XdpActionEditor({ action, onChange }: XdpActionEditorProps) {
  const isRedirect = typeof action === 'object' && 'redirect' in action;
  const currentType = isRedirect ? 'redirect' : (action as string);

  const handleTypeChange = (type: string) => {
    if (type === 'redirect') {
      onChange({ redirect: { target_if: '' } });
    } else {
      onChange(type as XdpAction);
    }
  };

  return (
    <div className="flex items-center gap-2">
      <select value={currentType} onChange={(e) => handleTypeChange(e.target.value)} className={smallSelectClass}>
        {XDP_SIMPLE_ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
        <option value="redirect">redirect</option>
      </select>
      {isRedirect && (
        <input
          type="text"
          value={(action as { redirect: { target_if: string } }).redirect.target_if}
          onChange={(e) => onChange({ redirect: { target_if: e.target.value } })}
          className="rounded border border-gray-300 px-2 py-1 text-xs w-28"
          placeholder="target interface"
        />
      )}
    </div>
  );
}

// ── XDP Match Editor (reuses NfMatch) ──

const MATCH_TYPES = ['ip', 'transport', 'iif', 'meta', 'mark'] as const;

function emptyMatch(): NfMatch {
  return { type: 'ip', field: 'saddr', op: 'eq', value: '' };
}

interface MatchEditorProps {
  match: NfMatch;
  onChange: (m: NfMatch) => void;
  onRemove: () => void;
}

function XdpMatchEditor({ match, onChange, onRemove }: MatchEditorProps) {
  const handleTypeChange = (type: string) => {
    switch (type) {
      case 'ip': onChange({ type: 'ip', field: 'saddr', op: 'eq', value: '' }); break;
      case 'transport': onChange({ type: 'transport', protocol: 'tcp', field: 'dport', op: 'eq', value: '' }); break;
      case 'iif': onChange({ type: 'iif', name: '' }); break;
      case 'meta': onChange({ type: 'meta', key: 'mark', op: 'eq', value: '' }); break;
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
            {['saddr', 'daddr', 'protocol'].map((f) => <option key={f} value={f}>{f}</option>)}
          </select>
          <select value={match.op} onChange={(e) => onChange({ ...match, op: e.target.value as never })} className={smallSelectClass}>
            {['eq', 'neq', 'in'].map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input
            type="text" value={match.value}
            onChange={(e) => onChange({ ...match, value: e.target.value })}
            className="rounded border border-gray-300 px-2 py-1 text-xs w-32"
            placeholder="value"
          />
        </>
      )}

      {match.type === 'transport' && (
        <>
          <select value={match.protocol} onChange={(e) => onChange({ ...match, protocol: e.target.value as never })} className={smallSelectClass}>
            {['tcp', 'udp'].map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <select value={match.field} onChange={(e) => onChange({ ...match, field: e.target.value as never })} className={smallSelectClass}>
            {['sport', 'dport'].map((f) => <option key={f} value={f}>{f}</option>)}
          </select>
          <select value={match.op} onChange={(e) => onChange({ ...match, op: e.target.value as never })} className={smallSelectClass}>
            {['eq', 'neq'].map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input
            type="text" value={match.value}
            onChange={(e) => onChange({ ...match, value: e.target.value })}
            className="rounded border border-gray-300 px-2 py-1 text-xs w-24"
            placeholder="port"
          />
        </>
      )}

      {match.type === 'iif' && (
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
            {['mark', 'protocol', 'length'].map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
          <select value={match.op} onChange={(e) => onChange({ ...match, op: e.target.value as never })} className={smallSelectClass}>
            {['eq', 'neq'].map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input
            type="text" value={match.value}
            onChange={(e) => onChange({ ...match, value: e.target.value })}
            className="rounded border border-gray-300 px-2 py-1 text-xs w-24"
            placeholder="value"
          />
        </>
      )}

      {match.type === 'mark' && (
        <>
          <select value={match.op} onChange={(e) => onChange({ ...match, op: e.target.value as never })} className={smallSelectClass}>
            {['eq', 'neq'].map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input
            type="number" value={match.value}
            onChange={(e) => onChange({ ...match, value: Number(e.target.value) })}
            className="rounded border border-gray-300 px-2 py-1 text-xs w-20"
          />
        </>
      )}

      <button onClick={onRemove} className="rounded p-0.5 text-red-400 hover:bg-red-50 hover:text-red-600">
        <X className="h-3 w-3" />
      </button>
    </div>
  );
}

// ── Main Component ──

interface XdpEditorProps {
  xdp: XdpConfig;
  onChange: (config: XdpConfig) => void;
  interfaceNames: string[];
}

export function XdpEditor({ xdp, onChange, interfaceNames }: XdpEditorProps) {
  const programs = xdp.programs ?? [];
  const [expandedProg, setExpandedProg] = useState<number | null>(null);

  const updatePrograms = (newPrograms: XdpProgram[]) => {
    onChange({ ...xdp, programs: newPrograms });
  };

  const addProgram = () => {
    updatePrograms([...programs, { interface: '', mode: 'generic', rules: [], default_action: 'pass' }]);
  };

  const deleteProgram = (idx: number) => {
    updatePrograms(programs.filter((_, i) => i !== idx));
  };

  const updateProgram = (idx: number, patch: Partial<XdpProgram>) => {
    updatePrograms(programs.map((p, i) => (i === idx ? { ...p, ...patch } : p)));
  };

  const addXdpRule = (progIdx: number) => {
    const prog = programs[progIdx];
    const rule: XdpRule = { matches: [], action: 'drop' };
    updateProgram(progIdx, { rules: [...(prog.rules ?? []), rule] });
  };

  const updateXdpRule = (progIdx: number, ruleIdx: number, rule: XdpRule) => {
    const prog = programs[progIdx];
    const rules = (prog.rules ?? []).map((r, i) => (i === ruleIdx ? rule : r));
    updateProgram(progIdx, { rules });
  };

  const deleteXdpRule = (progIdx: number, ruleIdx: number) => {
    const prog = programs[progIdx];
    updateProgram(progIdx, { rules: (prog.rules ?? []).filter((_, i) => i !== ruleIdx) });
  };

  return (
    <div className="space-y-4">
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
          <h3 className="text-sm font-semibold text-gray-900">
            XDP Programs ({programs.length})
          </h3>
          <button
            onClick={addProgram}
            className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-gray-800 transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            Add Program
          </button>
        </div>

        {programs.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-gray-400">
            No XDP programs. Click &quot;Add Program&quot; to create one.
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {programs.map((prog, pIdx) => (
              <div key={pIdx}>
                <div className="flex items-center gap-3 px-4 py-3">
                  <button
                    onClick={() => setExpandedProg(expandedProg === pIdx ? null : pIdx)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    {expandedProg === pIdx
                      ? <ChevronDown className="h-4 w-4" />
                      : <ChevronRight className="h-4 w-4" />}
                  </button>
                  <div className="flex items-center gap-3 flex-1">
                    <div>
                      <label className="text-xs text-gray-500">Interface</label>
                      {interfaceNames.length > 0 ? (
                        <select
                          value={prog.interface}
                          onChange={(e) => updateProgram(pIdx, { interface: e.target.value })}
                          className={selectClass}
                        >
                          <option value="">— select —</option>
                          {interfaceNames.map((n) => (
                            <option key={n} value={n}>{n}</option>
                          ))}
                        </select>
                      ) : (
                        <input
                          type="text"
                          value={prog.interface}
                          onChange={(e) => updateProgram(pIdx, { interface: e.target.value })}
                          className={inputClass}
                          placeholder="eth0"
                        />
                      )}
                    </div>
                    <div>
                      <label className="text-xs text-gray-500">Mode</label>
                      <select
                        value={prog.mode ?? 'generic'}
                        onChange={(e) => updateProgram(pIdx, { mode: e.target.value as XdpMode })}
                        className={selectClass}
                      >
                        {XDP_MODES.map((m) => <option key={m} value={m}>{m}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="text-xs text-gray-500">Default Action</label>
                      <XdpActionEditor
                        action={prog.default_action ?? 'pass'}
                        onChange={(a) => updateProgram(pIdx, { default_action: a })}
                      />
                    </div>
                    <span className="text-xs text-gray-400 mt-4">
                      {(prog.rules ?? []).length} rule(s)
                    </span>
                  </div>
                  <button
                    onClick={() => deleteProgram(pIdx)}
                    className="rounded px-2 py-1 text-red-400 hover:bg-red-50 hover:text-red-600"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>

                {expandedProg === pIdx && (
                  <div className="border-t border-gray-100 bg-gray-50 px-4 py-3 space-y-3">
                    {(prog.rules ?? []).map((rule, rIdx) => (
                      <div key={rIdx} className="rounded-md border border-gray-200 bg-white p-3 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium text-gray-600">Rule #{rIdx + 1}</span>
                          <div className="flex items-center gap-2">
                            {rule.comment && (
                              <span className="text-xs text-gray-400 italic">{rule.comment}</span>
                            )}
                            <button
                              onClick={() => deleteXdpRule(pIdx, rIdx)}
                              className="rounded p-1 text-red-400 hover:bg-red-50 hover:text-red-600"
                            >
                              <Trash2 className="h-3 w-3" />
                            </button>
                          </div>
                        </div>

                        <div>
                          <label className="text-xs text-gray-500">Comment</label>
                          <input
                            type="text"
                            value={rule.comment ?? ''}
                            onChange={(e) => updateXdpRule(pIdx, rIdx, { ...rule, comment: e.target.value || null })}
                            className={inputClass}
                            placeholder="optional"
                          />
                        </div>

                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <label className="text-xs text-gray-500">Matches</label>
                            <button
                              onClick={() => updateXdpRule(pIdx, rIdx, { ...rule, matches: [...(rule.matches ?? []), emptyMatch()] })}
                              className="inline-flex items-center gap-1 text-xs text-gray-500 hover:text-gray-700"
                            >
                              <Plus className="h-3 w-3" /> Add
                            </button>
                          </div>
                          <div className="space-y-1">
                            {(rule.matches ?? []).map((m, mIdx) => (
                              <XdpMatchEditor
                                key={mIdx}
                                match={m}
                                onChange={(updated) => {
                                  const newMatches = (rule.matches ?? []).map((mm, ii) => (ii === mIdx ? updated : mm));
                                  updateXdpRule(pIdx, rIdx, { ...rule, matches: newMatches });
                                }}
                                onRemove={() => {
                                  updateXdpRule(pIdx, rIdx, { ...rule, matches: (rule.matches ?? []).filter((_, ii) => ii !== mIdx) });
                                }}
                              />
                            ))}
                            {(rule.matches ?? []).length === 0 && (
                              <div className="text-xs text-gray-400 italic">No matches — matches all packets</div>
                            )}
                          </div>
                        </div>

                        <div>
                          <label className="text-xs text-gray-500">Action</label>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="text-xs text-gray-500">→</span>
                            <XdpActionEditor
                              action={rule.action}
                              onChange={(a) => updateXdpRule(pIdx, rIdx, { ...rule, action: a })}
                            />
                          </div>
                        </div>

                        <div className="text-xs font-mono text-gray-500 bg-gray-50 rounded px-2 py-1">
                          {(rule.matches ?? []).length > 0
                            ? `${(rule.matches ?? []).map(matchSummary).join(' && ')} → ${xdpActionToString(rule.action)}`
                            : `* → ${xdpActionToString(rule.action)}`}
                        </div>
                      </div>
                    ))}

                    <button
                      onClick={() => addXdpRule(pIdx)}
                      className="inline-flex items-center gap-1.5 rounded-md border border-dashed border-gray-300 px-3 py-1.5 text-xs text-gray-500 hover:border-gray-400 hover:text-gray-700"
                    >
                      <Plus className="h-3 w-3" />
                      Add Rule
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
