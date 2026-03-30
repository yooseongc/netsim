import { useState } from 'react';
import { Plus, Pencil, Trash2, ChevronDown, ChevronRight } from 'lucide-react';
import type {
  RoutingTable,
  Route,
  RouteScope,
  RouteType,
  IpRule,
  RuleAction,
} from '@/types/scenario';

const inputClass =
  'w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-gray-400';
const selectClass = inputClass;
const labelClass = 'mb-1 block text-sm font-medium text-gray-700';

const ROUTE_SCOPES: RouteScope[] = ['global', 'link', 'host', 'nowhere'];
const ROUTE_TYPES: RouteType[] = ['unicast', 'local', 'broadcast', 'blackhole', 'unreachable', 'prohibit', 'throw'];

// ── Route Form (inline) ──
function emptyRoute(): Route {
  return { destination: '', gateway: null, dev: null, metric: 0, scope: 'global', route_type: 'unicast' };
}

interface RouteFormProps {
  route: Route;
  onSave: (r: Route) => void;
  onCancel: () => void;
  interfaceNames: string[];
}

function RouteForm({ route, onSave, onCancel, interfaceNames }: RouteFormProps) {
  const [data, setData] = useState<Route>({ ...route });

  return (
    <div className="bg-gray-50 border border-gray-200 rounded-md p-3 space-y-3">
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className={labelClass}>Destination *</label>
          <input
            type="text"
            value={data.destination}
            onChange={(e) => setData({ ...data, destination: e.target.value })}
            className={inputClass}
            placeholder="10.0.0.0/24 or default"
          />
        </div>
        <div>
          <label className={labelClass}>Gateway</label>
          <input
            type="text"
            value={data.gateway ?? ''}
            onChange={(e) => setData({ ...data, gateway: e.target.value || null })}
            className={inputClass}
            placeholder="10.0.0.1"
          />
        </div>
        <div>
          <label className={labelClass}>Device</label>
          {interfaceNames.length > 0 ? (
            <select
              value={data.dev ?? ''}
              onChange={(e) => setData({ ...data, dev: e.target.value || null })}
              className={selectClass}
            >
              <option value="">— none —</option>
              {interfaceNames.map((n) => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
          ) : (
            <input
              type="text"
              value={data.dev ?? ''}
              onChange={(e) => setData({ ...data, dev: e.target.value || null })}
              className={inputClass}
              placeholder="eth0"
            />
          )}
        </div>
        <div>
          <label className={labelClass}>Source</label>
          <input
            type="text"
            value={data.src ?? ''}
            onChange={(e) => setData({ ...data, src: e.target.value || null })}
            className={inputClass}
            placeholder="10.0.0.2"
          />
        </div>
        <div>
          <label className={labelClass}>Metric</label>
          <input
            type="number"
            value={data.metric ?? 0}
            onChange={(e) => setData({ ...data, metric: Number(e.target.value) || 0 })}
            className={inputClass}
            min={0}
          />
        </div>
        <div>
          <label className={labelClass}>Scope</label>
          <select
            value={data.scope ?? 'global'}
            onChange={(e) => setData({ ...data, scope: e.target.value as RouteScope })}
            className={selectClass}
          >
            {ROUTE_SCOPES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <div>
          <label className={labelClass}>Type</label>
          <select
            value={data.route_type ?? 'unicast'}
            onChange={(e) => setData({ ...data, route_type: e.target.value as RouteType })}
            className={selectClass}
          >
            {ROUTE_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>
        <div>
          <label className={labelClass}>MTU</label>
          <input
            type="number"
            value={data.mtu ?? ''}
            onChange={(e) => setData({ ...data, mtu: e.target.value ? Number(e.target.value) : null })}
            className={inputClass}
            placeholder="1500"
          />
        </div>
      </div>
      <div className="flex justify-end gap-2">
        <button onClick={onCancel} className="rounded-md border border-gray-300 px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50">
          Cancel
        </button>
        <button
          onClick={() => { if (data.destination.trim()) onSave(data); }}
          className="rounded-md bg-gray-900 px-3 py-1.5 text-xs text-white hover:bg-gray-800"
        >
          Save
        </button>
      </div>
    </div>
  );
}

// ── IP Rule helpers ──

function ruleActionToString(a: RuleAction): string {
  if (typeof a === 'string') return a;
  if ('lookup' in a) return `lookup ${a.lookup}`;
  return 'blackhole';
}

function parseRuleAction(s: string): RuleAction {
  if (s.startsWith('lookup ')) {
    return { lookup: Number(s.slice(7)) || 254 };
  }
  if (s === 'blackhole' || s === 'unreachable' || s === 'prohibit') return s;
  return { lookup: 254 };
}

// ── Main Component ──

interface RoutingEditorProps {
  routingTables: RoutingTable[];
  ipRules: IpRule[];
  onChangeRoutingTables: (tables: RoutingTable[]) => void;
  onChangeIpRules: (rules: IpRule[]) => void;
  interfaceNames: string[];
}

export function RoutingEditor({
  routingTables,
  ipRules,
  onChangeRoutingTables,
  onChangeIpRules,
  interfaceNames,
}: RoutingEditorProps) {
  const [expandedTable, setExpandedTable] = useState<number | null>(null);
  const [addingRouteToTable, setAddingRouteToTable] = useState<number | null>(null);
  const [editingRoute, setEditingRoute] = useState<{ tableIdx: number; routeIdx: number } | null>(null);

  // Table CRUD
  const addTable = () => {
    const maxId = routingTables.reduce((m, t) => Math.max(m, t.id), 0);
    onChangeRoutingTables([...routingTables, { id: maxId + 1, name: null, routes: [] }]);
  };

  const deleteTable = (idx: number) => {
    onChangeRoutingTables(routingTables.filter((_, i) => i !== idx));
  };

  const updateTable = (idx: number, patch: Partial<RoutingTable>) => {
    onChangeRoutingTables(routingTables.map((t, i) => (i === idx ? { ...t, ...patch } : t)));
  };

  // Route CRUD within a table
  const addRoute = (tableIdx: number, route: Route) => {
    const table = routingTables[tableIdx];
    updateTable(tableIdx, { routes: [...(table.routes ?? []), route] });
    setAddingRouteToTable(null);
  };

  const updateRoute = (tableIdx: number, routeIdx: number, route: Route) => {
    const table = routingTables[tableIdx];
    const routes = (table.routes ?? []).map((r, i) => (i === routeIdx ? route : r));
    updateTable(tableIdx, { routes });
    setEditingRoute(null);
  };

  const deleteRoute = (tableIdx: number, routeIdx: number) => {
    const table = routingTables[tableIdx];
    updateTable(tableIdx, { routes: (table.routes ?? []).filter((_, i) => i !== routeIdx) });
  };

  // IP Rule CRUD
  const addIpRule = () => {
    const maxPrio = ipRules.reduce((m, r) => Math.max(m, r.priority), 0);
    onChangeIpRules([...ipRules, { priority: maxPrio + 100, action: { lookup: 254 } }]);
  };

  const updateIpRule = (idx: number, patch: Partial<IpRule>) => {
    onChangeIpRules(ipRules.map((r, i) => (i === idx ? { ...r, ...patch } : r)));
  };

  const deleteIpRule = (idx: number) => {
    onChangeIpRules(ipRules.filter((_, i) => i !== idx));
  };

  return (
    <div className="space-y-6">
      {/* Routing Tables */}
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
          <h3 className="text-sm font-semibold text-gray-900">
            Routing Tables ({routingTables.length})
          </h3>
          <button
            onClick={addTable}
            className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-gray-800 transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            Add Table
          </button>
        </div>

        {routingTables.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-gray-400">
            No routing tables. Click &quot;Add Table&quot; to create one.
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {routingTables.map((table, tIdx) => (
              <div key={tIdx}>
                <div className="flex items-center gap-3 px-4 py-3">
                  <button
                    onClick={() => setExpandedTable(expandedTable === tIdx ? null : tIdx)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    {expandedTable === tIdx
                      ? <ChevronDown className="h-4 w-4" />
                      : <ChevronRight className="h-4 w-4" />}
                  </button>
                  <div className="flex-1 min-w-0 flex items-center gap-2">
                    <span className="text-sm font-medium text-gray-900">Table {table.id}</span>
                    <input
                      type="text"
                      value={table.name ?? ''}
                      onChange={(e) => updateTable(tIdx, { name: e.target.value || null })}
                      className="rounded border border-gray-200 px-2 py-0.5 text-xs text-gray-600 w-28"
                      placeholder="name"
                    />
                    <span className="text-xs text-gray-400">
                      {(table.routes ?? []).length} route(s)
                    </span>
                  </div>
                  <button
                    onClick={() => deleteTable(tIdx)}
                    className="rounded px-2 py-1 text-xs text-red-400 hover:bg-red-50 hover:text-red-600"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </div>

                {expandedTable === tIdx && (
                  <div className="border-t border-gray-100 bg-gray-50 px-4 py-3 space-y-2">
                    {(table.routes ?? []).map((route, rIdx) => (
                      <div key={rIdx}>
                        {editingRoute?.tableIdx === tIdx && editingRoute.routeIdx === rIdx ? (
                          <RouteForm
                            route={route}
                            interfaceNames={interfaceNames}
                            onSave={(r) => updateRoute(tIdx, rIdx, r)}
                            onCancel={() => setEditingRoute(null)}
                          />
                        ) : (
                          <div className="flex items-center gap-2 rounded bg-white border border-gray-200 px-3 py-2">
                            <span className="text-sm font-mono text-gray-800 flex-1">
                              {route.destination}
                              {route.gateway && <span className="text-gray-500"> via {route.gateway}</span>}
                              {route.dev && <span className="text-gray-500"> dev {route.dev}</span>}
                              {route.route_type && route.route_type !== 'unicast' && (
                                <span className="ml-1 rounded bg-amber-100 px-1.5 py-0.5 text-xs text-amber-700">
                                  {route.route_type}
                                </span>
                              )}
                              {(route.metric ?? 0) > 0 && (
                                <span className="text-xs text-gray-400 ml-1">metric {route.metric}</span>
                              )}
                            </span>
                            <button
                              onClick={() => setEditingRoute({ tableIdx: tIdx, routeIdx: rIdx })}
                              className="rounded px-1.5 py-1 text-gray-400 hover:bg-gray-100 hover:text-gray-600"
                            >
                              <Pencil className="h-3 w-3" />
                            </button>
                            <button
                              onClick={() => deleteRoute(tIdx, rIdx)}
                              className="rounded px-1.5 py-1 text-red-400 hover:bg-red-50 hover:text-red-600"
                            >
                              <Trash2 className="h-3 w-3" />
                            </button>
                          </div>
                        )}
                      </div>
                    ))}

                    {addingRouteToTable === tIdx ? (
                      <RouteForm
                        route={emptyRoute()}
                        interfaceNames={interfaceNames}
                        onSave={(r) => addRoute(tIdx, r)}
                        onCancel={() => setAddingRouteToTable(null)}
                      />
                    ) : (
                      <button
                        onClick={() => setAddingRouteToTable(tIdx)}
                        className="inline-flex items-center gap-1.5 rounded-md border border-dashed border-gray-300 px-3 py-1.5 text-xs text-gray-500 hover:border-gray-400 hover:text-gray-700"
                      >
                        <Plus className="h-3 w-3" />
                        Add Route
                      </button>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      {/* IP Rules (Policy Routing) */}
      <section className="rounded-lg border border-gray-200 bg-white">
        <div className="flex items-center justify-between border-b border-gray-200 px-4 py-3">
          <h3 className="text-sm font-semibold text-gray-900">
            IP Rules — Policy Routing ({ipRules.length})
          </h3>
          <button
            onClick={addIpRule}
            className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-gray-800 transition-colors"
          >
            <Plus className="h-3.5 w-3.5" />
            Add Rule
          </button>
        </div>

        {ipRules.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-gray-400">
            No IP rules defined. Default routing uses table 254 (main).
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {ipRules.map((rule, idx) => (
              <div key={idx} className="px-4 py-3">
                <div className="grid grid-cols-6 gap-3 items-end">
                  <div>
                    <label className="text-xs text-gray-500">Priority</label>
                    <input
                      type="number"
                      value={rule.priority}
                      onChange={(e) => updateIpRule(idx, { priority: Number(e.target.value) || 0 })}
                      className={inputClass}
                      min={0}
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500">From</label>
                    <input
                      type="text"
                      value={rule.selector?.from ?? ''}
                      onChange={(e) =>
                        updateIpRule(idx, {
                          selector: { ...(rule.selector ?? {}), from: e.target.value || null },
                        })
                      }
                      className={inputClass}
                      placeholder="0.0.0.0/0"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500">To</label>
                    <input
                      type="text"
                      value={rule.selector?.to ?? ''}
                      onChange={(e) =>
                        updateIpRule(idx, {
                          selector: { ...(rule.selector ?? {}), to: e.target.value || null },
                        })
                      }
                      className={inputClass}
                      placeholder="10.0.0.0/8"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500">fwmark</label>
                    <input
                      type="number"
                      value={rule.selector?.fwmark ?? ''}
                      onChange={(e) =>
                        updateIpRule(idx, {
                          selector: {
                            ...(rule.selector ?? {}),
                            fwmark: e.target.value ? Number(e.target.value) : null,
                          },
                        })
                      }
                      className={inputClass}
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-500">Action</label>
                    <input
                      type="text"
                      value={ruleActionToString(rule.action)}
                      onChange={(e) => updateIpRule(idx, { action: parseRuleAction(e.target.value) })}
                      className={inputClass}
                      placeholder="lookup 254"
                    />
                  </div>
                  <div className="flex justify-end">
                    <button
                      onClick={() => deleteIpRule(idx)}
                      className="rounded px-2 py-2 text-red-400 hover:bg-red-50 hover:text-red-600"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
