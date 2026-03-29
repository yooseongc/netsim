import type { PacketState, StateChange } from '@/types/trace';
import { cn } from '@/lib/utils';

interface StateDiffViewProps {
  before: PacketState;
  after: PacketState;
  changes: StateChange[];
}

const DISPLAY_FIELDS: { key: keyof PacketState; label: string }[] = [
  { key: 'src_ip', label: 'Src IP' },
  { key: 'dst_ip', label: 'Dst IP' },
  { key: 'src_port', label: 'Src Port' },
  { key: 'dst_port', label: 'Dst Port' },
  { key: 'protocol', label: 'Protocol' },
  { key: 'ingress_if', label: 'Ingress' },
  { key: 'egress_if', label: 'Egress' },
  { key: 'ttl', label: 'TTL' },
  { key: 'mark', label: 'Mark' },
  { key: 'ct_state', label: 'CT State' },
  { key: 'ct_mark', label: 'CT Mark' },
  { key: 'dscp', label: 'DSCP' },
  { key: 'dnat_applied', label: 'DNAT' },
  { key: 'snat_applied', label: 'SNAT' },
  { key: 'src_mac', label: 'Src MAC' },
  { key: 'dst_mac', label: 'Dst MAC' },
];

function formatValue(val: unknown): string {
  if (val === null || val === undefined) return '-';
  if (typeof val === 'boolean') return val ? 'yes' : 'no';
  if (typeof val === 'object') return JSON.stringify(val);
  return String(val);
}

export function StateDiffView({ before, after, changes }: StateDiffViewProps) {
  const changedFields = new Set(changes.map((c) => c.field));

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs font-mono">
        <thead>
          <tr className="border-b bg-gray-50">
            <th className="px-3 py-1.5 text-left font-medium text-gray-600">Field</th>
            <th className="px-3 py-1.5 text-left font-medium text-gray-600">Before</th>
            <th className="px-3 py-1.5 text-left font-medium text-gray-600">After</th>
          </tr>
        </thead>
        <tbody>
          {DISPLAY_FIELDS.map(({ key, label }) => {
            const changed = changedFields.has(key);
            const beforeVal = formatValue(before[key]);
            const afterVal = formatValue(after[key]);
            // Skip fields that are empty on both sides
            if (beforeVal === '-' && afterVal === '-') return null;
            return (
              <tr
                key={key}
                className={cn(
                  'border-b',
                  changed ? 'bg-yellow-50' : '',
                )}
              >
                <td className="px-3 py-1 text-gray-600">{label}</td>
                <td className={cn('px-3 py-1', changed ? 'text-red-600 line-through' : 'text-gray-500')}>
                  {beforeVal}
                </td>
                <td className={cn('px-3 py-1', changed ? 'text-green-700 font-semibold' : 'text-gray-500')}>
                  {afterVal}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function StateChangeSummary({ changes }: { changes: StateChange[] }) {
  if (changes.length === 0) return null;

  return (
    <div className="rounded border border-amber-200 bg-amber-50 p-2 text-xs font-mono">
      <div className="mb-1 font-semibold text-amber-700">State Changes</div>
      {changes.map((c, i) => (
        <div key={i} className="text-amber-800">
          {c.field}: <span className="text-red-600 line-through">{c.from}</span>{' '}
          <span className="text-green-700">{c.to}</span>
        </div>
      ))}
    </div>
  );
}
