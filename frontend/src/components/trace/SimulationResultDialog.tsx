import { X } from 'lucide-react';
import type { SimulationResult } from '@/types/trace';
import { PipelineFlow } from './PipelineFlow';
import { VerdictBadge } from './VerdictBadge';

interface SimulationResultDialogProps {
  result: SimulationResult;
  onClose: () => void;
}

export function SimulationResultDialog({ result, onClose }: SimulationResultDialogProps) {
  const { summary, trace, verdict } = result;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 overflow-y-auto py-8">
      <div className="w-full max-w-4xl rounded-xl bg-white shadow-2xl mx-4">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-gray-200 px-6 py-4">
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-bold text-gray-900">Simulation Result</h2>
            <VerdictBadge verdict={verdict} />
            {verdict === 'forwarded' && summary.egress_interface && (
              <span className="rounded-md bg-blue-100 px-2.5 py-1 text-xs font-mono font-medium text-blue-700">
                → {summary.egress_interface}
              </span>
            )}
            {summary.nat_applied && (
              <span className="rounded-md bg-amber-100 px-2.5 py-1 text-xs font-medium text-amber-700">
                NAT
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-gray-400 hover:bg-gray-100 hover:text-gray-600 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Summary */}
        <div className="px-6 py-4 border-b border-gray-100 bg-gray-50">
          <div className="grid grid-cols-2 gap-x-8 gap-y-2 sm:grid-cols-4">
            <div>
              <div className="text-xs text-gray-500 mb-1">Verdict</div>
              <VerdictBadge verdict={verdict} />
            </div>
            <div>
              <div className="text-xs text-gray-500 mb-1">Egress Interface</div>
              <div className="text-sm font-mono font-medium text-gray-800">
                {summary.egress_interface ?? '-'}
              </div>
            </div>
            <div>
              <div className="text-xs text-gray-500 mb-1">Next Hop</div>
              <div className="text-sm font-mono font-medium text-gray-800">
                {summary.next_hop ?? '-'}
              </div>
            </div>
            <div>
              <div className="text-xs text-gray-500 mb-1">NAT Applied</div>
              <div className="text-sm font-medium text-gray-800">
                {summary.nat_applied ? (
                  <span className="text-amber-600">Yes</span>
                ) : (
                  <span className="text-gray-500">No</span>
                )}
              </div>
            </div>
            <div>
              <div className="text-xs text-gray-500 mb-1">Total Steps</div>
              <div className="text-sm font-medium text-gray-800">{summary.total_steps}</div>
            </div>
            {summary.matched_rules.length > 0 && (
              <div className="col-span-2 sm:col-span-3">
                <div className="text-xs text-gray-500 mb-1">Key Matched Rules</div>
                <div className="flex flex-wrap gap-1">
                  {summary.matched_rules.map((rule, i) => (
                    <span
                      key={i}
                      className="inline-flex rounded bg-gray-100 px-2 py-0.5 text-xs font-mono text-gray-700"
                    >
                      {rule.table}:{rule.chain} #{rule.rule_index}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Pipeline flow */}
        <div className="px-6 py-4 max-h-[60vh] overflow-y-auto">
          <PipelineFlow steps={trace} verdict={verdict} />
        </div>

        {/* Footer */}
        <div className="flex justify-end border-t border-gray-200 px-6 py-3">
          <button
            onClick={onClose}
            className="rounded-md bg-gray-900 px-4 py-2 text-sm font-medium text-white hover:bg-gray-800 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
