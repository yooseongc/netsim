import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Edit } from 'lucide-react';
import { useSimulationResult } from '@/contexts/SimulationContext';
import { PipelineFlow } from '@/components/trace/PipelineFlow';
import { VerdictBadge } from '@/components/trace/VerdictBadge';

export function SimulationResultPage() {
  const { name } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const { result } = useSimulationResult();
  const projectName = name ?? '';

  if (!result) {
    return (
      <div className="max-w-4xl mx-auto text-center py-12">
        <p className="text-gray-500 mb-4">No simulation result available.</p>
        <button
          onClick={() => navigate(`/projects/${encodeURIComponent(projectName)}`)}
          className="inline-flex items-center gap-2 rounded-md border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to Editor
        </button>
      </div>
    );
  }

  const { summary, trace, verdict } = result;

  return (
    <div className="max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <button
          onClick={() => navigate(`/projects/${encodeURIComponent(projectName)}`)}
          className="rounded p-1.5 text-gray-500 hover:bg-gray-100 transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
        </button>
        <h2 className="text-2xl font-bold text-gray-900">{projectName}</h2>
        <span className="text-sm text-gray-400">Simulation Result</span>
        <div className="ml-auto">
          <button
            onClick={() => navigate(`/projects/${encodeURIComponent(projectName)}`)}
            className="inline-flex items-center gap-2 rounded-md border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-50"
          >
            <Edit className="h-3.5 w-3.5" />
            Edit Scenario
          </button>
        </div>
      </div>

      {/* Summary card */}
      <div className="mb-6 rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
        <div className="text-lg font-semibold text-gray-800 mb-3">Summary</div>
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
      <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
        <PipelineFlow steps={trace} verdict={verdict} />
      </div>
    </div>
  );
}
