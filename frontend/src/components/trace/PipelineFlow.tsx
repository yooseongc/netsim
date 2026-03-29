import type { TraceStep, FinalVerdict } from '@/types/trace';
import { TraceStepCard } from './TraceStepCard';
import { VerdictBadge } from './VerdictBadge';

interface PipelineFlowProps {
  steps: TraceStep[];
  verdict: FinalVerdict;
}

export function PipelineFlow({ steps, verdict }: PipelineFlowProps) {
  return (
    <div>
      <div className="text-lg font-semibold text-gray-800 mb-4">Pipeline Flow</div>
      <div className="pl-1">
        {steps.map((step) => (
          <TraceStepCard key={step.seq} step={step} />
        ))}
        {/* Terminal node */}
        <div className="flex items-center gap-3">
          <div className="flex flex-col items-center">
            <div className="h-4 w-4 rounded-full bg-gray-700 ring-2 ring-white shrink-0" />
          </div>
          <div className="flex items-center gap-2 py-1">
            <span className="text-sm font-semibold text-gray-700">Final:</span>
            <VerdictBadge verdict={verdict} />
          </div>
        </div>
      </div>
    </div>
  );
}
