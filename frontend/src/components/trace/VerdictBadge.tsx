import { cn } from '@/lib/utils';
import type { FinalVerdict, StageDecision } from '@/types/trace';

const verdictStyles: Record<string, string> = {
  drop: 'bg-red-100 text-red-800 border-red-200',
  local_delivery: 'bg-green-100 text-green-800 border-green-200',
  forwarded: 'bg-blue-100 text-blue-800 border-blue-200',
  redirect: 'bg-purple-100 text-purple-800 border-purple-200',
  tx: 'bg-blue-100 text-blue-800 border-blue-200',
  rejected: 'bg-red-100 text-red-800 border-red-200',
  blackhole: 'bg-gray-100 text-gray-800 border-gray-200',
  tproxy: 'bg-purple-100 text-purple-800 border-purple-200',
  sent: 'bg-green-100 text-green-800 border-green-200',
};

const verdictLabels: Record<string, string> = {
  drop: 'DROP',
  local_delivery: 'LOCAL_DELIVERY',
  forwarded: 'FORWARDED',
  redirect: 'REDIRECT',
  tx: 'TX',
  rejected: 'REJECTED',
  blackhole: 'BLACKHOLE',
  tproxy: 'TPROXY',
  sent: 'SENT',
};

export function VerdictBadge({ verdict, className }: { verdict: FinalVerdict; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold',
        verdictStyles[verdict] ?? 'bg-gray-100 text-gray-800 border-gray-200',
        className,
      )}
    >
      {verdictLabels[verdict] ?? verdict.toUpperCase()}
    </span>
  );
}

function decisionColor(decision: StageDecision): string {
  switch (decision.type) {
    case 'continue':
    case 'accept':
    case 'local_delivery':
      return 'text-green-600';
    case 'drop':
    case 'reject':
      return 'text-red-600';
    case 'forward_to':
      return 'text-blue-600';
    case 'redirect':
    case 'stolen':
      return 'text-amber-600';
    default:
      return 'text-gray-600';
  }
}

function decisionLabel(decision: StageDecision): string {
  switch (decision.type) {
    case 'continue':
      return 'Continue';
    case 'accept':
      return 'Accept';
    case 'drop':
      return 'Drop';
    case 'reject':
      return 'Reject';
    case 'stolen':
      return 'Stolen';
    case 'redirect':
      return `Redirect → ${decision.target}`;
    case 'local_delivery':
      return 'LocalDelivery';
    case 'forward_to':
      return `ForwardTo → ${decision.egress_if}`;
    default:
      return 'Unknown';
  }
}

export function DecisionBadge({ decision, className }: { decision: StageDecision; className?: string }) {
  const color = decisionColor(decision);
  const label = decisionLabel(decision);

  return (
    <span className={cn('inline-flex items-center text-xs font-semibold', color, className)}>
      {label}
    </span>
  );
}
