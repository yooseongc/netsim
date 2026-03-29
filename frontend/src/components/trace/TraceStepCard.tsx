import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import type { TraceStep } from '@/types/trace';
import { cn } from '@/lib/utils';
import { DecisionBadge } from './VerdictBadge';
import { StateDiffView, StateChangeSummary } from './StateDiffView';

interface TraceStepCardProps {
  step: TraceStep;
}

const stageLabels: Record<string, string> = {
  interface_check: 'INTERFACE_CHECK',
  arp_process: 'ARP_PROCESS',
  l2_bypass: 'L2_BYPASS',
  xdp: 'XDP',
  rp_filter: 'RP_FILTER',
  tc_ingress: 'TC_INGRESS',
  conntrack_in: 'CONNTRACK_IN',
  pre_routing: 'PREROUTING',
  pre_routing_raw: 'PREROUTING_RAW',
  routing_decision: 'ROUTING',
  local_input: 'INPUT',
  forward: 'FORWARD',
  post_routing: 'POSTROUTING',
  mtu_check: 'MTU_CHECK',
  conntrack_confirm: 'CONNTRACK_CONFIRM',
  bridge_forward: 'BRIDGE_FORWARD',
  output: 'OUTPUT',
  br_nf_prerouting: 'BR_NF_PREROUTING',
  br_nf_forward: 'BR_NF_FORWARD',
  br_nf_postrouting: 'BR_NF_POSTROUTING',
  loopback_delivery: 'LOOPBACK_DELIVERY',
  reroute: 'REROUTE',
};

const stageBorderColors: Record<string, string> = {
  xdp: 'border-l-indigo-500',
  tc_ingress: 'border-l-slate-500',
  conntrack_in: 'border-l-cyan-500',
  conntrack_confirm: 'border-l-cyan-500',
  pre_routing: 'border-l-amber-500',
  pre_routing_raw: 'border-l-amber-400',
  routing_decision: 'border-l-blue-500',
  local_input: 'border-l-green-500',
  forward: 'border-l-teal-500',
  post_routing: 'border-l-orange-500',
  output: 'border-l-violet-500',
  interface_check: 'border-l-gray-400',
  mtu_check: 'border-l-gray-400',
  rp_filter: 'border-l-gray-400',
  arp_process: 'border-l-gray-400',
  l2_bypass: 'border-l-gray-400',
  bridge_forward: 'border-l-gray-400',
  br_nf_prerouting: 'border-l-amber-400',
  br_nf_forward: 'border-l-teal-400',
  br_nf_postrouting: 'border-l-orange-400',
  loopback_delivery: 'border-l-purple-500',
  reroute: 'border-l-yellow-500',
};

function nodeColor(step: TraceStep): string {
  switch (step.decision.type) {
    case 'drop':
    case 'reject':
      return 'bg-red-500';
    case 'forward_to':
      return 'bg-blue-500';
    case 'continue':
    case 'accept':
    case 'local_delivery':
      return 'bg-green-500';
    case 'stolen':
    case 'redirect':
      return 'bg-amber-500';
    default:
      return 'bg-gray-400';
  }
}

export function TraceStepCard({ step }: TraceStepCardProps) {
  const [expanded, setExpanded] = useState(false);
  const stageLabel = stageLabels[step.stage] ?? step.stage.toUpperCase();
  const borderColor = stageBorderColors[step.stage] ?? 'border-l-gray-400';

  return (
    <div className="relative flex gap-3">
      {/* Timeline node and line */}
      <div className="flex flex-col items-center">
        <div className={cn('h-3 w-3 rounded-full ring-2 ring-white shrink-0 mt-1.5', nodeColor(step))} />
        <div className="w-0.5 flex-1 bg-gray-200" />
      </div>

      {/* Card content */}
      <div
        className={cn(
          'mb-3 flex-1 rounded border border-gray-200 bg-white shadow-sm cursor-pointer',
          'border-l-4',
          borderColor,
        )}
        onClick={() => setExpanded(!expanded)}
      >
        {/* Header row */}
        <div className="flex items-center gap-2 px-3 py-2">
          {expanded ? (
            <ChevronDown className="h-3.5 w-3.5 text-gray-400 shrink-0" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5 text-gray-400 shrink-0" />
          )}
          <span className="text-xs text-gray-400 font-mono w-6">[{step.seq}]</span>
          <span className="text-sm font-semibold text-gray-800">{stageLabel}</span>
          <span className="mx-1 text-gray-300">—</span>
          <DecisionBadge decision={step.decision} />
          {step.state_changes.length > 0 && (
            <span className="ml-auto text-xs text-purple-600 font-medium">
              {step.state_changes.length} change{step.state_changes.length > 1 ? 's' : ''}
            </span>
          )}
        </div>

        {/* Brief description */}
        <div className="px-3 pb-2 text-xs text-gray-500">{step.explain}</div>

        {/* State changes summary (always visible if present) */}
        {!expanded && step.state_changes.length > 0 && (
          <div className="px-3 pb-2">
            <StateChangeSummary changes={step.state_changes} />
          </div>
        )}

        {/* Expanded detail */}
        {expanded && (
          <div className="border-t px-3 py-3 space-y-3">
            {/* Description */}
            <div>
              <div className="text-xs font-medium text-gray-600 mb-1">Description</div>
              <div className="text-sm text-gray-700">{step.description}</div>
            </div>

            {/* State diff */}
            <div>
              <div className="text-xs font-medium text-gray-600 mb-1">Packet State (Before / After)</div>
              <StateDiffView
                before={step.state_before}
                after={step.state_after}
                changes={step.state_changes}
              />
            </div>

            {/* State changes */}
            {step.state_changes.length > 0 && (
              <StateChangeSummary changes={step.state_changes} />
            )}

            {/* Matched rules */}
            {step.matched_rules.length > 0 && (
              <div>
                <div className="text-xs font-medium text-gray-600 mb-1">Matched Rules</div>
                <div className="space-y-1">
                  {step.matched_rules.map((rule, i) => (
                    <div
                      key={i}
                      className="rounded bg-gray-50 px-2 py-1 text-xs font-mono text-gray-700"
                    >
                      [{rule.source}] {rule.table}:{rule.chain} #{rule.rule_index}{' '}
                      <span className="text-gray-500">— {rule.rule_summary}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Explain */}
            <div>
              <div className="text-xs font-medium text-gray-600 mb-1">Explanation</div>
              <div className="rounded bg-blue-50 px-3 py-2 text-sm text-blue-800">{step.explain}</div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
