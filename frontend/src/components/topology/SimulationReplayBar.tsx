import { useState, useEffect, useCallback, useRef } from 'react';
import { Play, Pause, SkipForward, SkipBack, RotateCcw, X, ListOrdered } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { SimulationResult, TraceStep, PipelineStage } from '@/types/trace';

const STAGE_LABELS: Record<PipelineStage, string> = {
  interface_check: 'Interface Check',
  arp_process: 'ARP Process',
  l2_bypass: 'L2 Bypass',
  xdp: 'XDP',
  rp_filter: 'RP Filter',
  tc_ingress: 'TC Ingress',
  conntrack_in: 'Conntrack',
  pre_routing: 'PREROUTING',
  routing_decision: 'Routing',
  local_input: 'INPUT',
  forward: 'FORWARD',
  post_routing: 'POSTROUTING',
  mtu_check: 'MTU Check',
  conntrack_confirm: 'Conntrack Confirm',
  pre_routing_raw: 'PREROUTING (raw)',
  bridge_forward: 'Bridge Forward',
  output: 'OUTPUT',
  br_nf_prerouting: 'Br NF PREROUTING',
  br_nf_forward: 'Br NF FORWARD',
  br_nf_postrouting: 'Br NF POSTROUTING',
  loopback_delivery: 'Loopback Delivery',
  reroute: 'Reroute',
  bridge_fdb_lookup: 'Bridge FDB',
  arp_resolve: 'ARP Resolve',
  l2_rewrite: 'L2 Rewrite',
};

const STAGE_COLORS: Partial<Record<PipelineStage, string>> = {
  xdp: 'bg-indigo-500',
  pre_routing: 'bg-amber-500',
  routing_decision: 'bg-blue-500',
  local_input: 'bg-green-500',
  forward: 'bg-teal-500',
  post_routing: 'bg-orange-500',
  conntrack_in: 'bg-cyan-500',
  output: 'bg-violet-500',
};

function decisionText(step: TraceStep): string {
  const d = step.decision;
  switch (d.type) {
    case 'continue': return 'CONTINUE';
    case 'accept': return 'ACCEPT';
    case 'drop': return `DROP: ${d.reason}`;
    case 'reject': return `REJECT: ${d.reason}`;
    case 'local_delivery': return 'LOCAL DELIVERY';
    case 'forward_to': return `FORWARD → ${d.egress_if}`;
    case 'redirect': return `REDIRECT → ${d.target}`;
    case 'stolen': return 'STOLEN';
  }
}

function decisionColor(step: TraceStep): string {
  switch (step.decision.type) {
    case 'drop': case 'reject': return 'text-red-600';
    case 'local_delivery': return 'text-green-600';
    case 'forward_to': return 'text-blue-600';
    case 'accept': return 'text-green-600';
    default: return 'text-gray-600';
  }
}

interface SimulationReplayBarProps {
  result: SimulationResult;
  currentStep: number;
  onStepChange: (step: number) => void;
  onShowDetail?: () => void;
  onClose: () => void;
}

export function SimulationReplayBar({ result, currentStep, onStepChange, onClose, onShowDetail }: SimulationReplayBarProps) {
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1000); // ms per step
  const intervalRef = useRef<number | null>(null);
  const steps = result.trace;
  const totalSteps = steps.length;

  const stop = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    setPlaying(false);
  }, []);

  const play = useCallback(() => {
    stop();
    setPlaying(true);
    let step = currentStep;
    intervalRef.current = window.setInterval(() => {
      step += 1;
      if (step >= totalSteps) {
        stop();
        onStepChange(totalSteps - 1);
      } else {
        onStepChange(step);
      }
    }, speed);
  }, [currentStep, totalSteps, speed, onStepChange, stop]);

  useEffect(() => {
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, []);

  // Restart play if speed changes while playing
  useEffect(() => {
    if (playing) play();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [speed]);

  const step = steps[currentStep];
  const stageColor = step ? (STAGE_COLORS[step.stage] ?? 'bg-gray-500') : 'bg-gray-400';

  return (
    <div className="absolute bottom-0 left-0 right-0 z-20 border-t border-gray-200 bg-white shadow-lg">
      {/* Progress bar */}
      <div className="h-1.5 bg-gray-100 relative">
        <div
          className="h-full bg-blue-500 transition-all duration-300"
          style={{ width: `${((currentStep + 1) / totalSteps) * 100}%` }}
        />
        {/* Step dots */}
        <div className="absolute inset-0 flex items-center justify-between px-1">
          {steps.map((_, i) => (
            <button
              key={i}
              onClick={() => { stop(); onStepChange(i); }}
              className={cn(
                'w-2.5 h-2.5 rounded-full border-2 border-white transition-colors',
                i <= currentStep ? 'bg-blue-500' : 'bg-gray-300',
                i === currentStep && 'ring-2 ring-blue-300 bg-blue-600',
              )}
            />
          ))}
        </div>
      </div>

      <div className="flex items-center gap-3 px-4 py-2.5">
        {/* Controls */}
        <div className="flex items-center gap-1">
          <button
            onClick={() => { stop(); onStepChange(0); }}
            className="rounded p-1.5 text-gray-500 hover:bg-gray-100"
            title="Reset"
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={() => { stop(); onStepChange(Math.max(0, currentStep - 1)); }}
            disabled={currentStep === 0}
            className="rounded p-1.5 text-gray-500 hover:bg-gray-100 disabled:opacity-30"
          >
            <SkipBack className="h-3.5 w-3.5" />
          </button>
          <button
            onClick={playing ? stop : play}
            className="rounded-full p-2 bg-blue-600 text-white hover:bg-blue-700 transition-colors"
          >
            {playing ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
          </button>
          <button
            onClick={() => { stop(); onStepChange(Math.min(totalSteps - 1, currentStep + 1)); }}
            disabled={currentStep >= totalSteps - 1}
            className="rounded p-1.5 text-gray-500 hover:bg-gray-100 disabled:opacity-30"
          >
            <SkipForward className="h-3.5 w-3.5" />
          </button>
        </div>

        {/* Speed */}
        <select
          value={speed}
          onChange={(e) => setSpeed(Number(e.target.value))}
          className="rounded border border-gray-200 px-2 py-1 text-xs text-gray-600"
        >
          <option value={2000}>0.5x</option>
          <option value={1000}>1x</option>
          <option value={500}>2x</option>
          <option value={250}>4x</option>
        </select>

        {/* Current step info */}
        <div className="flex-1 flex items-center gap-2 min-w-0">
          <span className="text-xs text-gray-400 flex-shrink-0">
            {currentStep + 1}/{totalSteps}
          </span>
          {step && (
            <>
              <span className={cn('rounded px-2 py-0.5 text-[10px] font-bold text-white', stageColor)}>
                {STAGE_LABELS[step.stage] ?? step.stage}
              </span>
              <span className={cn('text-xs font-medium flex-shrink-0', decisionColor(step))}>
                {decisionText(step)}
              </span>
              <span className="text-xs text-gray-400 truncate">
                {step.description}
              </span>
            </>
          )}
        </div>

        {/* Verdict */}
        <span className={cn(
          'rounded-full px-2.5 py-0.5 text-xs font-bold flex-shrink-0',
          currentStep === totalSteps - 1 ? (
            result.verdict === 'drop' || result.verdict === 'rejected' ? 'bg-red-100 text-red-700'
            : result.verdict === 'forwarded' ? 'bg-blue-100 text-blue-700'
            : result.verdict === 'local_delivery' ? 'bg-green-100 text-green-700'
            : 'bg-gray-100 text-gray-700'
          ) : 'bg-gray-100 text-gray-500',
        )}>
          {result.verdict.toUpperCase()}
          {result.verdict === 'forwarded' && result.summary.egress_interface && ` → ${result.summary.egress_interface}`}
        </span>

        {onShowDetail && (
          <button
            onClick={onShowDetail}
            className="inline-flex items-center gap-1 rounded-md border border-gray-200 px-2 py-1 text-[10px] font-medium text-gray-600 hover:bg-gray-50"
            title="Show detailed trace"
          >
            <ListOrdered className="h-3 w-3" />
            Detail
          </button>
        )}

        <button onClick={onClose} className="rounded p-1.5 text-gray-400 hover:bg-gray-100 hover:text-gray-600">
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}
