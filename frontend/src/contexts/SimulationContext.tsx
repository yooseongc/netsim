import { createContext, useContext, useState, type ReactNode } from 'react';
import type { SimulationResult } from '@/types/trace';

interface SimulationContextValue {
  result: SimulationResult | null;
  setResult: (result: SimulationResult | null) => void;
}

const SimulationContext = createContext<SimulationContextValue | null>(null);

export function SimulationProvider({ children }: { children: ReactNode }) {
  const [result, setResult] = useState<SimulationResult | null>(null);

  return (
    <SimulationContext.Provider value={{ result, setResult }}>
      {children}
    </SimulationContext.Provider>
  );
}

export function useSimulationResult() {
  const ctx = useContext(SimulationContext);
  if (!ctx) {
    throw new Error('useSimulationResult must be used within SimulationProvider');
  }
  return ctx;
}
