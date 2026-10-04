import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import type { ScenarioResponse } from '../types/api';
import { api } from '../services/api';

interface ScenarioContextType {
  selectedScenario: ScenarioResponse | null;
  setSelectedScenario: (scenario: ScenarioResponse | null) => void;
  scenarios: ScenarioResponse[];
  isLoadingScenarios: boolean;
  refreshScenarios: () => Promise<void>;
}

const ScenarioContext = createContext<ScenarioContextType | undefined>(undefined);

export function ScenarioProvider({ children }: { children: ReactNode }) {
  const [selectedScenario, setSelectedScenario] = useState<ScenarioResponse | null>(null);
  const [scenarios, setScenarios] = useState<ScenarioResponse[]>([]);
  const [isLoadingScenarios, setIsLoadingScenarios] = useState(true);

  const refreshScenarios = useCallback(async () => {
    setIsLoadingScenarios(true);
    try {
      const data = await api.scenarios.list({ limit: 100 });
      setScenarios(data);
      if (selectedScenario && !data.find((s) => s.id === selectedScenario.id)) {
        setSelectedScenario(data[0] || null);
      }
    } catch (error) {
      console.error('Failed to load scenarios:', error);
    } finally {
      setIsLoadingScenarios(false);
    }
  }, [selectedScenario]);

  useEffect(() => {
    let cancelled = false;
    const init = async () => {
      setIsLoadingScenarios(true);
      try {
        const data = await api.scenarios.list({ limit: 100 });
        if (!cancelled) {
          setScenarios(data);
          if (data.length > 0) {
            setSelectedScenario((prev) => prev ?? data[0]);
          }
        }
      } catch (error) {
        console.error('Failed to load scenarios:', error);
      } finally {
        if (!cancelled) setIsLoadingScenarios(false);
      }
    };
    init();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <ScenarioContext.Provider value={{
      selectedScenario,
      setSelectedScenario,
      scenarios,
      isLoadingScenarios,
      refreshScenarios,
    }}>
      {children}
    </ScenarioContext.Provider>
  );
}

export function useScenario() {
  const context = useContext(ScenarioContext);
  if (!context) {
    throw new Error('useScenario must be used within a ScenarioProvider');
  }
  return context;
}