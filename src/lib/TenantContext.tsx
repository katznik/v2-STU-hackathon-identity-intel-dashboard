import { createContext, useContext, useMemo, type ReactNode } from 'react';
import { generateTenant } from '../data/generateTenant';
import { computeFindings } from '../analytics/findings';
import {
  computeBusinessUnitRisk,
  computeExecutiveSummary,
  computePillarScores,
  type BusinessUnitRisk,
  type ExecutiveSummary,
} from '../analytics/metrics';
import type { Finding, PillarScore, TenantDataset } from '../domain/types';

interface TenantContextValue {
  data: TenantDataset;
  findings: Finding[];
  pillars: PillarScore[];
  summary: ExecutiveSummary;
  businessUnitRisk: BusinessUnitRisk[];
}

const TenantContext = createContext<TenantContextValue | null>(null);

export function TenantProvider({ children }: { children: ReactNode }) {
  const value = useMemo<TenantContextValue>(() => {
    const data = generateTenant();
    const findings = computeFindings(data);
    const pillars = computePillarScores(findings);
    return {
      data,
      findings,
      pillars,
      summary: computeExecutiveSummary(data, findings, pillars),
      businessUnitRisk: computeBusinessUnitRisk(data),
    };
  }, []);

  return <TenantContext.Provider value={value}>{children}</TenantContext.Provider>;
}

export function useTenant(): TenantContextValue {
  const ctx = useContext(TenantContext);
  if (!ctx) throw new Error('useTenant must be used inside a TenantProvider');
  return ctx;
}
