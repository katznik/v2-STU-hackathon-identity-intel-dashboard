import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Search } from 'lucide-react';
import { useTenant } from '../lib/TenantContext';
import { PILLAR_META } from '../analytics/metrics';
import type { Pillar, Severity } from '../domain/types';
import { formatNumber } from '../analytics/helpers';
import { EmptyState, PageHeader, Panel, SEVERITY_STYLE } from '../components/ui';
import FindingCard from '../components/FindingCard';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const PILLARS = Object.keys(PILLAR_META) as Pillar[];
type SortKey = 'risk' | 'affected' | 'effort';

const EFFORT_RANK = { low: 0, medium: 1, high: 2 } as const;

export default function Findings() {
  const { findings } = useTenant();
  const [pillar, setPillar] = useState<Pillar | 'all'>('all');
  const [severity, setSeverity] = useState<Severity | 'all'>('all');
  const [sort, setSort] = useState<SortKey>('risk');
  const [query, setQuery] = useState('');

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return findings
      .filter((f) => pillar === 'all' || f.pillar === pillar)
      .filter((f) => severity === 'all' || f.severity === severity)
      .filter(
        (f) =>
          !needle ||
          f.title.toLowerCase().includes(needle) ||
          f.id.toLowerCase().includes(needle) ||
          f.evidence.toLowerCase().includes(needle) ||
          f.recommendation.toLowerCase().includes(needle),
      )
      .slice()
      .sort((a, b) => {
        if (sort === 'affected') return b.affectedCount - a.affectedCount;
        if (sort === 'effort') return EFFORT_RANK[a.effort] - EFFORT_RANK[b.effort] || b.riskScore - a.riskScore;
        return b.riskScore - a.riskScore;
      });
  }, [findings, pillar, severity, sort, query]);

  const counts = useMemo(
    () => Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length])) as Record<Severity, number>,
    [findings],
  );

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Detection catalogue"
        title={`${findings.length} open identity findings`}
        description="Every detection the analytics engine produced across the tenant, with the evidence behind it, the business consequence, the recommended action and the control frameworks it maps to. Filter by pillar, severity or keyword, and expand any finding for the affected entities."
      />

      <Panel bodyClassName="flex flex-wrap items-center gap-3 p-4">
        <div className="flex items-center gap-2 rounded-lg border border-white/8 bg-white/[0.03] px-3 py-1.5">
          <Search size={14} className="text-slate-500" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search findings…"
            className="w-56 bg-transparent text-sm text-slate-200 outline-none placeholder:text-slate-500"
          />
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <FilterChip active={pillar === 'all'} onClick={() => setPillar('all')}>
            All pillars
          </FilterChip>
          {PILLARS.map((p) => (
            <FilterChip key={p} active={pillar === p} onClick={() => setPillar(p)}>
              {PILLAR_META[p].short}
            </FilterChip>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <FilterChip active={severity === 'all'} onClick={() => setSeverity('all')}>
            All severities
          </FilterChip>
          {SEVERITIES.map((s) => (
            <FilterChip key={s} active={severity === s} onClick={() => setSeverity(s)} className={SEVERITY_STYLE[s].text}>
              {SEVERITY_STYLE[s].label} ({counts[s]})
            </FilterChip>
          ))}
        </div>

        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-slate-500">Sort by</span>
          <select
            value={sort}
            onChange={(e) => setSort(e.target.value as SortKey)}
            className="rounded-lg border border-white/8 bg-ink-800 px-2.5 py-1.5 text-xs text-slate-200 outline-none"
          >
            <option value="risk">Risk score</option>
            <option value="affected">Affected identities</option>
            <option value="effort">Easiest to fix</option>
          </select>
        </div>
      </Panel>

      <p className="text-xs text-slate-500">
        Showing {visible.length} of {findings.length} findings ·{' '}
        {formatNumber(visible.reduce((s, f) => s + f.affectedCount, 0))} affected identities in the current selection
      </p>

      {visible.length === 0 ? (
        <Panel bodyClassName="p-0">
          <EmptyState message="No findings match the current filters." />
        </Panel>
      ) : (
        <div className="space-y-3">
          {visible.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))}
        </div>
      )}
    </div>
  );
}

function FilterChip({
  active,
  onClick,
  children,
  className = '',
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
  className?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-lg border px-2.5 py-1.5 text-xs font-medium transition ${
        active ? 'border-accent-400/40 bg-accent-500/15 text-accent-300' : `border-white/8 bg-white/[0.02] text-slate-400 hover:text-slate-200 ${className}`
      }`}
    >
      {children}
    </button>
  );
}
