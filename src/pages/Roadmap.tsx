import { useMemo } from 'react';
import { CalendarClock, CalendarRange, Zap } from 'lucide-react';
import { useTenant } from '../lib/TenantContext';
import { computeRoadmap, PILLAR_META, type RoadmapItem } from '../analytics/metrics';
import { formatNumber } from '../analytics/helpers';
import { Kpi, PageHeader, Panel, SeverityBadge } from '../components/ui';

const HORIZONS: { key: RoadmapItem['horizon']; blurb: string; icon: typeof Zap }[] = [
  {
    key: 'Now (0–30 days)',
    blurb: 'Low-effort, high-impact changes that can be delivered by the existing team inside a single sprint. These are the actions to commit to at the next steering meeting.',
    icon: Zap,
  },
  {
    key: 'Next (1–3 months)',
    blurb: 'Requires coordination with application or business owners, but no new platform investment. Schedule these into the current quarter.',
    icon: CalendarClock,
  },
  {
    key: 'Later (3–12 months)',
    blurb: 'Structural work — process redesign, licensing, architecture or migration. These belong in the annual plan with a named programme owner.',
    icon: CalendarRange,
  },
];

export default function Roadmap() {
  const { findings } = useTenant();
  const roadmap = useMemo(() => computeRoadmap(findings), [findings]);

  const grouped = HORIZONS.map((h) => ({ ...h, items: roadmap.filter((i) => i.horizon === h.key) }));
  const quickWins = grouped[0].items;

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Remediation plan"
        title="Sequenced identity improvement roadmap"
        description="Every open finding is scored for risk reduction per unit of delivery effort, then placed into a horizon. The result is a defensible order of work: fix what is cheap and dangerous first, and plan the structural changes deliberately rather than reactively."
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Actions identified" value={roadmap.length} sublabel="Across all five posture pillars" />
        <Kpi label="Quick wins (0–30 days)" value={quickWins.length} sublabel="Low effort, high risk reduction" tone="good" />
        <Kpi
          label="Risk points addressable now"
          value={Math.round(quickWins.reduce((s, i) => s + i.finding.riskScore, 0))}
          sublabel="Cumulative risk score removable this month"
          tone="good"
        />
        <Kpi
          label="Identities touched"
          value={formatNumber(roadmap.reduce((s, i) => s + i.finding.affectedCount, 0))}
          sublabel="Total affected principals across the plan"
        />
      </div>

      {grouped.map((group) => {
        const Icon = group.icon;
        return (
          <Panel
            key={group.key}
            title={group.key}
            subtitle={group.blurb}
            action={<span className="chip border-white/10 bg-white/5 text-slate-400">{group.items.length} actions</span>}
            bodyClassName="p-0"
          >
            {group.items.length === 0 ? (
              <p className="px-5 py-10 text-center text-sm text-slate-500">Nothing sequenced into this horizon.</p>
            ) : (
              <ol className="divide-y divide-white/8">
                {group.items.map((item, index) => (
                  <li key={item.finding.id} className="flex flex-wrap items-start gap-4 px-5 py-4">
                    <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-full bg-accent-500/15 text-xs font-semibold text-accent-400">
                      <Icon size={13} />
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[11px] text-slate-500">{item.finding.id}</span>
                        <SeverityBadge severity={item.finding.severity} />
                        <span className="chip border-white/10 bg-white/5 text-slate-400">
                          {PILLAR_META[item.finding.pillar].short}
                        </span>
                      </div>
                      <p className="mt-1.5 text-sm font-semibold text-slate-100">
                        {index + 1}. {item.finding.title}
                      </p>
                      <p className="mt-1 text-xs leading-relaxed text-slate-400">{item.finding.recommendation}</p>
                      <p className="mt-1.5 text-[11px] text-slate-500">{item.finding.businessImpact}</p>
                    </div>
                    <div className="flex shrink-0 gap-6 text-right">
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Affected</p>
                        <p className="text-sm font-semibold tabular-nums text-slate-200">
                          {formatNumber(item.finding.affectedCount)}
                        </p>
                      </div>
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Effort</p>
                        <p className="text-sm font-semibold capitalize text-slate-200">{item.finding.effort}</p>
                      </div>
                      <div>
                        <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Impact/effort</p>
                        <p className="text-sm font-semibold tabular-nums text-accent-400">{item.impactScore}</p>
                      </div>
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </Panel>
        );
      })}
    </div>
  );
}
