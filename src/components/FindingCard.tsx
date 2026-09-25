import { useState } from 'react';
import type { ReactNode } from 'react';
import { ChevronDown, Gauge, Lightbulb, ScrollText, Target, Wrench } from 'lucide-react';
import type { Finding } from '../domain/types';
import { PILLAR_META } from '../analytics/metrics';
import { formatNumber } from '../analytics/helpers';
import { SEVERITY_STYLE, SeverityBadge } from './ui';

const EFFORT_LABEL = { low: 'Low effort', medium: 'Medium effort', high: 'High effort' } as const;

export default function FindingCard({ finding, defaultOpen = false }: { finding: Finding; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const style = SEVERITY_STYLE[finding.severity];

  return (
    <article className={`panel overflow-hidden border-l-2 ${style.border}`}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-4 px-5 py-4 text-left transition hover:bg-white/[0.03]"
      >
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[11px] text-slate-500">{finding.id}</span>
            <SeverityBadge severity={finding.severity} />
            <span className="chip border-white/10 bg-white/5 text-slate-400">{PILLAR_META[finding.pillar].short}</span>
            <span className="chip border-white/10 bg-white/5 text-slate-400">{EFFORT_LABEL[finding.effort]}</span>
          </div>
          <h3 className="mt-2 text-[15px] font-semibold text-slate-100">{finding.title}</h3>
          <p className="mt-1.5 line-clamp-2 text-xs leading-relaxed text-slate-400">{finding.evidence}</p>
        </div>

        <div className="flex shrink-0 items-center gap-5">
          <div className="text-right">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Affected</p>
            <p className="text-base font-semibold tabular-nums text-slate-200">{formatNumber(finding.affectedCount)}</p>
          </div>
          <div className="text-right">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Risk</p>
            <p className={`text-base font-semibold tabular-nums ${style.text}`}>{finding.riskScore}</p>
          </div>
          <ChevronDown size={16} className={`text-slate-500 transition-transform ${open ? 'rotate-180' : ''}`} />
        </div>
      </button>

      {open && (
        <div className="space-y-5 border-t border-white/8 px-5 py-5">
          <div className="grid gap-5 lg:grid-cols-2">
            <Section icon={<Target size={14} />} title="Why this matters to the business">
              {finding.businessImpact}
            </Section>
            <Section icon={<Gauge size={14} />} title="Evidence from the tenant">
              {finding.evidence}
            </Section>
            <Section icon={<Lightbulb size={14} />} title="Recommended action">
              {finding.recommendation}
            </Section>
            <Section icon={<ScrollText size={14} />} title="Control mapping">
              <div className="mt-1 flex flex-wrap gap-1.5">
                {finding.frameworks.map((f) => (
                  <span key={f} className="chip border-accent-400/25 bg-accent-500/10 text-accent-400 normal-case">
                    {f}
                  </span>
                ))}
                <span className="chip border-white/10 bg-white/5 text-slate-400">
                  <Wrench size={11} /> {EFFORT_LABEL[finding.effort]}
                </span>
              </div>
            </Section>
          </div>

          {finding.affectedEntities.length > 0 && (
            <div>
              <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                Affected entities — showing {Math.min(finding.affectedEntities.length, 60)} of{' '}
                {formatNumber(finding.affectedCount)}
              </p>
              <div className="max-h-72 overflow-y-auto rounded-lg border border-white/8">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th className="w-1/3">Entity</th>
                      <th>Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {finding.affectedEntities.map((entity, i) => (
                      <tr key={`${entity.id}-${i}`}>
                        <td className="font-medium text-slate-200">{entity.name}</td>
                        <td className="text-xs text-slate-400">{entity.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </article>
  );
}

function Section({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <div className="rounded-lg border border-white/8 bg-white/[0.02] p-4">
      <p className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
        {icon}
        {title}
      </p>
      <div className="mt-2 text-[13px] leading-relaxed text-slate-300">{children}</div>
    </div>
  );
}
