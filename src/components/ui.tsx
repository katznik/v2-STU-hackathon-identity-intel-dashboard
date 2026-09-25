import type { ReactNode } from 'react';
import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react';
import type { Severity } from '../domain/types';

export const SEVERITY_STYLE: Record<Severity, { text: string; border: string; bg: string; dot: string; label: string }> = {
  critical: { text: 'text-sev-critical', border: 'border-sev-critical/40', bg: 'bg-sev-critical/10', dot: 'bg-sev-critical', label: 'Critical' },
  high: { text: 'text-sev-high', border: 'border-sev-high/40', bg: 'bg-sev-high/10', dot: 'bg-sev-high', label: 'High' },
  medium: { text: 'text-sev-medium', border: 'border-sev-medium/40', bg: 'bg-sev-medium/10', dot: 'bg-sev-medium', label: 'Medium' },
  low: { text: 'text-sev-low', border: 'border-sev-low/40', bg: 'bg-sev-low/10', dot: 'bg-sev-low', label: 'Low' },
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEVERITY_STYLE[severity];
  return (
    <span className={`chip ${s.text} ${s.border} ${s.bg}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  );
}

export function scoreColor(score: number): string {
  if (score >= 85) return 'text-good';
  if (score >= 70) return 'text-sev-medium';
  if (score >= 55) return 'text-sev-high';
  return 'text-sev-critical';
}

export function scoreHex(score: number): string {
  if (score >= 85) return '#34d399';
  if (score >= 70) return '#f5c451';
  if (score >= 55) return '#ff8a3d';
  return '#f2385a';
}

export function Panel({
  title,
  subtitle,
  action,
  children,
  className = '',
  bodyClassName = 'p-5',
}: {
  title?: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {title && (
        <header className="panel-header">
          <div>
            <h2 className="text-sm font-semibold tracking-wide text-slate-100">{title}</h2>
            {subtitle && <p className="mt-1 max-w-2xl text-xs leading-relaxed text-slate-400">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}

export function Kpi({
  label,
  value,
  sublabel,
  delta,
  deltaGoodDirection = 'down',
  tone = 'neutral',
  icon,
}: {
  label: string;
  value: string | number;
  sublabel?: string;
  delta?: number;
  deltaGoodDirection?: 'up' | 'down';
  tone?: 'neutral' | 'good' | 'warn' | 'bad';
  icon?: ReactNode;
}) {
  const toneRing = {
    neutral: 'border-white/8',
    good: 'border-good/25',
    warn: 'border-sev-high/25',
    bad: 'border-sev-critical/30',
  }[tone];

  const toneText = {
    neutral: 'text-slate-100',
    good: 'text-good',
    warn: 'text-sev-high',
    bad: 'text-sev-critical',
  }[tone];

  const isGood = delta === undefined ? null : deltaGoodDirection === 'down' ? delta <= 0 : delta >= 0;

  return (
    <div className={`rounded-xl border ${toneRing} bg-white/[0.025] p-4`}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">{label}</span>
        {icon && <span className="text-slate-500">{icon}</span>}
      </div>
      <div className="mt-2 flex items-baseline gap-2">
        <span className={`text-2xl font-semibold tabular-nums ${toneText}`}>{value}</span>
        {delta !== undefined && (
          <span className={`inline-flex items-center gap-0.5 text-xs font-medium ${isGood ? 'text-good' : 'text-sev-high'}`}>
            {delta === 0 ? <Minus size={12} /> : delta > 0 ? <ArrowUpRight size={12} /> : <ArrowDownRight size={12} />}
            {Math.abs(delta)}
          </span>
        )}
      </div>
      {sublabel && <p className="mt-1.5 text-xs leading-snug text-slate-400">{sublabel}</p>}
    </div>
  );
}

export function ProgressBar({ value, tone }: { value: number; tone?: string }) {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/8">
      <div
        className="h-full rounded-full transition-all"
        style={{ width: `${Math.min(100, Math.max(0, value))}%`, background: tone ?? scoreHex(value) }}
      />
    </div>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-6 border-b border-white/8 pb-6">
      <div className="max-w-3xl">
        <p className="text-[11px] font-semibold uppercase tracking-[0.18em] text-accent-400">{eyebrow}</p>
        <h1 className="mt-2 text-2xl font-semibold tracking-tight text-white">{title}</h1>
        <p className="mt-2 text-sm leading-relaxed text-slate-400">{description}</p>
      </div>
      {children}
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return <p className="px-5 py-10 text-center text-sm text-slate-500">{message}</p>;
}

export const CHART_TOOLTIP_STYLE = {
  background: 'rgba(11, 17, 32, 0.96)',
  border: '1px solid rgba(255,255,255,0.1)',
  borderRadius: '10px',
  fontSize: '12px',
  color: '#e2e8f0',
  boxShadow: '0 12px 32px rgba(0,0,0,0.45)',
} as const;
