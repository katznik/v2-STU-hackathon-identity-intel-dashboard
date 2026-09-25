import { Link } from 'react-router-dom';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  PolarAngleAxis,
  PolarGrid,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Building2,
  Coins,
  KeyRound,
  UserX,
  Users,
} from 'lucide-react';
import { useTenant } from '../lib/TenantContext';
import { computeAuthMix, computeRoadmap, PILLAR_META } from '../analytics/metrics';
import { formatCurrency, formatNumber } from '../analytics/helpers';
import { CHART_TOOLTIP_STYLE, Kpi, PageHeader, Panel, ProgressBar, scoreColor, scoreHex } from '../components/ui';
import FindingCard from '../components/FindingCard';

const AUTH_COLORS: Record<string, string> = {
  'phishing-resistant': '#34d399',
  'strong-mfa': '#56b6ff',
  'weak-mfa': '#f5c451',
  'password-only': '#f2385a',
};

export default function ExecutiveOverview() {
  const { data, summary, pillars, findings, businessUnitRisk } = useTenant();
  const authMix = computeAuthMix(data);
  const roadmap = computeRoadmap(findings).slice(0, 3);
  const topFindings = findings.slice(0, 4);
  const worstUnits = businessUnitRisk.slice(0, 6);

  const radarData = pillars.map((p) => ({ pillar: PILLAR_META[p.pillar].short, score: p.score, target: 88 }));

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Leadership briefing"
        title="Identity posture at a glance"
        description={`${data.tenant.displayName} runs ${formatNumber(data.tenant.employeeCount)} employee identities, ${formatNumber(summary.guestCount)} external guests and ${data.applications.length} application identities. This view translates that estate into the handful of decisions leadership actually needs to make.`}
      >
        <div className="rounded-xl border border-white/8 bg-white/[0.03] px-6 py-4 text-center">
          <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Identity Risk Index</p>
          <p className={`mt-1 text-4xl font-semibold tabular-nums ${scoreColor(summary.riskIndex)}`}>{summary.riskIndex}</p>
          <p className="mt-0.5 text-xs text-slate-400">Grade {summary.grade} · target 88+</p>
          <div className="mt-3 w-40">
            <ProgressBar value={summary.riskIndex} />
          </div>
        </div>
      </PageHeader>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi
          label="Critical exposures"
          value={summary.criticalFindings}
          sublabel={`${summary.highFindings} high-severity findings behind them`}
          tone="bad"
          icon={<AlertTriangle size={15} />}
        />
        <Kpi
          label="Standing tier-0 admin"
          value={summary.standingTier0}
          sublabel="Permanent Global Admin-class access, always live"
          tone="bad"
          icon={<KeyRound size={15} />}
        />
        <Kpi
          label="Phishing-resistant coverage"
          value={`${summary.phishingResistantCoverage}%`}
          sublabel={`${summary.mfaCoverage}% have any MFA · ${formatNumber(summary.legacyAuthUsers)} still using legacy auth`}
          tone={summary.phishingResistantCoverage > 60 ? 'good' : 'warn'}
          icon={<BadgeCheck size={15} />}
        />
        <Kpi
          label="Reclaimable licence spend"
          value={formatCurrency(summary.reclaimableLicenceSpend)}
          sublabel={`${formatNumber(summary.dormantAccounts)} dormant accounts holding licences, annualised`}
          tone="good"
          icon={<Coins size={15} />}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.35fr_1fr]">
        <Panel
          title="Risk trajectory"
          subtitle="Identity Risk Index and open critical exposures over the last 12 months. The index blends all five posture pillars, weighted toward the factors that drive real breach outcomes."
        >
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={summary.riskTrend} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
              <defs>
                <linearGradient id="indexFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#2f97ec" stopOpacity={0.45} />
                  <stop offset="100%" stopColor="#2f97ec" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="month" tickLine={false} axisLine={false} />
              <YAxis yAxisId="left" domain={[0, 100]} tickLine={false} axisLine={false} />
              <YAxis yAxisId="right" orientation="right" tickLine={false} axisLine={false} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} cursor={{ stroke: 'rgba(255,255,255,0.15)' }} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
              <Area
                yAxisId="left"
                type="monotone"
                dataKey="index"
                name="Risk index"
                stroke="#2f97ec"
                strokeWidth={2}
                fill="url(#indexFill)"
              />
              <Line
                yAxisId="right"
                type="monotone"
                dataKey="critical"
                name="Critical findings"
                stroke="#f2385a"
                strokeWidth={2}
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </Panel>

        <Panel
          title="Posture by pillar"
          subtitle="Where the programme is strong and where it is structurally weak, scored against an 88-point maturity target."
        >
          <ResponsiveContainer width="100%" height={280}>
            <RadarChart data={radarData} outerRadius="72%">
              <PolarGrid stroke="rgba(255,255,255,0.1)" />
              <PolarAngleAxis dataKey="pillar" />
              <Radar name="Target" dataKey="target" stroke="#475569" fill="#475569" fillOpacity={0.12} />
              <Radar name="Current" dataKey="score" stroke="#2f97ec" fill="#2f97ec" fillOpacity={0.3} strokeWidth={2} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
            </RadarChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      <Panel
        title="Pillar scorecard"
        subtitle="Each pillar aggregates its detections weighted by severity and how much of the estate is exposed."
        bodyClassName="grid gap-4 p-5 md:grid-cols-2 xl:grid-cols-5"
      >
        {pillars.map((pillar) => (
          <div key={pillar.pillar} className="rounded-lg border border-white/8 bg-white/[0.02] p-4">
            <div className="flex items-start justify-between gap-2">
              <p className="text-[13px] font-semibold text-slate-100">{pillar.label}</p>
              <span className={`text-xl font-semibold tabular-nums ${scoreColor(pillar.score)}`}>{pillar.grade}</span>
            </div>
            <p className={`mt-1 text-2xl font-semibold tabular-nums ${scoreColor(pillar.score)}`}>{pillar.score}</p>
            <div className="mt-2">
              <ProgressBar value={pillar.score} />
            </div>
            <p className="mt-3 text-[11px] leading-relaxed text-slate-400">{pillar.description}</p>
            <p className="mt-3 text-[11px] text-slate-500">
              {pillar.findingCount} findings
              {pillar.criticalCount > 0 && <span className="text-sev-critical"> · {pillar.criticalCount} critical</span>}
            </p>
          </div>
        ))}
      </Panel>

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel
          title="Authentication strength distribution"
          subtitle="The single strongest predictor of account takeover. Everything below the green band is phishable."
        >
          <ResponsiveContainer width="100%" height={230}>
            <BarChart data={authMix} layout="vertical" margin={{ left: 60, right: 24, top: 4, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="label" width={150} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Bar dataKey="value" name="Accounts" radius={[0, 4, 4, 0]} barSize={22}>
                {authMix.map((entry) => (
                  <Cell key={entry.key} fill={AUTH_COLORS[entry.key]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Panel>

        <Panel
          title="Business unit risk ranking"
          subtitle="Weighted by MFA gaps, compromise signals, dormancy, privilege density and business criticality."
          action={
            <Link to="/business-units" className="flex items-center gap-1 text-xs font-medium text-accent-400 hover:text-accent-300">
              Full view <ArrowRight size={13} />
            </Link>
          }
          bodyClassName="p-0"
        >
          <div className="overflow-hidden">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Business unit</th>
                  <th className="text-right">People</th>
                  <th className="text-right">Privileged</th>
                  <th className="text-right">At risk</th>
                  <th className="w-36">Score</th>
                </tr>
              </thead>
              <tbody>
                {worstUnits.map((unit) => (
                  <tr key={unit.id}>
                    <td>
                      <span className="font-medium text-slate-200">{unit.name}</span>
                      <span className="ml-2 text-[10px] uppercase tracking-wider text-slate-500">{unit.criticality}</span>
                    </td>
                    <td className="text-right tabular-nums">{formatNumber(unit.headcount)}</td>
                    <td className="text-right tabular-nums">{unit.privilegedCount}</td>
                    <td className="text-right tabular-nums text-sev-high">{unit.riskyUserCount}</td>
                    <td>
                      <div className="flex items-center gap-2">
                        <span className={`w-7 text-right text-xs font-semibold tabular-nums ${scoreColor(unit.riskScore)}`}>
                          {unit.riskScore}
                        </span>
                        <div className="flex-1">
                          <ProgressBar value={unit.riskScore} tone={scoreHex(unit.riskScore)} />
                        </div>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi
          label="Accounts showing compromise signals"
          value={formatNumber(summary.peopleAtRisk)}
          sublabel="Medium or high Identity Protection risk, unremediated"
          tone="bad"
          icon={<UserX size={15} />}
        />
        <Kpi
          label="External guests"
          value={formatNumber(summary.guestCount)}
          sublabel={`${summary.ungovernedGuestPct}% have no accountable sponsor`}
          tone="warn"
          icon={<Users size={15} />}
        />
        <Kpi
          label="Overdue access reviews"
          value={summary.overdueReviews}
          sublabel="Control failures visible to audit today"
          tone="warn"
          icon={<Building2 size={15} />}
        />
        <Kpi
          label="Credentials expiring < 30 days"
          value={summary.expiringCredentials}
          sublabel="Unplanned integration outage risk"
          tone="warn"
          icon={<KeyRound size={15} />}
        />
      </div>

      <Panel
        title="Highest-impact exposures"
        subtitle="Ranked by inherent severity combined with the share of the estate exposed. Expand any finding for the evidence, the business consequence and the recommended action."
        action={
          <Link to="/findings" className="flex items-center gap-1 text-xs font-medium text-accent-400 hover:text-accent-300">
            All {findings.length} findings <ArrowRight size={13} />
          </Link>
        }
        bodyClassName="space-y-3 p-5"
      >
        {topFindings.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </Panel>

      <Panel
        title="Where to start"
        subtitle="The three actions with the highest risk reduction per unit of effort. These are deliberately achievable within one quarter."
        action={
          <Link to="/roadmap" className="flex items-center gap-1 text-xs font-medium text-accent-400 hover:text-accent-300">
            Full roadmap <ArrowRight size={13} />
          </Link>
        }
        bodyClassName="grid gap-4 p-5 lg:grid-cols-3"
      >
        {roadmap.map((item, index) => (
          <div key={item.finding.id} className="rounded-lg border border-white/8 bg-white/[0.02] p-4">
            <div className="flex items-center justify-between">
              <span className="grid h-6 w-6 place-items-center rounded-full bg-accent-500/15 text-xs font-semibold text-accent-400">
                {index + 1}
              </span>
              <span className="text-[11px] font-medium text-slate-500">{item.horizon}</span>
            </div>
            <p className="mt-3 text-sm font-semibold leading-snug text-slate-100">{item.finding.title}</p>
            <p className="mt-2 text-xs leading-relaxed text-slate-400">{item.finding.recommendation}</p>
            <div className="mt-3 flex items-center justify-between text-[11px] text-slate-500">
              <span>{formatNumber(item.finding.affectedCount)} affected</span>
              <span className="font-semibold text-accent-400">impact score {item.impactScore}</span>
            </div>
          </div>
        ))}
      </Panel>
    </div>
  );
}
