import { Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { LifeBuoy, ServerCog, ShieldOff, SlidersHorizontal } from 'lucide-react';
import { useTenant } from '../lib/TenantContext';
import { computeResilienceMetrics } from '../analytics/metrics';
import { formatDate, formatNumber } from '../analytics/helpers';
import { CHART_TOOLTIP_STYLE, Kpi, PageHeader, Panel, ProgressBar, scoreColor } from '../components/ui';
import FindingCard from '../components/FindingCard';

const STATE_COLORS: Record<string, string> = {
  enabled: '#34d399',
  enabledForReportingButNotEnforced: '#f5c451',
  disabled: '#f2385a',
};

const STATE_LABEL: Record<string, string> = {
  enabled: 'Enforced',
  enabledForReportingButNotEnforced: 'Report-only',
  disabled: 'Disabled',
};

export default function Resilience() {
  const { data, findings, pillars } = useTenant();
  const pillar = pillars.find((p) => p.pillar === 'resilience')!;
  const pillarFindings = findings.filter((f) => f.pillar === 'resilience');
  const metrics = computeResilienceMetrics(data);

  const stateMix = (['enabled', 'enabledForReportingButNotEnforced', 'disabled'] as const).map((state) => ({
    name: STATE_LABEL[state],
    key: state,
    value: data.conditionalAccessPolicies.filter((p) => p.state === state).length,
  }));

  const exclusionData = data.conditionalAccessPolicies
    .slice()
    .sort((a, b) => b.excludedUserCount - a.excludedUserCount)
    .slice(0, 10)
    .map((p) => ({ name: p.displayName, Excluded: p.excludedUserCount }));

  const dependencies = [
    { name: 'No SSPR registered', value: metrics.ssprGap, hint: 'Cannot self-recover — helpdesk becomes the single point of failure' },
    { name: 'Telephony-dependent MFA', value: metrics.telephonyDependent, hint: 'SMS/voice fails with carrier outages and SIM swap' },
    { name: 'Synced from on-premises', value: Math.round((metrics.hybridDependency / 100) * data.users.filter((u) => u.accountEnabled).length), hint: 'Authentication availability tied to on-premises infrastructure' },
  ];

  return (
    <div className="space-y-7">
      <PageHeader eyebrow="Pillar · Policy & Resilience" title="Can the controls hold, and can you recover?" description={pillar.description}>
        <div className="rounded-xl border border-white/8 bg-white/[0.03] px-6 py-4 text-center">
          <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Pillar score</p>
          <p className={`mt-1 text-4xl font-semibold tabular-nums ${scoreColor(pillar.score)}`}>{pillar.score}</p>
          <p className="mt-0.5 text-xs text-slate-400">Grade {pillar.grade} · {pillar.findingCount} findings</p>
          <div className="mt-3 w-40">
            <ProgressBar value={pillar.score} />
          </div>
        </div>
      </PageHeader>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi
          label="Policies actually enforcing"
          value={`${metrics.enforced}/${metrics.totalPolicies}`}
          sublabel={`${metrics.reportOnly} report-only · ${metrics.disabled} disabled and providing no protection`}
          tone={metrics.disabled > 0 ? 'warn' : 'good'}
          icon={<SlidersHorizontal size={15} />}
        />
        <Kpi
          label="Policy exclusions"
          value={formatNumber(metrics.totalExclusions)}
          sublabel={`Across ${metrics.excludedGroups} excluded groups — every exclusion is a permanent bypass`}
          tone="bad"
          icon={<ShieldOff size={15} />}
        />
        <Kpi
          label="Sign-ins with no policy applied"
          value={`${metrics.uncoveredSignInPct}%`}
          sublabel={`${formatNumber(metrics.blockedSignIns)} sign-ins were blocked by policy in the period`}
          tone="warn"
          icon={<ServerCog size={15} />}
        />
        <Kpi
          label="Cannot self-recover"
          value={formatNumber(metrics.ssprGap)}
          sublabel="No self-service password reset registered"
          tone="warn"
          icon={<LifeBuoy size={15} />}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1fr_1.3fr]">
        <Panel
          title="Conditional Access policy state"
          subtitle="Report-only is a testing state, not a control. Policies left there indefinitely give the illusion of coverage."
        >
          <ResponsiveContainer width="100%" height={270}>
            <PieChart>
              <Pie data={stateMix} dataKey="value" nameKey="name" innerRadius={58} outerRadius={100} paddingAngle={2}>
                {stateMix.map((entry) => (
                  <Cell key={entry.key} fill={STATE_COLORS[entry.key]} />
                ))}
              </Pie>
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
            </PieChart>
          </ResponsiveContainer>
        </Panel>

        <Panel
          title="Largest policy exclusion sets"
          subtitle="Exclusions are usually added for one urgent reason and then never removed. Attackers look for exactly these gaps."
        >
          <ResponsiveContainer width="100%" height={270}>
            <BarChart data={exclusionData} layout="vertical" margin={{ left: 70, right: 24, top: 4, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="name" width={210} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Bar dataKey="Excluded" fill="#f2385a" radius={[0, 4, 4, 0]} barSize={16} />
            </BarChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      <Panel
        title="Conditional Access inventory"
        subtitle="The full policy set with its grant controls, exclusion count and last modification. Use this to spot policies that are stale, scoped too narrowly, or missing legacy-auth and device controls."
        bodyClassName="p-0"
      >
        <div className="max-h-[460px] overflow-y-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Policy</th>
                <th>State</th>
                <th>Targets</th>
                <th>Grant controls</th>
                <th className="text-right">Excluded users</th>
                <th className="text-right">Excluded groups</th>
                <th>Last modified</th>
              </tr>
            </thead>
            <tbody>
              {data.conditionalAccessPolicies.map((policy) => (
                <tr key={policy.id}>
                  <td>
                    <span className="font-medium text-slate-200">{policy.displayName}</span>
                    <span className="block text-[11px] text-slate-500">
                      {policy.blocksLegacyAuth && 'blocks legacy auth · '}
                      {policy.requiresPhishingResistant && 'phishing-resistant · '}
                      {policy.requiresCompliantDevice && 'compliant device'}
                    </span>
                  </td>
                  <td style={{ color: STATE_COLORS[policy.state] }} className="text-xs">
                    {STATE_LABEL[policy.state]}
                  </td>
                  <td className="text-xs text-slate-400">
                    {policy.includeUsers} · {policy.targetsAllApps ? 'all apps' : 'scoped apps'}
                  </td>
                  <td className="text-xs text-slate-400">{policy.grantControls.join(', ') || '—'}</td>
                  <td className={`text-right tabular-nums ${policy.excludedUserCount > 20 ? 'text-sev-high' : 'text-slate-400'}`}>
                    {policy.excludedUserCount}
                  </td>
                  <td className="text-right tabular-nums text-slate-400">{policy.excludedGroupIds.length}</td>
                  <td className="text-xs text-slate-400">{formatDate(policy.lastModifiedDateTime)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel
        title="Recovery dependencies"
        subtitle="What breaks if a core dependency fails. These populations determine how long an identity outage lasts and how much of it lands on the service desk."
        bodyClassName="grid gap-4 p-5 md:grid-cols-3"
      >
        {dependencies.map((dep) => (
          <div key={dep.name} className="rounded-lg border border-white/8 bg-white/[0.02] p-4">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">{dep.name}</p>
            <p className="mt-2 text-2xl font-semibold tabular-nums text-sev-high">{formatNumber(dep.value)}</p>
            <p className="mt-2 text-xs leading-relaxed text-slate-400">{dep.hint}</p>
          </div>
        ))}
      </Panel>

      <Panel
        title={`Resilience findings (${pillarFindings.length})`}
        subtitle="Detections covering policy coverage, exception sprawl, break-glass readiness and recovery capability."
        bodyClassName="space-y-3 p-5"
      >
        {pillarFindings.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </Panel>
    </div>
  );
}
