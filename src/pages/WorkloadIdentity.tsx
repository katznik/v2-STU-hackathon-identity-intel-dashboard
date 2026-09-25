import { Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Bot, KeySquare, ShieldAlert, Timer } from 'lucide-react';
import { useTenant } from '../lib/TenantContext';
import { computeWorkloadMetrics } from '../analytics/metrics';
import { daysSince, daysUntil, formatDate, formatNumber } from '../analytics/helpers';
import { CHART_TOOLTIP_STYLE, Kpi, PageHeader, Panel, ProgressBar, scoreColor } from '../components/ui';
import FindingCard from '../components/FindingCard';

const SENSITIVITY_COLORS: Record<string, string> = {
  restricted: '#f2385a',
  confidential: '#ff8a3d',
  internal: '#56b6ff',
  public: '#475569',
};

export default function WorkloadIdentity() {
  const { data, findings, pillars } = useTenant();
  const pillar = pillars.find((p) => p.pillar === 'workload-identity')!;
  const pillarFindings = findings.filter((f) => f.pillar === 'workload-identity');
  const metrics = computeWorkloadMetrics(data);

  const credentialBuckets = [
    { name: 'Already expired', key: 'expired', value: 0, color: '#f2385a' },
    { name: 'Expires < 30 days', key: 'soon', value: 0, color: '#ff8a3d' },
    { name: '30–90 days', key: 'mid', value: 0, color: '#f5c451' },
    { name: '90+ days', key: 'far', value: 0, color: '#34d399' },
  ];
  for (const app of data.applications) {
    for (const cred of app.credentials) {
      if (cred.type === 'federated') continue;
      const days = daysUntil(cred.expiryDateTime);
      if (days < 0) credentialBuckets[0].value += 1;
      else if (days < 30) credentialBuckets[1].value += 1;
      else if (days < 90) credentialBuckets[2].value += 1;
      else credentialBuckets[3].value += 1;
    }
  }

  const sensitivityMix = (['restricted', 'confidential', 'internal', 'public'] as const).map((level) => ({
    name: level,
    key: level,
    value: data.applications.filter((a) => a.dataSensitivity === level).length,
  }));

  const highPrivilegeApps = data.applications
    .map((app) => ({
      app,
      highPerms: app.grantedPermissions.filter((p) => p.isHighPrivilege),
    }))
    .filter((row) => row.highPerms.length > 0)
    .sort((a, b) => b.highPerms.length - a.highPerms.length)
    .slice(0, 25);

  const expiringApps = data.applications
    .flatMap((app) =>
      app.credentials
        .filter((c) => c.type !== 'federated' && daysUntil(c.expiryDateTime) < 30)
        .map((c) => ({ app, cred: c, days: Math.round(daysUntil(c.expiryDateTime)) })),
    )
    .sort((a, b) => a.days - b.days)
    .slice(0, 25);

  return (
    <div className="space-y-7">
      <PageHeader eyebrow="Pillar · Workload Identity" title="The identities nobody owns" description={pillar.description}>
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
          label="Application identities"
          value={formatNumber(metrics.totalApps)}
          sublabel={`${metrics.workloadIdentities} run unattended · only ${metrics.managedIdentities} use managed identity`}
          icon={<Bot size={15} />}
        />
        <Kpi
          label="High-privilege consent"
          value={metrics.highPrivilegeApps}
          sublabel={`${metrics.unusedHighPrivilege} have never exercised the permission they were granted`}
          tone="bad"
          icon={<ShieldAlert size={15} />}
        />
        <Kpi
          label="Credentials expired or expiring"
          value={metrics.expiredCreds + metrics.expiringSoon}
          sublabel={`${metrics.expiredCreds} already expired · ${metrics.expiringSoon} within 30 days`}
          tone="warn"
          icon={<Timer size={15} />}
        />
        <Kpi
          label="Unowned applications"
          value={metrics.unownedApps}
          sublabel={`${metrics.staleApps} have not authenticated in 90 days`}
          tone="warn"
          icon={<KeySquare size={15} />}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel
          title="Credential expiry horizon"
          subtitle="Secrets and certificates that lapse without warning are the most common cause of unplanned integration outages — and long-lived ones are the most common cause of silent workload compromise."
        >
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={credentialBuckets} margin={{ top: 8, right: 16, left: -18, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="name" tickLine={false} axisLine={false} />
              <YAxis tickLine={false} axisLine={false} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Bar dataKey="value" name="Credentials" radius={[4, 4, 0, 0]} barSize={48}>
                {credentialBuckets.map((entry) => (
                  <Cell key={entry.key} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </Panel>

        <Panel
          title="Applications by data sensitivity"
          subtitle="Restricted-data applications deserve certificate or managed-identity authentication and a named owner without exception."
        >
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={sensitivityMix} dataKey="value" nameKey="name" innerRadius={55} outerRadius={95} paddingAngle={2}>
                {sensitivityMix.map((entry) => (
                  <Cell key={entry.key} fill={SENSITIVITY_COLORS[entry.key]} />
                ))}
              </Pie>
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
            </PieChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      <Panel
        title="Applications holding tenant-wide permissions"
        subtitle="Application-type consent runs with no signed-in user and is unaffected by Conditional Access. A single compromised secret on any of these is equivalent to an administrator breach."
        bodyClassName="p-0"
      >
        <div className="max-h-[440px] overflow-y-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Application</th>
                <th>Category</th>
                <th>Sensitivity</th>
                <th>High-privilege permissions</th>
                <th>Owner</th>
                <th>Last sign-in</th>
              </tr>
            </thead>
            <tbody>
              {highPrivilegeApps.map(({ app, highPerms }) => (
                <tr key={app.id}>
                  <td>
                    <span className="font-medium text-slate-200">{app.displayName}</span>
                    <span className="block font-mono text-[10px] text-slate-500">{app.appId}</span>
                  </td>
                  <td className="text-xs text-slate-400">{app.category}</td>
                  <td style={{ color: SENSITIVITY_COLORS[app.dataSensitivity] }} className="text-xs">
                    {app.dataSensitivity}
                  </td>
                  <td className="text-xs text-slate-400">{highPerms.map((p) => p.value).join(', ')}</td>
                  <td className={app.ownerIds.length === 0 ? 'text-sev-critical' : 'text-slate-400'}>
                    {app.ownerIds.length === 0 ? 'None' : `${app.ownerIds.length} owner(s)`}
                  </td>
                  <td className="text-xs text-slate-400">
                    {formatDate(app.lastSignInDateTime)}
                    {app.lastSignInDateTime && daysSince(app.lastSignInDateTime) > 90 && (
                      <span className="ml-1 text-sev-high">stale</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel
        title="Credentials requiring rotation now"
        subtitle="Ordered by urgency. Negative values are already expired — those integrations are either broken or being kept alive by a second credential nobody tracked."
        bodyClassName="p-0"
      >
        <div className="max-h-[360px] overflow-y-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Application</th>
                <th>Credential</th>
                <th>Type</th>
                <th>Expires</th>
                <th className="text-right">Days</th>
              </tr>
            </thead>
            <tbody>
              {expiringApps.map(({ app, cred, days }) => (
                <tr key={cred.id}>
                  <td className="font-medium text-slate-200">{app.displayName}</td>
                  <td className="text-xs text-slate-400">{cred.displayName}</td>
                  <td className="text-xs text-slate-400">{cred.type}</td>
                  <td className="text-xs text-slate-400">{formatDate(cred.expiryDateTime)}</td>
                  <td className={`text-right tabular-nums ${days < 0 ? 'text-sev-critical' : 'text-sev-high'}`}>{days}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel
        title={`Workload identity findings (${pillarFindings.length})`}
        subtitle="Detections covering consent, credential hygiene, ownership and application lifecycle."
        bodyClassName="space-y-3 p-5"
      >
        {pillarFindings.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </Panel>
    </div>
  );
}
