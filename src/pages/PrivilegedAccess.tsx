import { Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Clock, KeyRound, ShieldCheck, Users } from 'lucide-react';
import { useTenant } from '../lib/TenantContext';
import { computeRoleDistribution } from '../analytics/metrics';
import { formatNumber, pct, resolvePrivilegedUserIds, roleTierOf } from '../analytics/helpers';
import { CHART_TOOLTIP_STYLE, Kpi, PageHeader, Panel, ProgressBar, scoreColor } from '../components/ui';
import FindingCard from '../components/FindingCard';

const TIER_COLORS: Record<string, string> = { 'tier-0': '#f2385a', 'tier-1': '#ff8a3d', 'tier-2': '#56b6ff' };

const TIER_LABEL: Record<string, string> = {
  'tier-0': 'Tier 0 — tenant control plane',
  'tier-1': 'Tier 1 — service & data control',
  'tier-2': 'Tier 2 — operational',
};

export default function PrivilegedAccess() {
  const { data, findings, pillars } = useTenant();
  const pillar = pillars.find((p) => p.pillar === 'privileged-access')!;
  const pillarFindings = findings.filter((f) => f.pillar === 'privileged-access');

  const distribution = computeRoleDistribution(data);
  const assignments = data.roleAssignments;
  const privilegedUserIds = resolvePrivilegedUserIds(data);
  const userById = new Map(data.users.map((u) => [u.id, u]));

  const activeCount = assignments.filter((a) => a.assignmentType === 'active').length;
  const eligibleCount = assignments.filter((a) => a.assignmentType === 'eligible').length;
  const permanentTier0 = assignments.filter(
    (a) => a.isPermanent && a.assignmentType === 'active' && roleTierOf(data, a.roleId) === 'tier-0',
  );
  const neverActivated = assignments.filter((a) => a.assignmentType === 'eligible' && a.activationCount90d === 0).length;
  const noMfaOnActivation = assignments.filter((a) => !a.requiresMfaOnActivation).length;

  const tierMix = (['tier-0', 'tier-1', 'tier-2'] as const).map((tier) => ({
    name: TIER_LABEL[tier],
    key: tier,
    value: assignments.filter((a) => roleTierOf(data, a.roleId) === tier).length,
  }));

  const jitData = distribution
    .slice(0, 12)
    .map((r) => ({ role: r.role, Active: r.active, Eligible: r.eligible }));

  const weakAdmins = [...privilegedUserIds]
    .map((id) => userById.get(id))
    .filter((u): u is NonNullable<typeof u> => Boolean(u) && u!.accountEnabled)
    .filter((u) => u.authStrength !== 'phishing-resistant')
    .slice(0, 25);

  return (
    <div className="space-y-7">
      <PageHeader eyebrow="Pillar · Privileged Access" title="Who can change the tenant" description={pillar.description}>
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
          label="Standing tier-0 assignments"
          value={permanentTier0.length}
          sublabel="Permanent control-plane access that never expires"
          tone="bad"
          icon={<KeyRound size={15} />}
        />
        <Kpi
          label="Just-in-time coverage"
          value={`${pct(eligibleCount, activeCount + eligibleCount)}%`}
          sublabel={`${formatNumber(eligibleCount)} eligible vs ${formatNumber(activeCount)} always-on assignments`}
          tone="warn"
          icon={<Clock size={15} />}
        />
        <Kpi
          label="Privileged people"
          value={formatNumber(privilegedUserIds.size)}
          sublabel={`${weakAdmins.length > 0 ? `${weakAdmins.length}+ without phishing-resistant auth` : 'All using phishing-resistant auth'}`}
          tone="warn"
          icon={<Users size={15} />}
        />
        <Kpi
          label="Unused eligible roles"
          value={neverActivated}
          sublabel="Never activated in 90 days — candidates for removal"
          tone="neutral"
          icon={<ShieldCheck size={15} />}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.35fr_1fr]">
        <Panel
          title="Standing vs just-in-time access by role"
          subtitle="Active assignments are permanently live privilege. Eligible assignments must be activated, are time-bound and leave an audit trail — they should dominate every tier-0 role."
        >
          <ResponsiveContainer width="100%" height={340}>
            <BarChart data={jitData} layout="vertical" margin={{ left: 70, right: 24, top: 4, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="role" width={185} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
              <Bar dataKey="Active" stackId="a" fill="#f2385a" barSize={16} />
              <Bar dataKey="Eligible" stackId="a" fill="#34d399" radius={[0, 4, 4, 0]} barSize={16} />
            </BarChart>
          </ResponsiveContainer>
        </Panel>

        <Panel
          title="Privilege by tier"
          subtitle="Mapped to the Microsoft Enterprise Access Model. Tier-0 compromise means tenant compromise."
        >
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie data={tierMix} dataKey="value" nameKey="name" innerRadius={60} outerRadius={102} paddingAngle={2}>
                {tierMix.map((entry) => (
                  <Cell key={entry.key} fill={TIER_COLORS[entry.key]} />
                ))}
              </Pie>
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
            </PieChart>
          </ResponsiveContainer>
          <p className="mt-2 border-t border-white/8 pt-3 text-xs leading-relaxed text-slate-400">
            {noMfaOnActivation} assignments can be activated or used without a fresh MFA challenge, meaning a stolen session
            token is enough to exercise them.
          </p>
        </Panel>
      </div>

      <Panel
        title="Directory role inventory"
        subtitle="Every role with its tier, assignment mix and governance controls. Service principal and group-based assignments are highlighted because they bypass human-centric review processes."
        bodyClassName="p-0"
      >
        <div className="max-h-[460px] overflow-y-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Role</th>
                <th>Tier</th>
                <th className="text-right">Active</th>
                <th className="text-right">Eligible</th>
                <th className="text-right">Permanent</th>
                <th className="text-right">Via group</th>
                <th className="text-right">Service principals</th>
                <th className="text-right">Never used</th>
              </tr>
            </thead>
            <tbody>
              {distribution.map((row) => (
                <tr key={row.role}>
                  <td>
                    <span className="font-medium text-slate-200">{row.role}</span>
                    <span className="block text-[11px] text-slate-500">{row.description}</span>
                  </td>
                  <td>
                    <span className="chip border-white/10 bg-white/5" style={{ color: TIER_COLORS[row.tier] }}>
                      {row.tier}
                    </span>
                  </td>
                  <td className="text-right tabular-nums text-sev-high">{row.active}</td>
                  <td className="text-right tabular-nums text-good">{row.eligible}</td>
                  <td className="text-right tabular-nums">{row.permanent}</td>
                  <td className="text-right tabular-nums">{row.groups}</td>
                  <td className="text-right tabular-nums">{row.servicePrincipals}</td>
                  <td className="text-right tabular-nums text-slate-500">{row.neverActivated}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel
        title="Administrators without phishing-resistant authentication"
        subtitle="These accounts hold directory privilege but can be phished with an adversary-in-the-middle kit. This is the single most valuable remediation list in the platform."
        bodyClassName="p-0"
      >
        <div className="max-h-[380px] overflow-y-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Administrator</th>
                <th>Job title</th>
                <th>Auth strength</th>
                <th>Registered methods</th>
              </tr>
            </thead>
            <tbody>
              {weakAdmins.map((user) => (
                <tr key={user.id}>
                  <td>
                    <span className="font-medium text-slate-200">{user.displayName}</span>
                    <span className="block text-[11px] text-slate-500">{user.userPrincipalName}</span>
                  </td>
                  <td className="text-xs text-slate-400">{user.jobTitle}</td>
                  <td className={user.authStrength === 'password-only' ? 'text-sev-critical' : 'text-sev-medium'}>
                    {user.authStrength}
                  </td>
                  <td className="text-xs text-slate-400">{user.registeredMethods.join(', ') || 'None'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel
        title={`Privileged access findings (${pillarFindings.length})`}
        subtitle="Detections covering standing privilege, activation controls, nested group privilege and administrator hygiene."
        bodyClassName="space-y-3 p-5"
      >
        {pillarFindings.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </Panel>
    </div>
  );
}
