import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Fingerprint, ShieldAlert, UserMinus, UserPlus } from 'lucide-react';
import { useTenant } from '../lib/TenantContext';
import { computeAuthMix, computeSignInTrend } from '../analytics/metrics';
import { formatNumber, isDormant, pct } from '../analytics/helpers';
import { CHART_TOOLTIP_STYLE, Kpi, PageHeader, Panel, ProgressBar, scoreColor } from '../components/ui';
import FindingCard from '../components/FindingCard';

const AUTH_COLORS: Record<string, string> = {
  'phishing-resistant': '#34d399',
  'strong-mfa': '#56b6ff',
  'weak-mfa': '#f5c451',
  'password-only': '#f2385a',
};

const RISK_COLORS: Record<string, string> = { high: '#f2385a', medium: '#ff8a3d', low: '#f5c451', none: '#334155' };

export default function IdentityRisk() {
  const { data, findings, pillars } = useTenant();
  const pillar = pillars.find((p) => p.pillar === 'identity-risk')!;
  const pillarFindings = findings.filter((f) => f.pillar === 'identity-risk');

  const enabled = data.users.filter((u) => u.accountEnabled);
  const authMix = computeAuthMix(data);
  const trend = computeSignInTrend(data).slice().reverse();

  const riskMix = (['high', 'medium', 'low', 'none'] as const).map((level) => ({
    name: level === 'none' ? 'No risk signal' : `${level[0].toUpperCase()}${level.slice(1)} risk`,
    key: level,
    value: enabled.filter((u) => u.riskLevel === level).length,
  }));

  const detectionCounts = new Map<string, number>();
  for (const user of enabled) {
    for (const detection of user.riskDetections) {
      detectionCounts.set(detection, (detectionCounts.get(detection) ?? 0) + 1);
    }
  }
  const topDetections = [...detectionCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([name, value]) => ({ name, value }));

  const guests = enabled.filter((u) => u.userType === 'Guest');
  const dormant = enabled.filter((u) => isDormant(u));
  const riskyUsers = enabled
    .filter((u) => u.riskLevel === 'high' || u.riskLevel === 'medium')
    .sort((a, b) => (a.riskLevel === b.riskLevel ? b.riskDetections.length - a.riskDetections.length : a.riskLevel === 'high' ? -1 : 1))
    .slice(0, 25);

  const buName = new Map(data.businessUnits.map((b) => [b.id, b.name]));

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Pillar · Identity Risk"
        title="Human identity exposure"
        description={pillar.description}
      >
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
          label="Phishing-resistant accounts"
          value={`${pct(enabled.filter((u) => u.authStrength === 'phishing-resistant').length, enabled.length)}%`}
          sublabel="FIDO2, Windows Hello or certificate-based auth"
          tone="warn"
          icon={<Fingerprint size={15} />}
        />
        <Kpi
          label="Accounts with compromise signals"
          value={formatNumber(enabled.filter((u) => u.riskLevel === 'high' || u.riskLevel === 'medium').length)}
          sublabel="Identity Protection medium or high, unremediated"
          tone="bad"
          icon={<ShieldAlert size={15} />}
        />
        <Kpi
          label="Dormant accounts"
          value={formatNumber(dormant.length)}
          sublabel="Enabled but no sign-in for 90+ days — free attack surface"
          tone="warn"
          icon={<UserMinus size={15} />}
        />
        <Kpi
          label="External guests"
          value={formatNumber(guests.length)}
          sublabel={`${guests.filter((g) => !g.sponsorId).length} without an accountable internal sponsor`}
          tone="warn"
          icon={<UserPlus size={15} />}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1.3fr_1fr]">
        <Panel
          title="Sign-in health over 90 days"
          subtitle="Weekly sign-in volume against risky, failed and legacy-protocol authentications. Legacy auth cannot be protected by modern Conditional Access controls."
        >
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={trend} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="label" tickLine={false} axisLine={false} />
              <YAxis tickLine={false} axisLine={false} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} cursor={{ stroke: 'rgba(255,255,255,0.15)' }} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
              <Line type="monotone" dataKey="total" name="Sign-ins" stroke="#56b6ff" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="risky" name="Risky" stroke="#f2385a" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="failed" name="Failed" stroke="#ff8a3d" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="legacy" name="Legacy auth" stroke="#f5c451" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </Panel>

        <Panel
          title="Identity Protection risk distribution"
          subtitle="How much of the workforce is currently flagged by Entra risk detection."
        >
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie data={riskMix} dataKey="value" nameKey="name" innerRadius={62} outerRadius={104} paddingAngle={2}>
                {riskMix.map((entry) => (
                  <Cell key={entry.key} fill={RISK_COLORS[entry.key]} />
                ))}
              </Pie>
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
            </PieChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel
          title="Authentication strength"
          subtitle="Anything that is not phishing-resistant can be defeated by a real-time proxy phishing kit."
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

        <Panel title="Most common risk detections" subtitle="The attack techniques actually landing against this tenant.">
          <ResponsiveContainer width="100%" height={230}>
            <BarChart data={topDetections} layout="vertical" margin={{ left: 60, right: 24, top: 4, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="name" width={160} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Bar dataKey="value" name="Accounts" fill="#f2385a" radius={[0, 4, 4, 0]} barSize={16} />
            </BarChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      <Panel
        title="Accounts requiring immediate attention"
        subtitle="Highest-risk identities with unresolved detections. In a live tenant these are the accounts to force password reset and re-registration on today."
        bodyClassName="p-0"
      >
        <div className="max-h-[420px] overflow-y-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>User</th>
                <th>Business unit</th>
                <th>Risk</th>
                <th>Auth strength</th>
                <th>Detections</th>
              </tr>
            </thead>
            <tbody>
              {riskyUsers.map((user) => (
                <tr key={user.id}>
                  <td>
                    <span className="font-medium text-slate-200">{user.displayName}</span>
                    <span className="block text-[11px] text-slate-500">{user.userPrincipalName}</span>
                  </td>
                  <td className="text-xs text-slate-400">{buName.get(user.businessUnitId) ?? user.department}</td>
                  <td>
                    <span className={user.riskLevel === 'high' ? 'text-sev-critical' : 'text-sev-high'}>
                      {user.riskLevel}
                    </span>
                  </td>
                  <td className="text-xs text-slate-400">{user.authStrength}</td>
                  <td className="text-xs text-slate-400">{user.riskDetections.join(', ') || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel
        title={`Identity risk findings (${pillarFindings.length})`}
        subtitle="Explainable detections with evidence, business consequence and a recommended action."
        bodyClassName="space-y-3 p-5"
      >
        {pillarFindings.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </Panel>
    </div>
  );
}
