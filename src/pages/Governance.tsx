import { Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { ClipboardCheck, FileWarning, PackageOpen, Stamp } from 'lucide-react';
import { useTenant } from '../lib/TenantContext';
import { computeGovernanceMetrics } from '../analytics/metrics';
import { formatDate, formatNumber } from '../analytics/helpers';
import { CHART_TOOLTIP_STYLE, Kpi, PageHeader, Panel, ProgressBar, scoreColor } from '../components/ui';
import FindingCard from '../components/FindingCard';

const STATUS_COLORS: Record<string, string> = {
  completed: '#34d399',
  'in-progress': '#56b6ff',
  overdue: '#f2385a',
  'not-started': '#64748b',
};

export default function Governance() {
  const { data, findings, pillars } = useTenant();
  const pillar = pillars.find((p) => p.pillar === 'governance')!;
  const pillarFindings = findings.filter((f) => f.pillar === 'governance');
  const metrics = computeGovernanceMetrics(data);

  const statusMix = (['completed', 'in-progress', 'overdue', 'not-started'] as const).map((status) => ({
    name: status,
    key: status,
    value: data.accessReviews.filter((r) => r.status === status).length,
  }));

  const packageData = data.accessPackages
    .slice()
    .sort((a, b) => b.activeAssignments - a.activeAssignments)
    .slice(0, 12)
    .map((p) => ({ name: p.displayName, Active: p.activeAssignments, Pending: p.pendingRequests }));

  const problemReviews = data.accessReviews
    .filter((r) => r.status === 'overdue' || r.status === 'not-started' || r.rubberStampRate > 0.85 || r.reviewerType === 'self')
    .slice(0, 25);

  const ownerlessGroups = data.groups.filter((g) => g.ownerIds.length === 0).slice(0, 20);

  return (
    <div className="space-y-7">
      <PageHeader eyebrow="Pillar · Access Governance" title="Is access actually governed?" description={pillar.description}>
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
          label="Review decision completion"
          value={`${metrics.reviewCompletionRate}%`}
          sublabel={`${metrics.overdue} overdue and ${metrics.notStarted} never started`}
          tone={metrics.reviewCompletionRate >= 90 ? 'good' : 'warn'}
          icon={<ClipboardCheck size={15} />}
        />
        <Kpi
          label="Rubber-stamp rate"
          value={`${metrics.avgRubberStamp}%`}
          sublabel="Decisions approved with no change — review theatre, not assurance"
          tone="bad"
          icon={<Stamp size={15} />}
        />
        <Kpi
          label="Entitlement-governed groups"
          value={`${metrics.governedGroupPct}%`}
          sublabel={`${metrics.ownerlessGroups} groups have no owner at all`}
          tone="warn"
          icon={<PackageOpen size={15} />}
        />
        <Kpi
          label="Packages without expiry"
          value={metrics.packagesWithoutExpiry}
          sublabel={`${metrics.packagesWithoutApproval} also grant access with no approval step`}
          tone="warn"
          icon={<FileWarning size={15} />}
        />
      </div>

      <div className="grid gap-5 xl:grid-cols-[1fr_1.3fr]">
        <Panel
          title="Access review campaign status"
          subtitle="An overdue or unstarted review is a control failure that is already visible to your auditor."
        >
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie data={statusMix} dataKey="value" nameKey="name" innerRadius={60} outerRadius={102} paddingAngle={2}>
                {statusMix.map((entry) => (
                  <Cell key={entry.key} fill={STATUS_COLORS[entry.key]} />
                ))}
              </Pie>
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
            </PieChart>
          </ResponsiveContainer>
        </Panel>

        <Panel
          title="Entitlement package demand"
          subtitle="Active assignments versus requests waiting on an approver. Large pending queues push people toward informal, ungoverned access routes."
        >
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={packageData} layout="vertical" margin={{ left: 70, right: 24, top: 4, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="name" width={200} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Legend wrapperStyle={{ fontSize: 11, color: '#94a3b8' }} />
              <Bar dataKey="Active" stackId="a" fill="#2f97ec" barSize={14} />
              <Bar dataKey="Pending" stackId="a" fill="#f5c451" radius={[0, 4, 4, 0]} barSize={14} />
            </BarChart>
          </ResponsiveContainer>
        </Panel>
      </div>

      <Panel
        title="Reviews that are not providing assurance"
        subtitle="Overdue, unstarted, self-reviewed or rubber-stamped campaigns. Self-review in particular means the person benefiting from the access is the one approving it."
        bodyClassName="p-0"
      >
        <div className="max-h-[440px] overflow-y-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Campaign</th>
                <th>Scope</th>
                <th>Reviewer</th>
                <th>Status</th>
                <th>Due</th>
                <th className="text-right">Decisions</th>
                <th className="text-right">Rubber-stamp</th>
              </tr>
            </thead>
            <tbody>
              {problemReviews.map((review) => (
                <tr key={review.id}>
                  <td>
                    <span className="font-medium text-slate-200">{review.displayName}</span>
                    <span className="block text-[11px] text-slate-500">{review.recurrence}</span>
                  </td>
                  <td className="text-xs text-slate-400">
                    {review.scopeType} · {review.scopeName}
                  </td>
                  <td className={`text-xs ${review.reviewerType === 'self' ? 'text-sev-critical' : 'text-slate-400'}`}>
                    {review.reviewerType}
                  </td>
                  <td>
                    <span style={{ color: STATUS_COLORS[review.status] }}>{review.status}</span>
                  </td>
                  <td className="text-xs text-slate-400">{formatDate(review.dueDateTime)}</td>
                  <td className="text-right tabular-nums">
                    {formatNumber(review.decisionsMade)}/{formatNumber(review.decisionsTotal)}
                  </td>
                  <td className={`text-right tabular-nums ${review.rubberStampRate > 0.85 ? 'text-sev-high' : 'text-slate-400'}`}>
                    {Math.round(review.rubberStampRate * 100)}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel
        title="Groups without an accountable owner"
        subtitle="Ownerless groups cannot be reviewed, cannot be certified and quietly accumulate members forever."
        bodyClassName="p-0"
      >
        <div className="max-h-[320px] overflow-y-auto">
          <table className="data-table">
            <thead>
              <tr>
                <th>Group</th>
                <th>Type</th>
                <th>Membership</th>
                <th className="text-right">Members</th>
                <th>Grants privilege</th>
                <th>Last reviewed</th>
              </tr>
            </thead>
            <tbody>
              {ownerlessGroups.map((group) => (
                <tr key={group.id}>
                  <td className="font-medium text-slate-200">{group.displayName}</td>
                  <td className="text-xs text-slate-400">{group.groupType}</td>
                  <td className="text-xs text-slate-400">{group.membershipRule}</td>
                  <td className="text-right tabular-nums">{formatNumber(group.memberIds.length)}</td>
                  <td className={group.grantsPrivilegedAccess ? 'text-sev-critical' : 'text-slate-500'}>
                    {group.grantsPrivilegedAccess ? 'Yes' : 'No'}
                  </td>
                  <td className="text-xs text-slate-400">{formatDate(group.lastReviewedDateTime)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel
        title={`Governance findings (${pillarFindings.length})`}
        subtitle="Detections covering review quality, entitlement design, group ownership and joiner-mover-leaver hygiene."
        bodyClassName="space-y-3 p-5"
      >
        {pillarFindings.map((finding) => (
          <FindingCard key={finding.id} finding={finding} />
        ))}
      </Panel>
    </div>
  );
}
