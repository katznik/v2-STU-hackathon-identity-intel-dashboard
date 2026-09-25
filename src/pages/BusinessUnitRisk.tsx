import { useMemo, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from 'recharts';
import { useTenant } from '../lib/TenantContext';
import { formatNumber, pct } from '../analytics/helpers';
import { CHART_TOOLTIP_STYLE, Kpi, PageHeader, Panel, ProgressBar, scoreColor, scoreHex } from '../components/ui';

const CRITICALITY_LABEL: Record<string, string> = {
  'tier-1': 'Tier 1 — business critical',
  'tier-2': 'Tier 2 — important',
  'tier-3': 'Tier 3 — supporting',
};

export default function BusinessUnitRiskPage() {
  const { data, businessUnitRisk } = useTenant();
  const [selectedId, setSelectedId] = useState(businessUnitRisk[0]?.id ?? '');

  const selected = businessUnitRisk.find((b) => b.id === selectedId) ?? businessUnitRisk[0];
  const selectedUnit = data.businessUnits.find((b) => b.id === selected?.id);

  const worst = businessUnitRisk[0];
  const best = businessUnitRisk[businessUnitRisk.length - 1];
  const tier1Average = useMemo(() => {
    const tier1 = businessUnitRisk.filter((b) => b.criticality === 'tier-1');
    return tier1.length ? Math.round(tier1.reduce((s, b) => s + b.riskScore, 0) / tier1.length) : 0;
  }, [businessUnitRisk]);

  const scatterData = businessUnitRisk.map((b) => ({
    name: b.name,
    x: pct(b.privilegedCount, Math.max(b.headcount, 1)),
    y: pct(b.riskyUserCount + b.noMfaCount, Math.max(b.headcount, 1)),
    z: b.headcount,
    score: b.riskScore,
  }));

  const selectedBreakdown = selected
    ? [
        { label: 'No MFA registered', value: selected.noMfaCount },
        { label: 'Compromise signals', value: selected.riskyUserCount },
        { label: 'Dormant 90+ days', value: selected.dormantCount },
        { label: 'Privileged users', value: selected.privilegedCount },
        { label: 'External guests', value: selected.guestCount },
      ]
    : [];

  return (
    <div className="space-y-7">
      <PageHeader
        eyebrow="Accountability"
        title="Identity risk by business unit"
        description="Security debt is rarely evenly distributed. This view attributes identity risk to the parts of the business that own the people, the budget and the decision — weighted by how critical each unit is to operations."
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Highest-risk unit" value={worst?.name ?? '—'} sublabel={`Score ${worst?.riskScore} · grade ${worst?.grade}`} tone="bad" />
        <Kpi label="Strongest unit" value={best?.name ?? '—'} sublabel={`Score ${best?.riskScore} · grade ${best?.grade}`} tone="good" />
        <Kpi
          label="Tier-1 average score"
          value={tier1Average}
          sublabel="Business-critical units, where exposure costs the most"
          tone={tier1Average >= 80 ? 'good' : 'warn'}
        />
        <Kpi
          label="Units below grade C"
          value={businessUnitRisk.filter((b) => b.riskScore < 70).length}
          sublabel={`of ${businessUnitRisk.length} units require a remediation owner`}
          tone="warn"
        />
      </div>

      <Panel
        title="Risk league table"
        subtitle="Ordered worst to best. Select a row to break down the drivers behind the score."
        bodyClassName="p-0"
      >
        <table className="data-table">
          <thead>
            <tr>
              <th>Business unit</th>
              <th>Criticality</th>
              <th className="text-right">Headcount</th>
              <th className="text-right">No MFA</th>
              <th className="text-right">At risk</th>
              <th className="text-right">Dormant</th>
              <th className="text-right">Privileged</th>
              <th className="text-right">Guests</th>
              <th className="w-40">Score</th>
            </tr>
          </thead>
          <tbody>
            {businessUnitRisk.map((unit) => (
              <tr
                key={unit.id}
                onClick={() => setSelectedId(unit.id)}
                className={`cursor-pointer ${unit.id === selected?.id ? 'bg-accent-500/10' : ''}`}
              >
                <td className="font-medium text-slate-200">{unit.name}</td>
                <td className="text-xs text-slate-400">{CRITICALITY_LABEL[unit.criticality]}</td>
                <td className="text-right tabular-nums">{formatNumber(unit.headcount)}</td>
                <td className="text-right tabular-nums text-sev-medium">{unit.noMfaCount}</td>
                <td className="text-right tabular-nums text-sev-critical">{unit.riskyUserCount}</td>
                <td className="text-right tabular-nums">{unit.dormantCount}</td>
                <td className="text-right tabular-nums">{unit.privilegedCount}</td>
                <td className="text-right tabular-nums">{unit.guestCount}</td>
                <td>
                  <div className="flex items-center gap-2">
                    <span className={`w-10 text-right text-xs font-semibold tabular-nums ${scoreColor(unit.riskScore)}`}>
                      {unit.riskScore} {unit.grade}
                    </span>
                    <div className="flex-1">
                      <ProgressBar value={unit.riskScore} />
                    </div>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>

      <div className="grid gap-5 xl:grid-cols-2">
        <Panel
          title="Privilege density vs exposed population"
          subtitle="Units in the upper-right combine a high share of administrative power with a high share of weakly protected or compromised accounts — the most dangerous combination in the estate. Bubble size is headcount."
        >
          <ResponsiveContainer width="100%" height={300}>
            <ScatterChart margin={{ top: 12, right: 20, bottom: 16, left: -8 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis
                type="number"
                dataKey="x"
                name="Privileged %"
                unit="%"
                tickLine={false}
                axisLine={false}
                label={{ value: 'Privileged share of unit (%)', position: 'insideBottom', offset: -8, fill: '#64748b', fontSize: 11 }}
              />
              <YAxis type="number" dataKey="y" name="Exposed %" unit="%" tickLine={false} axisLine={false} />
              <ZAxis type="number" dataKey="z" range={[60, 420]} name="Headcount" />
              <Tooltip
                cursor={{ strokeDasharray: '3 3' }}
                content={({ payload }) => {
                  const point = payload?.[0]?.payload as (typeof scatterData)[number] | undefined;
                  if (!point) return null;
                  return (
                    <div style={CHART_TOOLTIP_STYLE} className="px-3 py-2">
                      <p className="font-semibold text-slate-100">{point.name}</p>
                      <p>Privileged: {point.x}%</p>
                      <p>Exposed accounts: {point.y}%</p>
                      <p>Headcount: {formatNumber(point.z)}</p>
                      <p>Score: {point.score}</p>
                    </div>
                  );
                }}
              />
              <Scatter data={scatterData} name="Business units">
                {scatterData.map((entry) => (
                  <Cell key={entry.name} fill={scoreHex(entry.score)} fillOpacity={0.75} />
                ))}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
        </Panel>

        <Panel
          title={selected ? `${selected.name} — risk drivers` : 'Risk drivers'}
          subtitle={
            selectedUnit
              ? `${CRITICALITY_LABEL[selectedUnit.criticality]} · ${selectedUnit.region} · executive owner ${selectedUnit.executiveOwner}`
              : 'Select a business unit from the table.'
          }
        >
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={selectedBreakdown} layout="vertical" margin={{ left: 60, right: 24, top: 4, bottom: 4 }}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} />
              <XAxis type="number" tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="label" width={150} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={CHART_TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              <Bar dataKey="value" name="Accounts" fill="#2f97ec" radius={[0, 4, 4, 0]} barSize={20} />
            </BarChart>
          </ResponsiveContainer>
          {selected && (
            <p className="mt-3 border-t border-white/8 pt-3 text-xs leading-relaxed text-slate-400">
              {selected.riskyUserCount > 0
                ? `${selected.riskyUserCount} accounts in this unit currently carry unresolved compromise signals. `
                : 'No accounts in this unit currently carry unresolved compromise signals. '}
              {selected.noMfaCount > 0
                ? `${selected.noMfaCount} have no MFA registered at all, which is where remediation should start.`
                : 'MFA registration is complete across the unit.'}
            </p>
          )}
        </Panel>
      </div>
    </div>
  );
}
