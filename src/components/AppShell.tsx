import { NavLink, Outlet } from 'react-router-dom';
import {
  Activity,
  AppWindow,
  Building2,
  ClipboardCheck,
  KeyRound,
  LayoutDashboard,
  ListChecks,
  ShieldCheck,
  ShieldHalf,
} from 'lucide-react';
import { useTenant } from '../lib/TenantContext';
import { scoreColor } from './ui';

const NAV = [
  { to: '/', label: 'Executive Overview', icon: LayoutDashboard, end: true, group: 'Leadership' },
  { to: '/business-units', label: 'Business Unit Risk', icon: Building2, group: 'Leadership' },
  { to: '/roadmap', label: 'Remediation Roadmap', icon: ListChecks, group: 'Leadership' },
  { to: '/identity-risk', label: 'Identity Risk', icon: ShieldHalf, group: 'Analysis' },
  { to: '/privileged-access', label: 'Privileged Access', icon: KeyRound, group: 'Analysis' },
  { to: '/governance', label: 'Access Governance', icon: ClipboardCheck, group: 'Analysis' },
  { to: '/workload-identity', label: 'Workload Identity', icon: AppWindow, group: 'Analysis' },
  { to: '/resilience', label: 'Policy & Resilience', icon: ShieldCheck, group: 'Analysis' },
  { to: '/findings', label: 'All Findings', icon: Activity, group: 'Analysis' },
];

export default function AppShell() {
  const { data, summary } = useTenant();
  const groups = [...new Set(NAV.map((n) => n.group))];

  return (
    <div className="flex h-full min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-white/8 bg-ink-950/70 backdrop-blur lg:flex">
        <div className="flex items-center gap-3 border-b border-white/8 px-5 py-5">
          <div className="grid h-9 w-9 place-items-center rounded-lg bg-gradient-to-br from-accent-400 to-accent-600 shadow-lg shadow-accent-600/20">
            <ShieldHalf size={19} className="text-ink-950" />
          </div>
          <div className="leading-tight">
            <p className="text-sm font-semibold text-white">Identity Intelligence</p>
            <p className="text-[11px] text-slate-500">Entra Risk &amp; Governance</p>
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto px-3 py-4">
          {groups.map((group) => (
            <div key={group} className="mb-5">
              <p className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-600">{group}</p>
              <div className="space-y-0.5">
                {NAV.filter((n) => n.group === group).map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    end={item.end}
                    className={({ isActive }) =>
                      `flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] font-medium transition ${
                        isActive
                          ? 'bg-accent-500/12 text-accent-400 shadow-[inset_2px_0_0_0] shadow-accent-400'
                          : 'text-slate-400 hover:bg-white/5 hover:text-slate-100'
                      }`
                    }
                  >
                    <item.icon size={16} />
                    {item.label}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-white/8 px-5 py-4">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-600">Tenant</p>
          <p className="mt-1 truncate text-sm font-medium text-slate-200">{data.tenant.displayName}</p>
          <p className="mt-0.5 text-[11px] text-slate-500">{data.tenant.industry}</p>
          <p className="mt-2 font-mono text-[10px] text-slate-600">{data.tenant.tenantId}</p>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 flex flex-wrap items-center justify-between gap-4 border-b border-white/8 bg-ink-950/80 px-6 py-3 backdrop-blur-lg">
          <div className="flex items-center gap-3 lg:hidden">
            <ShieldHalf size={18} className="text-accent-400" />
            <span className="text-sm font-semibold text-white">Identity Intelligence</span>
          </div>
          <div className="hidden text-xs text-slate-500 lg:block">
            Analysis window: last 90 days · {new Intl.NumberFormat('en-US').format(data.signIns.length)} sign-in events ·
            {' '}{new Intl.NumberFormat('en-US').format(data.users.length)} identities
          </div>
          <div className="flex items-center gap-5">
            <div className="text-right">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Identity Risk Index</p>
              <p className={`text-lg font-semibold leading-tight tabular-nums ${scoreColor(summary.riskIndex)}`}>
                {summary.riskIndex}
                <span className="ml-1 text-xs font-normal text-slate-500">/100 · {summary.grade}</span>
              </p>
            </div>
            <div className="h-9 w-px bg-white/10" />
            <div className="text-right">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Open Findings</p>
              <p className="text-lg font-semibold leading-tight tabular-nums text-slate-100">
                {summary.totalFindings}
                <span className="ml-1 text-xs font-normal text-sev-critical">{summary.criticalFindings} critical</span>
              </p>
            </div>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1500px] flex-1 px-6 py-7">
          <Outlet />
        </main>

        <footer className="border-t border-white/8 px-6 py-4 text-[11px] text-slate-600">
          Synthetic demonstration tenant. Entity shapes mirror Microsoft Graph so the analytics layer can be pointed at live
          Entra ID data without modification.
        </footer>
      </div>
    </div>
  );
}
