# Identity Risk Intelligence

An identity intelligence platform that turns Microsoft Entra identity, access, and governance
data into decisions — for CISOs, identity architects, and the business leaders who own the risk.

It ships with a deterministic synthetic tenant (~1,850 users, 120 applications, 14 Conditional
Access policies, 9,000 sign-ins) so the whole product is explorable immediately, with no tenant,
credentials, or consent required.

## Run it

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # type-check + production bundle into dist/
npm run lint
```

The built app uses `HashRouter`, so `dist/index.html` also works when opened directly from disk.

## What it answers

| Route | Audience | Question it answers |
| --- | --- | --- |
| `/` Executive Overview | Board / CISO | How exposed are we, is it improving, and what are the three things to do next? |
| `/business-units` | Business leaders | Which parts of the organisation carry the risk, and why? |
| `/roadmap` | Programme owners | What is the sequenced Now / Next / Later plan, ranked by impact per unit of effort? |
| `/identity-risk` | SOC / IAM | Where is authentication weak and who is actively at risk? |
| `/privileged-access` | IAM architects | How much standing privilege exists, and is it protected? |
| `/governance` | GRC / audit | Are access reviews, entitlements, guests, and group ownership under control? |
| `/workload-identity` | App / platform teams | What can our service principals reach, and which credentials are about to fail? |
| `/resilience` | Identity operations | Would our Conditional Access estate survive an outage or a break-glass event? |
| `/findings` | Everyone | The full, filterable catalogue of detections with evidence and remediation. |

## Architecture

Four strictly separated layers. Each depends only on the one below it.

```
pages/ + components/     presentation — dashboards, charts, tables
        ↑
analytics/               intelligence — findings rules, scoring, aggregation
        ↑
domain/types.ts          Microsoft Graph-shaped entity model
        ↑
data/generateTenant.ts   deterministic synthetic tenant (swappable)
```

### `domain/`
Entity types deliberately mirror Microsoft Graph resources — `User`, `Group`,
`ServicePrincipal`, `AppRoleAssignment`, `DirectoryRole`, `UnifiedRoleAssignment`,
`ConditionalAccessPolicy`, `AccessReview`, `AccessPackage`, `SignIn`, `RiskDetection`.
Because the analytics layer only consumes these shapes, replacing the generator with real
Graph calls requires **no change to the intelligence or presentation layers**.

### `data/`
A seeded PRNG (`random.ts`) drives `generateTenant.ts`, so every run produces an identical
tenant — findings, scores, and charts are reproducible and safe to reason about. The generator
plants realistic pathologies on purpose: dormant privileged accounts, guests with no sponsor,
service principals holding `Directory.ReadWrite.All`, report-only Conditional Access policies,
expiring client secrets, overdue access reviews, and rubber-stamped review decisions.

### `analytics/`
- **`findings.ts`** — the core engine. 30+ deterministic detection rules across five pillars
  (`IR-*` identity risk, `PA-*` privileged access, `GV-*` governance, `WI-*` workload identity,
  `RS-*` resilience). Every finding carries severity, affected entities, quantified evidence,
  plain-English business impact, a recommendation, an effort estimate, and control-framework
  mappings (NIST CSF 2.0, ISO 27001, CIS, Microsoft ZT).
- **`metrics.ts`** — scoring and aggregation for every dashboard.
- **`helpers.ts`** — shared temporal and set utilities, anchored on a single `NOW` constant that
  must stay in sync with the generator's `now`.

## The scoring model

**Finding risk score** blends how bad a finding is with how much of the estate it touches:

```
riskScore = min(100, SEVERITY_WEIGHT × 0.6 + min(1, √exposureRatio) × 38)
```

Severity weights are critical 100 / high 72 / medium 44 / low 22. The square root on exposure
means the first slice of blast radius moves the number far more than the last — a critical
finding touching 2% of the tenant still outranks a medium one touching 40%.

**Pillar score** converts accumulated burden into a 0–100 health score with exponential decay:

```
burden = Σ (riskScore × severityMultiplier)     # 1.35 / 1.0 / 0.6 / 0.3
score  = 100 × e^(−burden / 1000)
```

Decay is used rather than a linear cap because linear scoring collapses every pillar to zero
once a realistic number of findings fire, destroying all comparability. Decay keeps pillars
separable at every burden level and honestly models diminishing marginal risk: the tenth
critical finding genuinely does add less new exposure than the first.

**Identity Risk Index** is the weighted mean of the five pillars:

| Pillar | Weight |
| --- | --- |
| Identity Risk | 0.28 |
| Privileged Access | 0.28 |
| Governance | 0.16 |
| Workload Identity | 0.16 |
| Resilience | 0.12 |

**Business-unit risk** is scored independently from per-capita exposure — unprotected accounts,
dormancy, active user risk, privilege density, and guest concentration — normalised by headcount
and multiplied by the unit's business criticality tier, so a 160-person unit is comparable to a
1,000-person one.

## Pointing it at a real tenant

Replace `generateTenant()` in `src/lib/TenantContext.tsx` with a loader that hydrates the same
`TenantData` shape from Microsoft Graph. The relevant read-only scopes are roughly
`User.Read.All`, `Group.Read.All`, `Application.Read.All`, `RoleManagement.Read.Directory`,
`Policy.Read.All`, `AccessReview.Read.All`, `EntitlementManagement.Read.All`,
`AuditLog.Read.All`, and `IdentityRiskEvent.Read.All`. Nothing above that layer changes.

## Stack

Vite · React 19 · TypeScript · Tailwind CSS v4 · Recharts · React Router · lucide-react.
No backend, no network calls, no telemetry — all computation happens in the browser.
