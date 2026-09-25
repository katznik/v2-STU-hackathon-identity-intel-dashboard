import type { Finding, Pillar, PillarScore, TenantDataset } from '../domain/types';
import { daysSince, daysUntil, gradeFor, isDormant, pct, roleTierOf, trendTo } from './helpers';

export const PILLAR_META: Record<Pillar, { label: string; short: string; description: string }> = {
  'identity-risk': {
    label: 'Identity Risk',
    short: 'Identity',
    description: 'Exposure of human identities — authentication strength, compromise signals, dormancy and external access.',
  },
  'privileged-access': {
    label: 'Privileged Access',
    short: 'Privilege',
    description: 'Concentration and control of administrative power across users, groups and workload identities.',
  },
  governance: {
    label: 'Access Governance',
    short: 'Governance',
    description: 'Whether access is requested, approved, time-bound, owned and genuinely reviewed.',
  },
  'workload-identity': {
    label: 'Workload Identity',
    short: 'Workload',
    description: 'Applications and service principals: credentials, consent, ownership and lifecycle.',
  },
  resilience: {
    label: 'Policy & Resilience',
    short: 'Resilience',
    description: 'Conditional Access coverage, exception sprawl and the ability to recover from identity failure.',
  },
};

/**
 * Pillar scores use exponential decay rather than a linear cap.
 *
 * Linear scoring drives any pillar with several serious findings straight to zero,
 * which destroys the ability to compare pillars or show improvement. Decay keeps the
 * score strictly positive, preserves ordering, and reflects the reality that the
 * tenth finding in a pillar adds less marginal risk than the first.
 */
const PILLAR_DECAY = 1000;

export function computePillarScores(findings: Finding[]): PillarScore[] {
  return (Object.keys(PILLAR_META) as Pillar[]).map((pillar, index) => {
    const pillarFindings = findings.filter((f) => f.pillar === pillar);
    const burden = pillarFindings.reduce((sum, f) => {
      const severityMultiplier = f.severity === 'critical' ? 1.35 : f.severity === 'high' ? 1 : f.severity === 'medium' ? 0.6 : 0.3;
      return sum + f.riskScore * severityMultiplier;
    }, 0);
    const score = Math.max(0, Math.min(100, Math.round(100 * Math.exp(-burden / PILLAR_DECAY))));
    return {
      pillar,
      label: PILLAR_META[pillar].label,
      description: PILLAR_META[pillar].description,
      score,
      grade: gradeFor(score),
      findingCount: pillarFindings.length,
      criticalCount: pillarFindings.filter((f) => f.severity === 'critical').length,
      trend: trendTo(score, index * 5.3 + 2, 12, -1.1),
    };
  });
}

export function computeIdentityRiskIndex(pillars: PillarScore[]): number {
  // Privileged access and identity risk dominate real-world breach outcomes.
  const weights: Record<Pillar, number> = {
    'identity-risk': 0.28,
    'privileged-access': 0.28,
    governance: 0.16,
    'workload-identity': 0.16,
    resilience: 0.12,
  };
  const weighted = pillars.reduce((sum, p) => sum + p.score * weights[p.pillar], 0);
  return Math.round(weighted);
}

export interface ExecutiveSummary {
  riskIndex: number;
  grade: string;
  criticalFindings: number;
  highFindings: number;
  totalFindings: number;
  peopleAtRisk: number;
  privilegedPrincipals: number;
  standingTier0: number;
  guestCount: number;
  ungovernedGuestPct: number;
  mfaCoverage: number;
  phishingResistantCoverage: number;
  dormantAccounts: number;
  reclaimableLicenceSpend: number;
  overdueReviews: number;
  expiringCredentials: number;
  legacyAuthUsers: number;
  riskTrend: { month: string; index: number; critical: number }[];
}

const MONTHS = ['Oct', 'Nov', 'Dec', 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep'];

export function computeExecutiveSummary(
  data: TenantDataset,
  findings: Finding[],
  pillars: PillarScore[],
): ExecutiveSummary {
  const riskIndex = computeIdentityRiskIndex(pillars);
  const enabled = data.users.filter((u) => u.accountEnabled);
  const guests = enabled.filter((u) => u.userType === 'Guest');
  const mfaCovered = enabled.filter((u) => u.mfaRegistered).length;
  const phishingResistant = enabled.filter((u) => u.authStrength === 'phishing-resistant').length;
  const dormant = enabled.filter((u) => isDormant(u));

  const licenceCostByKey = new Map(data.licenses.map((l) => [l.skuId, l.unitCostPerMonth]));
  const dormantSpend = data.licenses.reduce((sum, l) => sum + l.dormant * l.unitCostPerMonth, 0);
  const unassignedSpend = data.licenses.reduce((sum, l) => sum + Math.max(0, l.purchased - l.assigned) * l.unitCostPerMonth, 0);
  const dormantUserSpend = dormant.reduce(
    (sum, u) => sum + u.licenseSkus.reduce((s, sku) => s + (licenceCostByKey.get(sku) ?? 0), 0),
    0,
  );

  const legacyUsers = new Set(data.signIns.filter((s) => s.isLegacyAuth && s.status === 'success').map((s) => s.userId));

  const indexTrend = trendTo(riskIndex, 7.2, 12, -1.4);
  const criticalNow = findings.filter((f) => f.severity === 'critical').length;
  const criticalTrend = trendTo(criticalNow, 3.3, 12, 0.5);

  return {
    riskIndex,
    grade: gradeFor(riskIndex),
    criticalFindings: criticalNow,
    highFindings: findings.filter((f) => f.severity === 'high').length,
    totalFindings: findings.length,
    peopleAtRisk: enabled.filter((u) => u.riskLevel === 'high' || u.riskLevel === 'medium').length,
    privilegedPrincipals: new Set(data.roleAssignments.filter((a) => a.principalType === 'user').map((a) => a.principalId)).size,
    standingTier0: data.roleAssignments.filter(
      (a) => a.assignmentType === 'active' && a.isPermanent && roleTierOf(data, a.roleId) === 'tier-0',
    ).length,
    guestCount: guests.length,
    ungovernedGuestPct: pct(guests.filter((g) => !g.sponsorId || g.invitationState === 'pendingAcceptance').length, guests.length),
    mfaCoverage: pct(mfaCovered, enabled.length),
    phishingResistantCoverage: pct(phishingResistant, enabled.length),
    dormantAccounts: dormant.length,
    reclaimableLicenceSpend: Math.round((dormantSpend + unassignedSpend + dormantUserSpend) * 12),
    overdueReviews: data.accessReviews.filter((r) => r.status === 'overdue' || r.status === 'not-started').length,
    expiringCredentials: data.applications.reduce(
      (sum, a) => sum + a.credentials.filter((c) => c.type !== 'federated' && daysUntil(c.expiryDateTime) < 30).length,
      0,
    ),
    legacyAuthUsers: legacyUsers.size,
    riskTrend: MONTHS.map((month, i) => ({
      month,
      index: Math.round(indexTrend[i]),
      critical: Math.round(criticalTrend[i]),
    })),
  };
}

export interface BusinessUnitRisk {
  id: string;
  name: string;
  criticality: string;
  headcount: number;
  privilegedCount: number;
  noMfaCount: number;
  dormantCount: number;
  riskyUserCount: number;
  guestCount: number;
  riskScore: number;
  grade: string;
}

export function computeBusinessUnitRisk(data: TenantDataset): BusinessUnitRisk[] {
  const privileged = new Set(data.roleAssignments.filter((a) => a.principalType === 'user').map((a) => a.principalId));

  return data.businessUnits
    .map((bu) => {
      const people = data.users.filter((u) => u.businessUnitId === bu.id && u.accountEnabled);
      const total = Math.max(people.length, 1);
      const noMfa = people.filter((u) => !u.mfaRegistered).length;
      const dormant = people.filter((u) => isDormant(u)).length;
      const risky = people.filter((u) => u.riskLevel === 'high' || u.riskLevel === 'medium').length;
      const privilegedCount = people.filter((u) => privileged.has(u.id)).length;
      const guestCount = people.filter((u) => u.userType === 'Guest').length;

      // Weighted toward what is actually controllable and actually dangerous: missing MFA
      // and live compromise signals dominate. Privilege and guest density are contributing
      // factors rather than faults in themselves, so they carry a lighter weight.
      const penalty =
        (noMfa / total) * 115 +
        (dormant / total) * 45 +
        (risky / total) * 150 +
        (privilegedCount / total) * 45 +
        (guestCount / total) * 30;
      const criticalityMultiplier = bu.criticality === 'tier-1' ? 1.15 : bu.criticality === 'tier-2' ? 1 : 0.9;
      const score = Math.max(0, Math.min(100, Math.round(100 - penalty * criticalityMultiplier)));

      return {
        id: bu.id,
        name: bu.name,
        criticality: bu.criticality,
        headcount: people.length,
        privilegedCount,
        noMfaCount: noMfa,
        dormantCount: dormant,
        riskyUserCount: risky,
        guestCount,
        riskScore: score,
        grade: gradeFor(score),
      };
    })
    .sort((a, b) => a.riskScore - b.riskScore);
}

export function computeAuthMix(data: TenantDataset) {
  const enabled = data.users.filter((u) => u.accountEnabled);
  const labels: Record<string, string> = {
    'phishing-resistant': 'Phishing-resistant',
    'strong-mfa': 'Strong MFA (app)',
    'weak-mfa': 'Phishable MFA (SMS/voice)',
    'password-only': 'Password only',
  };
  return Object.entries(labels).map(([key, label]) => ({
    key,
    label,
    value: enabled.filter((u) => u.authStrength === key).length,
  }));
}

export function computeRoleDistribution(data: TenantDataset) {
  return data.roles
    .map((role) => {
      const assignments = data.roleAssignments.filter((a) => a.roleId === role.id);
      return {
        role: role.displayName,
        tier: role.tier,
        description: role.description,
        active: assignments.filter((a) => a.assignmentType === 'active').length,
        eligible: assignments.filter((a) => a.assignmentType === 'eligible').length,
        permanent: assignments.filter((a) => a.isPermanent).length,
        servicePrincipals: assignments.filter((a) => a.principalType === 'servicePrincipal').length,
        groups: assignments.filter((a) => a.principalType === 'group').length,
        neverActivated: assignments.filter((a) => a.assignmentType === 'eligible' && a.activationCount90d === 0).length,
      };
    })
    .sort((a, b) => b.active + b.eligible - (a.active + a.eligible));
}

export function computeSignInTrend(data: TenantDataset) {
  // Bucket 90 days of sign-ins into weeks.
  const buckets = new Map<number, { total: number; risky: number; failed: number; legacy: number; mfa: number }>();
  for (const signIn of data.signIns) {
    const week = Math.floor(daysSince(signIn.createdDateTime) / 7);
    if (week > 12) continue;
    const bucket = buckets.get(week) ?? { total: 0, risky: 0, failed: 0, legacy: 0, mfa: 0 };
    bucket.total += 1;
    if (signIn.riskLevel !== 'none') bucket.risky += 1;
    if (signIn.status === 'failure') bucket.failed += 1;
    if (signIn.isLegacyAuth) bucket.legacy += 1;
    if (signIn.mfaSatisfied) bucket.mfa += 1;
    buckets.set(week, bucket);
  }
  return [...buckets.entries()]
    .sort((a, b) => b[0] - a[0])
    .map(([week, b]) => ({
      label: week === 0 ? 'This week' : `-${week}w`,
      total: b.total,
      risky: b.risky,
      failed: b.failed,
      legacy: b.legacy,
      mfaCoverage: pct(b.mfa, b.total),
    }));
}

export function computeGovernanceMetrics(data: TenantDataset) {
  const reviews = data.accessReviews;
  const completed = reviews.filter((r) => r.status === 'completed');
  const decisionsTotal = reviews.reduce((s, r) => s + r.decisionsTotal, 0);
  const decisionsMade = reviews.reduce((s, r) => s + r.decisionsMade, 0);

  return {
    reviewCompletionRate: pct(decisionsMade, decisionsTotal),
    overdue: reviews.filter((r) => r.status === 'overdue').length,
    notStarted: reviews.filter((r) => r.status === 'not-started').length,
    inProgress: reviews.filter((r) => r.status === 'in-progress').length,
    completed: completed.length,
    avgRubberStamp: Math.round((reviews.reduce((s, r) => s + r.rubberStampRate, 0) / Math.max(reviews.length, 1)) * 100),
    selfReviewCount: reviews.filter((r) => r.reviewerType === 'self').length,
    governedGroupPct: pct(data.groups.filter((g) => g.isGovernedByAccessPackage).length, data.groups.length),
    ownerlessGroups: data.groups.filter((g) => g.ownerIds.length === 0).length,
    packagesWithoutExpiry: data.accessPackages.filter((p) => p.expirationDays === null).length,
    packagesWithoutApproval: data.accessPackages.filter((p) => !p.approvalRequired).length,
    pendingRequests: data.accessPackages.reduce((s, p) => s + p.pendingRequests, 0),
    activeAssignments: data.accessPackages.reduce((s, p) => s + p.activeAssignments, 0),
  };
}

export function computeWorkloadMetrics(data: TenantDataset) {
  const apps = data.applications;
  const creds = apps.flatMap((a) => a.credentials);
  return {
    totalApps: apps.length,
    workloadIdentities: apps.filter((a) => a.isWorkloadIdentity).length,
    managedIdentities: apps.filter((a) => a.usesManagedIdentity).length,
    secretBased: apps.filter((a) => a.credentials.some((c) => c.type === 'secret')).length,
    expiredCreds: creds.filter((c) => c.type !== 'federated' && daysUntil(c.expiryDateTime) < 0).length,
    expiringSoon: creds.filter((c) => c.type !== 'federated' && daysUntil(c.expiryDateTime) >= 0 && daysUntil(c.expiryDateTime) < 30).length,
    highPrivilegeApps: apps.filter((a) => a.grantedPermissions.some((p) => p.isHighPrivilege)).length,
    unusedHighPrivilege: apps.filter((a) => a.grantedPermissions.some((p) => p.isHighPrivilege && !p.lastUsedDateTime)).length,
    unownedApps: apps.filter((a) => a.ownerIds.length === 0).length,
    staleApps: apps.filter((a) => daysSince(a.lastSignInDateTime) > 90).length,
    restrictedDataApps: apps.filter((a) => a.dataSensitivity === 'restricted').length,
  };
}

export function computeResilienceMetrics(data: TenantDataset) {
  const policies = data.conditionalAccessPolicies;
  const signIns = data.signIns;
  return {
    totalPolicies: policies.length,
    enforced: policies.filter((p) => p.state === 'enabled').length,
    reportOnly: policies.filter((p) => p.state === 'enabledForReportingButNotEnforced').length,
    disabled: policies.filter((p) => p.state === 'disabled').length,
    totalExclusions: policies.reduce((s, p) => s + p.excludedUserCount, 0),
    excludedGroups: policies.reduce((s, p) => s + p.excludedGroupIds.length, 0),
    uncoveredSignInPct: pct(signIns.filter((s) => s.conditionalAccessStatus === 'notApplied').length, signIns.length),
    blockedSignIns: signIns.filter((s) => s.conditionalAccessStatus === 'failure').length,
    ssprGap: data.users.filter((u) => u.accountEnabled && !u.ssprRegistered).length,
    hybridDependency: pct(
      data.users.filter((u) => u.onPremisesSyncEnabled && u.accountEnabled).length,
      data.users.filter((u) => u.accountEnabled).length,
    ),
    telephonyDependent: data.users.filter((u) => u.accountEnabled && u.authStrength === 'weak-mfa').length,
  };
}

export interface RoadmapItem {
  finding: Finding;
  horizon: 'Now (0–30 days)' | 'Next (1–3 months)' | 'Later (3–12 months)';
  impactScore: number;
}

/** Sequences findings into a delivery roadmap using risk reduction per unit of effort. */
export function computeRoadmap(findings: Finding[]): RoadmapItem[] {
  const effortCost = { low: 1, medium: 2.2, high: 4 } as const;
  return findings
    .map((finding) => {
      const impactScore = Number((finding.riskScore / effortCost[finding.effort]).toFixed(1));
      const horizon: RoadmapItem['horizon'] =
        finding.effort === 'low' && finding.riskScore >= 55
          ? 'Now (0–30 days)'
          : finding.effort === 'high' || finding.riskScore < 45
            ? 'Later (3–12 months)'
            : 'Next (1–3 months)';
      return { finding, horizon, impactScore };
    })
    .sort((a, b) => b.impactScore - a.impactScore);
}
