import type { Finding, FindingEntity, Pillar, Severity, TenantDataset } from '../domain/types';
import {
  daysSince,
  daysUntil,
  formatNumber,
  isDormant,
  pct,
  roleNameOf,
  roleTierOf,
  trendTo,
} from './helpers';

interface RuleResult {
  id: string;
  title: string;
  pillar: Pillar;
  severity: Severity;
  affectedCount: number;
  /** Share of the relevant population affected, used to weight the score. */
  exposureRatio: number;
  businessImpact: string;
  evidence: string;
  recommendation: string;
  frameworks: string[];
  effort: Finding['effort'];
  entities: FindingEntity[];
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 100,
  high: 72,
  medium: 44,
  low: 22,
};

function topEntities(entities: FindingEntity[], limit = 25): FindingEntity[] {
  return entities.slice(0, limit);
}

function severityFromRatio(ratio: number, thresholds: [number, number, number]): Severity {
  const [criticalAt, highAt, mediumAt] = thresholds;
  if (ratio >= criticalAt) return 'critical';
  if (ratio >= highAt) return 'high';
  if (ratio >= mediumAt) return 'medium';
  return 'low';
}

/* ------------------------------------------------------------------ */
/* Detection rules                                                     */
/* ------------------------------------------------------------------ */

function identityRiskRules(data: TenantDataset): RuleResult[] {
  const results: RuleResult[] = [];
  const enabledUsers = data.users.filter((u) => u.accountEnabled);
  const members = enabledUsers.filter((u) => u.userType === 'Member');
  const guests = enabledUsers.filter((u) => u.userType === 'Guest');

  // 1. Accounts without any MFA registration.
  const noMfa = enabledUsers.filter((u) => !u.mfaRegistered);
  results.push({
    id: 'IR-01',
    title: 'Enabled accounts with no MFA method registered',
    pillar: 'identity-risk',
    severity: severityFromRatio(noMfa.length / enabledUsers.length, [0.12, 0.06, 0.02]),
    affectedCount: noMfa.length,
    exposureRatio: noMfa.length / enabledUsers.length,
    businessImpact:
      'Password-only accounts are the single most exploited entry point in identity-based breaches. Each of these accounts can be taken over with a credential from a phishing kit or an infostealer log, with no second barrier.',
    evidence: `${formatNumber(noMfa.length)} of ${formatNumber(enabledUsers.length)} enabled accounts (${pct(noMfa.length, enabledUsers.length)}%) have only a password registered. ${noMfa.filter((u) => u.userType === 'Guest').length} are external guests and ${noMfa.filter((u) => u.isPrivileged).length} hold a directory role.`,
    recommendation:
      'Run a registration campaign targeting these users, then enforce Entra security defaults or a Conditional Access policy requiring MFA. Prioritise the privileged and guest subsets first.',
    frameworks: ['NIST CSF PR.AA-03', 'CIS 6.3', 'ISO 27001 A.5.17'],
    effort: 'medium',
    entities: noMfa.map((u) => ({
      id: u.id,
      name: u.displayName,
      detail: `${u.userType} · ${u.department} · last sign-in ${u.lastSignInDateTime ? `${Math.round(daysSince(u.lastSignInDateTime))}d ago` : 'never'}`,
    })),
  });

  // 2. Privileged users without phishing-resistant authentication.
  const weakAdmins = enabledUsers.filter((u) => u.isPrivileged && u.authStrength !== 'phishing-resistant');
  const privilegedTotal = enabledUsers.filter((u) => u.isPrivileged).length || 1;
  results.push({
    id: 'IR-02',
    title: 'Administrators without phishing-resistant authentication',
    pillar: 'identity-risk',
    severity: severityFromRatio(weakAdmins.length / privilegedTotal, [0.5, 0.3, 0.15]),
    affectedCount: weakAdmins.length,
    exposureRatio: weakAdmins.length / privilegedTotal,
    businessImpact:
      'Push-notification and SMS factors are defeated by adversary-in-the-middle phishing and MFA fatigue. An administrator compromised this way hands an attacker tenant-wide control, not just one mailbox.',
    evidence: `${weakAdmins.length} of ${privilegedTotal} role holders (${pct(weakAdmins.length, privilegedTotal)}%) rely on phishable factors. ${weakAdmins.filter((u) => u.authStrength === 'weak-mfa' || u.authStrength === 'password-only').length} use SMS, voice or password only.`,
    recommendation:
      'Issue FIDO2 keys or passkeys to all role holders and enforce a phishing-resistant authentication strength in Conditional Access scoped to directory roles.',
    frameworks: ['NIST SP 800-63B AAL3', 'CIS 6.5', 'Zero Trust — Verify explicitly'],
    effort: 'medium',
    entities: weakAdmins.map((u) => ({
      id: u.id,
      name: u.displayName,
      detail: `${u.authStrength.replace('-', ' ')} · ${u.department}`,
    })),
  });

  // 3. Users flagged at risk by Identity Protection with no remediation.
  const riskyUsers = enabledUsers.filter((u) => u.riskLevel === 'high' || u.riskLevel === 'medium');
  results.push({
    id: 'IR-03',
    title: 'Unremediated medium and high risk users',
    pillar: 'identity-risk',
    severity: riskyUsers.length > enabledUsers.length * 0.05 ? 'critical' : 'high',
    affectedCount: riskyUsers.length,
    exposureRatio: riskyUsers.length / enabledUsers.length,
    businessImpact:
      'These identities show active signals of compromise — leaked credentials, impossible travel or malicious IP activity. Every hour they stay unremediated is dwell time an attacker can use to establish persistence.',
    evidence: `${riskyUsers.length} accounts are flagged at medium or high risk. The most common detections are ${[...new Set(riskyUsers.flatMap((u) => u.riskDetections))].slice(0, 4).join(', ')}.`,
    recommendation:
      'Enable an enforced user-risk Conditional Access policy requiring secure password change, and a sign-in-risk policy requiring MFA. Investigate high-risk privileged accounts manually before auto-remediating.',
    frameworks: ['NIST CSF DE.CM-01', 'MITRE ATT&CK T1078'],
    effort: 'low',
    entities: riskyUsers
      .sort((a, b) => (a.riskLevel === 'high' ? -1 : 1) - (b.riskLevel === 'high' ? -1 : 1))
      .map((u) => ({
        id: u.id,
        name: u.displayName,
        detail: `${u.riskLevel} risk · ${u.riskDetections.join(', ') || 'no detail'}`,
      })),
  });

  // 4. Dormant enabled accounts.
  const dormant = enabledUsers.filter((u) => isDormant(u));
  results.push({
    id: 'IR-04',
    title: 'Dormant accounts still enabled',
    pillar: 'identity-risk',
    severity: severityFromRatio(dormant.length / enabledUsers.length, [0.15, 0.08, 0.04]),
    affectedCount: dormant.length,
    exposureRatio: dormant.length / enabledUsers.length,
    businessImpact:
      'Unused accounts retain all their access but nobody notices when they are abused. They also consume licences — dormant identities are simultaneously a security exposure and a recurring cost.',
    evidence: `${dormant.length} enabled accounts (${pct(dormant.length, enabledUsers.length)}%) have not signed in for 90+ days, including ${dormant.filter((u) => u.userType === 'Guest').length} guests and ${dormant.filter((u) => u.isPrivileged).length} role holders.`,
    recommendation:
      'Implement a lifecycle workflow that disables accounts after 60 days of inactivity and deletes after 120, with a manager attestation exception path. Reclaim the associated licences.',
    frameworks: ['ISO 27001 A.5.16', 'CIS 5.3', 'SOX ITGC — access provisioning'],
    effort: 'low',
    entities: dormant.map((u) => ({
      id: u.id,
      name: u.displayName,
      detail: `${u.userType} · inactive ${u.lastSignInDateTime ? `${Math.round(daysSince(u.lastSignInDateTime))} days` : 'since creation'} · ${u.licenseSkus.length} licence(s)`,
    })),
  });

  // 5. Guests with no sponsor or never-accepted invitations.
  const orphanGuests = guests.filter((g) => !g.sponsorId || g.invitationState === 'pendingAcceptance');
  results.push({
    id: 'IR-05',
    title: 'External guests without an accountable sponsor',
    pillar: 'identity-risk',
    severity: severityFromRatio(orphanGuests.length / Math.max(guests.length, 1), [0.35, 0.2, 0.1]),
    affectedCount: orphanGuests.length,
    exposureRatio: orphanGuests.length / Math.max(guests.length, 1),
    businessImpact:
      'Unsponsored external identities have no one responsible for removing them when the engagement ends. This is how third-party access quietly becomes permanent and how supply-chain compromise spreads inward.',
    evidence: `${orphanGuests.length} of ${guests.length} guests (${pct(orphanGuests.length, guests.length)}%) have no sponsor recorded or never accepted their invitation. Guests originate from ${new Set(guests.map((g) => g.userPrincipalName.split('_')[1]?.split('#')[0])).size} external domains.`,
    recommendation:
      'Make sponsor attribution mandatory in the B2B invitation flow, backfill sponsors for existing guests, and enable guest lifecycle management with automatic removal after 30 days of inactivity.',
    frameworks: ['NIST CSF GV.SC-06', 'ISO 27001 A.5.19'],
    effort: 'medium',
    entities: orphanGuests.map((g) => ({
      id: g.id,
      name: g.displayName,
      detail: `${g.invitationState === 'pendingAcceptance' ? 'Invitation never accepted' : 'No sponsor'} · ${g.userPrincipalName.split('_')[1]?.split('#')[0] ?? 'external'}`,
    })),
  });

  // 6. Legacy authentication still succeeding.
  const legacySignIns = data.signIns.filter((s) => s.isLegacyAuth);
  const legacySuccess = legacySignIns.filter((s) => s.status === 'success');
  const legacyUserIds = new Set(legacySuccess.map((s) => s.userId));
  const userById = new Map(data.users.map((u) => [u.id, u]));
  results.push({
    id: 'IR-06',
    title: 'Legacy authentication protocols still succeeding',
    pillar: 'identity-risk',
    severity: legacySuccess.length > 0 ? 'high' : 'low',
    affectedCount: legacyUserIds.size,
    exposureRatio: legacyUserIds.size / enabledUsers.length,
    businessImpact:
      'Legacy protocols such as IMAP, POP and Exchange ActiveSync cannot present an MFA challenge. Any policy requiring MFA is silently bypassed on these paths, which is why they remain a favourite of password-spray operators.',
    evidence: `${formatNumber(legacySuccess.length)} successful legacy-auth sign-ins from ${legacyUserIds.size} distinct accounts in the last 90 days, despite a block policy being present.`,
    recommendation:
      'Identify the remaining applications behind these sign-ins, migrate them to modern authentication, then remove the Conditional Access exclusions that let them through.',
    frameworks: ['CIS 6.4', 'MITRE ATT&CK T1110.003'],
    effort: 'high',
    entities: [...legacyUserIds].map((uid) => {
      const u = userById.get(uid);
      return {
        id: uid,
        name: u?.displayName ?? uid,
        detail: `${legacySuccess.filter((s) => s.userId === uid).length} legacy sign-ins · ${u?.department ?? ''}`,
      };
    }),
  });

  // 7. Members with no compliant managed device.
  const deviceById = new Map(data.devices.map((d) => [d.id, d]));
  const noCompliantDevice = members.filter(
    (u) => u.deviceIds.length > 0 && !u.deviceIds.some((d) => deviceById.get(d)?.isCompliant),
  );
  results.push({
    id: 'IR-07',
    title: 'Employees with no compliant managed device',
    pillar: 'identity-risk',
    severity: severityFromRatio(noCompliantDevice.length / members.length, [0.12, 0.07, 0.03]),
    affectedCount: noCompliantDevice.length,
    exposureRatio: noCompliantDevice.length / members.length,
    businessImpact:
      'Access from unmanaged endpoints removes the device half of Zero Trust. Corporate data can be copied to machines with no disk encryption, no EDR and no ability to wipe when the person leaves.',
    evidence: `${noCompliantDevice.length} employees (${pct(noCompliantDevice.length, members.length)}%) have no device marked compliant. ${data.devices.filter((d) => !d.isManaged).length} of ${formatNumber(data.devices.length)} registered devices are unmanaged.`,
    recommendation:
      'Extend the compliant-device Conditional Access grant beyond Office 365 to all high-sensitivity applications, and enrol or block the remaining unmanaged endpoints.',
    frameworks: ['Zero Trust — Device health', 'CIS 4.1'],
    effort: 'high',
    entities: noCompliantDevice.map((u) => ({
      id: u.id,
      name: u.displayName,
      detail: `${u.deviceIds.length} device(s), none compliant · ${u.department}`,
    })),
  });

  return results;
}

function privilegedAccessRules(data: TenantDataset): RuleResult[] {
  const results: RuleResult[] = [];
  const userById = new Map(data.users.map((u) => [u.id, u]));
  const groupById = new Map(data.groups.map((g) => [g.id, g]));
  const appById = new Map(data.applications.map((a) => [a.id, a]));

  const nameOf = (principalId: string, type: string) =>
    type === 'user'
      ? userById.get(principalId)?.displayName ?? principalId
      : type === 'group'
        ? groupById.get(principalId)?.displayName ?? principalId
        : appById.get(principalId)?.displayName ?? principalId;

  // 1. Standing (permanent, active) tier-0 assignments.
  const standingTier0 = data.roleAssignments.filter(
    (a) => a.assignmentType === 'active' && a.isPermanent && roleTierOf(data, a.roleId) === 'tier-0',
  );
  const allTier0 = data.roleAssignments.filter((a) => roleTierOf(data, a.roleId) === 'tier-0');
  results.push({
    id: 'PA-01',
    title: 'Standing permanent assignments to tier-0 roles',
    pillar: 'privileged-access',
    severity: standingTier0.length > 12 ? 'critical' : standingTier0.length > 5 ? 'high' : 'medium',
    affectedCount: standingTier0.length,
    exposureRatio: standingTier0.length / Math.max(allTier0.length, 1),
    businessImpact:
      'Permanent tier-0 access means the keys to the entire tenant are live 24/7. A single compromised session becomes a full tenant takeover with no activation step, no approval and no additional audit trail.',
    evidence: `${standingTier0.length} permanent active assignments across ${new Set(standingTier0.map((a) => a.roleId)).size} tier-0 roles, representing ${pct(standingTier0.length, allTier0.length)}% of all tier-0 assignments.`,
    recommendation:
      'Convert every tier-0 assignment to PIM-eligible with approval and justification, retaining no more than two cloud-only break-glass accounts that are excluded, monitored and alerted on.',
    frameworks: ['Microsoft Enterprise Access Model', 'NIST CSF PR.AA-05', 'CIS 5.4'],
    effort: 'medium',
    entities: standingTier0.map((a) => ({
      id: a.id,
      name: nameOf(a.principalId, a.principalType),
      detail: `${roleNameOf(data, a.roleId)} · ${a.principalType} · granted ${Math.round(daysSince(a.createdDateTime))}d ago`,
    })),
  });

  // 2. Service principals holding directory roles.
  const spRoles = data.roleAssignments.filter((a) => a.principalType === 'servicePrincipal');
  results.push({
    id: 'PA-02',
    title: 'Workload identities holding directory roles',
    pillar: 'privileged-access',
    severity: spRoles.some((a) => roleTierOf(data, a.roleId) === 'tier-0') ? 'critical' : 'high',
    affectedCount: spRoles.length,
    exposureRatio: spRoles.length / Math.max(data.roleAssignments.length, 1),
    businessImpact:
      'Service principals cannot be challenged with MFA and are rarely reviewed. A leaked secret on one of these identities gives an attacker persistent, unattended administrative access that looks like normal automation.',
    evidence: `${spRoles.length} directory-role assignments are held by application identities, of which ${spRoles.filter((a) => roleTierOf(data, a.roleId) === 'tier-0').length} are tier-0. All are permanent and none require approval.`,
    recommendation:
      'Replace secrets with managed identities or federated credentials, apply workload identity Conditional Access to pin them to known networks, and bring them into scope of PIM for Groups and access reviews.',
    frameworks: ['Microsoft Enterprise Access Model', 'MITRE ATT&CK T1098.001'],
    effort: 'high',
    entities: spRoles.map((a) => ({
      id: a.id,
      name: nameOf(a.principalId, a.principalType),
      detail: `${roleNameOf(data, a.roleId)} · ${roleTierOf(data, a.roleId)} · permanent`,
    })),
  });

  // 3. Eligible roles never activated.
  const unusedEligible = data.roleAssignments.filter(
    (a) => a.assignmentType === 'eligible' && a.activationCount90d === 0,
  );
  const eligibleTotal = data.roleAssignments.filter((a) => a.assignmentType === 'eligible').length || 1;
  results.push({
    id: 'PA-03',
    title: 'Eligible role assignments never activated',
    pillar: 'privileged-access',
    severity: severityFromRatio(unusedEligible.length / eligibleTotal, [0.4, 0.25, 0.12]),
    affectedCount: unusedEligible.length,
    exposureRatio: unusedEligible.length / eligibleTotal,
    businessImpact:
      'Access that is never used is access that is not needed. Every unused eligibility widens the blast radius of a compromised account for zero operational benefit, and inflates the population that must be reviewed and audited.',
    evidence: `${unusedEligible.length} of ${eligibleTotal} eligible assignments (${pct(unusedEligible.length, eligibleTotal)}%) have not been activated in 90 days.`,
    recommendation:
      'Remove eligibilities unused for two consecutive review cycles. Right-sizing here directly reduces audit scope and review fatigue without affecting day-to-day operations.',
    frameworks: ['Least privilege — NIST AC-6', 'SOX ITGC'],
    effort: 'low',
    entities: unusedEligible.map((a) => ({
      id: a.id,
      name: nameOf(a.principalId, a.principalType),
      detail: `${roleNameOf(data, a.roleId)} · eligible since ${Math.round(daysSince(a.createdDateTime))}d · 0 activations`,
    })),
  });

  // 4. Privileged activation without approval or MFA.
  const weakActivation = data.roleAssignments.filter(
    (a) => a.assignmentType === 'eligible' && roleTierOf(data, a.roleId) !== 'tier-2' && (!a.requiresApproval || !a.requiresMfaOnActivation),
  );
  results.push({
    id: 'PA-04',
    title: 'Privileged activation without approval or step-up MFA',
    pillar: 'privileged-access',
    severity: 'high',
    affectedCount: weakActivation.length,
    exposureRatio: weakActivation.length / eligibleTotal,
    businessImpact:
      'Just-in-time access only delivers its control value if activation is gated. Without approval and step-up authentication, an attacker holding a session token can elevate themselves at will.',
    evidence: `${weakActivation.length} eligible tier-0/tier-1 assignments can be activated without approval (${weakActivation.filter((a) => !a.requiresApproval).length}) or without MFA at activation (${weakActivation.filter((a) => !a.requiresMfaOnActivation).length}).`,
    recommendation:
      'Set PIM role settings for all tier-0 and tier-1 roles to require approval, require phishing-resistant MFA on activation, cap duration at 4 hours and mandate a ticket reference.',
    frameworks: ['NIST AC-2(7)', 'CIS 5.4', 'ISO 27001 A.8.2'],
    effort: 'low',
    entities: weakActivation.map((a) => ({
      id: a.id,
      name: nameOf(a.principalId, a.principalType),
      detail: `${roleNameOf(data, a.roleId)} · ${!a.requiresApproval ? 'no approval' : ''}${!a.requiresApproval && !a.requiresMfaOnActivation ? ' + ' : ''}${!a.requiresMfaOnActivation ? 'no MFA on activation' : ''}`,
    })),
  });

  // 5. Guests and dormant accounts holding roles.
  const riskyHolders = data.roleAssignments.filter((a) => {
    if (a.principalType !== 'user') return false;
    const u = userById.get(a.principalId);
    return !!u && (u.userType === 'Guest' || isDormant(u) || !u.accountEnabled);
  });
  results.push({
    id: 'PA-05',
    title: 'Roles held by guests, dormant or disabled accounts',
    pillar: 'privileged-access',
    severity: riskyHolders.some((a) => userById.get(a.principalId)?.userType === 'Guest') ? 'critical' : 'high',
    affectedCount: riskyHolders.length,
    exposureRatio: riskyHolders.length / Math.max(data.roleAssignments.length, 1),
    businessImpact:
      'Administrative power sitting on an external or abandoned identity is privilege with no accountability. These are the assignments that regulators and incident responders ask about first.',
    evidence: `${riskyHolders.length} role assignments are held by accounts that are external guests (${riskyHolders.filter((a) => userById.get(a.principalId)?.userType === 'Guest').length}), dormant (${riskyHolders.filter((a) => { const u = userById.get(a.principalId); return !!u && isDormant(u); }).length}) or disabled (${riskyHolders.filter((a) => userById.get(a.principalId)?.accountEnabled === false).length}).`,
    recommendation:
      'Remove directory roles from all guest accounts and route external administration through a dedicated, sponsored, PIM-governed member account. Auto-revoke roles on 45 days of inactivity.',
    frameworks: ['ISO 27001 A.5.18', 'SOX ITGC — privileged access'],
    effort: 'low',
    entities: riskyHolders.map((a) => {
      const u = userById.get(a.principalId);
      return {
        id: a.id,
        name: u?.displayName ?? a.principalId,
        detail: `${roleNameOf(data, a.roleId)} · ${u?.userType === 'Guest' ? 'external guest' : !u?.accountEnabled ? 'disabled account' : 'dormant account'}`,
      };
    }),
  });

  // 6. Privileged access delivered through nested groups.
  const privGroupAssignments = data.roleAssignments.filter((a) => a.principalType === 'group');
  const impacted = new Set(privGroupAssignments.flatMap((a) => groupById.get(a.principalId)?.memberIds ?? []));
  results.push({
    id: 'PA-06',
    title: 'Privileged roles granted through groups with broad membership',
    pillar: 'privileged-access',
    severity: impacted.size > 200 ? 'critical' : impacted.size > 50 ? 'high' : 'medium',
    affectedCount: impacted.size,
    exposureRatio: impacted.size / Math.max(data.users.length, 1),
    businessImpact:
      'Group-delivered privilege hides the true size of the administrative population. Adding someone to a routine-looking group can silently grant tenant-wide rights that never appear in a role-holder report.',
    evidence: `${privGroupAssignments.length} role assignments are made to groups, expanding to ${impacted.size} effective privileged principals. ${privGroupAssignments.filter((a) => (groupById.get(a.principalId)?.memberIds.length ?? 0) > 100).length} of those groups have more than 100 members.`,
    recommendation:
      'Convert these to role-assignable groups with restricted management, cap membership, require PIM for Groups activation, and review membership quarterly with the group owner.',
    frameworks: ['NIST AC-6(1)', 'Microsoft Enterprise Access Model'],
    effort: 'medium',
    entities: privGroupAssignments.map((a) => ({
      id: a.id,
      name: groupById.get(a.principalId)?.displayName ?? a.principalId,
      detail: `${roleNameOf(data, a.roleId)} · ${groupById.get(a.principalId)?.memberIds.length ?? 0} members`,
    })),
  });

  return results;
}

function governanceRules(data: TenantDataset): RuleResult[] {
  const results: RuleResult[] = [];

  // 1. Overdue or stalled access reviews.
  const stalled = data.accessReviews.filter((r) => r.status === 'overdue' || r.status === 'not-started');
  results.push({
    id: 'GV-01',
    title: 'Access reviews overdue or never started',
    pillar: 'governance',
    severity: severityFromRatio(stalled.length / Math.max(data.accessReviews.length, 1), [0.35, 0.2, 0.1]),
    affectedCount: stalled.length,
    exposureRatio: stalled.length / Math.max(data.accessReviews.length, 1),
    businessImpact:
      'An overdue review is a control that has failed silently. At audit time there is no evidence that access was ever validated, which turns a security gap into a compliance finding and a potential material weakness.',
    evidence: `${stalled.length} of ${data.accessReviews.length} reviews are overdue or not started, covering ${formatNumber(stalled.reduce((sum, r) => sum + r.decisionsTotal, 0))} undecided access decisions.`,
    recommendation:
      'Escalate overdue reviews to the reviewer’s manager, enable auto-apply of “remove access” for undecided items, and publish a review-completion SLA on the leadership scorecard.',
    frameworks: ['SOX ITGC — user access review', 'ISO 27001 A.5.18', 'NIST AC-2(3)'],
    effort: 'low',
    entities: stalled.map((r) => ({
      id: r.id,
      name: r.displayName,
      detail: `${r.status} · ${r.decisionsMade}/${r.decisionsTotal} decisions · reviewer: ${r.reviewerType}`,
    })),
  });

  // 2. Rubber-stamped reviews.
  const rubber = data.accessReviews.filter((r) => r.rubberStampRate >= 0.9 && r.decisionsMade > 0);
  results.push({
    id: 'GV-02',
    title: 'Access reviews approved without scrutiny',
    pillar: 'governance',
    severity: rubber.length > data.accessReviews.length * 0.25 ? 'high' : 'medium',
    affectedCount: rubber.length,
    exposureRatio: rubber.length / Math.max(data.accessReviews.length, 1),
    businessImpact:
      'A review where everything is approved provides false assurance. Leadership believes access is validated while entitlement creep continues unchecked — and the audit evidence will not survive scrutiny.',
    evidence: `${rubber.length} reviews approved 90%+ of decisions with no removals. ${data.accessReviews.filter((r) => r.reviewerType === 'self').length} reviews are self-attested, which averages a ${Math.round((data.accessReviews.filter((r) => r.reviewerType === 'self').reduce((s, r) => s + r.rubberStampRate, 0) / Math.max(data.accessReviews.filter((r) => r.reviewerType === 'self').length, 1)) * 100)}% approve-all rate.`,
    recommendation:
      'Eliminate self-attestation for anything sensitive, show reviewers last-used and peer-comparison signals in the review UI, and track a removal-rate metric per reviewer to identify rubber-stamping.',
    frameworks: ['SOX ITGC', 'COBIT DSS05.04'],
    effort: 'medium',
    entities: rubber.map((r) => ({
      id: r.id,
      name: r.displayName,
      detail: `${Math.round(r.rubberStampRate * 100)}% approved unchanged · reviewer: ${r.reviewerType}`,
    })),
  });

  // 3. Groups without owners.
  const ownerless = data.groups.filter((g) => g.ownerIds.length === 0);
  results.push({
    id: 'GV-03',
    title: 'Access groups with no accountable owner',
    pillar: 'governance',
    severity: severityFromRatio(ownerless.length / data.groups.length, [0.2, 0.1, 0.05]),
    affectedCount: ownerless.length,
    exposureRatio: ownerless.length / data.groups.length,
    businessImpact:
      'An ownerless group cannot be reviewed, because there is nobody who can say whether the access is still justified. These groups become permanent, unexamined access paths.',
    evidence: `${ownerless.length} of ${data.groups.length} groups have no owner, together granting access to ${formatNumber(new Set(ownerless.flatMap((g) => g.memberIds)).size)} distinct principals. ${ownerless.filter((g) => g.grantsPrivilegedAccess).length} of them convey privileged access.`,
    recommendation:
      'Assign a business owner to every access group as a prerequisite for continued existence, and block creation of ownerless groups in policy. Escalate privileged ownerless groups this quarter.',
    frameworks: ['ISO 27001 A.5.2', 'COBIT APO01.02'],
    effort: 'medium',
    entities: ownerless.map((g) => ({
      id: g.id,
      name: g.displayName,
      detail: `${g.memberIds.length} members${g.grantsPrivilegedAccess ? ' · privileged' : ''}`,
    })),
  });

  // 4. Never-reviewed groups conveying privilege.
  const neverReviewed = data.groups.filter((g) => g.grantsPrivilegedAccess && (!g.lastReviewedDateTime || daysSince(g.lastReviewedDateTime) > 365));
  results.push({
    id: 'GV-04',
    title: 'Privileged groups not reviewed in over a year',
    pillar: 'governance',
    severity: 'high',
    affectedCount: neverReviewed.length,
    exposureRatio: neverReviewed.length / Math.max(data.groups.filter((g) => g.grantsPrivilegedAccess).length, 1),
    businessImpact:
      'Entitlement creep is cumulative. Groups that convey elevated access and have gone a year or more without review almost always contain people who changed roles, changed teams, or left the project.',
    evidence: `${neverReviewed.length} privileged groups have no review in the last 365 days, covering ${formatNumber(new Set(neverReviewed.flatMap((g) => g.memberIds)).size)} members.`,
    recommendation:
      'Place every privileged group under a quarterly recurring access review with group-owner plus manager as dual reviewers and auto-removal of undecided members.',
    frameworks: ['NIST AC-2(3)', 'SOX ITGC'],
    effort: 'low',
    entities: neverReviewed.map((g) => ({
      id: g.id,
      name: g.displayName,
      detail: `${g.memberIds.length} members · last reviewed ${g.lastReviewedDateTime ? `${Math.round(daysSince(g.lastReviewedDateTime))}d ago` : 'never'}`,
    })),
  });

  // 5. Access packages with no expiry.
  const neverExpires = data.accessPackages.filter((p) => p.expirationDays === null);
  results.push({
    id: 'GV-05',
    title: 'Entitlement packages that grant access forever',
    pillar: 'governance',
    severity: severityFromRatio(neverExpires.length / Math.max(data.accessPackages.length, 1), [0.3, 0.18, 0.08]),
    affectedCount: neverExpires.reduce((sum, p) => sum + p.activeAssignments, 0),
    exposureRatio: neverExpires.length / Math.max(data.accessPackages.length, 1),
    businessImpact:
      'Access granted without an end date survives project completion, role change and offboarding gaps. Time-bound access is the cheapest governance control available and it is not being used here.',
    evidence: `${neverExpires.length} access packages have no expiration, covering ${formatNumber(neverExpires.reduce((s, p) => s + p.activeAssignments, 0))} active assignments. ${data.accessPackages.filter((p) => !p.approvalRequired).length} packages also grant access with no approval step.`,
    recommendation:
      'Set a maximum assignment duration of 180 days on all packages (90 for anything touching restricted data), with a self-service extension that requires re-justification.',
    frameworks: ['NIST AC-2(2)', 'ISO 27001 A.5.18'],
    effort: 'low',
    entities: neverExpires.map((p) => ({
      id: p.id,
      name: p.displayName,
      detail: `${p.activeAssignments} active assignments · ${p.approvalRequired ? 'approval required' : 'no approval'}`,
    })),
  });

  // 6. Ungoverned access paths — groups outside entitlement management.
  const ungoverned = data.groups.filter((g) => !g.isGovernedByAccessPackage && g.memberIds.length >= 25);
  results.push({
    id: 'GV-06',
    title: 'High-membership groups outside entitlement management',
    pillar: 'governance',
    severity: severityFromRatio(ungoverned.length / data.groups.length, [0.45, 0.3, 0.15]),
    affectedCount: ungoverned.length,
    exposureRatio: ungoverned.length / data.groups.length,
    businessImpact:
      'Access granted outside entitlement management has no request record, no approval trail and no automatic expiry. It is invisible to the joiner-mover-leaver process, so it persists after people move on.',
    evidence: `${ungoverned.length} groups with 25 or more members are not fronted by an access package. Only ${pct(data.groups.filter((g) => g.isGovernedByAccessPackage).length, data.groups.length)}% of groups are governed today.`,
    recommendation:
      'Onboard the highest-membership and highest-sensitivity groups into entitlement management first, making the access package the only supported way to obtain membership.',
    frameworks: ['ISO 27001 A.5.18', 'COBIT DSS05.04'],
    effort: 'high',
    entities: ungoverned
      .sort((a, b) => b.memberIds.length - a.memberIds.length)
      .map((g) => ({ id: g.id, name: g.displayName, detail: `${g.memberIds.length} members · ${g.membershipRule}` })),
  });

  // 7. Dynamic-group sprawl without ownership.
  const dynamicUnowned = data.groups.filter((g) => g.membershipRule === 'dynamic' && g.ownerIds.length === 0);
  results.push({
    id: 'GV-07',
    title: 'Dynamic groups with unowned membership rules',
    pillar: 'governance',
    severity: 'medium',
    affectedCount: dynamicUnowned.length,
    exposureRatio: dynamicUnowned.length / Math.max(data.groups.filter((g) => g.membershipRule === 'dynamic').length, 1),
    businessImpact:
      'A dynamic rule is code that grants access. When no one owns it, an attribute change in HR data can silently expand access to hundreds of people with no approval anywhere in the chain.',
    evidence: `${dynamicUnowned.length} of ${data.groups.filter((g) => g.membershipRule === 'dynamic').length} dynamic groups have no owner to validate the membership rule.`,
    recommendation:
      'Treat dynamic membership rules as change-controlled configuration: require an owner, peer review of rule changes, and alerting on membership deltas above a threshold.',
    frameworks: ['ISO 27001 A.8.32', 'COBIT BAI06'],
    effort: 'medium',
    entities: dynamicUnowned.map((g) => ({
      id: g.id,
      name: g.displayName,
      detail: `dynamic · ${g.memberIds.length} members · no owner`,
    })),
  });

  return results;
}

function workloadIdentityRules(data: TenantDataset): RuleResult[] {
  const results: RuleResult[] = [];

  // 1. Expired or imminently expiring credentials.
  const appsWithExpiring = data.applications.filter((a) =>
    a.credentials.some((c) => c.type !== 'federated' && daysUntil(c.expiryDateTime) < 30),
  );
  const expiredNow = data.applications.filter((a) =>
    a.credentials.some((c) => c.type !== 'federated' && daysUntil(c.expiryDateTime) < 0),
  );
  results.push({
    id: 'WI-01',
    title: 'Application credentials expired or expiring within 30 days',
    pillar: 'workload-identity',
    severity: expiredNow.length > 10 ? 'high' : 'medium',
    affectedCount: appsWithExpiring.length,
    exposureRatio: appsWithExpiring.length / Math.max(data.applications.length, 1),
    businessImpact:
      'This is an availability risk as much as a security one. Expiring secrets cause unannounced outages in business-critical integrations, and the emergency fix is usually a long-lived secret that makes the problem worse.',
    evidence: `${expiredNow.length} applications already hold expired credentials and ${appsWithExpiring.length - expiredNow.length} expire within 30 days. ${data.applications.filter((a) => a.credentials.some((c) => c.type === 'secret')).length} applications still authenticate with client secrets.`,
    recommendation:
      'Migrate to managed identities or workload identity federation where possible; where secrets are unavoidable, automate rotation through Key Vault with a 90-day maximum lifetime and owner alerting at 30 days.',
    frameworks: ['NIST IA-5', 'CIS 5.2'],
    effort: 'medium',
    entities: appsWithExpiring.map((a) => {
      const soonest = [...a.credentials].sort((x, y) => daysUntil(x.expiryDateTime) - daysUntil(y.expiryDateTime))[0];
      const days = Math.round(daysUntil(soonest.expiryDateTime));
      return {
        id: a.id,
        name: a.displayName,
        detail: `${soonest.type} · ${days < 0 ? `expired ${Math.abs(days)}d ago` : `expires in ${days}d`} · ${a.category}`,
      };
    }),
  });

  // 2. Over-permissioned application identities.
  const overPermissioned = data.applications.filter((a) =>
    a.grantedPermissions.some((p) => p.isHighPrivilege && p.type === 'Application'),
  );
  results.push({
    id: 'WI-02',
    title: 'Applications holding high-privilege tenant-wide permissions',
    pillar: 'workload-identity',
    severity: severityFromRatio(overPermissioned.length / data.applications.length, [0.3, 0.18, 0.08]),
    affectedCount: overPermissioned.length,
    exposureRatio: overPermissioned.length / data.applications.length,
    businessImpact:
      'Application permissions such as Mail.ReadWrite or Files.ReadWrite.All apply to every mailbox and every site with no user context. One compromised application identity can exfiltrate the entire organisation’s data.',
    evidence: `${overPermissioned.length} applications hold tenant-wide application permissions. The most common are ${[...new Set(overPermissioned.flatMap((a) => a.grantedPermissions.filter((p) => p.isHighPrivilege).map((p) => p.value)))].slice(0, 4).join(', ')}. ${overPermissioned.filter((a) => a.grantedPermissions.some((p) => p.isHighPrivilege && !p.lastUsedDateTime)).length} have never exercised the permission.`,
    recommendation:
      'Remove permissions with no recorded use, replace tenant-wide Graph scopes with resource-specific application access policies, and require a security review before any new high-privilege consent.',
    frameworks: ['NIST AC-6', 'MITRE ATT&CK T1550.001'],
    effort: 'high',
    entities: overPermissioned.map((a) => ({
      id: a.id,
      name: a.displayName,
      detail: a.grantedPermissions.filter((p) => p.isHighPrivilege).map((p) => p.value).join(', '),
    })),
  });

  // 3. Unowned applications.
  const unowned = data.applications.filter((a) => a.ownerIds.length === 0);
  results.push({
    id: 'WI-03',
    title: 'Applications with no registered owner',
    pillar: 'workload-identity',
    severity: severityFromRatio(unowned.length / data.applications.length, [0.2, 0.12, 0.05]),
    affectedCount: unowned.length,
    exposureRatio: unowned.length / data.applications.length,
    businessImpact:
      'Nobody can approve, review or safely decommission an unowned application. These accumulate until an incident forces the question, and by then the dependency map is unknown.',
    evidence: `${unowned.length} of ${data.applications.length} registrations have no owner, including ${unowned.filter((a) => a.dataSensitivity === 'restricted' || a.dataSensitivity === 'confidential').length} that handle confidential or restricted data.`,
    recommendation:
      'Require an owner at registration time, reconcile existing registrations against the CMDB, and disable applications that remain unclaimed after a 30-day notice period.',
    frameworks: ['ISO 27001 A.5.9', 'COBIT APO01.02'],
    effort: 'medium',
    entities: unowned.map((a) => ({
      id: a.id,
      name: a.displayName,
      detail: `${a.category} · ${a.dataSensitivity} data · ${a.lastSignInDateTime ? `last used ${Math.round(daysSince(a.lastSignInDateTime))}d ago` : 'never used'}`,
    })),
  });

  // 4. Stale applications still holding access.
  const stale = data.applications.filter((a) => daysSince(a.lastSignInDateTime) > 90);
  results.push({
    id: 'WI-04',
    title: 'Unused applications retaining tenant access',
    pillar: 'workload-identity',
    severity: severityFromRatio(stale.length / data.applications.length, [0.3, 0.2, 0.1]),
    affectedCount: stale.length,
    exposureRatio: stale.length / data.applications.length,
    businessImpact:
      'Abandoned integrations keep their permissions and their credentials. They are attractive to attackers precisely because no one is watching their sign-in logs.',
    evidence: `${stale.length} applications have not authenticated in 90+ days but retain ${stale.reduce((s, a) => s + a.grantedPermissions.length, 0)} granted permissions and ${stale.reduce((s, a) => s + a.credentials.length, 0)} active credentials.`,
    recommendation:
      'Run a quarterly application attestation: disable unused registrations, revoke their consent grants, and delete credentials after a 30-day soak period.',
    frameworks: ['ISO 27001 A.5.9', 'CIS 2.3'],
    effort: 'low',
    entities: stale.map((a) => ({
      id: a.id,
      name: a.displayName,
      detail: `${a.lastSignInDateTime ? `idle ${Math.round(daysSince(a.lastSignInDateTime))}d` : 'never signed in'} · ${a.grantedPermissions.length} permissions`,
    })),
  });

  // 5. User consent to multi-tenant applications.
  const userConsented = data.applications.filter(
    (a) => a.signInAudience !== 'AzureADMyOrg' && a.grantedPermissions.some((p) => p.consentType === 'user'),
  );
  results.push({
    id: 'WI-05',
    title: 'Multi-tenant applications consented by end users',
    pillar: 'workload-identity',
    severity: 'medium',
    affectedCount: userConsented.length,
    exposureRatio: userConsented.length / data.applications.length,
    businessImpact:
      'Illicit consent grants are a proven initial-access technique: a convincing app prompt gives a third party ongoing access to mail and files without ever stealing a password.',
    evidence: `${userConsented.length} externally-published applications hold permissions consented by individual users rather than an administrator.`,
    recommendation:
      'Restrict user consent to verified publishers and low-impact permissions, enable the admin consent request workflow, and review existing user-consented grants against the verified-publisher list.',
    frameworks: ['MITRE ATT&CK T1528', 'CIS 6.8'],
    effort: 'low',
    entities: userConsented.map((a) => ({
      id: a.id,
      name: a.displayName,
      detail: `${a.signInAudience} · ${a.grantedPermissions.filter((p) => p.consentType === 'user').map((p) => p.value).join(', ')}`,
    })),
  });

  return results;
}

function resilienceRules(data: TenantDataset): RuleResult[] {
  const results: RuleResult[] = [];
  const policies = data.conditionalAccessPolicies;

  // 1. Policies in report-only mode.
  const reportOnly = policies.filter((p) => p.state === 'enabledForReportingButNotEnforced');
  results.push({
    id: 'RS-01',
    title: 'Critical policies left in report-only mode',
    pillar: 'resilience',
    severity: reportOnly.length >= 3 ? 'high' : 'medium',
    affectedCount: reportOnly.length,
    exposureRatio: reportOnly.length / Math.max(policies.length, 1),
    businessImpact:
      'Report-only policies produce dashboards, not protection. Leadership sees a control that exists on paper while the underlying risk — including risk-based remediation — is entirely unenforced.',
    evidence: `${reportOnly.length} policies are report-only, including ${reportOnly.filter((p) => /risk/i.test(p.displayName)).map((p) => p.displayName.split(' — ')[0]).join(', ') || 'none'} covering identity-risk remediation. ${policies.filter((p) => p.state === 'disabled').length} further policies are fully disabled.`,
    recommendation:
      'Review the report-only impact data, resolve the exceptions it reveals, then move each policy to enforced with a documented rollback plan and a break-glass exclusion.',
    frameworks: ['NIST CSF PR.AA-05', 'Zero Trust — Enforce policy'],
    effort: 'low',
    entities: reportOnly.map((p) => ({ id: p.id, name: p.displayName, detail: `${p.state} · modified ${Math.round(daysSince(p.lastModifiedDateTime))}d ago` })),
  });

  // 2. Policy exclusion sprawl.
  const exclusionHeavy = policies.filter((p) => p.excludedUserCount >= 7 || p.excludedGroupIds.length >= 2);
  const totalExclusions = policies.reduce((s, p) => s + p.excludedUserCount, 0);
  results.push({
    id: 'RS-02',
    title: 'Conditional Access exclusion sprawl',
    pillar: 'resilience',
    severity: totalExclusions > 120 ? 'high' : 'medium',
    affectedCount: totalExclusions,
    exposureRatio: exclusionHeavy.length / Math.max(policies.length, 1),
    businessImpact:
      'Exclusions are permanent exceptions that nobody revisits. Every excluded identity is a documented bypass of the control, and attackers specifically hunt for these accounts.',
    evidence: `${formatNumber(totalExclusions)} user exclusions across ${exclusionHeavy.length} policies, plus ${policies.reduce((s, p) => s + p.excludedGroupIds.length, 0)} excluded groups. The largest single exclusion set covers ${Math.max(...policies.map((p) => p.excludedUserCount))} users.`,
    recommendation:
      'Inventory every exclusion with a named owner, business justification and expiry date. Replace standing exclusions with time-bound access packages and alert whenever an excluded account signs in.',
    frameworks: ['ISO 27001 A.5.15', 'CIS 6.1'],
    effort: 'medium',
    entities: exclusionHeavy.map((p) => ({
      id: p.id,
      name: p.displayName,
      detail: `${p.excludedUserCount} users + ${p.excludedGroupIds.length} groups excluded`,
    })),
  });

  // 3. Break-glass readiness.
  const breakGlassCandidates = data.roleAssignments.filter(
    (a) => a.roleId === 'role-ga' && a.assignmentType === 'active' && a.isPermanent,
  );
  results.push({
    id: 'RS-03',
    title: 'Break-glass account strategy not verifiable',
    pillar: 'resilience',
    severity: breakGlassCandidates.length < 2 || breakGlassCandidates.length > 4 ? 'high' : 'medium',
    affectedCount: breakGlassCandidates.length,
    exposureRatio: 0.5,
    businessImpact:
      'If Conditional Access, the identity provider or an MFA vendor fails, emergency access accounts are the only way back into the tenant. Too few means lockout; too many means the exception becomes the norm.',
    evidence: `${breakGlassCandidates.length} permanent active Global Administrator assignments exist. Industry practice is exactly two cloud-only accounts, excluded from Conditional Access, stored offline and alerted on every sign-in.`,
    recommendation:
      'Designate exactly two cloud-only break-glass accounts with long passphrases split under dual control and FIDO2 backup, exclude them from all policies, alert on any use, and test recovery twice a year.',
    frameworks: ['ISO 22301', 'NIST CP-2', 'Microsoft emergency access guidance'],
    effort: 'low',
    entities: breakGlassCandidates.map((a) => ({
      id: a.id,
      name: roleNameOf(data, a.roleId),
      detail: `permanent active · ${a.justification ?? 'no justification recorded'}`,
    })),
  });

  // 4. Coverage gap: policies not targeting all applications.
  const mfaAllApps = policies.filter((p) => p.state === 'enabled' && p.targetsAllApps && p.grantControls.some((c) => /multifactor|authentication strength/i.test(c)));
  const caFailures = data.signIns.filter((s) => s.conditionalAccessStatus === 'notApplied');
  results.push({
    id: 'RS-04',
    title: 'Sign-ins completing with no Conditional Access policy applied',
    pillar: 'resilience',
    severity: caFailures.length > data.signIns.length * 0.1 ? 'high' : 'medium',
    affectedCount: caFailures.length,
    exposureRatio: caFailures.length / Math.max(data.signIns.length, 1),
    businessImpact:
      'Every sign-in where no policy applied is an authentication that happened entirely outside your access controls. These gaps are where attackers operate undetected.',
    evidence: `${formatNumber(caFailures.length)} of ${formatNumber(data.signIns.length)} sign-ins (${pct(caFailures.length, data.signIns.length)}%) had no Conditional Access policy applied. Only ${mfaAllApps.length} enforced policy requires MFA across all applications.`,
    recommendation:
      'Close the gap with a catch-all baseline policy requiring MFA for all users and all cloud apps, then work the report-only impact data to resolve legitimate exceptions.',
    frameworks: ['Zero Trust — Verify explicitly', 'NIST CSF PR.AA-05'],
    effort: 'medium',
    entities: [...new Set(caFailures.map((s) => s.appId))].slice(0, 40).map((appId) => {
      const app = data.applications.find((a) => a.id === appId);
      return {
        id: appId,
        name: app?.displayName ?? appId,
        detail: `${caFailures.filter((s) => s.appId === appId).length} uncovered sign-ins · ${app?.category ?? ''}`,
      };
    }),
  });

  // 5. Single points of failure in authentication.
  const smsDependent = data.users.filter((u) => u.accountEnabled && u.authStrength === 'weak-mfa');
  results.push({
    id: 'RS-05',
    title: 'Authentication resilience depends on telephony',
    pillar: 'resilience',
    severity: severityFromRatio(smsDependent.length / Math.max(data.users.filter((u) => u.accountEnabled).length, 1), [0.2, 0.12, 0.06]),
    affectedCount: smsDependent.length,
    exposureRatio: smsDependent.length / Math.max(data.users.filter((u) => u.accountEnabled).length, 1),
    businessImpact:
      'Telephony factors fail during carrier outages, international travel and SIM-swap attacks. Users with only an SMS factor are both less secure and more likely to be locked out when it matters.',
    evidence: `${smsDependent.length} enabled accounts depend on SMS, voice or email OTP as their strongest factor. ${data.users.filter((u) => u.accountEnabled && !u.ssprRegistered).length} accounts are also not registered for self-service password reset, so recovery requires the service desk.`,
    recommendation:
      'Drive every user to at least two non-telephony methods (Authenticator plus passkey), disable SMS as a permitted method once coverage is sufficient, and complete SSPR registration to cut helpdesk dependency.',
    frameworks: ['NIST SP 800-63B', 'ISO 22301'],
    effort: 'medium',
    entities: smsDependent.slice(0, 200).map((u) => ({
      id: u.id,
      name: u.displayName,
      detail: `${u.registeredMethods.join(', ')} · ${u.ssprRegistered ? 'SSPR registered' : 'no SSPR'}`,
    })),
  });

  // 6. Hybrid dependency.
  const synced = data.users.filter((u) => u.onPremisesSyncEnabled && u.accountEnabled);
  results.push({
    id: 'RS-06',
    title: 'Cloud availability dependent on on-premises directory',
    pillar: 'resilience',
    severity: 'medium',
    affectedCount: synced.length,
    exposureRatio: synced.length / Math.max(data.users.filter((u) => u.accountEnabled).length, 1),
    businessImpact:
      'When a large share of identities are mastered on-premises, a datacentre, AD or sync outage becomes a cloud outage. Ransomware in Active Directory also propagates directly into cloud identity.',
    evidence: `${formatNumber(synced.length)} enabled accounts (${pct(synced.length, data.users.filter((u) => u.accountEnabled).length)}%) are synchronised from on-premises Active Directory, including ${synced.filter((u) => u.isPrivileged).length} privileged accounts.`,
    recommendation:
      'Ensure all privileged accounts are cloud-only, enable cloud Kerberos trust and password hash sync as an authentication fallback, and validate the tested recovery time for the sync infrastructure.',
    frameworks: ['ISO 22301', 'Microsoft Enterprise Access Model'],
    effort: 'high',
    entities: synced.filter((u) => u.isPrivileged).map((u) => ({
      id: u.id,
      name: u.displayName,
      detail: `synced privileged account · ${u.department}`,
    })),
  });

  return results;
}

/* ------------------------------------------------------------------ */
/* Engine                                                              */
/* ------------------------------------------------------------------ */

export function computeFindings(data: TenantDataset): Finding[] {
  const rules = [
    ...identityRiskRules(data),
    ...privilegedAccessRules(data),
    ...governanceRules(data),
    ...workloadIdentityRules(data),
    ...resilienceRules(data),
  ];

  return rules
    .filter((r) => r.affectedCount > 0)
    .map((r, index) => {
      // Score blends inherent severity with how much of the estate is exposed.
      // The severity base sets the band (critical 60, high 43, medium 26, low 13) and
      // exposure moves the finding up to 38 points within and above that band, so two
      // findings of equal severity are still separated by how much of the estate is at stake.
      const exposureBoost = Math.min(1, Math.sqrt(Math.max(r.exposureRatio, 0))) * 38;
      const riskScore = Math.round(Math.min(100, SEVERITY_WEIGHT[r.severity] * 0.6 + exposureBoost));
      return {
        id: r.id,
        title: r.title,
        pillar: r.pillar,
        severity: r.severity,
        riskScore,
        affectedCount: r.affectedCount,
        businessImpact: r.businessImpact,
        evidence: r.evidence,
        recommendation: r.recommendation,
        frameworks: r.frameworks,
        effort: r.effort,
        affectedEntities: topEntities(r.entities, 60),
        trend: trendTo(riskScore, index * 3.1, 12, 0.9),
      } satisfies Finding;
    })
    .sort((a, b) => b.riskScore - a.riskScore || b.affectedCount - a.affectedCount);
}
