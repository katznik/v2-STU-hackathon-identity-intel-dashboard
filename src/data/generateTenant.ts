import { Rng, id } from './random';
import {
  ANOMALOUS_LOCATIONS,
  APP_NAME_PARTS,
  FIRST_NAMES,
  HIGH_PRIVILEGE_PERMISSIONS,
  JOB_TITLES,
  LAST_NAMES,
  LOCATIONS,
  PARTNER_DOMAINS,
  RISK_DETECTIONS,
  STANDARD_PERMISSIONS,
} from './names';
import type {
  AccessPackage,
  AccessReview,
  AppCredential,
  AppPermission,
  Application,
  AuthStrength,
  BusinessUnit,
  ConditionalAccessPolicy,
  Device,
  DirectoryRole,
  Group,
  LicenseSku,
  RiskLevel,
  RoleAssignment,
  SignIn,
  TenantDataset,
  User,
} from '../domain/types';

const TENANT_DOMAIN = 'cascadiahealth.com';

const DIRECTORY_ROLES: DirectoryRole[] = [
  { id: 'role-ga', displayName: 'Global Administrator', tier: 'tier-0', description: 'Full control of every Entra ID and Microsoft 365 service.' },
  { id: 'role-pra', displayName: 'Privileged Role Administrator', tier: 'tier-0', description: 'Can grant any directory role, including Global Administrator.' },
  { id: 'role-paa', displayName: 'Privileged Authentication Administrator', tier: 'tier-0', description: 'Can reset credentials for any user, including Global Admins.' },
  { id: 'role-aa', displayName: 'Application Administrator', tier: 'tier-0', description: 'Can add credentials to any app identity and escalate privilege.' },
  { id: 'role-ca', displayName: 'Cloud Application Administrator', tier: 'tier-0', description: 'Manages app registrations and consent tenant-wide.' },
  { id: 'role-sa', displayName: 'Security Administrator', tier: 'tier-1', description: 'Manages security policies, Conditional Access and Identity Protection.' },
  { id: 'role-ea', displayName: 'Exchange Administrator', tier: 'tier-1', description: 'Full control of mailboxes and mail flow.' },
  { id: 'role-spa', displayName: 'SharePoint Administrator', tier: 'tier-1', description: 'Full control of SharePoint and OneDrive content.' },
  { id: 'role-ua', displayName: 'User Administrator', tier: 'tier-1', description: 'Creates and manages users and non-admin credentials.' },
  { id: 'role-ia', displayName: 'Intune Administrator', tier: 'tier-1', description: 'Manages device enrolment and compliance policy.' },
  { id: 'role-ha', displayName: 'Helpdesk Administrator', tier: 'tier-2', description: 'Resets passwords for non-administrators.' },
  { id: 'role-gr', displayName: 'Global Reader', tier: 'tier-2', description: 'Read-only access to all tenant configuration and data surfaces.' },
  { id: 'role-br', displayName: 'Billing Administrator', tier: 'tier-2', description: 'Manages subscriptions, purchases and support tickets.' },
  { id: 'role-ra', displayName: 'Reports Reader', tier: 'tier-2', description: 'Reads usage and sign-in reporting data.' },
];

const BUSINESS_UNITS: BusinessUnit[] = [
  { id: 'bu-clin', name: 'Clinical Operations', region: 'North America', headcount: 0, executiveOwner: 'Dr. Helena Vosburgh', criticality: 'tier-1' },
  { id: 'bu-fin', name: 'Finance & Treasury', region: 'North America', headcount: 0, executiveOwner: 'Martin Achebe', criticality: 'tier-1' },
  { id: 'bu-eng', name: 'Digital Engineering', region: 'Global', headcount: 0, executiveOwner: 'Sanjay Ramanathan', criticality: 'tier-1' },
  { id: 'bu-rnd', name: 'Research & Development', region: 'EMEA', headcount: 0, executiveOwner: 'Dr. Ingrid Solberg', criticality: 'tier-1' },
  { id: 'bu-sup', name: 'Supply Chain', region: 'APAC', headcount: 0, executiveOwner: 'Wei-Lin Cho', criticality: 'tier-2' },
  { id: 'bu-hr', name: 'People & Culture', region: 'Global', headcount: 0, executiveOwner: 'Danielle Okonkwo', criticality: 'tier-2' },
  { id: 'bu-sales', name: 'Commercial & Sales', region: 'Global', headcount: 0, executiveOwner: 'Peter Lindqvist', criticality: 'tier-2' },
  { id: 'bu-legal', name: 'Legal & Compliance', region: 'North America', headcount: 0, executiveOwner: 'Amara Osei', criticality: 'tier-1' },
  { id: 'bu-it', name: 'IT & Infrastructure', region: 'Global', headcount: 0, executiveOwner: 'Tomás Guerrero', criticality: 'tier-1' },
  { id: 'bu-mfg', name: 'Manufacturing', region: 'EMEA', headcount: 0, executiveOwner: 'Katrin Bauer', criticality: 'tier-2' },
];

const USER_COUNT = 1850;
const GUEST_SHARE = 0.11;
const GROUP_COUNT = 165;
const APP_COUNT = 120;
const SIGN_IN_COUNT = 9000;

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function buildUsers(rng: Rng, now: Date): User[] {
  const users: User[] = [];
  const guestCount = Math.round(USER_COUNT * GUEST_SHARE);
  const memberCount = USER_COUNT - guestCount;

  for (let i = 0; i < USER_COUNT; i += 1) {
    const isGuest = i >= memberCount;
    const first = rng.pick(FIRST_NAMES);
    const last = rng.pick(LAST_NAMES);
    const bu = rng.pick(BUSINESS_UNITS);
    const displayName = `${first} ${last}`;

    // Guests skew heavily toward weak authentication and stale usage.
    const authStrength = rng.weighted<AuthStrength>(
      isGuest
        ? [['phishing-resistant', 3], ['strong-mfa', 26], ['weak-mfa', 41], ['password-only', 30]]
        : [['phishing-resistant', 34], ['strong-mfa', 45], ['weak-mfa', 14], ['password-only', 7]],
    );

    const mfaRegistered = authStrength !== 'password-only';
    const methods: string[] = [];
    if (authStrength === 'phishing-resistant') methods.push(rng.pick(['FIDO2 security key', 'Windows Hello for Business', 'Certificate-based auth', 'Passkey (device-bound)']));
    if (authStrength === 'phishing-resistant' || authStrength === 'strong-mfa') methods.push('Microsoft Authenticator (number matching)');
    if (authStrength === 'weak-mfa') methods.push(rng.pick(['SMS', 'Voice call', 'Email OTP']));
    methods.push('Password');

    const createdDateTime = rng.dateDaysAgo(now, 2600, 5);
    const dormantProbability = isGuest ? 0.38 : 0.09;
    const neverSignedIn = rng.bool(isGuest ? 0.14 : 0.03);
    const lastSignInDateTime = neverSignedIn
      ? null
      : rng.bool(dormantProbability)
        ? rng.dateDaysAgo(now, 400, 91)
        : rng.dateDaysAgo(now, 30);

    const riskLevel = rng.weighted<RiskLevel>([
      ['none', 88], ['low', 6], ['medium', 4], ['high', 2],
    ]);
    const riskDetections = riskLevel === 'none' ? [] : rng.sample(RISK_DETECTIONS, rng.int(1, riskLevel === 'high' ? 3 : 2));

    const upn = isGuest
      ? `${slug(first)}.${slug(last)}_${rng.pick(PARTNER_DOMAINS)}#EXT#@${TENANT_DOMAIN}`
      : `${slug(first)}.${slug(last)}${i}@${TENANT_DOMAIN}`;

    users.push({
      id: id('usr', i),
      displayName: isGuest ? `${displayName} (Guest)` : displayName,
      userPrincipalName: upn,
      userType: isGuest ? 'Guest' : 'Member',
      department: bu.name,
      businessUnitId: bu.id,
      jobTitle: isGuest ? rng.pick(['External Consultant', 'Vendor Engineer', 'Auditor', 'Contract Developer', 'Agency Partner']) : rng.pick(JOB_TITLES),
      accountEnabled: rng.bool(isGuest ? 0.9 : 0.975),
      createdDateTime,
      lastSignInDateTime,
      lastPasswordChangeDateTime: rng.dateDaysAgo(now, 900, 1),
      authStrength,
      registeredMethods: methods,
      mfaRegistered,
      ssprRegistered: rng.bool(isGuest ? 0.4 : 0.9),
      riskLevel,
      riskDetections,
      onPremisesSyncEnabled: !isGuest && rng.bool(0.55),
      isPrivileged: false,
      sponsorId: null,
      invitationState: isGuest ? (rng.bool(0.88) ? 'accepted' : 'pendingAcceptance') : null,
      licenseSkus: [],
      groupIds: [],
      deviceIds: [],
    });
  }

  // Assign guest sponsors from the member population; some are deliberately orphaned.
  const members = users.filter((u) => u.userType === 'Member');
  for (const guest of users.filter((u) => u.userType === 'Guest')) {
    guest.sponsorId = rng.bool(0.72) ? rng.pick(members).id : null;
  }

  return users;
}

function buildGroups(rng: Rng, now: Date, users: User[]): Group[] {
  const groups: Group[] = [];
  const themes = [
    'Finance Systems', 'Clinical Records', 'Engineering Platform', 'Vendor Collaboration',
    'Executive Briefing', 'Payroll Data', 'R&D Protocols', 'Manufacturing Ops', 'Legal Hold',
    'Marketing Campaigns', 'Support Escalation', 'Data Science', 'Security Operations',
    'Procurement', 'Patient Portal', 'Quality Assurance',
  ];
  const qualifiers = ['Readers', 'Contributors', 'Owners', 'Admins', 'All Staff', 'Approvers', 'Elevated Access'];

  for (let i = 0; i < GROUP_COUNT; i += 1) {
    const displayName = `${rng.pick(themes)} — ${rng.pick(qualifiers)}`;
    const grantsPrivilegedAccess = /Admins|Owners|Elevated Access/.test(displayName) && rng.bool(0.55);
    const memberCount = rng.weighted([[rng.int(3, 15), 45], [rng.int(16, 80), 35], [rng.int(120, 600), 20]]);
    const members = rng.sample(users, memberCount);
    const ownerCount = rng.weighted([[0, 12], [1, 48], [2, 30], [3, 10]]);

    groups.push({
      id: id('grp', i),
      displayName,
      description: `Grants access to ${displayName.split(' — ')[0].toLowerCase()} resources.`,
      groupType: rng.weighted([['security', 60], ['microsoft365', 33], ['mail-enabled-security', 7]]),
      membershipRule: rng.bool(0.27) ? 'dynamic' : 'assigned',
      ownerIds: rng.sample(users.filter((u) => u.userType === 'Member'), ownerCount).map((u) => u.id),
      memberIds: members.map((u) => u.id),
      createdDateTime: rng.dateDaysAgo(now, 2200, 10),
      grantsPrivilegedAccess,
      isGovernedByAccessPackage: rng.bool(0.32),
      lastReviewedDateTime: rng.bool(0.48) ? rng.dateDaysAgo(now, 520, 5) : null,
    });
  }

  const byId = new Map(users.map((u) => [u.id, u]));
  for (const group of groups) {
    for (const memberId of group.memberIds) byId.get(memberId)?.groupIds.push(group.id);
  }

  return groups;
}

function buildCredentials(rng: Rng, now: Date, count: number): AppCredential[] {
  const credentials: AppCredential[] = [];
  for (let i = 0; i < count; i += 1) {
    const type = rng.weighted<AppCredential['type']>([['secret', 62], ['certificate', 28], ['federated', 10]]);
    const created = rng.dateDaysAgo(now, 1400, 20);
    // A meaningful slice of secrets are already expired or expiring imminently.
    const lifetimeDays = rng.weighted([[rng.int(-240, -1), 18], [rng.int(0, 30), 14], [rng.int(31, 180), 28], [rng.int(181, 730), 40]]);
    credentials.push({
      id: id('cred', rng.int(1, 99999)),
      type,
      displayName: type === 'federated' ? 'Workload identity federation' : `${type === 'secret' ? 'Client secret' : 'Signing certificate'} ${i + 1}`,
      createdDateTime: created,
      expiryDateTime: type === 'federated'
        ? rng.dateDaysAhead(now, 3650, 1800)
        : new Date(now.getTime() + lifetimeDays * 86_400_000).toISOString(),
    });
  }
  return credentials;
}

function buildApplications(rng: Rng, now: Date, users: User[]): Application[] {
  const apps: Application[] = [];
  const members = users.filter((u) => u.userType === 'Member');

  for (let i = 0; i < APP_COUNT; i += 1) {
    const category = rng.weighted<Application['category']>([
      ['saas', 32], ['line-of-business', 25], ['automation', 20], ['internal-api', 15], ['legacy', 8],
    ]);
    const isWorkloadIdentity = category === 'automation' || category === 'internal-api';
    const usesManagedIdentity = isWorkloadIdentity && rng.bool(0.38);

    const permissionCount = rng.int(1, 6);
    const permissions: AppPermission[] = [];
    for (let p = 0; p < permissionCount; p += 1) {
      const high = rng.bool(isWorkloadIdentity ? 0.32 : 0.16);
      permissions.push({
        value: high ? rng.pick(HIGH_PRIVILEGE_PERMISSIONS) : rng.pick(STANDARD_PERMISSIONS),
        type: isWorkloadIdentity ? 'Application' : rng.bool(0.4) ? 'Application' : 'Delegated',
        isHighPrivilege: high,
        consentType: high ? 'admin' : rng.bool(0.3) ? 'user' : 'admin',
        lastUsedDateTime: rng.bool(0.62) ? rng.dateDaysAgo(now, 90) : null,
      });
    }

    const ownerCount = rng.weighted([[0, 16], [1, 47], [2, 27], [3, 10]]);
    const lastSignIn = rng.weighted([[null, 9], [rng.dateDaysAgo(now, 30), 62], [rng.dateDaysAgo(now, 400, 91), 29]]);

    apps.push({
      id: id('app', i),
      displayName: `${rng.pick(APP_NAME_PARTS.prefix)} ${rng.pick(APP_NAME_PARTS.suffix)}`,
      appId: `${rng.int(10000000, 99999999)}-${rng.int(1000, 9999)}-${rng.int(1000, 9999)}-${rng.int(1000, 9999)}`,
      category,
      businessUnitId: rng.pick(BUSINESS_UNITS).id,
      ownerIds: rng.sample(members, ownerCount).map((u) => u.id),
      signInAudience: rng.weighted([['AzureADMyOrg', 74], ['AzureADMultipleOrgs', 20], ['AzureADandPersonalMicrosoftAccount', 6]]),
      credentials: usesManagedIdentity ? [] : buildCredentials(rng, now, rng.int(1, 3)),
      grantedPermissions: permissions,
      userAssignmentRequired: rng.bool(0.58),
      assignedUserCount: rng.weighted([[rng.int(1, 25), 40], [rng.int(26, 250), 40], [rng.int(251, 1500), 20]]),
      lastSignInDateTime: lastSignIn,
      usesManagedIdentity,
      isWorkloadIdentity,
      dataSensitivity: rng.weighted([['restricted', 16], ['confidential', 34], ['internal', 40], ['public', 10]]),
    });
  }

  return apps;
}

function buildDevices(rng: Rng, now: Date, users: User[]): Device[] {
  const devices: Device[] = [];
  const byId = new Map(users.map((u) => [u.id, u]));
  let n = 0;
  for (const user of users) {
    if (user.userType === 'Guest') continue;
    const count = rng.weighted([[1, 45], [2, 40], [3, 15]]);
    for (let d = 0; d < count; d += 1) {
      const joinType = rng.weighted<Device['joinType']>([
        ['entra-joined', 40], ['hybrid-joined', 33], ['registered', 19], ['unmanaged', 8],
      ]);
      const isManaged = joinType !== 'unmanaged' && joinType !== 'registered';
      const device: Device = {
        id: id('dev', n),
        displayName: `${user.displayName.split(' ')[0].toUpperCase()}-${rng.pick(['LT', 'WS', 'MBP', 'MOB'])}-${rng.int(1000, 9999)}`,
        ownerId: user.id,
        operatingSystem: rng.weighted([['Windows', 58], ['macOS', 16], ['iOS', 14], ['Android', 9], ['Linux', 3]]),
        joinType,
        isCompliant: isManaged ? rng.bool(0.91) : rng.bool(0.42),
        isManaged,
        lastSignInDateTime: rng.dateDaysAgo(now, 60),
      };
      devices.push(device);
      byId.get(user.id)?.deviceIds.push(device.id);
      n += 1;
    }
  }
  return devices;
}

function buildRoleAssignments(
  rng: Rng,
  now: Date,
  users: User[],
  groups: Group[],
  apps: Application[],
): RoleAssignment[] {
  const assignments: RoleAssignment[] = [];
  const members = users.filter((u) => u.userType === 'Member' && u.accountEnabled);
  const guests = users.filter((u) => u.userType === 'Guest');
  const privilegedGroups = groups.filter((g) => g.grantsPrivilegedAccess);
  let n = 0;

  const push = (partial: Omit<RoleAssignment, 'id'>) => {
    assignments.push({ id: id('ra', n), ...partial });
    n += 1;
  };

  for (const role of DIRECTORY_ROLES) {
    // Tier-0 roles are held by fewer principals but carry disproportionate risk.
    const userAssignmentCount = role.tier === 'tier-0' ? rng.int(4, 12) : role.tier === 'tier-1' ? rng.int(8, 22) : rng.int(15, 45);
    const holders = rng.sample(members, userAssignmentCount);

    for (const holder of holders) {
      const isEligible = rng.bool(role.tier === 'tier-0' ? 0.62 : 0.5);
      const isPermanent = !isEligible && rng.bool(role.tier === 'tier-0' ? 0.55 : 0.68);
      holder.isPrivileged = true;
      push({
        roleId: role.id,
        principalId: holder.id,
        principalType: 'user',
        assignmentType: isEligible ? 'eligible' : 'active',
        scope: rng.weighted([['tenant', 72], ['administrative-unit', 20], ['resource', 8]]),
        isPermanent,
        createdDateTime: rng.dateDaysAgo(now, 1500, 5),
        lastActivatedDateTime: isEligible ? (rng.bool(0.72) ? rng.dateDaysAgo(now, 180) : null) : null,
        activationCount90d: isEligible ? rng.weighted([[0, 30], [rng.int(1, 5), 45], [rng.int(6, 40), 25]]) : 0,
        requiresApproval: isEligible && rng.bool(role.tier === 'tier-0' ? 0.6 : 0.35),
        requiresMfaOnActivation: isEligible ? rng.bool(0.85) : rng.bool(0.3),
        justification: rng.bool(0.62) ? rng.pick([
          'Break-glass operational coverage',
          'Tier-1 support rotation',
          'Migration project access',
          'Vendor-managed service operations',
          'Audit remediation workstream',
        ]) : null,
      });
    }

    // Group-based role assignments (role-assignable groups).
    if (privilegedGroups.length && rng.bool(role.tier === 'tier-0' ? 0.3 : 0.45)) {
      const group = rng.pick(privilegedGroups);
      push({
        roleId: role.id,
        principalId: group.id,
        principalType: 'group',
        assignmentType: rng.bool(0.5) ? 'eligible' : 'active',
        scope: 'tenant',
        isPermanent: rng.bool(0.7),
        createdDateTime: rng.dateDaysAgo(now, 1100, 20),
        lastActivatedDateTime: null,
        activationCount90d: 0,
        requiresApproval: rng.bool(0.3),
        requiresMfaOnActivation: rng.bool(0.5),
        justification: 'Team-based administration',
      });
    }

    // Service principals holding directory roles — a commonly missed exposure.
    if (rng.bool(role.tier === 'tier-0' ? 0.35 : 0.3)) {
      const app = rng.pick(apps.filter((a) => a.isWorkloadIdentity)) ?? rng.pick(apps);
      push({
        roleId: role.id,
        principalId: app.id,
        principalType: 'servicePrincipal',
        assignmentType: 'active',
        scope: 'tenant',
        isPermanent: true,
        createdDateTime: rng.dateDaysAgo(now, 1300, 30),
        lastActivatedDateTime: null,
        activationCount90d: 0,
        requiresApproval: false,
        requiresMfaOnActivation: false,
        justification: 'Automation service account',
      });
    }
  }

  // A small number of guests hold directory roles — always worth surfacing.
  for (const guest of rng.sample(guests, rng.int(2, 5))) {
    guest.isPrivileged = true;
    push({
      roleId: rng.pick(DIRECTORY_ROLES.filter((r) => r.tier !== 'tier-2')).id,
      principalId: guest.id,
      principalType: 'user',
      assignmentType: rng.bool(0.5) ? 'active' : 'eligible',
      scope: 'tenant',
      isPermanent: rng.bool(0.6),
      createdDateTime: rng.dateDaysAgo(now, 800, 30),
      lastActivatedDateTime: rng.bool(0.4) ? rng.dateDaysAgo(now, 200) : null,
      activationCount90d: rng.int(0, 4),
      requiresApproval: rng.bool(0.3),
      requiresMfaOnActivation: rng.bool(0.5),
      justification: 'Managed service provider administration',
    });
  }

  return assignments;
}

function buildConditionalAccess(rng: Rng, now: Date, groups: Group[]): ConditionalAccessPolicy[] {
  const specs: Array<Partial<ConditionalAccessPolicy> & { displayName: string }> = [
    { displayName: 'CA001 — Require MFA for all users', includeUsers: 'all', targetsAllApps: true, grantControls: ['Require multifactor authentication'], state: 'enabled' },
    { displayName: 'CA002 — Block legacy authentication', includeUsers: 'all', targetsAllApps: true, grantControls: ['Block access'], blocksLegacyAuth: true, state: 'enabled' },
    { displayName: 'CA003 — Require phishing-resistant MFA for admins', includeUsers: 'roles', targetsAllApps: true, grantControls: ['Require authentication strength: Phishing-resistant MFA'], requiresPhishingResistant: true, state: 'enabled' },
    { displayName: 'CA004 — Require compliant device for Office 365', includeUsers: 'all', targetsAllApps: false, grantControls: ['Require device to be marked as compliant'], requiresCompliantDevice: true, state: 'enabled' },
    { displayName: 'CA005 — Require MFA for guest access', includeUsers: 'group', targetsAllApps: true, grantControls: ['Require multifactor authentication'], state: 'enabled' },
    { displayName: 'CA006 — Block access from unsupported countries', includeUsers: 'all', targetsAllApps: true, grantControls: ['Block access'], state: 'enabled' },
    { displayName: 'CA007 — Require MFA for Azure management', includeUsers: 'all', targetsAllApps: false, grantControls: ['Require multifactor authentication'], state: 'enabled' },
    { displayName: 'CA008 — Sign-in risk remediation', includeUsers: 'all', targetsAllApps: true, grantControls: ['Require multifactor authentication', 'Require password change'], state: 'enabledForReportingButNotEnforced' },
    { displayName: 'CA009 — User risk policy', includeUsers: 'all', targetsAllApps: true, grantControls: ['Require password change'], state: 'enabledForReportingButNotEnforced' },
    { displayName: 'CA010 — Require terms of use for partners', includeUsers: 'group', targetsAllApps: false, grantControls: ['Require terms of use'], state: 'enabled' },
    { displayName: 'CA011 — Session controls for unmanaged devices', includeUsers: 'all', targetsAllApps: false, grantControls: ['Use app enforced restrictions'], state: 'enabled' },
    { displayName: 'CA012 — Legacy VPN exception (temporary)', includeUsers: 'group', targetsAllApps: false, grantControls: ['Require multifactor authentication'], state: 'disabled' },
    { displayName: 'CA013 — Device code flow restriction', includeUsers: 'all', targetsAllApps: true, grantControls: ['Block access'], state: 'enabledForReportingButNotEnforced' },
    { displayName: 'CA014 — Require MFA for privileged workstations', includeUsers: 'group', targetsAllApps: false, grantControls: ['Require device to be marked as compliant'], requiresCompliantDevice: true, state: 'enabled' },
  ];

  return specs.map((spec, i) => ({
    id: id('cap', i),
    displayName: spec.displayName,
    state: spec.state ?? 'enabled',
    includeUsers: spec.includeUsers ?? 'all',
    excludedUserCount: rng.weighted([[0, 30], [rng.int(1, 6), 40], [rng.int(7, 35), 22], [rng.int(36, 180), 8]]),
    excludedGroupIds: rng.sample(groups, rng.int(0, 3)).map((g) => g.id),
    targetsAllApps: spec.targetsAllApps ?? false,
    grantControls: spec.grantControls ?? [],
    blocksLegacyAuth: spec.blocksLegacyAuth ?? false,
    requiresPhishingResistant: spec.requiresPhishingResistant ?? false,
    requiresCompliantDevice: spec.requiresCompliantDevice ?? false,
    createdDateTime: rng.dateDaysAgo(now, 1800, 200),
    lastModifiedDateTime: rng.dateDaysAgo(now, 400, 1),
  }));
}

function buildSignIns(rng: Rng, now: Date, users: User[], apps: Application[]): SignIn[] {
  const signIns: SignIn[] = [];
  const activeUsers = users.filter((u) => u.lastSignInDateTime !== null);
  const legacyApps = apps.filter((a) => a.category === 'legacy');

  for (let i = 0; i < SIGN_IN_COUNT; i += 1) {
    const user = rng.pick(activeUsers);
    const useLegacyApp = legacyApps.length > 0 && rng.bool(0.06);
    const app = useLegacyApp ? rng.pick(legacyApps) : rng.pick(apps);
    const isLegacyAuth = useLegacyApp ? rng.bool(0.55) : rng.bool(0.015);

    const risky = rng.bool(user.riskLevel === 'high' ? 0.45 : user.riskLevel === 'medium' ? 0.2 : 0.035);
    const riskLevel: RiskLevel = risky ? rng.weighted([['low', 45], ['medium', 35], ['high', 20]]) : 'none';
    const status = rng.weighted<SignIn['status']>(
      risky ? [['success', 46], ['failure', 42], ['interrupted', 12]] : [['success', 88], ['failure', 9], ['interrupted', 3]],
    );

    const mfaSatisfied = isLegacyAuth ? false : user.mfaRegistered && rng.bool(0.93);

    signIns.push({
      id: id('sin', i),
      userId: user.id,
      appId: app.id,
      createdDateTime: rng.dateDaysAgo(now, 90),
      status,
      failureReason: status === 'failure'
        ? rng.pick([
            'Invalid username or password',
            'Conditional Access policy blocked the request',
            'MFA required but not satisfied',
            'Account is locked',
            'Legacy authentication protocol blocked',
          ])
        : null,
      clientApp: isLegacyAuth
        ? rng.pick(['exchangeActiveSync', 'other'])
        : rng.weighted([['browser', 54], ['mobileAppsAndDesktopClients', 44], ['other', 2]]),
      isLegacyAuth,
      mfaSatisfied,
      conditionalAccessStatus: isLegacyAuth
        ? rng.weighted([['failure', 55], ['notApplied', 30], ['success', 15]])
        : rng.weighted([['success', 82], ['notApplied', 13], ['failure', 5]]),
      riskLevel,
      riskEventTypes: risky ? rng.sample(RISK_DETECTIONS, rng.int(1, 2)) : [],
      location: risky && rng.bool(0.55) ? rng.pick(ANOMALOUS_LOCATIONS) : rng.pick(LOCATIONS),
      ipAddress: `${rng.int(11, 223)}.${rng.int(0, 255)}.${rng.int(0, 255)}.${rng.int(1, 254)}`,
      deviceCompliant: rng.bool(0.82),
    });
  }

  return signIns.sort((a, b) => a.createdDateTime.localeCompare(b.createdDateTime));
}

function buildAccessPackages(rng: Rng, groups: Group[]): AccessPackage[] {
  const packages: AccessPackage[] = [];
  const names = [
    'Clinical Systems — Contractor Bundle', 'Finance Close Access', 'Engineering Platform Onboarding',
    'Vendor Collaboration Workspace', 'Payroll Analyst Access', 'R&D Protocol Library',
    'Manufacturing Floor Systems', 'Legal eDiscovery Access', 'Sales CRM Elevated',
    'Data Science Sandbox', 'Security Operations Toolkit', 'Procurement Approver Bundle',
    'Patient Portal Support', 'Quality Audit Reviewer', 'Executive Reporting Suite',
    'Partner API Integration', 'Temporary Break-Glass Bundle', 'Intern Baseline Access',
  ];

  names.forEach((displayName, i) => {
    packages.push({
      id: id('acp', i),
      displayName,
      businessUnitId: rng.pick(BUSINESS_UNITS).id,
      resourceGroupIds: rng.sample(groups, rng.int(1, 5)).map((g) => g.id),
      approvalRequired: rng.bool(0.74),
      expirationDays: rng.weighted([[null, 26], [30, 16], [90, 24], [180, 20], [365, 14]]),
      requiresAccessReview: rng.bool(0.6),
      activeAssignments: rng.int(4, 320),
      pendingRequests: rng.weighted([[0, 45], [rng.int(1, 8), 40], [rng.int(9, 60), 15]]),
    });
  });

  return packages;
}

function buildAccessReviews(rng: Rng, now: Date, groups: Group[], apps: Application[]): AccessReview[] {
  const reviews: AccessReview[] = [];
  const targets: Array<{ type: AccessReview['scopeType']; id: string; name: string }> = [
    ...rng.sample(groups, 26).map((g) => ({ type: 'group' as const, id: g.id, name: g.displayName })),
    ...rng.sample(apps, 14).map((a) => ({ type: 'application' as const, id: a.id, name: a.displayName })),
    { type: 'guest' as const, id: 'all-guests', name: 'All guest users' },
    { type: 'role' as const, id: 'role-ga', name: 'Global Administrator' },
    { type: 'role' as const, id: 'role-aa', name: 'Application Administrator' },
    { type: 'role' as const, id: 'role-sa', name: 'Security Administrator' },
  ];

  targets.forEach((target, i) => {
    const status = rng.weighted<AccessReview['status']>([
      ['completed', 44], ['in-progress', 23], ['overdue', 21], ['not-started', 12],
    ]);
    const decisionsTotal = rng.int(6, 340);
    const completionRatio = status === 'completed' ? 1 : status === 'in-progress' ? rng.float(0.2, 0.85) : status === 'overdue' ? rng.float(0, 0.6) : 0;
    const reviewerType = rng.weighted<AccessReview['reviewerType']>([
      ['group-owner', 36], ['manager', 30], ['self', 22], ['admin', 12],
    ]);

    reviews.push({
      id: id('rev', i),
      displayName: `${target.name} — periodic access review`,
      scopeType: target.type,
      scopeId: target.id,
      scopeName: target.name,
      status,
      startDateTime: rng.dateDaysAgo(now, 200, 10),
      dueDateTime: status === 'overdue' ? rng.dateDaysAgo(now, 90, 3) : rng.dateDaysAhead(now, 60, 1),
      reviewerType,
      decisionsTotal,
      decisionsMade: Math.round(decisionsTotal * completionRatio),
      // Self-review consistently produces the highest approve-all behaviour.
      rubberStampRate: reviewerType === 'self' ? rng.float(0.82, 0.99) : rng.float(0.35, 0.92),
      recurrence: rng.weighted([['one-time', 20], ['monthly', 10], ['quarterly', 38], ['semi-annual', 22], ['annual', 10]]),
    });
  });

  return reviews;
}

function buildLicenses(rng: Rng, users: User[]): LicenseSku[] {
  const catalog: Array<[string, string, number]> = [
    ['ENTERPRISEPREMIUM', 'Microsoft 365 E5', 57],
    ['SPE_E3', 'Microsoft 365 E3', 36],
    ['AAD_PREMIUM_P2', 'Entra ID P2', 9],
    ['EMS', 'Enterprise Mobility + Security E3', 10.6],
    ['IDENTITY_GOVERNANCE', 'Entra ID Governance', 7],
    ['POWER_BI_PRO', 'Power BI Pro', 14],
  ];

  const enabled = users.filter((u) => u.accountEnabled && u.userType === 'Member').length;

  return catalog.map(([skuId, displayName, unitCostPerMonth], index) => {
    const assigned = index === 0 ? Math.round(enabled * 0.52) : Math.round(enabled * rng.float(0.08, 0.4));
    const purchased = Math.round(assigned * rng.float(1.05, 1.35));
    return {
      skuId,
      displayName,
      purchased,
      assigned,
      dormant: Math.round(assigned * rng.float(0.04, 0.17)),
      unitCostPerMonth,
    };
  });
}

/** Builds the full synthetic tenant. Deterministic for a given seed. */
export function generateTenant(seed = 20260925): TenantDataset {
  const rng = new Rng(seed);
  const now = new Date('2026-09-25T00:00:00.000Z');

  const users = buildUsers(rng, now);
  const groups = buildGroups(rng, now, users);
  const applications = buildApplications(rng, now, users);
  const devices = buildDevices(rng, now, users);
  const roleAssignments = buildRoleAssignments(rng, now, users, groups, applications);
  const conditionalAccessPolicies = buildConditionalAccess(rng, now, groups);
  const signIns = buildSignIns(rng, now, users, applications);
  const accessPackages = buildAccessPackages(rng, groups);
  const accessReviews = buildAccessReviews(rng, now, groups, applications);
  const licenses = buildLicenses(rng, users);

  const businessUnits = BUSINESS_UNITS.map((bu) => ({
    ...bu,
    headcount: users.filter((u) => u.businessUnitId === bu.id).length,
  }));

  // Licence assignment is derived so headline counts stay internally consistent.
  const skuPool = licenses.map((l) => l.skuId);
  for (const user of users) {
    if (user.userType === 'Guest' || !user.accountEnabled) continue;
    user.licenseSkus = rng.sample(skuPool, rng.weighted([[1, 45], [2, 38], [3, 17]]));
  }

  return {
    tenant: {
      displayName: 'Cascadia Health Group',
      tenantId: 'c7d41f8e-2b6a-4d19-9f03-8ae51b7c2d44',
      generatedAt: now.toISOString(),
      industry: 'Healthcare & Life Sciences',
      employeeCount: users.filter((u) => u.userType === 'Member').length,
    },
    businessUnits,
    users,
    groups,
    applications,
    devices,
    roles: DIRECTORY_ROLES,
    roleAssignments,
    conditionalAccessPolicies,
    signIns,
    accessPackages,
    accessReviews,
    licenses,
  };
}

export { DIRECTORY_ROLES, BUSINESS_UNITS };
