/**
 * Domain model for the Identity Intelligence platform.
 *
 * Shapes are intentionally modelled on Microsoft Entra ID / Microsoft Graph
 * resources (users, groups, servicePrincipals, directoryRoles, signIns,
 * conditionalAccessPolicies, accessPackages, accessReviews, PIM eligibility)
 * so the synthetic dataset can later be swapped for live Graph data without
 * changing the analytics or presentation layers.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type Pillar =
  | 'identity-risk'
  | 'privileged-access'
  | 'governance'
  | 'workload-identity'
  | 'resilience';

export type UserType = 'Member' | 'Guest';

export type AuthStrength = 'phishing-resistant' | 'strong-mfa' | 'weak-mfa' | 'password-only';

export type RiskLevel = 'none' | 'low' | 'medium' | 'high';

export interface BusinessUnit {
  id: string;
  name: string;
  region: string;
  headcount: number;
  executiveOwner: string;
  criticality: 'tier-1' | 'tier-2' | 'tier-3';
}

export interface User {
  id: string;
  displayName: string;
  userPrincipalName: string;
  userType: UserType;
  department: string;
  businessUnitId: string;
  jobTitle: string;
  accountEnabled: boolean;
  createdDateTime: string;
  lastSignInDateTime: string | null;
  lastPasswordChangeDateTime: string;
  /** Strongest authentication method registered for the account. */
  authStrength: AuthStrength;
  registeredMethods: string[];
  mfaRegistered: boolean;
  ssprRegistered: boolean;
  riskLevel: RiskLevel;
  riskDetections: string[];
  onPremisesSyncEnabled: boolean;
  isPrivileged: boolean;
  /** Guests only: sponsoring internal user id. */
  sponsorId: string | null;
  invitationState: 'accepted' | 'pendingAcceptance' | null;
  licenseSkus: string[];
  groupIds: string[];
  deviceIds: string[];
}

export interface Group {
  id: string;
  displayName: string;
  description: string;
  groupType: 'security' | 'microsoft365' | 'mail-enabled-security';
  membershipRule: 'assigned' | 'dynamic';
  ownerIds: string[];
  memberIds: string[];
  createdDateTime: string;
  /** Group confers access to privileged roles or sensitive applications. */
  grantsPrivilegedAccess: boolean;
  isGovernedByAccessPackage: boolean;
  lastReviewedDateTime: string | null;
}

export interface AppCredential {
  id: string;
  type: 'secret' | 'certificate' | 'federated';
  displayName: string;
  createdDateTime: string;
  expiryDateTime: string;
}

export interface AppPermission {
  value: string;
  type: 'Application' | 'Delegated';
  /** Consent granting broad tenant-wide data access. */
  isHighPrivilege: boolean;
  consentType: 'admin' | 'user';
  lastUsedDateTime: string | null;
}

export interface Application {
  id: string;
  displayName: string;
  appId: string;
  category: 'line-of-business' | 'saas' | 'internal-api' | 'automation' | 'legacy';
  businessUnitId: string;
  ownerIds: string[];
  signInAudience: 'AzureADMyOrg' | 'AzureADMultipleOrgs' | 'AzureADandPersonalMicrosoftAccount';
  credentials: AppCredential[];
  grantedPermissions: AppPermission[];
  userAssignmentRequired: boolean;
  assignedUserCount: number;
  lastSignInDateTime: string | null;
  usesManagedIdentity: boolean;
  isWorkloadIdentity: boolean;
  dataSensitivity: 'restricted' | 'confidential' | 'internal' | 'public';
}

export interface Device {
  id: string;
  displayName: string;
  ownerId: string;
  operatingSystem: 'Windows' | 'macOS' | 'iOS' | 'Android' | 'Linux';
  joinType: 'entra-joined' | 'hybrid-joined' | 'registered' | 'unmanaged';
  isCompliant: boolean;
  isManaged: boolean;
  lastSignInDateTime: string;
}

export type RoleScope = 'tenant' | 'administrative-unit' | 'resource';

export interface DirectoryRole {
  id: string;
  displayName: string;
  /** Tier-0 roles can escalate to Global Administrator or read all tenant data. */
  tier: 'tier-0' | 'tier-1' | 'tier-2';
  description: string;
}

export interface RoleAssignment {
  id: string;
  roleId: string;
  principalId: string;
  principalType: 'user' | 'group' | 'servicePrincipal';
  assignmentType: 'active' | 'eligible';
  scope: RoleScope;
  /** Permanent (non-expiring) assignments are a key privileged-access risk signal. */
  isPermanent: boolean;
  createdDateTime: string;
  lastActivatedDateTime: string | null;
  activationCount90d: number;
  requiresApproval: boolean;
  requiresMfaOnActivation: boolean;
  justification: string | null;
}

export interface ConditionalAccessPolicy {
  id: string;
  displayName: string;
  state: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced';
  includeUsers: 'all' | 'group' | 'roles';
  excludedUserCount: number;
  excludedGroupIds: string[];
  targetsAllApps: boolean;
  grantControls: string[];
  blocksLegacyAuth: boolean;
  requiresPhishingResistant: boolean;
  requiresCompliantDevice: boolean;
  createdDateTime: string;
  lastModifiedDateTime: string;
}

export interface SignIn {
  id: string;
  userId: string;
  appId: string;
  createdDateTime: string;
  status: 'success' | 'failure' | 'interrupted';
  failureReason: string | null;
  clientApp: 'browser' | 'mobileAppsAndDesktopClients' | 'exchangeActiveSync' | 'other';
  isLegacyAuth: boolean;
  mfaSatisfied: boolean;
  conditionalAccessStatus: 'success' | 'failure' | 'notApplied';
  riskLevel: RiskLevel;
  riskEventTypes: string[];
  location: string;
  ipAddress: string;
  deviceCompliant: boolean;
}

export interface AccessPackage {
  id: string;
  displayName: string;
  businessUnitId: string;
  resourceGroupIds: string[];
  approvalRequired: boolean;
  /** Access expires automatically after this many days; null means never. */
  expirationDays: number | null;
  requiresAccessReview: boolean;
  activeAssignments: number;
  pendingRequests: number;
}

export interface AccessReview {
  id: string;
  displayName: string;
  scopeType: 'group' | 'application' | 'role' | 'guest';
  scopeId: string;
  scopeName: string;
  status: 'completed' | 'in-progress' | 'overdue' | 'not-started';
  startDateTime: string;
  dueDateTime: string;
  reviewerType: 'self' | 'manager' | 'group-owner' | 'admin';
  decisionsTotal: number;
  decisionsMade: number;
  /** Share of decisions approved with no change — a proxy for rubber-stamping. */
  rubberStampRate: number;
  recurrence: 'one-time' | 'monthly' | 'quarterly' | 'semi-annual' | 'annual';
}

export interface LicenseSku {
  skuId: string;
  displayName: string;
  purchased: number;
  assigned: number;
  /** Assigned but unused in the last 60 days. */
  dormant: number;
  unitCostPerMonth: number;
}

export interface Tenant {
  displayName: string;
  tenantId: string;
  generatedAt: string;
  industry: string;
  employeeCount: number;
}

export interface TenantDataset {
  tenant: Tenant;
  businessUnits: BusinessUnit[];
  users: User[];
  groups: Group[];
  applications: Application[];
  devices: Device[];
  roles: DirectoryRole[];
  roleAssignments: RoleAssignment[];
  conditionalAccessPolicies: ConditionalAccessPolicy[];
  signIns: SignIn[];
  accessPackages: AccessPackage[];
  accessReviews: AccessReview[];
  licenses: LicenseSku[];
}

export interface FindingEntity {
  id: string;
  name: string;
  detail: string;
}

/** A scored, explainable detection produced by the analytics engine. */
export interface Finding {
  id: string;
  title: string;
  pillar: Pillar;
  severity: Severity;
  /** 0-100 weighted contribution to the identity risk index. */
  riskScore: number;
  affectedCount: number;
  /** What leaders should understand about the consequence. */
  businessImpact: string;
  evidence: string;
  recommendation: string;
  frameworks: string[];
  effort: 'low' | 'medium' | 'high';
  affectedEntities: FindingEntity[];
  trend: number[];
}

export interface PillarScore {
  pillar: Pillar;
  label: string;
  description: string;
  score: number;
  grade: string;
  findingCount: number;
  criticalCount: number;
  trend: number[];
}
