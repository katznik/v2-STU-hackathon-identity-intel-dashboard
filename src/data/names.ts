export const FIRST_NAMES = [
  'Avery', 'Jordan', 'Priya', 'Mateo', 'Ingrid', 'Samuel', 'Noor', 'Kenji', 'Lucia', 'Dante',
  'Freya', 'Omar', 'Hana', 'Tobias', 'Sofia', 'Ravi', 'Elena', 'Marcus', 'Yara', 'Colin',
  'Anika', 'Theo', 'Rosa', 'Liam', 'Mei', 'Nikolai', 'Aisha', 'Bruno', 'Clara', 'Diego',
  'Esme', 'Farid', 'Greta', 'Hugo', 'Isla', 'Jonas', 'Kira', 'Lars', 'Maya', 'Nadia',
  'Oscar', 'Paloma', 'Quinn', 'Rafael', 'Sara', 'Tomas', 'Uma', 'Viktor', 'Wren', 'Xiomara',
];

export const LAST_NAMES = [
  'Whitfield', 'Okafor', 'Ramachandran', 'Delgado', 'Lindqvist', 'Abara', 'Haddad', 'Watanabe',
  'Moreau', 'Castellanos', 'Nyberg', 'Barakat', 'Kimura', 'Ferreira', 'Novak', 'Iyer', 'Petrov',
  'Sandoval', 'Osei', 'Fitzgerald', 'Kowalski', 'Mbeki', 'Ricci', 'Ahmadi', 'Lindgren', 'Duarte',
  'Farrow', 'Guerrero', 'Hollande', 'Ibarra', 'Jansen', 'Kaur', 'Lombardi', 'Marchetti',
  'Nakamura', 'Ortega', 'Pemberton', 'Quintero', 'Rasmussen', 'Solberg', 'Thackeray', 'Ulrich',
  'Vasquez', 'Wallace', 'Yilmaz', 'Zarate',
];

export const PARTNER_DOMAINS = [
  'northwind-logistics.com',
  'fabrikam-consulting.com',
  'contosolegal.co.uk',
  'adatum-analytics.io',
  'woodgrove-audit.com',
  'tailspin-msp.net',
  'proseware-dev.com',
  'litware-marketing.com',
];

export const LOCATIONS = [
  'Seattle, US', 'Austin, US', 'Toronto, CA', 'London, GB', 'Dublin, IE', 'Munich, DE',
  'Warsaw, PL', 'Bengaluru, IN', 'Singapore, SG', 'Sydney, AU', 'São Paulo, BR', 'Tokyo, JP',
];

/** Locations that do not map to any office or approved remote region. */
export const ANOMALOUS_LOCATIONS = [
  'Unknown', 'Lagos, NG', 'Kyiv, UA', 'Caracas, VE', 'Hanoi, VN', 'Tehran, IR',
];

export const JOB_TITLES = [
  'Software Engineer', 'Senior Software Engineer', 'Principal Engineer', 'Product Manager',
  'Program Manager', 'Data Analyst', 'Financial Analyst', 'Account Executive', 'Sales Director',
  'HR Business Partner', 'Recruiter', 'Controller', 'Treasury Analyst', 'Site Reliability Engineer',
  'Security Analyst', 'IT Support Specialist', 'Marketing Manager', 'Legal Counsel',
  'Supply Chain Planner', 'Plant Supervisor', 'Customer Success Manager', 'Executive Assistant',
];

export const HIGH_PRIVILEGE_PERMISSIONS = [
  'Directory.ReadWrite.All',
  'RoleManagement.ReadWrite.Directory',
  'AppRoleAssignment.ReadWrite.All',
  'Mail.ReadWrite',
  'Files.ReadWrite.All',
  'User.ReadWrite.All',
  'Application.ReadWrite.All',
  'Sites.FullControl.All',
];

export const STANDARD_PERMISSIONS = [
  'User.Read',
  'User.ReadBasic.All',
  'Group.Read.All',
  'Mail.Send',
  'Calendars.Read',
  'Files.Read.All',
  'offline_access',
  'Reports.Read.All',
];

export const RISK_DETECTIONS = [
  'unfamiliarFeatures',
  'anonymizedIPAddress',
  'impossibleTravel',
  'maliciousIPAddress',
  'leakedCredentials',
  'passwordSpray',
  'suspiciousInboxManipulation',
  'tokenIssuerAnomaly',
  'mfaFatigue',
];

export const APP_NAME_PARTS = {
  prefix: [
    'Atlas', 'Beacon', 'Cascade', 'Delta', 'Ember', 'Forge', 'Granite', 'Harbor', 'Ionic',
    'Juniper', 'Keystone', 'Lumen', 'Meridian', 'Nimbus', 'Orbit', 'Pinnacle', 'Quarry',
    'Redwood', 'Summit', 'Tessera', 'Vantage', 'Windward',
  ],
  suffix: [
    'Billing', 'CRM', 'Payroll', 'Analytics', 'Portal', 'Gateway', 'Scheduler', 'Vault',
    'Connector', 'Sync', 'Reporting', 'Workbench', 'Ledger', 'Registry', 'Automation', 'Hub',
  ],
};
