/** What the server answers, typed. Field names as the API sends them (camelCase). */

export type Mode = 'family' | 'office';

export type Passkey = { id: string; name: string; created: string; lastUsed: string | null };

export type AppPassword = {
  id: string;
  name: string;
  created: string;
  lastUsed: string | null;
  lastIp: string | null;
};

export type AttributeKind = 'text' | 'number' | 'date' | 'choice';

export type AttributeDef = {
  name: string;
  label: string;
  kind: AttributeKind;
  choices: string[];
  selfEditable: boolean;
};

/** A person as the lists show them. */
export type Person = {
  id: string;
  username: string;
  displayName: string;
  givenName: string | null;
  familyName: string | null;
  email: string | null;
  emailVerified: boolean;
  language: string;
  disabled: boolean;
  managed: boolean;
  hasPassword: boolean;
  hasTotp: boolean;
  expires: string | null;
  uidNumber: number;
  loginShell: string | null;
  homeDirectory: string | null;
  created: string;
  updated: string;
  lastLogin: string | null;
  deleted: string | null;
  admin: boolean;
  /** Groups they are directly in. */
  groups: string[];
  avatar: string | null;
  /** In the list only: whether they look after anybody. */
  manager?: boolean;
};

/** Days are a bit mask: Monday 1, Tuesday 2, … Sunday 64. Minutes after midnight, end up to 1440. */
export type Window = { days: number; start: number; end: number; app?: string | null };

export type Session = {
  id: string;
  created: string;
  lastSeen: string;
  expires: string;
  ip: string | null;
  device: string;
  userAgent: string | null;
  methods: string[];
  current: boolean;
};

export type PersonDetail = Person & {
  /** Every group they are in, through other groups too. */
  memberOf: string[];
  passkeys: Passkey[];
  recoveryCodesLeft: number;
  appPasswords: number;
  sessions: Session[];
  windows: Window[];
  attributes: Record<string, string>;
  managers: string[];
  manages: { people: string[]; groups: string[] };
  canEdit: 'all' | 'managed';
};

export type Me = Omit<Person, 'manager'> & {
  passkeys: Passkey[];
  recoveryCodesLeft: number;
  appPasswords: AppPassword[];
  memberOf: { id: string; name: string; builtin: string | null; direct: boolean }[];
  attributes: (AttributeDef & { value: string | null })[];
  needsMfa: boolean;
  restricted: boolean;
  fresh: boolean;
  manager: boolean;
  ownsGroups: string[];
  server: {
    organization: string;
    mode: Mode;
    setupDone: boolean;
    mail: boolean;
    passwordMinLength: number;
    version: string;
  };
};

export type Group = {
  id: string;
  name: string;
  description: string;
  builtin: string | null;
  gidNumber: number;
  requireMfa: boolean;
  ldapAppPasswordsOnly: boolean;
  members: number;
  owners: string[];
  owner: boolean;
  created: string;
  updated: string;
};

export type GroupDetail = Group & {
  people: string[];
  groups: string[];
  everybody: string[];
  windows: Window[];
};

export type LinkResult = {
  purpose: 'setup' | 'reset';
  link: string;
  expires: string;
  mailed: string | null;
};

export type Invitation = {
  id: string;
  email: string | null;
  displayName: string | null;
  groups: string[];
  admin: boolean;
  managed: boolean;
  managers: string[];
  createdBy: string | null;
  created: string;
  expires: string;
  expired: boolean;
  /** Only right after making or renewing it. */
  link?: string;
  mailed?: string | null;
};

export type LinkInfo = {
  purpose: 'invite' | 'setup' | 'reset' | 'verify';
  expires: string;
  organization: string;
  mode: Mode;
  passwordMinLength: number;
  email?: string | null;
  displayName?: string | null;
  username?: string;
  managed?: boolean;
  invitedBy?: string | null;
  language?: string | null;
  hasPassword?: boolean;
};

export type Smtp = {
  host: string;
  port: number;
  security: 'tls' | 'starttls' | 'none';
  username: string | null;
  from: string;
  fromName: string | null;
  passwordSet?: boolean;
};

export type Settings = {
  setupDone: boolean;
  organization: string;
  mode: Mode;
  defaultLanguage: 'de' | 'en';
  timezone: string;
  smtp: Smtp | null;
  passwordMinLength: number;
  hibp: boolean;
  sessionHours: number;
  rememberDays: number;
  newDeviceMail: boolean;
  lockoutAttempts: number;
  invitationDays: number;
};

export type Overview = {
  version: string;
  uptimeSeconds: number;
  people: number;
  disabled: number;
  managed: number;
  withTotp: number;
  trash: number;
  admins: number;
  groups: number;
  invitations: number;
  failedLoginsDay: number;
  databaseBytes: number;
  backups: number;
  lastBackup: string | null;
  mail: boolean;
  update: {
    checked: string | null;
    newer: string | null;
    url: string | null;
    commits: number | null;
    error: string | null;
    channel: string | null;
    commit: string | null;
  };
};

export type AuditEvent = {
  id: number;
  time: string;
  kind: string;
  actor: string | null;
  person: string | null;
  target: string | null;
  ip: string | null;
  detail: Record<string, unknown> | null;
};

export type LogLine = { seq: number; time: string; level: string; target: string; message: string };

export type Backup = { name: string; bytes: number; time: string | null };

export type ApiToken = {
  id: string;
  name: string;
  readOnly: boolean;
  createdBy: string | null;
  created: string;
  expires: string | null;
  lastUsed: string | null;
  secret?: string;
};

export type ImportReport = {
  people: { created: string[]; skipped: string[]; failed: { username: string; error: string }[] };
  groups: { created: string[]; skipped: string[] };
  dryRun: boolean;
};

// ── Apps (OpenID Connect) ─────────────────────────────────

export type GrantType =
  | 'authorization_code'
  | 'refresh_token'
  | 'client_credentials'
  | 'urn:ietf:params:oauth:grant-type:device_code';

/** An app as the admin portal sees it. */
export type App = {
  id: string;
  clientId: string;
  name: string;
  description: string;
  template: string | null;
  public: boolean;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  backchannelLogoutUri: string | null;
  grantTypes: GrantType[];
  tokenAuthMethod: 'client_secret_basic' | 'client_secret_post' | 'none';
  idTokenAlg: 'RS256' | 'ES256';
  consent: boolean;
  requirePkce: boolean;
  allowedGroups: string[];
  requireMfa: boolean;
  roles: { group: string; role: string }[];
  accessTokenMinutes: number;
  refreshTokenDays: number;
  launchUrl: string | null;
  disabled: boolean;
  created: string;
  updated: string;
  /** On the detail and right after making it. */
  issuer?: string;
  /** What to set on the app's side, from its template. */
  notes?: string;
  /** Only right after making it. */
  clientSecret?: string | null;
};

export type AppTemplate = {
  key: string;
  name: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  scopes: string;
  public: boolean;
  launchUrl: string;
  notes: string;
};

export type RegistrationToken = {
  id: string;
  name: string;
  usesLeft: number;
  created?: string;
  expires: string;
  createdBy?: string | null;
  /** Only right after making it. */
  secret?: string;
};

/** "My apps" in the portal. */
export type MyApps = {
  apps: {
    id: string;
    name: string;
    description: string;
    launchUrl: string;
    template: string | null;
  }[];
  connected: {
    id: string;
    app: string;
    appId: string;
    scopes: string[];
    created: string;
    lastUsed: string | null;
  }[];
};

export type ConsentInfo = {
  app: { name: string; description: string; launchUrl: string | null; template: string | null };
  scopes: string[];
  redirectHost: string;
};

export type DeviceInfo = {
  app: { name: string; description: string };
  scopes: string[];
  code: string;
};
