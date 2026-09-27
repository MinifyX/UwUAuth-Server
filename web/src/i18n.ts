// The web app speaks German and English. Every text lives here, in both, under the same key:
// i18n.test.ts fails when one language has a key the other does not.

export type Language = 'de' | 'en';

export const texts = {
  de: {
    tagline: 'Personen und Gruppen an einer Stelle, und jede App meldet sich darüber an.',
    checking: 'Frage den Server …',
    running: 'Läuft',
    unwell: 'Der Server antwortet, aber die Datenbank nicht.',
    unreachable: 'Der Server antwortet nicht.',
    version: 'Version',
    comingTitle: 'Hier entsteht UwUAuth',
    comingBody:
      'Diese Version ist das Gerüst: Server, Datenbank, Backups und Updates laufen schon. Als Nächstes kommt die Benutzerverwaltung mit Einladungen, Passkeys und Konten für Kinder, danach OpenID Connect, LDAP im Stil von Active Directory, die Kopplung mit der UwUSuite, Forward-Auth, SAML, SCIM und RADIUS.',
    plan: 'Zum Plan',
  },
  en: {
    tagline: 'People and groups in one place, and every app signs in through it.',
    checking: 'Asking the server …',
    running: 'Running',
    unwell: 'The server answers, but its database does not.',
    unreachable: 'The server does not answer.',
    version: 'Version',
    comingTitle: 'UwUAuth is on its way',
    comingBody:
      'This version is the frame: server, database, backups and updates already work. Next comes user management with invitations, passkeys and accounts for children, then OpenID Connect, LDAP in the style of Active Directory, pairing with the UwUSuite, forward auth, SAML, SCIM and RADIUS.',
    plan: 'Read the plan',
  },
} as const;

export type TextKey = keyof (typeof texts)['de'];

/** German for whoever's browser prefers it, English for everybody else. */
export function pickLanguage(preferred: readonly string[]): Language {
  for (const tag of preferred) {
    const base = tag.toLowerCase().split('-')[0];
    if (base === 'de' || base === 'en') return base;
  }
  return 'en';
}
