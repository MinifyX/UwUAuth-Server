/**
 * Apps that sign people in through UwUAuth (OpenID Connect): what their scopes mean in words,
 * the codes a TV shows, and what a template makes of an app's address.
 */

import type { IconName } from '../components/Icon';
import { N_ } from './i18n';
import type { GrantType } from './types';

/** What an app gets with each scope, as a person reads it. `openid` alone says nothing new. */
export const SCOPES: Record<string, { icon: IconName; text: string }> = {
  profile: { icon: 'user', text: N_('Deinen Namen, Benutzernamen und dein Bild') },
  email: { icon: 'mail', text: N_('Deine E-Mail-Adresse') },
  groups: { icon: 'users', text: N_('In welchen Gruppen du bist') },
  roles: { icon: 'crown', text: N_('Welche Rolle du in der App hast') },
  attributes: { icon: 'tag', text: N_('Die zusätzlichen Felder aus deinem Profil') },
  offline_access: {
    icon: 'refresh',
    text: N_('Bleibt angemeldet, auch wenn du gerade nicht da bist'),
  },
};

/** The scopes worth listing, in a stable order, the unknown ones left out. */
export function shownScopes(scopes: string[]): string[] {
  return Object.keys(SCOPES).filter((scope) => scopes.includes(scope));
}

/** The grant types an admin can pick, in words. */
export const GRANTS: { value: GrantType; label: string; hint: string }[] = [
  {
    value: 'authorization_code',
    label: N_('Anmelden im Browser'),
    hint: N_('Der Normalfall: Die App schickt Leute zum Anmelden hierher.'),
  },
  {
    value: 'refresh_token',
    label: N_('Angemeldet bleiben'),
    hint: N_('Die App darf ihre Anmeldung erneuern, ohne neu zu fragen.'),
  },
  {
    value: 'urn:ietf:params:oauth:grant-type:device_code',
    label: N_('Geräte ohne Browser'),
    hint: N_('Fernseher und Kommandozeilen: Sie zeigen einen Code, den man am Handy eingibt.'),
  },
  {
    value: 'client_credentials',
    label: N_('Die App für sich selbst'),
    hint: N_('Ein Dienst ohne Person dahinter holt sich mit seinem Geheimnis ein Token.'),
  },
];

/**
 * A code as typed from a TV: upper case, letters and digits only, a dash after the fourth.
 * "bcdf ghjk" → "BCDF-GHJK".
 */
export function formatUserCode(typed: string): string {
  const letters = typed
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '')
    .slice(0, 8);
  return letters.length > 4 ? `${letters.slice(0, 4)}-${letters.slice(4)}` : letters;
}

/** A template's pattern with the app's address (`{url}`) and short name (`{slug}`) filled in. */
export function fillTemplate(pattern: string, url: string, slug: string): string {
  return pattern.replaceAll('{url}', url.trim().replace(/\/+$/, '')).replaceAll('{slug}', slug);
}

/** Whether a template's addresses need the app's own address, or its short name. */
export function templateNeeds(patterns: string[]): { url: boolean; slug: boolean } {
  return {
    url: patterns.some((pattern) => pattern.includes('{url}')),
    slug: patterns.some((pattern) => pattern.includes('{slug}')),
  };
}

/** Where apps read everything about this server. */
export function discoveryUrl(issuer: string): string {
  return `${issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`;
}

/** Two letters for an app's tile: "Home Assistant" → "HA", "Nextcloud" → "Ne". */
export function appLetters(name: string): string {
  const words = name
    .replace(/[^\p{L}\p{N}\s]/gu, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (words.length === 0) return '?';
  if (words.length === 1) {
    const [first = '', second = ''] = [...words[0]!];
    return first.toUpperCase() + second.toLowerCase();
  }
  return ([...words[0]!][0]! + [...words[1]!][0]!).toUpperCase();
}
