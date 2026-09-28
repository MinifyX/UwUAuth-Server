/**
 * The words that depend on what the server is for. A family talks about kids and parents, an
 * office about a team and who looks after it; the API calls both "managed" and "managers".
 */

import { N_, t } from './i18n';
import type { Mode } from './types';

const WORDS = {
  family: {
    myPeople: N_('Meine Kinder'),
    managedAccount: N_('Kinderkonto'),
    managers: N_('Eltern'),
    manages: N_('Kinder'),
    addManaged: N_('Kind hinzufügen'),
    noManaged: N_(
      'Du kümmerst dich noch um niemanden. Leg ein Konto für dein Kind an – mit einem QR-Code richtet es sich auf dem Tablet selbst ein.',
    ),
    managedHint: N_(
      'Ein Kinderkonto wird von den Eltern betreut: Sie können Namen, Passwort und Zeitfenster ändern und das Konto sperren.',
    ),
  },
  office: {
    myPeople: N_('Mein Team'),
    managedAccount: N_('Betreutes Konto'),
    managers: N_('Verantwortlich'),
    manages: N_('Team'),
    addManaged: N_('Person hinzufügen'),
    noManaged: N_(
      'Du betreust noch niemanden. Leg ein Konto an – mit einem Einrichtungslink richtet die Person es selbst ein.',
    ),
    managedHint: N_(
      'Ein betreutes Konto wird von der Verwaltung gepflegt: Sie kann Namen, Passwort und Zeitfenster ändern und das Konto sperren.',
    ),
  },
} as const;

export type Word = keyof (typeof WORDS)['family'];

/** One of the words, for `mode`, in the current language. */
export function word(mode: Mode | undefined, key: Word): string {
  return t(WORDS[mode === 'office' ? 'office' : 'family'][key]);
}

/** A group's name; the two that come with the server in the reader's language. */
export function groupName(group: { name: string; builtin: string | null }): string {
  if (group.builtin === 'admins') return t('Admins');
  if (group.builtin === 'everyone') return t('Alle');
  return group.name;
}
