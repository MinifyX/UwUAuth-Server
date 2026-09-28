/**
 * What happened, as a sentence. The server writes down a kind (`passkey_added`), who did it,
 * whom it was about and a little JSON; this turns that into "Mia hat einen Passkey hinzugefügt"
 * with the names the page knows.
 */

import { N_, t } from './i18n';
import type { AuditEvent } from './types';

/** A name for an id: a person's display name, or something plain when the page does not know. */
export type Names = (id: string | null) => string;

const METHODS: Record<string, string> = {
  pwd: N_('Passwort'),
  otp: N_('Code aus der App'),
  kba: N_('Wiederherstellungscode'),
  hwk: N_('Passkey'),
};

const REASONS: Record<string, string> = {
  disabled: N_('das Konto ist gesperrt'),
  expired: N_('das Konto ist abgelaufen'),
  locked: N_('zu viele falsche Passwörter'),
  groups: N_('nicht in den Gruppen der App'),
  time: N_('außerhalb der Zeitfenster'),
  app_disabled: N_('die App ist ausgeschaltet'),
};

/** How somebody signed in: "Passkey", "Passwort + Code aus der App". */
export function methodsText(methods: unknown): string {
  const list = Array.isArray(methods) ? methods.filter((m) => m !== 'mfa') : [];
  return list.map((method) => (METHODS[method] ? t(METHODS[method]) : String(method))).join(' + ');
}

/** The categories the event log filters by: the kind's prefix, as the server matches it. */
export const EVENT_FILTERS: { value: string; label: string }[] = [
  { value: '', label: N_('Alles') },
  { value: 'login', label: N_('Anmeldungen') },
  { value: 'login_failed', label: N_('Fehlgeschlagene Anmeldungen') },
  { value: 'person_', label: N_('Personen') },
  { value: 'group_', label: N_('Gruppen') },
  { value: 'invitation_', label: N_('Einladungen') },
  { value: 'app_', label: N_('Apps') },
  { value: 'passkey_', label: N_('Passkeys') },
  { value: 'password_', label: N_('Passwörter') },
  { value: 'settings_', label: N_('Einstellungen') },
  { value: 'backup_', label: N_('Backups') },
];

/** One event as a sentence. */
export function eventText(event: AuditEvent, names: Names): string {
  const d = event.detail ?? {};
  const actor = event.actor?.startsWith('token:')
    ? t('Ein API-Token')
    : event.actor
      ? names(event.actor)
      : t('Jemand');
  const person = event.person ? names(event.person) : t('jemand');
  const self = event.actor !== null && event.actor === event.person;
  const text = (value: unknown) => (typeof value === 'string' ? value : '');
  const vars = {
    actor,
    person,
    name: text(d.name),
    email: text(d.email),
    app: text(d.app) || t('eine App'),
  };
  switch (event.kind) {
    case 'login':
      return t('{person} hat sich angemeldet ({how}).', {
        ...vars,
        how: methodsText(d.methods) || t('Passwort'),
      });
    case 'login_failed':
      if (!event.person)
        return d.login
          ? t('Anmeldung mit dem unbekannten Namen „{login}“ abgelehnt.', { login: text(d.login) })
          : t('Anmeldung mit einem unbekannten Passkey abgelehnt.');
      return d.method === 'second'
        ? t('Falscher zweiter Schritt bei der Anmeldung von {person}.', vars)
        : t('Falsches Passwort für {person}.', vars);
    case 'login_refused':
      return t('{person} wurde nicht angemeldet: {reason}.', {
        ...vars,
        reason: REASONS[text(d.reason)] ? t(REASONS[text(d.reason)]!) : text(d.reason),
      });
    case 'reauth_failed':
      return t('{person} hat sich beim Bestätigen vertippt.', vars);
    case 'recovery_code_used':
      return t('{person} hat einen Wiederherstellungscode benutzt.', vars);
    case 'reset_requested':
      return t('{person} hat einen Link für ein neues Passwort angefordert.', vars);
    case 'invitation_created':
      return vars.email
        ? t('{actor} hat {email} eingeladen.', vars)
        : t('{actor} hat eine Einladung erstellt.', vars);
    case 'invitation_accepted':
      return t('{person} hat die Einladung angenommen.', vars);
    case 'invitation_deleted':
      return t('{actor} hat eine Einladung zurückgezogen.', vars);
    case 'invitation_renewed':
      return t('{actor} hat einen neuen Einladungslink erstellt.', vars);
    case 'account_set_up':
      return t('{person} hat das Konto eingerichtet.', vars);
    case 'password_reset':
      return t('{person} hat über einen Link ein neues Passwort gesetzt.', vars);
    case 'email_change_requested':
      return t('{person} möchte die Adresse {email} verwenden.', vars);
    case 'email_verified':
      return t('{person} hat die Adresse {email} bestätigt.', vars);
    case 'password_changed':
      return t('{person} hat das Passwort geändert.', vars);
    case 'password_removed':
      return t('{person} meldet sich jetzt nur noch mit Passkeys an.', vars);
    case 'password_set':
      return t('{actor} hat ein neues Passwort für {person} gesetzt.', vars);
    case 'passkey_added':
      return vars.name
        ? t('{person} hat den Passkey „{name}“ hinzugefügt.', vars)
        : t('{person} hat einen Passkey hinzugefügt.', vars);
    case 'passkey_removed':
      return self
        ? t('{person} hat einen Passkey entfernt.', vars)
        : t('{actor} hat einen Passkey von {person} entfernt.', vars);
    case 'totp_added':
      return t('{person} hat die Authenticator-App eingerichtet.', vars);
    case 'totp_removed':
      return t('{person} hat die Authenticator-App entfernt.', vars);
    case 'totp_reset':
      return t('{actor} hat die Authenticator-App von {person} entfernt.', vars);
    case 'second_factors_reset':
      return t(
        'Passkeys und Authenticator-App von {person} wurden per Kommandozeile entfernt.',
        vars,
      );
    case 'recovery_codes_made':
      return t('{person} hat neue Wiederherstellungscodes erstellt.', vars);
    case 'app_password_added':
      return t('{person} hat das App-Passwort „{name}“ erstellt.', vars);
    case 'app_password_removed':
      return t('{person} hat ein App-Passwort gelöscht.', vars);
    case 'sessions_ended':
      return self
        ? t('{person} hat sich auf {count} anderen Geräten abgemeldet.', {
            ...vars,
            count: Number(d.count ?? 0),
          })
        : t('{actor} hat {person} auf {count} Geräten abgemeldet.', {
            ...vars,
            count: Number(d.count ?? 0),
          });
    case 'person_created':
      return t('{actor} hat das Konto {username} angelegt.', {
        ...vars,
        username: text(d.username),
      });
    case 'person_changed':
      return t('{actor} hat das Konto von {person} geändert.', vars);
    case 'person_deleted':
      return t('{actor} hat {username} in den Papierkorb gelegt.', {
        ...vars,
        username: text(d.username),
      });
    case 'person_restored':
      return t('{actor} hat {person} aus dem Papierkorb geholt.', vars);
    case 'person_purged':
      return t('{actor} hat {username} endgültig gelöscht.', {
        ...vars,
        username: text(d.username),
      });
    case 'person_disabled':
      return t('{actor} hat {person} gesperrt.', vars);
    case 'person_enabled':
      return t('{actor} hat {person} wieder freigegeben.', vars);
    case 'person_groups_changed':
      return t('{actor} hat die Gruppen von {person} geändert.', vars);
    case 'managers_changed':
      return t('{actor} hat geändert, wer sich um {person} kümmert.', vars);
    case 'manages_changed':
      return t('{actor} hat geändert, um wen sich {person} kümmert.', vars);
    case 'windows_changed':
      return event.person
        ? t('{actor} hat die Zeitfenster von {person} geändert.', vars)
        : t('{actor} hat die Zeitfenster einer Gruppe geändert.', vars);
    case 'link_made':
      return d.by === 'command'
        ? t('Über die Kommandozeile wurde ein Link für {person} erstellt.', vars)
        : d.purpose === 'setup'
          ? t('{actor} hat einen Einrichtungslink für {person} erstellt.', vars)
          : t('{actor} hat einen Link für ein neues Passwort von {person} erstellt.', vars);
    case 'group_created':
      return t('{actor} hat die Gruppe „{name}“ angelegt.', vars);
    case 'group_changed':
      return t('{actor} hat die Gruppe „{name}“ geändert.', vars);
    case 'group_deleted':
      return t('{actor} hat die Gruppe „{name}“ gelöscht.', vars);
    case 'group_members_changed':
      return t('{actor} hat die Mitglieder von „{name}“ geändert.', vars);
    case 'settings_changed':
      return t('{actor} hat die Einstellungen geändert.', vars);
    case 'setup_done':
      return t('{actor} hat UwUAuth eingerichtet.', vars);
    case 'attributes_changed':
      return t('{actor} hat die zusätzlichen Felder geändert.', vars);
    case 'backup_written':
      return t('{actor} hat ein Backup geschrieben.', vars);
    case 'backup_downloaded':
      return t('{actor} hat ein Backup heruntergeladen.', vars);
    case 'exported':
      return t('{actor} hat das Verzeichnis exportiert.', vars);
    case 'imported':
      return t('{actor} hat {count} Personen importiert.', {
        ...vars,
        count: Number(d.people ?? 0),
      });
    case 'token_created':
      return t('{actor} hat das API-Token „{name}“ erstellt.', vars);
    case 'token_deleted':
      return t('{actor} hat ein API-Token gelöscht.', vars);
    case 'logout':
      return t('{person} hat sich abgemeldet.', vars);
    case 'app_created':
      return t('{actor} hat die App „{name}“ angelegt.', vars);
    case 'app_changed':
      return t('{actor} hat die App „{name}“ geändert.', vars);
    case 'app_deleted':
      return t('{actor} hat die App „{name}“ gelöscht.', vars);
    case 'app_secret_renewed':
      return t('{actor} hat ein neues Secret für „{name}“ erstellt.', vars);
    case 'app_registered':
      return t('Die App „{name}“ hat sich mit dem Token „{token}“ selbst eingetragen.', {
        ...vars,
        token: text(d.token),
      });
    case 'app_paired':
      return t('„{name}“ ({product}) hat sich mit dem Kopplungscode von {actor} gekoppelt.', {
        ...vars,
        product: text(d.product),
      });
    case 'app_pairing_refused':
      return t('Ein Kopplungsversuch mit einem falschen Code wurde abgelehnt.', vars);
    case 'pairing_code_created':
      return t('{actor} hat einen Kopplungscode erstellt.', vars);
    case 'pairing_code_deleted':
      return t('{actor} hat einen Kopplungscode zurückgezogen.', vars);
    case 'app_scim_changed':
      return t('{actor} hat den SCIM-Abgleich für „{name}“ eingerichtet.', vars);
    case 'app_scim_removed':
      return t('{actor} hat den SCIM-Abgleich für „{name}“ beendet.', vars);
    case 'app_scim_failed':
      return t('Der SCIM-Abgleich mit „{name}“ ging schief: {error}', {
        ...vars,
        error: text(d.error),
      });
    case 'registration_token_created':
      return t('{actor} hat das Registrierungs-Token „{name}“ erstellt.', vars);
    case 'app_login':
      return t('{person} hat sich bei „{app}“ angemeldet.', vars);
    case 'app_refused':
      return t('{person} durfte „{app}“ nicht benutzen: {reason}.', {
        ...vars,
        reason: REASONS[text(d.reason)] ? t(REASONS[text(d.reason)]!) : text(d.reason),
      });
    case 'app_consent_refused':
      return t('{person} hat „{app}“ den Zugriff nicht erlaubt.', vars);
    case 'device_confirmed':
      return t('{person} hat ein Gerät mit „{app}“ verbunden.', vars);
    case 'grant_revoked':
      return t('{person} hat einer App den Zugriff entzogen.', vars);
    case 'refresh_token_reused':
      return t(
        'Ein schon benutztes Token von „{app}“ für {person} kam noch einmal – die App ist vorsichtshalber abgemeldet.',
        vars,
      );
    default:
      return event.kind;
  }
}

/** Events that mean something went wrong, shown in the alarm colour. */
export function alarming(kind: string): boolean {
  return (
    kind === 'login_failed' ||
    kind === 'login_refused' ||
    kind === 'reauth_failed' ||
    kind === 'app_refused' ||
    kind === 'app_pairing_refused' ||
    kind === 'app_scim_failed' ||
    kind === 'refresh_token_reused'
  );
}
