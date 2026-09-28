import { beforeEach, describe, expect, it } from 'vitest';
import { alarming, eventText } from './events';
import { setLanguage } from './i18n';
import type { AuditEvent } from './types';

const event = (kind: string, detail: Record<string, unknown>): AuditEvent => ({
  id: 1,
  time: '2026-09-28T10:00:00Z',
  kind,
  actor: 'p1',
  person: 'p1',
  target: 'a1',
  ip: null,
  detail,
});
const names = (id: string | null) => (id === 'p1' ? 'Mia' : 'jemand');

// The sentences in German, whatever language the machine running the tests speaks.
beforeEach(() => setLanguage('de'));

describe('app events', () => {
  it('read as sentences', () => {
    expect(eventText(event('app_login', { app: 'Nextcloud' }), names)).toBe(
      'Mia hat sich bei „Nextcloud“ angemeldet.',
    );
    expect(eventText(event('app_refused', { app: 'Spiele', reason: 'time' }), names)).toBe(
      'Mia durfte „Spiele“ nicht benutzen: außerhalb der Zeitfenster.',
    );
    expect(eventText(event('app_created', { name: 'Immich' }), names)).toBe(
      'Mia hat die App „Immich“ angelegt.',
    );
  });

  it('name the device and the grant', () => {
    expect(eventText(event('device_confirmed', { app: 'Fernseher' }), names)).toBe(
      'Mia hat ein Gerät mit „Fernseher“ verbunden.',
    );
    expect(eventText(event('grant_revoked', {}), names)).toBe(
      'Mia hat einer App den Zugriff entzogen.',
    );
  });

  it('mark refusals', () => {
    expect(alarming('app_refused')).toBe(true);
    expect(alarming('app_login')).toBe(false);
  });
});
