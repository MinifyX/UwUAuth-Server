import { useCallback, useEffect, useState } from 'react';
import { Ago, Badge } from '../components/bits';
import { Section, useAction } from '../components/controls';
import { EventList } from '../components/EventList';
import { Icon } from '../components/Icon';
import { PageTitle } from '../components/Shell';
import { api, seg } from '../lib/api';
import { errorText } from '../lib/errors';
import { methodsText } from '../lib/events';
import { when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import type { Me, Session } from '../lib/types';

/** Where one is signed in, and what happened with the account lately. */
export function Devices({ me }: { me: Me }) {
  useLanguage();
  const [sessions, setSessions] = useState<Session[] | null>(null);
  const [run, busy] = useAction();
  const load = useCallback(() => {
    api<Session[]>('/uwu/v1/me/sessions').then(setSessions, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(load, [load]);

  const others = sessions?.filter((session) => !session.current).length ?? 0;
  return (
    <>
      <PageTitle>{t('Geräte & Verlauf')}</PageTitle>
      <Section
        title={t('Angemeldete Geräte')}
        lead={t('Kennst du eines nicht? Melde es ab und ändere dein Passwort.')}
        actions={
          others > 0 && (
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  const answer = await api<{ ended: number }>('/uwu/v1/me/sessions/end-others', {
                    body: {},
                  });
                  toast(t('{n} Geräte abgemeldet.', { n: answer.ended }));
                  load();
                })
              }
            >
              {t('Alle anderen abmelden')}
            </button>
          )
        }
      >
        <SessionList
          sessions={sessions}
          busy={busy}
          onEnd={(session) =>
            void run(async () => {
              await api(`/uwu/v1/me/sessions/${seg(session.id)}`, { method: 'DELETE' });
              toast(t('Abgemeldet.'));
              load();
            })
          }
        />
      </Section>
      <Section
        title={t('Verlauf')}
        lead={t('Was mit deinem Konto passiert ist, das Neueste zuerst.')}
      >
        <EventList
          path="/uwu/v1/me/events"
          names={(id) => (id === me.id ? me.displayName : t('jemand anderes'))}
        />
      </Section>
    </>
  );
}

/** Sessions: device, where from, since when, and a way to end each. */
export function SessionList({
  sessions,
  busy,
  onEnd,
}: {
  sessions: Session[] | null;
  busy: boolean;
  onEnd: (session: Session) => void;
}) {
  useLanguage();
  if (!sessions) return null;
  if (sessions.length === 0) return <p className="empty-note">{t('Nirgends angemeldet.')}</p>;
  return (
    <ul className="item-list">
      {sessions.map((session) => (
        <li key={session.id} className="item">
          <span className="item-icon">
            <Icon name={/Android|iOS|iPadOS/.test(session.device) ? 'smartphone' : 'monitor'} />
          </span>
          <span className="item-text">
            <b>
              {deviceText(session.device)}
              {session.current && <Badge tone="ok">{t('dieses Gerät')}</Badge>}
            </b>
            <small>
              <Ago iso={session.lastSeen} prefix={t('aktiv')} />
              {session.ip ? ` · ${session.ip}` : ''}
              {' · '}
              {t('angemeldet {when}', { when: when(session.created) })}
              {session.methods.length > 0 && ` · ${methodsText(session.methods)}`}
            </small>
          </span>
          {!session.current && (
            <button
              type="button"
              className="quiet danger-text"
              disabled={busy}
              onClick={() => onEnd(session)}
            >
              {t('Abmelden')}
            </button>
          )}
        </li>
      ))}
    </ul>
  );
}

/** "Firefox / Linux" as the server guesses it; its "a browser" and "a device" in the reader's words. */
function deviceText(device: string): string {
  return device.replace('a browser', t('ein Browser')).replace('a device', t('ein Gerät'));
}
