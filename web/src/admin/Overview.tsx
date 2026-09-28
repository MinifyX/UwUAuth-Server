import { useEffect, useState } from 'react';
import { Loading } from '../components/bits';
import { Icon } from '../components/Icon';
import { PageTitle } from '../components/Shell';
import { api } from '../lib/api';
import { errorText } from '../lib/errors';
import { ago, bytes } from '../lib/format';
import { locale, t, useLanguage } from '../lib/i18n';
import { go } from '../lib/route';
import type { Overview as Data } from '../lib/types';

function uptime(total: number): string {
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  if (days) return t('{d} Tage, {h} Std.', { d: days, h: hours });
  return t('{h} Std., {m} Min.', { h: hours, m: Math.floor((total % 3600) / 60) });
}

/** "2026-09-25-031000" from a backup's name, as a local time. */
export function backupTime(stamp: string | null): string {
  const match = stamp?.match(/^(\d{4})-(\d{2})-(\d{2})-(\d{2})(\d{2})(\d{2})/);
  if (!match) return stamp ?? '';
  const [, y, m, d, hh, mm, ss] = match.map(Number) as number[];
  return new Date(Date.UTC(y!, m! - 1, d!, hh!, mm!, ss!)).toLocaleString(locale(), {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
}

/** The numbers, mail, backups and updates, at a glance. */
export function Overview() {
  useLanguage();
  const [data, setData] = useState<Data | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api<Data>('/uwu/v1/overview').then(setData, (e) => setError(errorText(e)));
  }, []);
  if (error) return <p className="form-error">{error}</p>;
  if (!data) return <Loading />;
  const update = data.update;
  return (
    <>
      <PageTitle>{t('Übersicht')}</PageTitle>
      {!data.mail && (
        <p className="notice">
          <Icon name="mail" />
          <span>
            {t(
              'Mails sind noch nicht eingerichtet. Einladungen und Einrichtungslinks gehen dann nur per QR-Code oder Link, und „Passwort vergessen“ schickt nichts.',
            )}
          </span>
          <button type="button" onClick={() => go('/settings')}>
            {t('Einrichten')}
          </button>
        </p>
      )}
      {update.newer && (
        <p className="notice" data-tone="info">
          <Icon name="sparkles" />
          <span>
            {t(
              'Version {version} ist da. Zum Aktualisieren: sudo bash update.sh neben compose.yaml.',
              {
                version: update.newer,
              },
            )}
          </span>
          {update.url && (
            <a className="button-link" href={update.url} target="_blank" rel="noreferrer">
              {t('Was ist neu?')}
            </a>
          )}
        </p>
      )}
      <div className="stat-grid">
        <Stat
          label={t('Personen')}
          value={data.people}
          note={t('{a} Admins, {d} gesperrt', { a: data.admins, d: data.disabled })}
          onClick={() => go('/people')}
        />
        <Stat label={t('Gruppen')} value={data.groups} onClick={() => go('/groups')} />
        <Stat
          label={t('Offene Einladungen')}
          value={data.invitations}
          onClick={() => go('/invitations')}
        />
        <Stat
          label={t('Mit Authenticator-App')}
          value={data.withTotp}
          note={t('von {n}', { n: data.people })}
        />
        <Stat label={t('Betreute Konten')} value={data.managed} />
        <Stat
          label={t('Fehlgeschlagene Anmeldungen')}
          value={data.failedLoginsDay}
          note={t('in den letzten 24 Stunden')}
          alarm={data.failedLoginsDay > 20}
          onClick={() => go('/events')}
        />
      </div>
      <div className="facts">
        <Fact
          label={t('Version')}
          value={`${data.version}${update.commit ? ` (${update.commit.slice(0, 7)})` : ''}`}
        />
        <Fact label={t('Läuft seit')} value={uptime(data.uptimeSeconds)} />
        <Fact label={t('Datenbank')} value={bytes(data.databaseBytes)} />
        <Fact
          label={t('Backups')}
          value={
            data.backups
              ? t('{n} Stück, das neueste vom {when}', {
                  n: data.backups,
                  when: backupTime(data.lastBackup?.replace(/^uwuauth-|\.db$/g, '') ?? null),
                })
              : t('noch keins – das erste schreibt der Server in der ersten Nacht')
          }
        />
        <Fact
          label={t('Mail')}
          value={data.mail ? t('eingerichtet') : t('nicht eingerichtet')}
          alarm={!data.mail}
        />
        <Fact
          label={t('Updates')}
          value={
            update.newer
              ? t('Version {version} ist da', { version: update.newer })
              : update.commits
                ? t('main ist {n} Commits weiter', { n: update.commits })
                : update.error
                  ? t('Nachsehen ging nicht: {error}', { error: update.error })
                  : update.checked
                    ? t('aktuell (nachgesehen {when})', { when: ago(update.checked) })
                    : t('noch nicht nachgesehen')
          }
          alarm={Boolean(update.newer)}
        />
        {data.trash > 0 && (
          <Fact label={t('Papierkorb')} value={t('{n} Personen', { n: data.trash })} />
        )}
      </div>
    </>
  );
}

function Stat({
  label,
  value,
  note,
  alarm,
  onClick,
}: {
  label: string;
  value: number;
  note?: string;
  alarm?: boolean;
  onClick?: () => void;
}) {
  const content = (
    <>
      <span className="stat-value">{value.toLocaleString()}</span>
      <span className="stat-label">{label}</span>
      {note && <span className="stat-note">{note}</span>}
    </>
  );
  return onClick ? (
    <button
      type="button"
      className="stat link-stat"
      data-alarm={alarm || undefined}
      onClick={onClick}
    >
      {content}
    </button>
  ) : (
    <div className="stat" data-alarm={alarm || undefined}>
      {content}
    </div>
  );
}

function Fact({ label, value, alarm }: { label: string; value: string; alarm?: boolean }) {
  return (
    <div className="fact" data-alarm={alarm || undefined}>
      <span className="fact-label">{label}</span>
      <span className="fact-value">{value}</span>
    </div>
  );
}
