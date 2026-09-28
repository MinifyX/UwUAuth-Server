import { useCallback, useEffect, useState } from 'react';
import { AppIcon } from '../components/AppIcon';
import { Ago, Day, Empty, Loading } from '../components/bits';
import { Section } from '../components/controls';
import { Icon } from '../components/Icon';
import { PageTitle } from '../components/Shell';
import { api, seg } from '../lib/api';
import { SCOPES, shownScopes } from '../lib/apps';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import type { MyApps as MyAppsData } from '../lib/types';
import { Confirm } from './Security';

/** The apps one may open, as tiles that open them. */
export function AppTiles({ apps }: { apps: MyAppsData['apps'] }) {
  return (
    <div className="app-tiles">
      {apps.map((app) => (
        <a
          key={app.id}
          className="app-tile"
          href={app.launchUrl}
          target="_blank"
          rel="noopener noreferrer"
        >
          <AppIcon name={app.name} size={44} />
          <span className="app-tile-text">
            <b>{app.name}</b>
            {app.description && <small>{app.description}</small>}
          </span>
          <Icon name="external" className="app-tile-arrow" />
        </a>
      ))}
    </div>
  );
}

/** "Meine Apps": what one may open, and which apps one let in and can take back. */
export function MyApps() {
  useLanguage();
  const [data, setData] = useState<MyAppsData | null>(null);
  const [revoking, setRevoking] = useState<MyAppsData['connected'][number] | null>(null);
  const load = useCallback(() => {
    api<MyAppsData>('/uwu/v1/me/apps').then(setData, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(load, [load]);

  return (
    <>
      <PageTitle>{t('Meine Apps')}</PageTitle>
      <p className="muted page-lead">
        {t('Apps, bei denen du dich mit deinem Konto anmeldest – ohne eigenes Passwort für jede.')}
      </p>
      {!data && <Loading />}
      {data && (
        <>
          <Section title={t('Zum Öffnen')}>
            {data.apps.length > 0 ? (
              <AppTiles apps={data.apps} />
            ) : (
              <Empty scene="sleepy" title={t('Noch keine Apps')}>
                {t('Sobald ein Admin eine App für dich freigibt, erscheint sie hier.')}
              </Empty>
            )}
          </Section>
          <Section
            title={t('Apps mit Zugriff')}
            lead={t(
              'Diese Apps haben dich schon einmal angemeldet. Entziehst du einer den Zugriff, kann sie dich nicht mehr von selbst angemeldet halten.',
            )}
          >
            {data.connected.length === 0 && (
              <p className="empty-note">{t('Noch keine App hat dich angemeldet.')}</p>
            )}
            {data.connected.length > 0 && (
              <ul className="item-list">
                {data.connected.map((grant) => (
                  <li key={grant.id} className="item">
                    <AppIcon name={grant.app} size={36} />
                    <span className="item-text">
                      <b>{grant.app}</b>
                      <small>
                        {shownScopes(grant.scopes)
                          .map((scope) => t(SCOPES[scope]!.text))
                          .join(' · ') || t('Nur, dass du es bist')}
                      </small>
                      <small>
                        {t('Seit')} <Day iso={grant.created} /> ·{' '}
                        <Ago iso={grant.lastUsed} prefix={t('zuletzt')} />
                      </small>
                    </span>
                    <button
                      type="button"
                      className="quiet danger-text"
                      onClick={() => setRevoking(grant)}
                    >
                      {t('Zugriff entziehen')}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </Section>
        </>
      )}
      {revoking && (
        <Confirm
          title={t('„{app}“ den Zugriff entziehen?', { app: revoking.app })}
          lead={t(
            'Die App bekommt dann nichts mehr von UwUAuth. Willst du sie wieder benutzen, meldest du dich dort einfach neu an.',
          )}
          confirm={t('Zugriff entziehen')}
          onCancel={() => setRevoking(null)}
          action={async () => {
            await api(`/uwu/v1/me/grants/${seg(revoking.id)}`, { method: 'DELETE' });
            setRevoking(null);
            toast(t('Zugriff entzogen.'));
            load();
          }}
        />
      )}
    </>
  );
}
