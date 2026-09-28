import { useEffect, useState } from 'react';
import { AppIcon } from '../components/AppIcon';
import { Loading } from '../components/bits';
import { FormError } from '../components/controls';
import { Icon } from '../components/Icon';
import { NyuScene } from '../components/nyu/scenes';
import { Centered } from '../components/Shell';
import { api, ApiError, seg } from '../lib/api';
import { SCOPES, shownScopes } from '../lib/apps';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { goTo } from '../lib/route';
import type { ConsentInfo, Me } from '../lib/types';

/** What an app gets, one line per scope. */
export function ScopeList({ scopes }: { scopes: string[] }) {
  useLanguage();
  const shown = shownScopes(scopes);
  return (
    <ul className="scope-list">
      <li>
        <Icon name="id" />
        <span>{t('Dass du es bist')}</span>
      </li>
      {shown.map((scope) => (
        <li key={scope}>
          <Icon name={SCOPES[scope]!.icon} />
          <span>{t(SCOPES[scope]!.text)}</span>
        </li>
      ))}
    </ul>
  );
}

/** A request that ran out or never was: back to the app. */
export function Gone({ text }: { text: string }) {
  useLanguage();
  return (
    <Centered>
      <NyuScene name="puzzled" className="center-scene" />
      <h1 className="card-title">{t('Das hat zu lange gedauert')}</h1>
      <p className="dialog-lead">{text}</p>
      <p className="center-foot">
        <a href="#/">{t('Zu meinem Konto')}</a>
      </p>
    </Centered>
  );
}

/**
 * "May this app know who you are?" — for apps that ask first. Yes sends the browser on to the
 * app with a code, no sends it back with a refusal.
 */
export function Consent({ me, request }: { me: Me; request: string }) {
  useLanguage();
  const [info, setInfo] = useState<ConsentInfo | null>(null);
  const [gone, setGone] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<ConsentInfo>(`/uwu/v1/consent/${seg(request)}`).then(setInfo, (e) => {
      if (e instanceof ApiError && e.status === 404) setGone(true);
      else setError(errorText(e));
    });
  }, [request]);

  const decide = async (approve: boolean) => {
    setBusy(true);
    setError(null);
    try {
      const { redirect } = await api<{ redirect: string }>(`/uwu/v1/consent/${seg(request)}`, {
        body: { approve },
      });
      goTo(redirect);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) setGone(true);
      else setError(errorText(e));
      setBusy(false);
    }
  };

  if (gone)
    return (
      <Gone
        text={t(
          'Die Anfrage der App ist abgelaufen. Geh zurück zur App und melde dich dort noch einmal an.',
        )}
      />
    );
  if (!info && !error) return <Loading />;
  return (
    <Centered>
      {info && (
        <>
          <div className="signin-head">
            <AppIcon name={info.app.name} size={64} />
            <h1 className="card-title">
              {t('„{app}“ möchte wissen, wer du bist', { app: info.app.name })}
            </h1>
            {info.app.description && <p className="muted">{info.app.description}</p>}
          </div>
          <div className="consent-box">
            <p className="consent-title">{t('Die App bekommt:')}</p>
            <ScopeList scopes={info.scopes} />
          </div>
          {info.redirectHost && (
            <p className="field-hint">
              {t('Danach geht es weiter zu {host}.', { host: info.redirectHost })}
            </p>
          )}
          <div className="form-actions center">
            <button type="button" onClick={() => void decide(false)} disabled={busy}>
              {t('Nicht erlauben')}
            </button>
            <button
              type="button"
              className="primary"
              onClick={() => void decide(true)}
              disabled={busy}
            >
              {busy ? t('Einen Moment …') : t('Erlauben')}
            </button>
          </div>
        </>
      )}
      <FormError error={error} />
      <p className="center-foot muted">
        {t('Angemeldet als {name}. Unter „Meine Apps“ kannst du das jederzeit zurücknehmen.', {
          name: me.username,
        })}
      </p>
    </Centered>
  );
}
