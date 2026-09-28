import { useEffect, useState } from 'react';
import { Loading } from '../components/bits';
import { FormError } from '../components/controls';
import { Icon } from '../components/Icon';
import { NyuScene, type SceneName } from '../components/nyu/scenes';
import { Centered } from '../components/Shell';
import { api, ApiError, seg } from '../lib/api';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { reloadMe } from '../lib/me';
import { askToConfirm } from '../lib/reauth';
import { continueTarget, go, goTo } from '../lib/route';
import type { Me } from '../lib/types';
import { Gone } from './Consent';

/** Why somebody may not use an app, in words: a title, a line, and Nyu's face for it. */
export function deniedText(
  reason: string,
  app: string | null,
): { title: string; text: string; scene: SceneName } {
  const name = app ?? t('diese App');
  switch (reason) {
    case 'groups':
      return {
        title: t('Diese App ist nicht für dich freigegeben'),
        text: t(
          '„{app}“ ist nur für bestimmte Gruppen da, und du bist in keiner davon. Wenn du die App brauchst, frag einen Admin.',
          { app: name },
        ),
        scene: 'puzzled',
      };
    case 'time':
      return {
        title: t('Gerade nicht'),
        text: t(
          'Für „{app}“ ist gerade keine Zeit – das sagen deine Zeitfenster. Später klappt es wieder.',
          { app: name },
        ),
        scene: 'sleepy',
      };
    case 'mfa':
      return {
        title: t('Noch ein Schritt für diese App'),
        text: t(
          '„{app}“ möchte, dass du mehr zeigst als ein Passwort: einen Passkey oder einen Code aus der Authenticator-App.',
          { app: name },
        ),
        scene: 'keys',
      };
    case 'disabled':
      return {
        title: t('Dein Konto ist gesperrt'),
        text: t('Solange es gesperrt ist, kommst du in keine App. Frag einen Admin.'),
        scene: 'sad',
      };
    case 'expired':
      return {
        title: t('Dein Konto ist abgelaufen'),
        text: t('Ein Admin kann es verlängern – dann geht es wieder.'),
        scene: 'sleepy',
      };
    case 'locked':
      return {
        title: t('Kurz gesperrt'),
        text: t(
          'Zu viele falsche Versuche. Warte eine Viertelstunde und versuch es dann noch einmal.',
        ),
        scene: 'sleepy',
      };
    case 'app_disabled':
      return {
        title: t('Diese App ist ausgeschaltet'),
        text: t('Ein Admin hat „{app}“ gerade abgeschaltet. Versuch es später noch einmal.', {
          app: name,
        }),
        scene: 'sleepy',
      };
    default:
      return {
        title: t('Das geht gerade nicht'),
        text: t('Du darfst „{app}“ gerade nicht benutzen.', { app: name }),
        scene: 'puzzled',
      };
  }
}

/** An app said no: why, and — for a missing second factor — how to get past it. */
export function Denied({
  me,
  reason,
  app,
  continueTo,
}: {
  me: Me | null;
  reason: string;
  app: string | null;
  continueTo: string | null;
}) {
  useLanguage();
  const [error, setError] = useState<string | null>(null);
  const target = continueTarget(continueTo);
  const { title, text, scene } = deniedText(reason, app);
  const hasFactor = Boolean(me && (me.passkeys.length > 0 || me.hasTotp));

  const confirmAndGo = async () => {
    setError(null);
    try {
      await askToConfirm();
      if (target) goTo(target);
    } catch (e) {
      setError(errorText(e));
    }
  };

  return (
    <Centered>
      <NyuScene name={scene} className="center-scene" />
      <h1 className="card-title">{title}</h1>
      <p className="dialog-lead">{text}</p>
      {reason === 'mfa' && me && (
        <>
          {hasFactor && target ? (
            <button
              type="button"
              className="primary big-button"
              onClick={() => void confirmAndGo()}
            >
              <Icon name="key" />
              {t('Jetzt bestätigen und weiter')}
            </button>
          ) : (
            <>
              <p className="field-hint">
                {t(
                  'Du hast noch keinen zweiten Faktor. Richte einen ein – das dauert eine Minute – und versuch es dann noch einmal.',
                )}
              </p>
              <button type="button" className="primary big-button" onClick={() => go('/security')}>
                <Icon name="shield" />
                {t('Zweiten Faktor einrichten')}
              </button>
            </>
          )}
          {!hasFactor && target && (
            <button type="button" className="big-button" onClick={() => goTo(target)}>
              {t('Noch einmal versuchen')}
            </button>
          )}
        </>
      )}
      <FormError error={error} />
      <p className="center-foot">
        <a href="#/">{t('Zu meinem Konto')}</a>
      </p>
    </Centered>
  );
}

/** An app sent a request that is wrong: its configuration, not the person's fault. */
export function OAuthError({ reason, app }: { reason: string; app: string | null }) {
  useLanguage();
  const name = app ?? t('Die App');
  let text: string;
  if (reason === 'redirect')
    text = t(
      '„{app}“ wollte dich nach der Anmeldung an eine Adresse schicken, die bei UwUAuth nicht eingetragen ist. Zu deinem Schutz geht es hier nicht weiter.',
      { app: name },
    );
  else if (reason === 'unknown_app' || reason === 'client')
    text = t('Diese App kennt UwUAuth nicht – oder ein Admin hat sie ausgeschaltet.');
  else text = t('Die App hat eine Anfrage geschickt, mit der UwUAuth nichts anfangen kann.');
  return (
    <Centered>
      <NyuScene name="puzzled" className="center-scene" />
      <h1 className="card-title">{t('Mit der App stimmt etwas nicht')}</h1>
      <p className="dialog-lead">{text}</p>
      <p className="field-hint">
        {t(
          'Das liegt an den Einstellungen der App, nicht an dir. Sag einem Admin Bescheid: Im Admin-Portal unter „Apps“ lässt es sich richten.',
        )}
      </p>
      <p className="center-foot">
        <a href="#/">{t('Zu meinem Konto')}</a>
      </p>
    </Centered>
  );
}

/** An app asks to sign out here too: confirm first, so a link alone cannot sign anybody out. */
export function LogoutConfirm({ request }: { request: string }) {
  useLanguage();
  const [info, setInfo] = useState<{ app: string | null; returns: boolean } | null>(null);
  const [gone, setGone] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<{ app: string | null; returns: boolean }>(`/uwu/v1/logout-request/${seg(request)}`, {
      anonymous: true,
    }).then(setInfo, (e) => {
      if (e instanceof ApiError && e.status === 404) setGone(true);
      else setError(errorText(e));
    });
  }, [request]);

  const decide = async (confirm: boolean) => {
    setBusy(true);
    setError(null);
    try {
      const { redirect } = await api<{ redirect: string }>(
        `/uwu/v1/logout-request/${seg(request)}`,
        { body: { confirm }, anonymous: true },
      );
      // Only the part after `#` may change: the page learns about the ended session first.
      await reloadMe().catch(() => undefined);
      goTo(redirect);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) setGone(true);
      else setError(errorText(e));
      setBusy(false);
    }
  };

  if (gone)
    return <Gone text={t('Die Anfrage zum Abmelden ist abgelaufen. Du bist noch angemeldet.')} />;
  if (!info && !error) return <Loading />;
  return (
    <Centered>
      <NyuScene name="sleepy" className="center-scene" />
      <h1 className="card-title">{t('Abmelden?')}</h1>
      <p className="dialog-lead">
        {info?.app
          ? t('„{app}“ möchte dich auch bei UwUAuth abmelden.', { app: info.app })
          : t('Eine App möchte dich bei UwUAuth abmelden.')}{' '}
        {info?.returns
          ? t('Danach geht es zurück zur App.')
          : t('Andere Apps, bei denen du über UwUAuth angemeldet bist, erfahren es auch.')}
      </p>
      <FormError error={error} />
      <div className="form-actions center">
        <button type="button" onClick={() => void decide(false)} disabled={busy}>
          {t('Angemeldet bleiben')}
        </button>
        <button type="button" className="primary" onClick={() => void decide(true)} disabled={busy}>
          {t('Abmelden')}
        </button>
      </div>
    </Centered>
  );
}

/** After signing out through an app. */
export function SignedOut() {
  useLanguage();
  return (
    <Centered>
      <NyuScene name="sleepy" className="center-scene" />
      <h1 className="card-title">{t('Du bist abgemeldet')}</h1>
      <p className="dialog-lead">{t('Bis bald! Nyu hält hier die Stellung.')}</p>
      <a className="button-link primary big-button" href="#/login">
        {t('Wieder anmelden')}
      </a>
    </Centered>
  );
}
