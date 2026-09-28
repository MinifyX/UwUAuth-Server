import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { Loading } from '../components/bits';
import { FormError, Segmented } from '../components/controls';
import { Icon } from '../components/Icon';
import { NyuScene } from '../components/nyu/scenes';
import { PasswordInput } from '../components/PasswordInput';
import { Centered } from '../components/Shell';
import { api, ApiError, seg } from '../lib/api';
import { errorText } from '../lib/errors';
import { when } from '../lib/format';
import { language, setLanguage, t, useLanguage } from '../lib/i18n';
import { reloadMe } from '../lib/me';
import { suggestUsername } from '../lib/names';
import { useRoute } from '../lib/route';
import type { LinkInfo } from '../lib/types';
import { available, createPasskey, deviceName } from '../lib/webauthn';
import { afterSignIn } from './SignIn';

type Purpose = LinkInfo['purpose'];
type Json = Record<string, unknown>;

/**
 * Where the links from mails and QR codes lead: an invitation, setting up an account somebody
 * made (often on a kid's tablet), a new password, confirming an address. Each works once.
 */
export function LinkPage({ purpose }: { purpose: Purpose }) {
  useLanguage();
  const route = useRoute();
  const token = route.query.get('token') ?? '';
  const [info, setInfo] = useState<LinkInfo | null>(null);
  const [error, setError] = useState<ApiError | Error | null>(null);

  useEffect(() => {
    if (!token) {
      setError(new ApiError(410, 'link_gone', 'No token.'));
      return;
    }
    api<LinkInfo>(`/uwu/v1/links/${purpose}/${seg(token)}`, { anonymous: true }).then((loaded) => {
      setInfo(loaded);
      // Somebody invited in English reads the page in English, before they chose anything.
      if (loaded.language) setLanguage(loaded.language);
    }, setError);
  }, [purpose, token]);

  if (error) {
    const gone = error instanceof ApiError && (error.code === 'link_gone' || error.status === 404);
    return (
      <Centered>
        <NyuScene name="sad" className="center-scene" />
        <h1 className="card-title">
          {gone ? t('Dieser Link geht nicht mehr') : t('Das hat nicht geklappt')}
        </h1>
        <p className="dialog-lead">
          {gone
            ? t(
                'Der Link wurde schon benutzt oder ist abgelaufen. Frag nach einem neuen – das geht ganz schnell.',
              )
            : errorText(error)}
        </p>
        <p className="center-foot">
          <a href="#/login">{t('Zur Anmeldung')}</a>
        </p>
      </Centered>
    );
  }
  if (!info) return <Loading />;
  if (purpose === 'verify') return <Verify token={token} info={info} />;
  if (purpose === 'invite') return <Invite token={token} info={info} />;
  return <SetUp token={token} info={info} purpose={purpose} />;
}

/** After a link signed somebody in: the admin assistant on a new server, else the portal. */
async function signedIn(query: URLSearchParams) {
  const me = await reloadMe();
  if (me?.admin && !me.server.setupDone) {
    location.href = '/admin';
    return;
  }
  await afterSignIn(query);
}

/** A passkey, or a password instead: the choice both invitations and setup links offer. */
function Credential({
  minLength,
  busy,
  passkeyLabel,
  passwordLabel,
  onPasskey,
  onPassword,
  newPassword = true,
  remember,
  onRemember,
  preferPassword,
  error,
}: {
  minLength: number;
  busy: boolean;
  passkeyLabel: string;
  passwordLabel: string;
  onPasskey: () => void;
  onPassword: (password: string) => void;
  newPassword?: boolean;
  remember: boolean;
  onRemember: (remember: boolean) => void;
  preferPassword?: boolean;
  error: string | null;
}) {
  useLanguage();
  const passkeys = available();
  const [usePassword, setUsePassword] = useState(!passkeys || Boolean(preferPassword));
  const [password, setPassword] = useState('');
  const [again, setAgain] = useState('');
  const mismatch = again.length > 0 && again !== password;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (password.length >= minLength && password === again) onPassword(password);
  };
  return (
    <div className="credential">
      <label className="check">
        <input type="checkbox" checked={remember} onChange={(e) => onRemember(e.target.checked)} />
        <span>{t('Auf diesem Gerät angemeldet bleiben')}</span>
      </label>
      {!usePassword ? (
        <>
          <div className="passkey-explainer">
            <Icon name="key" size={20} />
            <p>
              {t(
                'Ein Passkey ist ein Schlüssel, den dein Gerät für dich aufbewahrt: Du meldest dich mit Fingerabdruck, Gesicht oder der Geräte-PIN an – ganz ohne Passwort.',
              )}
            </p>
          </div>
          <FormError error={error} />
          <button type="button" className="primary big-button" onClick={onPasskey} disabled={busy}>
            <Icon name="key" />
            {busy ? t('Einen Moment …') : passkeyLabel}
          </button>
          <p className="center-foot">
            <button type="button" className="link-button" onClick={() => setUsePassword(true)}>
              {t('Lieber ein Passwort')}
            </button>
          </p>
        </>
      ) : (
        <form className="form" onSubmit={submit}>
          <label className="field">
            <span>{t('Passwort')}</span>
            <PasswordInput
              value={password}
              onChange={setPassword}
              autoComplete={newPassword ? 'new-password' : 'current-password'}
              disabled={busy}
            />
            <small className="field-hint">
              {t('Mindestens {n} Zeichen. Ein Satz, den du dir merken kannst, ist ideal.', {
                n: minLength,
              })}
            </small>
          </label>
          <label className="field">
            <span>{t('Passwort noch einmal')}</span>
            <PasswordInput
              value={again}
              onChange={setAgain}
              autoComplete="new-password"
              disabled={busy}
            />
            {mismatch && (
              <small className="field-error">{t('Die beiden sind nicht gleich.')}</small>
            )}
          </label>
          <FormError error={error} />
          <button
            type="submit"
            className="primary big-button"
            disabled={busy || password.length < minLength || password !== again}
          >
            {busy ? t('Einen Moment …') : passwordLabel}
          </button>
          {passkeys && (
            <p className="center-foot">
              <button type="button" className="link-button" onClick={() => setUsePassword(false)}>
                {t('Doch lieber mit Passkey')}
              </button>
            </p>
          )}
        </form>
      )}
    </div>
  );
}

function Invite({ token, info }: { token: string; info: LinkInfo }) {
  useLanguage();
  const route = useRoute();
  const [displayName, setDisplayName] = useState(info.displayName ?? '');
  const [username, setUsername] = useState(suggestUsername(info.displayName ?? ''));
  const [typedUsername, setTypedUsername] = useState(false);
  const [email, setEmail] = useState('');
  const [givenName, setGivenName] = useState('');
  const [familyName, setFamilyName] = useState('');
  const [lang, setLang] = useState<'de' | 'en'>(language());
  const [remember, setRemember] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const account = () => ({
    username: username.trim(),
    displayName: displayName.trim() || username.trim(),
    givenName: givenName.trim() || undefined,
    familyName: familyName.trim() || undefined,
    email: info.email ? undefined : email.trim() || undefined,
    language: lang,
    remember,
  });

  const run = async (work: () => Promise<Json>) => {
    setBusy(true);
    setError(null);
    try {
      const body = await work();
      await api(`/uwu/v1/links/invite/${seg(token)}`, { body, anonymous: true });
      await signedIn(route.query);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  const ready = username.trim().length > 0 && displayName.trim().length > 0;
  return (
    <Centered wide>
      <NyuScene name="welcome" className="center-scene" />
      <h1 className="card-title">{t('Willkommen bei {name}!', { name: info.organization })}</h1>
      <p className="dialog-lead">
        {info.invitedBy
          ? t('{name} hat dich eingeladen. Leg dein Konto an – das dauert nur eine Minute.', {
              name: info.invitedBy,
            })
          : t('Du bist eingeladen. Leg dein Konto an – das dauert nur eine Minute.')}
      </p>
      <div className="form">
        <label className="field">
          <span>{t('Wie sollen wir dich nennen?')}</span>
          <input
            value={displayName}
            onChange={(e) => {
              setDisplayName(e.target.value);
              if (!typedUsername) setUsername(suggestUsername(e.target.value));
            }}
            autoComplete="name"
            autoFocus
            disabled={busy}
          />
        </label>
        <label className="field">
          <span>{t('Benutzername')}</span>
          <input
            value={username}
            onChange={(e) => {
              setUsername(e.target.value.toLowerCase());
              setTypedUsername(true);
            }}
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            disabled={busy}
          />
          <small className="field-hint">
            {t('Damit meldest du dich an. Kleinbuchstaben, Ziffern, Punkt und Strich.')}
          </small>
        </label>
        {info.email ? (
          <label className="field">
            <span>{t('E-Mail-Adresse')}</span>
            <input value={info.email} readOnly />
          </label>
        ) : (
          <label className="field">
            <span>{t('E-Mail-Adresse (freiwillig)')}</span>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              disabled={busy}
            />
            <small className="field-hint">
              {t('Für einen Link, falls du dein Passwort einmal vergisst.')}
            </small>
          </label>
        )}
        <div className="field">
          <span>{t('Sprache')}</span>
          <Segmented
            label={t('Sprache')}
            value={lang}
            onChange={(next) => {
              setLang(next);
              setLanguage(next);
            }}
            options={[
              { value: 'de', label: 'Deutsch' },
              { value: 'en', label: 'English' },
            ]}
          />
        </div>
        <details className="advanced">
          <summary>{t('Vor- und Nachname (freiwillig)')}</summary>
          <div className="field-pair">
            <label className="field">
              <span>{t('Vorname')}</span>
              <input
                value={givenName}
                onChange={(e) => setGivenName(e.target.value)}
                autoComplete="given-name"
              />
            </label>
            <label className="field">
              <span>{t('Nachname')}</span>
              <input
                value={familyName}
                onChange={(e) => setFamilyName(e.target.value)}
                autoComplete="family-name"
              />
            </label>
          </div>
        </details>
      </div>
      <h2 className="step-title">{t('Wie möchtest du dich anmelden?')}</h2>
      {ready ? (
        <Credential
          minLength={info.passwordMinLength}
          busy={busy}
          passkeyLabel={t('Mit Passkey weiter')}
          passwordLabel={t('Konto anlegen')}
          remember={remember}
          onRemember={setRemember}
          error={error}
          onPasskey={() =>
            void run(async () => {
              const options = await api<Json>(
                `/uwu/v1/links/invite/${seg(token)}/passkey-options`,
                {
                  body: {
                    username: username.trim(),
                    displayName: displayName.trim() || username.trim(),
                  },
                  anonymous: true,
                },
              );
              const credential = await createPasskey(options);
              return {
                ...account(),
                passkey: { credential, name: deviceName(navigator.userAgent) },
              };
            })
          }
          onPassword={(password) => void run(async () => ({ ...account(), password }))}
        />
      ) : (
        <p className="field-hint">{t('Zuerst dein Name und ein Benutzername.')}</p>
      )}
      <p className="field-hint center-foot">
        {t('Die Einladung gilt bis {when}.', { when: when(info.expires) })}
      </p>
    </Centered>
  );
}

function SetUp({
  token,
  info,
  purpose,
}: {
  token: string;
  info: LinkInfo;
  purpose: 'setup' | 'reset';
}) {
  useLanguage();
  const route = useRoute();
  const [remember, setRemember] = useState(purpose === 'setup');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async (work: () => Promise<Json>) => {
    setBusy(true);
    setError(null);
    try {
      const body = await work();
      await api(`/uwu/v1/links/${purpose}/${seg(token)}`, {
        body: { ...body, remember },
        anonymous: true,
      });
      await signedIn(route.query);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  let title: string;
  let lead: ReactNode;
  if (purpose === 'setup') {
    title = t('Hallo {name}!', { name: info.displayName ?? info.username ?? '' });
    lead = t(
      'Hier richtest du dein Konto {username} bei {organization} ein. Danach meldest du dich auf diesem Gerät ganz einfach an.',
      { username: info.username ?? '', organization: info.organization },
    );
  } else {
    title = t('Neues Passwort');
    lead = t('Für das Konto {username} bei {organization}. Danach bist du gleich angemeldet.', {
      username: info.username ?? '',
      organization: info.organization,
    });
  }

  return (
    <Centered>
      <NyuScene name={purpose === 'setup' ? 'welcome' : 'keys'} className="center-scene" />
      <h1 className="card-title">{title}</h1>
      <p className="dialog-lead">{lead}</p>
      <Credential
        minLength={info.passwordMinLength}
        busy={busy}
        preferPassword={purpose === 'reset'}
        passkeyLabel={purpose === 'setup' ? t('Mit Passkey einrichten') : t('Passkey anlegen')}
        passwordLabel={purpose === 'setup' ? t('Konto einrichten') : t('Passwort speichern')}
        remember={remember}
        onRemember={setRemember}
        error={error}
        onPasskey={() =>
          void run(async () => {
            const options = await api<Json>(
              `/uwu/v1/links/${purpose}/${seg(token)}/passkey-options`,
              { body: {}, anonymous: true },
            );
            const credential = await createPasskey(options);
            return { passkey: { credential, name: deviceName(navigator.userAgent) } };
          })
        }
        onPassword={(password) => void run(async () => ({ password }))}
      />
      <p className="field-hint center-foot">
        {t('Der Link gilt bis {when}.', { when: when(info.expires) })}
      </p>
    </Centered>
  );
}

function Verify({ token, info }: { token: string; info: LinkInfo }) {
  useLanguage();
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      await api(`/uwu/v1/links/verify/${seg(token)}`, { body: {}, anonymous: true });
      setDone(true);
      void reloadMe();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Centered>
      <NyuScene name={done ? 'done' : 'invite'} className="center-scene" />
      <h1 className="card-title">{done ? t('Bestätigt ✧') : t('Adresse bestätigen')}</h1>
      <p className="dialog-lead">
        {done
          ? t('{email} ist jetzt deine Adresse.', { email: info.email ?? '' })
          : t('Soll {email} deine Adresse bei {organization} werden?', {
              email: info.email ?? '',
              organization: info.organization,
            })}
      </p>
      <FormError error={error} />
      {done ? (
        <a className="button-link primary big-button" href="#/">
          {t('Zum Portal')}
        </a>
      ) : (
        <button
          type="button"
          className="primary big-button"
          onClick={() => void confirm()}
          disabled={busy}
        >
          {t('Ja, bestätigen')}
        </button>
      )}
    </Centered>
  );
}
