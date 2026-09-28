import { useEffect, useRef, useState, type FormEvent } from 'react';
import { FormError } from '../components/controls';
import { Icon } from '../components/Icon';
import { Nyu } from '../components/nyu/Nyu';
import { PasswordInput } from '../components/PasswordInput';
import { Centered } from '../components/Shell';
import { api } from '../lib/api';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { reloadMe } from '../lib/me';
import { continueTarget, go, useRoute } from '../lib/route';
import { autofillAvailable, available, getPasskey } from '../lib/webauthn';

type Answer =
  | { status: 'signed_in'; restricted: boolean }
  | { status: 'second_factor'; pending: string; methods: ('totp' | 'passkey' | 'recovery')[] };

type Json = Record<string, unknown>;

/** After signing in: where `?continue=` points, or the portal. */
export async function afterSignIn(query: URLSearchParams) {
  const target = continueTarget(query.get('continue'));
  if (target) {
    location.href = target;
    return;
  }
  await reloadMe();
  go('/');
}

/**
 * Signing in: a name and a password, or a passkey — offered in the name field's suggestions
 * where the browser can, and as a big button everywhere else. A second step follows for
 * whoever has one.
 */
export function SignIn() {
  useLanguage();
  const route = useRoute();
  const [login, setLogin] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [second, setSecond] = useState<Extract<Answer, { status: 'second_factor' }> | null>(null);
  const autofill = useRef<AbortController | null>(null);
  const rememberRef = useRef(remember);
  rememberRef.current = remember;

  const done = async (answer: Answer) => {
    if (answer.status === 'second_factor') {
      setSecond(answer);
      setBusy(false);
      return;
    }
    await afterSignIn(route.query);
  };

  // Passkeys in the name field's suggestions: the browser shows them while one types, and
  // picking one signs in without anything else.
  useEffect(() => {
    let stopped = false;
    const start = async () => {
      if (!(await autofillAvailable()) || stopped) return;
      const controller = new AbortController();
      autofill.current = controller;
      try {
        const { id, options } = await api<{ id: string; options: Json }>(
          '/uwu/v1/login/passkey/options',
          { body: {}, anonymous: true },
        );
        const credential = await getPasskey(options, { signal: controller.signal });
        setBusy(true);
        const answer = await api<Answer>('/uwu/v1/login/passkey', {
          body: { id, credential, remember: rememberRef.current },
          anonymous: true,
        });
        await done(answer);
      } catch (e) {
        if (!controller.signal.aborted && !stopped) {
          setError(errorText(e));
          setBusy(false);
        }
      }
    };
    void start();
    return () => {
      stopped = true;
      autofill.current?.abort();
    };
    // Once per visit of the page; `done` only reads the route.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const withPassword = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const answer = await api<Answer>('/uwu/v1/login', {
        body: { login: login.trim(), password, remember },
        anonymous: true,
      });
      await done(answer);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  const withPasskey = async () => {
    autofill.current?.abort();
    setBusy(true);
    setError(null);
    try {
      const { id, options } = await api<{ id: string; options: Json }>(
        '/uwu/v1/login/passkey/options',
        { body: {}, anonymous: true },
      );
      const credential = await getPasskey(options);
      const answer = await api<Answer>('/uwu/v1/login/passkey', {
        body: { id, credential, remember },
        anonymous: true,
      });
      await done(answer);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  if (second) {
    return (
      <SecondStep
        pending={second.pending}
        methods={second.methods}
        onBack={() => {
          setSecond(null);
          setPassword('');
        }}
      />
    );
  }

  return (
    <Centered>
      <div className="signin-head">
        <Nyu size={92} mood="happy" />
        <h1 className="card-title">{t('Anmelden')}</h1>
        <p className="muted">{t('Schön, dass du da bist.')}</p>
      </div>
      {available() && (
        <>
          <button
            type="button"
            className="primary big-button"
            onClick={() => void withPasskey()}
            disabled={busy}
          >
            <Icon name="key" />
            {t('Mit Passkey anmelden')}
          </button>
          <p className="or-line">{t('oder mit Name und Passwort')}</p>
        </>
      )}
      <form className="form" onSubmit={withPassword}>
        <label className="field">
          <span>{t('Benutzername oder E-Mail-Adresse')}</span>
          <input
            name="username"
            value={login}
            onChange={(e) => setLogin(e.target.value)}
            autoComplete="username webauthn"
            autoCapitalize="none"
            spellCheck={false}
            disabled={busy}
            required
          />
        </label>
        <label className="field">
          <span>{t('Passwort')}</span>
          <PasswordInput value={password} onChange={setPassword} disabled={busy} />
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={remember}
            onChange={(e) => setRemember(e.target.checked)}
          />
          <span>{t('Auf diesem Gerät angemeldet bleiben')}</span>
        </label>
        <FormError error={error} />
        <button
          type="submit"
          className={available() ? 'big-button' : 'primary big-button'}
          disabled={busy || !login.trim() || !password}
        >
          {busy ? t('Einen Moment …') : t('Anmelden')}
        </button>
      </form>
      <p className="center-foot">
        <a href="#/forgot">{t('Passwort vergessen?')}</a>
      </p>
    </Centered>
  );
}

/** The second step: a code from the app, a passkey, or a recovery code. */
function SecondStep({
  pending,
  methods,
  onBack,
}: {
  pending: string;
  methods: ('totp' | 'passkey' | 'recovery')[];
  onBack: () => void;
}) {
  useLanguage();
  const route = useRoute();
  const [code, setCode] = useState('');
  const [recovery, setRecovery] = useState<string | null>(methods.includes('totp') ? null : '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const send = async (body: Json) => {
    setBusy(true);
    setError(null);
    try {
      const answer = await api<Answer>('/uwu/v1/login/second', {
        body: { pending, ...body },
        anonymous: true,
      });
      if (answer.status === 'signed_in') await afterSignIn(route.query);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  const withPasskey = async () => {
    setBusy(true);
    setError(null);
    try {
      const options = await api<Json>('/uwu/v1/login/second/options', {
        body: { pending },
        anonymous: true,
      });
      const passkey = await getPasskey(options);
      await send({ passkey });
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (recovery !== null) void send({ recovery: recovery.trim() });
    else void send({ code: code.replace(/\s/g, '') });
  };

  return (
    <Centered>
      <div className="signin-head">
        <Nyu size={80} mood="sparkle" />
        <h1 className="card-title">{t('Noch ein Schritt')}</h1>
        <p className="muted">
          {t('Zeig kurz, dass wirklich du es bist. So reicht ein Passwort allein nicht.')}
        </p>
      </div>
      {methods.includes('passkey') && available() && (
        <button
          type="button"
          className="primary big-button"
          onClick={() => void withPasskey()}
          disabled={busy}
        >
          <Icon name="key" />
          {t('Mit Passkey bestätigen')}
        </button>
      )}
      {(methods.includes('totp') || recovery !== null) && (
        <form className="form" onSubmit={submit}>
          {methods.includes('passkey') && available() && <p className="or-line">{t('oder')}</p>}
          {recovery === null ? (
            <label className="field">
              <span>{t('Code aus der Authenticator-App')}</span>
              <input
                className="code-input"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={7}
                autoFocus={!methods.includes('passkey')}
                disabled={busy}
              />
            </label>
          ) : (
            <label className="field">
              <span>{t('Wiederherstellungscode')}</span>
              <input
                className="code-input"
                value={recovery}
                onChange={(e) => setRecovery(e.target.value)}
                autoComplete="off"
                autoCapitalize="characters"
                spellCheck={false}
                autoFocus
                disabled={busy}
              />
            </label>
          )}
          <FormError error={error} />
          <button
            type="submit"
            className="big-button"
            disabled={
              busy ||
              (recovery === null ? code.replace(/\s/g, '').length < 6 : recovery.trim().length < 4)
            }
          >
            {t('Weiter')}
          </button>
        </form>
      )}
      {!(methods.includes('totp') || recovery !== null) && <FormError error={error} />}
      <p className="center-foot">
        {methods.includes('recovery') && recovery === null && (
          <button type="button" className="link-button" onClick={() => setRecovery('')}>
            {t('Wiederherstellungscode benutzen')}
          </button>
        )}
        {recovery !== null && methods.includes('totp') && (
          <button type="button" className="link-button" onClick={() => setRecovery(null)}>
            {t('Doch den Code aus der App')}
          </button>
        )}
        <button type="button" className="link-button" onClick={onBack}>
          {t('Zurück')}
        </button>
      </p>
    </Centered>
  );
}

/** "Forgot password": a link by mail, if there is an account with an address. */
export function Forgot() {
  useLanguage();
  const [login, setLogin] = useState('');
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api('/uwu/v1/forgot', { body: { login: login.trim() }, anonymous: true });
      setSent(true);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Centered>
      <div className="signin-head">
        <Nyu size={80} mood={sent ? 'happy' : 'puzzled'} />
        <h1 className="card-title">{t('Passwort vergessen?')}</h1>
      </div>
      {sent ? (
        <p className="dialog-lead">
          {t(
            'Wenn es das Konto gibt und es eine Adresse hat, ist ein Link unterwegs. Schau in dein Postfach – der Link gilt eine Stunde.',
          )}
        </p>
      ) : (
        <form className="form" onSubmit={submit}>
          <p className="dialog-lead">
            {t(
              'Gib deinen Namen oder deine Adresse ein. Du bekommst einen Link, mit dem du ein neues Passwort setzt.',
            )}
          </p>
          <label className="field">
            <span>{t('Benutzername oder E-Mail-Adresse')}</span>
            <input
              value={login}
              onChange={(e) => setLogin(e.target.value)}
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              autoFocus
              required
            />
          </label>
          <p className="field-hint">
            {t(
              'Für ein Konto, um das sich jemand kümmert – etwa das eines Kindes –, kommt kein Link. Da hilft, wer sich darum kümmert.',
            )}
          </p>
          <FormError error={error} />
          <button type="submit" className="primary big-button" disabled={busy || !login.trim()}>
            {t('Link schicken')}
          </button>
        </form>
      )}
      <p className="center-foot">
        <a href="#/login">{t('Zurück zur Anmeldung')}</a>
      </p>
    </Centered>
  );
}
