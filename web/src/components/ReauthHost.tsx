import { useEffect, useState, type FormEvent } from 'react';
import { api } from '../lib/api';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { cancelled, confirmed, useReauthAsked } from '../lib/reauth';
import type { Me } from '../lib/types';
import { available, getPasskey } from '../lib/webauthn';
import { FormError } from './controls';
import { Icon } from './Icon';
import { Modal } from './Modal';
import { PasswordInput } from './PasswordInput';

/** The "confirm that it's you" dialog, whenever the API layer asks for it. */
export function ReauthHost() {
  const asked = useReauthAsked();
  return asked ? <ReauthDialog /> : null;
}

function ReauthDialog() {
  useLanguage();
  const [me, setMe] = useState<Me | null>(null);
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // What it asks for depends on what the person has: a passkey, a password, the app.
    api<Me>('/uwu/v1/me').then(setMe, (e) => setError(errorText(e)));
  }, []);

  const withPasskey = async () => {
    setBusy(true);
    setError(null);
    try {
      const options = await api<Record<string, unknown>>('/uwu/v1/reauth/options', {
        body: {},
        noReauth: true,
      });
      const passkey = await getPasskey(options);
      await api('/uwu/v1/reauth', { body: { passkey }, noReauth: true });
      confirmed();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  const withPassword = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api('/uwu/v1/reauth', {
        body: { password, code: me?.hasTotp ? code.replace(/\s/g, '') : undefined },
        noReauth: true,
      });
      confirmed();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  const passkeys = (me?.passkeys.length ?? 0) > 0 && available();
  // Whoever has a passkey and no authenticator app confirms with the passkey: a password alone
  // is less than what they sign in with.
  const offerPassword = me?.hasPassword && !(passkeys && !me.hasTotp);
  return (
    <Modal
      title={t('Bestätige, dass du es bist')}
      onCancel={() => !busy && cancelled()}
      footer={
        <>
          <span className="spacer" />
          <button type="button" data-secondary onClick={cancelled} disabled={busy}>
            {t('Abbrechen')}
          </button>
          {offerPassword && (
            <button
              type="submit"
              form="reauth-password"
              className={passkeys ? undefined : 'primary'}
              disabled={busy || !password || (me?.hasTotp && code.replace(/\s/g, '').length < 6)}
            >
              {t('Bestätigen')}
            </button>
          )}
        </>
      }
    >
      <p className="dialog-lead">
        {t(
          'Das schützt dein Konto: Wer an einem offenen Gerät vorbeikommt, soll nicht ändern können, wie du dich anmeldest.',
        )}
      </p>
      {passkeys && (
        <button
          type="button"
          className="primary big-button"
          onClick={() => void withPasskey()}
          disabled={busy}
          data-autofocus
        >
          <Icon name="key" />
          {t('Mit Passkey bestätigen')}
        </button>
      )}
      {offerPassword && me && (
        <form id="reauth-password" className="form" onSubmit={withPassword}>
          {passkeys && <p className="or-line">{t('oder mit deinem Passwort')}</p>}
          <label className="field">
            <span>{t('Passwort')}</span>
            <PasswordInput
              value={password}
              onChange={setPassword}
              autoFocus={!passkeys}
              disabled={busy}
            />
          </label>
          {me.hasTotp && (
            <label className="field">
              <span>{t('Code aus der Authenticator-App')}</span>
              <input
                className="code-input"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                maxLength={7}
                disabled={busy}
              />
            </label>
          )}
        </form>
      )}
      <FormError error={error} />
    </Modal>
  );
}
