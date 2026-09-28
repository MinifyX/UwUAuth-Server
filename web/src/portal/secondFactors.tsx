/**
 * Adding a passkey and the authenticator app, and showing recovery codes: the security page
 * uses them, and so does the screen for a session that has to set one up first.
 */

import { useEffect, useState } from 'react';
import { FormError } from '../components/controls';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { Qr } from '../components/Qr';
import { api, saveFile } from '../lib/api';
import { copy } from '../lib/clipboard';
import { errorText } from '../lib/errors';
import { grouped } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { createPasskey, deviceName } from '../lib/webauthn';

type Json = Record<string, unknown>;

/** Make a passkey on this device and keep it for the signed-in person. */
export async function addPasskey(name: string) {
  const options = await api<Json>('/uwu/v1/me/passkeys/options', { body: {} });
  const credential = await createPasskey(options);
  await api('/uwu/v1/me/passkeys', { body: { credential, name: name.trim() || 'Passkey' } });
}

export function AddPasskeyDialog({
  onCancel,
  onDone,
}: {
  onCancel: () => void;
  onDone: () => void;
}) {
  useLanguage();
  const [name, setName] = useState(() => deviceName(navigator.userAgent));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const add = async () => {
    setBusy(true);
    setError(null);
    try {
      await addPasskey(name);
      onDone();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t('Passkey hinzufügen')}
      onCancel={() => !busy && onCancel()}
      footer={
        <>
          <span className="spacer" />
          <button type="button" data-secondary onClick={onCancel} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button
            type="button"
            className="primary"
            onClick={() => void add()}
            disabled={busy || !name.trim()}
          >
            <Icon name="key" />
            {busy ? t('Folge deinem Gerät …') : t('Passkey anlegen')}
          </button>
        </>
      }
    >
      <p className="dialog-lead">
        {t(
          'Dein Gerät fragt gleich nach Fingerabdruck, Gesicht oder PIN. Du kannst den Passkey auch auf dem Handy anlegen, wenn dein Browser das anbietet.',
        )}
      </p>
      <label className="field">
        <span>{t('Name, damit du ihn später wiedererkennst')}</span>
        <input
          value={name}
          maxLength={60}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && name.trim() && void add()}
          autoFocus
        />
      </label>
      <FormError error={error} />
    </Modal>
  );
}

/** The recovery codes, shown once: to write down, copy or save as a file. */
export function RecoveryCodes({ codes, organization }: { codes: string[]; organization: string }) {
  useLanguage();
  const file = [
    t('Wiederherstellungscodes für {name}', { name: organization }),
    t('Jeder Code funktioniert einmal. Heb sie getrennt von deinen Geräten auf.'),
    '',
    ...codes,
    '',
  ].join('\n');
  return (
    <div className="recovery">
      <p className="dialog-lead">
        {t(
          'Mit einem dieser Codes kommst du rein, wenn dein Handy mal weg ist. Jeder funktioniert einmal. Schreib sie auf oder speichere sie – du siehst sie nur jetzt.',
        )}
      </p>
      <ol className="code-list">
        {codes.map((code) => (
          <li key={code}>
            <code>{code}</code>
          </li>
        ))}
      </ol>
      <div className="form-actions">
        <button type="button" onClick={() => void copy(codes.join('\n'))}>
          <Icon name="copy" />
          {t('Kopieren')}
        </button>
        <button
          type="button"
          onClick={() =>
            saveFile(new Blob([file], { type: 'text/plain' }), 'uwuauth-recovery-codes.txt')
          }
        >
          <Icon name="download" />
          {t('Als Textdatei speichern')}
        </button>
      </div>
    </div>
  );
}

/**
 * The authenticator app: a QR code to scan (or the secret to type), then one code from the app
 * to show it works. The first time, recovery codes come with it.
 */
export function TotpDialog({
  organization,
  onCancel,
  onDone,
}: {
  organization: string;
  onCancel: () => void;
  onDone: () => void;
}) {
  useLanguage();
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<{ secret: string; uri: string }>('/uwu/v1/me/totp/start', { body: {} }).then(
      setSetup,
      (e) => setError(errorText(e)),
    );
  }, []);

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      const answer = await api<{ recoveryCodes: string[] | null }>('/uwu/v1/me/totp', {
        body: { code: code.replace(/\s/g, '') },
      });
      if (answer.recoveryCodes?.length) setCodes(answer.recoveryCodes);
      else onDone();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  if (codes) {
    return (
      <Modal
        title={t('Deine Wiederherstellungscodes')}
        onCancel={onDone}
        footer={
          <>
            <span className="spacer" />
            <button type="button" className="primary" onClick={onDone}>
              {t('Aufgeschrieben – fertig')}
            </button>
          </>
        }
      >
        <RecoveryCodes codes={codes} organization={organization} />
      </Modal>
    );
  }

  return (
    <Modal
      title={t('Authenticator-App einrichten')}
      onCancel={() => !busy && onCancel()}
      footer={
        <>
          <span className="spacer" />
          <button type="button" data-secondary onClick={onCancel} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button
            type="button"
            className="primary"
            onClick={() => void confirm()}
            disabled={busy || !setup || code.replace(/\s/g, '').length < 6}
          >
            {t('Einschalten')}
          </button>
        </>
      }
    >
      <p className="dialog-lead">
        {t(
          'Scanne den Code mit einer App wie Aegis, 2FAS, Google Authenticator oder der Passwort-App deines Handys. Sie zeigt dann alle 30 Sekunden einen neuen sechsstelligen Code.',
        )}
      </p>
      {setup && (
        <>
          <Qr value={setup.uri} label={t('QR-Code für die Authenticator-App')} />
          <p className="field-hint center-text">{t('Oder tipp den Schlüssel ab:')}</p>
          <code className="secret-key" data-testid="totp-secret">
            {grouped(setup.secret)}
          </code>
          <label className="field">
            <span>{t('Code aus der App')}</span>
            <input
              className="code-input"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && void confirm()}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={7}
              autoFocus
            />
          </label>
        </>
      )}
      <FormError error={error} />
    </Modal>
  );
}
