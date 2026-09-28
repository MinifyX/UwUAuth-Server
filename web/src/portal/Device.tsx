import { useEffect, useRef, useState, type FormEvent } from 'react';
import { AppIcon } from '../components/AppIcon';
import { FormError } from '../components/controls';
import { Icon } from '../components/Icon';
import { Nyu } from '../components/nyu/Nyu';
import { NyuScene } from '../components/nyu/scenes';
import { Centered } from '../components/Shell';
import { api, ApiError, seg } from '../lib/api';
import { formatUserCode } from '../lib/apps';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { go } from '../lib/route';
import type { DeviceInfo } from '../lib/types';
import { ScopeList } from './Consent';
import { deniedText } from './Notices';

type Step =
  { kind: 'code' } | { kind: 'confirm'; info: DeviceInfo } | { kind: 'done'; approved: boolean };

function deviceError(error: unknown, app: string | null): string {
  if (error instanceof ApiError) {
    if (error.status === 404)
      return t(
        'Diesen Code kennt der Server nicht – oder er ist schon abgelaufen. Prüf ihn bitte.',
      );
    const reason = error.detail?.reason;
    if (typeof reason === 'string') {
      const { text } = deniedText(reason, app);
      return text;
    }
  }
  return errorText(error);
}

/**
 * A TV or a command line shows a short code; here one types it, sees which app it is, and lets
 * the device in.
 */
export function Device({ initial }: { initial: string }) {
  useLanguage();
  const [code, setCode] = useState(formatUserCode(initial));
  const [step, setStep] = useState<Step>({ kind: 'code' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const looked = useRef(false);

  const lookUp = async (event?: FormEvent) => {
    event?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const info = await api<DeviceInfo>(`/uwu/v1/device/${seg(code)}`);
      setStep({ kind: 'confirm', info });
    } catch (e) {
      setError(deviceError(e, null));
    } finally {
      setBusy(false);
    }
  };

  // A link or QR code with the code in it: straight to "which app".
  useEffect(() => {
    if (looked.current || code.length !== 9) return;
    looked.current = true;
    void lookUp();
    // Once, for the code from the link.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const decide = async (info: DeviceInfo, approve: boolean) => {
    setBusy(true);
    setError(null);
    try {
      await api(`/uwu/v1/device/${seg(info.code)}`, { body: { approve } });
      setStep({ kind: 'done', approved: approve });
    } catch (e) {
      setError(deviceError(e, info.app.name));
    } finally {
      setBusy(false);
    }
  };

  if (step.kind === 'done')
    return (
      <Centered>
        <NyuScene name={step.approved ? 'done' : 'sleepy'} className="center-scene" />
        <h1 className="card-title">{step.approved ? t('Verbunden ✧') : t('Nicht verbunden')}</h1>
        <p className="dialog-lead">
          {step.approved
            ? t('Das Gerät ist gleich angemeldet. Du kannst dieses Fenster jetzt schließen.')
            : t('Das Gerät bekommt keinen Zugang. Du kannst dieses Fenster jetzt schließen.')}
        </p>
        <p className="center-foot">
          <a href="#/">{t('Zu meinem Konto')}</a>
        </p>
      </Centered>
    );

  if (step.kind === 'confirm') {
    const { info } = step;
    return (
      <Centered>
        <div className="signin-head">
          <AppIcon name={info.app.name} size={64} />
          <h1 className="card-title">{t('„{app}“ verbinden?', { app: info.app.name })}</h1>
          {info.app.description && <p className="muted">{info.app.description}</p>}
        </div>
        <code className="secret-key big">{info.code}</code>
        <p className="caution">
          <Icon name="warning" />
          <span>
            {t(
              'Verbinde nur, wenn du diesen Code gerade selbst auf deinem Gerät siehst. Hat dir jemand den Code geschickt, brich ab.',
            )}
          </span>
        </p>
        <div className="consent-box">
          <p className="consent-title">{t('Das Gerät bekommt:')}</p>
          <ScopeList scopes={info.scopes} />
        </div>
        <FormError error={error} />
        <div className="form-actions center">
          <button type="button" onClick={() => void decide(info, false)} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button
            type="button"
            className="primary"
            onClick={() => void decide(info, true)}
            disabled={busy}
          >
            {t('Verbinden')}
          </button>
        </div>
      </Centered>
    );
  }

  return (
    <Centered>
      <div className="signin-head">
        <Nyu size={80} mood="happy" />
        <h1 className="card-title">{t('Gerät verbinden')}</h1>
        <p className="muted">
          {t('Gib den Code ein, den dein Fernseher oder dein Programm gerade zeigt.')}
        </p>
      </div>
      <form className="form" onSubmit={lookUp}>
        <label className="field">
          <span>{t('Code')}</span>
          <input
            className="code-input"
            value={code}
            onChange={(e) => setCode(formatUserCode(e.target.value))}
            placeholder="ABCD-EFGH"
            autoComplete="one-time-code"
            autoCapitalize="characters"
            spellCheck={false}
            maxLength={9}
            autoFocus
            disabled={busy}
          />
        </label>
        <FormError error={error} />
        <button type="submit" className="primary big-button" disabled={busy || code.length !== 9}>
          {busy ? t('Einen Moment …') : t('Weiter')}
        </button>
      </form>
      <p className="center-foot">
        <button type="button" className="link-button" onClick={() => go('/')}>
          {t('Zu meinem Konto')}
        </button>
      </p>
    </Centered>
  );
}
