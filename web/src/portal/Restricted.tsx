import { useState } from 'react';
import { FormError } from '../components/controls';
import { Icon } from '../components/Icon';
import { NyuScene } from '../components/nyu/scenes';
import { Centered } from '../components/Shell';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { reloadMe } from '../lib/me';
import type { Me } from '../lib/types';
import { available, deviceName } from '../lib/webauthn';
import { addPasskey, TotpDialog } from './secondFactors';

/**
 * A group this person is in asks for a second factor, and they have none yet: until they add
 * one, this is all the session reaches. Friendly, one step, and then the portal opens.
 */
export function Restricted({ me }: { me: Me }) {
  useLanguage();
  const [totp, setTotp] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const withPasskey = async () => {
    setBusy(true);
    setError(null);
    try {
      await addPasskey(deviceName(navigator.userAgent));
      await reloadMe();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  return (
    <Centered>
      <NyuScene name="keys" className="center-scene" />
      <h1 className="card-title">
        {t('Noch ein kleiner Schritt, {name}', { name: me.displayName })}
      </h1>
      <p className="dialog-lead">
        {t(
          'Bei {organization} braucht dein Konto eine zweite Sicherung, damit ein Passwort allein nicht reicht. Richte eine ein – danach geht es gleich weiter.',
          { organization: me.server.organization },
        )}
      </p>
      {available() && (
        <div className="choice-card">
          <p className="choice-title">
            <Icon name="key" />
            {t('Passkey auf diesem Gerät')}
          </p>
          <p className="field-hint">
            {t(
              'Am einfachsten: Du meldest dich künftig mit Fingerabdruck, Gesicht oder PIN an. Ein Passkey zählt gleich doppelt.',
            )}
          </p>
          <button
            type="button"
            className="primary big-button"
            onClick={() => void withPasskey()}
            disabled={busy}
          >
            {busy ? t('Folge deinem Gerät …') : t('Passkey anlegen')}
          </button>
        </div>
      )}
      <div className="choice-card">
        <p className="choice-title">
          <Icon name="smartphone" />
          {t('Authenticator-App')}
        </p>
        <p className="field-hint">
          {t('Eine App auf deinem Handy zeigt dir bei jeder Anmeldung einen Code.')}
        </p>
        <button type="button" className="big-button" onClick={() => setTotp(true)} disabled={busy}>
          {t('App einrichten')}
        </button>
      </div>
      <FormError error={error} />
      {totp && (
        <TotpDialog
          organization={me.server.organization}
          onCancel={() => setTotp(false)}
          onDone={() => {
            setTotp(false);
            void reloadMe();
          }}
        />
      )}
    </Centered>
  );
}
