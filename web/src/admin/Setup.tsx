import { useEffect, useState, type FormEvent } from 'react';
import { FormError, Segmented } from '../components/controls';
import { Icon } from '../components/Icon';
import { NyuScene } from '../components/nyu/scenes';
import { Centered } from '../components/Shell';
import { api } from '../lib/api';
import { errorText } from '../lib/errors';
import { language, setLanguage, t, useLanguage } from '../lib/i18n';
import { reloadMe } from '../lib/me';
import type { Me, Mode } from '../lib/types';

/**
 * The first admin's assistant: what the household or company is called, family or office, the
 * language and the time zone. Four small steps; mail and the rest come later in the settings.
 */
export function Setup({ me }: { me: Me }) {
  useLanguage();
  const [step, setStep] = useState(0);
  const [organization, setOrganization] = useState(
    me.server.organization === 'UwUAuth' ? '' : me.server.organization,
  );
  const [mode, setMode] = useState<Mode>(me.server.mode);
  const [lang, setLang] = useState<'de' | 'en'>(language());
  const [zones, setZones] = useState<string[]>([]);
  const [timezone, setTimezone] = useState(
    () => Intl.DateTimeFormat().resolvedOptions().timeZone || 'Europe/Berlin',
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<string[]>('/uwu/v1/timezones').then(setZones, () => setZones([]));
  }, []);

  const finish = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api('/uwu/v1/setup', {
        body: { organization: organization.trim(), mode, language: lang, timezone },
      });
      setStep(3);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const dots = (
    <div className="steps" aria-label={t('Schritt {n} von 3', { n: Math.min(step + 1, 3) })}>
      {[0, 1, 2].map((index) => (
        <span key={index} data-on={index <= step || undefined} />
      ))}
    </div>
  );

  if (step === 3) {
    return (
      <Centered>
        <NyuScene name="done" className="center-scene" />
        <h1 className="card-title">{t('Fertig ✧')}</h1>
        <p className="dialog-lead">
          {mode === 'family'
            ? t(
                'UwUAuth ist bereit für {name}. Als Nächstes: Lade deine Familie ein oder leg Konten für die Kinder an – sie richten sich per QR-Code selbst ein.',
                { name: organization.trim() },
              )
            : t(
                'UwUAuth ist bereit für {name}. Als Nächstes: Leg Gruppen an und lade dein Team ein. Unter Einstellungen richtest du Mails ein.',
                { name: organization.trim() },
              )}
        </p>
        <button type="button" className="primary big-button" onClick={() => void reloadMe()}>
          {t('Los geht’s')}
        </button>
      </Centered>
    );
  }

  return (
    <Centered wide>
      {dots}
      {step === 0 && (
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            if (organization.trim()) setStep(1);
          }}
        >
          <NyuScene name="welcome" className="center-scene" />
          <h1 className="card-title">
            {t('Hallo {name}, willkommen bei UwUAuth!', { name: me.displayName })}
          </h1>
          <p className="dialog-lead">
            {t(
              'Hier meldet sich künftig jede App an, und hier verwaltest du alle, die dazugehören. Drei kurze Fragen, dann geht es los.',
            )}
          </p>
          <label className="field">
            <span>{t('Wie heißt ihr?')}</span>
            <input
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
              placeholder={t('z. B. Familie Neko oder Nyu & Co.')}
              maxLength={80}
              autoFocus
            />
            <small className="field-hint">{t('Steht auf der Anmeldeseite und in Mails.')}</small>
          </label>
          <button type="submit" className="primary big-button" disabled={!organization.trim()}>
            {t('Weiter')}
          </button>
        </form>
      )}
      {step === 1 && (
        <div className="form">
          <h1 className="card-title">{t('Wofür ist UwUAuth da?')}</h1>
          <p className="dialog-lead">
            {t(
              'Das ändert nur ein paar Wörter und Voreinstellungen. Du kannst es später umstellen.',
            )}
          </p>
          <div className="mode-cards">
            <button
              type="button"
              className="mode-card"
              aria-pressed={mode === 'family'}
              onClick={() => setMode('family')}
            >
              <NyuScene name="family" className="mode-scene" />
              <b>{t('Familie')}</b>
              <small>
                {t('Eltern kümmern sich um die Konten der Kinder, mit Zeitfenstern und QR-Codes.')}
              </small>
            </button>
            <button
              type="button"
              className="mode-card"
              aria-pressed={mode === 'office'}
              onClick={() => setMode('office')}
            >
              <NyuScene name="invite" className="mode-scene" />
              <b>{t('Büro oder Verein')}</b>
              <small>{t('Teams, Gruppen und eine Verwaltung, die sich um Konten kümmert.')}</small>
            </button>
          </div>
          <div className="form-actions">
            <button type="button" onClick={() => setStep(0)}>
              {t('Zurück')}
            </button>
            <span className="spacer" />
            <button type="button" className="primary" onClick={() => setStep(2)}>
              {t('Weiter')}
            </button>
          </div>
        </div>
      )}
      {step === 2 && (
        <form className="form" onSubmit={finish}>
          <h1 className="card-title">{t('Sprache und Zeit')}</h1>
          <div className="field">
            <span>{t('Sprache für neue Konten und Mails')}</span>
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
          <label className="field">
            <span>{t('Zeitzone')}</span>
            <select value={timezone} onChange={(e) => setTimezone(e.target.value)}>
              {(zones.length ? zones : [timezone]).map((zone) => (
                <option key={zone} value={zone}>
                  {zone.replace(/_/g, ' ')}
                </option>
              ))}
            </select>
            <small className="field-hint">{t('Für Zeitfenster und die Uhrzeiten in Mails.')}</small>
          </label>
          <FormError error={error} />
          <div className="form-actions">
            <button type="button" onClick={() => setStep(1)} disabled={busy}>
              {t('Zurück')}
            </button>
            <span className="spacer" />
            <button type="submit" className="primary" disabled={busy}>
              <Icon name="check" />
              {t('Fertig einrichten')}
            </button>
          </div>
        </form>
      )}
    </Centered>
  );
}
