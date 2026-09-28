import { useEffect, useState } from 'react';
import { Loading } from '../components/bits';
import { Row, Section, Segmented, Toggle, useAction } from '../components/controls';
import { PasswordInput } from '../components/PasswordInput';
import { PageTitle } from '../components/Shell';
import { api } from '../lib/api';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { reloadMe } from '../lib/me';
import { toast } from '../lib/toast';
import type { Me, Settings, Smtp } from '../lib/types';

const EMPTY_SMTP: Smtp = {
  host: '',
  port: 587,
  security: 'starttls',
  username: null,
  from: '',
  fromName: 'UwUAuth',
};

/** The server's settings, kept in its database; `.env` only gave the start. */
export function AdminSettings({ me }: { me: Me }) {
  useLanguage();
  const [saved, setSaved] = useState<Settings | null>(null);
  const [draft, setDraft] = useState<Settings | null>(null);
  const [smtpPassword, setSmtpPassword] = useState('');
  const [zones, setZones] = useState<string[]>([]);
  const [run, busy] = useAction();

  useEffect(() => {
    api<Settings>('/uwu/v1/settings').then(
      (loaded) => {
        setSaved(loaded);
        setDraft(loaded);
      },
      (e) => toast(errorText(e), 'error'),
    );
    api<string[]>('/uwu/v1/timezones').then(setZones, () => undefined);
  }, []);

  if (!draft || !saved) return <Loading />;
  const set = (patch: Partial<Settings>) => setDraft({ ...draft, ...patch });
  const smtp = draft.smtp ?? EMPTY_SMTP;
  const setSmtp = (patch: Partial<Smtp>) => set({ smtp: { ...smtp, ...patch } });
  const dirty = JSON.stringify(draft) !== JSON.stringify(saved) || smtpPassword !== '';
  const number = (value: string, fallback: number) => {
    const parsed = Number.parseInt(value, 10);
    return Number.isFinite(parsed) ? parsed : fallback;
  };

  const save = () =>
    run(async () => {
      const body = {
        ...draft,
        smtp: draft.smtp && draft.smtp.host.trim() ? draft.smtp : null,
        smtpPassword: smtpPassword || undefined,
      };
      const next = await api<Settings>('/uwu/v1/settings', { method: 'PUT', body });
      setSaved(next);
      setDraft(next);
      setSmtpPassword('');
      await reloadMe();
      toast(t('Gespeichert ✧'));
    });

  return (
    <div className="settings-page">
      <PageTitle>{t('Einstellungen')}</PageTitle>

      <Section title={t('Allgemein')}>
        <div className="field-pair">
          <label className="field">
            <span>{t('Name')}</span>
            <input
              value={draft.organization}
              maxLength={80}
              onChange={(e) => set({ organization: e.target.value })}
            />
            <small className="field-hint">{t('Steht auf der Anmeldeseite und in Mails.')}</small>
          </label>
          <label className="field">
            <span>{t('Zeitzone')}</span>
            <select value={draft.timezone} onChange={(e) => set({ timezone: e.target.value })}>
              {(zones.length ? zones : [draft.timezone]).map((zone) => (
                <option key={zone} value={zone}>
                  {zone.replace(/_/g, ' ')}
                </option>
              ))}
            </select>
          </label>
        </div>
        <Row
          label={t('Wofür')}
          description={t('Ändert ein paar Wörter: Kinder und Eltern, oder Team und Verwaltung.')}
        >
          <Segmented
            label={t('Wofür')}
            value={draft.mode}
            onChange={(mode) => set({ mode })}
            options={[
              { value: 'family', label: t('Familie') },
              { value: 'office', label: t('Büro oder Verein') },
            ]}
          />
        </Row>
        <Row
          label={t('Sprache neuer Konten')}
          description={t('Für Einladungen, und bis jemand selbst eine wählt.')}
        >
          <Segmented
            label={t('Sprache neuer Konten')}
            value={draft.defaultLanguage}
            onChange={(defaultLanguage) => set({ defaultLanguage })}
            options={[
              { value: 'de', label: 'Deutsch' },
              { value: 'en', label: 'English' },
            ]}
          />
        </Row>
      </Section>

      <Section
        title={t('Mail')}
        lead={t(
          'Für Einladungen, Einrichtungslinks, „Passwort vergessen“ und Hinweise auf neue Geräte. Ohne Mailserver geht alles andere trotzdem – Links gibt es dann als QR-Code.',
        )}
      >
        <div className="field-grid">
          <label className="field">
            <span>{t('Mailserver')}</span>
            <input
              value={smtp.host}
              onChange={(e) => setSmtp({ host: e.target.value })}
              placeholder="mail.example.com"
              spellCheck={false}
            />
          </label>
          <label className="field">
            <span>{t('Port')}</span>
            <input
              type="number"
              value={smtp.port}
              onChange={(e) => setSmtp({ port: number(e.target.value, 587) })}
            />
          </label>
          <div className="field">
            <span>{t('Verschlüsselung')}</span>
            <Segmented
              label={t('Verschlüsselung')}
              value={smtp.security}
              onChange={(security) =>
                setSmtp({
                  security,
                  port: security === 'tls' ? 465 : security === 'starttls' ? 587 : 25,
                })
              }
              options={[
                { value: 'starttls', label: 'STARTTLS' },
                { value: 'tls', label: 'TLS' },
                { value: 'none', label: t('keine') },
              ]}
            />
          </div>
          <label className="field">
            <span>{t('Benutzername')}</span>
            <input
              value={smtp.username ?? ''}
              onChange={(e) => setSmtp({ username: e.target.value || null })}
              autoComplete="off"
              spellCheck={false}
            />
          </label>
          <label className="field">
            <span>{t('Passwort')}</span>
            <PasswordInput
              value={smtpPassword}
              onChange={setSmtpPassword}
              autoComplete="new-password"
            />
            {smtp.passwordSet && !smtpPassword && (
              <small className="field-hint">
                {t('Ein Passwort ist gespeichert. Leer lassen behält es.')}
              </small>
            )}
          </label>
          <label className="field">
            <span>{t('Absender')}</span>
            <input
              value={smtp.from}
              onChange={(e) => setSmtp({ from: e.target.value })}
              placeholder="auth@example.com"
              spellCheck={false}
            />
          </label>
          <label className="field">
            <span>{t('Absendername')}</span>
            <input
              value={smtp.fromName ?? ''}
              onChange={(e) => setSmtp({ fromName: e.target.value || null })}
            />
          </label>
        </div>
        {smtp.security === 'none' && (
          <p className="field-hint">
            {t(
              'Ohne Verschlüsselung nur für einen Mailserver auf diesem Rechner oder im selben geschützten Netz.',
            )}
          </p>
        )}
        <div className="form-actions">
          <button
            type="button"
            disabled={busy || dirty || !me.server.mail || !me.email}
            title={dirty ? t('Erst speichern') : undefined}
            onClick={() =>
              void run(async () => {
                const answer = await api<{ sent: string }>('/uwu/v1/settings/test-mail', {
                  body: {},
                });
                toast(t('Die Testmail an {email} ist raus ✧', { email: answer.sent }));
              })
            }
          >
            {t('Testmail an mich')}
          </button>
          {!me.email && (
            <small className="field-hint">{t('Dafür braucht dein Konto eine Adresse.')}</small>
          )}
        </div>
      </Section>

      <Section title={t('Passwörter')}>
        <Row
          label={t('Mindestlänge')}
          description={t(
            'Länge schlägt Sonderzeichen: Ein langer Satz ist sicherer als „P@ssw0rt!“.',
          )}
        >
          <input
            className="number-input"
            type="number"
            min={8}
            max={128}
            value={draft.passwordMinLength}
            onChange={(e) => set({ passwordMinLength: number(e.target.value, 10) })}
          />
        </Row>
        <Row
          label={t('Gegen Datenlecks prüfen')}
          description={t(
            'Neue Passwörter werden mit Have I Been Pwned abgeglichen. Dabei verlassen nur die ersten fünf Zeichen eines Hashes den Server – nie das Passwort selbst, und niemand erfährt, welches geprüft wurde.',
          )}
        >
          <Toggle
            label={t('Gegen Datenlecks prüfen')}
            checked={draft.hibp}
            onChange={(hibp) => set({ hibp })}
          />
        </Row>
      </Section>

      <Section title={t('Anmeldung')}>
        <Row
          label={t('Angemeldet bleiben, normal')}
          description={t('Stunden ohne Benutzung, bis man sich neu anmeldet.')}
        >
          <input
            className="number-input"
            type="number"
            min={1}
            max={720}
            value={draft.sessionHours}
            onChange={(e) => set({ sessionHours: number(e.target.value, 12) })}
          />
        </Row>
        <Row
          label={t('Mit „Angemeldet bleiben“')}
          description={t('Tage, die ein gemerktes Gerät angemeldet bleibt.')}
        >
          <input
            className="number-input"
            type="number"
            min={1}
            max={365}
            value={draft.rememberDays}
            onChange={(e) => set({ rememberDays: number(e.target.value, 30) })}
          />
        </Row>
        <Row
          label={t('Sperre nach falschen Passwörtern')}
          description={t('So viele falsche Versuche, dann wartet das Konto eine Viertelstunde.')}
        >
          <input
            className="number-input"
            type="number"
            min={3}
            max={100}
            value={draft.lockoutAttempts}
            onChange={(e) => set({ lockoutAttempts: number(e.target.value, 10) })}
          />
        </Row>
        <Row
          label={t('Einladungen gelten')}
          description={t('Tage, die ein Einladungslink funktioniert.')}
        >
          <input
            className="number-input"
            type="number"
            min={1}
            max={90}
            value={draft.invitationDays}
            onChange={(e) => set({ invitationDays: number(e.target.value, 7) })}
          />
        </Row>
        <Row
          label={t('Mail bei neuem Gerät')}
          description={t('Wenn sich jemand auf einem Gerät anmeldet, das er noch nie benutzt hat.')}
        >
          <Toggle
            label={t('Mail bei neuem Gerät')}
            checked={draft.newDeviceMail}
            onChange={(newDeviceMail) => set({ newDeviceMail })}
          />
        </Row>
      </Section>

      <div className="form-actions sticky-actions">
        <span className="spacer" />
        <button
          type="button"
          data-secondary
          disabled={busy || !dirty}
          onClick={() => {
            setDraft(saved);
            setSmtpPassword('');
          }}
        >
          {t('Verwerfen')}
        </button>
        <button
          type="button"
          className="primary"
          disabled={busy || !dirty}
          onClick={() => void save()}
        >
          {t('Speichern')}
        </button>
      </div>
    </div>
  );
}
