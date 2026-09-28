import { useRef, useState, type FormEvent } from 'react';
import { Avatar, Badge } from '../components/bits';
import { AttributeInput } from '../components/AttributeInput';
import { Row, Section, Segmented, useAction } from '../components/controls';
import { Icon } from '../components/Icon';
import { PageTitle } from '../components/Shell';
import { api } from '../lib/api';
import { squareJpeg } from '../lib/avatar';
import { setLanguage, t, useLanguage } from '../lib/i18n';
import { patchMe, reloadMe } from '../lib/me';
import { setTheme, useTheme } from '../lib/theme';
import { toast } from '../lib/toast';
import type { Me } from '../lib/types';

/** One's own name, picture, address, language and look. */
export function Profile({ me }: { me: Me }) {
  useLanguage();
  const theme = useTheme();
  const [run, busy] = useAction();
  return (
    <>
      <PageTitle>{t('Profil')}</PageTitle>
      <PictureSection me={me} />
      <NameSection me={me} />
      <EmailSection me={me} />
      <Section title={t('Sprache und Aussehen')}>
        <Row label={t('Sprache')} description={t('Für diese Seiten und für Mails an dich.')}>
          <Segmented
            label={t('Sprache')}
            value={me.language === 'en' ? 'en' : 'de'}
            onChange={(language) =>
              void run(async () => {
                await api('/uwu/v1/me', { method: 'PATCH', body: { language } });
                patchMe({ language });
                setLanguage(language);
              })
            }
            options={[
              { value: 'de', label: 'Deutsch' },
              { value: 'en', label: 'English' },
            ]}
          />
        </Row>
        <Row label={t('Aussehen')} description={t('Gilt nur in diesem Browser.')}>
          <Segmented
            label={t('Aussehen')}
            value={theme}
            onChange={setTheme}
            options={[
              { value: 'system', label: t('Wie das System') },
              { value: 'light', label: t('Hell') },
              { value: 'dark', label: t('Dunkel') },
            ]}
          />
        </Row>
        {busy && <span className="sr-only">{t('Speichert …')}</span>}
      </Section>
      {me.attributes.length > 0 && <AttributesSection me={me} />}
    </>
  );
}

function PictureSection({ me }: { me: Me }) {
  useLanguage();
  const input = useRef<HTMLInputElement>(null);
  const [run, busy] = useAction();
  const upload = (file: File) =>
    run(async () => {
      const jpeg = await squareJpeg(file);
      await api('/uwu/v1/me/avatar', { method: 'PUT', body: jpeg, contentType: 'image/jpeg' });
      await reloadMe();
      toast(t('Neues Bild ✧'));
    });
  return (
    <Section title={t('Bild')}>
      <div className="picture-row">
        <Avatar name={me.displayName} src={me.avatar} size={72} />
        <div className="picture-actions">
          <p className="muted">{t('Apps, bei denen du dich mit UwUAuth anmeldest, zeigen es.')}</p>
          <div className="form-actions">
            <button type="button" onClick={() => input.current?.click()} disabled={busy}>
              <Icon name="upload" />
              {me.avatar ? t('Anderes Bild') : t('Bild wählen')}
            </button>
            {me.avatar && (
              <button
                type="button"
                className="quiet"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    await api('/uwu/v1/me/avatar', { method: 'DELETE' });
                    await reloadMe();
                  })
                }
              >
                {t('Entfernen')}
              </button>
            )}
          </div>
          <input
            ref={input}
            type="file"
            accept="image/*"
            hidden
            onChange={(e) => {
              const file = e.target.files?.[0];
              e.target.value = '';
              if (file) void upload(file);
            }}
          />
        </div>
      </div>
    </Section>
  );
}

function NameSection({ me }: { me: Me }) {
  useLanguage();
  const [displayName, setDisplayName] = useState(me.displayName);
  const [givenName, setGivenName] = useState(me.givenName ?? '');
  const [familyName, setFamilyName] = useState(me.familyName ?? '');
  const [run, busy] = useAction();
  const dirty =
    displayName !== me.displayName ||
    givenName !== (me.givenName ?? '') ||
    familyName !== (me.familyName ?? '');
  const save = (event: FormEvent) => {
    event.preventDefault();
    void run(async () => {
      await api('/uwu/v1/me', {
        method: 'PATCH',
        body: { displayName, givenName, familyName },
      });
      await reloadMe();
      toast(t('Gespeichert ✧'));
    });
  };
  return (
    <Section title={t('Name')}>
      <form className="form" onSubmit={save}>
        <div className="field-grid">
          <label className="field">
            <span>{t('Anzeigename')}</span>
            <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} required />
          </label>
          <label className="field">
            <span>{t('Vorname')}</span>
            <input value={givenName} onChange={(e) => setGivenName(e.target.value)} />
          </label>
          <label className="field">
            <span>{t('Nachname')}</span>
            <input value={familyName} onChange={(e) => setFamilyName(e.target.value)} />
          </label>
        </div>
        <p className="field-hint">
          {t('Dein Benutzername ist {username}. Ihn kann nur ein Admin ändern.', {
            username: me.username,
          })}
        </p>
        <div className="form-actions">
          <span className="spacer" />
          <button
            type="submit"
            className="primary"
            disabled={!dirty || busy || !displayName.trim()}
          >
            {t('Speichern')}
          </button>
        </div>
      </form>
    </Section>
  );
}

function EmailSection({ me }: { me: Me }) {
  useLanguage();
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState<string | null>(null);
  const [run, busy] = useAction();
  const submit = (event: FormEvent) => {
    event.preventDefault();
    void run(async () => {
      const answer = await api<{ sent: string }>('/uwu/v1/me/email', { body: { email } });
      setSent(answer.sent);
      setEmail('');
    });
  };
  return (
    <Section title={t('E-Mail-Adresse')}>
      <Row
        label={me.email ?? t('Noch keine')}
        description={
          me.email
            ? me.emailVerified
              ? t('Bestätigt. Hierhin gehen Links, wenn du dein Passwort vergisst.')
              : t('Noch nicht bestätigt.')
            : t(
                'Ohne Adresse kann dir niemand einen Link schicken, wenn du dein Passwort vergisst.',
              )
        }
      >
        {me.email && me.emailVerified && <Badge tone="ok">{t('bestätigt')}</Badge>}
      </Row>
      {me.server.mail ? (
        <form className="inline-form wrap" onSubmit={submit}>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder={t('neue Adresse')}
            aria-label={t('Neue E-Mail-Adresse')}
            autoComplete="email"
          />
          <button type="submit" disabled={busy || !email.includes('@')}>
            {me.email ? t('Adresse ändern') : t('Adresse hinzufügen')}
          </button>
        </form>
      ) : (
        <p className="field-hint">
          {t(
            'Dieser Server kann keine Mails verschicken. Deine Adresse kann ein Admin für dich ändern.',
          )}
        </p>
      )}
      {sent && (
        <p className="setting-result" role="status">
          {t(
            'Wir haben einen Link an {email} geschickt. Sobald du ihn öffnest, gilt die neue Adresse.',
            {
              email: sent,
            },
          )}
        </p>
      )}
    </Section>
  );
}

function AttributesSection({ me }: { me: Me }) {
  useLanguage();
  const initial = Object.fromEntries(me.attributes.map((a) => [a.name, a.value ?? '']));
  const [values, setValues] = useState<Record<string, string>>(initial);
  const [run, busy] = useAction();
  const editable = me.attributes.filter((a) => a.selfEditable);
  const changed = Object.fromEntries(
    editable
      .filter((a) => values[a.name] !== initial[a.name])
      .map((a) => [a.name, values[a.name]!]),
  );
  return (
    <Section
      title={t('Weitere Angaben')}
      lead={
        editable.length < me.attributes.length
          ? t('Grau Hinterlegtes pflegt ein Admin.')
          : undefined
      }
    >
      <div className="field-grid">
        {me.attributes.map((def) => (
          <AttributeInput
            key={def.name}
            def={def}
            value={values[def.name] ?? ''}
            disabled={!def.selfEditable}
            onChange={(value) => setValues({ ...values, [def.name]: value })}
          />
        ))}
      </div>
      <div className="form-actions">
        <span className="spacer" />
        <button
          type="button"
          className="primary"
          disabled={busy || Object.keys(changed).length === 0}
          onClick={() =>
            void run(async () => {
              await api('/uwu/v1/me', { method: 'PATCH', body: { attributes: changed } });
              await reloadMe();
              toast(t('Gespeichert ✧'));
            })
          }
        >
          {t('Speichern')}
        </button>
      </div>
    </Section>
  );
}
