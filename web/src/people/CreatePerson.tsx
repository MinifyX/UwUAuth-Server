import { useState, type FormEvent } from 'react';
import { LinkShare } from '../components/bits';
import { FormError, Segmented, Toggle } from '../components/controls';
import { Modal } from '../components/Modal';
import { PasswordInput } from '../components/PasswordInput';
import { Picker } from '../components/Picker';
import { api } from '../lib/api';
import { errorText } from '../lib/errors';
import { language, t, useLanguage } from '../lib/i18n';
import { suggestUsername } from '../lib/names';
import type { Group, LinkResult, Mode } from '../lib/types';
import { groupName, word } from '../lib/words';

type Created = { id: string; username: string; link?: LinkResult };

/**
 * A new account. Usually without a password: a setup link (a QR code for the kid's tablet, or a
 * mail) lets the person choose a passkey or a password on their own device.
 */
export function CreatePerson({
  admin,
  mode,
  mail,
  minLength,
  groups,
  onCancel,
  onDone,
}: {
  /** Admins choose groups, the admin right and whether somebody looks after the account. */
  admin: boolean;
  mode: Mode;
  mail: boolean;
  minLength: number;
  groups: Group[];
  onCancel: () => void;
  onDone: (id: string) => void;
}) {
  useLanguage();
  const [displayName, setDisplayName] = useState('');
  const [username, setUsername] = useState('');
  const [typedUsername, setTypedUsername] = useState(false);
  const [email, setEmail] = useState('');
  const [lang, setLang] = useState<'de' | 'en'>(language());
  const [picked, setPicked] = useState<string[]>([]);
  const [isAdmin, setIsAdmin] = useState(false);
  const [managed, setManaged] = useState(!admin);
  const [how, setHow] = useState<'link' | 'password'>('link');
  const [password, setPassword] = useState('');
  const [sendMail, setSendMail] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<Created | null>(null);

  const canMail = mail && email.includes('@');
  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const answer = await api<Created>('/uwu/v1/people', {
        body: {
          username: username.trim(),
          displayName: displayName.trim(),
          email: email.trim() || undefined,
          language: lang,
          managed,
          groups: admin ? picked : [],
          admin: admin && isAdmin,
          password: how === 'password' ? password : undefined,
          setupLink: how === 'link',
          mail: how === 'link' && canMail && sendMail,
        },
      });
      if (answer.link) setCreated(answer);
      else onDone(answer.id);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  if (created?.link) {
    return (
      <Modal
        title={t('{name} ist angelegt ✧', { name: displayName.trim() || created.username })}
        onCancel={() => onDone(created.id)}
        footer={
          <>
            <span className="spacer" />
            <button type="button" className="primary" onClick={() => onDone(created.id)}>
              {t('Fertig')}
            </button>
          </>
        }
      >
        <LinkShare
          link={created.link.link}
          expires={created.link.expires}
          mailed={created.link.mailed}
          lead={t(
            'Scann den Code mit dem Gerät, auf dem das Konto eingerichtet wird – oder schick den Link hinüber. Dort wählt {name} einen Passkey oder ein Passwort.',
            { name: displayName.trim() || created.username },
          )}
        />
      </Modal>
    );
  }

  const ready =
    username.trim() && displayName.trim() && (how === 'link' || password.length >= minLength);
  return (
    <Modal
      title={admin ? t('Person anlegen') : word(mode, 'addManaged')}
      size="wide"
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
            disabled={busy || !ready}
            onClick={() => void submit()}
          >
            {t('Anlegen')}
          </button>
        </>
      }
    >
      <form className="form" onSubmit={submit}>
        <div className="field-pair">
          <label className="field">
            <span>{t('Name')}</span>
            <input
              value={displayName}
              onChange={(e) => {
                setDisplayName(e.target.value);
                if (!typedUsername) setUsername(suggestUsername(e.target.value));
              }}
              autoFocus
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
              autoCapitalize="none"
              spellCheck={false}
            />
          </label>
          <label className="field">
            <span>{t('E-Mail-Adresse (freiwillig)')}</span>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
          <div className="field">
            <span>{t('Sprache')}</span>
            <Segmented
              label={t('Sprache')}
              value={lang}
              onChange={setLang}
              options={[
                { value: 'de', label: 'Deutsch' },
                { value: 'en', label: 'English' },
              ]}
            />
          </div>
        </div>

        {admin && (
          <>
            <div className="field">
              <span>{t('Gruppen')}</span>
              <Picker
                label={t('Gruppen')}
                choices={groups
                  .filter((group) => group.builtin !== 'everyone')
                  .map((group) => ({
                    id: group.id,
                    label: groupName(group),
                    kind: 'group' as const,
                  }))}
                picked={picked}
                onChange={setPicked}
                empty={t('Noch in keiner Gruppe.')}
              />
            </div>
            <label className="check">
              <Toggle label={t('Admin')} checked={isAdmin} onChange={setIsAdmin} />
              <span>{t('Admin: darf alles im Admin-Portal')}</span>
            </label>
            <label className="check">
              <Toggle
                label={word(mode, 'managedAccount')}
                checked={managed}
                onChange={setManaged}
              />
              <span>{word(mode, 'managedAccount')}</span>
            </label>
            {managed && <p className="field-hint">{word(mode, 'managedHint')}</p>}
          </>
        )}

        <div className="field">
          <span>{t('Wie kommt die Person in ihr Konto?')}</span>
          <Segmented
            label={t('Einrichtung')}
            value={how}
            onChange={setHow}
            wide
            options={[
              { value: 'link', label: t('Einrichtungslink') },
              { value: 'password', label: t('Passwort festlegen') },
            ]}
          />
        </div>
        {how === 'link' ? (
          <>
            <p className="field-hint">
              {t(
                'Du bekommst einen Link und einen QR-Code. Wer ihn öffnet, richtet das Konto mit Passkey oder Passwort ein. Er gilt eine Woche.',
              )}
            </p>
            {canMail && (
              <label className="check">
                <Toggle label={t('Per Mail schicken')} checked={sendMail} onChange={setSendMail} />
                <span>
                  {t('Link außerdem per Mail an {email} schicken', { email: email.trim() })}
                </span>
              </label>
            )}
          </>
        ) : (
          <label className="field">
            <span>{t('Passwort')}</span>
            <PasswordInput value={password} onChange={setPassword} autoComplete="new-password" />
            <small className="field-hint">
              {t('Mindestens {n} Zeichen. Sag es der Person persönlich.', { n: minLength })}
            </small>
          </label>
        )}
        <FormError error={error} />
        <button type="submit" hidden />
      </form>
    </Modal>
  );
}
