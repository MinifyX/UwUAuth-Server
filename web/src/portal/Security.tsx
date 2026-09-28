import { useState, type FormEvent } from 'react';
import { Ago, Day, SecretOnce } from '../components/bits';
import { FormError, Row, Section, useAction } from '../components/controls';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { PasswordInput } from '../components/PasswordInput';
import { PageTitle } from '../components/Shell';
import { api, seg } from '../lib/api';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { reloadMe } from '../lib/me';
import { toast } from '../lib/toast';
import type { Me, Passkey } from '../lib/types';
import { available } from '../lib/webauthn';
import { AddPasskeyDialog, RecoveryCodes, TotpDialog } from './secondFactors';

type Dialog =
  | { kind: 'passkey' }
  | { kind: 'rename'; passkey: Passkey }
  | { kind: 'remove-passkey'; passkey: Passkey }
  | { kind: 'password' }
  | { kind: 'remove-password' }
  | { kind: 'totp' }
  | { kind: 'remove-totp' }
  | { kind: 'recovery'; codes: string[] | null }
  | { kind: 'app-password' }
  | null;

/** Every way to sign in: passkeys first, then password, the app, recovery codes, app passwords. */
export function Security({ me }: { me: Me }) {
  useLanguage();
  const [dialog, setDialog] = useState<Dialog>(null);
  const [run, busy] = useAction();
  const close = () => setDialog(null);
  const done = async (message: string) => {
    setDialog(null);
    await reloadMe();
    toast(message);
  };
  const secondFactor = me.passkeys.length > 0 || me.hasTotp;

  return (
    <>
      <PageTitle>{t('Sicherheit')}</PageTitle>
      {me.needsMfa && (
        <p className="notice">
          <Icon name="shield" />
          {t(
            'Eine deiner Gruppen verlangt einen zweiten Faktor: einen Passkey oder die Authenticator-App. Behalte mindestens einen.',
          )}
        </p>
      )}

      <Section
        title={t('Passkeys')}
        lead={t(
          'Ein Passkey ist ein Schlüssel, den dein Gerät für dich aufbewahrt. Du meldest dich damit per Fingerabdruck, Gesicht oder PIN an – ohne Passwort, und niemand kann ihn dir auf einer falschen Seite abluchsen.',
        )}
        actions={
          <button
            type="button"
            className="primary"
            onClick={() => setDialog({ kind: 'passkey' })}
            disabled={!available()}
          >
            <Icon name="plus" />
            {t('Passkey hinzufügen')}
          </button>
        }
      >
        {me.passkeys.length === 0 ? (
          <p className="empty-note">
            {available()
              ? t('Noch keine. Mit einem Passkey geht die Anmeldung am schnellsten.')
              : t('Dieser Browser kann keine Passkeys.')}
          </p>
        ) : (
          <ul className="item-list">
            {me.passkeys.map((passkey) => (
              <li key={passkey.id} className="item">
                <span className="item-icon">
                  <Icon name="key" />
                </span>
                <span className="item-text">
                  <b>{passkey.name}</b>
                  <small>
                    {t('Angelegt')} <Day iso={passkey.created} /> ·{' '}
                    <Ago iso={passkey.lastUsed} prefix={t('zuletzt benutzt')} />
                  </small>
                </span>
                <button
                  type="button"
                  className="quiet"
                  onClick={() => setDialog({ kind: 'rename', passkey })}
                >
                  {t('Umbenennen')}
                </button>
                <button
                  type="button"
                  className="quiet danger-text"
                  onClick={() => setDialog({ kind: 'remove-passkey', passkey })}
                >
                  {t('Entfernen')}
                </button>
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title={t('Passwort')}>
        <Row
          label={me.hasPassword ? t('Passwort ist gesetzt') : t('Kein Passwort')}
          description={
            me.hasPassword
              ? t('Ändere es, wenn du glaubst, dass es jemand kennt.')
              : t(
                  'Du meldest dich nur mit Passkeys an. Ein Passwort kannst du jederzeit festlegen.',
                )
          }
        >
          <div className="row-buttons">
            <button type="button" onClick={() => setDialog({ kind: 'password' })}>
              {me.hasPassword ? t('Ändern') : t('Festlegen')}
            </button>
            {me.hasPassword && me.passkeys.length > 0 && (
              <button
                type="button"
                className="quiet"
                onClick={() => setDialog({ kind: 'remove-password' })}
              >
                {t('Nur noch Passkeys')}
              </button>
            )}
          </div>
        </Row>
      </Section>

      <Section title={t('Authenticator-App')}>
        <Row
          label={me.hasTotp ? t('Eingerichtet') : t('Nicht eingerichtet')}
          description={t(
            'Eine App wie Aegis, 2FAS oder Google Authenticator zeigt bei jeder Anmeldung mit Passwort einen Code. Dann reicht ein gestohlenes Passwort allein nicht.',
          )}
        >
          {me.hasTotp ? (
            <button
              type="button"
              className="danger"
              onClick={() => setDialog({ kind: 'remove-totp' })}
            >
              {t('Entfernen')}
            </button>
          ) : (
            <button type="button" onClick={() => setDialog({ kind: 'totp' })}>
              {t('Einrichten')}
            </button>
          )}
        </Row>
      </Section>

      <Section title={t('Wiederherstellungscodes')}>
        <Row
          label={
            secondFactor
              ? t('Noch {n} von 10 übrig', { n: me.recoveryCodesLeft })
              : t('Erst mit einem zweiten Faktor')
          }
          description={t(
            'Für den Tag, an dem dein Handy weg ist: Jeder Code ersetzt einmal den zweiten Schritt. Neue Codes machen die alten ungültig.',
          )}
        >
          <button
            type="button"
            disabled={!secondFactor}
            onClick={() => setDialog({ kind: 'recovery', codes: null })}
          >
            {t('Neue Codes')}
          </button>
        </Row>
      </Section>

      <Section
        title={t('App-Passwörter')}
        lead={t(
          'Für Geräte und Programme, die nur Name und Passwort kennen – ein NAS, die Anmeldung an einem Linux-Rechner, ein Mailprogramm. Jedes bekommt sein eigenes, und du kannst es einzeln wieder wegnehmen.',
        )}
        actions={
          <button type="button" onClick={() => setDialog({ kind: 'app-password' })}>
            <Icon name="plus" />
            {t('App-Passwort erstellen')}
          </button>
        }
      >
        {me.appPasswords.length === 0 ? (
          <p className="empty-note">{t('Noch keine.')}</p>
        ) : (
          <ul className="item-list">
            {me.appPasswords.map((app) => (
              <li key={app.id} className="item">
                <span className="item-icon">
                  <Icon name="drive" />
                </span>
                <span className="item-text">
                  <b>{app.name}</b>
                  <small>
                    {t('Erstellt')} <Day iso={app.created} /> ·{' '}
                    <Ago iso={app.lastUsed} prefix={t('zuletzt benutzt')} />
                    {app.lastIp ? ` · ${app.lastIp}` : ''}
                  </small>
                </span>
                <button
                  type="button"
                  className="quiet danger-text"
                  disabled={busy}
                  onClick={() =>
                    void run(async () => {
                      await api(`/uwu/v1/me/app-passwords/${seg(app.id)}`, { method: 'DELETE' });
                      await reloadMe();
                      toast(t('Gelöscht.'));
                    })
                  }
                >
                  {t('Löschen')}
                </button>
              </li>
            ))}
          </ul>
        )}
      </Section>

      {dialog?.kind === 'passkey' && (
        <AddPasskeyDialog onCancel={close} onDone={() => void done(t('Passkey angelegt ✧'))} />
      )}
      {dialog?.kind === 'rename' && (
        <RenameDialog
          passkey={dialog.passkey}
          onClose={close}
          onDone={() => void done(t('Gespeichert ✧'))}
        />
      )}
      {dialog?.kind === 'remove-passkey' && (
        <Confirm
          title={t('Passkey entfernen?')}
          lead={t('„{name}“ kann dich danach nicht mehr anmelden.', { name: dialog.passkey.name })}
          confirm={t('Entfernen')}
          onCancel={close}
          action={async () => {
            await api(`/uwu/v1/me/passkeys/${seg(dialog.passkey.id)}`, { method: 'DELETE' });
            await done(t('Entfernt.'));
          }}
        />
      )}
      {dialog?.kind === 'password' && (
        <PasswordDialog
          me={me}
          onCancel={close}
          onDone={() => void done(t('Passwort gespeichert ✧'))}
        />
      )}
      {dialog?.kind === 'remove-password' && (
        <Confirm
          title={t('Nur noch mit Passkeys anmelden?')}
          lead={t(
            'Dein Passwort wird gelöscht. Du meldest dich dann nur noch mit deinen Passkeys an – leg am besten auf zwei Geräten einen an.',
          )}
          confirm={t('Passwort löschen')}
          onCancel={close}
          action={async () => {
            await api('/uwu/v1/me/password', { method: 'DELETE' });
            await done(t('Passwort gelöscht.'));
          }}
        />
      )}
      {dialog?.kind === 'totp' && (
        <TotpDialog
          organization={me.server.organization}
          onCancel={close}
          onDone={() => void done(t('Die Authenticator-App ist eingerichtet ✧'))}
        />
      )}
      {dialog?.kind === 'remove-totp' && (
        <Confirm
          title={t('Authenticator-App entfernen?')}
          lead={t(
            'Danach fragt die Anmeldung mit Passwort nicht mehr nach einem Code aus der App.',
          )}
          confirm={t('Entfernen')}
          onCancel={close}
          action={async () => {
            await api('/uwu/v1/me/totp', { method: 'DELETE' });
            await done(t('Entfernt.'));
          }}
        />
      )}
      {dialog?.kind === 'recovery' &&
        (dialog.codes ? (
          <Modal
            title={t('Deine neuen Wiederherstellungscodes')}
            onCancel={close}
            footer={
              <>
                <span className="spacer" />
                <button type="button" className="primary" onClick={() => void done(t('Fertig ✧'))}>
                  {t('Aufgeschrieben – fertig')}
                </button>
              </>
            }
          >
            <RecoveryCodes codes={dialog.codes} organization={me.server.organization} />
          </Modal>
        ) : (
          <Confirm
            title={t('Neue Wiederherstellungscodes?')}
            lead={t('Die alten Codes funktionieren danach nicht mehr.')}
            confirm={t('Neue Codes machen')}
            tone="default"
            onCancel={close}
            action={async () => {
              const answer = await api<{ recoveryCodes: string[] }>('/uwu/v1/me/recovery', {
                body: {},
              });
              setDialog({ kind: 'recovery', codes: answer.recoveryCodes });
            }}
          />
        ))}
      {dialog?.kind === 'app-password' && (
        <AppPasswordDialog onClose={() => void done(t('Fertig ✧'))} onCancel={close} />
      )}
    </>
  );
}

/** Are you sure? — runs `action`, shows what went wrong and stays open for another try. */
export function Confirm({
  title,
  lead,
  confirm,
  onCancel,
  action,
  tone = 'warning',
}: {
  title: string;
  lead: string;
  confirm: string;
  onCancel: () => void;
  action: () => Promise<void>;
  tone?: 'default' | 'warning';
}) {
  useLanguage();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <Modal
      title={title}
      tone={tone}
      onCancel={() => !busy && onCancel()}
      footer={
        <>
          <span className="spacer" />
          <button type="button" data-autofocus onClick={onCancel} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button
            type="button"
            className={tone === 'warning' ? 'danger' : 'primary'}
            data-secondary
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              setError(null);
              try {
                await action();
              } catch (e) {
                setError(errorText(e));
                setBusy(false);
              }
            }}
          >
            {confirm}
          </button>
        </>
      }
    >
      <p className="dialog-lead">{lead}</p>
      <FormError error={error} />
    </Modal>
  );
}

function RenameDialog({
  passkey,
  onClose,
  onDone,
}: {
  passkey: Passkey;
  onClose: () => void;
  onDone: () => void;
}) {
  useLanguage();
  const [name, setName] = useState(passkey.name);
  const [run, busy] = useAction();
  const save = (event?: FormEvent) => {
    event?.preventDefault();
    void run(async () => {
      await api(`/uwu/v1/me/passkeys/${seg(passkey.id)}`, { method: 'PATCH', body: { name } });
      onDone();
    });
  };
  return (
    <Modal
      title={t('Passkey umbenennen')}
      onCancel={onClose}
      footer={
        <>
          <span className="spacer" />
          <button type="button" data-secondary onClick={onClose}>
            {t('Abbrechen')}
          </button>
          <button
            type="button"
            className="primary"
            disabled={busy || !name.trim()}
            onClick={() => save()}
          >
            {t('Speichern')}
          </button>
        </>
      }
    >
      <form onSubmit={save}>
        <label className="field">
          <span>{t('Name')}</span>
          <input value={name} maxLength={60} onChange={(e) => setName(e.target.value)} autoFocus />
        </label>
      </form>
    </Modal>
  );
}

function PasswordDialog({
  me,
  onCancel,
  onDone,
}: {
  me: Me;
  onCancel: () => void;
  onDone: () => void;
}) {
  useLanguage();
  const [password, setPassword] = useState('');
  const [again, setAgain] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const min = me.server.passwordMinLength;
  const ok = password.length >= min && password === again;
  const save = async (event?: FormEvent) => {
    event?.preventDefault();
    if (!ok) return;
    setBusy(true);
    setError(null);
    try {
      await api('/uwu/v1/me/password', { body: { password } });
      onDone();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };
  return (
    <Modal
      title={me.hasPassword ? t('Passwort ändern') : t('Passwort festlegen')}
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
            disabled={busy || !ok}
            onClick={() => void save()}
          >
            {t('Speichern')}
          </button>
        </>
      }
    >
      <form className="form" onSubmit={save}>
        <label className="field">
          <span>{t('Neues Passwort')}</span>
          <PasswordInput
            value={password}
            onChange={setPassword}
            autoComplete="new-password"
            autoFocus
          />
          <small className="field-hint">
            {t('Mindestens {n} Zeichen. Ein Satz, den du dir merken kannst, ist ideal.', {
              n: min,
            })}
          </small>
        </label>
        <label className="field">
          <span>{t('Noch einmal')}</span>
          <PasswordInput value={again} onChange={setAgain} autoComplete="new-password" />
          {again && again !== password && (
            <small className="field-error">{t('Die beiden sind nicht gleich.')}</small>
          )}
        </label>
        <p className="field-hint">
          {t('Alle anderen Geräte werden dabei abgemeldet; dieses bleibt angemeldet.')}
        </p>
        <FormError error={error} />
        <button type="submit" hidden />
      </form>
    </Modal>
  );
}

function AppPasswordDialog({ onCancel, onClose }: { onCancel: () => void; onClose: () => void }) {
  useLanguage();
  const [name, setName] = useState('');
  const [secret, setSecret] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const make = async (event?: FormEvent) => {
    event?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const answer = await api<{ secret: string }>('/uwu/v1/me/app-passwords', {
        body: { name: name.trim() },
      });
      setSecret(answer.secret);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t('App-Passwort erstellen')}
      onCancel={() => (secret ? onClose() : !busy && onCancel())}
      footer={
        <>
          <span className="spacer" />
          {secret ? (
            <button type="button" className="primary" onClick={onClose}>
              {t('Fertig')}
            </button>
          ) : (
            <>
              <button type="button" data-secondary onClick={onCancel} disabled={busy}>
                {t('Abbrechen')}
              </button>
              <button
                type="button"
                className="primary"
                disabled={busy || !name.trim()}
                onClick={() => void make()}
              >
                {t('Erstellen')}
              </button>
            </>
          )}
        </>
      }
    >
      {secret ? (
        <>
          <p className="dialog-lead">
            {t(
              'Gib es bei „{name}“ statt deines Passworts ein. Du siehst es nur jetzt – kopier es am besten gleich hinüber.',
              { name: name.trim() },
            )}
          </p>
          <SecretOnce value={secret} />
        </>
      ) : (
        <form className="form" onSubmit={make}>
          <label className="field">
            <span>{t('Wofür ist es?')}</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('z. B. NAS im Keller')}
              maxLength={60}
              autoFocus
            />
          </label>
          <FormError error={error} />
        </form>
      )}
    </Modal>
  );
}
