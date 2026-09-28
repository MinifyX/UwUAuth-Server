import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { AppIcon } from '../components/AppIcon';
import { Badge, CopyField, Day, Empty, Loading, SecretOnce } from '../components/bits';
import { FormError, Section } from '../components/controls';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { PageTitle } from '../components/Shell';
import { api, seg } from '../lib/api';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { go } from '../lib/route';
import { toast } from '../lib/toast';
import type { App, RegistrationToken } from '../lib/types';
import { Confirm } from '../portal/Security';
import { AppPage } from './AppDetail';
import { NewApp } from './NewApp';

/**
 * Apps: everything that signs people in through UwUAuth (OpenID Connect), and the tokens apps
 * register themselves with. `/apps/new` makes one, `/apps/<id>` is one.
 */
export function Apps({ id }: { id: string | null }) {
  useLanguage();
  if (id === 'new') return <NewApp />;
  if (id) return <AppPage key={id} id={id} />;
  return (
    <>
      <AppList />
      <RegistrationTokens />
    </>
  );
}

/** A few words on what makes an app special, as badges. */
export function AppBadges({ app }: { app: App }) {
  useLanguage();
  return (
    <>
      {app.disabled && <Badge tone="alarm">{t('aus')}</Badge>}
      {app.public && <Badge>{t('öffentlich')}</Badge>}
      {app.requireMfa && <Badge>{t('zweiter Faktor')}</Badge>}
      {app.consent && <Badge>{t('fragt nach')}</Badge>}
      {app.allowedGroups.length > 0 && <Badge>{t('nur für Gruppen')}</Badge>}
    </>
  );
}

function AppList() {
  useLanguage();
  const [list, setList] = useState<App[] | null>(null);
  useEffect(() => {
    api<App[]>('/uwu/v1/apps').then(setList, (e) => toast(errorText(e), 'error'));
  }, []);
  return (
    <>
      <PageTitle
        actions={
          <button type="button" className="primary" onClick={() => go('/apps/new')}>
            <Icon name="plus" />
            {t('Neue App')}
          </button>
        }
      >
        {t('Apps')}
      </PageTitle>
      <p className="muted page-lead">
        {t(
          'Apps, bei denen man sich mit dem UwUAuth-Konto anmeldet – über OpenID Connect. Wer welche App benutzen darf und wann, stellst du hier ein.',
        )}
      </p>
      {!list && <Loading />}
      {list?.length === 0 && (
        <Empty scene="invite" title={t('Noch keine Apps')}>
          {t(
            'Leg die erste an: Für Nextcloud, Immich, Jellyfin und viele andere gibt es eine Vorlage, die das meiste schon weiß.',
          )}
        </Empty>
      )}
      {list && list.length > 0 && (
        <ul className="people-list app-list">
          {list.map((app) => (
            <li key={app.id}>
              <button
                type="button"
                className="person-row"
                data-disabled={app.disabled || undefined}
                onClick={() => go(`/apps/${app.id}`)}
              >
                <AppIcon name={app.name} size={40} />
                <span className="person-text">
                  <b>
                    {app.name}
                    <AppBadges app={app} />
                  </b>
                  <small className="mono">{app.clientId}</small>
                </span>
                <small className="person-seen">
                  <Day iso={app.created} />
                </small>
                <Icon name="chevron" />
              </button>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

/** Tokens apps register themselves with (RFC 7591): shown once, a few uses, a little while. */
function RegistrationTokens() {
  useLanguage();
  const [list, setList] = useState<RegistrationToken[] | null>(null);
  const [creating, setCreating] = useState(false);
  const [removing, setRemoving] = useState<RegistrationToken | null>(null);
  const load = useCallback(() => {
    api<RegistrationToken[]>('/uwu/v1/registration-tokens').then(setList, (e) =>
      toast(errorText(e), 'error'),
    );
  }, []);
  useEffect(load, [load]);
  return (
    <Section
      title={t('Registrierungs-Tokens')}
      lead={t(
        'Mit so einem Token trägt sich eine App selbst ein – etwa ein Programm aus der UwUSuite. Jedes gilt nur ein paar Mal und eine Weile.',
      )}
      actions={
        <button type="button" onClick={() => setCreating(true)}>
          <Icon name="plus" />
          {t('Token erstellen')}
        </button>
      }
    >
      {!list && <Loading />}
      {list?.length === 0 && <p className="empty-note">{t('Keine offenen Tokens.')}</p>}
      {list && list.length > 0 && (
        <ul className="item-list">
          {list.map((token) => (
            <li key={token.id} className="item">
              <span className="item-icon">
                <Icon name="key" />
              </span>
              <span className="item-text">
                <b>{token.name}</b>
                <small>
                  {token.usesLeft === 1
                    ? t('noch einmal gültig')
                    : t('noch {n}-mal gültig', { n: token.usesLeft })}{' '}
                  · {t('läuft ab')} <Day iso={token.expires} />
                </small>
              </span>
              <button
                type="button"
                className="quiet danger-text"
                onClick={() => setRemoving(token)}
              >
                {t('Löschen')}
              </button>
            </li>
          ))}
        </ul>
      )}
      {creating && (
        <CreateRegistrationToken
          onClose={() => {
            setCreating(false);
            load();
          }}
        />
      )}
      {removing && (
        <Confirm
          title={t('Token „{name}“ löschen?', { name: removing.name })}
          lead={t('Apps können sich damit dann nicht mehr eintragen. Schon eingetragene bleiben.')}
          confirm={t('Löschen')}
          onCancel={() => setRemoving(null)}
          action={async () => {
            await api(`/uwu/v1/registration-tokens/${seg(removing.id)}`, { method: 'DELETE' });
            setRemoving(null);
            load();
          }}
        />
      )}
    </Section>
  );
}

const DURATIONS = [
  { hours: 1, label: () => t('1 Stunde') },
  { hours: 24, label: () => t('1 Tag') },
  { hours: 24 * 7, label: () => t('1 Woche') },
  { hours: 24 * 30, label: () => t('30 Tage') },
];

function CreateRegistrationToken({ onClose }: { onClose: () => void }) {
  useLanguage();
  const [name, setName] = useState('');
  const [uses, setUses] = useState('1');
  const [hours, setHours] = useState(24);
  const [secret, setSecret] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const make = async (event?: FormEvent) => {
    event?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const made = await api<RegistrationToken>('/uwu/v1/registration-tokens', {
        body: { name: name.trim(), uses: Math.max(1, Number(uses) || 1), hours },
      });
      setSecret(made.secret ?? '');
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t('Registrierungs-Token erstellen')}
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <span className="spacer" />
          {secret ? (
            <button type="button" className="primary" onClick={onClose}>
              {t('Fertig')}
            </button>
          ) : (
            <>
              <button type="button" data-secondary onClick={onClose} disabled={busy}>
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
              'Du siehst das Token nur jetzt. Gib es der App zusammen mit der Adresse zum Eintragen.',
            )}
          </p>
          <SecretOnce value={secret} />
          <div className="field">
            <span>{t('Adresse zum Eintragen')}</span>
            <CopyField
              value={`${location.origin}/oauth/register`}
              label={t('Adresse zum Eintragen')}
            />
          </div>
        </>
      ) : (
        <form className="form" onSubmit={make}>
          <label className="field">
            <span>{t('Für welche App?')}</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('z. B. UwUMail')}
              maxLength={80}
              autoFocus
            />
          </label>
          <div className="field-pair">
            <label className="field">
              <span>{t('Wie oft gültig')}</span>
              <input
                type="number"
                min={1}
                max={100}
                value={uses}
                onChange={(e) => setUses(e.target.value)}
                className="number-input"
              />
            </label>
            <label className="field">
              <span>{t('Gilt für')}</span>
              <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
                {DURATIONS.map((duration) => (
                  <option key={duration.hours} value={duration.hours}>
                    {duration.label()}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <FormError error={error} />
        </form>
      )}
    </Modal>
  );
}
