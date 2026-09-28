import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Ago, Day, Empty, Loading, SecretOnce } from '../components/bits';
import { FormError } from '../components/controls';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { PageTitle } from '../components/Shell';
import { api, seg } from '../lib/api';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import type { LdapAccount, LdapInfo } from '../lib/types';
import { Confirm } from '../portal/Security';
import { Fact } from './Overview';

const DOCS = 'https://github.com/MinifyX/UwUAuth-Server/blob/main/docs/ldap.md';

/**
 * LDAP: whether it is on, what apps set to reach it, and the accounts apps bind with to read the
 * directory. People bind with their own password or an app password; those need nothing here.
 */
export function Ldap() {
  useLanguage();
  const [info, setInfo] = useState<LdapInfo | null>(null);
  useEffect(() => {
    api<LdapInfo>('/uwu/v1/ldap').then(setInfo, (e) => toast(errorText(e), 'error'));
  }, []);

  return (
    <>
      <PageTitle>{t('LDAP')}</PageTitle>
      <p className="muted page-lead">
        {t(
          'Für alles, was keine Anmeldung per OpenID Connect kann: ein NAS, Linux-Anmeldungen mit SSSD, Nextclouds LDAP-Anbindung. Dieselben Personen und Gruppen, im Stil von OpenLDAP und Active Directory zugleich.',
        )}
      </p>
      {!info && <Loading />}
      {info && !info.enabled && <Off />}
      {info?.enabled && (
        <>
          <Settings info={info} />
          <Accounts info={info} />
        </>
      )}
    </>
  );
}

function Off() {
  useLanguage();
  return (
    <Empty scene="sleepy" title={t('LDAP ist aus')}>
      <p>{t('Es ist nur fürs eigene Netz gedacht und wird bei der Installation eingeschaltet:')}</p>
      <pre className="code-block">sudo bash install.sh --ldap --ldap-bind 192.0.2.10</pre>
      <p>
        <a href={DOCS} target="_blank" rel="noreferrer">
          {t('Wie das geht, steht in der Anleitung.')}
        </a>
      </p>
    </Empty>
  );
}

function Settings({ info }: { info: LdapInfo }) {
  useLanguage();
  const servers = [
    info.ldapsPort ? `ldaps://${info.host}` : null,
    info.ldapPort ? `ldap://${info.host}${info.ldapsPort ? ' (StartTLS)' : ''}` : null,
  ].filter(Boolean);
  return (
    <section className="section">
      <div className="section-head">
        <h2 className="section-title">{t('So finden Apps das Verzeichnis')}</h2>
      </div>
      <div className="facts">
        <Fact label={t('Server')} value={servers.join(' · ')} />
        <Fact label={t('Base DN')} value={info.base ?? ''} />
        <Fact label={t('Personen')} value={info.people ?? ''} />
        <Fact label={t('Gruppen')} value={info.groups ?? ''} />
        <Fact
          label={t('Im Docker-Netz')}
          value={[
            info.ldapPort ? `ldap://uwuauth:${info.ldapPort}` : null,
            info.ldapsPort ? `ldaps://uwuauth:${info.ldapsPort}` : null,
          ]
            .filter(Boolean)
            .join(' · ')}
        />
        <Fact
          label={t('Passwörter ohne TLS')}
          value={
            info.plainBind
              ? t('erlaubt – nur für ein Netz, in dem sonst niemand ist')
              : t('nicht erlaubt')
          }
          alarm={info.plainBind}
        />
      </div>
      <p className="section-lead">
        {t(
          'Personen melden sich mit ihrem Passwort oder einem App-Passwort an und sehen dann nur sich selbst und ihre Gruppen. Apps, die alle sehen müssen, bekommen unten ein eigenes Konto.',
        )}{' '}
        <a href={DOCS} target="_blank" rel="noreferrer">
          {t('Einstellungen für Nextcloud, SSSD, Synology und andere')}
        </a>
      </p>
    </section>
  );
}

function Accounts({ info }: { info: LdapInfo }) {
  useLanguage();
  const [list, setList] = useState<LdapAccount[] | null>(null);
  const [creating, setCreating] = useState(false);
  const [removing, setRemoving] = useState<LdapAccount | null>(null);
  const [renewing, setRenewing] = useState<LdapAccount | null>(null);
  const [shown, setShown] = useState<LdapAccount | null>(null);
  const load = useCallback(() => {
    api<LdapAccount[]>('/uwu/v1/ldap/accounts').then(setList, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(load, [load]);

  return (
    <section className="section">
      <div className="section-head">
        <h2 className="section-title">{t('Konten für Apps')}</h2>
        <button type="button" className="primary" onClick={() => setCreating(true)}>
          <Icon name="plus" />
          {t('Neues Konto')}
        </button>
      </div>
      <p className="section-lead">
        {t('Ein Konto pro App: Es darf das ganze Verzeichnis lesen und nichts ändern.')}
      </p>
      {!list && <Loading />}
      {list?.length === 0 && <Empty scene="sleepy">{t('Noch keine Konten.')}</Empty>}
      {list && list.length > 0 && (
        <ul className="item-list card">
          {list.map((account) => (
            <li key={account.id} className="item">
              <span className="item-icon">
                <Icon name="network" />
              </span>
              <span className="item-text">
                <b>{account.name}</b>
                <small>
                  <code>{account.bindDn}</code>
                </small>
                <small>
                  {account.description && <>{account.description} · </>}
                  {t('Erstellt')} <Day iso={account.created} /> ·{' '}
                  <Ago iso={account.lastUsed} prefix={t('zuletzt benutzt')} />
                </small>
              </span>
              <button type="button" className="quiet" onClick={() => setRenewing(account)}>
                {t('Neues Passwort')}
              </button>
              <button
                type="button"
                className="quiet danger-text"
                onClick={() => setRemoving(account)}
              >
                {t('Löschen')}
              </button>
            </li>
          ))}
        </ul>
      )}
      {creating && (
        <CreateAccount
          onDone={(account) => {
            setCreating(false);
            if (account) setShown(account);
            load();
          }}
        />
      )}
      {shown && <Shown account={shown} info={info} onClose={() => setShown(null)} />}
      {renewing && (
        <Confirm
          title={t('Neues Passwort für „{name}“?', { name: renewing.name })}
          lead={t('Das alte hört sofort auf zu gehen: Trag das neue gleich in der App ein.')}
          confirm={t('Neues Passwort')}
          onCancel={() => setRenewing(null)}
          action={async () => {
            const account = await api<LdapAccount>(
              `/uwu/v1/ldap/accounts/${seg(renewing.id)}/secret`,
              { method: 'POST' },
            );
            setRenewing(null);
            setShown(account);
          }}
        />
      )}
      {removing && (
        <Confirm
          title={t('Konto „{name}“ löschen?', { name: removing.name })}
          lead={t('Die App, die es benutzt, findet danach niemanden mehr.')}
          confirm={t('Löschen')}
          onCancel={() => setRemoving(null)}
          action={async () => {
            await api(`/uwu/v1/ldap/accounts/${seg(removing.id)}`, { method: 'DELETE' });
            setRemoving(null);
            load();
          }}
        />
      )}
    </section>
  );
}

function CreateAccount({ onDone }: { onDone: (account: LdapAccount | null) => void }) {
  useLanguage();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const make = async (event?: FormEvent) => {
    event?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onDone(
        await api<LdapAccount>('/uwu/v1/ldap/accounts', {
          body: { name: name.trim(), description: description.trim() || undefined },
        }),
      );
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t('Konto für eine App')}
      onCancel={() => !busy && onDone(null)}
      footer={
        <>
          <span className="spacer" />
          <button type="button" data-secondary onClick={() => onDone(null)} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button
            type="button"
            className="primary"
            disabled={busy || !name.trim()}
            onClick={() => void make()}
          >
            {t('Anlegen')}
          </button>
        </>
      }
    >
      <form className="form" onSubmit={make}>
        <label className="field">
          <span>{t('Name')}</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value.toLowerCase())}
            placeholder={t('z. B. nextcloud')}
            maxLength={64}
            autoFocus
          />
          <small className="muted">
            {t('Kleinbuchstaben, Ziffern, Punkt, Strich und Unterstrich.')}
          </small>
        </label>
        <label className="field">
          <span>{t('Wofür? (freiwillig)')}</span>
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            maxLength={200}
          />
        </label>
        <FormError error={error} />
      </form>
    </Modal>
  );
}

/** The password, once, with what to put into the app. */
function Shown({
  account,
  info,
  onClose,
}: {
  account: LdapAccount;
  info: LdapInfo;
  onClose: () => void;
}) {
  useLanguage();
  const server = info.ldapsPort ? `ldaps://${info.host}` : `ldap://${info.host}`;
  return (
    <Modal
      title={t('Konto „{name}“', { name: account.name })}
      onCancel={onClose}
      footer={
        <>
          <span className="spacer" />
          <button type="button" className="primary" onClick={onClose}>
            {t('Fertig')}
          </button>
        </>
      }
    >
      <p className="dialog-lead">
        {t('Das Passwort siehst du nur jetzt. Trag es gleich in der App ein.')}
      </p>
      <SecretOnce value={account.secret ?? ''} />
      <div className="facts">
        <Fact label={t('Bind-DN')} value={account.bindDn} />
        <Fact label={t('Base DN')} value={info.base ?? ''} />
      </div>
      <p className="muted">{t('Zum Ausprobieren:')}</p>
      <pre className="code-block">
        {`ldapsearch -H ${server} -D "${account.bindDn}" -W -b "${info.people}" "(uid=*)" uid mail`}
      </pre>
    </Modal>
  );
}
