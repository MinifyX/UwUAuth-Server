import { useEffect, useState, type FormEvent } from 'react';
import { AppIcon } from '../components/AppIcon';
import { CopyField } from '../components/bits';
import { FormError, Row, Section, Toggle } from '../components/controls';
import { NyuScene } from '../components/nyu/scenes';
import { Picker, type Choice } from '../components/Picker';
import { PageTitle } from '../components/Shell';
import { UriList } from '../components/UriList';
import { api } from '../lib/api';
import { FORWARD_AUTH, forwardAuthUrls } from '../lib/apps';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { go } from '../lib/route';
import type { App, AppTemplate, Group } from '../lib/types';
import { groupName } from '../lib/words';

/** The card in the template grid: not an OpenID Connect app, a proxy in front of one. */
export const FORWARD_TEMPLATE: AppTemplate = {
  key: FORWARD_AUTH,
  name: 'Forward-Auth',
  redirectUris: [],
  postLogoutRedirectUris: [],
  scopes: '',
  public: true,
  launchUrl: '',
  notes: '',
};

/** The groups an app can be limited to, as the picker offers them. */
export function groupChoices(groups: Group[]): Choice[] {
  return groups
    .filter((group) => group.builtin !== 'everyone')
    .map((group) => ({ id: group.id, label: groupName(group), kind: 'group' }));
}

/** A new forward-auth app: a name, the addresses the proxy guards, and who may in. */
export function ForwardForm({ onMade }: { onMade: (app: App) => void }) {
  useLanguage();
  const [name, setName] = useState('');
  const [addresses, setAddresses] = useState<string[]>([]);
  const [allowedGroups, setAllowedGroups] = useState<string[]>([]);
  const [requireMfa, setRequireMfa] = useState(false);
  const [groups, setGroups] = useState<Group[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api<Group[]>('/uwu/v1/groups').then(setGroups, () => undefined);
  }, []);
  const ready = name.trim() !== '' && addresses.length > 0;

  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      const made = await api<App>('/uwu/v1/apps', {
        body: {
          name: name.trim(),
          template: FORWARD_AUTH,
          forwardAuth: addresses,
          allowedGroups,
          requireMfa,
        },
      });
      onMade(made);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  return (
    <>
      <PageTitle>
        <span className="title-with-icon">
          <AppIcon name="Forward-Auth" size={36} />
          Forward-Auth
        </span>
      </PageTitle>
      <p className="muted page-lead">
        {t(
          'Für Apps ohne eigene Anmeldung: Caddy, Traefik, nginx oder Nginx Proxy Manager fragt bei jeder Anfrage UwUAuth, ob die Person hinein darf.',
        )}
      </p>
      <form className="card form app-form" onSubmit={submit}>
        <label className="field">
          <span>{t('Name')}</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t('So sehen ihn alle in „Meine Apps“')}
            maxLength={80}
            autoFocus
          />
        </label>
        <ForwardAddresses values={addresses} onChange={setAddresses} />
        <div className="field">
          <span>{t('Nur für diese Gruppen')}</span>
          <Picker
            label={t('Nur für diese Gruppen')}
            choices={groupChoices(groups)}
            picked={allowedGroups}
            onChange={setAllowedGroups}
            empty={t('Alle dürfen.')}
          />
        </div>
        <Row
          label={t('Zweiter Faktor Pflicht')}
          description={t(
            'Wer sich nur mit Passwort angemeldet hat, bestätigt vor dieser App noch mit Passkey oder Authenticator-App.',
          )}
        >
          <Toggle
            label={t('Zweiter Faktor Pflicht')}
            checked={requireMfa}
            onChange={setRequireMfa}
          />
        </Row>
        <FormError error={error} />
        <div className="form-actions">
          <span className="spacer" />
          <button type="button" data-secondary onClick={() => go('/apps')} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button type="submit" className="primary" disabled={busy || !ready}>
            {busy ? t('Einen Moment …') : t('App anlegen')}
          </button>
        </div>
      </form>
    </>
  );
}

/** The hosts, and maybe paths, a proxy guards with this app. */
export function ForwardAddresses({
  values,
  onChange,
}: {
  values: string[];
  onChange: (values: string[]) => void;
}) {
  useLanguage();
  return (
    <div className="field">
      <span>{t('Geschützte Adressen')}</span>
      <UriList
        label={t('Geschützte Adressen')}
        values={values}
        onChange={onChange}
        placeholder="wiki.example.com"
      />
      <small className="field-hint">
        {t(
          'Ein Host, wenn nötig mit Port und Pfad: wiki.example.com oder example.com/admin. Die genaueste Adresse entscheidet; einen Host, den keine App kennt, lässt UwUAuth nicht durch.',
        )}
      </small>
    </div>
  );
}

/** What to put into the proxy: the two addresses to ask, and the headers that come back. */
export function ForwardConnection() {
  useLanguage();
  const urls = forwardAuthUrls(location.origin);
  return (
    <Section
      title={t('Verbindung')}
      lead={t(
        'Das trägst du im Reverse-Proxy ein. Wie genau, steht in der Anleitung unter docs/forward-auth.md.',
      )}
    >
      <div className="field">
        <span>{t('Für Caddy, Traefik und Nginx Proxy Manager')}</span>
        <CopyField value={urls.proxy} label={t('Für Caddy, Traefik und Nginx Proxy Manager')} />
      </div>
      <div className="field">
        <span>{t('Für nginx (auth_request)')}</span>
        <CopyField value={urls.nginx} label={t('Für nginx (auth_request)')} />
      </div>
      <p className="field-hint">
        {t(
          'Die App bekommt Remote-User, Remote-Groups, Remote-Email und Remote-Name. Für Apps auf anderen Hosts als UwUAuth braucht es in den Einstellungen eine Cookie-Domain.',
        )}
      </p>
    </Section>
  );
}

/** The forward-auth app is there: no secret, only what the proxy needs. */
export function ForwardMade({ app }: { app: App }) {
  useLanguage();
  return (
    <>
      <div className="made-head">
        <NyuScene name="done" className="made-scene" />
        <div>
          <PageTitle>{t('„{app}“ ist angelegt ✧', { app: app.name })}</PageTitle>
          <p className="muted page-lead">
            {t('Jetzt fehlt nur noch der Reverse-Proxy: Trag dort diese Adresse ein.')}
          </p>
        </div>
      </div>
      <ForwardConnection />
      <div className="form-actions">
        <span className="spacer" />
        <button type="button" className="primary" onClick={() => go(`/apps/${app.id}`)}>
          {t('Fertig – zur App')}
        </button>
      </div>
    </>
  );
}
