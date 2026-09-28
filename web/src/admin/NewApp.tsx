import { useEffect, useState, type FormEvent } from 'react';
import { AppIcon } from '../components/AppIcon';
import { CopyField, Loading, SecretOnce } from '../components/bits';
import { FormError, Row, Toggle } from '../components/controls';
import { Icon } from '../components/Icon';
import { NyuScene } from '../components/nyu/scenes';
import { PageTitle } from '../components/Shell';
import { UriList } from '../components/UriList';
import { api } from '../lib/api';
import { discoveryUrl, fillTemplate, GRANTS, templateNeeds } from '../lib/apps';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { go } from '../lib/route';
import { toast } from '../lib/toast';
import type { App, AppTemplate, GrantType } from '../lib/types';

const GENERIC = 'generic';

/** A new app: pick what it is, say where it lives, and get its ID and secret (once). */
export function NewApp() {
  useLanguage();
  const [templates, setTemplates] = useState<AppTemplate[] | null>(null);
  const [template, setTemplate] = useState<AppTemplate | null>(null);
  const [made, setMade] = useState<App | null>(null);
  useEffect(() => {
    api<AppTemplate[]>('/uwu/v1/app-templates').then(setTemplates, (e) =>
      toast(errorText(e), 'error'),
    );
  }, []);

  const back = (
    <button
      type="button"
      className="back-button quiet"
      onClick={() => (template && !made ? setTemplate(null) : go('/apps'))}
    >
      <Icon name="chevron" size={15} />
      {template && !made ? t('Andere Vorlage') : t('Alle Apps')}
    </button>
  );

  if (made && template) return <Made app={made} template={template} />;
  if (template)
    return (
      <>
        {back}
        <AppForm template={template} onMade={setMade} />
      </>
    );
  return (
    <>
      {back}
      <PageTitle>{t('Neue App')}</PageTitle>
      <p className="muted page-lead">
        {t(
          'Welche App soll sich über UwUAuth anmelden? Für viele gibt es eine Vorlage – sie trägt die Adressen ein und sagt dir, was du in der App einstellen musst.',
        )}
      </p>
      {!templates && <Loading />}
      {templates && (
        <div className="template-grid">
          {[...templates]
            .sort((a, b) => Number(a.key === GENERIC) - Number(b.key === GENERIC))
            .map((option) => (
              <button
                key={option.key}
                type="button"
                className="template-card"
                onClick={() => setTemplate(option)}
              >
                <AppIcon name={option.key === GENERIC ? 'OpenID Connect' : option.name} size={44} />
                <b>{option.key === GENERIC ? t('Andere App') : option.name}</b>
                {option.key === GENERIC && <small>{t('Alles mit OpenID Connect')}</small>}
              </button>
            ))}
        </div>
      )}
    </>
  );
}

function AppForm({ template, onMade }: { template: AppTemplate; onMade: (app: App) => void }) {
  useLanguage();
  const generic = template.key === GENERIC;
  const needs = templateNeeds([...template.redirectUris, ...template.postLogoutRedirectUris]);
  const [name, setName] = useState(generic ? '' : template.name);
  const [url, setUrl] = useState('');
  const [slug, setSlug] = useState('uwuauth');
  const [redirects, setRedirects] = useState<string[]>([]);
  const [launchUrl, setLaunchUrl] = useState('');
  const [isPublic, setPublic] = useState(template.public);
  const [consent, setConsent] = useState(false);
  const [grants, setGrants] = useState<GrantType[]>(['authorization_code', 'refresh_token']);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const signsIn = grants.includes('authorization_code');
  const filled =
    needs.url && url.trim() ? template.redirectUris.map((uri) => fillTemplate(uri, url, slug)) : [];
  const ready =
    name.trim() !== '' &&
    grants.length > 0 &&
    (!needs.url || /^https?:\/\/\S+$/.test(url.trim())) &&
    (!generic || !signsIn || redirects.length > 0);

  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      const made = await api<App>('/uwu/v1/apps', {
        body: {
          name: name.trim(),
          template: template.key,
          url: needs.url ? url.trim() : undefined,
          slug: needs.slug ? slug.trim() || 'uwuauth' : undefined,
          redirectUris: generic ? redirects : [],
          launchUrl: generic ? launchUrl.trim() || undefined : undefined,
          public: isPublic,
          consent,
          grantTypes: grants,
        },
      });
      onMade(made);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  const toggleGrant = (grant: GrantType, on: boolean) =>
    setGrants(on ? [...grants, grant] : grants.filter((other) => other !== grant));

  return (
    <>
      <PageTitle>
        <span className="title-with-icon">
          <AppIcon name={generic ? 'OpenID Connect' : template.name} size={36} />
          {generic ? t('Andere App') : template.name}
        </span>
      </PageTitle>
      <form className="card form app-form" onSubmit={submit}>
        <label className="field">
          <span>{t('Name')}</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t('So sehen ihn alle in „Meine Apps“')}
            maxLength={80}
            autoFocus={generic}
          />
        </label>
        {needs.url && (
          <label className="field">
            <span>{t('Adresse der App')}</span>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://app.example.com"
              inputMode="url"
              autoCapitalize="none"
              spellCheck={false}
              autoFocus={!generic}
            />
            <small className="field-hint">
              {t('So, wie du sie im Browser öffnest – mit https:// und, wenn nötig, dem Port.')}
            </small>
          </label>
        )}
        {needs.slug && (
          <label className="field">
            <span>{t('Kurzname für UwUAuth in der App')}</span>
            <input
              value={slug}
              onChange={(e) => setSlug(e.target.value.replace(/[^A-Za-z0-9_-]/g, ''))}
              maxLength={40}
              autoCapitalize="none"
              spellCheck={false}
            />
            <small className="field-hint">
              {t(
                'Unter diesem Namen legst du UwUAuth in der App an. Er steckt in der Weiterleitungs-Adresse.',
              )}
            </small>
          </label>
        )}
        {!generic && filled.length > 0 && (
          <div className="field">
            <span>{t('Weiterleitungs-Adressen, die UwUAuth einträgt')}</span>
            <div className="uri-list">
              {filled.map((uri) => (
                <div className="uri-row" key={uri}>
                  <code>{uri}</code>
                </div>
              ))}
            </div>
          </div>
        )}
        {generic && (
          <>
            <div className="field">
              <span>{t('Weiterleitungs-Adressen')}</span>
              <UriList
                label={t('Weiterleitungs-Adressen')}
                values={redirects}
                onChange={setRedirects}
                placeholder="https://app.example.com/oauth/callback"
              />
              <small className="field-hint">
                {t(
                  'Wohin UwUAuth nach dem Anmelden zurückschickt. Die Adresse steht in der Anleitung der App, oft unter „Redirect URI“ oder „Callback URL“.',
                )}
              </small>
            </div>
            <label className="field">
              <span>{t('Adresse zum Öffnen (freiwillig)')}</span>
              <input
                value={launchUrl}
                onChange={(e) => setLaunchUrl(e.target.value)}
                placeholder="https://app.example.com"
                inputMode="url"
                autoCapitalize="none"
                spellCheck={false}
              />
              <small className="field-hint">
                {t('Mit einer Adresse erscheint die App als Kachel unter „Meine Apps“.')}
              </small>
            </label>
          </>
        )}
        <Row
          label={t('Öffentliche App, ohne Geheimnis')}
          description={t(
            'Für Apps auf dem Handy, im Browser oder auf dem Fernseher, die kein Geheimnis sicher aufbewahren können. Sie melden sich mit PKCE an.',
          )}
        >
          <Toggle
            label={t('Öffentliche App, ohne Geheimnis')}
            checked={isPublic}
            onChange={setPublic}
          />
        </Row>
        <Row
          label={t('Vorher um Erlaubnis fragen')}
          description={t(
            'Beim ersten Anmelden sieht jede Person, was die App bekommt, und sagt Ja oder Nein. Für Apps, die jemand anderes betreibt.',
          )}
        >
          <Toggle label={t('Vorher um Erlaubnis fragen')} checked={consent} onChange={setConsent} />
        </Row>
        <details className="advanced-section">
          <summary className="section-title">{t('Mehr Optionen')}</summary>
          <GrantChoices grants={grants} onToggle={toggleGrant} />
        </details>
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

/** Which ways of getting tokens the app may use. */
export function GrantChoices({
  grants,
  onToggle,
  disabled,
}: {
  grants: GrantType[];
  onToggle: (grant: GrantType, on: boolean) => void;
  disabled?: boolean;
}) {
  useLanguage();
  return (
    <div className="grant-choices" role="group" aria-label={t('Wie die App an Tokens kommt')}>
      {GRANTS.map((grant) => (
        <label className="check grant-choice" key={grant.value}>
          <input
            type="checkbox"
            checked={grants.includes(grant.value)}
            disabled={disabled}
            onChange={(e) => onToggle(grant.value, e.target.checked)}
          />
          <span>
            <b>{t(grant.label)}</b>
            <small>{t(grant.hint)}</small>
          </span>
        </label>
      ))}
    </div>
  );
}

/** The app is there: its ID, its secret once, and what to fill in on its side. */
function Made({ app, template }: { app: App; template: AppTemplate }) {
  useLanguage();
  const issuer = app.issuer ?? location.origin;
  return (
    <>
      <div className="made-head">
        <NyuScene name="done" className="made-scene" />
        <div>
          <PageTitle>{t('„{app}“ ist angelegt ✧', { app: app.name })}</PageTitle>
          <p className="muted page-lead">
            {t('Jetzt fehlt nur noch die Seite der App: Trag dort diese Angaben ein.')}
          </p>
        </div>
      </div>
      <div className="card connection">
        <div className="field">
          <span>{t('Client-ID')}</span>
          <CopyField value={app.clientId} label={t('Client-ID')} />
        </div>
        {app.clientSecret && (
          <div className="field">
            <span>{t('Client-Secret')}</span>
            <p className="caution">
              <Icon name="warning" />
              <span>
                {t(
                  'Das Secret siehst du nur jetzt. Kopier es gleich in die App – später gibt es nur ein neues.',
                )}
              </span>
            </p>
            <SecretOnce value={app.clientSecret} />
          </div>
        )}
        <div className="field">
          <span>{t('Issuer')}</span>
          <CopyField value={issuer} label={t('Issuer')} />
        </div>
        <div className="field">
          <span>{t('Discovery-URL')}</span>
          <CopyField value={discoveryUrl(issuer)} label={t('Discovery-URL')} />
        </div>
      </div>
      {template.notes && <Notes text={template.notes} name={app.name} />}
      <div className="form-actions">
        <span className="spacer" />
        <button type="button" className="primary" onClick={() => go(`/apps/${app.id}`)}>
          {t('Fertig – zur App')}
        </button>
      </div>
    </>
  );
}

/** What to set on the app's side, from its template. */
export function Notes({ text, name }: { text: string; name: string }) {
  useLanguage();
  return (
    <section className="section">
      <div className="section-head">
        <h2 className="section-title">{t('So richtest du {app} ein', { app: name })}</h2>
      </div>
      <p className="notes card">{text}</p>
    </section>
  );
}
