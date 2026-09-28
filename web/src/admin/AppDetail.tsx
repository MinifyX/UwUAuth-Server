import { useCallback, useEffect, useState } from 'react';
import { AppIcon } from '../components/AppIcon';
import { CopyField, Loading, SecretOnce } from '../components/bits';
import { Row, Section, Segmented, Toggle, useAction } from '../components/controls';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { Picker, type Choice } from '../components/Picker';
import { PageTitle } from '../components/Shell';
import { UriList } from '../components/UriList';
import { api, seg } from '../lib/api';
import { discoveryUrl } from '../lib/apps';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { go } from '../lib/route';
import { toast } from '../lib/toast';
import type { App, Group } from '../lib/types';
import { groupName } from '../lib/words';
import { Confirm } from '../portal/Security';
import { AppBadges } from './Apps';
import { GrantChoices, Notes } from './NewApp';

/** What the page lets one change, as the API names it. */
type Draft = {
  name: string;
  description: string;
  launchUrl: string;
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  backchannelLogoutUri: string;
  allowedGroups: string[];
  requireMfa: boolean;
  consent: boolean;
  enabled: boolean;
  public: boolean;
  tokenAuthMethod: App['tokenAuthMethod'];
  idTokenAlg: App['idTokenAlg'];
  grantTypes: App['grantTypes'];
  requirePkce: boolean;
  accessTokenMinutes: number;
  refreshTokenDays: number;
};

function draftOf(app: App): Draft {
  return {
    name: app.name,
    description: app.description,
    launchUrl: app.launchUrl ?? '',
    redirectUris: app.redirectUris,
    postLogoutRedirectUris: app.postLogoutRedirectUris,
    backchannelLogoutUri: app.backchannelLogoutUri ?? '',
    allowedGroups: app.allowedGroups,
    requireMfa: app.requireMfa,
    consent: app.consent,
    enabled: !app.disabled,
    public: app.public,
    tokenAuthMethod: app.tokenAuthMethod,
    idTokenAlg: app.idTokenAlg,
    grantTypes: app.grantTypes,
    requirePkce: app.requirePkce,
    accessTokenMinutes: app.accessTokenMinutes,
    refreshTokenDays: app.refreshTokenDays,
  };
}

/** Only what changed, as the PATCH body: the server keeps everything else. */
function changes(before: Draft, after: Draft): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  for (const key of Object.keys(after) as (keyof Draft)[]) {
    if (JSON.stringify(before[key]) === JSON.stringify(after[key])) continue;
    if (key === 'enabled') body.disabled = !after.enabled;
    else if (key === 'name' || key === 'description') body[key] = (after[key] as string).trim();
    else if (key === 'launchUrl' || key === 'backchannelLogoutUri')
      body[key] = (after[key] as string).trim();
    else body[key] = after[key];
  }
  return body;
}

export function AppPage({ id }: { id: string }) {
  useLanguage();
  const [app, setApp] = useState<App | null>(null);
  // Every fresh copy from the server starts the editor over, with nothing unsaved.
  const [version, setVersion] = useState(0);
  const [groups, setGroups] = useState<Group[]>([]);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => {
    api<App>(`/uwu/v1/apps/${seg(id)}`).then(
      (next) => {
        setApp(next);
        setVersion((count) => count + 1);
      },
      (e) => setError(errorText(e)),
    );
  }, [id]);
  useEffect(load, [load]);
  useEffect(() => {
    api<Group[]>('/uwu/v1/groups').then(setGroups, () => undefined);
  }, []);

  const back = (
    <button type="button" className="back-button quiet" onClick={() => go('/apps')}>
      <Icon name="chevron" size={15} />
      {t('Alle Apps')}
    </button>
  );
  if (error)
    return (
      <>
        {back}
        <p className="form-error">{error}</p>
      </>
    );
  if (!app) return <Loading />;
  return (
    <>
      {back}
      <AppEditor key={version} app={app} groups={groups} onSaved={load} />
    </>
  );
}

function AppEditor({ app, groups, onSaved }: { app: App; groups: Group[]; onSaved: () => void }) {
  useLanguage();
  const saved = draftOf(app);
  const [draft, setDraft] = useState<Draft>(saved);
  const [dialog, setDialog] = useState<'remove' | 'secret' | { secret: string } | null>(null);
  const [run, busy] = useAction();
  const set = (patch: Partial<Draft>) => setDraft({ ...draft, ...patch });
  const body = changes(saved, draft);
  const dirty = Object.keys(body).length > 0;
  const issuer = app.issuer ?? location.origin;
  const groupChoices: Choice[] = groups
    .filter((group) => group.builtin !== 'everyone')
    .map((group) => ({ id: group.id, label: groupName(group), kind: 'group' }));

  const save = () =>
    run(async () => {
      await api(`/uwu/v1/apps/${seg(app.id)}`, { method: 'PATCH', body });
      toast(t('Gespeichert ✧'));
      onSaved();
    });

  return (
    <>
      <PageTitle
        actions={
          <button type="button" className="danger" onClick={() => setDialog('remove')}>
            <Icon name="trash" />
            {t('Löschen')}
          </button>
        }
      >
        <span className="title-with-icon">
          <AppIcon name={app.name} size={36} />
          {app.name}
        </span>
      </PageTitle>
      <p className="badges page-lead">
        <AppBadges app={app} />
      </p>

      <Section title={t('Verbindung')} lead={t('Das trägst du auf der Seite der App ein.')}>
        <div className="field">
          <span>{t('Client-ID')}</span>
          <CopyField value={app.clientId} label={t('Client-ID')} />
        </div>
        <div className="field">
          <span>{t('Client-Secret')}</span>
          <div className="secret-line">
            <span className="muted">
              {app.public
                ? t('Keins – eine öffentliche App meldet sich mit PKCE an.')
                : t('Nur beim Anlegen zu sehen. Verloren? Mach ein neues.')}
            </span>
            <button type="button" onClick={() => setDialog('secret')}>
              <Icon name="refresh" />
              {t('Neues Secret')}
            </button>
          </div>
        </div>
        <div className="field">
          <span>{t('Issuer')}</span>
          <CopyField value={issuer} label={t('Issuer')} />
        </div>
        <div className="field">
          <span>{t('Discovery-URL')}</span>
          <CopyField value={discoveryUrl(issuer)} label={t('Discovery-URL')} />
        </div>
      </Section>
      {app.notes && <Notes text={app.notes} name={app.name} />}

      <Section title={t('Allgemein')}>
        <div className="form">
          <div className="field-pair">
            <label className="field">
              <span>{t('Name')}</span>
              <input
                value={draft.name}
                onChange={(e) => set({ name: e.target.value })}
                maxLength={80}
              />
            </label>
            <label className="field">
              <span>{t('Beschreibung')}</span>
              <input
                value={draft.description}
                onChange={(e) => set({ description: e.target.value })}
                maxLength={500}
              />
            </label>
          </div>
          <label className="field">
            <span>{t('Adresse zum Öffnen')}</span>
            <input
              value={draft.launchUrl}
              onChange={(e) => set({ launchUrl: e.target.value })}
              placeholder="https://app.example.com"
              inputMode="url"
              autoCapitalize="none"
              spellCheck={false}
            />
            <small className="field-hint">
              {t('Mit einer Adresse erscheint die App als Kachel unter „Meine Apps“.')}
            </small>
          </label>
        </div>
        <Row
          label={t('Eingeschaltet')}
          description={t(
            'Ausgeschaltet meldet die App niemanden an, und ihre Tokens gelten nicht mehr.',
          )}
        >
          <Toggle
            label={t('Eingeschaltet')}
            checked={draft.enabled}
            onChange={(enabled) => set({ enabled })}
          />
        </Row>
      </Section>

      <Section
        title={t('Wer darf')}
        lead={t(
          'Ohne Gruppen darf jede Person die App benutzen. Zeitfenster für einzelne Apps stellst du bei der Person oder der Gruppe ein.',
        )}
      >
        <div className="field">
          <span>{t('Nur für diese Gruppen')}</span>
          <Picker
            label={t('Nur für diese Gruppen')}
            choices={groupChoices}
            picked={draft.allowedGroups}
            onChange={(allowedGroups) => set({ allowedGroups })}
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
            checked={draft.requireMfa}
            onChange={(requireMfa) => set({ requireMfa })}
          />
        </Row>
        <Row
          label={t('Vorher um Erlaubnis fragen')}
          description={t(
            'Beim ersten Anmelden sieht jede Person, was die App bekommt, und sagt Ja oder Nein. Für Apps, die jemand anderes betreibt.',
          )}
        >
          <Toggle
            label={t('Vorher um Erlaubnis fragen')}
            checked={draft.consent}
            onChange={(consent) => set({ consent })}
          />
        </Row>
      </Section>

      <Section title={t('Adressen')}>
        <div className="field">
          <span>{t('Weiterleitungs-Adressen')}</span>
          <UriList
            label={t('Weiterleitungs-Adressen')}
            values={draft.redirectUris}
            onChange={(redirectUris) => set({ redirectUris })}
            placeholder="https://app.example.com/oauth/callback"
          />
          <small className="field-hint">
            {t('Nur an diese Adressen schickt UwUAuth nach dem Anmelden zurück.')}
          </small>
        </div>
        <div className="field">
          <span>{t('Adressen nach dem Abmelden')}</span>
          <UriList
            label={t('Adressen nach dem Abmelden')}
            values={draft.postLogoutRedirectUris}
            onChange={(postLogoutRedirectUris) => set({ postLogoutRedirectUris })}
            placeholder="https://app.example.com/"
          />
        </div>
        <label className="field">
          <span>{t('Back-Channel-Logout (freiwillig)')}</span>
          <input
            value={draft.backchannelLogoutUri}
            onChange={(e) => set({ backchannelLogoutUri: e.target.value })}
            placeholder="https://app.example.com/oauth/backchannel-logout"
            inputMode="url"
            autoCapitalize="none"
            spellCheck={false}
          />
          <small className="field-hint">
            {t('Hierhin sagt UwUAuth der App Bescheid, wenn sich jemand abmeldet.')}
          </small>
        </label>
      </Section>

      <Section title={t('Technik')}>
        <Row
          label={t('Öffentliche App, ohne Geheimnis')}
          description={
            app.public
              ? t('Mit „Neues Secret“ wird daraus eine App mit Geheimnis.')
              : draft.public
                ? t(
                    'Beim Speichern verfällt das Secret – die App meldet sich dann nur noch mit PKCE an.',
                  )
                : t(
                    'Für Apps auf dem Handy, im Browser oder auf dem Fernseher, die kein Geheimnis sicher aufbewahren können.',
                  )
          }
        >
          <Toggle
            label={t('Öffentliche App, ohne Geheimnis')}
            checked={draft.public}
            disabled={app.public}
            onChange={(isPublic) => set({ public: isPublic })}
          />
        </Row>
        {!draft.public && (
          <Row
            label={t('Wie die App ihr Secret schickt')}
            description={t('Steht in der Anleitung der App; fast alle nehmen „Basic“.')}
          >
            <Segmented
              label={t('Wie die App ihr Secret schickt')}
              value={
                draft.tokenAuthMethod === 'client_secret_post'
                  ? 'client_secret_post'
                  : 'client_secret_basic'
              }
              options={[
                { value: 'client_secret_basic', label: 'Basic' },
                { value: 'client_secret_post', label: 'POST' },
              ]}
              onChange={(tokenAuthMethod) => set({ tokenAuthMethod })}
            />
          </Row>
        )}
        <Row
          label={t('Signatur des ID-Tokens')}
          description={t('RS256 versteht jede App. ES256 nur, wenn die App es verlangt.')}
        >
          <Segmented
            label={t('Signatur des ID-Tokens')}
            value={draft.idTokenAlg}
            options={[
              { value: 'RS256', label: 'RS256' },
              { value: 'ES256', label: 'ES256' },
            ]}
            onChange={(idTokenAlg) => set({ idTokenAlg })}
          />
        </Row>
        <Row
          label={t('PKCE immer verlangen')}
          description={t(
            'Öffentliche Apps brauchen PKCE sowieso. Für Apps mit Secret ist es ein Extra-Schutz.',
          )}
        >
          <Toggle
            label={t('PKCE immer verlangen')}
            checked={draft.requirePkce || draft.public}
            disabled={draft.public}
            onChange={(requirePkce) => set({ requirePkce })}
          />
        </Row>
        <Row
          label={t('Access-Token gilt')}
          description={t('Minuten. Je kürzer, desto schneller greifen Sperren und Zeitfenster.')}
        >
          <input
            className="number-input"
            type="number"
            min={1}
            max={1440}
            value={draft.accessTokenMinutes}
            onChange={(e) => set({ accessTokenMinutes: Number(e.target.value) || 15 })}
          />
        </Row>
        <Row label={t('Angemeldet bleiben bis zu')} description={t('Tage ohne neues Anmelden.')}>
          <input
            className="number-input"
            type="number"
            min={1}
            max={3650}
            value={draft.refreshTokenDays}
            onChange={(e) => set({ refreshTokenDays: Number(e.target.value) || 30 })}
          />
        </Row>
        <div className="field">
          <span>{t('Wie die App an Tokens kommt')}</span>
          <GrantChoices
            grants={draft.grantTypes}
            onToggle={(grant, on) =>
              set({
                grantTypes: on
                  ? [...draft.grantTypes, grant]
                  : draft.grantTypes.filter((other) => other !== grant),
              })
            }
          />
        </div>
      </Section>

      {dirty && (
        <div className="form-actions sticky-actions">
          <span className="muted">{t('Ungespeicherte Änderungen')}</span>
          <span className="spacer" />
          <button type="button" data-secondary disabled={busy} onClick={() => setDraft(saved)}>
            {t('Verwerfen')}
          </button>
          <button
            type="button"
            className="primary"
            disabled={busy || !draft.name.trim() || draft.grantTypes.length === 0}
            onClick={() => void save()}
          >
            {t('Speichern')}
          </button>
        </div>
      )}

      {dialog === 'remove' && (
        <Confirm
          title={t('„{app}“ löschen?', { app: app.name })}
          lead={t(
            'Niemand kann sich dann noch über UwUAuth bei der App anmelden, und alle ihre Tokens verfallen. Das lässt sich nicht rückgängig machen.',
          )}
          confirm={t('Löschen')}
          onCancel={() => setDialog(null)}
          action={async () => {
            await api(`/uwu/v1/apps/${seg(app.id)}`, { method: 'DELETE' });
            toast(t('Gelöscht.'));
            go('/apps');
          }}
        />
      )}
      {dialog === 'secret' && (
        <Confirm
          title={t('Neues Secret für „{app}“?', { app: app.name })}
          lead={
            app.public
              ? t('Die App bekommt ein Secret und muss es ab jetzt mitschicken.')
              : t(
                  'Das alte Secret hört sofort auf zu gelten. Die App meldet niemanden an, bis du das neue dort einträgst.',
                )
          }
          confirm={t('Neues Secret')}
          onCancel={() => setDialog(null)}
          action={async () => {
            const made = await api<{ clientSecret: string }>(`/uwu/v1/apps/${seg(app.id)}/secret`, {
              method: 'POST',
              body: {},
            });
            setDialog({ secret: made.clientSecret });
          }}
        />
      )}
      {dialog && typeof dialog === 'object' && (
        <Modal
          title={t('Das neue Secret')}
          onCancel={() => {
            setDialog(null);
            onSaved();
          }}
          footer={
            <>
              <span className="spacer" />
              <button
                type="button"
                className="primary"
                onClick={() => {
                  setDialog(null);
                  onSaved();
                }}
              >
                {t('Fertig')}
              </button>
            </>
          }
        >
          <p className="caution">
            <Icon name="warning" />
            <span>
              {t(
                'Das Secret siehst du nur jetzt. Kopier es gleich in die App – später gibt es nur ein neues.',
              )}
            </span>
          </p>
          <SecretOnce value={dialog.secret} />
        </Modal>
      )}
    </>
  );
}
