import { useState } from 'react';
import { Ago, CopyField, Day } from '../components/bits';
import { FormError, Row, Section, Segmented, Toggle, useAction } from '../components/controls';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { PasswordInput } from '../components/PasswordInput';
import { Picker, type Choice } from '../components/Picker';
import { api, seg } from '../lib/api';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import type { App, Group, ScimInfo, SuiteInfo } from '../lib/types';
import { groupName } from '../lib/words';
import { Confirm } from '../portal/Security';

/** What a paired UwUSuite app said about itself. */
export function SuiteSection({ suite }: { suite: SuiteInfo }) {
  useLanguage();
  return (
    <Section
      title={t('UwUSuite')}
      lead={t(
        'Diese App hat sich mit einem Kopplungscode verbunden und dabei Client-ID, Secret und den SCIM-Token bekommen. Ein neues Secret musst du dort von Hand eintragen.',
      )}
    >
      <div className="field-pair">
        <div className="field">
          <span>{t('Programm')}</span>
          <p>
            {suite.product} {suite.version}
          </p>
        </div>
        <div className="field">
          <span>{t('Gekoppelt')}</span>
          <p>
            <Day iso={suite.paired} />
          </p>
        </div>
      </div>
      <div className="field">
        <span>{t('Adresse der App')}</span>
        <CopyField value={suite.url} label={t('Adresse der App')} />
      </div>
    </Section>
  );
}

export type RoleMapping = { group: string; role: string };

/**
 * Which groups get which role in the app — what goes into the `roles` claim. A paired suite app
 * says which roles it knows; for any other app, the admin names them.
 */
export function RolesEditor({
  roles,
  known,
  groups,
  onChange,
}: {
  roles: RoleMapping[];
  known: SuiteInfo['roles'] | null;
  groups: Group[];
  onChange: (roles: RoleMapping[]) => void;
}) {
  useLanguage();
  const [added, setAdded] = useState<string[]>([]);
  const [name, setName] = useState('');
  const choices: Choice[] = groups.map((group) => ({
    id: group.id,
    label: groupName(group),
    kind: 'group',
  }));
  const names = [
    ...(known ?? []).map((role) => role.id),
    ...roles.map((mapping) => mapping.role),
    ...added,
  ].filter((role, index, all) => all.indexOf(role) === index);
  const groupsOf = (role: string) =>
    roles.filter((mapping) => mapping.role === role).map((mapping) => mapping.group);
  const set = (role: string, picked: string[]) =>
    onChange([
      ...roles.filter((mapping) => mapping.role !== role),
      ...picked.map((group) => ({ group, role })),
    ]);
  const add = () => {
    const role = name.trim();
    if (role && !names.includes(role)) setAdded([...added, role]);
    setName('');
  };
  return (
    <>
      {names.length === 0 && (
        <p className="empty-note">
          {t('Noch keine Rollen. Die App bekommt dann eine leere Liste.')}
        </p>
      )}
      {names.map((role) => {
        const about = known?.find((item) => item.id === role);
        return (
          <div className="field" key={role}>
            <span>
              {about?.name ?? role}
              {about && about.name !== role && <small className="mono"> {role}</small>}
            </span>
            <Picker
              label={about?.name ?? role}
              choices={choices}
              picked={groupsOf(role)}
              onChange={(picked) => set(role, picked)}
              empty={t('Keine Gruppe hat diese Rolle.')}
            />
            {about?.description && <small className="field-hint">{about.description}</small>}
          </div>
        );
      })}
      {!known?.length && (
        <div className="field-pair">
          <label className="field">
            <span>{t('Neue Rolle')}</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  add();
                }
              }}
              placeholder={t('z. B. admin')}
              maxLength={60}
            />
          </label>
          <div className="field">
            <span aria-hidden="true">&nbsp;</span>
            <button type="button" onClick={add} disabled={!name.trim()}>
              <Icon name="plus" />
              {t('Hinzufügen')}
            </button>
          </div>
        </div>
      )}
    </>
  );
}

/** How pushing people and groups over SCIM goes — or setting it up for any app. */
export function ScimSection({ app, onChanged }: { app: App; onChanged: () => void }) {
  useLanguage();
  const [editing, setEditing] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [run, busy] = useAction();
  const scim = app.scim ?? null;
  const sync = (all: boolean) =>
    run(async () => {
      await api(`/uwu/v1/apps/${seg(app.id)}/scim/sync`, { body: { all } });
      toast(t('Der Abgleich läuft.'));
      window.setTimeout(onChanged, 1500);
    });
  return (
    <Section
      title={t('Personen und Gruppen (SCIM)')}
      lead={t(
        'UwUAuth schiebt die Personen, die die App benutzen dürfen, und ihre Gruppen dorthin – wer gesperrt wird oder keine Gruppe mehr hat, wird dort deaktiviert.',
      )}
      actions={
        scim ? (
          <>
            <button type="button" disabled={busy} onClick={() => void sync(false)}>
              <Icon name="refresh" />
              {t('Jetzt abgleichen')}
            </button>
            <button type="button" onClick={() => setEditing(true)}>
              <Icon name="pencil" />
              {t('Ändern')}
            </button>
          </>
        ) : (
          <button type="button" onClick={() => setEditing(true)}>
            <Icon name="plus" />
            {t('SCIM einrichten')}
          </button>
        )
      }
    >
      {scim ? (
        <ScimStatus scim={scim} />
      ) : (
        <p className="empty-note">
          {t('Aus. Nimmt die App SCIM an, trägst du hier ihre Adresse und ihren Token ein.')}
        </p>
      )}
      {scim && (
        <div className="form-actions">
          <button type="button" data-secondary disabled={busy} onClick={() => void sync(true)}>
            {t('Alles neu senden')}
          </button>
          <span className="spacer" />
          <button type="button" className="quiet danger-text" onClick={() => setStopping(true)}>
            {t('Abgleich beenden')}
          </button>
        </div>
      )}
      {editing && (
        <ScimForm
          app={app}
          onClose={(changed) => {
            setEditing(false);
            if (changed) onChanged();
          }}
        />
      )}
      {stopping && (
        <Confirm
          title={t('Abgleich mit „{app}“ beenden?', { app: app.name })}
          lead={t(
            'UwUAuth schickt dann nichts mehr dorthin. Was die App schon hat, bleibt dort, bis du es dort löschst.',
          )}
          confirm={t('Beenden')}
          onCancel={() => setStopping(false)}
          action={async () => {
            await api(`/uwu/v1/apps/${seg(app.id)}/scim`, { method: 'DELETE' });
            setStopping(false);
            onChanged();
          }}
        />
      )}
    </Section>
  );
}

function ScimStatus({ scim }: { scim: ScimInfo }) {
  useLanguage();
  return (
    <>
      <div className="field">
        <span>{t('SCIM-Adresse')}</span>
        <CopyField value={scim.baseUrl} label={t('SCIM-Adresse')} />
      </div>
      <Row
        label={t('Zuletzt abgeglichen')}
        description={t('{users} Personen, {groups} Gruppen', {
          users: scim.users,
          groups: scim.groups,
        })}
      >
        {scim.synced ? <Ago iso={scim.synced} /> : <span className="muted">{t('noch nie')}</span>}
      </Row>
      {scim.error && (
        <p className="caution">
          <Icon name="warning" />
          <span>
            {t('Der letzte Versuch ging schief: {error}', { error: scim.error })}{' '}
            {scim.tried && <Ago iso={scim.tried} />}
          </span>
        </p>
      )}
    </>
  );
}

function ScimForm({ app, onClose }: { app: App; onClose: (changed: boolean) => void }) {
  useLanguage();
  const scim = app.scim ?? null;
  const [baseUrl, setBaseUrl] = useState(scim?.baseUrl ?? '');
  const [token, setToken] = useState('');
  const [userName, setUserName] = useState<ScimInfo['userName']>(scim?.userName ?? 'email');
  const [groups, setGroups] = useState(scim ? scim.resources.includes('Group') : true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await api(`/uwu/v1/apps/${seg(app.id)}/scim`, {
        method: 'PUT',
        body: {
          baseUrl: baseUrl.trim(),
          token: token.trim() || undefined,
          userName,
          resources: groups ? ['User', 'Group'] : ['User'],
        },
      });
      toast(t('Gespeichert ✧'));
      onClose(true);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={scim ? t('SCIM ändern') : t('SCIM einrichten')}
      onCancel={() => !busy && onClose(false)}
      footer={
        <>
          <span className="spacer" />
          <button type="button" data-secondary onClick={() => onClose(false)} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button
            type="button"
            className="primary"
            disabled={busy || !baseUrl.trim() || (!scim && !token.trim())}
            onClick={() => void save()}
          >
            {t('Speichern')}
          </button>
        </>
      }
    >
      <form
        className="form"
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <label className="field">
          <span>{t('SCIM-Adresse der App')}</span>
          <input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://app.example.com/scim/v2"
            inputMode="url"
            autoCapitalize="none"
            spellCheck={false}
          />
        </label>
        <div className="field">
          <span>{scim ? t('Neuer Token (leer lassen: bleibt)') : t('Token der App')}</span>
          <PasswordInput value={token} onChange={setToken} autoComplete="off" />
          <small className="field-hint">
            {t(
              'Den Token zeigt die App in ihren SCIM-Einstellungen. UwUAuth schickt ihn bei jedem Aufruf mit.',
            )}
          </small>
        </div>
        <Row
          label={t('Personen erkennt die App an')}
          description={t('Die Programme der UwUSuite nehmen die E-Mail-Adresse.')}
        >
          <Segmented
            label={t('Personen erkennt die App an')}
            value={userName}
            options={[
              { value: 'email', label: t('E-Mail-Adresse') },
              { value: 'username', label: t('Benutzername') },
            ]}
            onChange={setUserName}
          />
        </Row>
        <Row
          label={t('Gruppen auch schicken')}
          description={t('Die erlaubten Gruppen und die der Rollen.')}
        >
          <Toggle label={t('Gruppen auch schicken')} checked={groups} onChange={setGroups} />
        </Row>
        <FormError error={error} />
      </form>
    </Modal>
  );
}
