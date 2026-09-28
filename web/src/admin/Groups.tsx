import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Badge, Empty, Loading } from '../components/bits';
import { FormError, Row, Section, Toggle, useAction } from '../components/controls';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { Picker, type Choice } from '../components/Picker';
import { PageTitle } from '../components/Shell';
import { WindowsEditor } from '../components/WindowsEditor';
import { api, seg } from '../lib/api';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { go } from '../lib/route';
import { toast } from '../lib/toast';
import type { App, Group, GroupDetail, Me, Person } from '../lib/types';
import { groupName } from '../lib/words';
import { Confirm } from '../portal/Security';

/** Groups: who is in which, what they ask for, and when their members may sign in. */
export function Groups({ me, id }: { me: Me; id: string | null }) {
  useLanguage();
  if (id) return <GroupPage key={id} id={id} me={me} />;
  return <GroupList />;
}

function GroupList() {
  useLanguage();
  const [list, setList] = useState<Group[] | null>(null);
  const [creating, setCreating] = useState(false);
  useEffect(() => {
    api<Group[]>('/uwu/v1/groups').then(setList, (e) => toast(errorText(e), 'error'));
  }, []);
  return (
    <>
      <PageTitle
        actions={
          <button type="button" className="primary" onClick={() => setCreating(true)}>
            <Icon name="plus" />
            {t('Gruppe anlegen')}
          </button>
        }
      >
        {t('Gruppen')}
      </PageTitle>
      {!list && <Loading />}
      {list && list.length === 0 && <Empty scene="sleepy">{t('Noch keine Gruppen.')}</Empty>}
      {list && list.length > 0 && (
        <ul className="people-list">
          {list.map((group) => (
            <li key={group.id}>
              <button
                type="button"
                className="person-row"
                onClick={() => go(`/groups/${group.id}`)}
              >
                <span className="item-icon big">
                  <Icon name="users" size={20} />
                </span>
                <span className="person-text">
                  <b>
                    {groupName(group)}
                    {group.builtin && <Badge>{t('vom Server')}</Badge>}
                    {group.requireMfa && <Badge>{t('zweiter Faktor Pflicht')}</Badge>}
                    {group.ldapAppPasswordsOnly && <Badge>{t('LDAP nur mit App-Passwort')}</Badge>}
                  </b>
                  <small>
                    {group.description || builtinText(group) || t('Keine Beschreibung.')}
                  </small>
                </span>
                <small className="person-seen">
                  {group.members === 1 ? t('1 Person') : t('{n} Personen', { n: group.members })}
                </small>
                <Icon name="chevron" />
              </button>
            </li>
          ))}
        </ul>
      )}
      {creating && <CreateGroup onCancel={() => setCreating(false)} />}
    </>
  );
}

function builtinText(group: Group): string | null {
  if (group.builtin === 'admins') return t('Wer hier drin ist, ist Admin.');
  if (group.builtin === 'everyone') return t('Alle Personen, von selbst.');
  return null;
}

function CreateGroup({ onCancel }: { onCancel: () => void }) {
  useLanguage();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const group = await api<Group>('/uwu/v1/groups', {
        body: { name: name.trim(), description: description.trim() },
      });
      toast(t('Gruppe angelegt ✧'));
      go(`/groups/${group.id}`);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t('Gruppe anlegen')}
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
            disabled={busy || !name.trim()}
            onClick={() => void submit()}
          >
            {t('Anlegen')}
          </button>
        </>
      }
    >
      <form className="form" onSubmit={submit}>
        <label className="field">
          <span>{t('Name')}</span>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t('z. B. Kinder, Familie, Büro')}
            maxLength={64}
            autoFocus
          />
        </label>
        <label className="field">
          <span>{t('Beschreibung (freiwillig)')}</span>
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            maxLength={500}
          />
        </label>
        <FormError error={error} />
      </form>
    </Modal>
  );
}

function GroupPage({ id, me }: { id: string; me: Me }) {
  useLanguage();
  const [group, setGroup] = useState<GroupDetail | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [people, setPeople] = useState<Person[]>([]);
  const [apps, setApps] = useState<App[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);
  const load = useCallback(() => {
    api<GroupDetail>(`/uwu/v1/groups/${seg(id)}`).then(setGroup, (e) => setError(errorText(e)));
  }, [id]);
  useEffect(load, [load]);
  useEffect(() => {
    api<Group[]>('/uwu/v1/groups').then(setGroups, () => undefined);
    api<Person[]>('/uwu/v1/people').then(setPeople, () => undefined);
    api<App[]>('/uwu/v1/apps').then(setApps, () => undefined);
  }, []);

  const back = (
    <button type="button" className="back-button quiet" onClick={() => go('/groups')}>
      <Icon name="chevron" size={15} />
      {t('Alle Gruppen')}
    </button>
  );
  if (error)
    return (
      <>
        {back}
        <p className="form-error">{error}</p>
      </>
    );
  if (!group) return <Loading />;
  const base = `/uwu/v1/groups/${seg(group.id)}`;
  const saved = () => {
    toast(t('Gespeichert ✧'));
    load();
  };

  return (
    <>
      {back}
      <PageTitle
        actions={
          !group.builtin && (
            <button type="button" className="danger" onClick={() => setRemoving(true)}>
              <Icon name="trash" />
              {t('Löschen')}
            </button>
          )
        }
      >
        {groupName(group)}
      </PageTitle>
      <p className="muted page-lead">
        {group.everybody.length === 1
          ? t('1 Person ist darin, auch über Gruppen in der Gruppe.')
          : t('{n} Personen sind darin, auch über Gruppen in der Gruppe.', {
              n: group.everybody.length,
            })}
      </p>
      <SettingsSection group={group} base={base} onSaved={saved} />
      {group.builtin !== 'everyone' && (
        <MembersSection
          group={group}
          groups={groups}
          people={people}
          base={base}
          onSaved={saved}
          me={me}
        />
      )}
      <Section
        title={t('Zeitfenster')}
        lead={t(
          'Wann sich alle in dieser Gruppe bei Apps anmelden dürfen, die über UwUAuth angemeldet werden – bei allen oder nur bei einer. Keine Zeitfenster heißt: jederzeit.',
        )}
      >
        <WindowsEditor
          key={JSON.stringify(group.windows)}
          windows={group.windows}
          apps={apps}
          onSave={async (windows) => {
            await api(`${base}/windows`, { method: 'PUT', body: windows });
            saved();
          }}
        />
      </Section>
      {removing && (
        <Confirm
          title={t('Gruppe „{name}“ löschen?', { name: group.name })}
          lead={t('Die Personen darin bleiben, nur die Gruppe verschwindet.')}
          confirm={t('Löschen')}
          onCancel={() => setRemoving(false)}
          action={async () => {
            await api(base, { method: 'DELETE' });
            toast(t('Gelöscht.'));
            go('/groups');
          }}
        />
      )}
    </>
  );
}

function SettingsSection({
  group,
  base,
  onSaved,
}: {
  group: GroupDetail;
  base: string;
  onSaved: () => void;
}) {
  useLanguage();
  const [name, setName] = useState(group.name);
  const [description, setDescription] = useState(group.description);
  const [requireMfa, setRequireMfa] = useState(group.requireMfa);
  const [ldap, setLdap] = useState(group.ldapAppPasswordsOnly);
  const [run, busy] = useAction();
  const dirty =
    name !== group.name ||
    description !== group.description ||
    requireMfa !== group.requireMfa ||
    ldap !== group.ldapAppPasswordsOnly;
  return (
    <Section title={t('Einstellungen')}>
      <div className="form">
        <div className="field-pair">
          <label className="field">
            <span>{t('Name')}</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={Boolean(group.builtin)}
              maxLength={64}
            />
          </label>
          <label className="field">
            <span>{t('Beschreibung')}</span>
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={500}
            />
          </label>
        </div>
      </div>
      <Row
        label={t('Zweiter Faktor Pflicht')}
        description={t(
          'Wer in dieser Gruppe ist, braucht einen Passkey oder die Authenticator-App. Wer noch keins hat, wird nach der nächsten Anmeldung durch die Einrichtung geführt.',
        )}
      >
        <Toggle label={t('Zweiter Faktor Pflicht')} checked={requireMfa} onChange={setRequireMfa} />
      </Row>
      <Row
        label={t('Für LDAP nur App-Passwörter')}
        description={t(
          'Programme, die per LDAP anmelden (NAS, Linux-Rechner), nehmen dann nicht das richtige Passwort, sondern nur App-Passwörter. LDAP kommt in einer späteren Version.',
        )}
      >
        <Toggle label={t('Für LDAP nur App-Passwörter')} checked={ldap} onChange={setLdap} />
      </Row>
      <div className="form-actions">
        <span className="spacer" />
        <button
          type="button"
          className="primary"
          disabled={!dirty || busy || !name.trim()}
          onClick={() =>
            void run(async () => {
              await api(base, {
                method: 'PATCH',
                body: {
                  name: group.builtin ? undefined : name.trim(),
                  description,
                  requireMfa,
                  ldapAppPasswordsOnly: ldap,
                },
              });
              onSaved();
            })
          }
        >
          {t('Speichern')}
        </button>
      </div>
    </Section>
  );
}

function MembersSection({
  group,
  groups,
  people,
  base,
  onSaved,
  me,
}: {
  group: GroupDetail;
  groups: Group[];
  people: Person[];
  base: string;
  onSaved: () => void;
  me: Me;
}) {
  useLanguage();
  const [members, setMembers] = useState(group.people);
  const [inner, setInner] = useState(group.groups);
  const [owners, setOwners] = useState(group.owners);
  const [run, busy] = useAction();
  const same = (a: string[], b: string[]) =>
    JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
  const dirty =
    !same(members, group.people) || !same(inner, group.groups) || !same(owners, group.owners);
  const personChoices: Choice[] = people
    .filter((person) => !person.deleted)
    .map((person) => ({
      id: person.id,
      label: person.displayName,
      sub: person.username,
      avatar: person.avatar,
    }));
  const groupChoices: Choice[] = groups
    .filter((other) => other.id !== group.id && other.builtin !== 'everyone')
    .map((other) => ({ id: other.id, label: groupName(other), kind: 'group' }));
  const leavingAdmin = group.builtin === 'admins' && !members.includes(me.id);
  return (
    <Section
      title={t('Mitglieder')}
      lead={t(
        'Personen direkt, und ganze Gruppen: Wer in einer Gruppe darin ist, gehört auch hierher.',
      )}
    >
      <div className="field">
        <span>{t('Personen')}</span>
        <Picker
          label={t('Personen')}
          choices={personChoices}
          picked={members}
          onChange={setMembers}
        />
      </div>
      <div className="field">
        <span>{t('Gruppen in dieser Gruppe')}</span>
        <Picker
          label={t('Gruppen in dieser Gruppe')}
          choices={groupChoices}
          picked={inner}
          onChange={setInner}
          empty={t('Keine.')}
        />
      </div>
      <div className="field">
        <span>{t('Verwaltet von')}</span>
        <Picker
          label={t('Verwaltet von')}
          choices={personChoices}
          picked={owners}
          onChange={setOwners}
          empty={t('Nur Admins.')}
        />
        <small className="field-hint">
          {t('Wer eine Gruppe verwaltet, kann im Portal ihre Beschreibung und Mitglieder ändern.')}
        </small>
      </div>
      {leavingAdmin && (
        <p className="field-hint" data-tone="warn">
          {t('Du nimmst dich selbst aus den Admins. Danach kommst du nicht mehr ins Admin-Portal.')}
        </p>
      )}
      <div className="form-actions">
        <span className="spacer" />
        <button
          type="button"
          className="primary"
          disabled={!dirty || busy}
          onClick={() =>
            void run(async () => {
              await api(`${base}/members`, {
                method: 'PUT',
                body: { people: members, groups: inner, owners },
              });
              onSaved();
            })
          }
        >
          {t('Speichern')}
        </button>
      </div>
    </Section>
  );
}
