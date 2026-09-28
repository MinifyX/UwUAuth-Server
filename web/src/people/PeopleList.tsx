import { useCallback, useEffect, useState } from 'react';
import { Ago, Avatar, Badge, Empty, Loading } from '../components/bits';
import { Segmented } from '../components/controls';
import { Icon } from '../components/Icon';
import { PageTitle } from '../components/Shell';
import { api } from '../lib/api';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import type { Group, Me, Person } from '../lib/types';
import { word } from '../lib/words';
import { CreatePerson } from './CreatePerson';

/**
 * Everybody the one looking may see: for an admin the whole directory (with the trash), for a
 * parent or team lead the people they look after.
 */
export function PeopleList({
  me,
  title,
  onOpen,
  only = null,
  afterCreate,
}: {
  me: Me;
  title: string;
  onOpen: (id: string) => void;
  /** Just these people, of all the server sends. */
  only?: Set<string> | null;
  /** What else a new account needs before it shows up. */
  afterCreate?: (id: string) => Promise<void>;
}) {
  useLanguage();
  const [trash, setTrash] = useState(false);
  const [list, setList] = useState<Person[] | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [search, setSearch] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const admin = me.admin;

  const load = useCallback(() => {
    api<Person[]>(`/uwu/v1/people${trash ? '?trash=true' : ''}`).then(
      (people) => {
        setList(people.sort((a, b) => a.displayName.localeCompare(b.displayName)));
        setError(null);
      },
      (e) => setError(errorText(e)),
    );
  }, [trash]);
  useEffect(load, [load]);
  useEffect(() => {
    if (admin) api<Group[]>('/uwu/v1/groups').then(setGroups, () => undefined);
  }, [admin]);

  const words = search.trim().toLowerCase();
  const shown = list?.filter(
    (person) =>
      (!only || only.has(person.id)) &&
      (!words ||
        `${person.displayName} ${person.username} ${person.email ?? ''}`
          .toLowerCase()
          .includes(words)),
  );
  const mode = me.server.mode;

  return (
    <>
      <PageTitle
        actions={
          <button type="button" className="primary" onClick={() => setCreating(true)}>
            <Icon name="plus" />
            {admin ? t('Person anlegen') : word(mode, 'addManaged')}
          </button>
        }
      >
        {title}
      </PageTitle>
      <div className="list-tools">
        <input
          className="search"
          type="search"
          placeholder={t('Suchen …')}
          aria-label={t('Personen suchen')}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        {admin && (
          <Segmented
            label={t('Welche')}
            value={trash ? 'trash' : 'active'}
            onChange={(value) => setTrash(value === 'trash')}
            options={[
              { value: 'active', label: t('Aktiv') },
              { value: 'trash', label: t('Papierkorb') },
            ]}
          />
        )}
      </div>
      {error && <p className="form-error">{error}</p>}
      {!list && !error && <Loading />}
      {shown && shown.length > 0 && (
        <ul className="people-list">
          {shown.map((person) => (
            <li key={person.id}>
              <button type="button" className="person-row" onClick={() => onOpen(person.id)}>
                <Avatar name={person.displayName} src={person.avatar} size={40} />
                <span className="person-text">
                  <b>
                    {person.displayName}
                    {person.admin && <Badge>{t('Admin')}</Badge>}
                    {person.managed && admin && <Badge>{word(mode, 'managedAccount')}</Badge>}
                    {person.disabled && <Badge tone="alarm">{t('gesperrt')}</Badge>}
                    {!person.hasPassword && !person.lastLogin && (
                      <Badge>{t('noch nicht eingerichtet')}</Badge>
                    )}
                  </b>
                  <small>
                    {person.username}
                    {person.email ? ` · ${person.email}` : ''}
                  </small>
                </span>
                <small className="person-seen">
                  <Ago iso={person.lastLogin} prefix={t('zuletzt da')} />
                </small>
                <Icon name="chevron" />
              </button>
            </li>
          ))}
        </ul>
      )}
      {shown && shown.length === 0 && (
        <Empty
          scene={trash ? 'sleepy' : 'family'}
          title={words ? t('Niemand gefunden.') : undefined}
        >
          {!words &&
            (trash
              ? t('Der Papierkorb ist leer.')
              : admin
                ? t('Noch niemand da.')
                : word(mode, 'noManaged'))}
        </Empty>
      )}
      {creating && (
        <CreatePerson
          admin={admin}
          mode={mode}
          mail={me.server.mail}
          minLength={me.server.passwordMinLength}
          groups={groups}
          onCancel={() => setCreating(false)}
          onDone={(id) => {
            setCreating(false);
            void (afterCreate?.(id) ?? Promise.resolve())
              .catch((e) => setError(errorText(e)))
              .then(() => {
                load();
                onOpen(id);
              });
          }}
        />
      )}
    </>
  );
}
