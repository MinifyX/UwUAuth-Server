import { useCallback, useEffect, useState } from 'react';
import { Badge, Empty } from '../components/bits';
import { Section, useAction } from '../components/controls';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { Picker } from '../components/Picker';
import { PageTitle } from '../components/Shell';
import { api, seg } from '../lib/api';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import type { Group, GroupDetail, Me, Person } from '../lib/types';
import { groupName } from '../lib/words';

/** The groups one is in, and for the groups one owns, their description and members. */
export function MyGroups({ me }: { me: Me }) {
  useLanguage();
  const [groups, setGroups] = useState<Group[]>([]);
  const [editing, setEditing] = useState<string | null>(null);
  const load = useCallback(() => {
    api<Group[]>('/uwu/v1/groups').then(setGroups, () => setGroups([]));
  }, []);
  useEffect(load, [load]);
  const byId = new Map(groups.map((group) => [group.id, group]));

  return (
    <>
      <PageTitle>{t('Gruppen')}</PageTitle>
      <Section
        title={t('Deine Gruppen')}
        lead={t('Gruppen bestimmen, welche Apps du benutzen darfst und was du dort sehen kannst.')}
      >
        {me.memberOf.length === 0 ? (
          <Empty scene="sleepy" title={t('In keiner Gruppe')}>
            {t('Ein Admin kann dich in Gruppen aufnehmen.')}
          </Empty>
        ) : (
          <ul className="item-list">
            {me.memberOf.map((membership) => {
              const group = byId.get(membership.id);
              const owner = me.ownsGroups.includes(membership.id);
              return (
                <li key={membership.id} className="item">
                  <span className="item-icon">
                    <Icon name="users" />
                  </span>
                  <span className="item-text">
                    <b>
                      {groupName(membership)}
                      {owner && <Badge>{t('du verwaltest sie')}</Badge>}
                      {group?.requireMfa && <Badge>{t('zweiter Faktor Pflicht')}</Badge>}
                    </b>
                    <small>
                      {group?.description ||
                        (membership.direct
                          ? t('Du bist direkt Mitglied.')
                          : t('Über eine andere Gruppe.'))}
                    </small>
                  </span>
                  {owner && (
                    <button type="button" onClick={() => setEditing(membership.id)}>
                      {t('Verwalten')}
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Section>
      {me.ownsGroups
        .filter((id) => !me.memberOf.some((membership) => membership.id === id))
        .map((id) => (
          <Section key={id} title={byId.get(id)?.name ?? t('Gruppe')}>
            <p className="muted">
              {t('Du verwaltest diese Gruppe, bist aber selbst nicht darin.')}
            </p>
            <button type="button" onClick={() => setEditing(id)}>
              {t('Verwalten')}
            </button>
          </Section>
        ))}
      {editing && (
        <OwnedGroup
          id={editing}
          onClose={() => {
            setEditing(null);
            load();
          }}
        />
      )}
    </>
  );
}

/** What an owner may change: the description, and who is in it. */
function OwnedGroup({ id, onClose }: { id: string; onClose: () => void }) {
  useLanguage();
  const [group, setGroup] = useState<GroupDetail | null>(null);
  const [people, setPeople] = useState<Person[] | null>(null);
  const [description, setDescription] = useState('');
  const [members, setMembers] = useState<string[]>([]);
  const [run, busy] = useAction();

  useEffect(() => {
    api<GroupDetail>(`/uwu/v1/groups/${seg(id)}`).then((loaded) => {
      setGroup(loaded);
      setDescription(loaded.description);
      setMembers(loaded.people);
    });
    // Names for the members come from the people list, which only admins and those who look
    // after somebody get; without it, the members cannot be picked here.
    api<Person[]>('/uwu/v1/people').then(setPeople, () => setPeople(null));
  }, [id]);

  const save = () =>
    run(async () => {
      if (!group) return;
      if (description !== group.description)
        await api(`/uwu/v1/groups/${seg(id)}`, { method: 'PATCH', body: { description } });
      if (people && JSON.stringify(members) !== JSON.stringify(group.people))
        await api(`/uwu/v1/groups/${seg(id)}/members`, {
          method: 'PUT',
          body: { people: members, groups: group.groups },
        });
      toast(t('Gespeichert ✧'));
      onClose();
    });

  return (
    <Modal
      title={group ? t('Gruppe „{name}“', { name: group.name }) : t('Gruppe')}
      size="wide"
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
            disabled={busy || !group}
            onClick={() => void save()}
          >
            {t('Speichern')}
          </button>
        </>
      }
    >
      {group && (
        <div className="form">
          <label className="field">
            <span>{t('Beschreibung')}</span>
            <textarea
              value={description}
              maxLength={500}
              onChange={(e) => setDescription(e.target.value)}
            />
          </label>
          {people ? (
            <div className="field">
              <span>{t('Mitglieder')}</span>
              <Picker
                label={t('Mitglieder')}
                choices={people.map((person) => ({
                  id: person.id,
                  label: person.displayName,
                  sub: person.username,
                  avatar: person.avatar,
                }))}
                picked={members}
                onChange={setMembers}
              />
            </div>
          ) : (
            <p className="field-hint">
              {t('In der Gruppe sind {n} Personen. Wer dazugehört, ändert ein Admin.', {
                n: group.members,
              })}
            </p>
          )}
        </div>
      )}
    </Modal>
  );
}
