import { useEffect, useState } from 'react';
import { Loading } from '../components/bits';
import { api, seg } from '../lib/api';
import { useLanguage } from '../lib/i18n';
import { go } from '../lib/route';
import type { GroupDetail, Me, PersonDetail as Detail } from '../lib/types';
import { word } from '../lib/words';
import { PeopleList } from '../people/PeopleList';
import { PersonDetail } from '../people/PersonDetail';

/** For parents and team leads: the people they look after, without the admin portal. */
export function MyPeople({ me, id }: { me: Me; id: string | null }) {
  useLanguage();
  // An admin's people list is everybody; here it should be only whom they look after.
  const [only, setOnly] = useState<Set<string> | null | undefined>(me.admin ? undefined : null);
  useEffect(() => {
    if (!me.admin) return;
    (async () => {
      const self = await api<Detail>(`/uwu/v1/people/${seg(me.id)}`);
      const ids = new Set(self.manages.people);
      for (const group of self.manages.groups) {
        const detail = await api<GroupDetail>(`/uwu/v1/groups/${seg(group)}`);
        for (const person of detail.everybody) ids.add(person);
      }
      ids.delete(me.id);
      setOnly(ids);
    })().catch(() => setOnly(null));
  }, [me.admin, me.id]);

  if (id) return <PersonDetail key={id} id={id} me={me} onBack={() => go('/people')} />;
  if (only === undefined) return <Loading />;
  return (
    <PeopleList
      me={{ ...me, admin: false }}
      only={only}
      title={word(me.server.mode, 'myPeople')}
      onOpen={(person) => go(`/people/${person}`)}
      // What a manager makes, the server hands to them; what an admin makes, it does not.
      afterCreate={
        me.admin
          ? (person) =>
              api(`/uwu/v1/people/${seg(person)}/managers`, {
                method: 'PUT',
                body: { managers: [me.id] },
              }).then(() => setOnly((ids) => new Set([...(ids ?? []), person])))
          : undefined
      }
    />
  );
}
