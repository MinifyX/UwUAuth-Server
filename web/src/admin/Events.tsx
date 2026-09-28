import { useEffect, useState } from 'react';
import { EventList } from '../components/EventList';
import { PageTitle } from '../components/Shell';
import { api } from '../lib/api';
import { EVENT_FILTERS } from '../lib/events';
import { t, useLanguage } from '../lib/i18n';
import type { Person } from '../lib/types';

/** Everything that happened on the server, as sentences, the newest first. */
export function Events() {
  useLanguage();
  const [kind, setKind] = useState('');
  const [person, setPerson] = useState('');
  const [people, setPeople] = useState<Person[]>([]);
  useEffect(() => {
    Promise.all([api<Person[]>('/uwu/v1/people'), api<Person[]>('/uwu/v1/people?trash=true')]).then(
      ([alive, trashed]) => setPeople([...alive, ...trashed]),
      () => undefined,
    );
  }, []);
  const query = new URLSearchParams();
  if (kind) query.set('kind', kind);
  if (person) query.set('person', person);
  const names = (id: string | null) =>
    people.find((other) => other.id === id)?.displayName ?? t('jemand Gelöschtes');

  return (
    <>
      <PageTitle>{t('Ereignisse')}</PageTitle>
      <div className="list-tools">
        <select
          className="select"
          value={kind}
          onChange={(e) => setKind(e.target.value)}
          aria-label={t('Art')}
        >
          {EVENT_FILTERS.map((filter) => (
            <option key={filter.value} value={filter.value}>
              {t(filter.label)}
            </option>
          ))}
        </select>
        <select
          className="select"
          value={person}
          onChange={(e) => setPerson(e.target.value)}
          aria-label={t('Person')}
        >
          <option value="">{t('Alle Personen')}</option>
          {[...people]
            .sort((a, b) => a.displayName.localeCompare(b.displayName))
            .map((other) => (
              <option key={other.id} value={other.id}>
                {other.displayName}
              </option>
            ))}
        </select>
      </div>
      <div className="card">
        <EventList
          key={query.toString()}
          path={`/uwu/v1/events?${query}`}
          names={names}
          pageSize={200}
        />
      </div>
    </>
  );
}
