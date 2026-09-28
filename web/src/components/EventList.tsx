import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api';
import { errorText } from '../lib/errors';
import { alarming, eventText, type Names } from '../lib/events';
import { when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import type { AuditEvent } from '../lib/types';
import { Ago } from './bits';

/**
 * What happened, newest first, as sentences; "older" fetches the next page. `path` is the
 * endpoint with its filters already in the query.
 */
export function EventList({
  path,
  names,
  pageSize = 100,
  showIp = true,
}: {
  path: string;
  names: Names;
  pageSize?: number;
  showIp?: boolean;
}) {
  useLanguage();
  const [list, setList] = useState<AuditEvent[] | null>(null);
  const [more, setMore] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    (before: number | null) => {
      const url = before ? `${path}${path.includes('?') ? '&' : '?'}before=${before}` : path;
      api<AuditEvent[]>(url).then(
        (page) => {
          setList((all) => (before && all ? [...all, ...page] : page));
          setMore(page.length >= pageSize);
          setError(null);
        },
        (e) => setError(errorText(e)),
      );
    },
    [path, pageSize],
  );
  useEffect(() => load(null), [load]);

  if (error) return <p className="form-error">{error}</p>;
  if (!list) return null;
  return (
    <>
      <ul className="event-list">
        {list.map((event) => (
          <li key={event.id} className="event" data-alarm={alarming(event.kind) || undefined}>
            <span className="event-text">{eventText(event, names)}</span>
            <small className="event-meta">
              <Ago iso={event.time} />
              {showIp && event.ip ? ` · ${event.ip}` : ''}
              <span className="sr-only"> {when(event.time)}</span>
            </small>
          </li>
        ))}
        {list.length === 0 && <li className="empty-note">{t('Noch nichts.')}</li>}
      </ul>
      {more && (
        <button
          type="button"
          className="load-more"
          onClick={() => load(list[list.length - 1]?.id ?? null)}
        >
          {t('Ältere laden')}
        </button>
      )}
    </>
  );
}
