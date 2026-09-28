import { useCallback, useEffect, useState } from 'react';
import { Empty, Loading } from '../components/bits';
import { useAction } from '../components/controls';
import { Icon } from '../components/Icon';
import { PageTitle } from '../components/Shell';
import { api, apiBlob, saveFile, seg } from '../lib/api';
import { errorText } from '../lib/errors';
import { bytes } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import type { Backup } from '../lib/types';
import { backupTime } from './Overview';

/**
 * Every night and before every update the server writes a backup and keeps a week of them. Here
 * one can be written now or taken home — the whole directory, so it asks who you are first.
 */
export function Backups() {
  useLanguage();
  const [list, setList] = useState<Backup[] | null>(null);
  const [run, busy] = useAction();
  const load = useCallback(() => {
    api<Backup[]>('/uwu/v1/backups').then(setList, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(load, [load]);

  return (
    <>
      <PageTitle
        actions={
          <button
            type="button"
            className="primary"
            disabled={busy}
            onClick={() =>
              void run(async () => {
                await api('/uwu/v1/backups', { body: {} });
                toast(t('Backup geschrieben ✧'));
                load();
              })
            }
          >
            <Icon name="archive" />
            {busy ? t('Schreibt …') : t('Jetzt sichern')}
          </button>
        }
      >
        {t('Backups')}
      </PageTitle>
      <p className="muted page-lead">
        {t(
          'Backups liegen neben der Datenbank auf derselben Platte. Gegen eine kaputte Platte hilft nur eine Kopie woanders: Lade ab und zu eines herunter. Zurückspielen geht mit „uwuauth-server restore“ auf dem Server.',
        )}
      </p>
      {!list && <Loading />}
      {list?.length === 0 && (
        <Empty scene="sleepy">
          {t('Noch keine Backups. Das erste schreibt der Server in der ersten Nacht.')}
        </Empty>
      )}
      {list && list.length > 0 && (
        <ul className="item-list card">
          {list.map((backup) => (
            <li key={backup.name} className="item">
              <span className="item-icon">
                <Icon name="drive" />
              </span>
              <span className="item-text">
                <b>{backupTime(backup.time)}</b>
                <small>
                  {backup.name} · {bytes(backup.bytes)}
                </small>
              </span>
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    const blob = await apiBlob(`/uwu/v1/backups/${seg(backup.name)}`, {
                      method: 'POST',
                      body: {},
                    });
                    saveFile(blob, backup.name);
                  })
                }
              >
                <Icon name="download" />
                {t('Herunterladen')}
              </button>
            </li>
          ))}
        </ul>
      )}
      <p className="field-hint">
        {t(
          'Ein Backup enthält alles: Konten, Passwort-Hashes, Passkeys. Heb es so sicher auf wie einen Hausschlüssel.',
        )}
      </p>
    </>
  );
}
