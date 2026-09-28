import { useState } from 'react';
import { clock, minutes, WEEKDAYS, windowsText, WORKDAYS } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import type { Window } from '../lib/types';
import { useAction } from './controls';
import { Icon } from './Icon';

type Draft = { days: number; start: string; end: string; app: string | null };

const toDraft = (window: Window): Draft => ({
  days: window.days,
  start: clock(window.start),
  end: clock(window.end % 1440),
  app: window.app ?? null,
});

/**
 * When somebody may sign in: rows of weekdays and a time from–to, each for every app or for one.
 * No rows means any time. The sentence under the rows says what the rows mean, so nobody has to
 * read the toggles.
 *
 * `apps` are the apps a row can be for; without them (a page that cannot list apps), a row keeps
 * whatever app it had.
 */
export function WindowsEditor({
  windows,
  onSave,
  disabled,
  apps,
}: {
  windows: Window[];
  onSave: (windows: Window[]) => Promise<void>;
  disabled?: boolean;
  apps?: { id: string; name: string }[];
}) {
  useLanguage();
  const [rows, setRows] = useState<Draft[]>(() => windows.map(toDraft));
  const [run, busy] = useAction();

  const parsed = rows.map((row) => ({
    days: row.days,
    start: minutes(row.start),
    end: minutes(row.end, true),
    app: row.app,
  }));
  const valid = parsed.every(
    (row) => row.days > 0 && row.start !== null && row.end !== null && row.start !== row.end,
  );
  const result: Window[] = valid
    ? parsed.map((row) => ({ days: row.days, start: row.start!, end: row.end!, app: row.app }))
    : [];
  const appName = (id: string) => apps?.find((app) => app.id === id)?.name ?? t('eine App');
  const dirty = JSON.stringify(rows) !== JSON.stringify(windows.map(toDraft));

  const change = (index: number, patch: Partial<Draft>) =>
    setRows(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));

  return (
    <div className="windows-editor">
      {rows.map((row, index) => (
        <div className="window-row" key={index}>
          <div className="day-toggles" role="group" aria-label={t('Tage')}>
            {WEEKDAYS.map((name, bit) => (
              <button
                key={name}
                type="button"
                className="day-toggle"
                aria-pressed={(row.days & (1 << bit)) !== 0}
                disabled={disabled}
                onClick={() => change(index, { days: row.days ^ (1 << bit) })}
              >
                {t(name)}
              </button>
            ))}
          </div>
          <div className="window-times">
            <label className="time-field">
              <span>{t('von')}</span>
              <input
                type="time"
                value={row.start}
                disabled={disabled}
                onChange={(e) => change(index, { start: e.target.value })}
              />
            </label>
            <label className="time-field">
              <span>{t('bis')}</span>
              <input
                type="time"
                value={row.end}
                disabled={disabled}
                onChange={(e) => change(index, { end: e.target.value })}
              />
            </label>
            {(apps?.length || row.app) && (
              <label className="time-field">
                <span>{t('für')}</span>
                <select
                  aria-label={t('Für welche App?')}
                  value={row.app ?? ''}
                  disabled={disabled || !apps?.length}
                  onChange={(e) => change(index, { app: e.target.value || null })}
                >
                  <option value="">{t('alle Apps')}</option>
                  {row.app && !apps?.some((app) => app.id === row.app) && (
                    <option value={row.app}>{appName(row.app)}</option>
                  )}
                  {apps?.map((app) => (
                    <option key={app.id} value={app.id}>
                      {app.name}
                    </option>
                  ))}
                </select>
              </label>
            )}
            <button
              type="button"
              className="icon-button"
              aria-label={t('Zeitfenster entfernen')}
              title={t('Zeitfenster entfernen')}
              disabled={disabled}
              onClick={() => setRows(rows.filter((_, i) => i !== index))}
            >
              <Icon name="close" />
            </button>
          </div>
        </div>
      ))}
      <p className="windows-summary" data-invalid={!valid || undefined}>
        {valid
          ? windowsText(result, appName)
          : t('Jedes Zeitfenster braucht mindestens einen Tag und zwei verschiedene Uhrzeiten.')}
      </p>
      {!disabled && (
        <div className="form-actions">
          <button
            type="button"
            onClick={() =>
              setRows([...rows, { days: WORKDAYS, start: '07:00', end: '20:00', app: null }])
            }
          >
            <Icon name="plus" />
            {t('Zeitfenster hinzufügen')}
          </button>
          <span className="spacer" />
          {dirty && (
            <button type="button" data-secondary onClick={() => setRows(windows.map(toDraft))}>
              {t('Verwerfen')}
            </button>
          )}
          <button
            type="button"
            className="primary"
            disabled={!dirty || !valid || busy}
            onClick={() => void run(() => onSave(result))}
          >
            {t('Speichern')}
          </button>
        </div>
      )}
    </div>
  );
}
