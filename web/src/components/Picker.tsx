import { useState } from 'react';
import { t, useLanguage } from '../lib/i18n';
import { Avatar } from './bits';
import { Icon } from './Icon';

export type Choice = {
  id: string;
  label: string;
  sub?: string;
  /** A picture for people; groups get an icon. */
  avatar?: string | null;
  kind?: 'person' | 'group';
};

/**
 * Pick several: what is picked stands on top as chips (a click takes one away), and a search
 * finds the rest. Long lists stay short on screen — the search is how one gets further.
 */
export function Picker({
  choices,
  picked,
  onChange,
  label,
  disabled,
  empty,
}: {
  choices: Choice[];
  picked: string[];
  onChange: (picked: string[]) => void;
  label: string;
  disabled?: boolean;
  empty?: string;
}) {
  useLanguage();
  const [search, setSearch] = useState('');
  const words = search.trim().toLowerCase();
  const byId = new Map(choices.map((choice) => [choice.id, choice]));
  const open = choices.filter(
    (choice) =>
      !picked.includes(choice.id) &&
      (!words || `${choice.label} ${choice.sub ?? ''}`.toLowerCase().includes(words)),
  );
  const shown = open.slice(0, words ? 30 : 8);
  return (
    <div className="picker" aria-label={label} role="group">
      <div className="chips">
        {picked.map((id) => {
          const choice = byId.get(id);
          return (
            <button
              key={id}
              type="button"
              className="chip"
              disabled={disabled}
              title={t('Entfernen')}
              onClick={() => onChange(picked.filter((other) => other !== id))}
            >
              {choice?.kind === 'group' ? (
                <Icon name="users" size={14} />
              ) : (
                <Avatar name={choice?.label ?? '?'} src={choice?.avatar} size={20} />
              )}
              <span>{choice?.label ?? t('Unbekannt')}</span>
              {!disabled && <Icon name="close" size={12} />}
            </button>
          );
        })}
        {picked.length === 0 && <span className="muted">{empty ?? t('Noch niemand.')}</span>}
      </div>
      {!disabled && choices.length > picked.length && (
        <>
          <input
            className="search"
            type="search"
            placeholder={t('Suchen …')}
            value={search}
            aria-label={t('{what} suchen', { what: label })}
            onChange={(e) => setSearch(e.target.value)}
          />
          <ul className="picker-list">
            {shown.map((choice) => (
              <li key={choice.id}>
                <button
                  type="button"
                  className="picker-option"
                  onClick={() => onChange([...picked, choice.id])}
                >
                  {choice.kind === 'group' ? (
                    <span className="picker-icon">
                      <Icon name="users" />
                    </span>
                  ) : (
                    <Avatar name={choice.label} src={choice.avatar} size={24} />
                  )}
                  <span className="picker-text">
                    <b>{choice.label}</b>
                    {choice.sub && <small>{choice.sub}</small>}
                  </span>
                  <Icon name="plus" />
                </button>
              </li>
            ))}
            {open.length > shown.length && (
              <li className="picker-more">
                {t('… und {n} weitere. Such nach dem Namen.', { n: open.length - shown.length })}
              </li>
            )}
            {open.length === 0 && <li className="picker-more">{t('Nichts gefunden.')}</li>}
          </ul>
        </>
      )}
    </div>
  );
}
