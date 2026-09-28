import { useState } from 'react';
import { t, useLanguage } from '../lib/i18n';
import { Icon } from './Icon';

/**
 * A few addresses, one per row: the ones there with a button to take each away, and a field to
 * add another (Enter adds it too).
 */
export function UriList({
  label,
  values,
  onChange,
  placeholder,
  disabled,
}: {
  label: string;
  values: string[];
  onChange: (values: string[]) => void;
  placeholder?: string;
  disabled?: boolean;
}) {
  useLanguage();
  const [draft, setDraft] = useState('');
  const add = () => {
    const value = draft.trim();
    if (!value) return;
    if (!values.includes(value)) onChange([...values, value]);
    setDraft('');
  };
  return (
    <div className="uri-list" role="group" aria-label={label}>
      {values.map((value, index) => (
        <div className="uri-row" key={value}>
          <code>{value}</code>
          <button
            type="button"
            className="icon-button"
            aria-label={t('{what} entfernen', { what: value })}
            title={t('Entfernen')}
            disabled={disabled}
            onClick={() => onChange(values.filter((_, i) => i !== index))}
          >
            <Icon name="close" />
          </button>
        </div>
      ))}
      {!disabled && (
        <div className="inline-form">
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                add();
              }
            }}
            onBlur={add}
            placeholder={placeholder}
            aria-label={t('{what}: neue Adresse', { what: label })}
            autoCapitalize="none"
            spellCheck={false}
            inputMode="url"
          />
          <button type="button" onClick={add} disabled={!draft.trim()}>
            <Icon name="plus" />
            {t('Hinzufügen')}
          </button>
        </div>
      )}
    </div>
  );
}
