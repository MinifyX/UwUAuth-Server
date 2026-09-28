import { t, useLanguage } from '../lib/i18n';
import type { AttributeDef } from '../lib/types';

/** One extra field an admin defined: text, a number, a date or one of a few choices. */
export function AttributeInput({
  def,
  value,
  onChange,
  disabled,
}: {
  def: AttributeDef;
  value: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  useLanguage();
  return (
    <label className="field">
      <span>{def.label || def.name}</span>
      {def.kind === 'choice' ? (
        <select value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled}>
          <option value="">{t('– nichts –')}</option>
          {def.choices.map((choice) => (
            <option key={choice} value={choice}>
              {choice}
            </option>
          ))}
        </select>
      ) : (
        <input
          type={def.kind === 'number' ? 'number' : def.kind === 'date' ? 'date' : 'text'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={disabled}
        />
      )}
    </label>
  );
}
