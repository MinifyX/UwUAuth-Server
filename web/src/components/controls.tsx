import { useState, type ReactNode } from 'react';
import { errorText } from '../lib/errors';
import { toast } from '../lib/toast';

/** One setting: a label, an optional explanation and its control. */
export function Row({
  label,
  description,
  children,
}: {
  label: ReactNode;
  description?: ReactNode;
  children?: ReactNode;
}) {
  return (
    <div className="setting-row">
      <div className="setting-text">
        <p className="setting-label">{label}</p>
        {description && <div className="setting-description">{description}</div>}
      </div>
      {children && <div className="setting-control">{children}</div>}
    </div>
  );
}

export function Segmented<T extends string | number>({
  label,
  value,
  options,
  onChange,
  wide,
}: {
  label: string;
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
  wide?: boolean;
}) {
  return (
    <div className={wide ? 'segmented wide' : 'segmented'} role="radiogroup" aria-label={label}>
      {options.map((option) => (
        <button
          key={String(option.value)}
          type="button"
          role="radio"
          aria-checked={option.value === value}
          onClick={() => onChange(option.value)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function Toggle({
  label,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      className="toggle"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
    >
      <span className="toggle-thumb" />
    </button>
  );
}

export type Result = { tone: 'info' | 'error'; text: string } | null;

export function ResultLine({ result }: { result: Result }) {
  if (!result) return null;
  return (
    <p className="setting-result" data-tone={result.tone} role="status">
      {result.text}
    </p>
  );
}

export function FormError({ error }: { error: string | null }) {
  if (!error) return null;
  return (
    <p className="form-error" role="alert">
      {error}
    </p>
  );
}

/**
 * Something that runs on a click: busy while it runs, and what went wrong as a toast. Returns
 * the runner and whether one is running, so a button can say so.
 */
export function useAction(): [(work: () => Promise<unknown>) => Promise<boolean>, boolean] {
  const [busy, setBusy] = useState(false);
  const run = async (work: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await work();
      return true;
    } catch (error) {
      toast(errorText(error), 'error');
      return false;
    } finally {
      setBusy(false);
    }
  };
  return [run, busy];
}

/** A section of a page: a heading, a line on what it is for, and its content in a card. */
export function Section({
  title,
  lead,
  actions,
  children,
  id,
}: {
  title: string;
  lead?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  id?: string;
}) {
  return (
    <section className="section" id={id}>
      <div className="section-head">
        <h2 className="section-title">{title}</h2>
        {actions && <div className="section-actions">{actions}</div>}
      </div>
      {lead && <p className="section-lead">{lead}</p>}
      {children && <div className="card">{children}</div>}
    </section>
  );
}
