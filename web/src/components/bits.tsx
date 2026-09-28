/** Small pieces several pages share: pictures, empty states, secrets shown once, links as QR codes. */

import { type ReactNode } from 'react';
import { saveFile } from '../lib/api';
import { copy } from '../lib/clipboard';
import { ago, day, when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { Icon } from './Icon';
import { NyuScene, type SceneName } from './nyu/scenes';
import { Qr } from './Qr';

/** Initials for somebody without a picture: "Mia Maus" → "MM". */
export function initials(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  const letters = words.length > 1 ? [words[0]!, words[words.length - 1]!] : words;
  return (
    letters
      .map((word) => [...word][0] ?? '')
      .join('')
      .toUpperCase() || '?'
  );
}

/** A person's picture, or their initials on a tint. */
export function Avatar({
  name,
  src,
  size = 36,
}: {
  name: string;
  src: string | null | undefined;
  size?: number;
}) {
  return (
    <span className="avatar" style={{ width: size, height: size, fontSize: size * 0.38 }}>
      {src ? <img src={src} alt="" width={size} height={size} /> : initials(name)}
    </span>
  );
}

/** Nyu and a line or two, where a list is empty. */
export function Empty({
  scene = 'sleepy',
  title,
  children,
}: {
  scene?: SceneName;
  title?: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      <NyuScene name={scene} className="empty-scene" />
      {title && <p className="empty-title">{title}</p>}
      {children && <div className="empty-text">{children}</div>}
    </div>
  );
}

/** A secret shown once: big, selectable, with copy and (optionally) download as a text file. */
export function SecretOnce({
  value,
  shown,
  file,
}: {
  value: string;
  /** How to show it, when that differs from what is copied (groups of four). */
  shown?: string;
  file?: { name: string; text: string };
}) {
  useLanguage();
  return (
    <div className="secret-once">
      <code className="secret-key big">{shown ?? value}</code>
      <div className="form-actions">
        <button type="button" onClick={() => void copy(file?.text ?? value)}>
          <Icon name="copy" />
          {t('Kopieren')}
        </button>
        {file && (
          <button
            type="button"
            onClick={() => saveFile(new Blob([file.text], { type: 'text/plain' }), file.name)}
          >
            <Icon name="download" />
            {t('Als Textdatei speichern')}
          </button>
        )}
      </div>
    </div>
  );
}

/**
 * A link to pass on — an invitation, a setup link: a big QR code to scan with the other device,
 * the link itself to copy, and until when it works.
 */
export function LinkShare({
  link,
  expires,
  mailed,
  lead,
}: {
  link: string;
  expires: string;
  mailed?: string | null;
  lead?: ReactNode;
}) {
  useLanguage();
  return (
    <div className="link-share">
      {lead && <p className="dialog-lead">{lead}</p>}
      {mailed && (
        <p className="notice-line">
          <Icon name="mail" />
          {t('Die Mail an {email} ist unterwegs.', { email: mailed })}
        </p>
      )}
      <Qr value={link} size="big" label={t('QR-Code für den Link')} />
      <div className="copy-field">
        <code>{link}</code>
        <button type="button" onClick={() => void copy(link)} data-autofocus>
          <Icon name="copy" />
          {t('Kopieren')}
        </button>
      </div>
      <p className="field-hint">{t('Funktioniert einmal, bis {when}.', { when: when(expires) })}</p>
    </div>
  );
}

/** "zuletzt vor 3 Std." with the exact time on hover. */
export function Ago({ iso, prefix }: { iso: string | null | undefined; prefix?: string }) {
  useLanguage();
  const text = ago(iso);
  return <span title={iso ? when(iso) : undefined}>{prefix ? `${prefix} ${text}` : text}</span>;
}

export function Day({ iso }: { iso: string | null | undefined }) {
  useLanguage();
  return <span title={iso ? when(iso) : undefined}>{day(iso)}</span>;
}

/** A small label next to a name. */
export function Badge({ children, tone }: { children: ReactNode; tone?: 'alarm' | 'ok' }) {
  return <span className={tone ? `badge ${tone}` : 'badge'}>{children}</span>;
}

/** A little spinner-free "loading": nothing flashes for fast answers. */
export function Loading() {
  useLanguage();
  return (
    <p className="loading" aria-live="polite">
      {t('Lädt …')}
    </p>
  );
}

/** A value to copy — a client ID, an address: shown whole, with a button. */
export function CopyField({ value, label }: { value: string; label: string }) {
  useLanguage();
  return (
    <div className="copy-field">
      <code>{value}</code>
      <button
        type="button"
        onClick={() => void copy(value)}
        aria-label={t('{what} kopieren', { what: label })}
        title={t('{what} kopieren', { what: label })}
      >
        <Icon name="copy" />
        <span className="copy-label">{t('Kopieren')}</span>
      </button>
    </div>
  );
}
