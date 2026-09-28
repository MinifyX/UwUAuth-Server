/** Times, sizes, time windows and secrets, the way a person reads them. */

import { N_, locale, t } from './i18n';
import type { Window } from './types';

/** An ISO time from the server, as a local date and time. */
export function when(iso: string | null | undefined): string {
  if (!iso) return '–';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '–';
  return date.toLocaleString(locale(), { dateStyle: 'medium', timeStyle: 'short' });
}

/** Just the date. */
export function day(iso: string | null | undefined): string {
  if (!iso) return '–';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '–';
  return date.toLocaleDateString(locale(), { dateStyle: 'medium' });
}

/** "gerade eben", "vor 5 Min.", "vor 3 Std.", or the date. */
export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return t('noch nie');
  const at = Date.parse(iso);
  if (Number.isNaN(at)) return '–';
  const seconds = Math.max(0, (now - at) / 1000);
  if (seconds < 60) return t('gerade eben');
  if (seconds < 3600) return t('vor {n} Min.', { n: Math.round(seconds / 60) });
  if (seconds < 86400) return t('vor {n} Std.', { n: Math.round(seconds / 3600) });
  if (seconds < 7 * 86400) return t('vor {n} Tagen', { n: Math.round(seconds / 86400) });
  return day(iso);
}

/** "12 KiB", "3.4 MiB". */
export function bytes(count: number): string {
  if (count < 1024) return `${count} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = count / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toLocaleString(locale(), { maximumFractionDigits: value < 10 ? 1 : 0 })} ${units[unit]}`;
}

/** A secret to type by hand, in groups of four: "ABCD EFGH …". */
export function grouped(secret: string, size = 4): string {
  return (secret.match(new RegExp(`.{1,${size}}`, 'g')) ?? []).join(' ');
}

// ── Time windows ──────────────────────────────────────────

/** Monday first, as the bit mask counts: Monday 1, Tuesday 2, … Sunday 64. */
export const WEEKDAYS = [
  N_('Mo'),
  N_('Di'),
  N_('Mi'),
  N_('Do'),
  N_('Fr'),
  N_('Sa'),
  N_('So'),
] as const;

export const EVERY_DAY = 127;
export const WORKDAYS = 31;
export const WEEKEND = 96;

/** Minutes after midnight as "07:30"; 1440 is "24:00", the end of the day. */
export function clock(minutes: number): string {
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`;
}

/** "07:30" as minutes after midnight; "24:00" and "00:00" as an end are both the end of the day. */
export function minutes(text: string, end = false): number | null {
  const match = /^(\d{1,2}):(\d{2})$/.exec(text.trim());
  if (!match) return null;
  const h = Number(match[1]);
  const m = Number(match[2]);
  if (h > 24 || m > 59 || (h === 24 && m > 0)) return null;
  const total = h * 60 + m;
  if (end && total === 0) return 1440;
  return total;
}

/** The days of a mask, as a short text: "Mo–Fr", "Sa, So", "Mo, Mi, Fr", "täglich". */
export function daysText(mask: number): string {
  if ((mask & EVERY_DAY) === EVERY_DAY) return t('täglich');
  const on = WEEKDAYS.map((_, index) => (mask & (1 << index)) !== 0);
  const parts: string[] = [];
  let index = 0;
  while (index < 7) {
    if (!on[index]) {
      index += 1;
      continue;
    }
    let last = index;
    while (last + 1 < 7 && on[last + 1]) last += 1;
    const first = t(WEEKDAYS[index]!);
    if (last - index >= 2) parts.push(`${first}–${t(WEEKDAYS[last]!)}`);
    else if (last === index + 1) parts.push(first, t(WEEKDAYS[last]!));
    else parts.push(first);
    index = last + 1;
  }
  return parts.join(', ');
}

/** One window as a sentence part: "Mo–Fr 07:00–20:00". */
export function windowText(window: Window): string {
  return `${daysText(window.days)} ${clock(window.start)}–${clock(window.end)}`;
}

/** Every window, or that there are none: "Mo–Fr 07:00–20:00 · Sa, So 09:00–21:00". */
export function windowsText(windows: Window[], appName?: (id: string) => string): string {
  if (windows.length === 0) return t('Keine Zeitfenster: jederzeit.');
  return windows
    .map((window) =>
      window.app && appName
        ? `${windowText(window)} (${t('nur {app}', { app: appName(window.app) })})`
        : windowText(window),
    )
    .join(' · ');
}
