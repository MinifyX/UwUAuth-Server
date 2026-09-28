/**
 * The web app in German or English.
 *
 * German is the source language: every string is written in German where it is used and wrapped
 * in `t()`, and the English catalogue in `src/i18n/en/` maps each German string to its English
 * one. A string without an English entry stays German; `pnpm lint` runs
 * `scripts/check-i18n.mjs`, which lists every one that is missing.
 *
 * Placeholders are `{name}`, filled from `vars`. Strings kept in module-level constants are
 * marked with `N_()` — which does nothing but lets the check find them — and translated with
 * `t()` where they are shown.
 *
 * Which language: the signed-in person's own (from `/uwu/v1/me`), and before anybody signs in,
 * whatever the browser prefers. A component that shows text calls `useLanguage()`, so it draws
 * again when the language changes.
 */

import { useSyncExternalStore } from 'react';
import { EN } from '../i18n/en';

export type Language = 'de' | 'en';

export type Vars = Record<string, string | number>;

/** German for whoever's browser prefers it, English for everybody else. */
export function pickLanguage(preferred: readonly string[]): Language {
  for (const tag of preferred) {
    const base = tag.toLowerCase().split('-')[0];
    if (base === 'de' || base === 'en') return base;
  }
  return 'en';
}

function browserLanguage(): Language {
  if (typeof navigator === 'undefined') return 'de';
  return pickLanguage(navigator.languages?.length ? navigator.languages : [navigator.language]);
}

let current: Language = browserLanguage();
const listeners = new Set<() => void>();

export function language(): Language {
  return current;
}

/** Switch the whole page; `null` goes back to the browser's choice. */
export function setLanguage(next: string | null) {
  const resolved: Language = next === null ? browserLanguage() : next === 'en' ? 'en' : 'de';
  if (resolved === current) return;
  current = resolved;
  if (typeof document !== 'undefined') document.documentElement.lang = resolved;
  for (const listener of listeners) listener();
}

function fill(template: string, vars?: Vars): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (whole, name: string) =>
    name in vars ? String(vars[name]) : whole,
  );
}

export function translate(lang: Language, text: string, vars?: Vars): string {
  return fill(lang === 'en' ? (EN[text] ?? text) : text, vars);
}

/** `text` (German) in the current language, placeholders filled. */
export function t(text: string, vars?: Vars): string {
  return translate(current, text, vars);
}

/** Marks a German string kept in a constant for translation where it is shown. */
export function N_(text: string): string {
  return text;
}

/** The current language; the calling component draws again when it changes. */
export function useLanguage(): Language {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}

/** For dates and numbers. */
export function locale(lang: Language = current): string {
  return lang === 'de' ? 'de-DE' : 'en-GB';
}
