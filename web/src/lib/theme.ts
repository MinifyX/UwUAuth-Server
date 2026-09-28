/**
 * Light or dark. Follows the system unless the person picks one in their profile; the choice is
 * kept in this browser only, like any other preference that is not worth a round trip.
 */

import { useSyncExternalStore } from 'react';

export type Theme = 'system' | 'light' | 'dark';

const KEY = 'uwuauth.theme';

function load(): Theme {
  try {
    const value = window.localStorage.getItem(KEY);
    return value === 'light' || value === 'dark' ? value : 'system';
  } catch {
    return 'system';
  }
}

let current: Theme = load();
const listeners = new Set<() => void>();
const darkQuery = () => window.matchMedia('(prefers-color-scheme: dark)');

function apply() {
  const dark = current === 'dark' || (current === 'system' && darkQuery().matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
}

export function setTheme(next: Theme) {
  current = next;
  try {
    if (next === 'system') window.localStorage.removeItem(KEY);
    else window.localStorage.setItem(KEY, next);
  } catch {
    // Private windows may refuse; the choice then lasts as long as the page.
  }
  apply();
  for (const listener of listeners) listener();
}

export function useTheme(): Theme {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}

/** Puts the theme on <html>, now and whenever the system switches. */
export function applyTheme() {
  apply();
  darkQuery().addEventListener('change', apply);
}
