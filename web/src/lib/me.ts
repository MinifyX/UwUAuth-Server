/**
 * Who is signed in: `/uwu/v1/me`, kept for every page, with the language switched to theirs.
 * `null` is "nobody"; `undefined` is "not asked yet".
 */

import { useSyncExternalStore } from 'react';
import { api, ApiError, onSessionChange } from './api';
import { setLanguage } from './i18n';
import type { Me } from './types';

let current: Me | null | undefined;
const listeners = new Set<() => void>();

function set(next: Me | null) {
  current = next;
  setLanguage(next ? next.language : null);
  for (const listener of listeners) listener();
}

/** Ask the server again; `null` when nobody is signed in. */
export async function reloadMe(): Promise<Me | null> {
  try {
    const me = await api<Me>('/uwu/v1/me', { anonymous: true });
    set(me);
    return me;
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      set(null);
      return null;
    }
    throw error;
  }
}

export function getMe(): Me | null | undefined {
  return current;
}

export function useMe(): Me | null | undefined {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}

/** Change a few fields here after the server took them, without asking it again. */
export function patchMe(change: Partial<Me>) {
  if (current) set({ ...current, ...change });
}

export async function signOut() {
  try {
    await api('/uwu/v1/logout', { method: 'POST', body: {}, anonymous: true });
  } finally {
    set(null);
  }
}

// A session that ended elsewhere (signed out everywhere, disabled, a new password) shows the
// sign-in again; a restricted one shows what has to be set up first.
onSessionChange((change) => {
  if (change === 'ended') set(null);
  else void reloadMe();
});
