/**
 * "Confirm that it's you", asked by the API layer and answered by `ReauthHost`. Requests that
 * need it at the same moment share one question: two failed requests open one dialog, and both
 * go out again once it is answered.
 */

import { useSyncExternalStore } from 'react';

type Pending = { resolve: () => void; reject: (error: Error) => void; promise: Promise<void> };

let pending: Pending | null = null;
const listeners = new Set<() => void>();

function changed() {
  for (const listener of listeners) listener();
}

/** Resolves once the person confirmed; rejects when they cancel. */
export function askToConfirm(): Promise<void> {
  if (pending) return pending.promise;
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  pending = { resolve, reject, promise };
  changed();
  return promise;
}

export function confirmed() {
  const done = pending;
  pending = null;
  changed();
  done?.resolve();
}

export class Cancelled extends Error {
  code = 'cancelled';
}

export function cancelled() {
  const done = pending;
  pending = null;
  changed();
  done?.reject(new Cancelled('Not confirmed.'));
}

export function useReauthAsked(): boolean {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => pending !== null,
  );
}
