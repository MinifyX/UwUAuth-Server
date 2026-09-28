/**
 * Where on the page we are, from the part after `#`: `#/invite?token=…` is the link from an
 * invitation mail, `#/security` a page of the portal. Both the portal at `/` and the admin
 * portal at `/admin` route this way, so the server only ever has to serve one page.
 */

import { useSyncExternalStore } from 'react';

export type Route = { path: string; query: URLSearchParams };

export function parseRoute(hash: string): Route {
  const [path = '', query = ''] = hash.replace(/^#/, '').split('?');
  return { path: path || '/', query: new URLSearchParams(query) };
}

let current = parseRoute(typeof location === 'undefined' ? '' : location.hash);
const listeners = new Set<() => void>();

if (typeof window !== 'undefined') {
  window.addEventListener('hashchange', () => {
    current = parseRoute(location.hash);
    for (const listener of listeners) listener();
  });
}

export function useRoute(): Route {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}

export function go(path: string) {
  location.hash = path;
}

/**
 * Where to go after signing in, from `?continue=`: only a path on this server under `/oauth/`
 * (where OpenID Connect sends people to sign in first). Anything else — another site, `//host`,
 * a script URL — is ignored, so a link can never send somebody somewhere else after they
 * signed in.
 */
export function continueTarget(value: string | null): string | null {
  if (!value) return null;
  if (!value.startsWith('/oauth/') || value.startsWith('//') || value.includes('\\')) return null;
  try {
    const url = new URL(value, 'http://uwuauth.invalid');
    if (url.origin !== 'http://uwuauth.invalid' || !url.pathname.startsWith('/oauth/')) return null;
    return url.pathname + url.search + url.hash;
  } catch {
    return null;
  }
}
