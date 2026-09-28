/**
 * Talking to the server: `/uwu/v1/…` on this page's origin. The session is a cookie the page
 * never sees, so every request just goes out with `credentials: 'same-origin'`; the server checks
 * the `Origin` header the browser adds to every request that changes something.
 *
 * Two answers are handled here once, for every page:
 *
 * - `reauth` (403): changing how one signs in needs a recent proof of who one is. The dialog in
 *   `ReauthHost` asks for it, and the request goes out again by itself.
 * - `unauthorized` (401) on a signed-in page, and a restricted session: the app hears about it
 *   through `onSessionChange` and draws the sign-in or the "second factor first" screen.
 */

import { askToConfirm } from './reauth';

export class ApiError extends Error {
  status: number;
  code: string;
  detail: Record<string, unknown> | null;
  constructor(status: number, code: string, message: string, detail?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.detail = detail && typeof detail === 'object' ? (detail as Record<string, unknown>) : null;
  }
}

type Options = {
  method?: string;
  /** JSON, unless it is a Blob or a string with `contentType`. */
  body?: unknown;
  contentType?: string;
  /** Pages before sign-in: a 401 there is an answer, not a lost session. */
  anonymous?: boolean;
  /** The confirming itself must not ask to confirm. */
  noReauth?: boolean;
};

type SessionChange = 'ended' | 'restricted';
const sessionListeners = new Set<(change: SessionChange) => void>();

/** Hear when the session ends or turns out to be restricted. */
export function onSessionChange(listener: (change: SessionChange) => void): () => void {
  sessionListeners.add(listener);
  return () => sessionListeners.delete(listener);
}

async function parse(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

async function send(path: string, options: Options): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  let body: BodyInit | undefined;
  if (options.body instanceof Blob) {
    body = options.body;
    headers['Content-Type'] = options.contentType ?? options.body.type;
  } else if (typeof options.body === 'string' && options.contentType) {
    body = options.body;
    headers['Content-Type'] = options.contentType;
  } else if (options.body !== undefined) {
    body = JSON.stringify(options.body);
    headers['Content-Type'] = 'application/json';
  }
  try {
    return await fetch(path, {
      method: options.method ?? (body !== undefined ? 'POST' : 'GET'),
      headers,
      body,
      credentials: 'same-origin',
    });
  } catch {
    throw new ApiError(0, 'network', 'The server does not answer.');
  }
}

async function failure(response: Response, options: Options): Promise<ApiError> {
  const body = (await parse(response)) as Record<string, unknown> | string | null;
  const value = body && typeof body === 'object' ? body : {};
  const code = typeof value.error === 'string' ? value.error : `http_${response.status}`;
  const message =
    typeof value.message === 'string'
      ? value.message
      : `The server answered with HTTP ${response.status}.`;
  const error = new ApiError(response.status, code, message, value.detail);
  if (!options.anonymous) {
    if (response.status === 401 && code === 'unauthorized') {
      for (const listener of sessionListeners) listener('ended');
    } else if (error.detail?.restricted === true) {
      for (const listener of sessionListeners) listener('restricted');
    }
  }
  return error;
}

/** A request with a recent proof of who one is, asked for once when the server wants one. */
async function respond(path: string, options: Options): Promise<Response> {
  let response = await send(path, options);
  if (response.status === 403 && !options.noReauth) {
    const peek = response.clone();
    const body = (await parse(peek)) as Record<string, unknown> | null;
    if (body && body.error === 'reauth') {
      await askToConfirm();
      response = await send(path, options);
    }
  }
  if (!response.ok) throw await failure(response, options);
  return response;
}

/** A request; the answer's JSON (or null). Throws `ApiError` for anything but 2xx. */
export async function api<T = unknown>(path: string, options: Options = {}): Promise<T> {
  const response = await respond(path, options);
  return (await parse(response)) as T;
}

/** A file from the server, for downloads: backups, exports. */
export async function apiBlob(path: string, options: Options = {}): Promise<Blob> {
  const response = await respond(path, options);
  return response.blob();
}

/** A file to the downloads folder. */
export function saveFile(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Path segments are ids and tokens from the server; still, never build a path from raw text. */
export const seg = (value: string) => encodeURIComponent(value);
