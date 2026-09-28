/**
 * Passkeys in the browser. The server sends WebAuthn options as JSON with the bytes in base64url;
 * `navigator.credentials` wants them as ArrayBuffers, and what it answers goes back as JSON with
 * base64url again. Newer browsers do both conversions themselves (`parse…FromJSON`, `toJSON`);
 * for the others the small converters here do it.
 */

type Json = Record<string, unknown>;

export function toBase64Url(bytes: ArrayBuffer | Uint8Array): string {
  const array = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let text = '';
  for (const byte of array) text += String.fromCharCode(byte);
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(text: string): Uint8Array<ArrayBuffer> {
  const plain = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = plain + '='.repeat((4 - (plain.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

/** Whether this browser can do passkeys at all. */
export function available(): boolean {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function';
}

/** Whether the browser offers passkeys right in the name field's suggestions. */
export async function autofillAvailable(): Promise<boolean> {
  if (!available()) return false;
  const check = (
    PublicKeyCredential as unknown as { isConditionalMediationAvailable?: () => Promise<boolean> }
  ).isConditionalMediationAvailable;
  try {
    return Boolean(check && (await check.call(PublicKeyCredential)));
  } catch {
    return false;
  }
}

const list = (value: unknown): Json[] => (Array.isArray(value) ? (value as Json[]) : []);

/** Options for `create()`, from the server's JSON. */
export function creationOptions(json: Json): PublicKeyCredentialCreationOptions {
  const user = json.user as Json;
  return {
    rp: json.rp as PublicKeyCredentialRpEntity,
    user: {
      id: fromBase64Url(String(user.id)),
      name: String(user.name),
      displayName: String(user.displayName ?? user.name),
    },
    challenge: fromBase64Url(String(json.challenge)),
    pubKeyCredParams: json.pubKeyCredParams as PublicKeyCredentialParameters[],
    timeout: Number(json.timeout ?? 300_000),
    attestation: 'none',
    authenticatorSelection: json.authenticatorSelection as AuthenticatorSelectionCriteria,
    excludeCredentials: list(json.excludeCredentials).map((entry) => ({
      type: 'public-key',
      id: fromBase64Url(String(entry.id)),
    })),
    extensions: json.extensions as AuthenticationExtensionsClientInputs | undefined,
  };
}

/**
 * Options for `get()`, from the server's JSON. User verification is always asked for: the server
 * only takes answers where the device checked who is there (PIN, fingerprint, face), also for a
 * second step, where its options say "discouraged".
 */
export function requestOptions(json: Json): PublicKeyCredentialRequestOptions {
  return {
    challenge: fromBase64Url(String(json.challenge)),
    timeout: Number(json.timeout ?? 300_000),
    rpId: json.rpId as string | undefined,
    allowCredentials: list(json.allowCredentials).map((entry) => ({
      type: 'public-key',
      id: fromBase64Url(String(entry.id)),
    })),
    userVerification: 'required',
  };
}

/** A new passkey as the server takes it. */
export function attestationJson(credential: {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  response: { attestationObject: ArrayBuffer; clientDataJSON: ArrayBuffer };
}): Json {
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: toBase64Url(credential.response.attestationObject),
      clientDataJSON: toBase64Url(credential.response.clientDataJSON),
    },
  };
}

/** A passkey's answer as the server takes it. */
export function assertionJson(credential: {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  response: {
    authenticatorData: ArrayBuffer;
    clientDataJSON: ArrayBuffer;
    signature: ArrayBuffer;
    userHandle: ArrayBuffer | null;
  };
}): Json {
  const { response } = credential;
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: toBase64Url(response.authenticatorData),
      clientDataJSON: toBase64Url(response.clientDataJSON),
      signature: toBase64Url(response.signature),
      userHandle: response.userHandle ? toBase64Url(response.userHandle) : null,
    },
  };
}

type Parsers = {
  parseCreationOptionsFromJSON?: (json: Json) => PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON?: (json: Json) => PublicKeyCredentialRequestOptions;
};

function parsers(): Parsers {
  return PublicKeyCredential as unknown as Parsers;
}

/** Make a passkey with the server's creation options; the answer as JSON for the server. */
export async function createPasskey(json: Json): Promise<Json> {
  let options: PublicKeyCredentialCreationOptions;
  try {
    options = parsers().parseCreationOptionsFromJSON?.(json) ?? creationOptions(json);
  } catch {
    options = creationOptions(json);
  }
  const credential = (await navigator.credentials.create({
    publicKey: options,
  })) as PublicKeyCredential | null;
  if (!credential) throw new DOMException('No passkey.', 'NotAllowedError');
  return attestationJson(credential as unknown as Parameters<typeof attestationJson>[0]);
}

/**
 * Sign in or confirm with a passkey. With `conditional`, the browser offers it in the name
 * field's suggestions instead of opening a dialog, until `signal` aborts.
 */
export async function getPasskey(json: Json, conditional?: { signal: AbortSignal }): Promise<Json> {
  let options: PublicKeyCredentialRequestOptions;
  try {
    options = parsers().parseRequestOptionsFromJSON?.(json) ?? requestOptions(json);
  } catch {
    options = requestOptions(json);
  }
  options.userVerification = 'required';
  const credential = (await navigator.credentials.get({
    publicKey: options,
    ...(conditional ? { mediation: 'conditional' as CredentialMediationRequirement } : {}),
    signal: conditional?.signal,
  })) as PublicKeyCredential | null;
  if (!credential) throw new DOMException('No passkey.', 'NotAllowedError');
  return assertionJson(credential as unknown as Parameters<typeof assertionJson>[0]);
}

/** A name for a new passkey, from the device it is made on: "iPhone", "Windows", … */
export function deviceName(agent: string): string {
  if (/iPhone/.test(agent)) return 'iPhone';
  if (/iPad/.test(agent)) return 'iPad';
  if (/Android/.test(agent)) return 'Android';
  if (/CrOS/.test(agent)) return 'Chromebook';
  if (/Mac OS X|Macintosh/.test(agent)) return 'Mac';
  if (/Windows/.test(agent)) return 'Windows';
  if (/Linux/.test(agent)) return 'Linux';
  return 'Passkey';
}
