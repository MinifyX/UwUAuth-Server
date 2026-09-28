import { describe, expect, it } from 'vitest';
import {
  assertionJson,
  attestationJson,
  creationOptions,
  deviceName,
  fromBase64Url,
  requestOptions,
  toBase64Url,
} from './webauthn';

const bytes = (...values: number[]) => new Uint8Array(values);
const buffer = (...values: number[]) => bytes(...values).buffer;

describe('base64url', () => {
  it('goes both ways without padding and with the url alphabet', () => {
    const data = bytes(0xfb, 0xff, 0xfe, 0x01);
    expect(toBase64Url(data)).toBe('-__-AQ');
    expect([...fromBase64Url('-__-AQ')]).toEqual([...data]);
  });

  it('reads padded and plain base64 too', () => {
    expect([...fromBase64Url('+//+AQ==')]).toEqual([0xfb, 0xff, 0xfe, 0x01]);
    expect(toBase64Url(new Uint8Array())).toBe('');
  });
});

describe('options from the server', () => {
  it('turns the bytes of creation options into buffers and keeps the rest', () => {
    const options = creationOptions({
      rp: { id: 'auth.example.com', name: 'UwUAuth' },
      user: { id: 'AQID', name: 'mia', displayName: 'Mia' },
      challenge: 'BAUG',
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 1000,
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      excludeCredentials: [{ type: 'public-key', id: 'BwgJ' }],
    });
    expect([...new Uint8Array(options.user.id as ArrayBuffer)]).toEqual([1, 2, 3]);
    expect([...new Uint8Array(options.challenge as ArrayBuffer)]).toEqual([4, 5, 6]);
    expect([...new Uint8Array(options.excludeCredentials![0]!.id as ArrayBuffer)]).toEqual([
      7, 8, 9,
    ]);
    expect(options.user.displayName).toBe('Mia');
    expect(options.timeout).toBe(1000);
  });

  it('always asks the device to check who is there', () => {
    const options = requestOptions({
      challenge: 'AQID',
      rpId: 'auth.example.com',
      allowCredentials: [{ type: 'public-key', id: 'BAUG' }],
      userVerification: 'discouraged',
    });
    expect(options.userVerification).toBe('required');
    expect(options.rpId).toBe('auth.example.com');
    expect([...new Uint8Array(options.allowCredentials![0]!.id as ArrayBuffer)]).toEqual([4, 5, 6]);
    expect(requestOptions({ challenge: 'AQID' }).allowCredentials).toEqual([]);
  });
});

describe('answers to the server', () => {
  it('encodes a new passkey', () => {
    const json = attestationJson({
      id: 'AQI',
      rawId: buffer(1, 2),
      type: 'public-key',
      response: { attestationObject: buffer(3), clientDataJSON: buffer(4) },
    });
    expect(json).toEqual({
      id: 'AQI',
      rawId: 'AQI',
      type: 'public-key',
      response: { attestationObject: 'Aw', clientDataJSON: 'BA' },
    });
  });

  it('encodes an assertion, with or without a user handle', () => {
    const answer = (userHandle: ArrayBuffer | null) =>
      assertionJson({
        id: 'AQI',
        rawId: buffer(1, 2),
        type: 'public-key',
        response: {
          authenticatorData: buffer(5),
          clientDataJSON: buffer(6),
          signature: buffer(7),
          userHandle,
        },
      });
    expect(answer(buffer(8)).response).toEqual({
      authenticatorData: 'BQ',
      clientDataJSON: 'Bg',
      signature: 'Bw',
      userHandle: 'CA',
    });
    expect((answer(null).response as Record<string, unknown>).userHandle).toBeNull();
  });
});

describe('deviceName', () => {
  it('names the device a passkey is made on', () => {
    expect(deviceName('Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)')).toBe('iPhone');
    expect(deviceName('Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140')).toBe('Windows');
    expect(deviceName('Mozilla/5.0 (Linux; Android 15; Pixel 9)')).toBe('Android');
    expect(deviceName('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)')).toBe('Mac');
    expect(deviceName('Mozilla/5.0 (X11; Linux x86_64)')).toBe('Linux');
    expect(deviceName('curl/8')).toBe('Passkey');
  });
});
