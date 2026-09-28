import { describe, expect, it } from 'vitest';
import { continueTarget, parseRoute } from './route';

describe('continueTarget', () => {
  it('takes paths under /oauth/ on this server', () => {
    expect(continueTarget('/oauth/authorize?client_id=wiki&state=x')).toBe(
      '/oauth/authorize?client_id=wiki&state=x',
    );
  });

  it('takes the device and consent pages of this app', () => {
    expect(continueTarget('/#/device?code=BCDF-GHJK')).toBe('/#/device?code=BCDF-GHJK');
    expect(continueTarget('/#/device')).toBe('/#/device');
    expect(continueTarget('/#/consent?request=a1_b-2')).toBe('/#/consent?request=a1_b-2');
  });

  it('refuses everything else', () => {
    for (const value of [
      null,
      '',
      '/security',
      'https://evil.example.net/oauth/authorize',
      '//evil.example.net/oauth/authorize',
      '/oauth/../admin',
      '/\\evil.example.net/oauth/',
      'javascript:alert(1)',
      '/#/admin',
      '/#/device/../admin',
      '/#/device?code=<script>',
      '/#/device?code=x#y',
      '//#/device',
      'https://evil.example.net/#/device',
      '/oauth\\authorize',
    ]) {
      expect(continueTarget(value), String(value)).toBeNull();
    }
  });
});

describe('parseRoute', () => {
  it('splits the hash into a path and a query', () => {
    const route = parseRoute('#/invite?token=abc');
    expect(route.path).toBe('/invite');
    expect(route.query.get('token')).toBe('abc');
    expect(parseRoute('').path).toBe('/');
  });
});
