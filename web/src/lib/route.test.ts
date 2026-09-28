import { describe, expect, it } from 'vitest';
import { continueTarget, parseRoute } from './route';

describe('continueTarget', () => {
  it('takes paths under /oauth/ on this server', () => {
    expect(continueTarget('/oauth/authorize?client_id=wiki&state=x')).toBe(
      '/oauth/authorize?client_id=wiki&state=x',
    );
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
