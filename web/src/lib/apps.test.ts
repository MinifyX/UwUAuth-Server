import { describe, expect, it } from 'vitest';
import {
  appLetters,
  discoveryUrl,
  fillTemplate,
  formatUserCode,
  shownScopes,
  templateNeeds,
} from './apps';

describe('formatUserCode', () => {
  it('writes the code the way the TV shows it', () => {
    expect(formatUserCode('bcdf ghjk')).toBe('BCDF-GHJK');
    expect(formatUserCode('BCDF-GHJK')).toBe('BCDF-GHJK');
    expect(formatUserCode('bc')).toBe('BC');
    expect(formatUserCode('bcdfg')).toBe('BCDF-G');
    expect(formatUserCode('bcdf-ghjk-extra')).toBe('BCDF-GHJK');
  });
});

describe('templates', () => {
  it('fill in the address without a trailing slash', () => {
    expect(
      fillTemplate('{url}/user/oauth2/{slug}/callback', 'https://git.example.com/', 'uwu'),
    ).toBe('https://git.example.com/user/oauth2/uwu/callback');
    expect(templateNeeds(['{url}/cb', 'app.immich:///oauth-callback'])).toEqual({
      url: true,
      slug: false,
    });
    expect(templateNeeds([])).toEqual({ url: false, slug: false });
  });

  it('point at the discovery document', () => {
    expect(discoveryUrl('https://auth.example.com/')).toBe(
      'https://auth.example.com/.well-known/openid-configuration',
    );
  });
});

describe('shownScopes', () => {
  it('lists the ones worth saying, in order', () => {
    expect(shownScopes(['groups', 'openid', 'email', 'profile', 'made_up'])).toEqual([
      'profile',
      'email',
      'groups',
    ]);
  });
});

describe('appLetters', () => {
  it('makes a tile from a name', () => {
    expect(appLetters('Home Assistant')).toBe('HA');
    expect(appLetters('Nextcloud')).toBe('Ne');
    expect(appLetters('Forgejo / Gitea')).toBe('FG');
    expect(appLetters('')).toBe('?');
  });
});
