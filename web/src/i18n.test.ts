import { describe, expect, it } from 'vitest';
import { EN } from './i18n/en';
import { pickLanguage, translate } from './lib/i18n';

// That every German string has an English one is `pnpm lint`'s job (scripts/check-i18n.mjs);
// this checks what that script cannot: the English says the same placeholders.
describe('the English catalogue', () => {
  it('keeps every placeholder', () => {
    const names = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    for (const [german, english] of Object.entries(EN)) {
      expect(names(english), german).toEqual(names(german));
    }
  });

  it('fills placeholders in both languages', () => {
    expect(translate('de', 'vor {n} Min.', { n: 5 })).toBe('vor 5 Min.');
    expect(translate('en', 'vor {n} Min.', { n: 5 })).toBe('5 min ago');
  });
});

describe('pickLanguage', () => {
  it('takes the first language it speaks', () => {
    expect(pickLanguage(['de-AT', 'en'])).toBe('de');
    expect(pickLanguage(['fr-FR', 'en-GB', 'de'])).toBe('en');
  });

  it('falls back to English', () => {
    expect(pickLanguage(['fr', 'ja'])).toBe('en');
    expect(pickLanguage([])).toBe('en');
  });
});
