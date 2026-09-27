import { describe, expect, it } from 'vitest';
import { pickLanguage, texts } from './i18n';

describe('texts', () => {
  it('has every key in both languages, and none empty', () => {
    expect(Object.keys(texts.en).sort()).toEqual(Object.keys(texts.de).sort());
    for (const language of [texts.de, texts.en]) {
      for (const value of Object.values(language)) expect(value.trim()).not.toBe('');
    }
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
