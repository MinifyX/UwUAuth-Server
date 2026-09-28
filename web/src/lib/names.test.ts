import { describe, expect, it } from 'vitest';
import { suggestUsername, validUsername } from './names';

describe('suggestUsername', () => {
  it('makes a user name the server takes', () => {
    expect(suggestUsername('Mia Müller')).toBe('mia.mueller');
    expect(suggestUsername('  José  Gómez ')).toBe('jose.gomez');
    expect(suggestUsername('Straße 12')).toBe('strasse.12');
    expect(suggestUsername('--Nyu!!')).toBe('nyu');
    expect(suggestUsername('😺')).toBe('');
    for (const name of ['Mia Müller', 'José Gómez', 'A. B.']) {
      expect(validUsername(suggestUsername(name)), name).toBe(true);
    }
  });

  it('knows the rule', () => {
    expect(validUsername('mia')).toBe(true);
    expect(validUsername('-mia')).toBe(false);
    expect(validUsername('Mia')).toBe(false);
    expect(validUsername('mia@example.com')).toBe(false);
  });
});
