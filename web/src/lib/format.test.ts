import { afterEach, describe, expect, it } from 'vitest';
import {
  ago,
  clock,
  daysText,
  grouped,
  minutes,
  windowsText,
  windowText,
  WORKDAYS,
} from './format';
import { setLanguage } from './i18n';

afterEach(() => setLanguage('de'));

describe('time windows', () => {
  it('reads like people write it', () => {
    setLanguage('de');
    expect(windowText({ days: WORKDAYS, start: 420, end: 1200 })).toBe('Mo–Fr 07:00–20:00');
    expect(windowText({ days: 96, start: 540, end: 1440 })).toBe('Sa, So 09:00–24:00');
    expect(windowText({ days: 1 | 4 | 16, start: 0, end: 60 })).toBe('Mo, Mi, Fr 00:00–01:00');
    expect(windowText({ days: 127, start: 1320, end: 360 })).toBe('täglich 22:00–06:00');
    expect(daysText(1 | 2 | 8 | 16 | 32)).toBe('Mo, Di, Do–Sa');
  });

  it('in English too', () => {
    setLanguage('en');
    expect(windowText({ days: WORKDAYS, start: 420, end: 1200 })).toBe('Mon–Fri 07:00–20:00');
    expect(windowsText([])).toBe('No time windows: any time.');
  });

  it('joins several and says when there are none', () => {
    setLanguage('de');
    expect(windowsText([])).toBe('Keine Zeitfenster: jederzeit.');
    expect(
      windowsText([
        { days: WORKDAYS, start: 420, end: 1200 },
        { days: 96, start: 540, end: 1260 },
      ]),
    ).toBe('Mo–Fr 07:00–20:00 · Sa, So 09:00–21:00');
  });

  it('turns clock times into minutes and back', () => {
    expect(clock(0)).toBe('00:00');
    expect(clock(1440)).toBe('24:00');
    expect(minutes('7:05')).toBe(425);
    expect(minutes('24:00')).toBe(1440);
    expect(minutes('00:00', true)).toBe(1440);
    expect(minutes('00:00')).toBe(0);
    for (const bad of ['25:00', '12:60', 'noon', '24:01']) expect(minutes(bad)).toBeNull();
  });
});

describe('ago', () => {
  it('says how long ago, roughly', () => {
    setLanguage('de');
    const now = Date.parse('2026-09-27T12:00:00Z');
    expect(ago(null, now)).toBe('noch nie');
    expect(ago('2026-09-27T11:59:30Z', now)).toBe('gerade eben');
    expect(ago('2026-09-27T11:55:00Z', now)).toBe('vor 5 Min.');
    expect(ago('2026-09-27T09:00:00Z', now)).toBe('vor 3 Std.');
    expect(ago('2026-09-25T12:00:00Z', now)).toBe('vor 2 Tagen');
  });
});

describe('grouped', () => {
  it('splits a secret into groups to type', () => {
    expect(grouped('ABCDEFGHIJ')).toBe('ABCD EFGH IJ');
    expect(grouped('')).toBe('');
  });
});
