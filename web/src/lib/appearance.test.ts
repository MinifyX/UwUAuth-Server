import { readFileSync } from 'node:fs';
import { bootScript } from '@uwusuite/design';
import { describe, expect, it } from 'vitest';
import { KEY, parseLook } from './appearance';

describe('appearance', () => {
  it('keeps known choices and drops everything else', () => {
    expect(parseLook('{"theme":"dark","contrast":"high","textSize":"larger"}')).toEqual({
      theme: 'dark',
      contrast: 'high',
      motion: 'system',
      textSize: 'larger',
    });
    const system = { theme: 'system', contrast: 'system', motion: 'system', textSize: 'system' };
    expect(parseLook('{"theme":"<x>","motion":7,"textSize":"huge"}')).toEqual(system);
    expect(parseLook('not json')).toEqual(system);
    expect(parseLook('null')).toEqual(system);
    expect(parseLook(null)).toEqual(system);
  });

  // The content security policy allows no inline scripts, so the suite's boot script is a file.
  it('ships the boot script of the design package', () => {
    expect(readFileSync('public/boot.js', 'utf8').trim()).toBe(bootScript(KEY));
  });
});
