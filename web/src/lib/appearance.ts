/**
 * How the pages look in this browser: light or dark, contrast, motion and text size. Each follows
 * the system unless the person picks something in their profile; the choice is kept in this
 * browser only, like any other preference that is not worth a round trip.
 */

import {
  isTextSizeChoice,
  type ContrastSetting,
  type MotionSetting,
  type TextSizeChoice,
  type ThemeSetting,
} from '@uwusuite/design';
import { useSyncExternalStore } from 'react';

export type Look = {
  theme: ThemeSetting;
  contrast: ContrastSetting;
  motion: MotionSetting;
  textSize: TextSizeChoice;
};

/** Also in `public/boot.js`, which sets the look before the first paint. */
export const KEY = 'uwuauth.appearance';

const DEFAULTS: Look = {
  theme: 'system',
  contrast: 'system',
  motion: 'system',
  textSize: 'system',
};

const oneOf = <T extends string>(value: unknown, choices: readonly T[], fallback: T): T =>
  choices.includes(value as T) ? (value as T) : fallback;

/** Whatever the storage holds, only known choices come out of it. */
export function parseLook(json: string | null): Look {
  let saved: Partial<Record<keyof Look, unknown>> = {};
  try {
    const value: unknown = JSON.parse(json ?? '{}');
    if (value && typeof value === 'object') saved = value;
  } catch {
    // Not ours, or damaged: start from the system's look.
  }
  return {
    theme: oneOf(saved.theme, ['system', 'light', 'dark'], 'system'),
    contrast: oneOf(saved.contrast, ['system', 'normal', 'high'], 'system'),
    motion: oneOf(saved.motion, ['system', 'on', 'off'], 'system'),
    textSize: isTextSizeChoice(saved.textSize) ? saved.textSize : 'system',
  };
}

function load(): Look {
  try {
    return parseLook(window.localStorage.getItem(KEY));
  } catch {
    return DEFAULTS;
  }
}

let current: Look = load();
const listeners = new Set<() => void>();

export function setLook(change: Partial<Look>) {
  current = { ...current, ...change };
  try {
    window.localStorage.setItem(KEY, JSON.stringify(current));
  } catch {
    // Private windows may refuse; the choice then lasts as long as the page.
  }
  for (const listener of listeners) listener();
}

export function useLook(): Look {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}
