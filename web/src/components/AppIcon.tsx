import { appLetters } from '../lib/apps';

/** An app's tile: its letters on a tint. No logos — the app's name says which one it is. */
export function AppIcon({ name, size = 40 }: { name: string; size?: number }) {
  return (
    <span
      className="app-icon"
      aria-hidden="true"
      style={{ width: size, height: size, fontSize: size * 0.36, borderRadius: size * 0.28 }}
    >
      {appLetters(name)}
    </span>
  );
}
