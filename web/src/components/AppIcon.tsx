import { appLetters } from '../lib/apps';

/**
 * An app's tile: its letters on a tint. No logos — the app's name says which one it is. A paired
 * UwUSuite app brings its own icon, which is shown instead.
 */
export function AppIcon({
  name,
  size = 40,
  src,
}: {
  name: string;
  size?: number;
  src?: string | null;
}) {
  if (src)
    return (
      <img
        className="app-icon app-icon-image"
        src={src}
        alt=""
        aria-hidden="true"
        width={size}
        height={size}
        style={{ borderRadius: size * 0.28 }}
      />
    );
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
