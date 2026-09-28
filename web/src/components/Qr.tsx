import { renderSVG } from 'uqr';

/**
 * A QR code, drawn here: nothing about a link or a secret goes to a service that draws them.
 * Always dark on white, in either theme — phone cameras read that best.
 */
export function Qr({
  value,
  size = 'default',
  label,
}: {
  value: string;
  size?: 'default' | 'big';
  label?: string;
}) {
  return (
    <div
      className="qr"
      data-size={size}
      role="img"
      aria-label={label}
      dangerouslySetInnerHTML={{
        __html: renderSVG(value, { border: 2, whiteColor: '#ffffff', blackColor: '#1c1420' }),
      }}
    />
  );
}
