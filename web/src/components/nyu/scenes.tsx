import type { ReactNode } from 'react';
import { NYU, NyuFigure, Paw, Sticker } from './Nyu';

// Every scene is drawn on a 320 × 220 canvas, the same as UwUMail's and UwULock's. Nyu sits at
// about 0.58 scale, so props use a 6 px outline and an 18 px edge to match.

const S = { stroke: NYU.outline, strokeWidth: 6 } as const;
const EDGE = 18;
/** Nyu's own edge at scene scale: 30 × 0.6 ≈ the props' 18 px. */
const NYU_EDGE = 30;

function Shadow({ cx = 160, rx = 104 }: { cx?: number; rx?: number }) {
  return (
    <ellipse
      className="no-edge"
      cx={cx}
      cy="206"
      rx={rx}
      ry="8"
      fill={NYU.outline}
      opacity="0.08"
    />
  );
}

function Star({
  x,
  y,
  r = 12,
  className,
}: {
  x: number;
  y: number;
  r?: number;
  className?: string;
}) {
  const k = r * 0.2;
  return (
    <path
      className={className}
      d={`M${x} ${y - r} Q${x + k} ${y - k} ${x + r} ${y} Q${x + k} ${y + k} ${x} ${y + r} Q${x - k} ${y + k} ${x - r} ${y} Q${x - k} ${y - k} ${x} ${y - r}Z`}
      fill={NYU.star}
      stroke={NYU.outline}
      strokeWidth={r > 10 ? 4 : 3}
    />
  );
}

function Heart({
  x,
  y,
  size = 1,
  fill = NYU.body,
}: {
  x: number;
  y: number;
  size?: number;
  fill?: string;
}) {
  return (
    <path
      transform={`translate(${x} ${y}) scale(${size})`}
      d="M0 13 C-15 3 -18 -4 -17 -8 C-16 -15 -7 -16 -3 -11 L0 -8 L3 -11 C7 -16 16 -15 17 -8 C18 -4 15 3 0 13Z"
      fill={fill}
      stroke={NYU.outline}
      strokeWidth={4 / size}
    />
  );
}

/** A key, for passkeys: the round bow and the bit. */
function Key({
  x,
  y,
  rotate = 0,
  size = 1,
}: {
  x: number;
  y: number;
  rotate?: number;
  size?: number;
}) {
  return (
    <g transform={`translate(${x} ${y}) rotate(${rotate}) scale(${size})`}>
      <g fill="none" stroke={NYU.outline} strokeWidth={6}>
        <path d="M0 4 V40 M0 24 H13 M0 35 H10" />
      </g>
      <circle cx="0" cy="-9" r="13" fill={NYU.lilac} {...S} />
      <circle className="no-edge" cx="0" cy="-9" r="4.5" fill={NYU.tile} />
    </g>
  );
}

/** An envelope, for invitations. */
function Envelope({ x, y, rotate = 0 }: { x: number; y: number; rotate?: number }) {
  return (
    <g transform={`translate(${x} ${y}) rotate(${rotate})`}>
      <rect x="-30" y="-20" width="60" height="40" rx="6" fill={NYU.paper} {...S} strokeWidth={5} />
      <path d="M-28 -17 L0 4 L28 -17" fill="none" stroke={NYU.outline} strokeWidth={5} />
      <Heart x={0} y={10} size={0.4} />
    </g>
  );
}

/** Hello: Nyu waves. */
function Welcome() {
  return (
    <>
      <Shadow />
      <path
        d="M248 50 q12 9 10 25 M264 38 q16 13 14 35"
        fill="none"
        stroke={NYU.outline}
        strokeWidth={4}
        opacity="0.4"
      />
      <NyuFigure
        mood="happy"
        x={150}
        y={134}
        scale={0.58}
        tilt={-6}
        edge={NYU_EDGE}
        front={<Paw x={236} y={118} className="nyu-wave" />}
      />
      <Sticker edge={12}>
        <Heart x={52} y={66} size={0.95} />
        <Star x={286} y={156} r={11} />
        <Star x={38} y={150} r={8} />
      </Sticker>
    </>
  );
}

const CONFETTI: [x: number, y: number, rotate: number, fill: string][] = [
  [42, 40, -20, NYU.body],
  [78, 16, 30, NYU.star],
  [118, 24, 70, NYU.mint],
  [210, 18, -40, NYU.lilac],
  [250, 44, 15, NYU.body],
  [284, 20, 60, NYU.sky],
  [30, 108, 45, NYU.sky],
  [292, 104, -30, NYU.star],
  [48, 170, 20, NYU.lilac],
  [276, 172, -60, NYU.mint],
];

/** Done: Nyu cheers with both paws up. */
function Done() {
  return (
    <>
      <Shadow />
      <Sticker edge={10}>
        {CONFETTI.map(([x, y, rotate, fill]) => (
          <rect
            key={`${x}-${y}`}
            x={x - 7}
            y={y - 4}
            width="14"
            height="8"
            rx="2"
            transform={`rotate(${rotate} ${x} ${y})`}
            fill={fill}
            stroke={NYU.outline}
            strokeWidth={3}
          />
        ))}
      </Sticker>
      <NyuFigure
        mood="cheer"
        x={160}
        y={140}
        scale={0.58}
        edge={NYU_EDGE}
        front={
          <>
            <Paw x={26} y={120} />
            <Paw x={230} y={120} />
          </>
        }
      />
    </>
  );
}

/** Passkeys and second factors: Nyu holds up a key, glowing. */
function Keys() {
  return (
    <>
      <Shadow cx={150} />
      <NyuFigure
        mood="sparkle"
        x={140}
        y={136}
        scale={0.56}
        tilt={-3}
        edge={NYU_EDGE}
        front={<Paw x={226} y={116} />}
      />
      <Sticker edge={EDGE}>
        <g className="nyu-bob">
          <Key x={262} y={72} rotate={24} size={1.2} />
        </g>
      </Sticker>
      <Sticker edge={10}>
        <g className="nyu-sparks">
          <Star x={296} y={36} r={9} />
          <Star x={230} y={32} r={6} />
          <Star x={300} y={116} r={6} />
        </g>
      </Sticker>
    </>
  );
}

/** Looking after somebody: Nyu and a little badge cat next to her. */
function Family() {
  return (
    <>
      <Shadow cx={160} rx={120} />
      <NyuFigure mood="happy" x={124} y={134} scale={0.56} tilt={-4} edge={NYU_EDGE} />
      <g className="nyu-hop">
        <NyuFigure mood="uwu" x={232} y={162} scale={0.34} tilt={6} edge={NYU_EDGE * 1.6} />
      </g>
      <Sticker edge={12}>
        <Heart x={188} y={70} size={0.8} />
        <Star x={40} y={60} r={9} className="nyu-twinkle" />
      </Sticker>
    </>
  );
}

/** Invitations: Nyu carries an envelope. */
function Invite() {
  return (
    <>
      <Shadow cx={160} />
      <g className="nyu-walk">
        <NyuFigure mood="happy" x={140} y={130} scale={0.56} tilt={3} edge={NYU_EDGE} />
        <Sticker edge={EDGE}>
          <Envelope x={236} y={150} rotate={-10} />
          <Paw x={206} y={160} />
        </Sticker>
      </g>
      <Sticker edge={12}>
        <Star x={278} y={62} r={9} className="nyu-twinkle" />
      </Sticker>
    </>
  );
}

/** Something needs a decision first, or is not allowed: Nyu holds up a page with a question mark. */
function Puzzled() {
  return (
    <>
      <Shadow cx={150} />
      <NyuFigure mood="puzzled" x={112} y={136} scale={0.56} tilt={-8} edge={NYU_EDGE} />
      <Sticker edge={EDGE}>
        <g transform="rotate(8 226 118)">
          <path d="M190 58 H240 L262 80 V176 H190Z" fill={NYU.paper} {...S} />
          <path d="M240 58 V80 H262" fill={NYU.screen} {...S} />
          <path
            d="M212 106 q0 -15 15 -15 q15 0 15 13 q0 10 -13 14 v8"
            fill="none"
            stroke={NYU.body}
            strokeWidth={9}
          />
          <circle cx="229" cy="145" r="5.5" fill={NYU.body} />
        </g>
        <ellipse cx="186" cy="140" rx="12" ry="10" fill={NYU.body} {...S} />
      </Sticker>
    </>
  );
}

/** Something went wrong, or a link ran out: Nyu is sad. */
function Sad() {
  return (
    <>
      <Shadow />
      <NyuFigure mood="sad" x={160} y={136} scale={0.58} tilt={4} edge={NYU_EDGE} />
      <Sticker edge={12}>
        <Heart x={58} y={62} size={0.85} fill={NYU.lilac} />
        <Star x={280} y={44} r={9} />
      </Sticker>
    </>
  );
}

/** Nothing going on: Nyu naps, a little "z" floating up. */
function Sleepy() {
  return (
    <>
      <Shadow cx={160} rx={90} />
      <NyuFigure mood="sleepy" x={160} y={142} scale={0.56} tilt={8} edge={NYU_EDGE} />
      <g className="nyu-zzz" fill="none" stroke={NYU.violet} strokeWidth={5}>
        <path d="M232 70 h16 l-16 16 h16" />
        <path d="M258 40 h11 l-11 11 h11" />
      </g>
    </>
  );
}

const SCENES = {
  welcome: Welcome,
  done: Done,
  keys: Keys,
  family: Family,
  invite: Invite,
  puzzled: Puzzled,
  sad: Sad,
  sleepy: Sleepy,
} satisfies Record<string, () => ReactNode>;

export type SceneName = keyof typeof SCENES;

/** A small illustration of Nyu for empty states, welcomes and errors. Decorative only. */
export function NyuScene({ name, className }: { name: SceneName; className?: string }) {
  const Scene = SCENES[name];
  return (
    <svg
      viewBox="-10 -10 340 230"
      className={className ? `nyu-host nyu-blink ${className}` : 'nyu-host nyu-blink'}
      style={{ overflow: 'visible' }}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
    >
      <Scene />
    </svg>
  );
}
