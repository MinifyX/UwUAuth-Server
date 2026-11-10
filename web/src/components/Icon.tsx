import { ICONS, Icon as SuiteIcon, type IconSize } from '@uwusuite/design';
import {
  Activity,
  ArrowLeftRight,
  Code,
  Heart,
  Smartphone,
  Sparkles,
  type LucideIcon,
} from 'lucide-react';

/**
 * UwUAuth's names for the suite's icons. Everything is drawn by `@uwusuite/design`; the few
 * meanings its vocabulary lacks come straight from lucide, the set the vocabulary is made of.
 */
const GLYPHS = {
  archive: ICONS.archive,
  house: ICONS.home,
  plus: ICONS.add,
  chevron: ICONS.next,
  back: ICONS.back,
  menu: ICONS.menu,
  refresh: ICONS.refresh,
  trash: ICONS.delete,
  pencil: ICONS.edit,
  download: ICONS.download,
  upload: ICONS.upload,
  key: ICONS.passkey,
  lock: ICONS.locked,
  unlock: ICONS.unlocked,
  shield: ICONS.securityCheck,
  crown: ICONS.admin,
  terminal: ICONS.terminal,
  copy: ICONS.copy,
  check: ICONS.done,
  close: ICONS.close,
  sparkles: Sparkles,
  network: ICONS.network,
  eye: ICONS.show,
  eyeOff: ICONS.hide,
  drive: ICONS.drive,
  stop: ICONS.stop,
  monitor: ICONS.computer,
  grid: ICONS.overview,
  user: ICONS.account,
  id: ICONS.identity,
  external: ICONS.openExternal,
  logout: ICONS.signOut,
  building: ICONS.organization,
  history: ICONS.history,
  warning: ICONS.warning,
  pulse: Activity,
  lifebuoy: ICONS.help,
  devices: ICONS.device,
  users: ICONS.people,
  mail: ICONS.mail,
  link: ICONS.link,
  tag: ICONS.label,
  qr: ICONS.qrCode,
  heart: Heart,
  swap: ArrowLeftRight,
  code: Code,
  smartphone: Smartphone,
  settings: ICONS.settings,
} satisfies Record<string, LucideIcon>;

export type IconName = keyof typeof GLYPHS;

/** The suite's five sizes (14, 16, 18, 20, 24 px); a number picks the nearest. */
function sizeOf(px: number): IconSize {
  if (px <= 14) return 'xs';
  if (px <= 16) return 'sm';
  if (px <= 18) return 'md';
  if (px <= 20) return 'lg';
  return 'xl';
}

export function Icon({
  name,
  size = 16,
  title,
  className,
}: {
  name: IconName;
  size?: number;
  title?: string;
  className?: string;
}) {
  return (
    <SuiteIcon
      icon={GLYPHS[name]}
      size={sizeOf(size)}
      label={title}
      className={className ? `icon ${className}` : 'icon'}
    />
  );
}
