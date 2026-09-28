import { type ReactNode } from 'react';
import { t, useLanguage } from '../lib/i18n';
import { useToast } from '../lib/toast';
import { Icon, type IconName } from './Icon';
import { Nyu } from './nyu/Nyu';
import { ReauthHost } from './ReauthHost';

export type NavItem = { path: string; label: string; icon: IconName };

/**
 * The frame around every page: the bar with Nyu and the name, and what goes on top of
 * everything — the note at the bottom and the "confirm it's you" dialog.
 */
export function Frame({
  area,
  organization,
  actions,
  children,
}: {
  /** "Admin" in the admin portal; nothing in the portal. */
  area?: string;
  organization?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  useLanguage();
  const toast = useToast();
  return (
    <div className="shell">
      <header className="topbar">
        <a className="topbar-brand" href="/" aria-label="UwUAuth">
          <Nyu size={26} blink={false} title="UwUAuth" />
          <span className="wordmark">
            <span>UwU</span>Auth
          </span>
          {area && <span className="topbar-area">{area}</span>}
          {organization && <span className="topbar-org">{organization}</span>}
        </a>
        <span className="spacer" />
        {actions}
      </header>
      <main className="stage">{children}</main>
      {toast && (
        <div className="toast" data-tone={toast.tone} role="status" key={toast.id}>
          {toast.text}
        </div>
      )}
      <ReauthHost />
    </div>
  );
}

/** A side list of pages on a wide screen, a row to swipe along on a phone. */
export function Layout({
  items,
  current,
  onGo,
  label,
  foot,
  children,
}: {
  items: NavItem[];
  current: string;
  onGo: (path: string) => void;
  label: string;
  foot?: ReactNode;
  children: ReactNode;
}) {
  useLanguage();
  return (
    <div className="layout">
      <nav className="side-nav" aria-label={label}>
        {items.map((item) => (
          <button
            key={item.path}
            type="button"
            aria-current={item.path === current ? 'page' : undefined}
            onClick={() => onGo(item.path)}
          >
            <Icon name={item.icon} size={17} />
            <span>{t(item.label)}</span>
          </button>
        ))}
        <span className="spacer" />
        {foot}
      </nav>
      <section className="page">{children}</section>
    </div>
  );
}

/** A page's title, with what one can do on it next to it. */
export function PageTitle({ children, actions }: { children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <h1 className="page-title">{children}</h1>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

/** A plain centred card, for sign-in, links, and "not for you". */
export function Centered({ children, wide }: { children: ReactNode; wide?: boolean }) {
  return (
    <div className="centered">
      <div className={wide ? 'center-card wide' : 'center-card'}>{children}</div>
    </div>
  );
}
