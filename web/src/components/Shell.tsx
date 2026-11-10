import { Fragment, useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { t, useLanguage } from '../lib/i18n';
import { useToast } from '../lib/toast';
import { Icon, type IconName } from './Icon';
import { Nyu } from './nyu/Nyu';
import { ReauthHost } from './ReauthHost';

/** `group` is the heading the page stands under; pages of one group follow each other. */
export type NavItem = { path: string; label: string; icon: IconName; group?: string };

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
        <a className="topbar-brand" href="/">
          <span aria-hidden="true">
            <Nyu size={26} blink={false} />
          </span>
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

/** A side list of pages on a wide screen; below 1024px a drawer behind a menu button. */
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
  const [open, setOpen] = useState(false);
  const navId = useId();
  const menuButton = useRef<HTMLButtonElement>(null);
  const nav = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!open) return;
    const button = menuButton.current;
    // The drawer is modal: focus goes in when it opens and back to the button when it closes.
    nav.current?.querySelector<HTMLElement>('[aria-current], button')?.focus();
    const onKey = (event: KeyboardEvent) => event.key === 'Escape' && setOpen(false);
    window.addEventListener('keydown', onKey);
    return () => {
      window.removeEventListener('keydown', onKey);
      button?.focus();
    };
  }, [open]);
  const here = items.find((item) => item.path === current);
  return (
    <div className="layout">
      <div className="nav-bar">
        <button
          type="button"
          className="icon-button"
          ref={menuButton}
          aria-label={t('Menü')}
          aria-expanded={open}
          aria-controls={navId}
          onClick={() => setOpen(!open)}
        >
          <Icon name="menu" size={20} />
        </button>
        {here && <span>{t(here.label)}</span>}
      </div>
      <div className="nav-veil" data-open={open || undefined} onClick={() => setOpen(false)} />
      <nav
        ref={nav}
        id={navId}
        className="side-nav"
        aria-label={label}
        data-open={open || undefined}
      >
        {items.map((item, at) => (
          <Fragment key={item.path}>
            {item.group && item.group !== items[at - 1]?.group && (
              <h2 className="nav-group">{t(item.group)}</h2>
            )}
            <button
              type="button"
              aria-current={item.path === current ? 'page' : undefined}
              onClick={() => {
                setOpen(false);
                onGo(item.path);
              }}
            >
              <Icon name={item.icon} size={18} />
              <span>{t(item.label)}</span>
            </button>
          </Fragment>
        ))}
        <span className="spacer" />
        {foot}
      </nav>
      <section className="page" inert={open}>
        {children}
      </section>
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
