import { useEffect, useState } from 'react';
import { Loading } from '../components/bits';
import { Icon } from '../components/Icon';
import { NyuScene } from '../components/nyu/scenes';
import { Centered, Frame, Layout, type NavItem } from '../components/Shell';
import { errorText } from '../lib/errors';
import { N_, t, useLanguage } from '../lib/i18n';
import { reloadMe, signOut, useMe } from '../lib/me';
import { go, useRoute } from '../lib/route';
import type { Me } from '../lib/types';
import { PeopleList } from '../people/PeopleList';
import { PersonDetail } from '../people/PersonDetail';
import { Restricted } from '../portal/Restricted';
import { Forgot, SignIn } from '../portal/SignIn';
import { Attributes } from './Attributes';
import { Backups } from './Backups';
import { Events } from './Events';
import { Groups } from './Groups';
import { Invitations } from './Invitations';
import { Logs } from './Logs';
import { Overview } from './Overview';
import { AdminSettings } from './Settings';
import { Setup } from './Setup';
import { Tokens } from './Tokens';
import { Transfer } from './Transfer';

const PAGES: NavItem[] = [
  { path: '/', label: N_('Übersicht'), icon: 'house' },
  { path: '/people', label: N_('Personen'), icon: 'user' },
  { path: '/groups', label: N_('Gruppen'), icon: 'users' },
  { path: '/invitations', label: N_('Einladungen'), icon: 'sparkles' },
  { path: '/attributes', label: N_('Zusätzliche Felder'), icon: 'tag' },
  { path: '/settings', label: N_('Einstellungen'), icon: 'building' },
  { path: '/events', label: N_('Ereignisse'), icon: 'history' },
  { path: '/logs', label: N_('Log'), icon: 'terminal' },
  { path: '/backups', label: N_('Backups'), icon: 'drive' },
  { path: '/tokens', label: N_('API-Tokens'), icon: 'code' },
  { path: '/transfer', label: N_('Import & Export'), icon: 'swap' },
];

/**
 * The admin portal at `/admin`: the same sign-in as the portal, and then — for admins — people,
 * groups, invitations and the server's settings. A new server starts with the assistant.
 */
export function AdminApp() {
  useLanguage();
  const route = useRoute();
  const me = useMe();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    reloadMe().catch((e) => setError(errorText(e)));
  }, []);

  let body;
  if (error && me === undefined) body = <p className="form-error page-error">{error}</p>;
  else if (me === undefined) body = <Loading />;
  else if (me === null) body = route.path === '/forgot' ? <Forgot /> : <SignIn />;
  else if (me.restricted) body = <Restricted me={me} />;
  else if (!me.admin) body = <NotAdmin />;
  else if (!me.server.setupDone) body = <Setup me={me} />;
  else body = <AdminPages me={me} />;

  return (
    <Frame
      area={t('Admin')}
      organization={me?.server.setupDone ? me.server.organization : undefined}
      actions={
        me && (
          <>
            <a className="topbar-link" href="/">
              <Icon name="user" size={15} />
              <span>{t('Mein Konto')}</span>
            </a>
            <button
              type="button"
              className="topbar-action"
              onClick={() => void signOut().then(() => go('/'))}
              title={t('Abmelden')}
              aria-label={t('Abmelden')}
            >
              <Icon name="logout" size={18} />
            </button>
          </>
        )
      }
    >
      {body}
    </Frame>
  );
}

function NotAdmin() {
  useLanguage();
  return (
    <Centered>
      <NyuScene name="puzzled" className="center-scene" />
      <h1 className="card-title">{t('Nur für Admins')}</h1>
      <p className="dialog-lead">
        {t('Dein Konto hat kein Admin-Recht. Ein Admin kann es dir im Admin-Portal geben.')}
      </p>
      <div className="form-actions center">
        <a className="button-link primary" href="/">
          {t('Zu meinem Konto')}
        </a>
        <button type="button" onClick={() => void signOut().then(() => go('/'))}>
          {t('Abmelden')}
        </button>
      </div>
    </Centered>
  );
}

function AdminPages({ me }: { me: Me }) {
  useLanguage();
  const route = useRoute();
  const [, top = '', sub = ''] = route.path.split('/');
  const page = PAGES.find((p) => p.path === `/${top}`) ?? PAGES[0]!;
  return (
    <Layout
      items={PAGES}
      current={page.path}
      onGo={go}
      label={t('Admin-Portal')}
      foot={
        <p className="nav-who">
          {t('Angemeldet als {name}', { name: me.username })}
          <br />
          <span className="muted">UwUAuth {me.server.version}</span>
        </p>
      }
    >
      {page.path === '/' && <Overview />}
      {page.path === '/people' &&
        (sub ? (
          <PersonDetail key={sub} id={sub} me={me} onBack={() => go('/people')} />
        ) : (
          <PeopleList me={me} title={t('Personen')} onOpen={(id) => go(`/people/${id}`)} />
        ))}
      {page.path === '/groups' && <Groups me={me} id={sub || null} />}
      {page.path === '/invitations' && <Invitations me={me} />}
      {page.path === '/attributes' && <Attributes />}
      {page.path === '/settings' && <AdminSettings me={me} />}
      {page.path === '/events' && <Events />}
      {page.path === '/logs' && <Logs />}
      {page.path === '/backups' && <Backups />}
      {page.path === '/tokens' && <Tokens />}
      {page.path === '/transfer' && <Transfer me={me} />}
    </Layout>
  );
}
