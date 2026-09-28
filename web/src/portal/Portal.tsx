import { Layout, type NavItem } from '../components/Shell';
import { N_, t, useLanguage } from '../lib/i18n';
import { go, useRoute } from '../lib/route';
import type { Me } from '../lib/types';
import { word } from '../lib/words';
import { Devices } from './Devices';
import { MyGroups } from './MyGroups';
import { MyPeople } from './MyPeople';
import { Overview } from './Overview';
import { Profile } from './Profile';
import { Security } from './Security';

const PAGES: NavItem[] = [
  { path: '/', label: N_('Übersicht'), icon: 'house' },
  { path: '/profile', label: N_('Profil'), icon: 'user' },
  { path: '/security', label: N_('Sicherheit'), icon: 'shield' },
  { path: '/devices', label: N_('Geräte & Verlauf'), icon: 'devices' },
  { path: '/groups', label: N_('Gruppen'), icon: 'users' },
];

/** The self-service portal: one's own profile and every way one signs in. */
export function Portal({ me }: { me: Me }) {
  useLanguage();
  const route = useRoute();
  const pages: NavItem[] = me.manager
    ? [...PAGES, { path: '/people', label: word(me.server.mode, 'myPeople'), icon: 'heart' }]
    : PAGES;
  const top = `/${route.path.split('/')[1] ?? ''}`;
  const current = pages.find((page) => page.path === top) ?? pages[0]!;

  return (
    <Layout
      items={pages}
      current={current.path}
      onGo={go}
      label={t('Portal')}
      foot={
        <p className="nav-who">
          {t('Angemeldet als {name}', { name: me.username })}
          <br />
          <span className="muted">UwUAuth {me.server.version}</span>
        </p>
      }
    >
      {current.path === '/' && <Overview me={me} />}
      {current.path === '/profile' && <Profile me={me} />}
      {current.path === '/security' && <Security me={me} />}
      {current.path === '/devices' && <Devices me={me} />}
      {current.path === '/groups' && <MyGroups me={me} />}
      {current.path === '/people' && <MyPeople me={me} id={route.path.split('/')[2] || null} />}
    </Layout>
  );
}
