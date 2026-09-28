import { useEffect, useState } from 'react';
import { Loading } from '../components/bits';
import { Icon } from '../components/Icon';
import { NyuScene } from '../components/nyu/scenes';
import { Centered, Frame } from '../components/Shell';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { reloadMe, signOut, useMe } from '../lib/me';
import { continueTarget, go, goTo, useRoute } from '../lib/route';
import { Consent } from './Consent';
import { Device } from './Device';
import { LinkPage } from './Links';
import { Denied, LogoutConfirm, OAuthError, SignedOut } from './Notices';
import { Portal } from './Portal';
import { Restricted } from './Restricted';
import { Forgot, SignIn } from './SignIn';

const LINKS = ['invite', 'setup', 'reset', 'verify'] as const;

/** Pages apps send people to that need somebody signed in: sign-in first, then back here. */
const SIGNED_IN_PAGES = ['/consent', '/device'];

/**
 * The page at `/`: signing in, the links from mails and QR codes, the pages apps send people to
 * (OpenID Connect), and the self-service portal for whoever is signed in.
 */
export function App() {
  useLanguage();
  const route = useRoute();
  const me = useMe();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    reloadMe().catch((e) => setError(errorText(e)));
  }, []);

  // `fresh=1`: the app asked to sign in again, so the form shows even for whoever is signed in.
  const fresh = route.path === '/login' && route.query.get('fresh') === '1';
  // Signed in already and sent here to sign in for an app: straight on.
  const target = route.path === '/login' ? continueTarget(route.query.get('continue')) : null;
  useEffect(() => {
    if (me && !me.restricted && target && !fresh) goTo(target);
  }, [me, target, fresh]);

  // Signed in on the sign-in page (a bookmark, the back button): the portal instead.
  const signedIn = Boolean(me);
  useEffect(() => {
    if (signedIn && !target && (route.path === '/login' || route.path === '/forgot')) go('/');
  }, [signedIn, target, route.path]);

  // A page for apps that needs a session, and there is none: sign in, then come back.
  const needsSession = me === null && SIGNED_IN_PAGES.includes(route.path);
  useEffect(() => {
    if (!needsSession) return;
    const search = route.query.toString();
    const here = `/#${route.path}${search ? `?${search}` : ''}`;
    go(`/login?continue=${encodeURIComponent(continueTarget(here) ?? `/#${route.path}`)}`);
  }, [needsSession, route]);

  const link = LINKS.find((purpose) => route.path === `/${purpose}`);
  const query = (name: string) => route.query.get(name);
  let body;
  if (link) body = <LinkPage purpose={link} key={link} />;
  else if (route.path === '/oauth-error')
    body = <OAuthError reason={query('reason') ?? ''} app={query('app')} />;
  else if (route.path === '/logout') body = <LogoutConfirm request={query('request') ?? ''} />;
  else if (error && me === undefined)
    body = (
      <Centered>
        <NyuScene name="sad" className="center-scene" />
        <h1 className="card-title">{t('Der Server antwortet nicht')}</h1>
        <p className="dialog-lead">{error}</p>
        <button type="button" className="primary" onClick={() => location.reload()}>
          {t('Noch einmal versuchen')}
        </button>
      </Centered>
    );
  else if (me === undefined) body = <Loading />;
  else if (route.path === '/signed-out' && !me) body = <SignedOut />;
  else if (route.path === '/denied')
    body = (
      <Denied
        me={me}
        reason={query('reason') ?? ''}
        app={query('app')}
        continueTo={query('continue')}
      />
    );
  else if (me === null || fresh)
    body = needsSession ? <Loading /> : route.path === '/forgot' ? <Forgot /> : <SignIn />;
  else if (me.restricted) body = <Restricted me={me} />;
  else if (target) body = <Loading />;
  else if (route.path === '/consent')
    body = <Consent me={me} request={query('request') ?? ''} key={query('request')} />;
  else if (route.path === '/device') body = <Device initial={query('code') ?? ''} />;
  else body = <Portal me={me} />;

  return (
    <Frame
      organization={me?.server.organization}
      actions={
        me && (
          <>
            {me.admin && !me.restricted && (
              <a className="topbar-link" href="/admin">
                <Icon name="shield" size={15} />
                <span>{t('Admin-Portal')}</span>
              </a>
            )}
            <button
              type="button"
              className="topbar-action"
              onClick={() => void signOut().then(() => go('/login'))}
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
