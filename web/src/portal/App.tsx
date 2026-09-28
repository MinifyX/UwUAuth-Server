import { useEffect, useState } from 'react';
import { Loading } from '../components/bits';
import { Icon } from '../components/Icon';
import { NyuScene } from '../components/nyu/scenes';
import { Centered, Frame } from '../components/Shell';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { reloadMe, signOut, useMe } from '../lib/me';
import { continueTarget, go, useRoute } from '../lib/route';
import { LinkPage } from './Links';
import { Portal } from './Portal';
import { Restricted } from './Restricted';
import { Forgot, SignIn } from './SignIn';

const LINKS = ['invite', 'setup', 'reset', 'verify'] as const;

/**
 * The page at `/`: signing in, the links from mails and QR codes, and the self-service portal
 * for whoever is signed in.
 */
export function App() {
  useLanguage();
  const route = useRoute();
  const me = useMe();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    reloadMe().catch((e) => setError(errorText(e)));
  }, []);

  // Signed in already and sent here to sign in for an app: straight on.
  const target = continueTarget(route.query.get('continue'));
  useEffect(() => {
    if (me && !me.restricted && target) location.href = target;
  }, [me, target]);

  // Signed in on the sign-in page (a bookmark, the back button): the portal instead.
  const signedIn = Boolean(me);
  useEffect(() => {
    if (signedIn && !target && (route.path === '/login' || route.path === '/forgot')) go('/');
  }, [signedIn, target, route.path]);

  const link = LINKS.find((purpose) => route.path === `/${purpose}`);
  let body;
  if (link) body = <LinkPage purpose={link} key={link} />;
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
  else if (me === null) body = route.path === '/forgot' ? <Forgot /> : <SignIn />;
  else if (me.restricted) body = <Restricted me={me} />;
  else if (target) body = <Loading />;
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
