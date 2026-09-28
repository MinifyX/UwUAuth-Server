import { useEffect, useState } from 'react';
import { Avatar } from '../components/bits';
import { Section } from '../components/controls';
import { Icon, type IconName } from '../components/Icon';
import { NyuScene } from '../components/nyu/scenes';
import { api } from '../lib/api';
import { t, useLanguage } from '../lib/i18n';
import { go } from '../lib/route';
import type { Me, MyApps } from '../lib/types';
import { word } from '../lib/words';
import { AppTiles } from './MyApps';

type Todo = { icon: IconName; title: string; text: string; action: string; path: string };

/** What would make this account better, most useful first. */
function todos(me: Me): Todo[] {
  const list: Todo[] = [];
  if (me.admin && !me.server.setupDone) {
    list.push({
      icon: 'sparkles',
      title: t('Richte UwUAuth ein'),
      text: t('Ein paar Fragen, dann ist der Server bereit für alle anderen.'),
      action: t('Zum Assistenten'),
      path: 'admin',
    });
  }
  if (me.passkeys.length === 0) {
    list.push({
      icon: 'key',
      title: t('Richte einen Passkey ein'),
      text: t(
        'Dann meldest du dich mit Fingerabdruck, Gesicht oder PIN an – schneller als mit Passwort, und niemand kann ihn dir abluchsen.',
      ),
      action: t('Passkey hinzufügen'),
      path: '/security',
    });
  }
  if (!me.email && !me.managed) {
    list.push({
      icon: 'mail',
      title: t('Hinterlege eine E-Mail-Adresse'),
      text: t('Damit du dein Passwort zurücksetzen kannst, falls du es einmal vergisst.'),
      action: t('Zum Profil'),
      path: '/profile',
    });
  }
  if (me.hasTotp && me.recoveryCodesLeft < 3) {
    list.push({
      icon: 'lifebuoy',
      title: t('Mach neue Wiederherstellungscodes'),
      text:
        me.recoveryCodesLeft === 0
          ? t('Du hast keine mehr übrig. Ohne sie kommst du ohne Handy nicht rein.')
          : t('Du hast nur noch {n} übrig.', { n: me.recoveryCodesLeft }),
      action: t('Zur Sicherheit'),
      path: '/security',
    });
  }
  if (!me.avatar) {
    list.push({
      icon: 'user',
      title: t('Zeig dich'),
      text: t('Ein Bild hilft anderen, dich in Apps wiederzuerkennen.'),
      action: t('Bild wählen'),
      path: '/profile',
    });
  }
  return list;
}

export function Overview({ me }: { me: Me }) {
  useLanguage();
  const list = todos(me);
  const [apps, setApps] = useState<MyApps['apps']>([]);
  useEffect(() => {
    api<MyApps>('/uwu/v1/me/apps').then(
      (data) => setApps(data.apps),
      () => undefined,
    );
  }, []);
  return (
    <>
      <div className="hello">
        <Avatar name={me.displayName} src={me.avatar} size={64} />
        <div>
          <h1 className="page-title">{t('Hallo, {name}!', { name: me.displayName })}</h1>
          <p className="muted">
            {t('Dein Konto bei {organization}.', { organization: me.server.organization })}
          </p>
        </div>
      </div>

      {apps.length > 0 && (
        <Section
          title={t('Meine Apps')}
          actions={
            <button type="button" className="link-button small" onClick={() => go('/apps')}>
              {t('Alle ansehen')}
            </button>
          }
        >
          <AppTiles apps={apps} />
        </Section>
      )}

      {list.length > 0 ? (
        <div className="todo-grid">
          {list.map((todo) => (
            <div className="todo" key={todo.title}>
              <span className="todo-icon">
                <Icon name={todo.icon} size={20} />
              </span>
              <div className="todo-text">
                <p className="todo-title">{todo.title}</p>
                <p className="muted">{todo.text}</p>
              </div>
              <button
                type="button"
                onClick={() => (todo.path === 'admin' ? (location.href = '/admin') : go(todo.path))}
              >
                {todo.action}
              </button>
            </div>
          ))}
        </div>
      ) : (
        <div className="all-good">
          <NyuScene name="done" className="all-good-scene" />
          <p className="empty-title">{t('Alles bestens ✧')}</p>
          <p className="muted">{t('Dein Konto ist gut gesichert. Mehr ist nicht zu tun.')}</p>
        </div>
      )}

      <div className="stat-grid">
        <button type="button" className="stat link-stat" onClick={() => go('/security')}>
          <span className="stat-value">{me.passkeys.length}</span>
          <span className="stat-label">{t('Passkeys')}</span>
        </button>
        <button type="button" className="stat link-stat" onClick={() => go('/security')}>
          <span className="stat-value">{me.hasTotp ? t('an') : t('aus')}</span>
          <span className="stat-label">{t('Authenticator-App')}</span>
        </button>
        <button type="button" className="stat link-stat" onClick={() => go('/groups')}>
          <span className="stat-value">{me.memberOf.length}</span>
          <span className="stat-label">{t('Gruppen')}</span>
        </button>
        {me.manager && (
          <button type="button" className="stat link-stat" onClick={() => go('/people')}>
            <span className="stat-value">
              <Icon name="heart" size={24} />
            </span>
            <span className="stat-label">{word(me.server.mode, 'myPeople')}</span>
          </button>
        )}
      </div>
    </>
  );
}
