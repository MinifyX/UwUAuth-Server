import { useEffect, useState } from 'react';
import { pickLanguage, texts } from './i18n';

type Health =
  | { state: 'checking' }
  | { state: 'ok'; version: string }
  | { state: 'unwell'; version: string }
  | { state: 'unreachable' };

const PLAN = 'https://github.com/MinifyX/UwUAuth-Server/blob/main/docs/plan.md';

export function App() {
  const language = pickLanguage(navigator.languages ?? [navigator.language]);
  const t = texts[language];
  const [health, setHealth] = useState<Health>({ state: 'checking' });

  useEffect(() => {
    document.documentElement.lang = language;
  }, [language]);

  useEffect(() => {
    let current = true;
    fetch('/healthz')
      .then(async (response) => {
        const body = (await response.json()) as { ok?: boolean; version?: string };
        if (!current) return;
        const version = body.version ?? '?';
        setHealth(body.ok ? { state: 'ok', version } : { state: 'unwell', version });
      })
      .catch(() => {
        if (current) setHealth({ state: 'unreachable' });
      });
    return () => {
      current = false;
    };
  }, []);

  return (
    <main className="welcome">
      <img className="welcome-nyu" src="/nyu.svg" alt="" width={160} height={160} />
      <h1>UwUAuth Server</h1>
      <p className="welcome-tagline">{t.tagline}</p>

      <p className={`welcome-status welcome-status-${health.state}`} role="status">
        <span className="welcome-dot" aria-hidden="true" />
        {health.state === 'checking' && t.checking}
        {health.state === 'ok' && `${t.running} · ${t.version} ${health.version}`}
        {health.state === 'unwell' && t.unwell}
        {health.state === 'unreachable' && t.unreachable}
      </p>

      <section className="welcome-card">
        <h2>{t.comingTitle}</h2>
        <p>{t.comingBody}</p>
        <a className="welcome-button" href={PLAN} target="_blank" rel="noreferrer">
          {t.plan}
        </a>
      </section>
    </main>
  );
}
