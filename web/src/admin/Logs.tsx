import { useEffect, useRef, useState } from 'react';
import { Segmented, Toggle } from '../components/controls';
import { PageTitle } from '../components/Shell';
import { api } from '../lib/api';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import type { LogLine } from '../lib/types';

/** The server's newest log lines, as they come, while the page is open. Nothing secret is logged. */
export function Logs() {
  useLanguage();
  const [level, setLevel] = useState('info');
  const [lines, setLines] = useState<LogLine[]>([]);
  const [follow, setFollow] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const last = useRef(0);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    last.current = 0;
    setLines([]);
    let stopped = false;
    let timer: number | undefined;
    // One request at a time: the next one waits for the answer, then three seconds.
    const poll = async () => {
      try {
        const fresh = await api<LogLine[]>(
          `/uwu/v1/logs?after=${last.current}&level=${encodeURIComponent(level)}&limit=1000`,
        );
        if (stopped) return;
        if (fresh.length) {
          last.current = fresh[fresh.length - 1]!.seq;
          setLines((all) => [...all, ...fresh].slice(-2000));
        }
        setError(null);
      } catch (e) {
        if (!stopped) setError(errorText(e));
      }
      if (!stopped) timer = window.setTimeout(() => void poll(), 3000);
    };
    void poll();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [level]);

  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [lines, follow]);

  return (
    <>
      <PageTitle>{t('Log')}</PageTitle>
      <div className="list-tools">
        <Segmented
          label={t('Stufe')}
          value={level}
          onChange={setLevel}
          options={[
            { value: 'error', label: t('Fehler') },
            { value: 'warn', label: t('Warnungen') },
            { value: 'info', label: t('Info') },
            { value: 'debug', label: t('Alles') },
          ]}
        />
        <span className="spacer" />
        <label className="check">
          <Toggle label={t('Mitlaufen')} checked={follow} onChange={setFollow} />
          <span>{t('Mitlaufen')}</span>
        </label>
      </div>
      {error && <p className="form-error">{error}</p>}
      <div className="log-box" ref={box}>
        {lines.map((line) => (
          <p key={line.seq} className="log-line" data-level={line.level}>
            <span className="log-time">{line.time.slice(11, 19)}</span>
            <span className="log-level">{line.level}</span>
            <span className="log-message">{line.message}</span>
          </p>
        ))}
        {lines.length === 0 && <p className="empty-note">{t('Noch nichts.')}</p>}
      </div>
    </>
  );
}
