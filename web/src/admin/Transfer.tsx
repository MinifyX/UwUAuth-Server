import { useRef, useState } from 'react';
import { Section, useAction } from '../components/controls';
import { Icon } from '../components/Icon';
import { PageTitle } from '../components/Shell';
import { api, apiBlob, saveFile, seg } from '../lib/api';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import type { ImportReport, Me, Person } from '../lib/types';

/**
 * Moving the directory: out as JSON (people and groups, for another UwUAuth) or CSV (people, for
 * a spreadsheet), and in again. Nothing to sign in with ever goes out; who comes in sets up their
 * account with a link.
 */
export function Transfer({ me }: { me: Me }) {
  useLanguage();
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<{ name: string; text: string; csv: boolean } | null>(null);
  const [report, setReport] = useState<ImportReport | null>(null);
  const [links, setLinks] = useState<string | null>(null);
  const [run, busy] = useAction();

  const exportAs = (format: 'json' | 'csv') =>
    run(async () => {
      const blob = await apiBlob(`/uwu/v1/export?format=${format}`);
      saveFile(blob, format === 'csv' ? 'uwuauth-people.csv' : 'uwuauth-directory.json');
    });

  const importFile = (dryRun: boolean) =>
    run(async () => {
      if (!file) return;
      const answer = await api<ImportReport>(`/uwu/v1/import?dryRun=${dryRun}`, {
        method: 'POST',
        body: file.text,
        contentType: file.csv ? 'text/csv' : 'application/json',
      });
      setReport(answer);
      setLinks(null);
      if (!dryRun) toast(t('Importiert ✧'));
    });

  // Everybody new who has an address gets a setup link by mail, one after the other.
  const mailLinks = () =>
    run(async () => {
      if (!report) return;
      const created = new Set(report.people.created);
      const people = await api<Person[]>('/uwu/v1/people');
      const targets = people.filter(
        (person) => created.has(person.username) && person.email && !person.hasPassword,
      );
      let sent = 0;
      for (const person of targets) {
        await api(`/uwu/v1/people/${seg(person.id)}/link`, { body: { mail: true } });
        sent += 1;
        setLinks(t('{n} von {total} verschickt …', { n: sent, total: targets.length }));
      }
      setLinks(
        targets.length === 0
          ? t('Unter den Neuen hat niemand eine Adresse.')
          : t('{n} Einrichtungslinks verschickt ✧', { n: sent }),
      );
    });

  return (
    <>
      <PageTitle>{t('Import & Export')}</PageTitle>
      <Section
        title={t('Exportieren')}
        lead={t(
          'Ohne Passwörter, Passkeys oder sonst etwas zum Anmelden. JSON nimmt Gruppen und Mitgliedschaften mit, für ein anderes UwUAuth; CSV ist für eine Tabelle.',
        )}
      >
        <div className="form-actions">
          <button type="button" disabled={busy} onClick={() => void exportAs('json')}>
            <Icon name="download" />
            {t('Als JSON')}
          </button>
          <button type="button" disabled={busy} onClick={() => void exportAs('csv')}>
            <Icon name="download" />
            {t('Als CSV')}
          </button>
        </div>
      </Section>

      <Section
        title={t('Importieren')}
        lead={t(
          'Eine JSON-Datei aus einem UwUAuth-Export oder eine CSV-Tabelle mit einer Spalte „username“ (dazu gern displayName, givenName, familyName, email, language, groups – Gruppen mit Semikolon getrennt). Wen es schon gibt, der bleibt, wie er ist.',
        )}
      >
        <div className="form-actions wrap">
          <button type="button" onClick={() => input.current?.click()} disabled={busy}>
            <Icon name="upload" />
            {file ? t('Andere Datei') : t('Datei wählen')}
          </button>
          {file && <span className="muted">{file.name}</span>}
          <span className="spacer" />
          <button type="button" disabled={!file || busy} onClick={() => void importFile(true)}>
            {t('Probelauf')}
          </button>
          <button
            type="button"
            className="primary"
            disabled={!file || busy || !report?.dryRun}
            title={!report?.dryRun ? t('Erst ein Probelauf') : undefined}
            onClick={() => void importFile(false)}
          >
            {t('Jetzt importieren')}
          </button>
        </div>
        <input
          ref={input}
          type="file"
          accept=".json,.csv,application/json,text/csv"
          hidden
          onChange={async (e) => {
            const picked = e.target.files?.[0];
            e.target.value = '';
            if (!picked) return;
            const text = await picked.text();
            setFile({
              name: picked.name,
              text,
              csv: picked.name.toLowerCase().endsWith('.csv') || picked.type === 'text/csv',
            });
            setReport(null);
          }}
        />
        {report && <Report report={report} />}
        {report && !report.dryRun && report.people.created.length > 0 && (
          <div className="notice-block">
            <p>
              {t(
                'Die neuen Personen haben noch keine Möglichkeit, sich anzumelden. Sie bekommen sie mit einem Einrichtungslink.',
              )}
            </p>
            {me.server.mail ? (
              <button type="button" disabled={busy} onClick={() => void mailLinks()}>
                <Icon name="mail" />
                {t('Einrichtungslinks per Mail an alle Neuen mit Adresse')}
              </button>
            ) : (
              <p className="field-hint">
                {t('Ohne Mail-Einrichtung machst du die Links bei jeder Person unter „Personen“.')}
              </p>
            )}
            {links && <p className="setting-result">{links}</p>}
          </div>
        )}
      </Section>
    </>
  );
}

function Report({ report }: { report: ImportReport }) {
  useLanguage();
  const { people, groups } = report;
  return (
    <div className="report">
      <p className="report-title">
        {report.dryRun ? t('Probelauf – noch ist nichts passiert:') : t('Erledigt:')}
      </p>
      <ul>
        <li>
          {t('{n} Personen neu', { n: people.created.length })}
          {people.created.length > 0 && <small>{people.created.join(', ')}</small>}
        </li>
        <li>
          {t('{n} Personen gab es schon', { n: people.skipped.length })}
          {people.skipped.length > 0 && <small>{people.skipped.join(', ')}</small>}
        </li>
        {people.failed.length > 0 && (
          <li className="danger-text">
            {t('{n} Personen gingen nicht:', { n: people.failed.length })}
            {people.failed.map((failure) => (
              <small key={failure.username}>
                {failure.username}: {failure.error}
              </small>
            ))}
          </li>
        )}
        <li>
          {t('{n} Gruppen neu, {m} gab es schon', {
            n: groups.created.length,
            m: groups.skipped.length,
          })}
        </li>
      </ul>
    </div>
  );
}
