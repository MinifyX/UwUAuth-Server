import { useEffect, useState } from 'react';
import { Empty, Loading } from '../components/bits';
import { Toggle, useAction } from '../components/controls';
import { Icon } from '../components/Icon';
import { PageTitle } from '../components/Shell';
import { api } from '../lib/api';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import type { AttributeDef, AttributeKind } from '../lib/types';

type Draft = AttributeDef & { choicesText: string };

const toDraft = (def: AttributeDef): Draft => ({ ...def, choicesText: def.choices.join(', ') });

/**
 * Extra fields every person has: a room number, a birthday, a department. Apps get them later
 * through OpenID Connect and LDAP; people may fill in the ones marked for them.
 */
export function Attributes() {
  useLanguage();
  const [saved, setSaved] = useState<AttributeDef[] | null>(null);
  const [rows, setRows] = useState<Draft[]>([]);
  const [run, busy] = useAction();
  useEffect(() => {
    api<AttributeDef[]>('/uwu/v1/attributes').then(
      (defs) => {
        setSaved(defs);
        setRows(defs.map(toDraft));
      },
      (e) => toast(errorText(e), 'error'),
    );
  }, []);
  if (!saved) return <Loading />;

  const change = (index: number, patch: Partial<Draft>) =>
    setRows(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));
  const body = rows.map((row) => ({
    name: row.name.trim(),
    label: row.label.trim(),
    kind: row.kind,
    choices:
      row.kind === 'choice'
        ? row.choicesText
            .split(',')
            .map((choice) => choice.trim())
            .filter(Boolean)
        : [],
    selfEditable: row.selfEditable,
  }));
  const dirty =
    JSON.stringify(body) !==
    JSON.stringify(
      saved.map((def) => ({ ...def, choices: def.kind === 'choice' ? def.choices : [] })),
    );

  return (
    <>
      <PageTitle>{t('Zusätzliche Felder')}</PageTitle>
      <p className="muted page-lead">
        {t(
          'Felder, die jede Person hat – etwa Zimmer, Geburtstag oder Abteilung. Apps bekommen sie später über OpenID Connect und LDAP. Der Name ist für Apps (kleine Buchstaben, Ziffern, Unterstriche), die Bezeichnung für Menschen.',
        )}
      </p>
      {rows.length === 0 && <Empty scene="sleepy">{t('Noch keine zusätzlichen Felder.')}</Empty>}
      <div className="attribute-rows">
        {rows.map((row, index) => (
          <div className="attribute-row card" key={index}>
            <label className="field">
              <span>{t('Bezeichnung')}</span>
              <input
                value={row.label}
                onChange={(e) => change(index, { label: e.target.value })}
                placeholder={t('z. B. Zimmer')}
              />
            </label>
            <label className="field">
              <span>{t('Name für Apps')}</span>
              <input
                value={row.name}
                onChange={(e) => change(index, { name: e.target.value.toLowerCase() })}
                placeholder="room"
                spellCheck={false}
                autoCapitalize="none"
              />
            </label>
            <label className="field">
              <span>{t('Art')}</span>
              <select
                value={row.kind}
                onChange={(e) => change(index, { kind: e.target.value as AttributeKind })}
              >
                <option value="text">{t('Text')}</option>
                <option value="number">{t('Zahl')}</option>
                <option value="date">{t('Datum')}</option>
                <option value="choice">{t('Auswahl')}</option>
              </select>
            </label>
            {row.kind === 'choice' && (
              <label className="field wide">
                <span>{t('Auswahl, mit Komma getrennt')}</span>
                <input
                  value={row.choicesText}
                  onChange={(e) => change(index, { choicesText: e.target.value })}
                  placeholder={t('z. B. Rot, Grün, Blau')}
                />
              </label>
            )}
            <label className="check">
              <Toggle
                label={t('Selbst ausfüllen')}
                checked={row.selfEditable}
                onChange={(selfEditable) => change(index, { selfEditable })}
              />
              <span>{t('Jede Person darf es selbst ausfüllen')}</span>
            </label>
            <button
              type="button"
              className="icon-button remove-row"
              title={t('Feld entfernen')}
              aria-label={t('Feld entfernen')}
              onClick={() => setRows(rows.filter((_, i) => i !== index))}
            >
              <Icon name="trash" />
            </button>
          </div>
        ))}
      </div>
      <div className="form-actions">
        <button
          type="button"
          onClick={() =>
            setRows([
              ...rows,
              {
                name: '',
                label: '',
                kind: 'text',
                choices: [],
                selfEditable: false,
                choicesText: '',
              },
            ])
          }
        >
          <Icon name="plus" />
          {t('Feld hinzufügen')}
        </button>
        <span className="spacer" />
        {dirty && (
          <button type="button" data-secondary onClick={() => setRows(saved.map(toDraft))}>
            {t('Verwerfen')}
          </button>
        )}
        <button
          type="button"
          className="primary"
          disabled={!dirty || busy || body.some((row) => !row.name)}
          onClick={() =>
            void run(async () => {
              const defs = await api<AttributeDef[]>('/uwu/v1/attributes', {
                method: 'PUT',
                body,
              });
              setSaved(defs);
              setRows(defs.map(toDraft));
              toast(t('Gespeichert ✧'));
            })
          }
        >
          {t('Speichern')}
        </button>
      </div>
      {rows.length < saved.length && (
        <p className="field-hint" data-tone="warn">
          {t('Ein entferntes Feld nimmt beim Speichern seine Werte bei allen Personen mit.')}
        </p>
      )}
    </>
  );
}
