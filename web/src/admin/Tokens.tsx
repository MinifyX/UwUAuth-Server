import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Ago, Badge, Day, Empty, Loading, SecretOnce } from '../components/bits';
import { FormError, Toggle } from '../components/controls';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { PageTitle } from '../components/Shell';
import { api, seg } from '../lib/api';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import type { ApiToken } from '../lib/types';
import { Confirm } from '../portal/Security';

/** Tokens for scripts: they act as an admin, so each is shown once and can be taken back. */
export function Tokens() {
  useLanguage();
  const [list, setList] = useState<ApiToken[] | null>(null);
  const [creating, setCreating] = useState(false);
  const [removing, setRemoving] = useState<ApiToken | null>(null);
  const load = useCallback(() => {
    api<ApiToken[]>('/uwu/v1/tokens').then(setList, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(load, [load]);

  return (
    <>
      <PageTitle
        actions={
          <button type="button" className="primary" onClick={() => setCreating(true)}>
            <Icon name="plus" />
            {t('Token erstellen')}
          </button>
        }
      >
        {t('API-Tokens')}
      </PageTitle>
      <p className="muted page-lead">
        {t(
          'Für Skripte und Automatisierungen: Ein Token wird als „Authorization: Bearer …“ mitgeschickt und darf, was ein Admin darf – oder nur lesen.',
        )}
      </p>
      {!list && <Loading />}
      {list?.length === 0 && <Empty scene="sleepy">{t('Noch keine Tokens.')}</Empty>}
      {list && list.length > 0 && (
        <ul className="item-list card">
          {list.map((token) => (
            <li key={token.id} className="item">
              <span className="item-icon">
                <Icon name="code" />
              </span>
              <span className="item-text">
                <b>
                  {token.name}
                  {token.readOnly && <Badge>{t('nur lesen')}</Badge>}
                </b>
                <small>
                  {t('Erstellt')} <Day iso={token.created} /> ·{' '}
                  <Ago iso={token.lastUsed} prefix={t('zuletzt benutzt')} />
                  {token.expires && (
                    <>
                      {' · '}
                      {t('läuft ab')} <Day iso={token.expires} />
                    </>
                  )}
                </small>
              </span>
              <button
                type="button"
                className="quiet danger-text"
                onClick={() => setRemoving(token)}
              >
                {t('Löschen')}
              </button>
            </li>
          ))}
        </ul>
      )}
      {creating && (
        <CreateToken
          onClose={() => {
            setCreating(false);
            load();
          }}
        />
      )}
      {removing && (
        <Confirm
          title={t('Token „{name}“ löschen?', { name: removing.name })}
          lead={t('Skripte, die es benutzen, bekommen danach keinen Zugriff mehr.')}
          confirm={t('Löschen')}
          onCancel={() => setRemoving(null)}
          action={async () => {
            await api(`/uwu/v1/tokens/${seg(removing.id)}`, { method: 'DELETE' });
            setRemoving(null);
            load();
          }}
        />
      )}
    </>
  );
}

function CreateToken({ onClose }: { onClose: () => void }) {
  useLanguage();
  const [name, setName] = useState('');
  const [readOnly, setReadOnly] = useState(true);
  const [days, setDays] = useState('');
  const [secret, setSecret] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const make = async (event?: FormEvent) => {
    event?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const token = await api<ApiToken>('/uwu/v1/tokens', {
        body: { name: name.trim(), readOnly, days: days ? Number(days) : undefined },
      });
      setSecret(token.secret ?? '');
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t('Token erstellen')}
      onCancel={() => !busy && onClose()}
      footer={
        <>
          <span className="spacer" />
          {secret ? (
            <button type="button" className="primary" onClick={onClose}>
              {t('Fertig')}
            </button>
          ) : (
            <>
              <button type="button" data-secondary onClick={onClose} disabled={busy}>
                {t('Abbrechen')}
              </button>
              <button
                type="button"
                className="primary"
                disabled={busy || !name.trim()}
                onClick={() => void make()}
              >
                {t('Erstellen')}
              </button>
            </>
          )}
        </>
      }
    >
      {secret ? (
        <>
          <p className="dialog-lead">
            {t('Du siehst das Token nur jetzt. Kopier es gleich in dein Skript.')}
          </p>
          <SecretOnce value={secret} />
        </>
      ) : (
        <form className="form" onSubmit={make}>
          <label className="field">
            <span>{t('Wofür ist es?')}</span>
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('z. B. Backup-Skript')}
              maxLength={80}
              autoFocus
            />
          </label>
          <label className="check">
            <Toggle label={t('Nur lesen')} checked={readOnly} onChange={setReadOnly} />
            <span>{t('Nur lesen – ändern darf es nichts')}</span>
          </label>
          <label className="field">
            <span>{t('Läuft ab nach … Tagen (leer: nie)')}</span>
            <input
              type="number"
              min={1}
              value={days}
              onChange={(e) => setDays(e.target.value)}
              className="number-input"
            />
          </label>
          <FormError error={error} />
        </form>
      )}
    </Modal>
  );
}
