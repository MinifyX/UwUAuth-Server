import { useCallback, useEffect, useState } from 'react';
import { CopyField, Loading } from '../components/bits';
import { FormError, Section } from '../components/controls';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { Picker, type Choice } from '../components/Picker';
import { Qr } from '../components/Qr';
import { api, seg } from '../lib/api';
import { copy } from '../lib/clipboard';
import { errorText } from '../lib/errors';
import { when } from '../lib/format';
import { t, useLanguage } from '../lib/i18n';
import { go } from '../lib/route';
import { toast } from '../lib/toast';
import type { Group, PairingCode } from '../lib/types';
import { groupName } from '../lib/words';
import { Confirm } from '../portal/Security';

/** How often the dialog asks whether an app took the code. */
const POLL_MS = 2000;

function groupChoices(groups: Group[]): Choice[] {
  return groups
    .filter((group) => group.builtin !== 'everyone')
    .map((group) => ({ id: group.id, label: groupName(group), kind: 'group' }));
}

/** The groups' names for a list of ids, for one line of text. */
function names(groups: Group[], ids: string[]): string {
  return ids
    .map((id) => groups.find((group) => group.id === id))
    .filter((group): group is Group => !!group)
    .map(groupName)
    .join(', ');
}

/**
 * "Pair a UwUSuite app": who may use it and who is its admin, then a code (and QR code) to type
 * into the app. The dialog waits for the app to take it and then leads to the app's page.
 */
export function PairDialog({ onClose }: { onClose: () => void }) {
  useLanguage();
  const [groups, setGroups] = useState<Group[]>([]);
  const [allowed, setAllowed] = useState<string[]>([]);
  const [admins, setAdmins] = useState<string[]>([]);
  const [code, setCode] = useState<PairingCode | null>(null);
  const [state, setState] = useState<PairingCode | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<Group[]>('/uwu/v1/groups').then(setGroups, () => undefined);
  }, []);

  // While the code is shown: has an app taken it?
  useEffect(() => {
    if (!code) return;
    let stopped = false;
    const timer = window.setInterval(() => {
      api<PairingCode>(`/uwu/v1/pairing-codes/${seg(code.id)}`).then(
        (next) => {
          if (stopped) return;
          setState(next);
          if (!next.open) window.clearInterval(timer);
        },
        () => undefined,
      );
    }, POLL_MS);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [code]);

  const make = async () => {
    setBusy(true);
    setError(null);
    try {
      const made = await api<PairingCode>('/uwu/v1/pairing-codes', {
        body: {
          allowedGroups: allowed,
          roleGroups: admins.length > 0 ? { admin: admins } : {},
        },
      });
      setState(null);
      setCode(made);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const withdraw = async () => {
    if (!code) return;
    try {
      await api(`/uwu/v1/pairing-codes/${seg(code.id)}`, { method: 'DELETE' });
    } catch (e) {
      toast(errorText(e), 'error');
    }
    onClose();
  };

  const paired = state?.app ?? null;
  const gone = !!state && !state.open && !paired;
  let footer;
  if (paired)
    footer = (
      <>
        <span className="spacer" />
        <button type="button" data-secondary onClick={onClose}>
          {t('Schließen')}
        </button>
        <button type="button" className="primary" onClick={() => go(`/apps/${paired.id}`)}>
          {t('Zur App')}
        </button>
      </>
    );
  else if (code)
    footer = (
      <>
        {!gone && (
          <button
            type="button"
            data-secondary
            className="danger-text"
            onClick={() => void withdraw()}
          >
            {t('Code zurückziehen')}
          </button>
        )}
        <span className="spacer" />
        {gone && (
          <button type="button" onClick={() => void make()} disabled={busy}>
            {t('Neuer Code')}
          </button>
        )}
        <button type="button" className="primary" onClick={onClose}>
          {t('Schließen')}
        </button>
      </>
    );
  else
    footer = (
      <>
        <span className="spacer" />
        <button type="button" data-secondary onClick={onClose} disabled={busy}>
          {t('Abbrechen')}
        </button>
        <button type="button" className="primary" disabled={busy} onClick={() => void make()}>
          {t('Code erstellen')}
        </button>
      </>
    );

  return (
    <Modal title={t('UwUSuite-App koppeln')} onCancel={onClose} footer={footer}>
      {paired ? (
        <div className="pairing-done">
          <Icon name="check" size={28} />
          <p className="dialog-lead">
            {t(
              '„{name}“ ist gekoppelt. Wer darf, meldet sich dort jetzt mit dem UwUAuth-Konto an.',
              {
                name: paired.name,
              },
            )}
          </p>
        </div>
      ) : code ? (
        <div className="link-share">
          <p className="dialog-lead">
            {t(
              'In der Suite-App unter „Mit UwUAuth verbinden“ diese Adresse und den Code eintragen – oder den QR-Code scannen.',
            )}
          </p>
          <div className="field">
            <span>{t('Adresse')}</span>
            <CopyField value={location.origin} label={t('Adresse')} />
          </div>
          <div className="field">
            <span>{t('Kopplungscode')}</span>
            <div className="pairing-code-line">
              <code className="pairing-code">{code.code}</code>
              <button type="button" onClick={() => void copy(code.code ?? '')}>
                <Icon name="copy" />
                {t('Kopieren')}
              </button>
            </div>
          </div>
          {code.link && <Qr value={code.link} size="big" label={t('QR-Code zum Koppeln')} />}
          {gone ? (
            <p className="form-error">{t('Der Code gilt nicht mehr. Mach einen neuen.')}</p>
          ) : (
            <p className="field-hint">
              {t('Gilt einmal, bis {when}. Dieses Fenster merkt, wenn die App ihn benutzt.', {
                when: when(code.expires),
              })}
            </p>
          )}
        </div>
      ) : (
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            void make();
          }}
        >
          <p className="dialog-lead">
            {t(
              'UwUMail, UwULock und die anderen Programme der UwUSuite verbinden sich mit einem Code: Sie bekommen Anmeldung per OpenID Connect und die Personen per SCIM, ohne dass du etwas abtippen musst.',
            )}
          </p>
          <div className="field">
            <span>{t('Wer darf die App benutzen?')}</span>
            <Picker
              label={t('Wer darf die App benutzen?')}
              choices={groupChoices(groups)}
              picked={allowed}
              onChange={setAllowed}
              empty={t('Alle dürfen.')}
            />
          </div>
          <div className="field">
            <span>{t('Wer ist dort Admin?')}</span>
            <Picker
              label={t('Wer ist dort Admin?')}
              choices={groupChoices(groups)}
              picked={admins}
              onChange={setAdmins}
              empty={t('Niemand über UwUAuth.')}
            />
            <small className="field-hint">
              {t('Weitere Rollen der App stellst du nach dem Koppeln auf ihrer Seite ein.')}
            </small>
          </div>
          <FormError error={error} />
        </form>
      )}
    </Modal>
  );
}

/** Codes that were made and not used yet, to withdraw. Nothing when there are none. */
export function OpenCodes({ version }: { version: number }) {
  useLanguage();
  const [list, setList] = useState<PairingCode[] | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [removing, setRemoving] = useState<PairingCode | null>(null);
  const load = useCallback(() => {
    api<PairingCode[]>('/uwu/v1/pairing-codes').then(setList, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(load, [load, version]);
  useEffect(() => {
    api<Group[]>('/uwu/v1/groups').then(setGroups, () => undefined);
  }, []);
  if (!list) return <Loading />;
  if (list.length === 0) return null;
  return (
    <Section
      title={t('Offene Kopplungscodes')}
      lead={t(
        'Jeder gilt einmal und 15 Minuten. Einen, den niemand mehr braucht, ziehst du zurück.',
      )}
    >
      <ul className="item-list">
        {list.map((code) => (
          <li key={code.id} className="item">
            <span className="item-icon">
              <Icon name="link" />
            </span>
            <span className="item-text">
              <b>{t('gilt bis {when}', { when: when(code.expires) })}</b>
              <small>
                {code.allowedGroups.length > 0
                  ? t('für {groups}', { groups: names(groups, code.allowedGroups) })
                  : t('für alle')}
              </small>
            </span>
            <button type="button" className="quiet danger-text" onClick={() => setRemoving(code)}>
              {t('Zurückziehen')}
            </button>
          </li>
        ))}
      </ul>
      {removing && (
        <Confirm
          title={t('Kopplungscode zurückziehen?')}
          lead={t('Keine App kann sich dann noch damit koppeln.')}
          confirm={t('Zurückziehen')}
          onCancel={() => setRemoving(null)}
          action={async () => {
            await api(`/uwu/v1/pairing-codes/${seg(removing.id)}`, { method: 'DELETE' });
            setRemoving(null);
            load();
          }}
        />
      )}
    </Section>
  );
}
