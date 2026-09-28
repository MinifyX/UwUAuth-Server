import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Badge, Day, Empty, LinkShare, Loading } from '../components/bits';
import { FormError, Segmented, Toggle, useAction } from '../components/controls';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { Picker } from '../components/Picker';
import { PageTitle } from '../components/Shell';
import { api, seg } from '../lib/api';
import { errorText } from '../lib/errors';
import { language, t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import type { Group, Invitation, Me, Person } from '../lib/types';
import { groupName, word } from '../lib/words';
import { Confirm } from '../portal/Security';

/**
 * Invitations: a link (and its QR code) that makes one account, with its groups and role chosen
 * beforehand. By mail when there is an address and mail; the link is shown either way, once.
 */
export function Invitations({ me }: { me: Me }) {
  useLanguage();
  const [list, setList] = useState<Invitation[] | null>(null);
  const [groups, setGroups] = useState<Group[]>([]);
  const [people, setPeople] = useState<Person[]>([]);
  const [creating, setCreating] = useState(false);
  const [shown, setShown] = useState<Invitation | null>(null);
  const [removing, setRemoving] = useState<Invitation | null>(null);
  const [run, busy] = useAction();
  const load = useCallback(() => {
    api<Invitation[]>('/uwu/v1/invitations').then(setList, (e) => toast(errorText(e), 'error'));
  }, []);
  useEffect(load, [load]);
  useEffect(() => {
    api<Group[]>('/uwu/v1/groups').then(setGroups, () => undefined);
    api<Person[]>('/uwu/v1/people').then(setPeople, () => undefined);
  }, []);
  const name = (id: string | null) => people.find((person) => person.id === id)?.displayName;
  const groupLabel = (id: string) => {
    const group = groups.find((other) => other.id === id);
    return group ? groupName(group) : '?';
  };

  return (
    <>
      <PageTitle
        actions={
          <button type="button" className="primary" onClick={() => setCreating(true)}>
            <Icon name="plus" />
            {t('Einladen')}
          </button>
        }
      >
        {t('Einladungen')}
      </PageTitle>
      <p className="muted page-lead">
        {t(
          'Wer eingeladen ist, legt sein Konto selbst an – mit Passkey oder Passwort. Gruppen und Rechte hast du vorher festgelegt.',
        )}
      </p>
      {!list && <Loading />}
      {list && list.length === 0 && <Empty scene="invite">{t('Keine offenen Einladungen.')}</Empty>}
      {list && list.length > 0 && (
        <ul className="item-list card">
          {list.map((invitation) => (
            <li
              key={invitation.id}
              className="item"
              data-disabled={invitation.expired || undefined}
            >
              <span className="item-icon">
                <Icon name="mail" />
              </span>
              <span className="item-text">
                <b>
                  {invitation.displayName || invitation.email || t('Einladung ohne Namen')}
                  {invitation.admin && <Badge>{t('Admin')}</Badge>}
                  {invitation.managed && <Badge>{word(me.server.mode, 'managedAccount')}</Badge>}
                  {invitation.expired && <Badge tone="alarm">{t('abgelaufen')}</Badge>}
                </b>
                <small>
                  {[
                    invitation.email && invitation.displayName ? invitation.email : null,
                    invitation.groups.length ? invitation.groups.map(groupLabel).join(', ') : null,
                    invitation.createdBy
                      ? t('von {name}', { name: name(invitation.createdBy) ?? t('jemandem') })
                      : t('von der Kommandozeile'),
                  ]
                    .filter(Boolean)
                    .join(' · ')}
                  {' · '}
                  {t('gilt bis')} <Day iso={invitation.expires} />
                </small>
              </span>
              <span className="row-buttons">
                <button
                  type="button"
                  disabled={busy}
                  onClick={() =>
                    void run(async () => {
                      const renewed = await api<Invitation>(
                        `/uwu/v1/invitations/${seg(invitation.id)}/renew`,
                        { body: { mail: false } },
                      );
                      setShown(renewed);
                      load();
                    })
                  }
                >
                  {t('Neuer Link')}
                </button>
                <button
                  type="button"
                  className="quiet danger-text"
                  onClick={() => setRemoving(invitation)}
                >
                  {t('Zurückziehen')}
                </button>
              </span>
            </li>
          ))}
        </ul>
      )}
      {creating && (
        <CreateInvitation
          me={me}
          groups={groups}
          people={people}
          onCancel={() => setCreating(false)}
          onDone={(made) => {
            setCreating(false);
            setShown(made);
            load();
          }}
        />
      )}
      {shown?.link && (
        <Modal
          title={t('Die Einladung ist fertig ✧')}
          onCancel={() => setShown(null)}
          footer={
            <>
              <span className="spacer" />
              <button type="button" className="primary" onClick={() => setShown(null)}>
                {t('Fertig')}
              </button>
            </>
          }
        >
          <LinkShare
            link={shown.link}
            expires={shown.expires}
            mailed={shown.mailed}
            lead={t(
              'Du siehst den Link nur jetzt. Schick ihn weiter oder lass den QR-Code scannen – er funktioniert einmal.',
            )}
          />
        </Modal>
      )}
      {removing && (
        <Confirm
          title={t('Einladung zurückziehen?')}
          lead={t('Der Link funktioniert danach nicht mehr.')}
          confirm={t('Zurückziehen')}
          onCancel={() => setRemoving(null)}
          action={async () => {
            await api(`/uwu/v1/invitations/${seg(removing.id)}`, { method: 'DELETE' });
            setRemoving(null);
            load();
          }}
        />
      )}
    </>
  );
}

function CreateInvitation({
  me,
  groups,
  people,
  onCancel,
  onDone,
}: {
  me: Me;
  groups: Group[];
  people: Person[];
  onCancel: () => void;
  onDone: (invitation: Invitation) => void;
}) {
  useLanguage();
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [picked, setPicked] = useState<string[]>([]);
  const [admin, setAdmin] = useState(false);
  const [managed, setManaged] = useState(false);
  const [managers, setManagers] = useState<string[]>([me.id]);
  const [lang, setLang] = useState<'de' | 'en'>(language());
  const [mail, setMail] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mode = me.server.mode;
  const canMail = me.server.mail && email.includes('@');

  const submit = async (event?: FormEvent) => {
    event?.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const made = await api<Invitation>('/uwu/v1/invitations', {
        body: {
          email: email.trim() || undefined,
          displayName: displayName.trim() || undefined,
          groups: picked,
          admin,
          managed,
          managers: managed ? managers : [],
          language: lang,
          mail: canMail && mail,
        },
      });
      onDone(made);
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };

  return (
    <Modal
      title={t('Jemanden einladen')}
      size="wide"
      onCancel={() => !busy && onCancel()}
      footer={
        <>
          <span className="spacer" />
          <button type="button" data-secondary onClick={onCancel} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button type="button" className="primary" disabled={busy} onClick={() => void submit()}>
            {canMail && mail ? t('Einladung schicken') : t('Link erstellen')}
          </button>
        </>
      }
    >
      <form className="form" onSubmit={submit}>
        <div className="field-pair">
          <label className="field">
            <span>{t('Name (freiwillig)')}</span>
            <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} autoFocus />
          </label>
          <label className="field">
            <span>{t('E-Mail-Adresse (freiwillig)')}</span>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </label>
        </div>
        {canMail && (
          <label className="check">
            <Toggle label={t('Per Mail schicken')} checked={mail} onChange={setMail} />
            <span>{t('Per Mail schicken – den Link siehst du trotzdem')}</span>
          </label>
        )}
        {!me.server.mail && (
          <p className="field-hint">
            {t('Ohne Mail-Einrichtung bekommst du einen Link und einen QR-Code zum Weitergeben.')}
          </p>
        )}
        <div className="field">
          <span>{t('Gruppen')}</span>
          <Picker
            label={t('Gruppen')}
            choices={groups
              .filter((group) => !group.builtin)
              .map((group) => ({ id: group.id, label: groupName(group), kind: 'group' as const }))}
            picked={picked}
            onChange={setPicked}
            empty={t('Keine.')}
          />
        </div>
        <div className="field">
          <span>{t('Sprache')}</span>
          <Segmented
            label={t('Sprache')}
            value={lang}
            onChange={setLang}
            options={[
              { value: 'de', label: 'Deutsch' },
              { value: 'en', label: 'English' },
            ]}
          />
        </div>
        <label className="check">
          <Toggle label={t('Admin')} checked={admin} onChange={setAdmin} />
          <span>{t('Als Admin: darf alles im Admin-Portal')}</span>
        </label>
        <label className="check">
          <Toggle label={word(mode, 'managedAccount')} checked={managed} onChange={setManaged} />
          <span>{word(mode, 'managedAccount')}</span>
        </label>
        {managed && (
          <div className="field">
            <span>{t('Wer sich darum kümmert')}</span>
            <Picker
              label={word(mode, 'managers')}
              choices={people
                .filter((person) => !person.deleted)
                .map((person) => ({
                  id: person.id,
                  label: person.displayName,
                  sub: person.username,
                  avatar: person.avatar,
                }))}
              picked={managers}
              onChange={setManagers}
            />
          </div>
        )}
        <FormError error={error} />
      </form>
    </Modal>
  );
}
