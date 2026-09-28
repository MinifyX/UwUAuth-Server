import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { AttributeInput } from '../components/AttributeInput';
import { Ago, Avatar, Badge, Day, LinkShare, Loading } from '../components/bits';
import { FormError, Row, Section, Segmented, Toggle, useAction } from '../components/controls';
import { EventList } from '../components/EventList';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { PasswordInput } from '../components/PasswordInput';
import { Picker, type Choice } from '../components/Picker';
import { WindowsEditor } from '../components/WindowsEditor';
import { api, seg } from '../lib/api';
import { squareJpeg } from '../lib/avatar';
import { errorText } from '../lib/errors';
import { t, useLanguage } from '../lib/i18n';
import { toast } from '../lib/toast';
import type {
  AttributeDef,
  Group,
  LinkResult,
  Me,
  Person,
  PersonDetail as Detail,
} from '../lib/types';
import { groupName, word } from '../lib/words';
import { SessionList } from '../portal/Devices';
import { Confirm } from '../portal/Security';

type Dialog =
  | { kind: 'link' }
  | { kind: 'password' }
  | { kind: 'disable' }
  | { kind: 'trash' }
  | { kind: 'purge' }
  | { kind: 'totp' }
  | { kind: 'passkey'; id: string; name: string }
  | { kind: 'sessions' }
  | null;

/**
 * One person, with everything the one looking may do: an admin everything, somebody who looks
 * after them (a parent) the names, the picture, a password or a setup link, second factors,
 * sessions, time windows and what happened.
 */
export function PersonDetail({ id, me, onBack }: { id: string; me: Me; onBack: () => void }) {
  useLanguage();
  const [person, setPerson] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [people, setPeople] = useState<Person[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [defs, setDefs] = useState<AttributeDef[]>([]);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [run, busy] = useAction();

  const load = useCallback(() => {
    api<Detail>(`/uwu/v1/people/${seg(id)}`).then(setPerson, (e) => setError(errorText(e)));
  }, [id]);
  useEffect(load, [load]);
  useEffect(() => {
    api<Person[]>('/uwu/v1/people').then(setPeople, () => undefined);
    if (me.admin) {
      api<Group[]>('/uwu/v1/groups').then(setGroups, () => undefined);
      api<AttributeDef[]>('/uwu/v1/attributes').then(setDefs, () => undefined);
    }
  }, [me.admin]);

  if (error)
    return (
      <>
        <BackButton onBack={onBack} />
        <p className="form-error">{error}</p>
      </>
    );
  if (!person) return <Loading />;

  const all = person.canEdit === 'all';
  const mode = me.server.mode;
  const base = `/uwu/v1/people/${seg(person.id)}`;
  const self = person.id === me.id;
  const names = (other: string | null) =>
    other === person.id
      ? person.displayName
      : (people.find((p) => p.id === other)?.displayName ??
        (other === me.id ? me.displayName : t('jemand')));
  const close = () => setDialog(null);
  const changed = async (message?: string) => {
    setDialog(null);
    load();
    if (message) toast(message);
  };
  const setup = !person.hasPassword && person.passkeys.length === 0;

  return (
    <>
      <BackButton onBack={onBack} />
      <div className="person-head">
        <PictureButton person={person} base={base} onChanged={load} />
        <div className="person-title">
          <h1 className="page-title">{person.displayName}</h1>
          <p className="muted">
            {person.username}
            {person.email ? ` · ${person.email}` : ''}
          </p>
          <span className="badges">
            {person.admin && <Badge>{t('Admin')}</Badge>}
            {person.managed && <Badge>{word(mode, 'managedAccount')}</Badge>}
            {person.disabled && <Badge tone="alarm">{t('gesperrt')}</Badge>}
            {person.deleted && <Badge tone="alarm">{t('im Papierkorb')}</Badge>}
            {setup && <Badge>{t('noch nicht eingerichtet')}</Badge>}
            {self && <Badge>{t('du')}</Badge>}
          </span>
        </div>
      </div>

      <div className="action-bar">
        {!person.deleted && (
          <>
            <button type="button" className="primary" onClick={() => setDialog({ kind: 'link' })}>
              <Icon name="qr" />
              {setup ? t('Einrichtungslink') : t('Link für neues Passwort')}
            </button>
            <button type="button" onClick={() => setDialog({ kind: 'password' })}>
              <Icon name="lock" />
              {t('Passwort setzen')}
            </button>
            {person.disabled ? (
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  void run(async () => {
                    await api(`${base}/enable`, { body: {} });
                    await changed(t('Wieder freigegeben ✧'));
                  })
                }
              >
                <Icon name="unlock" />
                {t('Freigeben')}
              </button>
            ) : (
              <button type="button" disabled={self} onClick={() => setDialog({ kind: 'disable' })}>
                <Icon name="stop" />
                {t('Sperren')}
              </button>
            )}
          </>
        )}
        {all && !person.deleted && (
          <button
            type="button"
            className="danger"
            disabled={self}
            onClick={() => setDialog({ kind: 'trash' })}
          >
            <Icon name="trash" />
            {t('In den Papierkorb')}
          </button>
        )}
        {all && person.deleted && (
          <>
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() =>
                void run(async () => {
                  await api(`${base}/restore`, { body: {} });
                  await changed(t('Zurückgeholt ✧'));
                })
              }
            >
              <Icon name="refresh" />
              {t('Wiederherstellen')}
            </button>
            <button type="button" className="danger" onClick={() => setDialog({ kind: 'purge' })}>
              <Icon name="trash" />
              {t('Endgültig löschen')}
            </button>
          </>
        )}
      </div>

      <DetailsSection
        person={person}
        all={all}
        mode={mode}
        base={base}
        onSaved={() => void changed(t('Gespeichert ✧'))}
      />

      <Section title={t('Anmeldung')}>
        <Row label={t('Passwort')} description={person.hasPassword ? t('Gesetzt.') : t('Keins.')} />
        <Row
          label={t('Passkeys')}
          description={
            person.passkeys.length === 0
              ? t('Keine.')
              : t('{n} Stück.', { n: person.passkeys.length })
          }
        />
        {person.passkeys.length > 0 && (
          <ul className="item-list compact">
            {person.passkeys.map((passkey) => (
              <li key={passkey.id} className="item">
                <span className="item-icon">
                  <Icon name="key" />
                </span>
                <span className="item-text">
                  <b>{passkey.name}</b>
                  <small>
                    {t('Angelegt')} <Day iso={passkey.created} /> ·{' '}
                    <Ago iso={passkey.lastUsed} prefix={t('zuletzt benutzt')} />
                  </small>
                </span>
                <button
                  type="button"
                  className="quiet danger-text"
                  onClick={() => setDialog({ kind: 'passkey', id: passkey.id, name: passkey.name })}
                >
                  {t('Entfernen')}
                </button>
              </li>
            ))}
          </ul>
        )}
        <Row
          label={t('Authenticator-App')}
          description={
            person.hasTotp
              ? t('Eingerichtet. Wiederherstellungscodes: noch {n}.', {
                  n: person.recoveryCodesLeft,
                })
              : t('Nicht eingerichtet.')
          }
        >
          {person.hasTotp && (
            <button type="button" className="danger" onClick={() => setDialog({ kind: 'totp' })}>
              {t('Entfernen')}
            </button>
          )}
        </Row>
        <Row
          label={t('App-Passwörter')}
          description={
            person.appPasswords === 0
              ? t('Keine.')
              : t('{n} Stück. Die Person verwaltet sie selbst.', { n: person.appPasswords })
          }
        />
      </Section>

      {all && (
        <GroupsSection
          person={person}
          groups={groups}
          base={base}
          onSaved={() => void changed(t('Gespeichert ✧'))}
        />
      )}
      {all && (
        <CareSection
          person={person}
          people={people}
          groups={groups}
          mode={mode}
          base={base}
          onSaved={() => void changed(t('Gespeichert ✧'))}
        />
      )}

      <Section
        title={t('Zeitfenster')}
        lead={t(
          'Wann sich {name} bei Apps anmelden darf, die über UwUAuth angemeldet werden – das gilt ab der nächsten Version von UwUAuth. Keine Zeitfenster heißt: jederzeit.',
          { name: person.displayName },
        )}
      >
        <WindowsEditor
          key={JSON.stringify(person.windows)}
          windows={person.windows}
          onSave={async (windows) => {
            await api(`${base}/windows`, { method: 'PUT', body: windows });
            await changed(t('Gespeichert ✧'));
          }}
        />
      </Section>

      {all && defs.length > 0 && (
        <AttributesSection
          person={person}
          defs={defs}
          base={base}
          onSaved={() => void changed(t('Gespeichert ✧'))}
        />
      )}
      {all && (
        <PosixSection
          person={person}
          base={base}
          onSaved={() => void changed(t('Gespeichert ✧'))}
        />
      )}

      <Section
        title={t('Geräte')}
        actions={
          person.sessions.length > 0 && (
            <button type="button" onClick={() => setDialog({ kind: 'sessions' })}>
              {t('Überall abmelden')}
            </button>
          )
        }
      >
        <SessionList
          sessions={person.sessions}
          busy={busy}
          onEnd={(session) =>
            void run(async () => {
              await api(`${base}/sessions/${seg(session.id)}`, { method: 'DELETE' });
              await changed(t('Abgemeldet.'));
            })
          }
        />
      </Section>

      <Section title={t('Verlauf')}>
        <EventList path={`${base}/events`} names={names} />
      </Section>

      {dialog?.kind === 'link' && (
        <LinkDialog
          person={person}
          base={base}
          mail={me.server.mail}
          onClose={() => void changed()}
        />
      )}
      {dialog?.kind === 'password' && (
        <SetPasswordDialog
          person={person}
          base={base}
          minLength={me.server.passwordMinLength}
          onCancel={close}
          onDone={() => void changed(t('Passwort gesetzt ✧'))}
        />
      )}
      {dialog?.kind === 'disable' && (
        <Confirm
          title={t('{name} sperren?', { name: person.displayName })}
          lead={t(
            '{name} wird überall abgemeldet und kann sich nicht mehr anmelden, bis du das Konto wieder freigibst.',
            { name: person.displayName },
          )}
          confirm={t('Sperren')}
          onCancel={close}
          action={async () => {
            await api(`${base}/disable`, { body: {} });
            await changed(t('Gesperrt.'));
          }}
        />
      )}
      {dialog?.kind === 'trash' && (
        <Confirm
          title={t('{name} in den Papierkorb legen?', { name: person.displayName })}
          lead={t(
            'Das Konto hört sofort auf zu funktionieren. Aus dem Papierkorb kannst du es zurückholen oder endgültig löschen.',
          )}
          confirm={t('In den Papierkorb')}
          onCancel={close}
          action={async () => {
            await api(base, { method: 'DELETE' });
            await changed(t('Im Papierkorb.'));
          }}
        />
      )}
      {dialog?.kind === 'purge' && (
        <Confirm
          title={t('{name} endgültig löschen?', { name: person.displayName })}
          lead={t('Das Konto und alles dazu verschwindet. Das lässt sich nicht rückgängig machen.')}
          confirm={t('Endgültig löschen')}
          onCancel={close}
          action={async () => {
            await api(`${base}/purge`, { method: 'DELETE' });
            toast(t('Gelöscht.'));
            onBack();
          }}
        />
      )}
      {dialog?.kind === 'totp' && (
        <Confirm
          title={t('Authenticator-App entfernen?')}
          lead={t(
            'Für ein verlorenes Handy: Die App und die Wiederherstellungscodes von {name} gelten danach nicht mehr. Mach das nur, wenn du sicher bist, dass wirklich {name} fragt.',
            { name: person.displayName },
          )}
          confirm={t('Entfernen')}
          onCancel={close}
          action={async () => {
            await api(`${base}/totp`, { method: 'DELETE' });
            await changed(t('Entfernt.'));
          }}
        />
      )}
      {dialog?.kind === 'passkey' && (
        <Confirm
          title={t('Passkey entfernen?')}
          lead={t('„{name}“ kann {person} danach nicht mehr anmelden.', {
            name: dialog.name,
            person: person.displayName,
          })}
          confirm={t('Entfernen')}
          onCancel={close}
          action={async () => {
            await api(`${base}/passkeys/${seg(dialog.id)}`, { method: 'DELETE' });
            await changed(t('Entfernt.'));
          }}
        />
      )}
      {dialog?.kind === 'sessions' && (
        <Confirm
          title={t('Überall abmelden?')}
          lead={t('{name} muss sich auf jedem Gerät neu anmelden.', { name: person.displayName })}
          confirm={t('Abmelden')}
          tone="default"
          onCancel={close}
          action={async () => {
            await api(`${base}/sessions`, { method: 'DELETE' });
            await changed(t('Abgemeldet.'));
          }}
        />
      )}
    </>
  );
}

function BackButton({ onBack }: { onBack: () => void }) {
  useLanguage();
  return (
    <button type="button" className="back-button quiet" onClick={onBack}>
      <Icon name="chevron" size={15} />
      {t('Zurück')}
    </button>
  );
}

function PictureButton({
  person,
  base,
  onChanged,
}: {
  person: Detail;
  base: string;
  onChanged: () => void;
}) {
  useLanguage();
  const input = useRef<HTMLInputElement>(null);
  const [run, busy] = useAction();
  return (
    <div className="picture-button">
      <button
        type="button"
        className="avatar-button"
        title={t('Bild ändern')}
        aria-label={t('Bild ändern')}
        disabled={busy}
        onClick={() => input.current?.click()}
      >
        <Avatar name={person.displayName} src={person.avatar} size={72} />
        <span className="avatar-edit">
          <Icon name="pencil" size={14} />
        </span>
      </button>
      {person.avatar && (
        <button
          type="button"
          className="link-button small"
          disabled={busy}
          onClick={() =>
            void run(async () => {
              await api(`${base}/avatar`, { method: 'DELETE' });
              onChanged();
            })
          }
        >
          {t('Bild entfernen')}
        </button>
      )}
      <input
        ref={input}
        type="file"
        accept="image/*"
        hidden
        onChange={(e) => {
          const file = e.target.files?.[0];
          e.target.value = '';
          if (file)
            void run(async () => {
              const jpeg = await squareJpeg(file);
              await api(`${base}/avatar`, { method: 'PUT', body: jpeg, contentType: 'image/jpeg' });
              onChanged();
            });
        }}
      />
    </div>
  );
}

/** Names, language, and for admins the rest: user name, address, expiry, who looks after it. */
function DetailsSection({
  person,
  all,
  mode,
  base,
  onSaved,
}: {
  person: Detail;
  all: boolean;
  mode: Me['server']['mode'];
  base: string;
  onSaved: () => void;
}) {
  useLanguage();
  const initial = {
    displayName: person.displayName,
    givenName: person.givenName ?? '',
    familyName: person.familyName ?? '',
    language: person.language === 'en' ? 'en' : 'de',
    username: person.username,
    email: person.email ?? '',
    emailVerified: person.emailVerified,
    managed: person.managed,
    expires: person.expires ? person.expires.slice(0, 10) : '',
  };
  const [draft, setDraft] = useState(initial);
  const [run, busy] = useAction();
  const set = (patch: Partial<typeof initial>) => setDraft({ ...draft, ...patch });
  const changes: Record<string, unknown> = {};
  for (const key of Object.keys(initial) as (keyof typeof initial)[]) {
    if (draft[key] !== initial[key]) changes[key] = draft[key];
  }
  // An expiry is a day; it ends at the end of that day, in the browser's time zone.
  if ('expires' in changes)
    changes.expires = draft.expires ? new Date(`${draft.expires}T23:59:59`).toISOString() : '';
  const dirty = Object.keys(changes).length > 0;
  const save = (event: FormEvent) => {
    event.preventDefault();
    void run(async () => {
      await api(base, { method: 'PATCH', body: changes });
      onSaved();
    });
  };
  return (
    <Section title={t('Angaben')}>
      <form className="form" onSubmit={save}>
        <div className="field-grid">
          <label className="field">
            <span>{t('Anzeigename')}</span>
            <input
              value={draft.displayName}
              onChange={(e) => set({ displayName: e.target.value })}
            />
          </label>
          <label className="field">
            <span>{t('Vorname')}</span>
            <input value={draft.givenName} onChange={(e) => set({ givenName: e.target.value })} />
          </label>
          <label className="field">
            <span>{t('Nachname')}</span>
            <input value={draft.familyName} onChange={(e) => set({ familyName: e.target.value })} />
          </label>
          {all && (
            <label className="field">
              <span>{t('Benutzername')}</span>
              <input
                value={draft.username}
                onChange={(e) => set({ username: e.target.value.toLowerCase() })}
                autoCapitalize="none"
                spellCheck={false}
              />
            </label>
          )}
          {all && (
            <label className="field">
              <span>{t('E-Mail-Adresse')}</span>
              <input
                type="email"
                value={draft.email}
                onChange={(e) => set({ email: e.target.value })}
              />
            </label>
          )}
          <div className="field">
            <span>{t('Sprache')}</span>
            <Segmented
              label={t('Sprache')}
              value={draft.language}
              onChange={(language) => set({ language })}
              options={[
                { value: 'de', label: 'Deutsch' },
                { value: 'en', label: 'English' },
              ]}
            />
          </div>
          {all && (
            <label className="field">
              <span>{t('Läuft ab am')}</span>
              <input
                type="date"
                value={draft.expires}
                onChange={(e) => set({ expires: e.target.value })}
              />
              <small className="field-hint">{t('Leer: läuft nie ab.')}</small>
            </label>
          )}
        </div>
        {all && (
          <>
            <label className="check">
              <Toggle
                label={t('Adresse bestätigt')}
                checked={draft.emailVerified}
                disabled={!draft.email}
                onChange={(emailVerified) => set({ emailVerified })}
              />
              <span>{t('Adresse ist bestätigt')}</span>
            </label>
            <label className="check">
              <Toggle
                label={word(mode, 'managedAccount')}
                checked={draft.managed}
                onChange={(managed) => set({ managed })}
              />
              <span>{word(mode, 'managedAccount')}</span>
            </label>
          </>
        )}
        <div className="form-actions">
          <span className="spacer" />
          {dirty && (
            <button type="button" data-secondary onClick={() => setDraft(initial)}>
              {t('Verwerfen')}
            </button>
          )}
          <button type="submit" className="primary" disabled={!dirty || busy}>
            {t('Speichern')}
          </button>
        </div>
      </form>
    </Section>
  );
}

function GroupsSection({
  person,
  groups,
  base,
  onSaved,
}: {
  person: Detail;
  groups: Group[];
  base: string;
  onSaved: () => void;
}) {
  useLanguage();
  const [picked, setPicked] = useState(person.groups);
  const [run, busy] = useAction();
  const dirty = JSON.stringify([...picked].sort()) !== JSON.stringify([...person.groups].sort());
  const indirect = person.memberOf.filter((id) => !person.groups.includes(id));
  return (
    <Section title={t('Gruppen')} lead={t('Die Gruppe „Admins“ macht zum Admin.')}>
      <Picker
        label={t('Gruppen')}
        choices={groups
          .filter((group) => group.builtin !== 'everyone')
          .map((group) => ({ id: group.id, label: groupName(group), kind: 'group' as const }))}
        picked={picked}
        onChange={setPicked}
        empty={t('In keiner Gruppe.')}
      />
      {indirect.length > 0 && (
        <p className="field-hint">
          {t('Über andere Gruppen außerdem in: {list}', {
            list: indirect
              .map((id) => groups.find((group) => group.id === id))
              .filter((group): group is Group => Boolean(group))
              .map(groupName)
              .join(', '),
          })}
        </p>
      )}
      <div className="form-actions">
        <span className="spacer" />
        <button
          type="button"
          className="primary"
          disabled={!dirty || busy}
          onClick={() =>
            void run(async () => {
              await api(`${base}/groups`, { method: 'PUT', body: { groups: picked } });
              onSaved();
            })
          }
        >
          {t('Speichern')}
        </button>
      </div>
    </Section>
  );
}

/** Who looks after this person, and whom they look after. */
function CareSection({
  person,
  people,
  groups,
  mode,
  base,
  onSaved,
}: {
  person: Detail;
  people: Person[];
  groups: Group[];
  mode: Me['server']['mode'];
  base: string;
  onSaved: () => void;
}) {
  useLanguage();
  const [managers, setManagers] = useState(person.managers);
  const [managesPeople, setManagesPeople] = useState(person.manages.people);
  const [managesGroups, setManagesGroups] = useState(person.manages.groups);
  const [run, busy] = useAction();
  const others: Choice[] = people
    .filter((other) => other.id !== person.id && !other.deleted)
    .map((other) => ({
      id: other.id,
      label: other.displayName,
      sub: other.username,
      avatar: other.avatar,
    }));
  const same = (a: string[], b: string[]) =>
    JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
  const dirtyManagers = !same(managers, person.managers);
  const dirtyManages =
    !same(managesPeople, person.manages.people) || !same(managesGroups, person.manages.groups);
  return (
    <Section
      title={t('Wer kümmert sich um wen')}
      lead={t(
        'Wer sich um jemanden kümmert, sieht ihn im Portal und kann Namen, Passwort, Einrichtungslinks, Zeitfenster und Sperren selbst erledigen – ganz ohne Admin-Recht.',
      )}
    >
      <div className="field">
        <span>{t('Wer sich um {name} kümmert', { name: person.displayName })}</span>
        <Picker
          label={word(mode, 'managers')}
          choices={others}
          picked={managers}
          onChange={setManagers}
        />
      </div>
      <div className="form-actions">
        <span className="spacer" />
        <button
          type="button"
          className="primary"
          disabled={!dirtyManagers || busy}
          onClick={() =>
            void run(async () => {
              await api(`${base}/managers`, { method: 'PUT', body: { managers } });
              onSaved();
            })
          }
        >
          {t('Speichern')}
        </button>
      </div>
      <div className="field">
        <span>{t('{name} kümmert sich um diese Personen', { name: person.displayName })}</span>
        <Picker
          label={word(mode, 'manages')}
          choices={others}
          picked={managesPeople}
          onChange={setManagesPeople}
        />
      </div>
      <div className="field">
        <span>{t('… und um alle in diesen Gruppen')}</span>
        <Picker
          label={t('Gruppen')}
          choices={groups
            .filter((group) => !group.builtin)
            .map((group) => ({ id: group.id, label: groupName(group), kind: 'group' as const }))}
          picked={managesGroups}
          onChange={setManagesGroups}
          empty={t('Keine.')}
        />
      </div>
      <div className="form-actions">
        <span className="spacer" />
        <button
          type="button"
          className="primary"
          disabled={!dirtyManages || busy}
          onClick={() =>
            void run(async () => {
              await api(`${base}/manages`, {
                method: 'PUT',
                body: { people: managesPeople, groups: managesGroups },
              });
              onSaved();
            })
          }
        >
          {t('Speichern')}
        </button>
      </div>
    </Section>
  );
}

function AttributesSection({
  person,
  defs,
  base,
  onSaved,
}: {
  person: Detail;
  defs: AttributeDef[];
  base: string;
  onSaved: () => void;
}) {
  useLanguage();
  const [values, setValues] = useState<Record<string, string>>(person.attributes);
  const [run, busy] = useAction();
  const dirty = defs.some(
    (def) => (values[def.name] ?? '') !== (person.attributes[def.name] ?? ''),
  );
  return (
    <Section title={t('Weitere Angaben')}>
      <div className="field-grid">
        {defs.map((def) => (
          <AttributeInput
            key={def.name}
            def={def}
            value={values[def.name] ?? ''}
            onChange={(value) => setValues({ ...values, [def.name]: value })}
          />
        ))}
      </div>
      <div className="form-actions">
        <span className="spacer" />
        <button
          type="button"
          className="primary"
          disabled={!dirty || busy}
          onClick={() =>
            void run(async () => {
              const attributes = Object.fromEntries(
                defs.map((def) => [def.name, values[def.name] ?? '']),
              );
              await api(base, { method: 'PATCH', body: { attributes } });
              onSaved();
            })
          }
        >
          {t('Speichern')}
        </button>
      </div>
    </Section>
  );
}

/** What a Linux login needs: the number, the shell and the home directory. */
function PosixSection({
  person,
  base,
  onSaved,
}: {
  person: Detail;
  base: string;
  onSaved: () => void;
}) {
  useLanguage();
  const [shell, setShell] = useState(person.loginShell ?? '');
  const [home, setHome] = useState(person.homeDirectory ?? '');
  const [run, busy] = useAction();
  const dirty = shell !== (person.loginShell ?? '') || home !== (person.homeDirectory ?? '');
  return (
    <details className="section advanced-section">
      <summary className="section-title">{t('Linux-Anmeldung')}</summary>
      <p className="section-lead">
        {t(
          'Für Rechner, die sich später über LDAP an UwUAuth anmelden. Leer lassen nimmt die üblichen Werte.',
        )}
      </p>
      <div className="card">
        <div className="field-grid">
          <label className="field">
            <span>{t('Benutzernummer (uid)')}</span>
            <input value={person.uidNumber} readOnly />
          </label>
          <label className="field">
            <span>{t('Shell')}</span>
            <input
              value={shell}
              onChange={(e) => setShell(e.target.value)}
              placeholder="/bin/bash"
            />
          </label>
          <label className="field">
            <span>{t('Home-Verzeichnis')}</span>
            <input
              value={home}
              onChange={(e) => setHome(e.target.value)}
              placeholder={`/home/${person.username}`}
            />
          </label>
        </div>
        <div className="form-actions">
          <span className="spacer" />
          <button
            type="button"
            className="primary"
            disabled={!dirty || busy}
            onClick={() =>
              void run(async () => {
                await api(base, {
                  method: 'PATCH',
                  body: { loginShell: shell, homeDirectory: home },
                });
                onSaved();
              })
            }
          >
            {t('Speichern')}
          </button>
        </div>
      </div>
    </details>
  );
}

/**
 * A setup link (for an account nobody can sign in to yet) or a link for a new password: shown
 * as a big QR code to scan with the other device, or sent by mail.
 */
function LinkDialog({
  person,
  base,
  mail,
  onClose,
}: {
  person: Detail;
  base: string;
  mail: boolean;
  onClose: () => void;
}) {
  useLanguage();
  const [link, setLink] = useState<LinkResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const canMail = mail && Boolean(person.email);
  const make = useCallback(
    async (byMail: boolean) => {
      setBusy(true);
      setError(null);
      try {
        setLink(await api<LinkResult>(`${base}/link`, { body: { mail: byMail } }));
      } catch (e) {
        setError(errorText(e));
      } finally {
        setBusy(false);
      }
    },
    [base],
  );
  // Nothing to choose without mail: the QR code straight away.
  useEffect(() => {
    if (!canMail) void make(false);
  }, [canMail, make]);

  const setup = !person.hasPassword && person.passkeys.length === 0;
  return (
    <Modal
      title={
        setup
          ? t('Einrichtungslink für {name}', { name: person.displayName })
          : t('Link für ein neues Passwort')
      }
      onCancel={onClose}
      footer={
        <>
          <span className="spacer" />
          <button type="button" className={link ? 'primary' : undefined} onClick={onClose}>
            {link ? t('Fertig') : t('Abbrechen')}
          </button>
        </>
      }
    >
      {link ? (
        <LinkShare
          link={link.link}
          expires={link.expires}
          mailed={link.mailed}
          lead={
            setup
              ? t(
                  'Scann den Code mit dem Gerät von {name} – etwa dem Tablet. Dort wählt {name} einen Passkey oder ein Passwort.',
                  { name: person.displayName },
                )
              : t('Damit setzt {name} ein neues Passwort. Ein älterer Link gilt dann nicht mehr.', {
                  name: person.displayName,
                })
          }
        />
      ) : canMail ? (
        <div className="form">
          <p className="dialog-lead">
            {t('Wie soll der Link zu {name} kommen?', { name: person.displayName })}
          </p>
          <button
            type="button"
            className="big-button"
            disabled={busy}
            onClick={() => void make(false)}
          >
            <Icon name="qr" />
            {t('Als QR-Code zeigen')}
          </button>
          <button
            type="button"
            className="big-button"
            disabled={busy}
            onClick={() => void make(true)}
          >
            <Icon name="mail" />
            {t('Per Mail an {email}', { email: person.email ?? '' })}
          </button>
        </div>
      ) : (
        !error && <Loading />
      )}
      <FormError error={error} />
    </Modal>
  );
}

function SetPasswordDialog({
  person,
  base,
  minLength,
  onCancel,
  onDone,
}: {
  person: Detail;
  base: string;
  minLength: number;
  onCancel: () => void;
  onDone: () => void;
}) {
  useLanguage();
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const save = async (event?: FormEvent) => {
    event?.preventDefault();
    if (password.length < minLength) return;
    setBusy(true);
    setError(null);
    try {
      await api(`${base}/password`, { body: { password } });
      onDone();
    } catch (e) {
      setError(errorText(e));
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t('Passwort für {name} setzen', { name: person.displayName })}
      onCancel={() => !busy && onCancel()}
      footer={
        <>
          <span className="spacer" />
          <button type="button" data-secondary onClick={onCancel} disabled={busy}>
            {t('Abbrechen')}
          </button>
          <button
            type="button"
            className="primary"
            disabled={busy || password.length < minLength}
            onClick={() => void save()}
          >
            {t('Speichern')}
          </button>
        </>
      }
    >
      <form className="form" onSubmit={save}>
        <p className="dialog-lead">
          {t(
            '{name} wird überall abgemeldet und meldet sich danach mit diesem Passwort an. Ein Einrichtungslink ist meist netter: Dann wählt {name} selbst.',
            { name: person.displayName },
          )}
        </p>
        <label className="field">
          <span>{t('Neues Passwort')}</span>
          <PasswordInput
            value={password}
            onChange={setPassword}
            autoComplete="new-password"
            autoFocus
          />
          <small className="field-hint">{t('Mindestens {n} Zeichen.', { n: minLength })}</small>
        </label>
        <FormError error={error} />
      </form>
    </Modal>
  );
}
