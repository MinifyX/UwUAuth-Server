/**
 * The server says what went wrong with a code and an English message; the page says it in the
 * reader's language, by code, and falls back to the message for codes it does not know.
 */

import { ApiError } from './api';
import { t } from './i18n';

export function errorText(error: unknown): string {
  if (!(error instanceof ApiError)) {
    if (error instanceof DOMException) return webauthnText(error);
    if (error && typeof error === 'object' && 'code' in error && error.code === 'cancelled')
      return t('Abgebrochen.');
    return error instanceof Error ? error.message : String(error);
  }
  const detail = error.detail ?? {};
  switch (error.code) {
    case 'network':
      return t('Der Server antwortet nicht. Ist die Verbindung da?');
    case 'wrong':
      return t('Name oder Passwort stimmt nicht.');
    case 'wrong_code':
      return t('Das hat nicht geklappt. Prüf den Code und versuch es noch einmal.');
    case 'locked':
      return t(
        'Zu viele falsche Versuche. Warte eine Viertelstunde und versuch es dann noch einmal.',
      );
    case 'disabled':
      return t('Dieses Konto ist gesperrt.');
    case 'expired':
      return t('Das hat zu lange gedauert. Fang bitte noch einmal an.');
    case 'too_many':
      return t('Zu viele Versuche auf einmal. Warte kurz und versuch es noch einmal.');
    case 'reauth':
      return t('Bestätige zuerst, dass du es bist.');
    case 'cancelled':
      return t('Abgebrochen.');
    case 'link_gone':
      return t('Der Link wurde schon benutzt oder ist abgelaufen.');
    case 'exists':
      return detail.field === 'email'
        ? t('Mit dieser Adresse gibt es schon ein Konto.')
        : detail.field === 'username'
          ? t('Diesen Benutzernamen gibt es schon.')
          : t('Den Namen oder die Adresse gibt es schon.');
    case 'too_short':
      return t('Das Passwort ist zu kurz: mindestens {min} Zeichen.', {
        min: Number(detail.min ?? 10),
      });
    case 'too_long':
      return t('Das Passwort ist zu lang.');
    case 'contains_name':
      return t('Das Passwort enthält deinen Namen. Nimm lieber etwas anderes.');
    case 'pwned':
      return t(
        'Dieses Passwort ist schon {count}-mal in Datenlecks aufgetaucht. Nimm bitte ein anderes.',
        { count: Number(detail.count ?? 1).toLocaleString() },
      );
    case 'last_admin':
      return t('Das ist der letzte Admin. Mach zuerst jemand anderen zum Admin.');
    case 'last_credential':
      return t(
        'Das ist die letzte Möglichkeit, dich anzumelden. Leg zuerst ein Passwort oder einen weiteren Passkey an.',
      );
    case 'mfa_required':
      return t('Eine deiner Gruppen verlangt einen zweiten Faktor. Behalte mindestens einen.');
    case 'loop':
      return t('Eine Gruppe kann nicht in sich selbst stecken.');
    case 'mail_failed':
      return t('Die Mail ging nicht raus: {reason}', { reason: error.message });
    case 'no_mail':
      return t('Dieser Server kann keine Mails verschicken. Frag einen Admin.');
    case 'no_email':
      return t('Dein Konto hat keine Adresse, an die die Testmail gehen könnte.');
    case 'unauthorized':
      return t('Du bist nicht mehr angemeldet.');
    case 'forbidden':
      return error.detail?.restricted
        ? t('Richte zuerst einen zweiten Faktor ein.')
        : t('Das darfst du nicht.');
    case 'not_found':
      return t('Das gibt es nicht (mehr).');
    case 'username':
      return t(
        'Ein Benutzername besteht aus kleinen Buchstaben, Ziffern, Punkten, Binde- und Unterstrichen und fängt mit einem Buchstaben oder einer Ziffer an.',
      );
    case 'email':
      return t('Das ist keine E-Mail-Adresse.');
    case 'required':
      return t('Da fehlt noch etwas.');
    case 'group_name':
      return t(
        'Ein Gruppenname besteht aus Buchstaben, Ziffern, Leerzeichen, Punkten und Strichen.',
      );
    case 'passkey':
      return t('Der Passkey hat nicht geklappt. Versuch es noch einmal.');
    case 'challenge':
      return t('Das hat zu lange gedauert. Fang bitte noch einmal an.');
    case 'self':
      return t('Das geht nicht mit deinem eigenen Konto.');
    case 'builtin':
      return t('Diese Gruppe gehört zum Server und bleibt, wie sie ist.');
    case 'not_in_trash':
      return t('Leg die Person zuerst in den Papierkorb.');
    case 'window':
      return t('Ein Zeitfenster braucht mindestens einen Tag und verschiedene Uhrzeiten.');
    case 'attribute':
      return t('Dieser Wert passt nicht zum Feld.');
    case 'attribute_name':
      return t(
        'Ein Feldname besteht aus kleinen Buchstaben, Ziffern und Unterstrichen, und manche Namen sind schon vergeben.',
      );
    case 'not_jpeg':
    case 'too_large':
      return t('Mit diesem Bild klappt es nicht. Nimm bitte ein anderes.');
    case 'timezone':
      return t('Diese Zeitzone kennt der Server nicht.');
    case 'range':
      return t('Ein Wert ist zu klein oder zu groß.');
    case 'smtp':
      return t('Mit diesen Mail-Einstellungen klappt es nicht: {reason}', {
        reason: error.message,
      });
    case 'csv':
      return t('Die CSV-Datei braucht in der ersten Zeile eine Spalte „username“.');
    case 'json':
      return t('Das ist kein Export aus UwUAuth.');
    case 'encoding':
      return t('Die Datei muss UTF-8 sein.');
    case 'internal':
      return t('Auf dem Server ist etwas schiefgegangen. Im Log steht mehr.');
    default:
      return error.message;
  }
}

/** What the browser says when a passkey did not work. */
function webauthnText(error: DOMException): string {
  switch (error.name) {
    case 'NotAllowedError':
    case 'AbortError':
      return t('Abgebrochen – oder das Gerät hat nicht geantwortet.');
    case 'InvalidStateError':
      return t('Auf diesem Gerät gibt es schon einen Passkey für dieses Konto.');
    case 'SecurityError':
      return t('Passkeys gehen nur über die richtige Adresse des Servers (https).');
    case 'NotSupportedError':
      return t('Dieses Gerät kann keine Passkeys.');
    default:
      return error.message;
  }
}
