/**
 * The English catalogue: German string → English string, one file per area of the app. See
 * `lib/i18n.ts`.
 */

import admin from './admin.json';
import app from './app.json';
import ldap from './ldap.json';
import oidc from './oidc.json';
import portal from './portal.json';
import signin from './signin.json';

export const EN: Readonly<Record<string, string>> = {
  ...app,
  ...signin,
  ...portal,
  ...admin,
  ...oidc,
  ...ldap,
};
