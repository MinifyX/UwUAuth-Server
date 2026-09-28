// The web app, end to end, against a running server:
//
//   node scripts/e2e/web.mjs <invite link> <base url> <screenshot dir>
//
// The invite link is the one `uwuauth-server invite --admin` prints. Goes through the main
// flow the way a family would: the first admin accepts the invitation with a passkey and runs
// the setup assistant, makes a group, invites somebody, makes an account for a kid with a setup
// link and sets it up in a second browser with a password, adds the authenticator app, signs
// out and in again with the passkey, and opens every page of the admin portal.
//
// Runs in the Playwright image (mcr.microsoft.com/playwright). Passkeys come from Chrome's
// virtual authenticator. Exits non-zero on the first failure, with a screenshot of every open
// page in the screenshot dir; E2E_SHOTS=1 keeps one of every step too.

import { createHmac } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

const [inviteLink, baseArg, shotDir] = process.argv.slice(2);
if (!inviteLink || !baseArg || !shotDir) {
  console.error('usage: node scripts/e2e/web.mjs <invite link> <base url> <screenshot dir>');
  process.exit(2);
}
const base = baseArg.replace(/\/+$/, '');
mkdirSync(shotDir, { recursive: true });
const everyStep = process.env.E2E_SHOTS === '1';

// `playwright` from node_modules, or wherever PLAYWRIGHT points (the image has it in a
// different place than a checkout).
const { chromium } = await import(process.env.PLAYWRIGHT ?? 'playwright');

/** The authenticator app's code for a base32 secret, now. */
function totp(secret, at = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of secret.replace(/[\s=]/g, '').toUpperCase()) {
    bits += alphabet.indexOf(char).toString(2).padStart(5, '0');
  }
  const key = Buffer.from(bits.match(/.{8}/g).map((byte) => parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const hash = createHmac('sha1', key).update(counter).digest();
  const offset = hash[hash.length - 1] & 0xf;
  const value = (hash.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(value).padStart(6, '0');
}

const browser = await chromium.launch();
const pages = [];
let step = 0;

async function shot(page, name) {
  step += 1;
  if (everyStep) {
    await page.screenshot({
      path: join(shotDir, `${String(step).padStart(2, '0')}-${name}.png`),
      fullPage: true,
    });
  }
}

/** A browser of its own, German, with a passkey-capable authenticator built in. */
async function newBrowser(name) {
  const context = await browser.newContext({
    locale: 'de-DE',
    viewport: { width: 1280, height: 860 },
  });
  const page = await context.newPage();
  page.setDefaultTimeout(15_000);
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  page.on('pageerror', (error) => console.error(`[${name}] page error: ${error.message}`));
  pages.push({ name, page });
  return page;
}

/** A page's title is there: the page loaded and drew. */
async function title(page, text) {
  await page.getByRole('heading', { level: 1, name: text }).waitFor();
}

async function run() {
  // ── The first admin: invitation with a passkey, then the assistant ──
  const admin = await newBrowser('admin');
  const invite = new URL(inviteLink);
  await admin.goto(`${base}/${invite.hash}`);
  await title(admin, /Willkommen bei/);
  await admin.getByLabel('Wie sollen wir dich nennen?').fill('Nyu Neko');
  await admin.getByLabel('Benutzername').fill('nyu');
  await shot(admin, 'invite');
  await admin.getByRole('button', { name: 'Mit Passkey weiter' }).click();

  // A new server sends its first admin straight to the assistant.
  await admin.waitForURL(/\/admin/);
  await title(admin, /willkommen bei UwUAuth/);
  await admin.getByLabel('Wie heißt ihr?').fill('Familie Neko');
  await shot(admin, 'setup-name');
  await admin.getByRole('button', { name: 'Weiter' }).click();
  await title(admin, 'Wofür ist UwUAuth da?');
  await admin.getByRole('button', { name: /^Familie/ }).click();
  await shot(admin, 'setup-mode');
  await admin.getByRole('button', { name: 'Weiter' }).click();
  await title(admin, 'Sprache und Zeit');
  await admin.getByRole('button', { name: 'Fertig einrichten' }).click();
  await title(admin, 'Fertig ✧');
  await shot(admin, 'setup-done');
  await admin.getByRole('button', { name: 'Los geht’s' }).click();
  await title(admin, 'Übersicht');
  await shot(admin, 'admin-overview');

  // ── A group ──
  await admin.goto(`${base}/admin#/groups`);
  await title(admin, 'Gruppen');
  await admin.getByRole('button', { name: 'Gruppe anlegen' }).click();
  await admin.getByRole('dialog').getByLabel('Name').fill('Kinder');
  await admin.getByRole('dialog').getByRole('button', { name: 'Anlegen' }).click();
  await title(admin, 'Kinder');
  await shot(admin, 'group');

  // ── An invitation for a second grown-up ──
  await admin.goto(`${base}/admin#/invitations`);
  await title(admin, 'Einladungen');
  await admin.getByRole('button', { name: 'Einladen' }).click();
  const inviteDialog = admin.getByRole('dialog');
  await inviteDialog.getByLabel('Name (freiwillig)').fill('Mama Neko');
  await inviteDialog.getByRole('button', { name: 'Link erstellen' }).click();
  const invitation = await admin.locator('.copy-field code').innerText();
  if (!invitation.includes('/#/invite?token=')) throw new Error(`no invitation link: ${invitation}`);
  await shot(admin, 'invitation');
  await admin.getByRole('dialog').getByRole('button', { name: 'Fertig' }).click();
  await admin.getByText('Mama Neko').waitFor();

  // ── A kid's account with a setup link ──
  await admin.goto(`${base}/admin#/people`);
  await title(admin, 'Personen');
  await admin.getByRole('button', { name: 'Person anlegen' }).click();
  const create = admin.getByRole('dialog');
  await create.getByLabel('Name', { exact: true }).fill('Mia Neko');
  await create.getByRole('switch', { name: 'Kinderkonto' }).click();
  await create.getByRole('button', { name: 'Anlegen' }).click();
  const setupLink = await admin.locator('.copy-field code').innerText();
  if (!setupLink.includes('/#/setup?token=')) throw new Error(`no setup link: ${setupLink}`);
  await shot(admin, 'kid-link');
  await admin.getByRole('dialog').getByRole('button', { name: 'Fertig' }).click();
  await title(admin, 'Mia Neko');
  await shot(admin, 'kid');

  // The kid's tablet: a second browser, a password.
  const tablet = await newBrowser('tablet');
  await tablet.goto(`${base}/${new URL(setupLink).hash}`);
  await title(tablet, 'Hallo Mia Neko!');
  await tablet.getByRole('button', { name: 'Lieber ein Passwort' }).click();
  const passwords = tablet.locator('input[autocomplete="new-password"]');
  await passwords.nth(0).fill('mein geheimes Katzenpasswort');
  await passwords.nth(1).fill('mein geheimes Katzenpasswort');
  await shot(tablet, 'kid-setup');
  await tablet.getByRole('button', { name: 'Konto einrichten' }).click();
  await title(tablet, 'Hallo, Mia Neko!');
  await shot(tablet, 'kid-portal');

  // ── The authenticator app for the admin ──
  await admin.goto(`${base}/#/security`);
  await title(admin, 'Sicherheit');
  await admin
    .locator('.section', { hasText: 'Authenticator-App' })
    .getByRole('button', { name: 'Einrichten' })
    .click();
  const secret = (await admin.getByTestId('totp-secret').innerText()).replace(/\s/g, '');
  await admin.getByLabel('Code aus der App').fill(totp(secret));
  await shot(admin, 'totp');
  await admin.getByRole('dialog').getByRole('button', { name: 'Einschalten' }).click();
  await admin.getByRole('heading', { name: 'Deine Wiederherstellungscodes' }).waitFor();
  await shot(admin, 'recovery-codes');
  await admin.getByRole('button', { name: 'Aufgeschrieben – fertig' }).click();
  await admin.locator('.section', { hasText: 'Authenticator-App' }).getByText('Eingerichtet').waitFor();

  // ── Out, and in again with the passkey ──
  await admin.getByRole('button', { name: 'Abmelden' }).click();
  await title(admin, 'Anmelden');
  await shot(admin, 'signed-out');
  // Chrome's virtual authenticator answers the passkey offer in the name field at once, where a
  // real browser waits for a pick: either way the passkey signs in.
  const passkeyButton = admin.getByRole('button', { name: 'Mit Passkey anmelden' });
  await passkeyButton.click({ timeout: 3000 }).catch(() => undefined);
  await title(admin, 'Hallo, Nyu Neko!');
  await shot(admin, 'portal-overview');

  // ── Every page of the admin portal ──
  const adminPages = [
    ['', 'Übersicht'],
    ['people', 'Personen'],
    ['groups', 'Gruppen'],
    ['invitations', 'Einladungen'],
    ['attributes', 'Zusätzliche Felder'],
    ['settings', 'Einstellungen'],
    ['events', 'Ereignisse'],
    ['logs', 'Log'],
    ['backups', 'Backups'],
    ['tokens', 'API-Tokens'],
    ['transfer', 'Import & Export'],
  ];
  for (const [path, name] of adminPages) {
    await admin.goto(`${base}/admin#/${path}`);
    await title(admin, name);
    await shot(admin, `admin-${path || 'overview'}`);
  }
  // The event log tells what happened, in sentences.
  await admin.goto(`${base}/admin#/events`);
  await admin.getByText('Nyu Neko hat UwUAuth eingerichtet.').waitFor();
}

try {
  await run();
  console.log('✓ the web app works end to end');
  await browser.close();
} catch (error) {
  console.error(`✗ ${error.stack ?? error}`);
  for (const { name, page } of pages) {
    await page
      .screenshot({ path: join(shotDir, `failure-${name}.png`), fullPage: true })
      .catch(() => undefined);
  }
  await browser.close();
  process.exit(1);
}
