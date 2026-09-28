// Grafana and Forgejo sign a person in through UwUAuth, in a real browser: the "Sign in with …"
// button, UwUAuth's sign-in page, back to the app, and the app knows who it is.
//
//   node oidc.mjs <UwUAuth address> <user> <password>

import { chromium } from 'playwright';

const [uwuauth, user, password] = process.argv.slice(2);
const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
page.setDefaultTimeout(20_000);

/** UwUAuth's sign-in page, if the browser is on it: the name, the password, go. */
async function signIn() {
  await page.waitForURL((url) => url.href.startsWith(uwuauth));
  const name = page.locator('input[autocomplete~="username"]').first();
  await name.waitFor();
  await name.fill(user);
  await page.locator('input[type="password"]').first().fill(password);
  await page.locator('form button[type="submit"]').first().click();
}

function check(what, ok, detail) {
  if (!ok) {
    console.error(`${what}: ${detail}`);
    process.exitCode = 1;
  } else {
    console.log(`${what}: ok`);
  }
}

try {
  // Grafana: its generic OAuth button, then UwUAuth's page.
  await page.goto('http://grafana:3000/login');
  await page.getByText('Sign in with UwUAuth').click();
  await signIn();
  await page.waitForURL((url) => url.href.startsWith('http://grafana:3000/'));
  const grafanaUser = await (await context.request.get('http://grafana:3000/api/user')).json();
  check('Grafana knows who signed in', grafanaUser.login === user, JSON.stringify(grafanaUser));
  const orgs = await (await context.request.get('http://grafana:3000/api/user/orgs')).json();
  check('Grafana made an admin of an admin', orgs.some((org) => org.role === 'Admin'), JSON.stringify(orgs));

  // Forgejo: signed in at UwUAuth already, so straight through.
  // Back at Forgejo once the round trip through UwUAuth is over: not on the address that starts it.
  await page.goto('http://forgejo:3000/user/oauth2/uwuauth');
  await page.waitForURL(
    (url) => url.origin === 'http://forgejo:3000' && !url.pathname.startsWith('/user/oauth2/'),
  );
  // Forgejo's API wants a token, not the browser's session: its settings page says who it is.
  await page.goto('http://forgejo:3000/user/settings');
  const forgejoName = await page.locator('input[name="name"]').inputValue().catch(() => '');
  check('Forgejo knows who signed in', forgejoName === user, `${page.url()} shows "${forgejoName}"`);
} catch (error) {
  console.error(error);
  await page.screenshot({ path: '/tmp/interop-failure.png' }).catch(() => {});
  console.error('on', page.url());
  process.exitCode = 1;
} finally {
  await browser.close();
}
