// Nextcloud signs a person in through UwUAuth with OpenID Connect (user_oidc).
//
//   node nextcloud.mjs <UwUAuth address> <user> <password>

import { chromium } from 'playwright';

const [uwuauth, user, password] = process.argv.slice(2);
const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
page.setDefaultTimeout(30_000);

try {
  await page.goto('http://nextcloud/apps/user_oidc/login/1');
  await page.waitForURL((url) => url.href.startsWith(uwuauth));
  await page.locator('input[autocomplete~="username"]').first().fill(user);
  await page.locator('input[type="password"]').first().fill(password);
  await page.locator('form button[type="submit"]').first().click();
  await page.waitForURL((url) => url.href.startsWith('http://nextcloud/') && !url.pathname.includes('/login'));
  const response = await context.request.get('http://nextcloud/ocs/v2.php/cloud/user?format=json', {
    headers: { 'OCS-APIRequest': 'true' },
  });
  const body = await response.json();
  const id = body?.ocs?.data?.id;
  if (id !== user) throw new Error(`Nextcloud says ${JSON.stringify(body?.ocs?.data)}`);
  console.log(`Nextcloud signed ${id} in through UwUAuth: ok`);
} catch (error) {
  console.error(error, 'on', page.url());
  // What the page said: Nextcloud shows its own errors there.
  console.error((await page.locator('body').innerText().catch(() => '')).slice(0, 800));
  process.exitCode = 1;
} finally {
  await browser.close();
}
