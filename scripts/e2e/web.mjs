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
// Then OpenID Connect, with no app needed: an app from the generic template that asks for
// consent, a sign-in to it with PKCE (its redirect address is caught in the browser, the code
// exchanged for tokens here), "My apps" with the grant and taking it back, signing in again for
// an app that asks for it (`prompt=login`), a TV that connects with a code typed in the browser,
// the pages for refusals and broken apps, and signing out from an app.
//
// Before that, the UwUSuite: a pairing code from the admin portal, taken by this script as if
// it were UwULock, and the paired app's page.
//
// Runs in the Playwright image (mcr.microsoft.com/playwright). Passkeys come from Chrome's
// virtual authenticator. Exits non-zero on the first failure, with a screenshot of every open
// page in the screenshot dir; E2E_SHOTS=1 keeps one of every step too.

import { createHash, createHmac, randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const [inviteLink, baseArg, shotDir] = process.argv.slice(2);
if (!inviteLink || !baseArg || !shotDir) {
    console.error(
        "usage: node scripts/e2e/web.mjs <invite link> <base url> <screenshot dir>",
    );
    process.exit(2);
}
const base = baseArg.replace(/\/+$/, "");
mkdirSync(shotDir, { recursive: true });
const everyStep = process.env.E2E_SHOTS === "1";

// `playwright` from node_modules, or wherever PLAYWRIGHT points (the image has it in a
// different place than a checkout).
const { chromium } = await import(process.env.PLAYWRIGHT ?? "playwright");

/** The authenticator app's code for a base32 secret, now. */
function totp(secret, at = Date.now()) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = "";
    for (const char of secret.replace(/[\s=]/g, "").toUpperCase()) {
        bits += alphabet.indexOf(char).toString(2).padStart(5, "0");
    }
    const key = Buffer.from(
        bits.match(/.{8}/g).map((byte) => parseInt(byte, 2)),
    );
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
    const hash = createHmac("sha1", key).update(counter).digest();
    const offset = hash[hash.length - 1] & 0xf;
    const value = (hash.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
    return String(value).padStart(6, "0");
}

const browser = await chromium.launch();
const pages = [];
let step = 0;

async function shot(page, name) {
    step += 1;
    if (everyStep) {
        await page.screenshot({
            path: join(shotDir, `${String(step).padStart(2, "0")}-${name}.png`),
            fullPage: true,
        });
    }
}

/** A browser of its own, German, with a passkey-capable authenticator built in. */
async function newBrowser(name) {
    const context = await browser.newContext({
        locale: "de-DE",
        viewport: { width: 1280, height: 860 },
    });
    const page = await context.newPage();
    page.setDefaultTimeout(15_000);
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable", { enableUI: false });
    const { authenticatorId } = await cdp.send(
        "WebAuthn.addVirtualAuthenticator",
        {
            options: {
                protocol: "ctap2",
                transport: "internal",
                hasResidentKey: true,
                hasUserVerification: true,
                isUserVerified: true,
                automaticPresenceSimulation: true,
            },
        },
    );
    // The virtual authenticator answers the passkey offer in the sign-in page's name field at
    // once, where a real browser waits for a pick. Off, the sign-in page stays until switched on.
    page.presence = (enabled) =>
        cdp.send("WebAuthn.setAutomaticPresenceSimulation", {
            authenticatorId,
            enabled,
        });
    page.on("pageerror", (error) =>
        console.error(`[${name}] page error: ${error.message}`),
    );
    pages.push({ name, page });
    return page;
}

/** A form POST to the server, from here (as an app would), as JSON. */
async function post(path, form, basic) {
    const headers = { "content-type": "application/x-www-form-urlencoded" };
    if (basic) {
        const [id, secret] = basic.map(encodeURIComponent);
        headers.authorization = `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;
    }
    const response = await fetch(`${base}${path}`, {
        method: "POST",
        headers,
        body: new URLSearchParams(form),
    });
    const body = await response.json();
    if (!response.ok)
        throw new Error(`${path}: ${response.status} ${JSON.stringify(body)}`);
    return body;
}

/** A JWT's claims, unchecked: the server's tests check signatures, this only reads. */
function claims(jwt) {
    return JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString());
}

/** A page's title is there: the page loaded and drew. */
async function title(page, text) {
    await page.getByRole("heading", { level: 1, name: text }).waitFor();
}

async function run() {
    // ── The first admin: invitation with a passkey, then the assistant ──
    const admin = await newBrowser("admin");
    const invite = new URL(inviteLink);
    await admin.goto(`${base}/${invite.hash}`);
    await title(admin, /Willkommen bei/);
    await admin.getByLabel("Wie sollen wir dich nennen?").fill("Nyu Neko");
    await admin.getByLabel("Benutzername").fill("nyu");
    await shot(admin, "invite");
    await admin.getByRole("button", { name: "Mit Passkey weiter" }).click();

    // A new server sends its first admin straight to the assistant.
    await admin.waitForURL(/\/admin/);
    await title(admin, /willkommen bei UwUAuth/);
    await admin.getByLabel("Wie heißt ihr?").fill("Familie Neko");
    await shot(admin, "setup-name");
    await admin.getByRole("button", { name: "Weiter" }).click();
    await title(admin, "Wofür ist UwUAuth da?");
    await admin.getByRole("button", { name: /^Familie/ }).click();
    await shot(admin, "setup-mode");
    await admin.getByRole("button", { name: "Weiter" }).click();
    await title(admin, "Sprache und Zeit");
    await admin.getByRole("button", { name: "Fertig einrichten" }).click();
    await title(admin, "Fertig ✧");
    await shot(admin, "setup-done");
    await admin.getByRole("button", { name: "Los geht’s" }).click();
    await title(admin, "Übersicht");
    await shot(admin, "admin-overview");

    // ── A group ──
    await admin.goto(`${base}/admin#/groups`);
    await title(admin, "Gruppen");
    await admin.getByRole("button", { name: "Gruppe anlegen" }).click();
    await admin.getByRole("dialog").getByLabel("Name").fill("Kinder");
    await admin
        .getByRole("dialog")
        .getByRole("button", { name: "Anlegen" })
        .click();
    await title(admin, "Kinder");
    await shot(admin, "group");

    // ── An invitation for a second grown-up ──
    await admin.goto(`${base}/admin#/invitations`);
    await title(admin, "Einladungen");
    await admin.getByRole("button", { name: "Einladen" }).click();
    const inviteDialog = admin.getByRole("dialog");
    await inviteDialog.getByLabel("Name (freiwillig)").fill("Mama Neko");
    await inviteDialog.getByRole("button", { name: "Link erstellen" }).click();
    const invitation = await admin.locator(".copy-field code").innerText();
    if (!invitation.includes("/#/invite?token="))
        throw new Error(`no invitation link: ${invitation}`);
    await shot(admin, "invitation");
    await admin
        .getByRole("dialog")
        .getByRole("button", { name: "Fertig" })
        .click();
    await admin.getByText("Mama Neko").waitFor();

    // ── A kid's account with a setup link ──
    await admin.goto(`${base}/admin#/people`);
    await title(admin, "Personen");
    await admin.getByRole("button", { name: "Person anlegen" }).click();
    const create = admin.getByRole("dialog");
    await create.getByLabel("Name", { exact: true }).fill("Mia Neko");
    await create.getByRole("switch", { name: "Kinderkonto" }).click();
    await create.getByRole("button", { name: "Anlegen" }).click();
    const setupLink = await admin.locator(".copy-field code").innerText();
    if (!setupLink.includes("/#/setup?token="))
        throw new Error(`no setup link: ${setupLink}`);
    await shot(admin, "kid-link");
    await admin
        .getByRole("dialog")
        .getByRole("button", { name: "Fertig" })
        .click();
    await title(admin, "Mia Neko");
    await shot(admin, "kid");

    // The kid's tablet: a second browser, a password.
    const tablet = await newBrowser("tablet");
    await tablet.goto(`${base}/${new URL(setupLink).hash}`);
    await title(tablet, "Hallo Mia Neko!");
    await tablet.getByRole("button", { name: "Lieber ein Passwort" }).click();
    const passwords = tablet.locator('input[autocomplete="new-password"]');
    await passwords.nth(0).fill("mein geheimes Katzenpasswort");
    await passwords.nth(1).fill("mein geheimes Katzenpasswort");
    await shot(tablet, "kid-setup");
    await tablet.getByRole("button", { name: "Konto einrichten" }).click();
    await title(tablet, "Hallo, Mia Neko!");
    await shot(tablet, "kid-portal");

    // ── The authenticator app for the admin ──
    await admin.goto(`${base}/#/security`);
    await title(admin, "Sicherheit");
    await admin
        .locator(".section", { hasText: "Authenticator-App" })
        .getByRole("button", { name: "Einrichten" })
        .click();
    const secret = (await admin.getByTestId("totp-secret").innerText()).replace(
        /\s/g,
        "",
    );
    await admin.getByLabel("Code aus der App").fill(totp(secret));
    await shot(admin, "totp");
    await admin
        .getByRole("dialog")
        .getByRole("button", { name: "Einschalten" })
        .click();
    await admin
        .getByRole("heading", { name: "Deine Wiederherstellungscodes" })
        .waitFor();
    await shot(admin, "recovery-codes");
    await admin
        .getByRole("button", { name: "Aufgeschrieben – fertig" })
        .click();
    await admin
        .locator(".section", { hasText: "Authenticator-App" })
        .getByText("Eingerichtet")
        .waitFor();

    // ── Out, and in again with the passkey ──
    // Chrome's virtual authenticator would answer the passkey offer in the name field at once,
    // where a real browser waits for a pick: so nobody touches it until the page is there.
    await admin.presence(false);
    await admin.getByRole("button", { name: "Abmelden" }).click();
    await title(admin, "Anmelden");
    await shot(admin, "signed-out");
    await admin.presence(true);
    // Either the button or the offer in the name field: the passkey signs in.
    const passkeyButton = admin.getByRole("button", {
        name: "Mit Passkey anmelden",
    });
    await passkeyButton.click({ timeout: 3000 }).catch(() => undefined);
    await title(admin, "Hallo, Nyu Neko!");
    await shot(admin, "portal-overview");

    // ── Every page of the admin portal ──
    const adminPages = [
        ["", "Übersicht"],
        ["people", "Personen"],
        ["groups", "Gruppen"],
        ["invitations", "Einladungen"],
        ["apps", "Apps"],
        ["attributes", "Zusätzliche Felder"],
        ["settings", "Einstellungen"],
        ["events", "Ereignisse"],
        ["logs", "Log"],
        ["backups", "Backups"],
        ["tokens", "API-Tokens"],
        ["transfer", "Import & Export"],
    ];
    for (const [path, name] of adminPages) {
        await admin.goto(`${base}/admin#/${path}`);
        await title(admin, name);
        await shot(admin, `admin-${path || "overview"}`);
    }
    // LDAP: an account for an app, its password shown once. Only when the server serves LDAP.
    await admin.goto(`${base}/admin#/ldap`);
    await title(admin, "LDAP");
    const newAccount = admin.getByRole("button", { name: "Neues Konto" });
    if (await newAccount.isVisible()) {
        await newAccount.click();
        await admin.getByRole("dialog").getByLabel("Name").fill("nas");
        await admin
            .getByRole("dialog")
            .getByRole("button", { name: "Anlegen" })
            .click();
        await admin.getByText("Das Passwort siehst du nur jetzt.").waitFor();
        await shot(admin, "admin-ldap-account");
        await admin.getByRole("button", { name: "Fertig" }).click();
        await admin.getByText("cn=nas,ou=services,").waitFor();
    }
    await shot(admin, "admin-ldap");

    // The event log tells what happened, in sentences.
    await admin.goto(`${base}/admin#/events`);
    await admin.getByText("Nyu Neko hat UwUAuth eingerichtet.").waitFor();

    await suite(admin);
    await oidc(admin);
}

/** Pairing a UwUSuite app: a code in the admin portal, taken by this script as the app. */
async function suite(admin) {
    await admin.goto(`${base}/admin#/apps`);
    await title(admin, "Apps");
    await admin.getByRole("button", { name: "UwUSuite-App koppeln" }).click();
    const dialog = admin.getByRole("dialog");
    await dialog.getByRole("button", { name: "Code erstellen" }).click();
    const code = (await dialog.locator(".pairing-code").innerText()).trim();
    if (!/^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/.test(code))
        throw new Error(`not a pairing code: ${code}`);
    await shot(admin, "admin-pairing-code");
    const info = await (await fetch(`${base}/uwu/v1/server`)).json();
    if (info.product !== "UwUAuth" || !(info.pairing >= 1))
        throw new Error(`/uwu/v1/server: ${JSON.stringify(info)}`);
    const url = "http://localhost:18745";
    const response = await fetch(`${base}/uwu/v1/pair`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
            code: code.toLowerCase(),
            app: {
                product: "UwULock",
                version: "0.6.0",
                name: "UwULock (Test)",
                url,
                // One pink pixel.
                icon: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
                redirectUris: [`${url}/identity/connect/oidc-signin`],
                roles: [
                    { id: "admin", name: "Administrator" },
                    { id: "user", name: "Person mit Tresor" },
                ],
            },
        }),
    });
    const paired = await response.json();
    if (!response.ok || !paired.clientSecret || paired.issuer !== info.issuer)
        throw new Error(`/uwu/v1/pair: ${response.status} ${JSON.stringify(paired)}`);
    // The dialog notices by itself.
    await dialog.getByText("„UwULock (Test)“ ist gekoppelt.").waitFor();
    await shot(admin, "admin-pairing-done");
    await dialog.getByRole("button", { name: "Zur App" }).click();
    await title(admin, "UwULock (Test)");
    await admin.getByText("UwULock 0.6.0").waitFor();
    await shot(admin, "admin-app-suite");
    await admin.getByText("Person mit Tresor").scrollIntoViewIfNeeded();
    await shot(admin, "admin-app-suite-roles");
}

/** OpenID Connect, end to end, with the admin's browser as the person and this script as the app. */
async function oidc(admin) {
    const callback = "http://localhost:18744/cb";
    // Nothing listens there: the browser's request is answered here, and the address it went to
    // carries the answer.
    await admin.route("http://localhost:18744/**", (route) =>
        route.fulfill({
            status: 200,
            contentType: "text/html",
            body: "<h1>Die App</h1>",
        }),
    );

    // ── An app from the generic template that asks first ──
    await admin.goto(`${base}/admin#/apps`);
    await title(admin, "Apps");
    await admin.getByRole("button", { name: "Neue App" }).click();
    await title(admin, "Neue App");
    await shot(admin, "admin-app-templates");
    await admin.getByRole("button", { name: /Andere App/ }).click();
    await admin.getByLabel("Name", { exact: true }).fill("Testapp");
    const redirects = admin.getByLabel("Weiterleitungs-Adressen: neue Adresse");
    await redirects.fill(callback);
    await redirects.press("Enter");
    await admin
        .getByLabel("Adresse zum Öffnen (freiwillig)")
        .fill("http://localhost:18744/");
    await admin
        .getByRole("switch", { name: "Vorher um Erlaubnis fragen" })
        .click();
    await shot(admin, "admin-app-new");
    await admin.getByRole("button", { name: "App anlegen" }).click();
    await title(admin, "„Testapp“ ist angelegt ✧");
    const clientId = await admin
        .locator(".copy-field code")
        .first()
        .innerText();
    const clientSecret = await admin.locator(".secret-once code").innerText();
    if (!clientId.startsWith("testapp-") || clientSecret.length < 20)
        throw new Error(`no client id or secret: ${clientId} ${clientSecret}`);
    await shot(admin, "admin-app-secret");
    await admin.getByRole("button", { name: "Fertig – zur App" }).click();
    await title(admin, "Testapp");
    await admin.locator(".secret-once").waitFor({ state: "detached" });
    await shot(admin, "admin-app-detail");
    await admin.emulateMedia({ colorScheme: "dark" });
    await admin.setViewportSize({ width: 1280, height: 2300 });
    await shot(admin, "admin-app-detail-dark");
    await admin.setViewportSize({ width: 1280, height: 860 });
    await admin.emulateMedia({ colorScheme: "light" });
    // Changing one thing sends only that.
    await admin.getByLabel("Beschreibung").fill("Nur zum Testen");
    await admin.getByRole("button", { name: "Speichern" }).click();
    await admin.getByText("Gespeichert ✧").waitFor();
    await admin
        .getByText("Ungespeicherte Änderungen")
        .waitFor({ state: "detached" });

    // A time window for this app only, for the kids.
    await admin.goto(`${base}/admin#/groups`);
    await admin.getByRole("button", { name: /Kinder/ }).click();
    await title(admin, "Kinder");
    const windows = admin.locator(".section", { hasText: "Zeitfenster" });
    await windows
        .getByRole("button", { name: "Zeitfenster hinzufügen" })
        .click();
    await windows
        .getByLabel("Für welche App?")
        .selectOption({ label: "Testapp" });
    await windows.getByText("(nur Testapp)").waitFor();
    await windows.getByRole("button", { name: "Speichern" }).click();
    await admin.getByText("Gespeichert ✧").waitFor();
    await admin.reload();
    await title(admin, "Kinder");
    await windows.getByText("(nur Testapp)").waitFor();
    await shot(admin, "group-app-window");

    // ── Signing in to it: authorize with PKCE, agree, the code for tokens ──
    const signIn = async (extra = {}) => {
        const verifier = randomBytes(32).toString("base64url");
        const challenge = createHash("sha256")
            .update(verifier)
            .digest("base64url");
        const state = randomBytes(8).toString("hex");
        const query = new URLSearchParams({
            response_type: "code",
            client_id: clientId,
            redirect_uri: callback,
            scope: "openid profile email groups",
            state,
            nonce: "n-0S6",
            code_challenge: challenge,
            code_challenge_method: "S256",
            ...extra,
        });
        await admin.goto(`${base}/oauth/authorize?${query}`);
        return { verifier, state };
    };
    const exchange = async ({ verifier, state }) => {
        await admin.waitForURL(/^http:\/\/localhost:18744\/cb\?/);
        const answer = new URL(admin.url());
        if (answer.searchParams.get("state") !== state)
            throw new Error(`state: ${answer}`);
        if (answer.searchParams.get("iss") !== base)
            throw new Error(`iss: ${answer}`);
        const tokens = await post(
            "/oauth/token",
            {
                grant_type: "authorization_code",
                code: answer.searchParams.get("code") ?? "",
                redirect_uri: callback,
                code_verifier: verifier,
            },
            [clientId, clientSecret],
        );
        const idToken = claims(tokens.id_token);
        if (idToken.preferred_username !== "nyu" || idToken.nonce !== "n-0S6")
            throw new Error(`ID token: ${JSON.stringify(idToken)}`);
        return tokens;
    };
    let flow = await signIn();
    await title(admin, "„Testapp“ möchte wissen, wer du bist");
    await shot(admin, "consent");
    await admin.getByRole("button", { name: "Erlauben", exact: true }).click();
    await exchange(flow);

    // ── "My apps": the tile, the grant, and taking it back ──
    await admin.goto(`${base}/#/apps`);
    await title(admin, "Meine Apps");
    const grant = admin.locator(".item", { hasText: "Testapp" });
    await grant.waitFor();
    await admin.locator(".app-tile", { hasText: "Testapp" }).waitFor();
    await shot(admin, "my-apps");
    await admin.setViewportSize({ width: 390, height: 844 });
    await shot(admin, "my-apps-phone");
    await admin.setViewportSize({ width: 1280, height: 860 });
    await grant.getByRole("button", { name: "Zugriff entziehen" }).click();
    await admin
        .getByRole("dialog")
        .getByRole("button", { name: "Zugriff entziehen" })
        .click();
    await admin.getByText("Noch keine App hat dich angemeldet.").waitFor();

    // ── The app asks to sign in again: the form shows although a session is there ──
    await admin.presence(false);
    flow = await signIn({ prompt: "login" });
    await title(admin, "Anmelden");
    if (!admin.url().includes("fresh=1"))
        throw new Error(`no fresh sign-in: ${admin.url()}`);
    await admin
        .getByText("Die App möchte, dass du dich noch einmal anmeldest.")
        .waitFor();
    await shot(admin, "login-fresh");
    await admin.presence(true);
    await admin
        .getByRole("button", { name: "Mit Passkey anmelden" })
        .click({ timeout: 3000 })
        .catch(() => undefined);
    // The grant was taken back: the app asks again.
    await title(admin, "„Testapp“ möchte wissen, wer du bist");
    await admin.setViewportSize({ width: 390, height: 844 });
    await shot(admin, "consent-phone");
    await admin.setViewportSize({ width: 1280, height: 860 });
    await admin.getByRole("button", { name: "Erlauben", exact: true }).click();
    await exchange(flow);

    // ── A TV: a public app with the device flow, the code typed in the browser ──
    await admin.goto(`${base}/admin#/apps/new`);
    await admin.getByRole("button", { name: /Andere App/ }).click();
    await admin.getByLabel("Name", { exact: true }).fill("Fernseher");
    await admin
        .getByRole("switch", { name: "Öffentliche App, ohne Geheimnis" })
        .click();
    await admin.getByText("Mehr Optionen").click();
    await admin
        .getByRole("checkbox", { name: /Anmelden im Browser/ })
        .uncheck();
    await admin.getByRole("checkbox", { name: /Geräte ohne Browser/ }).check();
    await admin.getByRole("button", { name: "App anlegen" }).click();
    await title(admin, "„Fernseher“ ist angelegt ✧");
    const tvId = await admin.locator(".copy-field code").first().innerText();
    const started = await post("/oauth/device_authorization", {
        client_id: tvId,
        scope: "openid profile",
    });
    if (!started.verification_uri_complete?.includes("/#/device?code="))
        throw new Error(`device: ${JSON.stringify(started)}`);

    // Somebody without a session is sent to sign in first, and comes back to the code.
    const phone = await newBrowser("phone");
    await phone.presence(false);
    await phone.goto(started.verification_uri_complete);
    await title(phone, "Anmelden");
    if (!decodeURIComponent(phone.url()).includes("continue=/#/device?code="))
        throw new Error(`no way back to the device page: ${phone.url()}`);
    await shot(phone, "device-sign-in-first");

    await admin.goto(`${base}/#/device`);
    await title(admin, "Gerät verbinden");
    await admin
        .getByLabel("Code")
        .fill(started.user_code.toLowerCase().replace("-", " "));
    await shot(admin, "device-code");
    await admin.getByRole("button", { name: "Weiter" }).click();
    await title(admin, "„Fernseher“ verbinden?");
    await shot(admin, "device-confirm");
    await admin.getByRole("button", { name: "Verbinden", exact: true }).click();
    await title(admin, "Verbunden ✧");
    await shot(admin, "device-done");
    const deviceTokens = await post("/oauth/token", {
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: started.device_code,
        client_id: tvId,
    });
    if (claims(deviceTokens.id_token).preferred_username !== "nyu")
        throw new Error(`device tokens: ${JSON.stringify(deviceTokens)}`);

    // ── The apps list, and the pages for refusals and broken apps ──
    await admin.goto(`${base}/admin#/apps`);
    await title(admin, "Apps");
    await admin.locator(".person-row", { hasText: "Fernseher" }).waitFor();
    await shot(admin, "admin-apps");
    await admin.goto(
        `${base}/#/denied?reason=mfa&app=Tresor&continue=${encodeURIComponent("/oauth/authorize?client_id=x")}`,
    );
    await title(admin, "Noch ein Schritt für diese App");
    await admin
        .getByRole("button", { name: "Jetzt bestätigen und weiter" })
        .waitFor();
    await shot(admin, "denied-mfa");
    await admin.goto(`${base}/#/denied?reason=time&app=Spiele`);
    await title(admin, "Gerade nicht");
    await shot(admin, "denied-time");
    await admin.goto(
        `${base}/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent("https://evil.example.net/cb")}`,
    );
    await title(admin, "Mit der App stimmt etwas nicht");
    await shot(admin, "oauth-error");

    // The event log tells about apps too.
    await admin.goto(`${base}/admin#/events`);
    await admin
        .getByText("Nyu Neko hat sich bei „Testapp“ angemeldet.")
        .first()
        .waitFor();
    await admin
        .getByText("Nyu Neko hat ein Gerät mit „Fernseher“ verbunden.")
        .waitFor();
    await shot(admin, "admin-events-apps");

    // ── Signing out from an app, without a hint: confirmed first ──
    await admin.presence(false);
    await admin.goto(`${base}/oauth/logout`);
    await title(admin, "Abmelden?");
    await shot(admin, "logout-confirm");
    await admin
        .getByRole("button", { name: "Abmelden", exact: true })
        .last()
        .click();
    await title(admin, "Du bist abgemeldet");
    await admin.emulateMedia({ colorScheme: "dark" });
    await shot(admin, "signed-out-dark");
    await admin.emulateMedia({ colorScheme: "light" });
}

try {
    await run();
    console.log("✓ the web app works end to end");
    await browser.close();
} catch (error) {
    console.error(`✗ ${error.stack ?? error}`);
    for (const { name, page } of pages) {
        await page
            .screenshot({
                path: join(shotDir, `failure-${name}.png`),
                fullPage: true,
            })
            .catch(() => undefined);
    }
    await browser.close();
    process.exit(1);
}
