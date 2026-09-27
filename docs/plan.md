# Plan: UwUAuth Server

Ein eigener Identitätsserver für die UwUSuite und alles andere im Haus: Personen und Gruppen an
einer Stelle, und jede App meldet sich darüber an — per OpenID Connect, LDAP, SAML, RADIUS oder
hinter einem Reverse-Proxy. Gedacht für die Familie zuhause und das kleine Büro, gebaut so, dass
später auch eine Firma damit auskommt.

Stand: September 2026. Stufe 0 (das Gerüst) ist fertig und wird 0.0.1. Als Nächstes kommt
Stufe 1, die Benutzerverwaltung.

## Leitlinien

- **Zuerst die Benutzerverwaltung.** Personen, Gruppen, Einladungen und Anmeldung sind der Kern.
  Jedes Protokoll ist danach nur eine weitere Tür zu derselben Liste, keine eigene Welt mit
  eigenen Konten.
- **Für die Familie gedacht, für die Firma gebaut.** In fünf Minuten eingerichtet, die Oberfläche
  spricht von „Personen“, „Gruppen“ und „Apps“ statt von DNs und Realms. Darunter stecken aber
  Begriffe, die tragen: stabile IDs, verschachtelte Gruppen, Organisationseinheiten und
  delegierte Verwaltung (später), PostgreSQL (später).
- **Standards statt Eigenbau.** OpenID Connect / OAuth 2, LDAPv3, SAML 2.0, SCIM 2.0, RADIUS.
  Der UwUSuite-Weg ist nur eine Komfortschicht darüber (Kopplung per Code). Jede Suite-App
  funktioniert auch mit Keycloak, Authentik oder Authelia, und UwUAuth mit jeder anderen App.
- **Active Directory nur als LDAP-Dialekt.** UwUAuth spricht LDAP so, dass Apps mit der
  Einstellung „Active Directory“ es dafür halten (sAMAccountName, userPrincipalName, memberOf …).
  Ein echter Domain Controller (Windows-Domänenbeitritt, Kerberos, NTLM, Gruppenrichtlinien) ist
  **ausdrücklich kein Ziel**. Dafür bleibt Samba.
- **Passkeys zuerst.** Anmelden ohne Passwort ist der Normalfall, den die Oberfläche anbietet.
  Passwörter gibt es trotzdem (LDAP und RADIUS brauchen sie), gespeichert als Argon2id. Für
  Protokolle, die keinen Passkey können, gibt es App-Passwörter pro Gerät oder Dienst.
- **Eine Datei, ein Container.** SQLite, ein Docker-Image für amd64 und arm64, `install.sh` und
  `update.sh` wie bei UwULock Server und UwUMail Server. PostgreSQL kommt später als zweites
  Backend hinter derselben `Store`-Schicht.
- **Nichts nach draußen.** Keine Telemetrie. Von sich aus öffnet der Server nur Verbindungen zu
  Let's Encrypt (falls genutzt), zum eigenen Mailserver und einmal am Tag zu GitHub für den
  Update-Hinweis (`UWUAUTH_UPDATE_CHECK=off` schaltet das ab).
- **Sicher ab Werk.** Rate-Limits, ein Ereignisprotokoll für jede Anmeldung und jede Änderung,
  keine Geheimnisse im Log, Schlüssel und Geheimnisse in der Datenbank versiegelt. Vor jeder
  Beta mit neuem Protokoll gibt es ein Security-Review.

## Einordnung

Warum nicht einfach eines der vorhandenen Programme? Alle sind gut, aber keines ist genau das hier:

| Programm | Stärke | Warum trotzdem UwUAuth |
| --- | --- | --- |
| Keycloak | Kann alles, Standard in Firmen | Java, groß, für eine Familie viel zu schwer |
| Authentik | Viele Protokolle, schöne Flows | Mehrere Container, Python, PostgreSQL nötig |
| Authelia | Schlank, Forward-Auth und OIDC | Keine eigene Benutzerverwaltung (Datei oder fremdes LDAP) |
| LLDAP | Rust, winzig, einfaches LDAP | Nur LDAP, keine Anmeldeprotokolle darüber |
| Kanidm | Rust, durchdacht, LDAP + OIDC + RADIUS | Eigenwillig in der Bedienung, keine Familien-Funktionen |
| Samba AD | Echter Domain Controller | Schwer zu betreiben, für Web-Apps nicht gemacht |

UwUAuth will: ein Container, eine Oberfläche im UwU-Look, Familien-Funktionen (Kinderkonten,
Einladung per QR-Code) und die direkte Verbindung zur UwUSuite.

## Begriffe und Datenmodell

- **Person** — eine unveränderliche ID (UUID; für LDAP zusätzlich als `objectGUID`/`entryUUID`),
  ein änderbarer Benutzername, Anzeigename, Vor- und Nachname, E-Mail-Adressen (verifiziert oder
  nicht), Profilbild, Sprache, Status (eingeladen, aktiv, gesperrt), optional ein Ablaufdatum.
  Dazu frei definierbare Attribute und optional POSIX-Werte (`uidNumber`, `gidNumber`,
  `homeDirectory`, `loginShell`) für Linux-Rechner und NAS.
- **Gruppe** — Name, Beschreibung, Besitzer, Mitglieder (Personen und Gruppen, also
  verschachtelt), optional eine POSIX-`gidNumber`. Von Anfang an da: „Admins“ und „Alle“.
- **Rollen** — *Admin* (darf alles), *Verwalter* (verwaltet bestimmte Personen: Eltern ihre
  Kinder, eine Teamleitung ihr Team), *Mitglied*, *verwaltetes Konto* (Kind: ohne eigene
  E-Mail möglich, Zurücksetzen nur durch den Verwalter).
- **Anmeldemethoden** — Passkey (WebAuthn, auch als einziger Faktor), Passwort, TOTP,
  Wiederherstellungscodes. **App-Passwörter** für alles, was nur Benutzername und Passwort kennt
  (LDAP-Bind, RADIUS, Mail-Apps über UwUMail), jedes einzeln widerrufbar.
- **Apps** (ab Stufe 2) — OIDC-Clients, SAML-Dienste, LDAP-Dienstkonten, RADIUS-Clients und
  Proxy-geschützte Seiten. Jede App hat Zugriffsregeln: welche Gruppen, zu welchen Zeiten, ob
  ein zweiter Faktor Pflicht ist.
- **Ereignisprotokoll** — jede Anmeldung (auch fehlgeschlagene), jede Änderung, wer sie gemacht
  hat, von wo. Für Admins alles, für Verwalter das ihrer Personen, für jeden das Eigene.
- **Mandant** — in 0.x genau einer pro Server (der Haushalt, das Büro). Mehrere Mandanten auf
  einem Server sind eine Frage für Stufe 9.

## Aufbau

| Crate / Ordner | Was es macht |
| --- | --- |
| `uwuauth-store` | Datenbank: SQLite mit einer Schreib- und mehreren Leseverbindungen, Migrationen, Backup und Restore. Alles darüber spricht nur mit `Store`, nie direkt mit SQLite. |
| `uwuauth-api` | HTTP: UwUAuths eigene API unter `/uwu/v1` (Web-App, Skripte, Suite), später die HTTP-Protokolle (OIDC, SAML, SCIM, Forward-Auth), und die Web-App. |
| `uwuauth-web` | Die Dateien der Web-App, in die Binary eingebettet. |
| `uwuauth-server` | Das Programm: Einstellungen, TLS (Let's Encrypt, Zertifikatsdateien oder hinter einem Proxy), Befehle, nächtliche Backups, Update-Hinweis; startet später auch die LDAP- und RADIUS-Listener. |
| `web/` | Die Web-App (React, im Look der anderen UwU-Apps, Deutsch und Englisch): Anmeldeseiten, Self-Service-Portal und Admin-Portal. |
| später `uwuauth-mail` | SMTP und Mailvorlagen (de/en). Stufe 1. |
| später `uwuauth-oidc` | OAuth-2- und OpenID-Connect-Provider. Stufe 2. |
| später `uwuauth-ldap` | LDAPv3-Server, mit dem Protokoll-Code aus `ldap3_proto` (von Kanidm). Stufe 3. |
| später `uwuauth-scim` | SCIM 2.0 als Client (UwUAuth schiebt Personen in Apps) und als Server. Stufen 4 und 7. |
| später `uwuauth-saml` | SAML-2.0-IdP. Stufe 6. |
| später `uwuauth-radius` | RADIUS mit EAP-TTLS und EAP-TLS. Stufe 8. |

**Ports.** 443 (HTTPS: Web-App, OIDC, SAML, SCIM, Forward-Auth), 389 und 636 (LDAP mit
StartTLS, LDAPS), 1812/1813 UDP (RADIUS). Im Container lauscht alles über 1024 (8443, 10389,
10636, 11812/11813), so braucht er weiterhin keine Linux-Capability. `compose.yaml` bildet die
Standard-Ports darauf ab, und jede Stufe schaltet ihren Port erst frei, wenn sie da ist.

**Zertifikate.** Ein Zertifikat für alles: dasselbe von Let's Encrypt oder aus Dateien dient
HTTPS, LDAPS und (als Server-Zertifikat) EAP. Hinter einem Proxy braucht LDAPS eigene
Zertifikatsdateien oder den Proxy auch für TCP (Stufe 3 beschreibt beides).

## Stufen

Jede Stufe ist ein Release und für sich nutzbar. Stufen mit neuem Protokoll bekommen vor dem
Release ein Security-Review (Critical/High/Medium beheben, Low aufschreiben).

### Stufe 0 — Gerüst (0.0.1, fertig)

- [x] Repository, Workspace, CI (fmt, clippy, Tests, Audit, Web-App, Binaries amd64 + arm64
      nativ cross-kompiliert, Install-/Update-Test, Image mit Trivy-Scan, Release)
- [x] Docker-Image amd64 + arm64, `install.sh` (Let's Encrypt oder hinter einem Proxy, auch
      Proxy im Container) und `update.sh` mit Kanälen latest / beta / edge und Rückweg, wenn
      eine Version nicht hochkommt
- [x] TLS: Let's Encrypt über TLS-ALPN-01 (nur Port 443), Zertifikatsdateien mit Neuladen, oder
      Klartext hinter einem Proxy; in CI gegen Pebble getestet
- [x] SQLite mit Migrationen, Backups (nächtlich, vor jedem Update, sieben behalten), Restore
- [x] `/healthz`, `/alive`, Update-Hinweis im Log, `/uwu/v1/server` (was dieser Server ist und
      welche Protokolle er spricht, das Erste, was eine Suite-App fragt)
- [x] Web-App als Platzhalter, eingebettet, mit strenger CSP und ohne Einbettung in fremde Seiten
- [x] Plan, README, Nyu als Ausweis

### Stufe 1 — Benutzerverwaltung (0.1)

Das Herz. Noch kein Protokoll nach außen, aber alles, was die späteren Protokolle brauchen.

**Personen und Gruppen**

- [ ] Personen anlegen, ändern, sperren, entsperren, löschen (erst 30 Tage im Papierkorb)
- [ ] Gruppen, verschachtelt, mit Besitzern; „Admins“ und „Alle“ von Anfang an
- [ ] Eigene Attribute pro Person (Text, Zahl, Datum, Auswahl); optionale POSIX-Werte, fortlaufend
      vergeben
- [ ] Profilbilder (klein gerechnet, im Container gespeichert)
- [ ] Import und Export als CSV und JSON

**Einladung und Einrichtung**

- [ ] Ersteinrichtung: `install.sh --admin` bzw. `uwuauth-server invite --admin` gibt den Link aus,
      dann ein kurzer Assistent: Name des Haushalts oder der Firma, Sprache, Mail
- [ ] Wahl beim Einrichten: *Familie* oder *Büro* — ändert nur Wörter und Voreinstellungen
      (z. B. „Eltern/Kinder“ statt „Verwalter/verwaltete Konten“), nicht die Funktionen
- [ ] Einladung per Link und **QR-Code**: einmal nutzbar, 7 Tage gültig, Gruppen und Rolle
      vorausgewählt, per Mail, wenn ein Mailserver eingerichtet ist
- [ ] Beim Annehmen direkt einen Passkey anlegen (Passwort nur, wenn gewünscht)
- [ ] Registrierung nur per Einladung; offene Registrierung oder Registrierung per Domain erst,
      wenn jemand danach fragt

**Anmeldung**

- [ ] Passkeys (WebAuthn, Discoverable Credentials, Passkey-Autofill im Anmeldefeld)
- [ ] Passwort mit Argon2id; Regeln nach NIST SP 800-63B (Länge statt Sonderzeichen-Zwang);
      optional die Prüfung gegen Have I Been Pwned per k-Anonymität über den Server, sodass der
      Browser nie mit Dritten spricht
- [ ] TOTP und Wiederherstellungscodes; zweiter Faktor als Pflicht pro Gruppe
- [ ] Sitzungen und Geräte: Liste, einzeln abmelden, überall abmelden
- [ ] Passwort vergessen per Mail; bei verwalteten Konten Zurücksetzen durch den Verwalter
- [ ] Rate-Limits pro Adresse und pro Konto, sanfte Sperre nach Fehlversuchen, Hinweis per Mail
      bei Anmeldung von einem neuen Gerät (abschaltbar)
- [ ] App-Passwörter anlegen und widerrufen (genutzt ab Stufe 3)

**Self-Service-Portal** (für jeden)

- [ ] Profil, Profilbild, Sprache, E-Mail-Adresse ändern (mit Bestätigung)
- [ ] Passkeys, Passwort, TOTP, Wiederherstellungscodes, App-Passwörter
- [ ] Eigene Sitzungen und eigener Anmeldeverlauf
- [ ] Eigene Gruppen; „Meine Apps“ als Kacheln (leer, bis Stufe 2 Apps bringt)

**Verwaltete Konten (Kinder)**

- [ ] Rolle *Verwalter* für bestimmte Personen oder Gruppen (Eltern → Kinder, Teamleitung → Team)
- [ ] Konto ohne E-Mail, nur mit Benutzername; Passkey-Einrichtung per QR-Code auf dem Gerät des
      Kindes, vom Verwalter ausgelöst
- [ ] Verwalter setzen Passwörter zurück, sperren und entsperren, sehen Anmeldungen ihrer Personen
- [ ] Regeln für App-Zugriff und Zeitfenster pro Person oder Gruppe hinterlegen („Schul-Tablet
      nur 7–20 Uhr“). Wirksam, sobald Apps sich über UwUAuth anmelden (Stufe 2, 5 und 8)

**Admin-Portal** unter `/admin`

- [ ] Personen, Gruppen, Einladungen, Rollen
- [ ] Einstellungen: Mail (mit Testmail), Sprache, Passwortregeln, Sitzungsdauer, Registrierung
- [ ] Ereignisprotokoll, Server-Log, Backups (anlegen, herunterladen), Update-Hinweis
- [ ] Admin-API mit API-Tokens für Skripte, beschrieben als OpenAPI

**Werkzeuge**

- [ ] `uwuauth-mail`: SMTP (STARTTLS/TLS), Vorlagen auf Deutsch und Englisch
- [ ] Befehle: `invite`, `admin`, `reset-password`, `reset-2fa`, damit man auch ohne
      funktionierenden Admin wieder hineinkommt
- [ ] Browser-Test in CI (Playwright): einladen, Passkey anlegen (virtueller Authenticator),
      anmelden, Kind verwalten

### Stufe 2 — OpenID Connect und OAuth 2 (0.2)

- [ ] OIDC-Provider: Discovery, JWKS (ES256, dazu RS256 für ältere Apps), Authorization Code mit
      PKCE, Refresh-Tokens mit Rotation, UserInfo, RP-initiated und Back-Channel-Logout
- [ ] Device Authorization Grant (RFC 8628) für Fernseher und Kommandozeilen, Client Credentials
      für Dienste, Token Introspection und Revocation
- [ ] Claims: `sub` (die unveränderliche ID), `preferred_username`, `email`, `name`, `picture`,
      `groups`, eigene Attribute und Rollen pro App
- [ ] Apps im Admin-Portal anlegen, mit Vorlagen für häufige selbst gehostete Apps (Nextcloud,
      Immich, Jellyfin, Home Assistant, Forgejo/Gitea, Grafana, Paperless-ngx, Proxmox,
      Portainer …), jeweils mit einer kurzen Anleitung für die Gegenseite
- [ ] Zugriffsregeln greifen: Gruppen, Zeitfenster, zweiter Faktor pro App
- [ ] Anmeldeseite im UwU-Look, „Angemeldet bleiben“, Zustimmung nur für fremde Apps
- [ ] Dynamic Client Registration (RFC 7591), aber nur mit Einmal-Token — die Grundlage der
      Suite-Kopplung in Stufe 4
- [ ] Anmeldung mit externen Konten (Google, Microsoft, Apple, GitHub) als Option pro Person
- [ ] In CI: die OpenID-Conformance-Suite (als eigener, wöchentlicher Job)

### Stufe 3 — LDAP im Stil von Active Directory (0.3)

- [ ] LDAPv3-Server: Bind (Konto-Passwort oder App-Passwort), Search, Compare, WhoAmI (RFC 4532),
      StartTLS und LDAPS, Paged Results (RFC 2696), Root DSE und Schema
- [ ] Zwei Sichten auf dieselben Daten, gleichzeitig:
  - **RFC 2307bis / inetOrgPerson** für Linux (SSSD), NAS und die meisten Apps
  - **AD-Stil**: `sAMAccountName`, `userPrincipalName`, `memberOf`, `objectGUID`, `objectSid`,
    `userAccountControl`, `primaryGroupID`, `distinguishedName`, damit Apps mit der Einstellung
    „Active Directory“ funktionieren
- [ ] Verschachtelte Gruppen, auch über `LDAP_MATCHING_RULE_IN_CHAIN`
      (`1.2.840.113556.1.4.1941`), wie Apps es von AD kennen
- [ ] Dienstkonten für Apps: nur lesen, auf Teilbäume beschränkt
- [ ] Passwort ändern über LDAP: Password Modify (RFC 3062) und AD-`unicodePwd`
- [ ] Schreiben über LDAP (Personen anlegen) erst, wenn es gebraucht wird
- [ ] Getestet mit: `ldapsearch`, SSSD, Synology- und QNAP-Verzeichnisdienst, Nextcloud,
      Jellyfin-LDAP-Plugin, Forgejo, Proxmox (AD-Realm), Home Assistant
- [ ] Kein Kerberos, kein NTLM, kein Domänenbeitritt (siehe Leitlinien)

### Stufe 4 — Kopplung mit der UwUSuite (0.4)

Die Suite-Apps sprechen danach OIDC und SCIM wie jede andere App — die Kopplung nimmt nur das
Abtippen von Client-IDs, Secrets und Redirect-URIs ab.

**So läuft es**

1. Im UwUAuth-Admin-Portal: *Apps → UwUSuite-App koppeln* zeigt einen Kopplungscode (einmal
   nutzbar, 15 Minuten gültig, auch als QR-Code).
2. In der Suite-App (z. B. im Admin-Portal von UwUMail Server): *Mit UwUAuth verbinden*, Adresse
   und Code eintragen.
3. Die App fragt `/uwu/v1/server` (Ist das ein UwUAuth? Was spricht es?) und schickt dann
   `POST /uwu/v1/pair` mit dem Code und ihren Daten: Name, Symbol, Redirect-URIs, ihr
   SCIM-Endpunkt und welche Rollen sie kennt.
4. UwUAuth legt einen OIDC-Client an und gibt Issuer, Client-ID und Secret zurück, dazu einen
   Token, mit dem die App SCIM-Aufrufe von UwUAuth prüft.
5. UwUAuth schiebt Personen und Gruppen per SCIM in die App, aber nur die Gruppen, die im
   Admin-Portal für diese App freigegeben sind. Anmeldung läuft über OIDC. Die lokalen Konten
   der App bleiben als Notzugang erhalten.

**Pro Programm** (jeweils ein eigener PR in dessen Repository)

- [ ] **UwUMail Server** — kann schon OIDC-Anmeldung und LDAP. Dazu kommen die Kopplung, SCIM
      (Postfach anlegen, sperren, Alias aus E-Mail-Adressen) und die Frage, ob Mail-Apps sich mit
      App-Passwörtern aus UwUAuth anmelden oder weiter über UwUMails eigenes OAuth
- [ ] **UwULock Server** — Zero-Knowledge bleibt: SSO bestätigt nur, wer jemand ist; der Tresor
      wird weiter mit dem Master-Passwort entschlüsselt (wie Bitwardens „SSO mit
      Master-Passwort“), später vielleicht mit vertrauenswürdigen Geräten. Einladungen kommen per
      SCIM statt per Mail
- [ ] **UwUSync Server** (UwUSSH, UwURDP) — Anmeldung mit dem UwUAuth-Konto; die Daten bleiben
      Ende-zu-Ende-verschlüsselt
- [ ] **Desktop-Apps** (UwUMail, UwULock, UwUSSH, UwURDP) — Anmeldung im Browser (OIDC mit PKCE
      und Loopback-Redirect), wenn ihr Server mit UwUAuth gekoppelt ist
- [ ] `/.well-known/uwusuite` für die automatische Erkennung im selben Netz oder unter derselben
      Domain

### Stufe 5 — Forward-Auth für Reverse-Proxies (0.5)

- [ ] `/uwu/v1/forward-auth` für Caddy (`forward_auth`), Traefik (ForwardAuth), nginx
      (`auth_request`) und Nginx Proxy Manager; gibt `Remote-User`, `Remote-Groups`,
      `Remote-Email`, `Remote-Name` weiter
- [ ] Sitzungs-Cookie für die ganze Domain, Regeln pro Host und Pfad (Gruppen, Zeitfenster,
      zweiter Faktor)
- [ ] Damit lassen sich Apps ohne eigene Anmeldung schützen, und Zeitfenster für Kinder gelten
      auch dort
- [ ] Beispiele für jeden Proxy in `docs/`, im CI gegen einen echten Caddy getestet

### Stufe 6 — SAML 2.0 (0.6)

- [ ] IdP: Metadaten, SP- und IdP-initiiertes SSO, HTTP-Redirect und HTTP-POST, signierte
      Assertions (RSA-SHA256), optional verschlüsselt, Single Logout
- [ ] XML-Signatur ohne `xmlsec` (C-Abhängigkeit, schwierig für die arm64-Cross-Builds): eine
      schmale eigene Umsetzung (Exclusive C14N, nur das, was ein IdP braucht), mit Tests gegen
      Signature Wrapping; vorher prüfen, ob es eine reine Rust-Bibliothek gibt, die reicht
- [ ] Vorlagen für Apps, die nur SAML können

### Stufe 7 — SCIM 2.0 und Übernahme (0.7)

- [ ] SCIM-Client allgemein: Personen und Gruppen in jede App schieben, die SCIM annimmt
- [ ] SCIM-Server: Personen aus Entra ID, Google Workspace oder Okta empfangen, für Firmen, die
      dort führen
- [ ] Einmalige Übernahme aus OpenLDAP, LLDAP, Authentik, Keycloak und einem echten AD (per LDAP)
- [ ] Laufender Abgleich aus einem vorhandenen AD oder LDAP (UwUAuth als Front davor)

### Stufe 8 — RADIUS (0.8)

- [ ] RADIUS-Server (UDP 1812/1813); Clients (Router, Access Points) mit Shared Secret im
      Admin-Portal
- [ ] WLAN mit WPA2/WPA3-Enterprise:
  - **EAP-TTLS/PAP** — das Passwort im TLS-Tunnel, funktioniert mit Argon2-Hashes
  - **EAP-TLS** — ein Zertifikat pro Gerät von einer kleinen eigenen CA; Einrichtung per
    Profil-Download bzw. QR-Code für iOS, Android, Windows und macOS
  - **PEAP-MSCHAPv2** nur, wenn ausdrücklich eingeschaltet: braucht den NT-Hash, also nur für
    Personen oder Gruppen, die es wirklich brauchen, mit deutlicher Warnung
- [ ] VLAN pro Gruppe (Kinder-WLAN, Gäste-WLAN), Zeitfenster auch fürs WLAN
- [ ] Getestet mit `eapol_test` und `radtest` in CI, von Hand mit UniFi, OpenWrt, MikroTik und
      OPNsense

### Stufe 9 — Größere Umgebungen (1.x)

- [ ] PostgreSQL als zweites Backend
- [ ] Mehrere Instanzen hinter einem Load Balancer, Hochverfügbarkeit
- [ ] Organisationseinheiten und delegierte Admins; mehrere Mandanten auf einem Server
- [ ] Richtlinien pro Gruppe (Passwortregeln, erlaubte Netze, Pflicht-Passkey)
- [ ] Lebenszyklus: Eintritt und Austritt als Ablauf, Konten mit Ablaufdatum,
      regelmäßige Zugriffsüberprüfung
- [ ] Prometheus-Metriken, Ereignisprotokoll an Syslog oder ein SIEM
- [ ] Zertifizierung bei der OpenID Foundation, wenn es sich lohnt

## Tests und CI

Schnell bleiben ist Teil des Plans, Vorbild ist UwUMail Server:

- Eine Integrationstest-Binary pro Crate (`tests/integration/main.rs` bindet alle Dateien als
  Module ein), `debug = "line-tables-only"` und keine Debug-Infos für Abhängigkeiten.
- Jeder Test hat seine eigene Datenbank im Temp-Verzeichnis, Ports über `127.0.0.1:0`,
  HTTP-Handler in-process ohne Socket. Mailserver, SCIM-Gegenstellen, OIDC-Clients und
  RADIUS-Clients sind lokale Fakes. Tests, die das Internet oder externe Dienste brauchen, sind
  `#[ignore]` und laufen in eigenen Jobs.
- Keine festen Sleeps; Argon2 in Tests mit günstigen Parametern.
- CI: Cache für Cargo und pnpm, `concurrency` mit `cancel-in-progress`, reine Doku-Änderungen
  überspringen, unabhängige Jobs parallel, die Binaries einmal bauen und an Install-Test und Image
  weiterreichen, arm64 nativ cross-kompiliert statt unter QEMU.
- Protokoll-Konformität in eigenen, langsameren Jobs: OpenID-Conformance-Suite,
  `ldapsearch`/SSSD in Containern, `eapol_test`, ein SAML-SP (z. B. SimpleSAMLphp) im Container.

## Offene Fragen für später

- Soll UwUAuth seine Mails über einen gekoppelten UwUMail Server verschicken können, ohne eigene
  SMTP-Einstellungen?
- Mehrere Mandanten auf einem Server oder lieber ein Server pro Mandant?
- Eine eigene Authenticator-App (TOTP und Push-Bestätigung) als UwUAuth-Client, oder reichen
  Passkeys?
