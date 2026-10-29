//! Templates for apps people often run at home or in a small office: where they want the answer
//! sent, which scopes they read, and what to fill in on their side.
//!
//! `{url}` in a template is the app's own address, which the admin types; `{slug}` a short name
//! some apps put into their callback. The notes say where the settings are in the app, as far as
//! a note can — apps move their settings around between versions.

use serde_json::{Value, json};

pub struct Template {
    pub key: &'static str,
    pub name: &'static str,
    pub redirect_uris: &'static [&'static str],
    pub post_logout_redirect_uris: &'static [&'static str],
    pub scopes: &'static str,
    /// An app on phones that cannot keep a secret.
    pub public: bool,
    pub id_token_alg: &'static str,
    pub launch_url: &'static str,
    pub notes_de: &'static str,
    pub notes_en: &'static str,
}

pub const TEMPLATES: &[Template] = &[
    Template {
        key: "nextcloud",
        name: "Nextcloud",
        redirect_uris: &["{url}/apps/user_oidc/code"],
        post_logout_redirect_uris: &["{url}/"],
        scopes: "openid profile email groups",
        public: false,
        id_token_alg: "RS256",
        launch_url: "{url}/",
        notes_de: "In Nextcloud die App „OpenID Connect user backend“ (user_oidc) installieren. Unter Administration → OpenID Connect einen Anbieter hinzufügen: Kennung „UwUAuth“, Client-ID und Geheimnis von hier, Discovery-Endpunkt {issuer}/.well-known/openid-configuration. Für Gruppen „Gruppen-Provisionierung“ einschalten und als Gruppen-Claim „groups“ eintragen.",
        notes_en: "In Nextcloud, install the app “OpenID Connect user backend” (user_oidc). Under Administration → OpenID Connect add a provider: identifier “UwUAuth”, client ID and secret from here, discovery endpoint {issuer}/.well-known/openid-configuration. For groups, turn on group provisioning with the claim “groups”.",
    },
    Template {
        key: "immich",
        name: "Immich",
        redirect_uris: &["{url}/auth/login", "{url}/user-settings", "app.immich:///oauth-callback"],
        post_logout_redirect_uris: &[],
        scopes: "openid profile email",
        public: false,
        id_token_alg: "RS256",
        launch_url: "{url}/",
        notes_de: "In Immich unter Administration → Einstellungen → OAuth-Anmeldung: Aussteller-URL {issuer}, Client-ID und Geheimnis von hier, Bereich „openid email profile“. Für die Handy-App „Mobile Weiterleitungs-URI überschreiben“ nicht nötig: app.immich:///oauth-callback ist schon eingetragen.",
        notes_en: "In Immich under Administration → Settings → OAuth: issuer URL {issuer}, client ID and secret from here, scope “openid email profile”. The phone app's app.immich:///oauth-callback is registered already.",
    },
    Template {
        key: "jellyfin",
        name: "Jellyfin",
        redirect_uris: &["{url}/sso/OID/redirect/{slug}", "{url}/sso/OID/r/{slug}"],
        post_logout_redirect_uris: &[],
        scopes: "openid profile groups",
        public: false,
        id_token_alg: "RS256",
        launch_url: "{url}/",
        notes_de: "In Jellyfin das Plugin „SSO Authentication“ installieren und einen OpenID-Anbieter mit dem Namen „{slug}“ anlegen: OID Endpoint {issuer}, Client-ID und Geheimnis von hier. Für Rollen „Roles“ auf den Claim „groups“ setzen.",
        notes_en: "In Jellyfin, install the “SSO Authentication” plugin and add an OpenID provider named “{slug}”: OID endpoint {issuer}, client ID and secret from here. For roles, map the claim “groups”.",
    },
    Template {
        key: "home-assistant",
        name: "Home Assistant",
        redirect_uris: &["{url}/auth/openid/callback", "{url}/auth/oidc/callback"],
        post_logout_redirect_uris: &[],
        scopes: "openid profile groups",
        public: false,
        id_token_alg: "RS256",
        launch_url: "{url}/",
        notes_de: "Home Assistant kann OpenID Connect nur mit einer Erweiterung aus HACS (z. B. „OpenID Connect“ / hass-oidc-auth). Dort die Discovery-URL {issuer}/.well-known/openid-configuration, Client-ID und Geheimnis eintragen.",
        notes_en: "Home Assistant needs an extension from HACS for OpenID Connect (e.g. “OpenID Connect” / hass-oidc-auth). Give it the discovery URL {issuer}/.well-known/openid-configuration, the client ID and the secret.",
    },
    Template {
        key: "forgejo",
        name: "Forgejo / Gitea",
        redirect_uris: &["{url}/user/oauth2/{slug}/callback"],
        post_logout_redirect_uris: &[],
        scopes: "openid profile email groups",
        public: false,
        id_token_alg: "RS256",
        launch_url: "{url}/",
        notes_de: "In Forgejo unter Website-Administration → Identitäts- & Zugriffsverwaltung → Authentifizierungsquellen eine Quelle „OAuth2“ mit dem Namen „{slug}“ anlegen: Anbieter „OpenID Connect“, Client-ID und Geheimnis von hier, Auto-Discovery-URL {issuer}/.well-known/openid-configuration. Admins über „Claim-Name für Gruppen“ = groups und den Namen der Admin-Gruppe.",
        notes_en: "In Forgejo under Site administration → Identity & access → Authentication sources add an “OAuth2” source named “{slug}”: provider “OpenID Connect”, client ID and secret from here, auto discovery URL {issuer}/.well-known/openid-configuration. For admins, set the group claim name to “groups” and the admin group's name.",
    },
    Template {
        key: "grafana",
        name: "Grafana",
        redirect_uris: &["{url}/login/generic_oauth"],
        post_logout_redirect_uris: &["{url}/login"],
        scopes: "openid profile email groups",
        public: false,
        id_token_alg: "RS256",
        launch_url: "{url}/",
        notes_de: "In grafana.ini unter [auth.generic_oauth]: enabled = true, client_id und client_secret von hier, scopes = openid profile email groups, auth_url = {issuer}/oauth/authorize, token_url = {issuer}/oauth/token, api_url = {issuer}/oauth/userinfo, use_pkce = true. Rollen z. B. mit role_attribute_path = contains(groups[*], 'admins') && 'Admin' || 'Viewer'.",
        notes_en: "In grafana.ini under [auth.generic_oauth]: enabled = true, client_id and client_secret from here, scopes = openid profile email groups, auth_url = {issuer}/oauth/authorize, token_url = {issuer}/oauth/token, api_url = {issuer}/oauth/userinfo, use_pkce = true. Roles e.g. with role_attribute_path = contains(groups[*], 'admins') && 'Admin' || 'Viewer'.",
    },
    Template {
        key: "paperless",
        name: "Paperless-ngx",
        redirect_uris: &["{url}/accounts/oidc/{slug}/login/callback/"],
        post_logout_redirect_uris: &[],
        scopes: "openid profile email",
        public: false,
        id_token_alg: "RS256",
        launch_url: "{url}/",
        notes_de: "In Paperless-ngx PAPERLESS_APPS=allauth.socialaccount.providers.openid_connect setzen und PAPERLESS_SOCIALACCOUNT_PROVIDERS mit provider_id „{slug}“, client_id und secret von hier und server_url {issuer}/.well-known/openid-configuration.",
        notes_en: "In Paperless-ngx set PAPERLESS_APPS=allauth.socialaccount.providers.openid_connect and PAPERLESS_SOCIALACCOUNT_PROVIDERS with provider_id “{slug}”, client_id and secret from here, and server_url {issuer}/.well-known/openid-configuration.",
    },
    Template {
        key: "proxmox",
        name: "Proxmox VE",
        redirect_uris: &["{url}", "{url}/"],
        post_logout_redirect_uris: &[],
        scopes: "openid profile email",
        public: false,
        id_token_alg: "RS256",
        launch_url: "{url}/",
        notes_de: "In Proxmox unter Rechenzentrum → Berechtigungen → Realms einen Realm „OpenID Connect“ anlegen: Issuer-URL {issuer}, Client-ID und Schlüssel von hier, Benutzername-Claim „username“ oder „email“. Die Adresse ist die der Proxmox-Oberfläche, mit Port (z. B. https://pve.example.com:8006).",
        notes_en: "In Proxmox under Datacenter → Permissions → Realms add an “OpenID Connect” realm: issuer URL {issuer}, client ID and key from here, username claim “username” or “email”. The address is the Proxmox web UI's, with its port (e.g. https://pve.example.com:8006).",
    },
    Template {
        key: "portainer",
        name: "Portainer",
        redirect_uris: &["{url}", "{url}/"],
        post_logout_redirect_uris: &[],
        scopes: "openid profile email",
        public: false,
        id_token_alg: "RS256",
        launch_url: "{url}/",
        notes_de: "In Portainer unter Einstellungen → Authentifizierung „OAuth“ und „Custom“ wählen: Client-ID und Geheimnis von hier, Authorization URL {issuer}/oauth/authorize, Access token URL {issuer}/oauth/token, Resource URL {issuer}/oauth/userinfo, Redirect URL ist die Portainer-Adresse, User identifier „preferred_username“, Scopes „openid profile email“.",
        notes_en: "In Portainer under Settings → Authentication choose “OAuth” and “Custom”: client ID and secret from here, authorization URL {issuer}/oauth/authorize, access token URL {issuer}/oauth/token, resource URL {issuer}/oauth/userinfo, redirect URL is Portainer's address, user identifier “preferred_username”, scopes “openid profile email”.",
    },
    Template {
        key: "audiobookshelf",
        name: "Audiobookshelf",
        redirect_uris: &["{url}/auth/openid/callback", "{url}/auth/openid/mobile-redirect", "audiobookshelf://oauth"],
        post_logout_redirect_uris: &[],
        scopes: "openid profile email groups",
        public: false,
        id_token_alg: "RS256",
        launch_url: "{url}/",
        notes_de: "In Audiobookshelf unter Einstellungen → Authentifizierung „OpenID Connect“ einschalten, Issuer-URL {issuer} eintragen und „Auto-populate“ drücken, dann Client-ID und Geheimnis von hier. Die Handy-Weiterleitung audiobookshelf://oauth ist schon eingetragen.",
        notes_en: "In Audiobookshelf under Settings → Authentication turn on “OpenID Connect”, enter the issuer URL {issuer} and press “Auto-populate”, then the client ID and secret from here. The phone redirect audiobookshelf://oauth is registered already.",
    },
    Template {
        key: "open-webui",
        name: "Open WebUI",
        redirect_uris: &["{url}/oauth/oidc/callback"],
        post_logout_redirect_uris: &[],
        scopes: "openid profile email",
        public: false,
        id_token_alg: "RS256",
        launch_url: "{url}/",
        notes_de: "Open WebUI mit ENABLE_OAUTH_SIGNUP=true, OAUTH_CLIENT_ID und OAUTH_CLIENT_SECRET von hier, OPENID_PROVIDER_URL={issuer}/.well-known/openid-configuration und OAUTH_PROVIDER_NAME=UwUAuth starten.",
        notes_en: "Start Open WebUI with ENABLE_OAUTH_SIGNUP=true, OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET from here, OPENID_PROVIDER_URL={issuer}/.well-known/openid-configuration and OAUTH_PROVIDER_NAME=UwUAuth.",
    },
    Template {
        key: "synology-dsm",
        name: "Synology DSM",
        redirect_uris: &["{url}", "{url}/"],
        post_logout_redirect_uris: &[],
        scopes: "openid profile email",
        public: false,
        id_token_alg: "RS256",
        launch_url: "{url}/",
        notes_de: "In DSM unter Systemsteuerung → Domain/LDAP → SSO-Client „OpenID Connect SSO-Dienst aktivieren“: Profil „OIDC“, Name „UwUAuth“, Well-Known-URL {issuer}/.well-known/openid-configuration, Anwendungs-ID und -Schlüssel von hier, Umleitungs-URI ist die DSM-Adresse mit Port (z. B. https://nas.example.com:5001), Autorisierungsbereich „openid profile email“, Benutzername-Claim „preferred_username“. Damit sich lokale DSM-Konten anmelden können, „Anmeldung lokaler Benutzer erlauben“ einschalten; der Benutzername in UwUAuth muss dem DSM-Konto entsprechen.",
        notes_en: "In DSM under Control Panel → Domain/LDAP → SSO Client turn on “Enable OpenID Connect SSO service”: profile “OIDC”, name “UwUAuth”, well-known URL {issuer}/.well-known/openid-configuration, application ID and key from here, redirect URI is DSM's address with its port (e.g. https://nas.example.com:5001), authorization scope “openid profile email”, username claim “preferred_username”. For local DSM accounts to sign in, turn on “Allow local users to sign in”; the UwUAuth username has to match the DSM account.",
    },
    Template {
        key: "technitium",
        name: "Technitium DNS",
        redirect_uris: &["{url}/sso/callback"],
        post_logout_redirect_uris: &[],
        scopes: "openid profile email groups",
        public: false,
        id_token_alg: "RS256",
        launch_url: "{url}/",
        notes_de: "In Technitium unter Administration → Single Sign-On: Authority {issuer}, Client-ID und Geheimnis von hier, Scopes „openid profile email groups“. Unter „Group Map“ eine UwUAuth-Gruppe auf „Administrators“ (oder eine andere Technitium-Gruppe) abbilden und nur abgebildete Benutzer anlegen lassen. Läuft Technitium hinter einem Reverse-Proxy, dessen IP unter Einstellungen → Web Service → Reverse Proxy eintragen, sonst schickt Technitium eine http-Rücksprungadresse. In einem Cluster für jeden Knoten seine Adresse als Weiterleitung eintragen.",
        notes_en: "In Technitium under Administration → Single Sign-On: authority {issuer}, client ID and secret from here, scopes “openid profile email groups”. Under “Group Map” map a UwUAuth group to “Administrators” (or another Technitium group) and only let mapped users be created. If Technitium runs behind a reverse proxy, enter the proxy's IP under Settings → Web Service → Reverse Proxy, or Technitium sends an http callback. In a cluster, add each node's address as a redirect.",
    },
    Template {
        key: "generic",
        name: "OpenID Connect",
        redirect_uris: &[],
        post_logout_redirect_uris: &[],
        scopes: "openid profile email groups",
        public: false,
        id_token_alg: "RS256",
        launch_url: "",
        notes_de: "Für jede andere App mit OpenID Connect: Discovery-URL {issuer}/.well-known/openid-configuration, Client-ID und Geheimnis von hier. Die Weiterleitungs-URL steht in der Anleitung der App.",
        notes_en: "For any other app with OpenID Connect: discovery URL {issuer}/.well-known/openid-configuration, client ID and secret from here. The redirect URL is in the app's documentation.",
    },
];

pub fn find(key: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|template| template.key == key)
}

/// `{url}` and `{slug}` filled in.
pub fn fill(pattern: &str, url: &str, slug: &str) -> String {
    pattern.replace("{url}", url.trim_end_matches('/')).replace("{slug}", slug)
}

/// The templates for the portal, notes in `language` with `{issuer}` filled in.
pub fn list(issuer: &str, language: &str) -> Value {
    json!(TEMPLATES
        .iter()
        .map(|template| json!({
            "key": template.key,
            "name": template.name,
            "redirectUris": template.redirect_uris,
            "postLogoutRedirectUris": template.post_logout_redirect_uris,
            "scopes": template.scopes,
            "public": template.public,
            "launchUrl": template.launch_url,
            "notes": if language == "en" { template.notes_en } else { template.notes_de }.replace("{issuer}", issuer),
        }))
        .collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_is_filled_in_whole() {
        for template in TEMPLATES {
            for uri in template.redirect_uris {
                let filled = fill(uri, "https://app.example.com/", "uwuauth");
                assert!(!filled.contains('{'), "{}: {filled}", template.key);
            }
            assert!(template.scopes.starts_with("openid"), "{}", template.key);
        }
        assert_eq!(
            fill("{url}/user/oauth2/{slug}/callback", "https://git.example.com/", "uwuauth"),
            "https://git.example.com/user/oauth2/uwuauth/callback"
        );
    }
}
