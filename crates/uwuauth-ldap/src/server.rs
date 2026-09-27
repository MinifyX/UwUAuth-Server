//! Connections: one task each, a message at a time, in order.

use crate::directory::{Entry, Kind, ON_REQUEST, Snapshot, Source, domain_of, person_dn, service_dn};
use crate::dn::Dn;
use crate::filter::matches;
use futures_util::{SinkExt, StreamExt};
use ldap3_proto::LdapCodec;
use ldap3_proto::control::LdapControl;
use ldap3_proto::proto::{
    LdapBindCred, LdapBindRequest, LdapBindResponse, LdapCompareRequest, LdapExtendedRequest, LdapExtendedResponse,
    LdapModifyRequest, LdapModifyType, LdapMsg, LdapOp, LdapPartialAttribute, LdapPasswordModifyRequest, LdapResult,
    LdapResultCode, LdapSearchRequest, LdapSearchResultEntry, LdapSearchScope, OID_PASSWORD_MODIFY, OID_WHOAMI,
};
use parking_lot::RwLock;
use serde_json::json;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_util::codec::Framed;
use uwuauth_api::crypto::{secret_hash, sha256, verify_password};
use uwuauth_api::{AppState, audit, policy};
use uwuauth_store::{Person, people};

pub const OID_STARTTLS: &str = "1.3.6.1.4.1.1466.20037";
const OID_PAGED: &str = "1.2.840.113556.1.4.319";

/// A connection that sends nothing for this long is closed.
const IDLE: Duration = Duration::from_secs(5 * 60);
/// At most this many entries per search, whatever the client asks for.
const MOST: usize = 10_000;

#[derive(Debug, Clone)]
pub struct LdapConfig {
    /// `dc=example,dc=com`.
    pub base: String,
    /// Binds with a password over a connection without TLS. Only for a network nobody else is
    /// on, like the Docker network next to the apps.
    pub allow_plain_bind: bool,
}

/// Who a connection is bound as.
#[derive(Debug, Clone)]
enum Bound {
    Anonymous,
    Person { id: String, dn: String },
    Service { dn: String },
}

/// Where the TLS configuration comes from, asked for each connection: the certificate may have
/// been renewed since the last one.
pub type TlsSource = Arc<dyn Fn() -> Option<Arc<rustls::ServerConfig>> + Send + Sync>;

pub struct Ldap {
    state: AppState,
    config: LdapConfig,
    base: Dn,
    domain: String,
    /// The TLS for StartTLS and LDAPS; none when the server has no certificate of its own.
    tls: Option<TlsSource>,
    cache: RwLock<Option<Cached>>,
    sid: [u32; 3],
}

/// The directory as built last, with the store's generation it was built at.
type Cached = (u64, Arc<Snapshot>, Arc<Vec<Person>>);

/// Any stream a connection runs over: plain TCP, TLS, or a pipe in tests.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<S: AsyncRead + AsyncWrite + Unpin + Send> Stream for S {}

/// What happens after a connection's loop.
enum Next<S> {
    Done,
    StartTls(S),
}

fn result(code: LdapResultCode, message: &str) -> LdapResult {
    LdapResult { code, matcheddn: String::new(), message: message.to_string(), referral: Vec::new() }
}

fn msg(msgid: i32, op: LdapOp) -> LdapMsg {
    LdapMsg { msgid, op, ctrl: Vec::new() }
}

impl Ldap {
    pub async fn new(state: AppState, config: LdapConfig, tls: Option<TlsSource>) -> Result<Arc<Self>, String> {
        let base = Dn::parse(&config.base)
            .filter(|dn| !dn.0.is_empty())
            .ok_or_else(|| format!("{} is not a DN", config.base))?;
        let domain = domain_of(&base);
        // The domain's SID: random once, kept, so objectSid stays the same across restarts.
        let fresh = uwuauth_api::crypto::random_bytes(12);
        let text = format!(
            "{},{},{}",
            u32::from_le_bytes(fresh[0..4].try_into().expect("4 bytes")) >> 1,
            u32::from_le_bytes(fresh[4..8].try_into().expect("4 bytes")) >> 1,
            u32::from_le_bytes(fresh[8..12].try_into().expect("4 bytes")) >> 1
        );
        let kept = state.store.setting_or_insert("ldap_domain_sid", &text).await.map_err(|error| error.to_string())?;
        let parts: Vec<u32> = kept.split(',').filter_map(|part| part.parse().ok()).collect();
        let sid = [
            parts.first().copied().unwrap_or(1),
            parts.get(1).copied().unwrap_or(2),
            parts.get(2).copied().unwrap_or(3),
        ];
        Ok(Arc::new(Ldap { state, config, base, domain, tls, cache: RwLock::new(None), sid }))
    }

    /// The directory as it is now: from memory, or built again when something changed.
    fn acceptor(&self) -> Option<tokio_rustls::TlsAcceptor> {
        self.tls.as_ref().and_then(|source| source()).map(tokio_rustls::TlsAcceptor::from)
    }

    async fn snapshot(&self) -> Result<(Arc<Snapshot>, Arc<Vec<Person>>), String> {
        let generation = self.state.store.generation();
        if let Some((known, snapshot, people)) = self.cache.read().as_ref()
            && *known == generation
        {
            return Ok((snapshot.clone(), people.clone()));
        }
        let store = &self.state.store;
        let error = |error: uwuauth_store::StoreError| error.to_string();
        let people = store.people().await.map_err(error)?;
        let groups = store.groups().await.map_err(error)?;
        let membership = store.membership().await.map_err(error)?;
        let attributes = store.all_attributes().await.map_err(error)?;
        let mut avatars = BTreeMap::new();
        for id in store.avatar_ids().await.map_err(error)? {
            if let Some((jpeg, _)) = store.avatar(&id).await.map_err(error)? {
                avatars.insert(id, jpeg);
            }
        }
        let services: Vec<String> =
            store.ldap_accounts().await.map_err(error)?.into_iter().map(|account| account.name).collect();
        let snapshot = Arc::new(Snapshot::build(Source {
            base: &self.base,
            domain: &self.domain,
            sid: self.sid,
            people: &people,
            groups: &groups,
            membership: &membership,
            attributes: &attributes,
            avatars: &avatars,
            services: &services,
        }));
        let people = Arc::new(people);
        *self.cache.write() = Some((generation, snapshot.clone(), people.clone()));
        Ok((snapshot, people))
    }

    /// Accept connections on `listener` until `stop`. `ldaps`: TLS from the first byte.
    pub async fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        ldaps: bool,
        stop: impl std::future::Future<Output = ()>,
    ) {
        tokio::pin!(stop);
        loop {
            let accepted = tokio::select! {
                _ = &mut stop => return,
                accepted = listener.accept() => accepted,
            };
            let Ok((stream, peer)) = accepted else { continue };
            let ldap = self.clone();
            let ip = uwuauth_api::session::canonical(peer.ip());
            tokio::spawn(async move {
                if ldaps {
                    let Some(acceptor) = ldap.acceptor() else { return };
                    match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => ldap.connection(stream, ip, true).await,
                        _ => tracing::debug!(%ip, "an LDAPS handshake did not finish"),
                    }
                } else {
                    ldap.connection(stream, ip, false).await;
                }
            });
        }
    }

    /// Serve one connection. After StartTLS it goes on over TLS.
    pub async fn connection<S>(self: Arc<Self>, stream: S, ip: IpAddr, secure: bool)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        match self.run(stream, ip, secure).await {
            Next::Done => {}
            Next::StartTls(stream) => {
                let Some(acceptor) = self.acceptor() else { return };
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                    // Over TLS a second StartTLS is refused, so this goes no deeper.
                    Ok(Ok(stream)) => {
                        let stream: Box<dyn Stream> = Box::new(stream);
                        let _ = self.run(stream, ip, true).await;
                    }
                    _ => tracing::debug!(%ip, "a StartTLS handshake did not finish"),
                }
            }
        }
    }

    async fn run<S>(&self, stream: S, ip: IpAddr, secure: bool) -> Next<S>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut framed = Framed::new(stream, LdapCodec::default());
        let mut bound = Bound::Anonymous;
        loop {
            let message = match tokio::time::timeout(IDLE, framed.next()).await {
                Ok(Some(Ok(message))) => message,
                _ => return Next::Done,
            };
            let id = message.msgid;
            let replies = match message.op {
                LdapOp::UnbindRequest => return Next::Done,
                LdapOp::AbandonRequest(_) => continue,
                LdapOp::BindRequest(request) => {
                    let (reply, now) = self.bind(id, request, ip, secure).await;
                    bound = now;
                    vec![reply]
                }
                LdapOp::SearchRequest(request) => self.search(id, &request, &message.ctrl, &bound).await,
                LdapOp::CompareRequest(request) => vec![self.compare(id, &request, &bound).await],
                LdapOp::ExtendedRequest(request) if request.name == OID_STARTTLS => {
                    let code = if secure {
                        result(LdapResultCode::OperationsError, "TLS is on already")
                    } else if self.acceptor().is_none() {
                        result(LdapResultCode::Unavailable, "this server has no certificate for LDAP")
                    } else {
                        result(LdapResultCode::Success, "")
                    };
                    let upgrade = code.code == LdapResultCode::Success;
                    let reply = msg(
                        id,
                        LdapOp::ExtendedResponse(LdapExtendedResponse {
                            res: code,
                            name: Some(OID_STARTTLS.into()),
                            value: None,
                        }),
                    );
                    if framed.send(reply).await.is_err() {
                        return Next::Done;
                    }
                    if upgrade {
                        // Nothing may be buffered past the request: RFC 4511 section 4.14.1.
                        let parts = framed.into_parts();
                        if !parts.read_buf.is_empty() {
                            return Next::Done;
                        }
                        return Next::StartTls(parts.io);
                    }
                    continue;
                }
                LdapOp::ExtendedRequest(request) => vec![self.extended(id, &request, &bound, ip, secure).await],
                LdapOp::ModifyRequest(request) => vec![self.modify(id, &request, &bound, ip, secure).await],
                LdapOp::AddRequest(_) => vec![msg(
                    id,
                    LdapOp::AddResponse(result(
                        LdapResultCode::UnwillingToPerform,
                        "the directory is changed in UwUAuth's portal",
                    )),
                )],
                LdapOp::DelRequest(_) => vec![msg(
                    id,
                    LdapOp::DelResponse(result(
                        LdapResultCode::UnwillingToPerform,
                        "the directory is changed in UwUAuth's portal",
                    )),
                )],
                LdapOp::ModifyDNRequest(_) => vec![msg(
                    id,
                    LdapOp::ModifyDNResponse(result(
                        LdapResultCode::UnwillingToPerform,
                        "the directory is changed in UwUAuth's portal",
                    )),
                )],
                _ => vec![msg(
                    id,
                    LdapOp::ExtendedResponse(LdapExtendedResponse {
                        res: result(LdapResultCode::ProtocolError, "not understood"),
                        name: None,
                        value: None,
                    }),
                )],
            };
            for reply in replies {
                if framed.send(reply).await.is_err() {
                    return Next::Done;
                }
            }
        }
    }

    // ── Bind ──────────────────────────────────────────────

    async fn bind(&self, id: i32, request: LdapBindRequest, ip: IpAddr, secure: bool) -> (LdapMsg, Bound) {
        let reply = |code: LdapResultCode, message: &str| {
            msg(id, LdapOp::BindResponse(LdapBindResponse { res: result(code, message), saslcreds: None }))
        };
        let password = match request.cred {
            LdapBindCred::Simple(password) => password,
            LdapBindCred::SASL(_) => {
                return (reply(LdapResultCode::AuthMethodNotSupported, "only simple binds"), Bound::Anonymous);
            }
        };
        if request.dn.is_empty() && password.is_empty() {
            return (reply(LdapResultCode::Success, ""), Bound::Anonymous);
        }
        if password.is_empty() {
            // An "unauthenticated bind" (RFC 4513 section 5.1.2): refused, it is a trap for apps
            // that think it checked a password.
            return (reply(LdapResultCode::UnwillingToPerform, "a bind needs a password"), Bound::Anonymous);
        }
        if !secure && !self.config.allow_plain_bind {
            return (reply(LdapResultCode::ConfidentialityRequired, "use LDAPS or StartTLS"), Bound::Anonymous);
        }
        if !self.state.limits.login.check(ip) {
            return (reply(LdapResultCode::Busy, "too many tries, wait a minute"), Bound::Anonymous);
        }
        // AD's reasons, in the form apps read them ("data 52e").
        let invalid = |data: &str| {
            reply(
                LdapResultCode::InvalidCredentials,
                &format!("80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, data {data}, v4563"),
            )
        };

        // An app's LDAP account.
        if let Some(dn) = Dn::parse(&request.dn)
            && dn.0.len() > 1
            && dn.parent().normalized() == format!("ou=services,{}", self.base.normalized())
            && let Some(first) = dn.first()
        {
            let found = self
                .state
                .store
                .use_ldap_account(&first.value, sha256(password.as_bytes()), &ip.to_string())
                .await
                .ok()
                .flatten();
            return match found {
                Some(account) => {
                    let dn = service_dn(&self.base_text(), &account.name);
                    (reply(LdapResultCode::Success, ""), Bound::Service { dn })
                }
                None => {
                    audit(
                        &self.state,
                        "ldap_login_failed",
                        None,
                        None,
                        Some(&first.value),
                        &ip,
                        json!({ "service": true }),
                    )
                    .await;
                    (invalid("52e"), Bound::Anonymous)
                }
            };
        }

        let Ok((snapshot, people)) = self.snapshot().await else {
            return (reply(LdapResultCode::Unavailable, "the directory is not available"), Bound::Anonymous);
        };
        let Some(person) = snapshot.find_person(&request.dn, &people).cloned() else {
            // The same work as for somebody who exists, so the time does not tell.
            verify_password(self.state.config.hash_cost, None, &password).await;
            audit(&self.state, "ldap_login_failed", None, None, None, &ip, json!({ "name": request.dn })).await;
            return (invalid("52e"), Bound::Anonymous);
        };
        if !self.state.limits.account.allows(&person.id) {
            return (reply(LdapResultCode::Busy, "too many tries, wait a minute"), Bound::Anonymous);
        }
        let app_password =
            self.state.store.use_app_password(&person.id, secret_hash(&password), &ip.to_string()).await.ok().flatten();
        let right = if app_password.is_some() {
            true
        } else {
            let membership = snapshot.membership.clone();
            let groups = self.state.store.groups().await.unwrap_or_default();
            let of_person = membership.groups_of(&person.id);
            let app_passwords_only =
                groups.iter().any(|group| group.ldap_app_passwords_only && of_person.contains(&group.id));
            let hash = person.password_hash.as_deref().filter(|_| !app_passwords_only);
            verify_password(self.state.config.hash_cost, hash, &password).await
        };
        if !right {
            self.state.limits.account.take(person.id.clone());
            audit(&self.state, "login_failed", None, Some(&person.id), None, &ip, json!({ "method": "ldap" })).await;
            return (invalid("52e"), Bound::Anonymous);
        }
        match policy::refusal(&self.state, &person).await {
            Ok(None) => {}
            Ok(Some(reason)) => {
                audit(
                    &self.state,
                    "login_refused",
                    None,
                    Some(&person.id),
                    None,
                    &ip,
                    json!({ "reason": reason, "method": "ldap" }),
                )
                .await;
                let data = match reason {
                    "expired" => "701",
                    "locked" => "775",
                    _ => "533",
                };
                return (invalid(data), Bound::Anonymous);
            }
            Err(_) => return (reply(LdapResultCode::Unavailable, "the directory is not available"), Bound::Anonymous),
        }
        let groups = snapshot.membership.groups_of(&person.id);
        let windows = self.state.store.windows_for(&person.id, &groups).await.unwrap_or_default();
        if !policy::within_windows(&self.state, &windows, None) {
            audit(
                &self.state,
                "login_refused",
                None,
                Some(&person.id),
                None,
                &ip,
                json!({ "reason": "time", "method": "ldap" }),
            )
            .await;
            return (invalid("530"), Bound::Anonymous);
        }
        audit(
            &self.state,
            "ldap_login",
            Some(&person.id),
            Some(&person.id),
            app_password.as_ref().map(|app| app.id.as_str()),
            &ip,
            json!({ "appPassword": app_password.as_ref().map(|app| app.name.clone()) }),
        )
        .await;
        let dn = person_dn(&self.base_text(), &person.username);
        (reply(LdapResultCode::Success, ""), Bound::Person { id: person.id, dn })
    }

    fn base_text(&self) -> String {
        self.base
            .0
            .iter()
            .map(|rdn| format!("{}={}", rdn.name, crate::dn::escape(&rdn.value)))
            .collect::<Vec<_>>()
            .join(",")
    }

    // ── Search ────────────────────────────────────────────

    fn root_dse(&self) -> LdapSearchResultEntry {
        let base = self.base_text();
        let attribute = |name: &str, values: &[&str]| LdapPartialAttribute {
            atype: name.into(),
            vals: values.iter().map(|value| value.as_bytes().to_vec()).collect(),
        };
        LdapSearchResultEntry {
            dn: String::new(),
            attributes: vec![
                attribute("objectClass", &["top"]),
                attribute("namingContexts", &[&base]),
                attribute("defaultNamingContext", &[&base]),
                attribute("rootDomainNamingContext", &[&base]),
                attribute("supportedLDAPVersion", &["3"]),
                attribute("supportedExtension", &[OID_WHOAMI, OID_PASSWORD_MODIFY, OID_STARTTLS]),
                attribute("supportedControl", &[OID_PAGED]),
                attribute("supportedSASLMechanisms", &[]),
                attribute("vendorName", &["UwUAuth"]),
                attribute("vendorVersion", &[self.state.version]),
                attribute(
                    "dnsHostName",
                    &[self
                        .state
                        .config
                        .public
                        .split("://")
                        .nth(1)
                        .unwrap_or_default()
                        .split(':')
                        .next()
                        .unwrap_or_default()],
                ),
                attribute("subschemaSubentry", &["cn=schema"]),
            ],
        }
    }

    async fn search(
        &self,
        id: i32,
        request: &LdapSearchRequest,
        controls: &[LdapControl],
        bound: &Bound,
    ) -> Vec<LdapMsg> {
        let done = |code: LdapResultCode, message: &str| msg(id, LdapOp::SearchResultDone(result(code, message)));
        // The root DSE, for anybody: how clients find the base.
        if request.base.is_empty() && request.scope == LdapSearchScope::Base {
            return vec![msg(id, LdapOp::SearchResultEntry(self.root_dse())), done(LdapResultCode::Success, "")];
        }
        if matches!(bound, Bound::Anonymous) {
            return vec![done(LdapResultCode::InsufficentAccessRights, "bind first")];
        }
        let Some(base) = Dn::parse(&request.base) else {
            return vec![done(LdapResultCode::InvalidDNSyntax, "the base is not a DN")];
        };
        let Ok((snapshot, _)) = self.snapshot().await else {
            return vec![done(LdapResultCode::Unavailable, "the directory is not available")];
        };
        if !base.is_under(&snapshot.base) {
            let mut reply = result(LdapResultCode::NoSuchObject, "outside this directory");
            reply.matcheddn = String::new();
            return vec![msg(id, LdapOp::SearchResultDone(reply))];
        }
        let base_normalized = base.normalized();
        if !snapshot.entries.iter().any(|entry| entry.normalized == base_normalized) {
            let mut reply = result(LdapResultCode::NoSuchObject, "no such entry");
            reply.matcheddn = self.base_text();
            return vec![msg(id, LdapOp::SearchResultDone(reply))];
        }
        let in_scope = |entry: &Entry| match request.scope {
            LdapSearchScope::Base => entry.normalized == base_normalized,
            LdapSearchScope::OneLevel => entry.parsed.0.len() == base.0.len() + 1 && entry.parsed.is_under(&base),
            LdapSearchScope::Subtree => entry.parsed.is_under(&base),
            LdapSearchScope::Children => entry.parsed.is_under(&base) && entry.normalized != base_normalized,
        };
        let found: Vec<&Entry> = snapshot
            .entries
            .iter()
            .filter(|entry| in_scope(entry) && matches(&request.filter, entry, &snapshot))
            .collect();

        // Paged results: the cookie is how far the last page went.
        let paged = controls.iter().find_map(|control| match control {
            LdapControl::SimplePagedResults { size, cookie } => Some((*size, cookie.clone())),
            _ => None,
        });
        let (start, page) = match &paged {
            Some((size, cookie)) => {
                let start = std::str::from_utf8(cookie).ok().and_then(|text| text.parse::<usize>().ok()).unwrap_or(0);
                (start, usize::try_from(*size).unwrap_or(0).clamp(1, MOST))
            }
            None => (0, MOST),
        };
        let limit = usize::try_from(request.sizelimit).ok().filter(|limit| *limit > 0).unwrap_or(MOST).min(MOST);
        let mut replies: Vec<LdapMsg> = found
            .iter()
            .skip(start)
            .take(page.min(limit))
            .map(|entry| msg(id, LdapOp::SearchResultEntry(self.present(entry, &request.attrs, request.typesonly))))
            .collect();
        let shown = replies.len();
        let over_limit = paged.is_none() && found.len() > limit;
        let mut last = done(if over_limit { LdapResultCode::SizeLimitExceeded } else { LdapResultCode::Success }, "");
        if paged.is_some() {
            let next = start + shown;
            let cookie = if next < found.len() { next.to_string().into_bytes() } else { Vec::new() };
            last.ctrl.push(LdapControl::SimplePagedResults { size: found.len() as i64, cookie });
        }
        replies.push(last);
        replies
    }

    /// An entry with the attributes asked for: `*` (or nothing) for every ordinary one, `+` for
    /// the operational ones, names for exactly those, `1.1` for none.
    fn present(&self, entry: &Entry, asked: &[String], types_only: bool) -> LdapSearchResultEntry {
        let asked: Vec<String> = asked.iter().map(|name| name.to_lowercase()).collect();
        let all_user = asked.is_empty() || asked.iter().any(|name| name == "*");
        let all_operational = asked.iter().any(|name| name == "+");
        let only_none = asked.len() == 1 && asked[0] == "1.1";
        let mut attributes = Vec::new();
        if !only_none {
            for (lower, (name, values)) in &entry.attributes {
                let operational = ON_REQUEST.contains(&lower.as_str());
                let wanted = asked.contains(lower) || (operational && all_operational) || (!operational && all_user);
                if wanted {
                    attributes.push(LdapPartialAttribute {
                        atype: name.clone(),
                        vals: if types_only { Vec::new() } else { values.clone() },
                    });
                }
            }
            if asked.iter().any(|name| name == "entrydn") {
                attributes
                    .push(LdapPartialAttribute { atype: "entryDN".into(), vals: vec![entry.dn.clone().into_bytes()] });
            }
            if asked.iter().any(|name| name == "hassubordinates") || all_operational {
                let subordinates = matches!(entry.kind, Kind::Base | Kind::Container);
                attributes.push(LdapPartialAttribute {
                    atype: "hasSubordinates".into(),
                    vals: vec![if subordinates { b"TRUE".to_vec() } else { b"FALSE".to_vec() }],
                });
            }
        }
        LdapSearchResultEntry { dn: entry.dn.clone(), attributes }
    }

    async fn compare(&self, id: i32, request: &LdapCompareRequest, bound: &Bound) -> LdapMsg {
        let reply = |code: LdapResultCode| msg(id, LdapOp::CompareResult(result(code, "")));
        if matches!(bound, Bound::Anonymous) {
            return reply(LdapResultCode::InsufficentAccessRights);
        }
        let Ok((snapshot, _)) = self.snapshot().await else { return reply(LdapResultCode::Unavailable) };
        let Some(dn) = Dn::parse(&request.dn).map(|dn| dn.normalized()) else {
            return reply(LdapResultCode::InvalidDNSyntax);
        };
        let Some(entry) = snapshot.entries.iter().find(|entry| entry.normalized == dn) else {
            return reply(LdapResultCode::NoSuchObject);
        };
        let value = String::from_utf8_lossy(&request.val).to_string();
        let filter = ldap3_proto::proto::LdapFilter::Equality(request.atype.clone(), value);
        if matches(&filter, entry, &snapshot) {
            reply(LdapResultCode::CompareTrue)
        } else {
            reply(LdapResultCode::CompareFalse)
        }
    }

    // ── Extended operations and passwords ─────────────────

    async fn extended(
        &self,
        id: i32,
        request: &LdapExtendedRequest,
        bound: &Bound,
        ip: IpAddr,
        secure: bool,
    ) -> LdapMsg {
        let reply = |res: LdapResult, value: Option<Vec<u8>>| {
            msg(id, LdapOp::ExtendedResponse(LdapExtendedResponse { res, name: None, value }))
        };
        match request.name.as_str() {
            OID_WHOAMI => {
                let who = match bound {
                    Bound::Anonymous => String::new(),
                    Bound::Person { dn, .. } | Bound::Service { dn, .. } => format!("dn:{dn}"),
                };
                reply(result(LdapResultCode::Success, ""), Some(who.into_bytes()))
            }
            OID_PASSWORD_MODIFY => {
                let Bound::Person { id: person, .. } = bound else {
                    return reply(
                        result(LdapResultCode::InsufficentAccessRights, "only a person changes their own password"),
                        None,
                    );
                };
                let Ok(parsed) = LdapPasswordModifyRequest::try_from(request) else {
                    return reply(result(LdapResultCode::ProtocolError, "not a password modify request"), None);
                };
                if parsed.user_identity.as_ref().is_some_and(|identity| !self.is_self(identity, person)) {
                    return reply(result(LdapResultCode::InsufficentAccessRights, "only your own password"), None);
                }
                let (Some(old), Some(new)) = (parsed.old_password, parsed.new_password) else {
                    return reply(
                        result(
                            LdapResultCode::UnwillingToPerform,
                            "the old and the new password are needed; the server does not make one up",
                        ),
                        None,
                    );
                };
                reply(self.change_password(person, &old, &new, ip, secure).await, None)
            }
            _ => reply(result(LdapResultCode::ProtocolError, "unknown extended operation"), None),
        }
    }

    fn is_self(&self, identity: &str, person: &str) -> bool {
        let identity = identity.strip_prefix("dn:").or_else(|| identity.strip_prefix("u:")).unwrap_or(identity);
        let Some(snapshot) = self.cache.read().as_ref().map(|(_, snapshot, people)| (snapshot.clone(), people.clone()))
        else {
            return false;
        };
        snapshot.0.find_person(identity, &snapshot.1).is_some_and(|found| found.id == person)
    }

    async fn change_password(&self, person: &str, old: &str, new: &str, ip: IpAddr, secure: bool) -> LdapResult {
        if !secure && !self.config.allow_plain_bind {
            return result(LdapResultCode::ConfidentialityRequired, "use LDAPS or StartTLS");
        }
        let Ok(Some(found)) = self.state.store.person(person).await else {
            return result(LdapResultCode::NoSuchObject, "");
        };
        if !verify_password(self.state.config.hash_cost, found.password_hash.as_deref(), old).await {
            audit(
                &self.state,
                "password_change_failed",
                Some(person),
                Some(person),
                None,
                &ip,
                json!({ "method": "ldap" }),
            )
            .await;
            return result(LdapResultCode::InvalidCredentials, "the old password is wrong");
        }
        if let Err(error) = policy::password(&self.state, new, Some((&found.username, found.email.as_deref()))).await {
            return result(LdapResultCode::ConstraintViolation, &error.message);
        }
        let Ok(hash) = uwuauth_api::crypto::hash_password(self.state.config.hash_cost, new).await else {
            return result(LdapResultCode::Other, "the password could not be kept");
        };
        let changed = self
            .state
            .store
            .update_person(person, move |person| {
                person.password_hash = Some(hash);
                person.password_changed = Some(uwuauth_store::clock::now());
                person.security_stamp = people::stamp();
            })
            .await;
        if changed.is_err() {
            return result(LdapResultCode::Other, "the password could not be kept");
        }
        audit(&self.state, "password_changed", Some(person), Some(person), None, &ip, json!({ "method": "ldap" }))
            .await;
        result(LdapResultCode::Success, "")
    }

    /// Only one change goes through LDAP: a person's own password as Active Directory writes it
    /// (`unicodePwd`: delete the old, add the new, each in quotes and UTF-16).
    async fn modify(&self, id: i32, request: &LdapModifyRequest, bound: &Bound, ip: IpAddr, secure: bool) -> LdapMsg {
        let reply = |res: LdapResult| msg(id, LdapOp::ModifyResponse(res));
        let Bound::Person { id: person, dn } = bound else {
            return reply(result(
                LdapResultCode::InsufficentAccessRights,
                "the directory is changed in UwUAuth's portal",
            ));
        };
        let own = Dn::parse(&request.dn).map(|target| target.normalized()) == Dn::parse(dn).map(|dn| dn.normalized());
        let decode = |value: &[u8]| -> Option<String> {
            let units: Vec<u16> = value.as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
            let text = String::from_utf16(&units).ok()?;
            text.strip_prefix('"')?.strip_suffix('"').map(str::to_string)
        };
        let mut old = None;
        let mut new = None;
        for change in &request.changes {
            if !change.modification.atype.eq_ignore_ascii_case("unicodePwd") || !own {
                return reply(result(
                    LdapResultCode::InsufficentAccessRights,
                    "the directory is changed in UwUAuth's portal",
                ));
            }
            let value = change.modification.vals.first().and_then(|value| decode(value));
            match change.operation {
                LdapModifyType::Delete => old = value,
                LdapModifyType::Add => new = value,
                LdapModifyType::Replace => {
                    return reply(result(
                        LdapResultCode::InsufficentAccessRights,
                        "a reset is done in UwUAuth's portal",
                    ));
                }
            }
        }
        match (old, new) {
            (Some(old), Some(new)) => reply(self.change_password(person, &old, &new, ip, secure).await),
            _ => reply(result(LdapResultCode::UnwillingToPerform, "delete the old unicodePwd and add the new one")),
        }
    }
}
