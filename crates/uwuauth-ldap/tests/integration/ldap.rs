use futures_util::{SinkExt, StreamExt};
use ldap3_proto::LdapCodec;
use ldap3_proto::control::LdapControl;
use ldap3_proto::proto::*;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio_util::codec::Framed;
use uwuauth_api::{ApiConfig, AppState, HashCost, Limits, LogBuffer};
use uwuauth_ldap::{Ldap, LdapConfig};
use uwuauth_store::{ADMINS_ID, GroupFields, Members, NewPerson, Store, Window};

const BASE: &str = "dc=example,dc=com";
const PASSWORD: &str = "correct horse battery";
const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10));

struct World {
    state: AppState,
    ldap: Arc<Ldap>,
    _dir: tempfile::TempDir,
}

async fn world(allow_plain_bind: bool, tls: Option<Arc<rustls::ServerConfig>>) -> World {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open_sqlite(&dir.path().join("uwuauth.db"), &uwuauth_store::Options { readers: 2 }).unwrap();
    let mut config = ApiConfig::new("https://auth.example.com", dir.path().to_path_buf());
    config.hash_cost = HashCost::cheap();
    let mut state = AppState::new(store, config, "0.0.0-test", LogBuffer::new(10)).await.unwrap();
    state.limits = Arc::new(Limits::generous());
    let tls: Option<uwuauth_ldap::TlsSource> =
        tls.map(|config| Arc::new(move || Some(config.clone())) as uwuauth_ldap::TlsSource);
    let ldap = Ldap::new(state.clone(), LdapConfig { base: BASE.into(), allow_plain_bind }, tls).await.unwrap();
    World { state, ldap, _dir: dir }
}

impl World {
    async fn person(&self, username: &str, display: &str) -> String {
        let person = self
            .state
            .store
            .create_person(NewPerson {
                username: username.into(),
                display_name: display.into(),
                email: Some(format!("{username}@example.com")),
                language: "de".into(),
                ..NewPerson::default()
            })
            .await
            .unwrap();
        let hash = uwuauth_api::crypto::hash_password(HashCost::cheap(), PASSWORD).await.unwrap();
        self.state.store.update_person(&person.id, move |person| person.password_hash = Some(hash)).await.unwrap();
        person.id
    }

    async fn group(&self, name: &str) -> String {
        self.state.store.create_group(GroupFields { name: name.into(), ..GroupFields::default() }).await.unwrap().id
    }

    async fn service(&self, name: &str, password: &str) {
        self.state
            .store
            .create_ldap_account(name, "", uwuauth_api::crypto::sha256(password.as_bytes()), None)
            .await
            .unwrap();
    }

    fn connect(&self) -> Client<DuplexStream> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(self.ldap.clone().connection(server, IP, false));
        Client { framed: Framed::new(client, LdapCodec::default()), next: 1 }
    }
}

struct Client<S> {
    framed: Framed<S, LdapCodec>,
    next: i32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    async fn send(&mut self, op: LdapOp, ctrl: Vec<LdapControl>) -> i32 {
        let id = self.next;
        self.next += 1;
        self.framed.send(LdapMsg { msgid: id, op, ctrl }).await.unwrap();
        id
    }

    async fn receive(&mut self) -> LdapMsg {
        self.framed.next().await.expect("an answer").expect("a message")
    }

    async fn bind(&mut self, dn: &str, password: &str) -> LdapResult {
        self.send(
            LdapOp::BindRequest(LdapBindRequest { dn: dn.into(), cred: LdapBindCred::Simple(password.into()) }),
            vec![],
        )
        .await;
        match self.receive().await.op {
            LdapOp::BindResponse(response) => response.res,
            other => panic!("{other:?}"),
        }
    }

    async fn search_with(
        &mut self,
        base: &str,
        scope: LdapSearchScope,
        filter: &str,
        attrs: &[&str],
        ctrl: Vec<LdapControl>,
    ) -> (Vec<LdapSearchResultEntry>, LdapMsg) {
        let filter = unescape(ldap3_proto::parse_ldap_filter_str(filter).expect("a filter"));
        let request = LdapSearchRequest {
            base: base.into(),
            scope,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter,
            attrs: attrs.iter().map(|attr| attr.to_string()).collect(),
        };
        self.send(LdapOp::SearchRequest(request), ctrl).await;
        let mut entries = Vec::new();
        loop {
            let message = self.receive().await;
            match message.op {
                LdapOp::SearchResultEntry(entry) => entries.push(entry),
                LdapOp::SearchResultDone(_) => return (entries, message),
                other => panic!("{other:?}"),
            }
        }
    }

    async fn search(&mut self, filter: &str, attrs: &[&str]) -> Vec<LdapSearchResultEntry> {
        let (entries, done) = self.search_with(BASE, LdapSearchScope::Subtree, filter, attrs, vec![]).await;
        let LdapOp::SearchResultDone(result) = done.op else { unreachable!() };
        assert_eq!(result.code, LdapResultCode::Success, "{result:?}");
        entries
    }
}

/// The text filter parser keeps `\3d` as it is; on the wire a client sends the plain value.
fn unescape(filter: LdapFilter) -> LdapFilter {
    let plain = |value: String| value.replace("\\3d", "=").replace("\\2c", ",");
    match filter {
        LdapFilter::And(all) => LdapFilter::And(all.into_iter().map(unescape).collect()),
        LdapFilter::Or(any) => LdapFilter::Or(any.into_iter().map(unescape).collect()),
        LdapFilter::Not(inner) => LdapFilter::Not(Box::new(unescape(*inner))),
        LdapFilter::Equality(name, value) => LdapFilter::Equality(name, plain(value)),
        LdapFilter::Extensible(mut assertion) => {
            assertion.match_value = plain(assertion.match_value);
            LdapFilter::Extensible(assertion)
        }
        other => other,
    }
}

fn values(entry: &LdapSearchResultEntry, name: &str) -> Vec<String> {
    entry
        .attributes
        .iter()
        .filter(|attribute| attribute.atype.eq_ignore_ascii_case(name))
        .flat_map(|attribute| attribute.vals.iter().map(|value| String::from_utf8_lossy(value).to_string()))
        .collect()
}

#[tokio::test]
async fn anybody_finds_the_base_but_nothing_else() {
    let world = world(true, None).await;
    let mut client = world.connect();
    let (entries, _) = client.search_with("", LdapSearchScope::Base, "(objectClass=*)", &["*"], vec![]).await;
    assert_eq!(values(&entries[0], "namingContexts"), [BASE]);
    assert!(values(&entries[0], "supportedExtension").contains(&"1.3.6.1.4.1.1466.20037".to_string()), "StartTLS");
    let (entries, done) = client.search_with(BASE, LdapSearchScope::Subtree, "(objectClass=*)", &[], vec![]).await;
    assert!(entries.is_empty());
    let LdapOp::SearchResultDone(result) = done.op else { unreachable!() };
    assert_eq!(result.code, LdapResultCode::InsufficentAccessRights);
}

#[tokio::test]
async fn people_bind_however_their_app_writes_the_name() {
    let world = world(true, None).await;
    world.person("nyu", "Nyu Neko").await;
    for name in [
        "uid=nyu,ou=people,dc=example,dc=com",
        "UID=Nyu, OU=People, DC=Example, DC=Com",
        "nyu",
        "nyu@example.com",
        "EXAMPLE\\nyu",
    ] {
        let mut client = world.connect();
        assert_eq!(client.bind(name, PASSWORD).await.code, LdapResultCode::Success, "{name}");
    }
    let mut client = world.connect();
    let wrong = client.bind("nyu", "wrong password").await;
    assert_eq!(wrong.code, LdapResultCode::InvalidCredentials);
    assert!(wrong.message.contains("data 52e"), "{}", wrong.message);
    assert_eq!(client.bind("nobody", PASSWORD).await.code, LdapResultCode::InvalidCredentials);
    assert_eq!(client.bind("nyu", "").await.code, LdapResultCode::UnwillingToPerform, "no unauthenticated binds");
}

#[tokio::test]
async fn without_tls_a_password_is_refused() {
    let world = world(false, None).await;
    world.person("nyu", "Nyu").await;
    let mut client = world.connect();
    assert_eq!(client.bind("nyu", PASSWORD).await.code, LdapResultCode::ConfidentialityRequired);
}

#[tokio::test]
async fn app_passwords_bind_and_a_group_can_insist_on_them() {
    let world = world(true, None).await;
    let nyu = world.person("nyu", "Nyu").await;
    world.state.store.add_app_password(&nyu, "NAS", uwuauth_api::crypto::secret_hash("abcd-efgh-jkmn")).await.unwrap();
    let mut client = world.connect();
    assert_eq!(client.bind("nyu", "ABCD EFGH JKMN").await.code, LdapResultCode::Success);
    let strict = world
        .state
        .store
        .create_group(GroupFields { name: "strict".into(), ldap_app_passwords_only: true, ..GroupFields::default() })
        .await
        .unwrap();
    world.state.store.add_member(&strict.id, &nyu).await.unwrap();
    let mut client = world.connect();
    assert_eq!(
        client.bind("nyu", PASSWORD).await.code,
        LdapResultCode::InvalidCredentials,
        "the account password no more"
    );
    assert_eq!(client.bind("nyu", "abcd-efgh-jkmn").await.code, LdapResultCode::Success);
}

#[tokio::test]
async fn an_app_finds_people_the_active_directory_way() {
    let world = world(true, None).await;
    let nyu = world.person("nyu", "Nyu Neko").await;
    let mia = world.person("mia", "Mia").await;
    let papa = world.person("papa", "Papa").await;
    let kids = world.group("Kinder").await;
    let family = world.group("Familie").await;
    world.state.store.add_member(&kids, &mia).await.unwrap();
    world
        .state
        .store
        .set_members(&family, Members { people: vec![papa.clone()], groups: vec![kids.clone()], owners: vec![] })
        .await
        .unwrap();
    world.state.store.add_member(ADMINS_ID, &nyu).await.unwrap();
    world.state.store.update_person(&papa, |person| person.disabled = true).await.unwrap();
    world.service("nextcloud", "service secret").await;

    let mut client = world.connect();
    assert_eq!(
        client.bind("cn=nextcloud,ou=services,dc=example,dc=com", "service secret").await.code,
        LdapResultCode::Success
    );
    let found = client.search("(&(objectClass=user)(sAMAccountName=nyu))", &["*"]).await;
    assert_eq!(found.len(), 1);
    let nyu_entry = &found[0];
    assert_eq!(nyu_entry.dn, "uid=nyu,ou=people,dc=example,dc=com");
    assert_eq!(values(nyu_entry, "userPrincipalName"), ["nyu@example.com"]);
    assert_eq!(values(nyu_entry, "cn"), ["Nyu Neko"]);
    assert!(values(nyu_entry, "memberOf").contains(&"cn=admins,ou=groups,dc=example,dc=com".to_string()));
    assert!(
        nyu_entry.attributes.iter().any(|attribute| attribute.atype == "objectGUID" && attribute.vals[0].len() == 16)
    );
    assert!(values(nyu_entry, "entryUUID").is_empty(), "operational attributes only when asked for");

    // Everybody in Familie, through Kinder too. (The test's filter parser wants `=` in a value
    // escaped, as RFC 4515 allows.)
    let family_dn = r"cn\3dFamilie,ou\3dgroups,dc\3dexample,dc\3dcom";
    let nested = client.search(&format!("(memberOf:1.2.840.113556.1.4.1941:={family_dn})"), &["uid"]).await;
    let mut names: Vec<String> = nested.iter().flat_map(|entry| values(entry, "uid")).collect();
    names.sort();
    assert_eq!(names, ["mia", "papa"]);
    let direct = client.search(&format!("(memberOf={family_dn})"), &["uid"]).await;
    assert_eq!(direct.iter().flat_map(|entry| values(entry, "uid")).collect::<Vec<_>>(), ["papa"]);
    // Not disabled: the bit AD apps filter on.
    let enabled =
        client.search("(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", &["uid"]).await;
    let mut names: Vec<String> = enabled.iter().flat_map(|entry| values(entry, "uid")).collect();
    names.sort();
    assert_eq!(names, ["mia", "nyu"]);

    // Groups the posix way, and the AD way.
    let groups = client.search("(&(objectClass=posixGroup)(cn=Familie))", &["member", "memberUid", "gidNumber"]).await;
    assert_eq!(values(&groups[0], "memberUid"), ["papa"]);
    assert!(values(&groups[0], "member").contains(&"cn=Kinder,ou=groups,dc=example,dc=com".to_string()));
    let everyone = client.search("(cn=everyone)", &["member"]).await;
    assert_eq!(values(&everyone[0], "member").len(), 3);
    let substring = client.search("(&(objectClass=person)(displayName=*ek*))", &["uid"]).await;
    assert_eq!(substring.len(), 1);
}

#[tokio::test]
async fn a_long_list_comes_in_pages() {
    let world = world(true, None).await;
    for name in ["a1", "a2", "a3", "a4", "a5"] {
        world.person(name, name).await;
    }
    world.service("app", "secret secret").await;
    let mut client = world.connect();
    client.bind("cn=app,ou=services,dc=example,dc=com", "secret secret").await;
    let mut cookie = Vec::new();
    let mut seen = Vec::new();
    loop {
        let (entries, done) = client
            .search_with(
                "ou=people,dc=example,dc=com",
                LdapSearchScope::OneLevel,
                "(objectClass=person)",
                &["uid"],
                vec![LdapControl::SimplePagedResults { size: 2, cookie: cookie.clone() }],
            )
            .await;
        assert!(entries.len() <= 2);
        seen.extend(entries.iter().flat_map(|entry| values(entry, "uid")));
        cookie = done
            .ctrl
            .iter()
            .find_map(|control| match control {
                LdapControl::SimplePagedResults { cookie, .. } => Some(cookie.clone()),
                _ => None,
            })
            .expect("the paged control comes back");
        if cookie.is_empty() {
            break;
        }
    }
    seen.sort();
    assert_eq!(seen, ["a1", "a2", "a3", "a4", "a5"]);
}

#[tokio::test]
async fn a_person_changes_their_password_over_ldap() {
    let world = world(true, None).await;
    world.person("nyu", "Nyu").await;
    let mut client = world.connect();
    client.bind("nyu", PASSWORD).await;
    client.send(LdapOp::ExtendedRequest(LdapExtendedRequest { name: OID_WHOAMI.into(), value: None }), vec![]).await;
    let LdapOp::ExtendedResponse(who) = client.receive().await.op else { panic!() };
    assert_eq!(who.value.unwrap(), b"dn:uid=nyu,ou=people,dc=example,dc=com");

    // Active Directory's way: delete the old unicodePwd, add the new, quoted, UTF-16.
    let utf16 = |text: &str| format!("\"{text}\"").encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
    let change = |old: &str, new: &str| LdapModifyRequest {
        dn: "uid=nyu,ou=people,dc=example,dc=com".into(),
        changes: vec![
            LdapModify {
                operation: LdapModifyType::Delete,
                modification: LdapPartialAttribute { atype: "unicodePwd".into(), vals: vec![utf16(old)] },
            },
            LdapModify {
                operation: LdapModifyType::Add,
                modification: LdapPartialAttribute { atype: "unicodePwd".into(), vals: vec![utf16(new)] },
            },
        ],
    };
    client.send(LdapOp::ModifyRequest(change("wrong old one", "a brand new password")), vec![]).await;
    let LdapOp::ModifyResponse(result) = client.receive().await.op else { panic!() };
    assert_eq!(result.code, LdapResultCode::InvalidCredentials);
    client.send(LdapOp::ModifyRequest(change(PASSWORD, "short")), vec![]).await;
    let LdapOp::ModifyResponse(result) = client.receive().await.op else { panic!() };
    assert_eq!(result.code, LdapResultCode::ConstraintViolation);
    client.send(LdapOp::ModifyRequest(change(PASSWORD, "a brand new password")), vec![]).await;
    let LdapOp::ModifyResponse(result) = client.receive().await.op else { panic!() };
    assert_eq!(result.code, LdapResultCode::Success);
    let mut again = world.connect();
    assert_eq!(again.bind("nyu", "a brand new password").await.code, LdapResultCode::Success);

    // Changing anything else is the portal's job.
    let other = LdapModifyRequest {
        dn: "uid=nyu,ou=people,dc=example,dc=com".into(),
        changes: vec![LdapModify {
            operation: LdapModifyType::Replace,
            modification: LdapPartialAttribute { atype: "mail".into(), vals: vec![b"x@example.com".to_vec()] },
        }],
    };
    again.send(LdapOp::ModifyRequest(other), vec![]).await;
    let LdapOp::ModifyResponse(result) = again.receive().await.op else { panic!() };
    assert_eq!(result.code, LdapResultCode::InsufficentAccessRights);
}

#[tokio::test]
async fn disabled_people_and_closed_windows_are_refused_with_ad_s_reasons() {
    let world = world(true, None).await;
    let nyu = world.person("nyu", "Nyu").await;
    let mia = world.person("mia", "Mia").await;
    world.state.store.update_person(&nyu, |person| person.disabled = true).await.unwrap();
    let mut client = world.connect();
    assert!(client.bind("nyu", PASSWORD).await.message.contains("data 533"));
    // A window that is never now: one minute, twelve hours away.
    let now = jiff::Timestamp::now().to_zoned(world.state.settings().tz());
    let minute = (now.hour() as u16 * 60 + now.minute() as u16 + 720) % 1440;
    let window = Window {
        id: String::new(),
        subject_kind: String::new(),
        subject_id: String::new(),
        app_id: None,
        days: 127,
        start_minute: minute,
        end_minute: (minute + 1) % 1440,
    };
    world.state.store.set_windows("person", &mia, vec![window]).await.unwrap();
    assert!(client.bind("mia", PASSWORD).await.message.contains("data 530"));
}

#[tokio::test]
async fn starttls_then_bind() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let issued = rcgen::generate_simple_self_signed(vec!["auth.example.com".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(issued.signing_key.serialize_der().into());
    let server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![issued.cert.der().clone()], key)
        .unwrap();
    let world = world(false, Some(Arc::new(server_tls))).await;
    world.person("nyu", "Nyu").await;

    let (client, server) = tokio::io::duplex(64 * 1024);
    tokio::spawn(world.ldap.clone().connection(server, IP, false));
    let mut plain = Client { framed: Framed::new(client, LdapCodec::default()), next: 1 };
    plain
        .send(
            LdapOp::ExtendedRequest(LdapExtendedRequest { name: "1.3.6.1.4.1.1466.20037".into(), value: None }),
            vec![],
        )
        .await;
    let LdapOp::ExtendedResponse(response) = plain.receive().await.op else { panic!() };
    assert_eq!(response.res.code, LdapResultCode::Success);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(issued.cert.der().clone()).unwrap();
    let client_tls = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
    let stream = plain.framed.into_inner();
    let tls =
        connector.connect(rustls::pki_types::ServerName::try_from("auth.example.com").unwrap(), stream).await.unwrap();
    let mut secure = Client { framed: Framed::new(tls, LdapCodec::default()), next: 10 };
    assert_eq!(secure.bind("nyu", PASSWORD).await.code, LdapResultCode::Success, "over TLS a password is fine");
}
