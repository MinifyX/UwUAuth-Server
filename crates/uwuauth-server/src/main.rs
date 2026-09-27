//! `uwuauth-server` — run it, or ask it something.
//!
//! With no arguments it serves. The other commands are the ones you reach for from a shell on
//! the box: invite the first admin, take a backup, put one back, ask whether it is well — and
//! get back in when the only admin lost their passkey or their phone.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uwuauth_server::{Config, health, updates};
use uwuauth_store::backups;
use uwuauth_store::with_suffix;

#[derive(Parser)]
#[command(name = "uwuauth-server", version, about = "People and groups in one place, for every app that needs them")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Serve. The default.
    Serve,
    /// Write a consistent copy of the database, while the server runs.
    Backup {
        /// Where to write it. The default is a dated file under `backups`.
        #[arg(long)]
        to: Option<PathBuf>,
    },
    /// Put a backup back. Without a name, list the backups there are. Only while the server is
    /// stopped: `docker compose stop && docker compose run --rm uwuauth restore <name>`
    Restore {
        /// A file under `backups`, or a path.
        backup: Option<PathBuf>,
    },
    /// Ask the running server whether it is well. The container's health check: the image has no
    /// shell and no curl, so the server asks itself.
    Health,
    /// Invite somebody: prints the link to make an account with, and mails it if the server can.
    /// `docker compose exec uwuauth uwuauth-server invite --admin you@example.com` makes the
    /// first admin.
    Invite {
        /// Where the invitation goes. Without one, pass the link on by hand.
        email: Option<String>,
        /// The account will be an admin.
        #[arg(long)]
        admin: bool,
    },
    /// Make somebody an admin, or (`--remove`) no longer one.
    Admin {
        /// User name or address.
        login: String,
        #[arg(long)]
        remove: bool,
    },
    /// Print a link to set a new password (or, for somebody without any way to sign in, to set
    /// one up). It works for a day.
    ResetPassword {
        /// User name or address.
        login: String,
    },
    /// Take away the authenticator app, the recovery codes and every passkey of somebody who lost
    /// them. They sign in with their password afterwards, or with a link from reset-password.
    ResetTwoFactor {
        /// User name or address.
        login: String,
    },
}

fn main() -> Result<(), String> {
    use std::io::IsTerminal;
    // Everything this server writes is its own: the database, the backups, the certificate key.
    // Nobody else on the machine reads them.
    #[cfg(unix)]
    // SAFETY: umask only sets this process's file mode mask; it cannot fail and touches no memory.
    unsafe {
        libc::umask(0o077);
    }
    // The newest lines also stay in memory, for the admin portal.
    let logs = uwuauth_api::LogBuffer::new(5000);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "uwuauth_server=info,uwuauth_api=info,uwuauth_store=info,warn".into()),
        )
        // The log goes to stderr, so what a command prints on stdout is only that.
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr).with_ansi(std::io::stderr().is_terminal()))
        .with(logs.layer())
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();
    let config = Config::from_env()?;
    match cli.command.unwrap_or(Command::Serve) {
        // Asked every half minute, so it touches nothing but the network — not even the database.
        Command::Health => health::probe(&config),
        // Opening the database would be using it, and a restore needs it unused.
        Command::Restore { backup } => restore(&config, backup),
        Command::Backup { to } => runtime()?.block_on(async {
            let store = uwuauth_server::open_store(&config)?;
            let path = backups::write(&store, &config.backups(), to).await?;
            println!("Written to {}", path.display());
            Ok(())
        }),
        Command::Invite { email, admin } => runtime()?.block_on(invite(config, email, admin, logs)),
        Command::Admin { login, remove } => runtime()?.block_on(async {
            let store = uwuauth_server::open_store(&config)?;
            let person = find(&store, &login).await?;
            let result = if remove {
                store.remove_member(uwuauth_store::ADMINS_ID, &person.id).await
            } else {
                store.add_member(uwuauth_store::ADMINS_ID, &person.id).await
            };
            result.map_err(|error| error.to_string())?;
            println!("{} is {} an admin.", person.username, if remove { "no longer" } else { "now" });
            Ok(())
        }),
        Command::ResetPassword { login } => runtime()?.block_on(reset_password(config, login)),
        Command::ResetTwoFactor { login } => runtime()?.block_on(async {
            let store = uwuauth_server::open_store(&config)?;
            let person = find(&store, &login).await?;
            let error = |error: uwuauth_store::StoreError| error.to_string();
            store.update_person(&person.id, |person| person.totp_secret = None).await.map_err(error)?;
            store.set_recovery_codes(&person.id, Vec::new()).await.map_err(error)?;
            for passkey in store.passkeys(&person.id).await.map_err(error)? {
                store.remove_passkey(&person.id, &passkey.id).await.map_err(error)?;
            }
            store
                .record("second_factors_reset", None, Some(&person.id), None, None, r#"{"by":"command"}"#)
                .await
                .map_err(error)?;
            println!("{} has no authenticator app, recovery codes or passkeys any more.", person.username);
            if person.password_hash.is_none() {
                println!(
                    "They have no password either: uwuauth-server reset-password {} makes a link to set one.",
                    person.username
                );
            }
            Ok(())
        }),
        Command::Serve => runtime()?.block_on(serve(config, logs)),
    }
}

async fn find(store: &uwuauth_store::Store, login: &str) -> Result<uwuauth_store::Person, String> {
    store
        .person_by_login(login)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("There is nobody called {login}."))
}

/// `uwuauth-server invite [--admin] [email]`.
async fn invite(
    config: Config,
    email: Option<String>,
    admin: bool,
    logs: std::sync::Arc<uwuauth_api::LogBuffer>,
) -> Result<(), String> {
    if config.public.is_none() {
        eprintln!("UWUAUTH_PUBLIC is not set, so the link below points at this machine's own address.");
    }
    let store = uwuauth_server::open_store(&config)?;
    let state = uwuauth_server::app_state(&config, store, logs).await?;
    let fields = uwuauth_api::routes::invitations::InviteFields { email, admin, mail: true, ..Default::default() };
    let invited =
        uwuauth_api::routes::invitations::invite(&state, None, fields).await.map_err(|error| error.message)?;
    println!(
        "Invited{}{}.",
        invited["email"].as_str().map(|email| format!(" {email}")).unwrap_or_default(),
        if admin { " as an admin" } else { "" }
    );
    if invited["mailed"].is_string() {
        println!("The invitation went out by mail. The link, in case it does not arrive:");
    } else {
        println!("Pass this link on — it is the only way to use this invitation:");
    }
    println!("{}", invited["link"].as_str().unwrap_or_default());
    Ok(())
}

/// `uwuauth-server reset-password <login>`.
async fn reset_password(config: Config, login: String) -> Result<(), String> {
    use uwuauth_api::crypto::{random_token, sha256};
    let store = uwuauth_server::open_store(&config)?;
    let person = find(&store, &login).await?;
    let error = |error: uwuauth_store::StoreError| error.to_string();
    let setup = person.password_hash.is_none() && store.passkeys(&person.id).await.map_err(error)?.is_empty();
    let (purpose, path) =
        if setup { (uwuauth_store::Purpose::Setup, "setup") } else { (uwuauth_store::Purpose::Reset, "reset") };
    let token = random_token(32);
    let expires = uwuauth_store::clock::in_seconds(86_400);
    store
        .create_link(sha256(token.as_bytes()), purpose, Some(&person.id), "{}", None, &expires)
        .await
        .map_err(error)?;
    store.record("link_made", None, Some(&person.id), None, None, r#"{"by":"command"}"#).await.map_err(error)?;
    println!("For {} — it works once, for a day:", person.username);
    println!("{}/#/{path}?token={token}", config.base_url());
    Ok(())
}

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|error| error.to_string())
}

async fn serve(config: Config, logs: std::sync::Arc<uwuauth_api::LogBuffer>) -> Result<(), String> {
    let build = updates::build();
    tracing::info!(version = build.version, commit = build.commit.unwrap_or("-"), "UwUAuth Server");
    let store = uwuauth_server::open_store(&config)?;
    uwuauth_server::run(config, store, logs, uwuauth_server::shutdown_signal(), None).await
}

/// `uwuauth-server restore [name]`.
fn restore(config: &Config, backup: Option<PathBuf>) -> Result<(), String> {
    let Some(backup) = backup else {
        let found = backups::list(&config.backups());
        if found.is_empty() {
            println!("No backups in {} yet.", config.backups().display());
        }
        for (name, bytes) in found {
            println!("{name}  {} KiB", bytes.div_ceil(1024));
        }
        return Ok(());
    };
    // A bare name means one of the backups; anything else is a path.
    let path =
        if backup.components().count() == 1 && !backup.exists() { config.backups().join(&backup) } else { backup };
    let database = config.database();
    let aside = with_suffix(&database, &format!(".before-restore-{}", backups::stamp(backups::now_ms())));
    uwuauth_store::restore(&path, &database, &aside)?;
    println!("Restored from {}.", path.display());
    if aside.exists() {
        println!("What was there before is kept as {}.", aside.display());
    }
    println!("Start the server again: docker compose up -d");
    Ok(())
}
