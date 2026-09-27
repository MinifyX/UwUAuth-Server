//! Have I Been Pwned, asked the way that never gives a password away (k-anonymity).
//!
//! The server hashes the password with SHA-1 and sends only the first five hex digits of the
//! hash. HIBP answers with every hash in its list that starts with them — hundreds — padded with
//! made-up ones, so not even the size of the answer tells anything. The server looks for the
//! rest of its hash in that list itself. HIBP never sees the password, nor its hash; it only
//! learns that somebody asked about one of countless passwords sharing five characters.
//!
//! Off unless an admin turns it on. Answers are kept for a day.

use crate::AppState;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

const KEEP: Duration = Duration::from_secs(24 * 60 * 60);
const MOST: usize = 1024;
/// What an answer from HIBP may be at the most.
const MAX_ANSWER: usize = 512 * 1024;

/// Ranges by HIBP address and prefix, with when they came.
type Ranges = Mutex<HashMap<String, (Arc<str>, Instant)>>;

fn cache() -> &'static Ranges {
    static CACHE: OnceLock<Ranges> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

fn client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            let roots: rustls::RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
            let tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|error| error.to_string())?
                .with_root_certificates(roots)
                .with_no_client_auth();
            reqwest::Client::builder()
                .tls_backend_preconfigured(tls)
                .user_agent("UwUAuth-Server")
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(Clone::clone)
}

async fn range(base: &str, prefix: &str) -> Result<Arc<str>, String> {
    let key = format!("{base}|{prefix}");
    if let Some((range, at)) = cache().lock().get(&key)
        && at.elapsed() < KEEP
    {
        return Ok(range.clone());
    }
    let mut response = client()?
        .get(format!("{}/range/{prefix}", base.trim_end_matches('/')))
        .header("add-padding", "true")
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("HIBP answered {}", response.status()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| error.to_string())? {
        if body.len() + chunk.len() > MAX_ANSWER {
            return Err("HIBP answered with far more than a range".into());
        }
        body.extend_from_slice(&chunk);
    }
    let text: Arc<str> = String::from_utf8(body).map_err(|_| "HIBP answered with something that is not text")?.into();
    let mut cache = cache().lock();
    if cache.len() >= MOST {
        cache.clear();
    }
    cache.insert(key, (text.clone(), Instant::now()));
    Ok(text)
}

/// How often `password` appears in known leaks; 0 when it does not.
pub async fn pwned(state: &AppState, password: &str) -> Result<u64, String> {
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, password.as_bytes());
    let hex: String = digest.as_ref().iter().map(|byte| format!("{byte:02X}")).collect();
    let (prefix, rest) = hex.split_at(5);
    let list = range(&state.config.hibp_url, prefix).await?;
    Ok(list
        .lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find(|(suffix, _)| suffix.eq_ignore_ascii_case(rest))
        .and_then(|(_, count)| count.trim().parse().ok())
        .unwrap_or(0))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// HIBP on this machine: knows `password` (SHA-1 5BAA6…) 3 times, counts how often it is asked
    /// and checks it is only ever asked for five characters, with padding.
    pub(crate) async fn fake_hibp() -> (String, std::sync::Arc<AtomicUsize>) {
        let asked = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = asked.clone();
        let app = axum::Router::new().route(
            "/range/{prefix}",
            axum::routing::get(
                move |axum::extract::Path(prefix): axum::extract::Path<String>, headers: axum::http::HeaderMap| {
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(headers.get("add-padding").unwrap(), "true");
                        assert_eq!(prefix.len(), 5, "only five characters leave the server");
                        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0"
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), asked)
    }
}
