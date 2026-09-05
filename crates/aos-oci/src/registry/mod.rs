//! Authenticated OCI Distribution client with resumable verified transfers.
//!
//! The client accepts a complete [`RegistryReference`], validates that an
//! explicit registry origin names the same authority, and implements the standard
//! Bearer challenge. Pull retains partial blobs and resumes with ranges. Push
//! persists only upload locations and offsets - never credentials - and updates
//! a mutable tag only after the entire descriptor graph is verified and durable.

mod publication;
mod pull;
mod push;

use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use futures_util::StreamExt as _;
use futures_util::future::BoxFuture;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue, WWW_AUTHENTICATE};
use reqwest::redirect::Policy;
use reqwest::{Method, Response, StatusCode};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::layout::VerifiedImage;
use crate::reference::{PlatformSelector, RegistryReference};
use aos_oci_types::{ContainerRelease, RepositoryName, Sha256Digest};

pub use publication::{
    VerifiedPublicationCommit, VerifiedPublicationHook, VerifiedPublicationRequest,
    VerifiedPublicationResult, VerifiedPublicationSession,
};

const TOKEN_RESPONSE_LIMIT: usize = 1024 * 1024;

/// One stable progress event emitted by a pull or push operation.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum TransferEvent {
    /// A descriptor is being checked locally or remotely.
    Checking {
        /// Exact SHA-256 digest.
        digest: String,
    },
    /// A blob download is progressing.
    Downloading {
        /// Exact SHA-256 digest.
        digest: String,
        /// Bytes now durably present in the partial file.
        offset: u64,
        /// Expected descriptor byte length.
        total: u64,
    },
    /// A blob upload is progressing.
    Uploading {
        /// Exact SHA-256 digest.
        digest: String,
        /// Bytes acknowledged by the registry.
        offset: u64,
        /// Expected descriptor byte length.
        total: u64,
    },
    /// One descriptor transfer or remote existence check completed.
    Complete {
        /// Exact SHA-256 digest.
        digest: String,
        /// Exact descriptor byte length.
        size: u64,
    },
}

/// Verified result of publishing one selected image graph.
#[derive(Clone, Debug, Serialize)]
pub struct PushResult {
    /// The selected image that was verified before the first network effect.
    pub image: VerifiedImage,
    /// Digest of the exact index bytes uploaded by digest and, for tags, assigned last.
    pub published_index_digest: Sha256Digest,
}

/// Pull behavior and durable destination state.
#[derive(Clone)]
pub struct PullOptions {
    /// Destination directory for the OCI layout and retained partial blobs.
    pub destination: PathBuf,
    /// Runnable platform to select from an index.
    pub platform: PlatformSelector,
    /// Cooperative cancellation observed between network and filesystem writes.
    pub cancellation: CancellationToken,
    /// Optional stable progress-event sink.
    pub events: Option<UnboundedSender<TransferEvent>>,
}

impl PullOptions {
    /// Creates pull options for the native host platform.
    #[must_use]
    pub fn native(destination: PathBuf) -> Self {
        Self {
            destination,
            platform: PlatformSelector::native(),
            cancellation: CancellationToken::new(),
            events: None,
        }
    }
}

/// Push behavior and credential-free resumable state.
#[derive(Clone)]
pub struct PushOptions {
    /// Source OCI layout directory.
    pub source: PathBuf,
    /// Runnable platform to select from the source index.
    pub platform: PlatformSelector,
    /// Private local directory holding upload location/offset checkpoints.
    pub state_directory: PathBuf,
    /// Maximum bytes sent in one PATCH request.
    pub chunk_bytes: usize,
    /// Cooperative cancellation observed between upload chunks and tag writes.
    pub cancellation: CancellationToken,
    /// Optional stable progress-event sink.
    pub events: Option<UnboundedSender<TransferEvent>>,
}

/// Result of uploading every object named by one signed AOS release graph.
#[derive(Clone, Debug, Serialize)]
pub struct ReleaseGraphPushResult {
    /// Exact immutable OCI index digest declared by the release sidecar.
    pub root_index_digest: Sha256Digest,
    /// Number of distinct content-addressed objects admitted by the graph walk.
    pub object_count: usize,
}

impl PushOptions {
    /// Creates push options using the native platform and 4 MiB chunks.
    #[must_use]
    pub fn native(source: PathBuf, state_directory: PathBuf) -> Self {
        Self {
            source,
            platform: PlatformSelector::native(),
            state_directory,
            chunk_bytes: 4 * 1024 * 1024,
            cancellation: CancellationToken::new(),
            events: None,
        }
    }
}

/// A native OCI Distribution client bound to one registry origin.
#[derive(Clone)]
pub struct RegistryClient {
    inner: Arc<ClientInner>,
}

type CredentialProvider = Arc<dyn Fn() -> BoxFuture<'static, Result<Option<String>>> + Send + Sync>;

struct ClientInner {
    http: reqwest::Client,
    origin: Url,
    reference_authority: String,
    seed_token: Option<Zeroizing<String>>,
    credential_provider: Option<CredentialProvider>,
    deferred_token: tokio::sync::OnceCell<Option<Zeroizing<String>>>,
    scoped_tokens: Mutex<BTreeMap<String, Zeroizing<String>>>,
}

impl RegistryClient {
    /// Constructs a client for a reference and optional explicit registry origin.
    ///
    /// Without `origin`, HTTPS is used at the reference authority. An explicit
    /// HTTP origin is accepted only for a loopback host, supporting native Hub
    /// development without weakening remote credential transport.
    ///
    /// # Errors
    ///
    /// Returns an error when the origin is not root-mounted HTTP(S), names a
    /// different authority, uses non-loopback plaintext HTTP, or the HTTP client
    /// cannot be constructed.
    pub fn new(
        reference: &RegistryReference,
        origin: Option<&str>,
        seed_token: Option<String>,
    ) -> Result<Self> {
        Self::build(reference, origin, seed_token, None)
    }

    /// Constructs a client that loads credentials only after anonymous authentication fails.
    ///
    /// The provider is called only when a same-origin Bearer token endpoint
    /// rejects an anonymous request with 401 or 403, or the registry rejects
    /// the resulting anonymous scoped token. A successfully resolved credential
    /// is cached for this client and never sent to an external token realm.
    ///
    /// # Errors
    ///
    /// Returns the same construction errors as [`Self::new`]. Provider errors
    /// are propagated by the transfer that needs authentication.
    pub fn with_credential_provider<F, Fut>(
        reference: &RegistryReference,
        origin: Option<&str>,
        provider: F,
    ) -> Result<Self>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<String>>> + Send + 'static,
    {
        Self::build(
            reference,
            origin,
            None,
            Some(Arc::new(move || Box::pin(provider()))),
        )
    }

    fn build(
        reference: &RegistryReference,
        origin: Option<&str>,
        seed_token: Option<String>,
        credential_provider: Option<CredentialProvider>,
    ) -> Result<Self> {
        let origin = match origin {
            Some(origin) => Url::parse(origin).context("parsing registry origin")?,
            None => reference.default_origin()?,
        };
        validate_origin(&origin, reference.authority())?;
        let http = http_client_builder()
            .user_agent(concat!("aos-oci/", env!("CARGO_PKG_VERSION")))
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(5 * 60))
            .build()
            .context("building OCI HTTP client")?;
        Ok(Self {
            inner: Arc::new(ClientInner {
                http,
                origin,
                reference_authority: reference.authority().to_string(),
                seed_token: seed_token.map(Zeroizing::new),
                credential_provider,
                deferred_token: tokio::sync::OnceCell::new(),
                scoped_tokens: Mutex::new(BTreeMap::new()),
            }),
        })
    }

    /// Pulls and verifies one selected platform into a resumable OCI layout.
    ///
    /// # Errors
    ///
    /// Returns an error for authentication or HTTP failure, cancellation,
    /// malformed registry content, any descriptor mismatch, unsafe local state,
    /// or final layout verification failure.
    pub async fn pull(
        &self,
        reference: &RegistryReference,
        options: &PullOptions,
    ) -> Result<VerifiedImage> {
        self.ensure_reference(reference)?;
        pull::run(self, reference, options).await
    }

    /// Verifies and pushes one selected platform, updating the tag last.
    ///
    /// # Errors
    ///
    /// Returns an error for local graph corruption, authentication or HTTP
    /// failure, invalid resumable state, upload digest disagreement,
    /// cancellation, or a final manifest/tag update failure.
    pub async fn push(
        &self,
        reference: &RegistryReference,
        options: &PushOptions,
    ) -> Result<PushResult> {
        self.ensure_reference(reference)?;
        push::run(self, reference, options).await
    }

    /// Pushes an image while attempting authorized cross-repository blob mounts.
    ///
    /// Each source is a repository in the same registry authority. The client
    /// obtains source-pull and destination-push grants together, checks that the
    /// source owns the blob, and falls back to a normal upload when mounting is
    /// unavailable.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::push`], plus authorization or protocol
    /// failures while checking and mounting source blobs.
    pub async fn push_with_mounts(
        &self,
        reference: &RegistryReference,
        options: &PushOptions,
        mount_sources: &[RepositoryName],
    ) -> Result<PushResult> {
        self.ensure_reference(reference)?;
        push::run_with_mounts(self, reference, options, mount_sources).await
    }

    /// Verifies and uploads the complete graph declared by a signed AOS release.
    ///
    /// The destination must use the release's immutable index digest. Every
    /// config, layer, platform manifest, index, and evidence payload is checked
    /// locally before the first request. Documents are then written by digest
    /// only; this operation never mutates a tag or marks a release verified.
    ///
    /// # Errors
    ///
    /// Returns an error when the sidecar and local layout disagree, the graph
    /// is incomplete or cyclic, a descriptor fails exact verification, the
    /// destination is not the declared digest, or a Distribution transfer fails.
    pub async fn push_release_graph(
        &self,
        reference: &RegistryReference,
        options: &PushOptions,
        release: &ContainerRelease,
        mount_sources: &[RepositoryName],
    ) -> Result<ReleaseGraphPushResult> {
        self.ensure_reference(reference)?;
        push::run_release_graph(self, reference, options, release, mount_sources).await
    }

    /// Deletes an immutable manifest or index digest.
    ///
    /// Tag deletion is deliberately rejected because it is ambiguous across
    /// registries and bypasses the Hub's tag compare-and-swap history.
    ///
    /// # Errors
    ///
    /// Returns an error for a tag reference, authentication or HTTP failure,
    /// cancellation, or a registry that refuses digest deletion.
    pub async fn delete_manifest(
        &self,
        reference: &RegistryReference,
        cancellation: &CancellationToken,
    ) -> Result<()> {
        self.ensure_reference(reference)?;
        push::delete_manifest(self, reference, cancellation).await
    }

    /// Cancels all resumable upload sessions recorded for a repository.
    ///
    /// Checkpoints are removed only after the registry accepts deletion or
    /// reports the session absent. A bounded retry absorbs transient service
    /// unavailability while an in-flight upload request finishes. Credentials
    /// are never stored in the state directory.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe or foreign checkpoint state, cancellation,
    /// authentication failure, or a registry that refuses an upload deletion
    /// after the bounded retry window.
    pub async fn cancel_uploads(
        &self,
        reference: &RegistryReference,
        state_directory: &std::path::Path,
        cancellation: &CancellationToken,
    ) -> Result<usize> {
        self.ensure_reference(reference)?;
        push::cancel_uploads(self, reference, state_directory, cancellation).await
    }

    fn ensure_reference(&self, reference: &RegistryReference) -> Result<()> {
        ensure!(
            reference.authority() == self.inner.reference_authority,
            "registry client is bound to a different reference authority"
        );
        Ok(())
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.inner
            .origin
            .join(path)
            .context("constructing Distribution URL")
    }

    async fn send(
        &self,
        method: Method,
        url: Url,
        scope: &str,
        headers: &HeaderMap,
        body: Option<Bytes>,
        cancellation: &CancellationToken,
    ) -> Result<Response> {
        let scopes = [scope.to_string()];
        self.send_scoped(method, url, &scopes, headers, body, cancellation)
            .await
    }

    async fn send_scoped(
        &self,
        method: Method,
        url: Url,
        scopes: &[String],
        headers: &HeaderMap,
        body: Option<Bytes>,
        cancellation: &CancellationToken,
    ) -> Result<Response> {
        let scopes = normalized_scopes(scopes)?;
        let cache_key = scopes.join("\n");
        let mut retries = 0;
        let mut previous_challenge = None;
        loop {
            let token = self.token_for_scope(&cache_key)?;
            let mut request = self
                .inner
                .http
                .request(method.clone(), url.clone())
                .headers(headers.clone());
            if let Some(token) = token.as_deref() {
                request = request.bearer_auth(token);
            }
            if let Some(body) = body.clone() {
                request = request.body(body);
            }
            let response = tokio::select! {
                () = cancellation.cancelled() => bail!("OCI transfer cancelled"),
                response = request.send() => response.context("sending Distribution request")?,
            };
            let denied = matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            );
            // An anonymous token can carry fewer grants than requested. Retry
            // only this denied request after one authenticated exchange.
            let retry_credentials = retries == 1 && self.inner.credential_provider.is_some();
            if !denied
                || retries >= 2
                || (retries == 1 && !retry_credentials)
                || (retries == 0 && response.status() != StatusCode::UNAUTHORIZED)
            {
                return Ok(response);
            }
            let challenge = match response.headers().get(WWW_AUTHENTICATE) {
                Some(value) => value
                    .to_str()
                    .context("registry returned a non-ASCII authentication challenge")?
                    .to_owned(),
                None => previous_challenge
                    .clone()
                    .context("registry returned 401 without WWW-Authenticate")?,
            };
            let token = self
                .authorize(&challenge, &scopes, cancellation, retry_credentials)
                .await?;
            self.store_scoped_token(&cache_key, token)?;
            previous_challenge = Some(challenge);
            retries += 1;
        }
    }

    async fn get_blob(
        &self,
        url: Url,
        scope: &str,
        headers: &HeaderMap,
        cancellation: &CancellationToken,
    ) -> Result<Response> {
        const MAX_REDIRECTS: usize = 3;

        let mut current = url;
        let mut authenticated = true;
        for hop in 0..=MAX_REDIRECTS {
            let response = if authenticated {
                self.send(
                    Method::GET,
                    current.clone(),
                    scope,
                    headers,
                    None,
                    cancellation,
                )
                .await?
            } else {
                let client = external_client(&current, cancellation).await?;
                let request = client.get(current.clone()).headers(headers.clone());
                tokio::select! {
                    () = cancellation.cancelled() => bail!("OCI transfer cancelled"),
                    response = request.send() => response.context("sending redirected blob request")?,
                }
            };
            if !response.status().is_redirection() {
                return Ok(response);
            }
            ensure!(
                matches!(
                    response.status(),
                    StatusCode::MOVED_PERMANENTLY
                        | StatusCode::FOUND
                        | StatusCode::TEMPORARY_REDIRECT
                        | StatusCode::PERMANENT_REDIRECT
                ),
                "registry returned an unsupported blob redirect status"
            );
            ensure!(hop < MAX_REDIRECTS, "registry blob redirect limit exceeded");
            let next = resolve_location(&current, &response)?;
            validate_blob_redirect(&self.inner.origin, &next)?;
            authenticated = same_authority(&next, &self.inner.origin);
            current = next;
        }
        bail!("registry blob redirect limit exceeded")
    }

    fn token_for_scope(&self, scope: &str) -> Result<Option<Zeroizing<String>>> {
        let scoped = self
            .inner
            .scoped_tokens
            .lock()
            .map_err(|_| anyhow::anyhow!("OCI token cache lock is poisoned"))?;
        Ok(scoped
            .get(scope)
            .cloned()
            .or_else(|| self.inner.seed_token.clone()))
    }

    fn store_scoped_token(&self, scope: &str, token: Zeroizing<String>) -> Result<()> {
        self.inner
            .scoped_tokens
            .lock()
            .map_err(|_| anyhow::anyhow!("OCI token cache lock is poisoned"))?
            .insert(scope.to_string(), token);
        Ok(())
    }

    async fn deferred_credential(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<Option<Zeroizing<String>>> {
        let Some(provider) = &self.inner.credential_provider else {
            return Ok(None);
        };
        let seed = tokio::select! {
            () = cancellation.cancelled() => bail!("OCI transfer cancelled"),
            seed = self.inner.deferred_token.get_or_try_init(|| async {
                provider().await.map(|token| token.map(Zeroizing::new))
            }) => seed?,
        };
        Ok(seed.clone())
    }

    async fn authorize(
        &self,
        challenge: &str,
        requested_scopes: &[String],
        cancellation: &CancellationToken,
        require_credentials: bool,
    ) -> Result<Zeroizing<String>> {
        let parameters = parse_bearer_challenge(challenge)?;
        let realm = parameters
            .get("realm")
            .context("Bearer challenge lacks realm")?;
        let mut realm = Url::parse(realm).context("Bearer challenge realm is not a URL")?;
        ensure!(
            matches!(realm.scheme(), "http" | "https"),
            "Bearer challenge realm must use HTTP or HTTPS"
        );
        ensure!(
            realm.username().is_empty() && realm.password().is_none(),
            "Bearer realm must not contain credentials"
        );
        ensure!(
            realm.fragment().is_none(),
            "Bearer realm must not contain a fragment"
        );
        validate_bearer_realm(&self.inner.origin, &realm)?;
        if let Some(challenge_scope) = parameters.get("scope") {
            ensure!(
                requested_scopes
                    .iter()
                    .any(|scope| challenge_scope_is_subset(scope, challenge_scope)),
                "registry challenged for a different repository or additional action scope"
            );
        }
        {
            let mut query = realm.query_pairs_mut();
            if let Some(service) = parameters.get("service") {
                query.append_pair("service", service);
            }
            for scope in requested_scopes {
                query.append_pair("scope", scope);
            }
        }

        let same_origin = same_authority(&realm, &self.inner.origin);
        let external;
        let mut request = if same_origin {
            self.inner.http.get(realm.clone())
        } else {
            external = external_client(&realm, cancellation).await?;
            external.get(realm.clone())
        };
        let deferred_seed;
        if same_origin {
            let seed = if require_credentials {
                deferred_seed = self.deferred_credential(cancellation).await?;
                deferred_seed.as_deref()
            } else {
                self.inner.seed_token.as_deref()
            };
            if let Some(seed) = seed {
                request = request.header(AUTHORIZATION, bearer_header(seed)?);
            }
        }
        let mut response = tokio::select! {
            () = cancellation.cancelled() => bail!("OCI transfer cancelled"),
            response = request.send() => response.context("requesting registry bearer token")?,
        };
        // Public registries can challenge every request and still issue tokens
        // anonymously. Consult local credentials only after that exchange fails.
        if same_origin
            && matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            )
            && !require_credentials
            && self.inner.credential_provider.is_some()
        {
            let seed = self.deferred_credential(cancellation).await?;
            if let Some(seed) = seed {
                let request = self
                    .inner
                    .http
                    .get(realm)
                    .header(AUTHORIZATION, bearer_header(&seed)?);
                response = tokio::select! {
                    () = cancellation.cancelled() => bail!("OCI transfer cancelled"),
                    response = request.send() => response.context("requesting authenticated registry bearer token")?,
                };
            }
        }
        ensure!(
            response.status().is_success(),
            "registry bearer-token request failed with {}",
            response.status()
        );
        let bytes = read_bounded_body(
            response,
            TOKEN_RESPONSE_LIMIT,
            cancellation,
            "registry bearer-token response",
        )
        .await?;

        #[derive(Deserialize)]
        struct TokenResponse {
            token: Option<String>,
            access_token: Option<String>,
        }
        let response: TokenResponse =
            serde_json::from_slice(&bytes).context("decoding registry bearer-token response")?;
        let token = response
            .token
            .or(response.access_token)
            .filter(|token| !token.is_empty())
            .context("registry bearer-token response lacks a token")?;
        Ok(Zeroizing::new(token))
    }
}

fn normalized_scopes(scopes: &[String]) -> Result<Vec<String>> {
    ensure!(!scopes.is_empty(), "registry request requires a scope");
    let mut normalized = scopes.to_vec();
    for scope in &normalized {
        ensure!(
            !scope.is_empty()
                && scope.is_ascii()
                && !scope.bytes().any(|byte| byte.is_ascii_control()),
            "registry scope contains invalid bytes"
        );
    }
    normalized.sort();
    normalized.dedup();
    Ok(normalized)
}

fn challenge_scope_is_subset(requested: &str, challenged: &str) -> bool {
    fn split(value: &str) -> Option<(RepositoryName, Vec<&str>)> {
        let mut parts = value.splitn(3, ':');
        let kind = parts.next()?;
        let name = parts.next()?;
        let mut actions = parts.next()?.split(',').collect::<Vec<_>>();
        if kind != "repository"
            || actions.is_empty()
            || actions.iter().any(|action| action.is_empty())
        {
            return None;
        }
        let repository = RepositoryName::parse(name).ok()?;
        actions.sort_unstable();
        actions.dedup();
        Some((repository, actions))
    }

    let Some((requested_repository, requested_actions)) = split(requested) else {
        return false;
    };
    let Some((challenged_repository, challenged_actions)) = split(challenged) else {
        return false;
    };
    requested_repository == challenged_repository
        && challenged_actions
            .iter()
            .all(|action| requested_actions.contains(action))
}

fn bearer_header(token: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(&format!("Bearer {token}"))
        .context("bearer token contains invalid HTTP header bytes")
}

fn validate_origin(origin: &Url, reference_authority: &str) -> Result<()> {
    ensure!(
        matches!(origin.scheme(), "http" | "https"),
        "registry origin must use HTTP or HTTPS"
    );
    ensure!(
        origin.username().is_empty() && origin.password().is_none(),
        "registry origin must not contain credentials"
    );
    ensure!(
        origin.path() == "/",
        "registry origin must be mounted at / for the /v2 API"
    );
    ensure!(
        origin.query().is_none() && origin.fragment().is_none(),
        "registry origin must not contain query or fragment data"
    );
    ensure!(
        origin_authority(origin)? == reference_authority,
        "registry origin authority does not match the image reference"
    );
    if origin.scheme() == "http" {
        ensure!(
            is_loopback(origin),
            "plaintext registry origins must be loopback"
        );
    }
    Ok(())
}

fn origin_authority(origin: &Url) -> Result<String> {
    let host = origin.host().context("registry origin lacks a host")?;
    let host = match host {
        Host::Ipv6(address) => format!("[{address}]"),
        Host::Ipv4(address) => address.to_string(),
        Host::Domain(domain) => domain.to_ascii_lowercase(),
    };
    Ok(match origin.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn validate_remote_endpoint(url: &Url, allowed: Option<&Url>) -> Result<()> {
    if allowed.is_some_and(|allowed| same_authority(url, allowed)) {
        return Ok(());
    }
    match url.host().context("remote endpoint lacks a host")? {
        Host::Ipv4(address) => validate_remote_ip(IpAddr::V4(address))?,
        Host::Ipv6(address) => validate_remote_ip(IpAddr::V6(address))?,
        Host::Domain(domain) => ensure!(
            !domain.eq_ignore_ascii_case("localhost")
                && !domain.to_ascii_lowercase().ends_with(".localhost"),
            "remote endpoint uses a loopback host name"
        ),
    }
    Ok(())
}

async fn external_client(url: &Url, cancellation: &CancellationToken) -> Result<reqwest::Client> {
    validate_remote_endpoint(url, None)?;
    let Some(Host::Domain(domain)) = url.host() else {
        return build_http_client(None);
    };
    let port = url
        .port_or_known_default()
        .context("remote endpoint lacks a known port")?;
    let addresses = tokio::select! {
        () = cancellation.cancelled() => bail!("OCI transfer cancelled"),
        addresses = tokio::net::lookup_host((domain, port)) => {
            addresses.context("resolving remote OCI endpoint")?.collect::<Vec<_>>()
        }
    };
    ensure!(!addresses.is_empty(), "remote OCI endpoint did not resolve");
    for address in &addresses {
        validate_remote_ip(address.ip())?;
    }
    build_http_client(Some((domain, &addresses)))
}

fn build_http_client(resolution: Option<(&str, &[SocketAddr])>) -> Result<reqwest::Client> {
    let mut builder = http_client_builder()
        .user_agent(concat!("aos-oci/", env!("CARGO_PKG_VERSION")))
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(5 * 60));
    if let Some((domain, addresses)) = resolution {
        builder = builder.resolve_to_addrs(domain, addresses);
    }
    builder.build().context("building confined OCI HTTP client")
}

fn http_client_builder() -> reqwest::ClientBuilder {
    let native_roots = rustls_native_certs::load_native_certs()
        .certs
        .into_iter()
        .filter_map(|certificate| reqwest::Certificate::from_der(certificate.as_ref()).ok())
        .collect::<Vec<_>>();
    let mut builder = reqwest::Client::builder();
    if !native_roots.is_empty() {
        // AOS-managed trust is authoritative when the platform publishes it.
        // Minimal environments without native roots retain reqwest's bundled
        // WebPKI roots as a bootstrap fallback.
        builder = builder.tls_built_in_root_certs(false);
        for certificate in native_roots {
            builder = builder.add_root_certificate(certificate);
        }
    }
    builder
}

fn validate_remote_ip(address: IpAddr) -> Result<()> {
    let allowed = match address {
        IpAddr::V4(address) => is_remote_ipv4(address),
        IpAddr::V6(address) => is_remote_ipv6(address),
    };
    ensure!(
        allowed,
        "remote endpoint resolves to a local or non-routable address"
    );
    Ok(())
}

fn is_remote_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !(address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_unspecified()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 198 && matches!(octets[1], 18 | 19))
        || octets[0] >= 224)
}

fn is_remote_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_remote_ipv4(mapped);
    }
    !(address.is_loopback()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || address.is_multicast()
        || address.is_unspecified())
}

fn validate_blob_redirect(origin: &Url, redirect: &Url) -> Result<()> {
    ensure!(
        redirect.username().is_empty() && redirect.password().is_none(),
        "blob redirect contains credentials"
    );
    ensure!(
        redirect.fragment().is_none(),
        "blob redirect contains a fragment"
    );
    if origin.scheme() == "https" {
        ensure!(
            redirect.scheme() == "https",
            "blob redirect would downgrade HTTPS"
        );
    } else {
        ensure!(
            same_authority(origin, redirect),
            "loopback HTTP registry cannot redirect blob requests cross-origin"
        );
    }
    validate_remote_endpoint(redirect, Some(origin))
}

fn validate_bearer_realm(origin: &Url, realm: &Url) -> Result<()> {
    if realm.scheme() == "http" {
        ensure!(
            origin.scheme() == "http" && is_loopback(origin) && same_authority(realm, origin),
            "plaintext Bearer realm must match the loopback registry origin"
        );
        return Ok(());
    }
    ensure!(
        realm.scheme() == "https",
        "Bearer realm must use HTTP or HTTPS"
    );
    validate_remote_endpoint(realm, Some(origin))
}

fn same_authority(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host() == right.host()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn parse_bearer_challenge(value: &str) -> Result<BTreeMap<String, String>> {
    let (scheme, parameters) = value
        .split_once(' ')
        .context("registry authentication challenge is malformed")?;
    ensure!(
        scheme.eq_ignore_ascii_case("Bearer"),
        "registry authentication challenge is not Bearer"
    );
    let mut result = BTreeMap::new();
    let mut cursor = parameters.trim();
    while !cursor.is_empty() {
        let equals = cursor
            .find('=')
            .context("malformed Bearer challenge parameter")?;
        let key = cursor[..equals].trim().to_ascii_lowercase();
        ensure!(
            !key.is_empty(),
            "Bearer challenge has an empty parameter name"
        );
        let rest = cursor[equals + 1..].trim_start();
        ensure!(
            rest.starts_with('"'),
            "Bearer challenge values must be quoted"
        );
        let (value, consumed) = parse_quoted(rest)?;
        ensure!(
            result.insert(key, value).is_none(),
            "Bearer challenge repeats a parameter"
        );
        cursor = rest[consumed..].trim_start();
        if cursor.is_empty() {
            break;
        }
        cursor = cursor
            .strip_prefix(',')
            .context("Bearer challenge parameters must be comma-separated")?
            .trim_start();
    }
    Ok(result)
}

fn parse_quoted(value: &str) -> Result<(String, usize)> {
    let mut output = String::new();
    let mut escaped = false;
    for (index, character) in value[1..].char_indices() {
        if escaped {
            ensure!(
                matches!(character, '"' | '\\'),
                "unsupported Bearer challenge escape"
            );
            output.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if character == '"' {
            return Ok((output, index + 2));
        } else {
            ensure!(
                !character.is_control(),
                "Bearer challenge contains a control character"
            );
            output.push(character);
        }
    }
    bail!("unterminated Bearer challenge value")
}

fn header(name: &'static str, value: &str) -> Result<(HeaderName, HeaderValue)> {
    Ok((
        HeaderName::from_static(name),
        HeaderValue::from_str(value).with_context(|| format!("invalid {name} header value"))?,
    ))
}

fn emit(events: &Option<UnboundedSender<TransferEvent>>, event: TransferEvent) {
    if let Some(events) = events {
        let _ = events.send(event);
    }
}

fn ensure_not_cancelled(cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        bail!("OCI transfer cancelled");
    }
    Ok(())
}

async fn read_bounded_body(
    response: Response,
    limit: usize,
    cancellation: &CancellationToken,
    label: &str,
) -> Result<Vec<u8>> {
    if let Some(length) = response.content_length() {
        ensure!(
            length <= u64::try_from(limit).context("response limit conversion")?,
            "{label} is oversized"
        );
    }
    let mut bytes =
        Vec::with_capacity(response.content_length().unwrap_or(0).min(limit as u64) as usize);
    let mut stream = response.bytes_stream();
    loop {
        let next = tokio::select! {
            () = cancellation.cancelled() => bail!("OCI transfer cancelled"),
            next = stream.next() => next,
        };
        let Some(chunk) = next else { break };
        let chunk = chunk.with_context(|| format!("reading {label}"))?;
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= limit,
            "{label} is oversized"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn repository_path(reference: &RegistryReference) -> String {
    reference.repository().to_string()
}

fn check_response(response: &Response, expected: &[StatusCode], operation: &str) -> Result<()> {
    ensure!(
        expected.contains(&response.status()),
        "{operation} failed with HTTP {}",
        response.status()
    );
    Ok(())
}

fn resolve_location(base: &Url, response: &Response) -> Result<Url> {
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .context("registry upload response lacks Location")?
        .to_str()
        .context("registry upload Location is not ASCII")?;
    base.join(location)
        .context("resolving registry upload Location")
}

fn build_headers(values: impl IntoIterator<Item = (HeaderName, HeaderValue)>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.extend(values);
    headers
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn challenge_parser_is_strict_and_order_independent() {
        let parsed = parse_bearer_challenge(
            r#"Bearer service="aos-hub",realm="https://registry.example/token",scope="repository:aos:pull""#,
        )
        .expect("challenge");
        assert_eq!(parsed.get("service").map(String::as_str), Some("aos-hub"));
        assert_eq!(
            parsed.get("scope").map(String::as_str),
            Some("repository:aos:pull")
        );
        assert!(parse_bearer_challenge("Basic abc").is_err());
        assert!(parse_bearer_challenge("Bearer realm=https://bad").is_err());
        assert!(parse_bearer_challenge("BEARER realm=\"https://registry.example/token\"").is_ok());
        assert!(challenge_scope_is_subset(
            "repository:aos:pull,push",
            "repository:aos:push,pull"
        ));
        assert!(challenge_scope_is_subset(
            "repository:aos:pull,push",
            "repository:aos:pull"
        ));
        assert!(!challenge_scope_is_subset(
            "repository:aos:pull,push",
            "repository:other:pull,push"
        ));
        assert!(!challenge_scope_is_subset(
            "repository:aos:pull,push",
            "repository:aos:pull,delete"
        ));
        assert!(!challenge_scope_is_subset(
            "repository:aos:pull,push",
            "repository:aos:"
        ));
        assert!(!challenge_scope_is_subset(
            "repository:aos:pull,push",
            "repository:AOS:pull"
        ));
    }

    #[test]
    fn origin_validation_allows_only_matching_loopback_http() {
        assert!(
            validate_origin(
                &Url::parse("http://127.0.0.1:5000/").expect("URL"),
                "127.0.0.1:5000"
            )
            .is_ok()
        );
        assert!(
            validate_origin(
                &Url::parse("http://registry.example/").expect("URL"),
                "registry.example"
            )
            .is_err()
        );
        assert!(
            validate_origin(
                &Url::parse("https://other.example/").expect("URL"),
                "registry.example"
            )
            .is_err()
        );
    }

    #[test]
    fn redirect_and_bearer_endpoints_reject_downgrade_and_loopback_ssrf() {
        let origin = Url::parse("https://registry.example/").expect("origin");
        assert!(
            validate_blob_redirect(
                &origin,
                &Url::parse("http://registry.example/blob").expect("downgrade")
            )
            .is_err()
        );
        assert!(
            validate_bearer_realm(
                &origin,
                &Url::parse("http://127.0.0.1/token").expect("loopback realm")
            )
            .is_err()
        );
        assert!(
            validate_bearer_realm(
                &Url::parse("http://127.0.0.1:5000/").expect("local origin"),
                &Url::parse("http://127.0.0.1:5001/token").expect("other local realm")
            )
            .is_err()
        );
    }
}
