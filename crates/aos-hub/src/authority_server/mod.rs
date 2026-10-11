//! Dedicated Native authority HTTP issuer over its private retained journal.
//!
//! This process has no Hub router, metadata SQL connection or provider dispatch.
//! Publisher control and executor renewal authenticate separately; usable tokens
//! follow both actual durable SQLite acknowledgments. No serving path initializes
//! missing state. Loopback qualification establishes no hosted deployment safety.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::storage_authority::lease::{
    control::{
        sign_issuer_reply_observed, verify_issuer_reply_at_time, verify_issuer_request,
        IssuerOperation, IssuerReply, IssuerRequest, ISSUER_CONTROL_PATH, MAX_ISSUER_CONTROL_BYTES,
    },
    EpochLeaseSigningKey, EpochLeaseVerifier,
};
use aos_hub_core::storage_work::{StorageWorkKey, STORAGE_WORK_SIGNATURE_HEADER};
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::authority_journal::{AuthorityJournal, IssuerLiveState, IssuerPublicationReceipt};
use clock::{ClockSource, NativeClock};

mod clock;
mod config;
pub(crate) mod observation;
pub mod recovery_operator;

#[cfg(test)]
mod tests;

pub use config::{AuthorityConfiguration, AuthorityTlsConfiguration};
pub use observation::LocalIssuerObservationConfiguration;

/// Header containing the independently domain-separated issuer authentication tag.
///
/// Its transport spelling matches the Worker backend; the dedicated shared
/// issuer request domain refuses ordinary StorageWork authentication.
pub const ISSUER_SIGNATURE_HEADER: &str = STORAGE_WORK_SIGNATURE_HEADER;

/// Opened private issuer service with real per-authority SQLite persistence.
#[derive(Clone)]
pub struct AuthorityServer {
    inner: Arc<Inner>,
}

struct Inner {
    journal: AuthorityJournal,
    installation: crate::authority_journal::IssuerInstallation,
    publisher_key: StorageWorkKey,
    renewal_key: StorageWorkKey,
    signer: EpochLeaseSigningKey,
    verifier: EpochLeaseVerifier,
    signing_key_id: String,
    issuance_enabled: bool,
    clock: Arc<dyn ClockSource>,
    gate: Mutex<()>,
    observation: Option<observation::Observation>,
    listen: std::net::SocketAddr,
    tls: Option<AuthorityTlsConfiguration>,
}

impl AuthorityServer {
    /// Opens an existing exact installation and explicitly configured credentials.
    ///
    /// Keys are read from private files; no key or state is created. The installed
    /// policy must exactly match configuration. Runtime identity and resource
    /// novelty still require independently qualified deployment ownership.
    ///
    /// # Errors
    /// Returns an error for missing/changed/corrupt state, insecure credentials,
    /// reused role material, mismatched policy or invalid clock/key configuration.
    pub fn open(configuration: &AuthorityConfiguration) -> Result<Self> {
        Self::open_with_clock_resolution(configuration, None)
    }

    /// Opens one explicitly nominated successor using a retained recovery receipt.
    ///
    /// The independent review and exact durable positive are verified before the
    /// one-use successor is consumed. A failed start never restores the old session.
    ///
    /// # Errors
    /// Returns an error for invalid configuration, active owners, changed or used
    /// receipts, credential reuse, clock failure or indeterminate session commit.
    pub fn open_with_clock_resolution(
        configuration: &AuthorityConfiguration,
        resolution: Option<&crate::authority_journal::recovery::ClockRecoveryReceipt>,
    ) -> Result<Self> {
        Self::open_observed(configuration, resolution, None)
    }

    /// Opens an exact issuer with explicit owner-private local observations.
    ///
    /// Ordinary policy, keys, journal claims and signing authority are unchanged.
    /// Measurements require an independent source/executable and runtime join;
    /// this recorder establishes no clock, fleet or provider qualification.
    ///
    /// # Errors
    /// Returns the existing opening errors and refuses invalid observation
    /// custody, a changed selected executable/configuration or an unavailable log.
    pub fn open_with_local_observation(
        configuration: &AuthorityConfiguration,
        resolution: Option<&crate::authority_journal::recovery::ClockRecoveryReceipt>,
        selected: &LocalIssuerObservationConfiguration,
    ) -> Result<Self> {
        Self::open_observed(configuration, resolution, Some(selected))
    }

    fn open_observed(
        configuration: &AuthorityConfiguration,
        resolution: Option<&crate::authority_journal::recovery::ClockRecoveryReceipt>,
        selected: Option<&LocalIssuerObservationConfiguration>,
    ) -> Result<Self> {
        configuration.validate()?;
        let observation = selected
            .map(|selected| observation::Observation::open(selected, configuration))
            .transpose()?;
        let journal = AuthorityJournal::open_existing(
            &configuration.journal_file,
            &configuration.boundary(),
            configuration.installation.clone(),
        )?
        .with_observation(observation.clone());
        let state = journal.load()?;
        journal.verify_recovery_policy(configuration.clock_recovery.as_ref())?;
        ensure!(
            state.journal.policy == configuration.policy,
            "configured issuer policy differs"
        );
        let publisher =
            crate::auth::seal::read_secret_file_zeroizing(&configuration.publisher_key_file)?;
        let renewal =
            crate::auth::seal::read_secret_file_zeroizing(&configuration.renewal_key_file)?;
        let seed = load_seed(&configuration.signing_seed_file)?;
        ensure!(
            !same_auth_material(&publisher, &renewal)
                && !reuses_seed(&publisher, &seed)
                && !reuses_seed(&renewal, &seed),
            "publisher, renewal and signing material must differ"
        );
        let publisher_key = StorageWorkKey::new(&*publisher)?;
        let renewal_key = StorageWorkKey::new(&*renewal)?;
        let signing_key_id = configuration.signing_key_id.clone();
        let signer = EpochLeaseSigningKey::from_bytes(signing_key_id.clone(), &seed)?;
        let public = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        if let Some(policy) = &configuration.clock_recovery {
            ensure!(
                policy.reviewer_public_key != hex::encode(public),
                "recovery reviewer must be independent from issuance"
            );
            for material in [&*publisher, &*renewal] {
                if let Some(seed) = normalized_seed_material(material) {
                    let role_public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
                    ensure!(
                        policy.reviewer_public_key != hex::encode(role_public.to_bytes()),
                        "recovery reviewer must be independent from publisher and renewal roles"
                    );
                }
            }
        }
        let verifier = EpochLeaseVerifier::from_bytes(signing_key_id.clone(), &public)?;
        let clock = NativeClock::new_with_resolution(
            journal.clone(),
            configuration.clock_uncertainty.get(),
            configuration.clock_commit_latency.get(),
            state.journal.clock_floor.get(),
            resolution,
        )?;
        clock.observe()?;
        Ok(Self {
            inner: Arc::new(Inner {
                journal,
                installation: configuration.installation.clone(),
                publisher_key,
                renewal_key,
                signer,
                verifier,
                signing_key_id,
                issuance_enabled: configuration.issuance_enabled,
                clock: Arc::new(clock),
                gate: Mutex::new(()),
                observation,
                listen: configuration.listen,
                tls: configuration.tls.clone(),
            }),
        })
    }

    /// Builds only the dedicated issuer endpoint and minimal process liveness.
    pub fn router(&self) -> Router {
        Router::new()
            .route(ISSUER_CONTROL_PATH, post(handle))
            .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
            .with_state(self.clone())
    }

    /// Binds the explicitly configured private listener and serves this installation.
    ///
    /// Non-loopback listeners require configured Native TLS and exact SNI.
    /// This establishes no hosted volume, ingress, clock or provider readiness.
    ///
    /// # Errors
    /// Returns an error for a changed installation/policy, unavailable listener,
    /// insecure TLS key, invalid certificate/key or server transport failure.
    pub async fn serve(&self) -> Result<()> {
        self.load().await?;
        if let Some(tls) = &self.inner.tls {
            // Reuse the existing secure private-file reader before the Native
            // listener consumes PEM material. No secret value is logged.
            let _private = crate::auth::seal::read_secret_file_zeroizing(&tls.private_key_file)?;
            let listener = tokio::net::TcpListener::bind(self.inner.listen)
                .await
                .context("binding private authority listener")?;
            let listener = crate::native_tls::NativeTlsListener::new(
                listener,
                &tls.certificate_file,
                &tls.private_key_file,
                tls.expected_server_name.clone(),
            )?;
            if self.inner.observation.is_some() {
                axum::serve(listener, self.router())
                    .with_graceful_shutdown(local_observation_shutdown())
                    .await?;
            } else {
                axum::serve(listener, self.router()).await?;
            }
        } else {
            let listener = tokio::net::TcpListener::bind(self.inner.listen)
                .await
                .context("binding private authority listener")?;
            if self.inner.observation.is_some() {
                axum::serve(listener, self.router())
                    .with_graceful_shutdown(local_observation_shutdown())
                    .await?;
            } else {
                axum::serve(listener, self.router()).await?;
            }
        }
        if let Some(observer) = &self.inner.observation {
            observer.finish()?;
        }
        Ok(())
    }

    async fn execute(&self, request: &IssuerRequest) -> Result<Vec<u8>> {
        self.execute_observed(request, None).await
    }

    async fn execute_observed(
        &self,
        request: &IssuerRequest,
        observer: Option<observation::Observation>,
    ) -> Result<Vec<u8>> {
        let mut outcome = observation::RequestOutcome::new(observer.clone());
        let result = self.execute_body(request, observer).await;
        outcome.completed(result.is_ok());
        result
    }

    async fn execute_body(
        &self,
        request: &IssuerRequest,
        observer: Option<observation::Observation>,
    ) -> Result<Vec<u8>> {
        let queue_started = observer.as_ref().map(|_| std::time::Instant::now());
        let _gate = self.inner.gate.lock().await;
        if let (Some(observer), Some(queue_started)) = (&observer, queue_started) {
            observer.record(
                "gate_acquired",
                serde_json::json!({ "queueWaitNs": observation::elapsed_ns(queue_started) }),
            );
        }
        let clock = self.inner.clock.observe()?;
        request.validate(&self.inner.installation, clock.observed_at)?;
        let current = self.load_observed(observer.clone()).await?;
        let mut applied = None;
        let mut lease = None;
        match &request.operation {
            IssuerOperation::Current => {}
            IssuerOperation::Install(_)
            | IssuerOperation::Publish(_)
            | IssuerOperation::Deny(_) => {
                let journal = self.inner.journal.with_observation(observer.clone());
                let operation = request.operation.clone();
                applied =
                    tokio::task::spawn_blocking(move || journal.receipt_for_operation(operation))
                        .await??;
                if applied.is_none() {
                    applied = Some(
                        self.apply_control(&current, request, clock, observer.clone())
                            .await?,
                    );
                }
            }
            IssuerOperation::Issue {
                cohort,
                requested_not_after,
            } => {
                ensure!(
                    self.inner.issuance_enabled,
                    "authority issuance is disabled"
                );
                let prepared = current.journal.prepare_issue(
                    &current.publication,
                    cohort.clone(),
                    &self.inner.signing_key_id,
                    requested_not_after.get(),
                    clock,
                )?;
                let journal = self.inner.journal.with_observation(observer.clone());
                let mut signature = observer
                    .as_ref()
                    .map(|observer| observer.signature_observer());
                let bytes = prepared
                    .commit_and_sign_observed(
                        &self.inner.signer,
                        move |transition| {
                            let journal = journal.clone();
                            async move { journal.commit_lease(transition).await }
                        },
                        || self.inner.clock.observe(),
                        |event| {
                            if let Some(signature) = &mut signature {
                                signature(event);
                            }
                        },
                    )
                    .await?;
                lease = Some(String::from_utf8(bytes)?);
            }
        }
        let head = self.load_observed(observer.clone()).await?.head()?;
        let reply = IssuerReply {
            protocol_version: 1,
            issuer_key_id: self.inner.signing_key_id.clone(),
            installation: head.installation.clone(),
            nonce: request.nonce.clone(),
            request_digest: request.digest()?,
            current: head,
            applied,
            lease,
        };
        let mut signature = observer
            .as_ref()
            .map(|observer| observer.signature_observer());
        let bytes = sign_issuer_reply_observed(&self.inner.signer, request, reply, |event| {
            if let Some(signature) = &mut signature {
                signature(event);
            }
        })?;
        // A different process can win a durable CAS despite this local gate.
        // Refuse a head/token mismatch before any signed bytes leave the server.
        verify_issuer_reply_at_time(&self.inner.verifier, request, &bytes, || {
            self.inner.clock.observe()
        })?;
        Ok(bytes)
    }

    async fn load(&self) -> Result<IssuerLiveState> {
        self.load_observed(self.inner.observation.clone()).await
    }

    async fn load_observed(
        &self,
        observer: Option<observation::Observation>,
    ) -> Result<IssuerLiveState> {
        let journal = self.inner.journal.with_observation(observer);
        tokio::task::spawn_blocking(move || journal.load()).await?
    }

    async fn apply_control(
        &self,
        current: &IssuerLiveState,
        request: &IssuerRequest,
        clock: aos_hub_core::storage_authority::lease::LeaseClock,
        observer: Option<observation::Observation>,
    ) -> Result<IssuerPublicationReceipt> {
        match &request.operation {
            IssuerOperation::Install(_) => {
                anyhow::bail!("serving never initializes an installation")
            }
            IssuerOperation::Publish(publication) => {
                let transition = current.journal.prepare_publication(publication, clock)?;
                self.inner
                    .journal
                    .with_observation(observer)
                    .commit_publication(transition, publication.clone(), clock)
                    .await
            }
            IssuerOperation::Deny(denial) => {
                let transition = current.journal.prepare_denied_gap(denial, clock)?;
                self.inner
                    .journal
                    .with_observation(observer)
                    .commit_denial(transition, denial.clone(), clock)
                    .await
            }
            IssuerOperation::Current | IssuerOperation::Issue { .. } => {
                anyhow::bail!("not a control operation")
            }
        }
    }
}

fn load_seed(path: &std::path::Path) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = crate::auth::seal::read_secret_file_zeroizing(path)?;
    let decoded = Zeroizing::new(crate::auth::seal::parse_key(&bytes)?);
    let seed: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("issuer seed must contain exactly 32 bytes"))?;
    Ok(Zeroizing::new(seed))
}

#[derive(Clone, Copy)]
enum Role {
    Publisher,
    Renewal,
}

fn same_auth_material(left: &[u8], right: &[u8]) -> bool {
    if left == right {
        return true;
    }
    match (
        normalized_seed_material(left),
        normalized_seed_material(right),
    ) {
        (Some(left), Some(right)) => *left == *right,
        _ => false,
    }
}

fn reuses_seed(bytes: &[u8], seed: &[u8; 32]) -> bool {
    normalized_seed_material(bytes).is_some_and(|material| *material == *seed)
}

fn normalized_seed_material(bytes: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    if bytes.len() == 32 {
        return bytes.try_into().ok().map(Zeroizing::new);
    }
    // Only fixed-size known representations are decoded. Configuration values
    // outside this small bound cannot allocate an unbounded scratch buffer.
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.len() > 128 {
        return None;
    }
    if let Ok(decoded) = hex::decode(text) {
        let decoded = Zeroizing::new(decoded);
        if let Ok(material) = decoded.as_slice().try_into() {
            return Some(Zeroizing::new(material));
        }
    }
    use base64::Engine as _;
    for engine in [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ] {
        if let Ok(decoded) = engine.decode(text) {
            let decoded = Zeroizing::new(decoded);
            if let Ok(material) = decoded.as_slice().try_into() {
                return Some(Zeroizing::new(material));
            }
        }
    }
    None
}

async fn handle(State(server): State<AuthorityServer>, request: Request) -> Response {
    match handle_inner(server, request).await {
        Ok(bytes) => (
            [
                ("content-type", "application/json"),
                ("cache-control", "no-store"),
            ],
            bytes,
        )
            .into_response(),
        Err(status) => (
            status,
            [("cache-control", "no-store")],
            "issuer request refused",
        )
            .into_response(),
    }
}

async fn handle_inner(
    server: AuthorityServer,
    request: Request,
) -> std::result::Result<Vec<u8>, StatusCode> {
    let (parts, body) = request.into_parts();
    let signatures: Vec<_> = parts
        .headers
        .get_all(ISSUER_SIGNATURE_HEADER)
        .iter()
        .collect();
    if signatures.len() != 1 {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let signature = signatures[0]
        .to_str()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let bytes = tokio::time::timeout(
        Duration::from_secs(30),
        to_bytes(body, MAX_ISSUER_CONTROL_BYTES),
    )
    .await
    .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
    .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    let publisher = verify_issuer_request(&server.inner.publisher_key, signature, &bytes).is_ok();
    let renewal = verify_issuer_request(&server.inner.renewal_key, signature, &bytes).is_ok();
    if !publisher && !renewal {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let role = if publisher {
        Role::Publisher
    } else {
        Role::Renewal
    };
    let request = IssuerRequest::decode(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    let permitted = match (&role, &request.operation) {
        (_, IssuerOperation::Current) | (Role::Renewal, IssuerOperation::Issue { .. }) => true,
        (
            Role::Publisher,
            IssuerOperation::Install(_) | IssuerOperation::Publish(_) | IssuerOperation::Deny(_),
        ) => true,
        _ => false,
    };
    if !permitted {
        return Err(StatusCode::FORBIDDEN);
    }
    let observer = server.inner.observation.as_ref().and_then(|observer| {
        match observer.for_request(&request, &bytes) {
            Ok(context) => Some(context),
            Err(_) => {
                // Measurement failure invalidates the recorder; the existing
                // authority execution still determines the request result.
                observer.invalidate();
                None
            }
        }
    });
    let result = match observer {
        Some(observer) => server.execute_observed(&request, Some(observer)).await,
        None => server.execute(&request).await,
    };
    result.map_err(|_| StatusCode::CONFLICT)
}

async fn local_observation_shutdown() {
    // Only the explicit local recorder selects this orderly shutdown path. A
    // failed signal subscription makes its terminal sample unavailable.
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}
