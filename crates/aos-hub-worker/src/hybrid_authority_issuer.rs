//! Dedicated live issuer role and per-authority persistent lease admission.
//!
//! This role has no provider or Hub SQL bindings. Its private publication key is
//! distinct from renewal authentication and its Ed25519 seed never enters an
//! ordinary executor Env. Explicit timing acceptance is required before any
//! route is enabled; local Date.now behavior is not hosted qualification.

use std::{cell::Cell, sync::Arc, time::Duration};

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::storage_authority::lease::{
    control::*, BoundedLeaseRevocationPolicy, EpochLeaseIssuerJournal, EpochLeaseSigningKey,
    IssuerTransition, LeaseClock, LeaseInteger, LeaseTimingProfile,
};
use aos_hub_core::storage_work::{StorageWorkKey, STORAGE_WORK_SIGNATURE_HEADER};
use futures_util::lock::Mutex;
use worker::{
    durable_object, DurableObject, Env, Headers, Method, Request, RequestInit, Response, State,
    Storage,
};

use crate::hybrid_authority_issuer_deadline::validate_request_deadline;

const HEAD: &str = "live-issuer-v1";
const ACTIVATED: &str = "issuer-activated-v1";
const BINDING: &str = "HYBRID_AUTHORITY_ISSUERS";
const SEED: &str = "HUB_AUTHORITY_ISSUER_SEED";
const PUBLISHER_KEY: &str = "HUB_AUTHORITY_PUBLISHER_KEY";
const RENEWAL_KEY: &str = "HUB_AUTHORITY_RENEWAL_KEY";

/// Owns a permanent authority's publication, issuance and denial serialization.
#[durable_object]
pub struct HybridAuthorityIssuer {
    state: State,
    env: Env,
    gate: Arc<Mutex<()>>,
    last_clock: Cell<i64>,
}

impl DurableObject for HybridAuthorityIssuer {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            gate: Arc::new(Mutex::new(())),
            last_clock: Cell::new(0),
        }
    }

    async fn fetch(&self, request: Request) -> worker::Result<Response> {
        match self.execute(request).await {
            Ok(response) => Ok(response),
            Err(_) => Response::error("live issuer requires reconciliation", 409),
        }
    }
}

impl HybridAuthorityIssuer {
    async fn execute(&self, mut request: Request) -> Result<Response> {
        ensure!(
            request.method() == Method::Post && request.url()?.path() == "/issuer",
            "unsupported issuer route"
        );
        let config = IssuerConfiguration::load(&self.env)?;
        let (control, body, signature) = authenticated_request(&mut request, &self.env).await?;
        config.validate_installation(&control.installation)?;
        let binding = self.env.durable_object(BINDING)?;
        let expected_id = binding.id_from_name(&issuer_name(&control.installation))?;
        ensure!(
            expected_id.to_string() == self.state.id().to_string(),
            "issuer object address differs"
        );
        let _permit = loop {
            if let Some(permit) = Arc::clone(&self.gate).try_lock_owned() {
                break permit;
            }
            worker::Delay::from(Duration::from_millis(10)).await;
        };
        let clock = QualifiedClock::new(config.uncertainty, &self.last_clock);
        validate_request_deadline(&control, clock.observe()?)?;
        let storage = self.state.storage();
        let current = load(&storage).await?;
        let activation = load_activation(&storage).await?;
        if let Some(activation) = &activation {
            validate_activation(&storage, &control.installation, activation).await?;
            ensure!(current.is_some(), "activated issuer lost retained head");
        }
        if current.is_none() || activation.is_none() {
            ensure!(
                matches!(control.operation, IssuerOperation::Install(_)),
                "initial installation/activation remains pending"
            );
        }
        if let Some(current) = &current {
            current.validate()?;
            ensure!(
                current.installation == control.installation
                    && current.journal.policy == config.policy,
                "issuer installation or reviewed policy changed"
            );
        }
        let operation_digest = operation_digest(&control.operation)?;
        let mut applied = None;
        let mut lease = None;
        match &control.operation {
            IssuerOperation::Current => {
                ensure!(
                    current.is_some() && activation.is_some(),
                    "issuer is not activated"
                );
            }
            IssuerOperation::Issue {
                cohort,
                requested_not_after,
            } => {
                ensure!(activation.is_some(), "issuer activation is pending");
                let current = current
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("issuer is not installed"))?;
                let prepared = current.journal.prepare_issue(
                    &current.publication,
                    cohort.clone(),
                    &config.key_id,
                    requested_not_after.get(),
                    clock.observe()?,
                )?;
                let signer = signer(&self.env, &config.key_id)?;
                let snapshot = current.clone();
                let bytes = prepared
                    .commit_and_sign(
                        &signer,
                        |transition| {
                            let storage = self.state.storage();
                            let snapshot = snapshot.clone();
                            async move { persist_lease(&storage, &snapshot, transition).await }
                        },
                        || clock.observe(),
                    )
                    .await?;
                lease = Some(String::from_utf8(bytes)?);
            }
            IssuerOperation::Install(publication) | IssuerOperation::Publish(publication) => {
                let reserved = reserve(&self.env, &body, &signature, false).await?;
                ensure!(
                    current.is_some() || reserved.activation.is_none(),
                    "activated issuer requires retained journal"
                );
                if activation.is_none() {
                    let initial = IssuerPublicationReceipt::from_publication(publication)?;
                    ensure!(
                        publication.generation == 1 && reserved.current_receipt == initial,
                        "pending installation is behind registry head"
                    );
                    if let Some(current) = &current {
                        ensure!(
                            IssuerPublicationReceipt::from_publication(&current.publication)?
                                == initial,
                            "pending local head differs from registry installation"
                        );
                    }
                }
                applied = Some(IssuerPublicationReceipt::from_publication(publication)?);
                let receipt = applied
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("missing issuer receipt"))?;
                if !receipt_exists(&storage, receipt, &operation_digest).await? {
                    let journal = match &current {
                        Some(current) => {
                            current
                                .journal
                                .prepare_publication(publication, clock.observe()?)?
                                .next
                        }
                        None => {
                            ensure!(
                                matches!(control.operation, IssuerOperation::Install(_)),
                                "missing retained issuer journal"
                            );
                            EpochLeaseIssuerJournal::initialize_fresh_namespace(
                                publication,
                                &config.executor,
                                config.policy.clone(),
                                clock.observe()?,
                            )?
                        }
                    };
                    let next = IssuerLiveState {
                        installation: control.installation.clone(),
                        publication: publication.clone(),
                        journal,
                    };
                    persist_publication(
                        &storage,
                        current.clone(),
                        next,
                        receipt.clone(),
                        operation_digest.clone(),
                    )
                    .await?;
                } else {
                    ensure!(current.is_some(), "receipt without issuer head");
                }
                if matches!(control.operation, IssuerOperation::Install(_)) && activation.is_none()
                {
                    let activated = reserve(&self.env, &body, &signature, true)
                        .await?
                        .activation
                        .ok_or_else(|| anyhow::anyhow!("activation remains pending"))?;
                    validate_activation(&storage, &control.installation, &activated).await?;
                    persist_activation(&storage, &activated).await?;
                }
            }
            IssuerOperation::Deny(transition) => {
                reserve(&self.env, &body, &signature, false).await?;
                let current = current
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("denial requires retained issuer journal"))?;
                let receipt = IssuerPublicationReceipt::from_publication(&transition.publication)?;
                if !receipt_exists(&storage, &receipt, &operation_digest).await? {
                    let next_journal = current
                        .journal
                        .prepare_denied_gap(transition, clock.observe()?)?
                        .next;
                    let next = IssuerLiveState {
                        installation: current.installation.clone(),
                        publication: transition.publication.clone(),
                        journal: next_journal,
                    };
                    persist_publication(
                        &storage,
                        Some(current.clone()),
                        next,
                        receipt.clone(),
                        operation_digest.clone(),
                    )
                    .await?;
                }
                applied = Some(receipt);
            }
        }
        let current = load(&storage)
            .await?
            .ok_or_else(|| anyhow::anyhow!("issuer is not installed"))?;
        // The response reload is actual storage I/O. Recheck the deadline and
        // final token time after it; expiry never erases the committed issuance.
        let observed = clock.observe()?;
        validate_request_deadline(&control, observed)?;
        let mut lease_expiry = None;
        if let Some(bytes) = &lease {
            let envelope: serde_json::Value = serde_json::from_str(bytes)?;
            let expiry: LeaseInteger =
                serde_json::from_value(envelope["payload"]["not_after"].clone())?;
            lease_expiry = Some(expiry.get());
            ensure!(
                observed
                    .observed_at
                    .checked_add(observed.uncertainty)
                    .is_some_and(|latest| latest < expiry.get()),
                "lease expired before response"
            );
        }
        let signer = signer(&self.env, &config.key_id)?;
        let reply = IssuerReply {
            protocol_version: 1,
            issuer_key_id: config.key_id,
            installation: control.installation.clone(),
            nonce: control.nonce.clone(),
            request_digest: control.digest()?,
            current: current.head()?,
            applied,
            lease,
        };
        let bytes = sign_issuer_reply(&signer, &control, reply)?;
        let final_observation = clock.observe()?;
        validate_request_deadline(&control, final_observation)?;
        // No application await follows this observation. Its hosted clock and
        // continuation bound remains part of explicit operator qualification.
        if let Some(expiry) = lease_expiry {
            ensure!(
                final_observation
                    .observed_at
                    .checked_add(final_observation.uncertainty)
                    .is_some_and(|latest| latest < expiry),
                "lease expired while signing response"
            );
        }
        let headers = Headers::new();
        headers.set("content-type", "application/json")?;
        headers.set("cache-control", "private, no-store")?;
        Ok(Response::from_bytes(bytes)?.with_headers(headers))
    }
}

async fn load(storage: &Storage) -> Result<Option<IssuerLiveState>> {
    crate::authority_issuer_storage::read(storage, HEAD)
        .await?
        .map(|raw| serde_json::from_str(&raw).map_err(Into::into))
        .transpose()
}

async fn load_transaction(transaction: &worker::Transaction) -> Result<Option<IssuerLiveState>> {
    crate::authority_issuer_storage::read_transaction(transaction, HEAD)
        .await?
        .map(|raw| serde_json::from_str(&raw).map_err(Into::into))
        .transpose()
}

async fn write_state(
    transaction: &worker::Transaction,
    state: &IssuerLiveState,
) -> worker::Result<()> {
    state.validate().map_err(error)?;
    crate::authority_issuer_storage::write(
        transaction,
        HEAD,
        &serde_json::to_string(state).map_err(error)?,
    )
    .await
}

/// Commits an exact closed semantic operation, excluding fresh nonce/time.
///
/// Installation is separately pinned exactly by the permanent addressed record.
///
/// # Errors
/// Returns an error if canonical serialization fails.
pub(crate) fn operation_digest(operation: &IssuerOperation) -> Result<String> {
    use sha2::{Digest as _, Sha256};
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(operation)?)))
}

async fn receipt_exists(
    storage: &Storage,
    receipt: &IssuerPublicationReceipt,
    expected_operation: &str,
) -> Result<bool> {
    let stored = storage.get::<String>(&receipt_key(receipt)).await?;
    if let Some(stored) = stored {
        ensure!(
            serde_json::from_str::<IssuerPublicationReceipt>(&stored)? == *receipt,
            "issuer generation fork"
        );
        ensure!(
            storage
                .get::<String>(&format!("operation/{}", receipt.generation.get()))
                .await?
                .as_deref()
                == Some(expected_operation),
            "issuer operation replay changed"
        );
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn persist_lease(
    storage: &Storage,
    snapshot: &IssuerLiveState,
    transition: IssuerTransition,
) -> Result<()> {
    let installation = snapshot.installation.clone();
    let publication = snapshot.publication.clone();
    storage
        .transaction(move |transaction| {
            let installation = installation.clone();
            let publication = publication.clone();
            let transition = transition.clone();
            async move {
                let mut current = load_transaction(&transaction)
                    .await
                    .map_err(error)?
                    .ok_or_else(|| error("retained issuer is missing"))?;
                current.validate().map_err(error)?;
                if current.installation != installation
                    || current.publication != publication
                    || current.journal != transition.expected
                {
                    return Err(error("live issuer CAS refused"));
                }
                current.journal = transition.next;
                current.validate().map_err(error)?;
                write_state(&transaction, &current).await?;
                Ok(())
            }
        })
        .await
        .context("durable issuer lease CAS")
}

async fn persist_publication(
    storage: &Storage,
    expected: Option<IssuerLiveState>,
    next: IssuerLiveState,
    receipt: IssuerPublicationReceipt,
    operation_digest: String,
) -> Result<()> {
    next.validate()?;
    receipt.validate(&next.publication)?;
    storage
        .transaction(move |transaction| {
            let expected = expected.clone();
            let next = next.clone();
            let receipt = receipt.clone();
            let operation_digest = operation_digest.clone();
            async move {
                let actual = load_transaction(&transaction).await.map_err(error)?;
                if actual != expected {
                    return Err(error("live publication CAS refused"));
                }
                let key = receipt_key(&receipt);
                if crate::authority_issuer_storage::read_optional_transaction(&transaction, &key)
                    .await?
                    .is_some()
                {
                    return Err(error("issuer receipt already exists"));
                }
                transaction
                    .put(&key, serde_json::to_string(&receipt).map_err(error)?)
                    .await?;
                transaction
                    .put(
                        &format!("operation/{}", receipt.generation.get()),
                        operation_digest,
                    )
                    .await?;
                write_state(&transaction, &next).await?;
                Ok(())
            }
        })
        .await
        .context("durable issuer publication and receipt CAS")
}

fn receipt_key(receipt: &IssuerPublicationReceipt) -> String {
    format!("receipt/{}", receipt.generation.get())
}
fn issuer_name(installation: &IssuerInstallation) -> String {
    format!(
        "authority-issuer-v1/{}",
        installation.authority.authority_id.as_str()
    )
}

/// Explicit protected configuration; loading does not qualify hosted clocks.
pub(crate) struct IssuerConfiguration {
    resource: String,
    runtime: String,
    namespace: String,
    /// Immutable independently reviewed executor identity.
    pub(crate) executor: String,
    key_id: String,
    uncertainty: i64,
    policy: BoundedLeaseRevocationPolicy,
}

impl IssuerConfiguration {
    /// Checks explicit timing acceptance, binding pins and protected key material.
    ///
    /// Known-name checks do not prove an arbitrary deployment has no additional
    /// provider/SQL capabilities; the dedicated binding graph requires review.
    ///
    /// # Errors
    /// Returns an error for absent acceptance/config, changed actual namespaces,
    /// obvious key reuse or malformed signer/authentication inputs.
    pub(crate) fn load(env: &Env) -> Result<Self> {
        ensure!(
            env.var("HUB_RUNTIME_ROLE")?.to_string() == "authority_issuer",
            "issuer role required"
        );
        ensure!(
            env.var("HUB_AUTHORITY_CLOCK_ACCEPTANCE")?.to_string() == "operator_qualified",
            "live issuance timing is disabled"
        );
        // Explicit input is an operator acceptance, not proof established by this
        // adapter. Hosted paused clocks/continuations require actual qualification.
        let registry = env.durable_object("HYBRID_AUTHORITY_STATE")?;
        ensure!(
            registry
                .id_from_name("physical-authority-ledger-v1")?
                .to_string()
                == env.var("HUB_AUTHORITY_REGISTRY_OBJECT_ID")?.to_string(),
            "permanent registry binding changed"
        );
        let issuers = env.durable_object(BINDING)?;
        ensure!(
            issuers
                .id_from_name("issuer-namespace-probe-v1")?
                .to_string()
                == env
                    .var("HUB_AUTHORITY_ISSUER_NAMESPACE_PROBE_ID")?
                    .to_string(),
            "permanent issuer namespace binding changed"
        );
        let profile: LeaseTimingProfile =
            serde_json::from_str(&env.var("HUB_AUTHORITY_TIMING_PROFILE")?.to_string())?;
        profile.validate()?;
        let uncertainty = env
            .var("HUB_AUTHORITY_CLOCK_UNCERTAINTY_SECS")?
            .to_string()
            .parse::<i64>()?;
        ensure!(
            uncertainty > 0 && uncertainty <= profile.maximum_clock_uncertainty.get(),
            "clock uncertainty is not explicitly qualified"
        );
        for binding in ["REGISTRY_BUCKET", "HUB_DB", "HUB_STORAGE_WORK_KEY"] {
            ensure!(
                env.bucket(binding).is_err()
                    && env.durable_object(binding).is_err()
                    && env.secret(binding).is_err(),
                "issuer contains executor capability"
            );
        }
        let key_id = env.var("HUB_AUTHORITY_ISSUER_KEY_ID")?.to_string();
        let _validated_signer = signer(env, &key_id)?;
        let runtime = env.var("HUB_AUTHORITY_ISSUER_RUNTIME_ID")?.to_string();
        ensure!(
            !runtime.is_empty() && runtime.len() <= 128,
            "issuer runtime exceeds registry control bound"
        );
        Ok(Self {
            resource: env.var("HUB_AUTHORITY_ISSUER_RESOURCE_ID")?.to_string(),
            runtime,
            namespace: env.var("HUB_EXTERNAL_GUARD_NAMESPACE_ID")?.to_string(),
            executor: env.var("HUB_EXTERNAL_STORAGE_EXECUTOR_ID")?.to_string(),
            key_id,
            uncertainty,
            policy: BoundedLeaseRevocationPolicy {
                timing_profile: profile,
            },
        })
    }

    /// Compares the complete installation against the configured live domain.
    ///
    /// # Errors
    /// Returns an error for malformed or changed resource/runtime/authority facts.
    pub(crate) fn validate_installation(&self, installation: &IssuerInstallation) -> Result<()> {
        installation.validate()?;
        ensure!(
            installation.issuer_resource_id == self.resource
                && installation.runtime_identity == self.runtime
                && installation.authority.guard_namespace_id == self.namespace
                && installation.executor_identity == self.executor,
            "issuer installation domain differs"
        );
        Ok(())
    }
}

struct QualifiedClock<'a> {
    uncertainty: i64,
    last: &'a Cell<i64>,
}
impl<'a> QualifiedClock<'a> {
    fn new(uncertainty: i64, last: &'a Cell<i64>) -> Self {
        Self { uncertainty, last }
    }
    fn observe(&self) -> Result<LeaseClock> {
        let now = worker::js_sys::Date::now();
        ensure!(
            now.is_finite() && now >= 0.0 && now / 1000.0 < i64::MAX as f64,
            "invalid issuer clock"
        );
        let observed_at = (now / 1000.0).floor() as i64;
        ensure!(observed_at >= self.last.get(), "issuer clock rolled back");
        self.last.set(observed_at);
        Ok(LeaseClock {
            observed_at,
            uncertainty: self.uncertainty,
        })
    }
}

fn auth_reuses_seed(value: &str, seed: &[u8; 32]) -> bool {
    use base64::Engine as _;
    if value.as_bytes() == seed || hex::decode(value).is_ok_and(|bytes| bytes.as_slice() == seed) {
        return true;
    }
    [
        base64::engine::general_purpose::STANDARD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ]
    .iter()
    .any(|engine| {
        engine
            .decode(value)
            .is_ok_and(|bytes| bytes.as_slice() == seed)
    })
}

fn signer(env: &Env, key_id: &str) -> Result<EpochLeaseSigningKey> {
    let seed = env.secret(SEED)?.to_string();
    let bytes: [u8; 32] = hex::decode(&seed)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("issuer seed format differs"))?;
    let publisher = env.secret(PUBLISHER_KEY)?.to_string();
    let renewal = env.secret(RENEWAL_KEY)?.to_string();
    ensure!(
        publisher != renewal
            && seed != publisher
            && seed != renewal
            && !auth_reuses_seed(&publisher, &bytes)
            && !auth_reuses_seed(&renewal, &bytes),
        "issuer signing and shared authentication material must differ"
    );
    StorageWorkKey::new(&publisher)?;
    StorageWorkKey::new(&renewal)?;
    EpochLeaseSigningKey::from_bytes(key_id.to_owned(), &bytes)
}

/// Authenticates bounded raw bytes before parsing or durable storage effects.
///
/// # Errors
/// Returns an error for absent/wrong signatures, malformed bounded canonical wire
/// or an authentication role that cannot perform the selected operation.
pub(crate) async fn authenticated_request(
    request: &mut Request,
    env: &Env,
) -> Result<(IssuerRequest, Vec<u8>, String)> {
    let signature = request
        .headers()
        .get(STORAGE_WORK_SIGNATURE_HEADER)?
        .ok_or_else(|| anyhow::anyhow!("issuer request signature required"))?;
    let body = crate::hybrid::read_bounded_body(request, MAX_ISSUER_CONTROL_BYTES)
        .await?
        .ok_or_else(|| anyhow::anyhow!("issuer request too large"))?;
    let publisher = env.secret(PUBLISHER_KEY)?.to_string();
    let renewal = env.secret(RENEWAL_KEY)?.to_string();
    ensure!(
        publisher != renewal,
        "publisher and renewal keys must differ"
    );
    let publisher = StorageWorkKey::new(publisher)?;
    let renewal = StorageWorkKey::new(renewal)?;
    let is_publisher = verify_issuer_request(&publisher, &signature, &body).is_ok();
    let is_renewal = verify_issuer_request(&renewal, &signature, &body).is_ok();
    ensure!(is_publisher || is_renewal, "issuer authentication refused");
    let control = IssuerRequest::decode(&body)?;
    let publication = matches!(
        control.operation,
        IssuerOperation::Install(_) | IssuerOperation::Publish(_) | IssuerOperation::Deny(_)
    );
    ensure!(
        !publication || is_publisher,
        "renewal authentication cannot publish control"
    );
    ensure!(
        !matches!(control.operation, IssuerOperation::Issue { .. }) || is_renewal,
        "issuance requires renewal authentication"
    );
    Ok((control, body, signature))
}

/// Dispatches only bounded issuer routes in the dedicated script role.
///
/// # Errors
/// Returns an error for unavailable bindings; invalid/disabled config rejects
/// without reserving an issuer or exposing a signing key.
pub(crate) async fn fetch(mut request: Request, env: &Env) -> worker::Result<Response> {
    if request.method() != Method::Post || request.url()?.path() != ISSUER_CONTROL_PATH {
        return Response::error("not found", 404);
    }
    let config = match IssuerConfiguration::load(env) {
        Ok(config) => config,
        Err(_) => return Response::error("live issuer is disabled", 503),
    };
    let (control, body, signature) = match authenticated_request(&mut request, env).await {
        Ok(value) => value,
        Err(_) => return Response::error("issuer authentication refused", 401),
    };
    if config.validate_installation(&control.installation).is_err() {
        return Response::error("issuer domain differs", 400);
    }
    let binding = env.durable_object(BINDING)?;
    let id = binding.id_from_name(&issuer_name(&control.installation))?;
    id.get_stub()?
        .fetch_with_request(forwarded("https://authority/issuer", body, signature)?)
        .await
}

/// Forwards opaque control bytes; an ordinary executor has no publication key.
///
/// # Errors
/// Returns an error for unavailable service bindings or body/transport failure.
pub(crate) async fn forward(mut request: Request, env: &Env) -> worker::Result<Response> {
    for key in [SEED, PUBLISHER_KEY] {
        if env.secret(key).is_ok() {
            return Response::error("executor has issuer capability", 503);
        }
    }
    if request.method() != Method::Post {
        return Response::error("method not allowed", 405);
    }
    let Some(signature) = request.headers().get(STORAGE_WORK_SIGNATURE_HEADER)? else {
        return Response::error("issuer signature required", 401);
    };
    let Some(body) =
        crate::hybrid::read_bounded_body(&mut request, MAX_ISSUER_CONTROL_BYTES).await?
    else {
        return Response::error("issuer body too large", 413);
    };
    env.service("HUB_AUTHORITY_ISSUER")?
        .fetch_request(forwarded(
            &format!("https://authority{ISSUER_CONTROL_PATH}"),
            body,
            signature,
        )?)
        .await
}

/// Irreversible global activation; it never expires or settles provider I/O.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActivatedIssuerReceipt {
    /// Complete permanent issuer attachment.
    pub(crate) installation: IssuerInstallation,
    /// Exact first publication commitment.
    pub(crate) initial_receipt: IssuerPublicationReceipt,
    /// Exact initial install semantic fingerprint.
    pub(crate) initial_operation_digest: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
/// Private registry acknowledgment; reservation alone is not activation.
pub(crate) struct IssuerReservationReply {
    /// Exact latest durable registry head, separate from historical replay.
    pub(crate) current_receipt: IssuerPublicationReceipt,
    /// Irreversible global activation, absent during the initial gap.
    pub(crate) activation: Option<ActivatedIssuerReceipt>,
}

async fn load_activation(storage: &Storage) -> Result<Option<ActivatedIssuerReceipt>> {
    storage
        .get::<String>(ACTIVATED)
        .await?
        .map(|raw| serde_json::from_str(&raw).map_err(Into::into))
        .transpose()
}

async fn validate_activation(
    storage: &Storage,
    installation: &IssuerInstallation,
    activation: &ActivatedIssuerReceipt,
) -> Result<()> {
    ensure!(
        &activation.installation == installation
            && activation.initial_receipt.generation.get() == 1,
        "activation attachment differs"
    );
    ensure!(
        receipt_exists(
            storage,
            &activation.initial_receipt,
            &activation.initial_operation_digest
        )
        .await?,
        "activation requires retained initial receipt"
    );
    Ok(())
}

async fn persist_activation(storage: &Storage, activation: &ActivatedIssuerReceipt) -> Result<()> {
    let activation = activation.clone();
    storage
        .transaction(move |transaction| {
            let activation = activation.clone();
            async move {
                let current = load_transaction(&transaction)
                    .await
                    .map_err(error)?
                    .ok_or_else(|| error("issuer head missing during activation"))?;
                if current.installation != activation.installation
                    || IssuerPublicationReceipt::from_publication(&current.publication)
                        .map_err(error)?
                        != activation.initial_receipt
                {
                    return Err(error("activation installation/head differs"));
                }
                let prior = crate::authority_issuer_storage::read_optional_transaction(
                    &transaction,
                    ACTIVATED,
                )
                .await?;
                if let Some(prior) = prior {
                    if serde_json::from_str::<ActivatedIssuerReceipt>(&prior).map_err(error)?
                        != activation
                    {
                        return Err(error("local activation changed"));
                    }
                } else {
                    transaction
                        .put(
                            ACTIVATED,
                            serde_json::to_string(&activation).map_err(error)?,
                        )
                        .await?;
                }
                Ok(())
            }
        })
        .await
        .context("persisting globally acknowledged local activation")
}

async fn reserve(
    env: &Env,
    body: &[u8],
    signature: &str,
    activate: bool,
) -> Result<IssuerReservationReply> {
    let registry = env.durable_object("HYBRID_AUTHORITY_STATE")?;
    let id = registry.id_from_name("physical-authority-ledger-v1")?;
    let route = if activate {
        "issuer-activate"
    } else {
        "issuer-reserve"
    };
    let mut response = id
        .get_stub()?
        .fetch_with_request(forwarded(
            &format!("https://authority/{route}"),
            body.to_vec(),
            signature.to_owned(),
        )?)
        .await?;
    ensure!(
        response.status_code() == 200,
        "registry reservation/install gap remains pending"
    );
    let mut bytes = Vec::new();
    use futures_util::StreamExt as _;
    let mut stream = response.stream()?;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            bytes.len() + chunk.len() <= 8 * 1024,
            "activation receipt exceeds bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    let reply: IssuerReservationReply = serde_json::from_slice(&bytes)?;
    Ok(reply)
}

fn forwarded(url: &str, body: Vec<u8>, signature: String) -> worker::Result<Request> {
    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set(STORAGE_WORK_SIGNATURE_HEADER, &signature)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(
            worker::js_sys::Uint8Array::from(body.as_slice()).into(),
        ));
    Request::new_with_init(url, &init)
}

fn error(value: impl std::fmt::Display) -> worker::Error {
    worker::Error::RustError(value.to_string())
}
