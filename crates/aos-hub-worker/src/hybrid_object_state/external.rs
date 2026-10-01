//! Prerequisite journal contract for mutations of approved external objects.
//!
//! This module has no provider dispatch or production route. External DELETE
//! remains disabled. Integration must supply an authenticated, persisted
//! authority admission and hold the object's DO gate across each call.
//! Credentials belong only to request-local effect closures, never this journal.
//! Neither unknown effects nor receipts expire automatically.

use anyhow::{bail, ensure, Result};
use aos_hub_core::storage_authority::control::StorageAuthorityObjectScope;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Describes an exact provider address whose alias relationship was approved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
pub(crate) struct ExternalCoordinates {
    /// Canonical HTTPS origin, without credentials, path, query or fragment.
    pub origin: String,
    /// Provider bucket, independent of logical binding and credential revisions.
    pub bucket: String,
}

#[cfg(test)]
impl ExternalCoordinates {
    fn validate(&self) -> Result<()> {
        let parsed = url::Url::parse(&self.origin)?;
        ensure!(
            parsed.scheme() == "https"
                && parsed.host_str().is_some()
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.path() == "/"
                && parsed.query().is_none()
                && parsed.fragment().is_none()
                && parsed.as_str() == self.origin,
            "external storage origin is not canonical HTTPS"
        );
        ensure!(
            !self.bucket.is_empty()
                && self.bucket.len() <= 255
                && self.bucket.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'.')
                }),
            "external storage bucket is malformed"
        );
        Ok(())
    }
}

/// Declares aliases independently verified to identify one physical bucket.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
pub(crate) struct ApprovedExternalNamespace {
    /// Permanent authority ID retained while the physical storage can be reused.
    pub authority_id: String,
    /// Exact approved addresses; DNS similarity and matching credentials are insufficient.
    pub aliases: Vec<ExternalCoordinates>,
}

/// Resolves provider addresses using authenticated operator or SQL approvals.
#[cfg(test)]
pub(crate) struct ExternalAuthorityMap {
    entries: Vec<ApprovedExternalNamespace>,
}

#[cfg(test)]
impl ExternalAuthorityMap {
    /// Validates previously authenticated, persisted namespace approvals.
    ///
    /// Authentication and provider ownership/alias evidence are prerequisites;
    /// structural validation cannot establish either. This constructor must not
    /// receive an authority label or alias list from an ordinary work request.
    /// Approval changes must preserve historical mappings and drain admitted
    /// operations before revocation. Initial integration must reject unproven
    /// aliases rather than manufacture separate authorities for them.
    ///
    /// # Errors
    /// Returns an error for malformed, duplicate or conflicting approvals.
    pub(crate) fn from_verified_entries(entries: Vec<ApprovedExternalNamespace>) -> Result<Self> {
        let mut authority_ids = std::collections::BTreeSet::new();
        let mut coordinates = std::collections::BTreeSet::new();
        for entry in &entries {
            ensure!(
                valid_id(&entry.authority_id),
                "invalid external storage authority ID"
            );
            ensure!(
                authority_ids.insert(entry.authority_id.clone()),
                "duplicate authority ID"
            );
            ensure!(
                !entry.aliases.is_empty(),
                "external authority has no approved address"
            );
            for alias in &entry.aliases {
                alias.validate()?;
                ensure!(
                    coordinates.insert((alias.origin.clone(), alias.bucket.clone())),
                    "external address has duplicate or conflicting authority approvals"
                );
            }
        }
        Ok(Self { entries })
    }

    /// Resolves the approved bucket and joins all prefixes into one physical key.
    ///
    /// Binding IDs, credential generations and publication revisions are absent
    /// deliberately. Prefixes are part of the key, not separate guard authorities.
    ///
    /// # Errors
    /// Returns an error for unapproved coordinates or a noncanonical key.
    pub(crate) fn scope(
        &self,
        coordinates: &ExternalCoordinates,
        binding_prefix: &str,
        placement_prefix: &str,
        path: &str,
    ) -> Result<ExternalObjectScope> {
        coordinates.validate()?;
        ensure!(
            valid_path(binding_prefix, true),
            "invalid external binding prefix"
        );
        ensure!(
            valid_path(placement_prefix, true),
            "invalid external placement prefix"
        );
        ensure!(valid_path(path, false), "invalid external object path");
        let approved = self
            .entries
            .iter()
            .find(|entry| entry.aliases.contains(coordinates))
            .ok_or_else(|| anyhow::anyhow!("external storage address has no approved authority"))?;
        let key = [binding_prefix, placement_prefix, path]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        ensure!(key.len() <= 2048, "external object key exceeds its limit");
        ExternalObjectScope::from_verified_scope(
            StorageAuthorityObjectScope {
                guard_namespace_id: "test-fixture/actual-namespace".into(),
                physical_authority_id:
                    aos_hub_core::storage_authority::PhysicalStorageAuthorityId::parse(
                        approved.authority_id.clone(),
                    )?,
                full_key: key,
            },
            "test-fixture/actual-namespace",
        )
    }
}

/// Pins one journal to the shared, approved permanent full-key scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct ExternalObjectScope(StorageAuthorityObjectScope);

impl ExternalObjectScope {
    /// Checks an independently admitted scope against actual runtime configuration.
    ///
    /// This is a structural adapter, not proof of root approval or fresh admission.
    /// The addressed object DO must establish both before provider dispatch.
    ///
    /// # Errors
    /// Returns an error for a changed namespace or noncanonical full key.
    pub(crate) fn from_verified_scope(
        scope: StorageAuthorityObjectScope,
        configured_namespace: &str,
    ) -> Result<Self> {
        ensure!(
            scope.guard_namespace_id == configured_namespace,
            "external object namespace differs from runtime configuration"
        );
        scope.guard_name()?;
        Ok(Self(scope))
    }

    /// Borrows the actual configured immutable namespace identity.
    pub(crate) fn namespace(&self) -> &str {
        &self.0.guard_namespace_id
    }

    /// Returns the permanent physical authority shared by approved aliases.
    pub(crate) fn authority_id(&self) -> &str {
        self.0.physical_authority_id.as_str()
    }

    /// Returns the exact provider key, including every physical prefix.
    pub(crate) fn key(&self) -> &str {
        &self.0.full_key
    }

    /// Computes the canonical shared addressed guard name.
    ///
    /// # Errors
    /// Returns an error for a malformed scope or failed canonical encoding.
    pub(crate) fn guard_name(&self) -> Result<String> {
        self.0.guard_name()
    }
}

/// Contains only nonsecret inputs that determine one visible provider effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ExternalEffect {
    /// Binds metadata or probe PUT bytes without persisting the body.
    Put {
        /// SHA-256 computed from the exact dispatched body.
        sha256: String,
        /// Exact dispatched body length.
        size: u64,
    },
    /// Binds the exact provider upload and canonical completion payload digest.
    CompleteMultipart {
        /// Exact provider upload identifier.
        upload_id: String,
        /// SHA-256 of the validated ordered completion parts payload.
        parts_sha256: String,
    },
    /// Removes a service-owned probe under its separately validated path scope.
    DeleteProbe,
    /// Reserves the reviewed action contract; first dispatch remains disabled.
    ConditionalDelete {
        /// Existing nonsecret fingerprint of the frozen reviewed SQL action.
        action_fingerprint: String,
        /// Exact reviewed strong provider condition.
        etag: String,
    },
}

/// Freezes replay identity without request IDs, leases or secret material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExternalMutation {
    scope: ExternalObjectScope,
    operation_id: String,
    effect: ExternalEffect,
    fingerprint: String,
}

impl ExternalMutation {
    /// Returns the operation identity used for the journal's receipt key.
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Returns the pinned physical scope used to address the journal.
    pub(crate) fn scope(&self) -> &ExternalObjectScope {
        &self.scope
    }

    /// Returns the nonsecret effect metadata checked by provider adapters.
    pub(crate) fn effect(&self) -> &ExternalEffect {
        &self.effect
    }

    /// Captures the stable effect identity before provider dispatch.
    ///
    /// Callers must obtain PUT digests from the exact dispatched bytes and
    /// completion digests from the validated upload/parts payload. A retained
    /// SQL action, never a transient claim token, supplies deletion identity.
    ///
    /// # Errors
    /// Returns an error for malformed effect metadata or operation identity.
    pub(crate) fn new(
        scope: ExternalObjectScope,
        operation_id: &str,
        effect: ExternalEffect,
    ) -> Result<Self> {
        scope.guard_name()?;
        ensure!(valid_id(operation_id), "invalid external operation ID");
        match &effect {
            ExternalEffect::Put { sha256, .. } => {
                ensure!(valid_digest(sha256), "invalid PUT digest")
            }
            ExternalEffect::CompleteMultipart {
                upload_id,
                parts_sha256,
            } => {
                ensure!(
                    !upload_id.is_empty()
                        && upload_id.len() <= 2048
                        && !upload_id.chars().any(char::is_control),
                    "invalid external upload identity"
                );
                ensure!(valid_digest(parts_sha256), "invalid completion digest");
            }
            ExternalEffect::ConditionalDelete {
                action_fingerprint,
                etag,
            } => {
                ensure!(
                    valid_digest(action_fingerprint),
                    "invalid reviewed action fingerprint"
                );
                ensure!(
                    etag.len() <= 1024
                        && aos_hub_core::surface_write::strong_if_match_etag(etag).is_ok(),
                    "invalid reviewed delete condition"
                );
            }
            ExternalEffect::DeleteProbe => ensure!(
                scope
                    .key()
                    .split('/')
                    .collect::<Vec<_>>()
                    .windows(2)
                    .any(|parts| { parts == [".aos-internal", "conditional-delete-probes"] }),
                "external probe deletion is outside its reserved namespace"
            ),
        }
        let encoded = serde_json::to_vec(&(&scope, &effect))?;
        Ok(Self {
            scope,
            operation_id: operation_id.into(),
            effect,
            fingerprint: hex::encode(Sha256::digest(encoded)),
        })
    }
}

/// Records a settled provider response; transport errors are never outcomes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ExternalOutcome {
    /// The provider acknowledged the exact PUT payload.
    PutAcknowledged,
    /// The provider acknowledged visible completion of the exact upload.
    MultipartCompleted {
        /// Strong ETag from the completion acknowledgement, not a later HEAD.
        etag: String,
    },
    /// The provider acknowledged removal of the service-owned probe key.
    ProbeDeleted,
    /// The provider acknowledged the exact atomic reviewed delete condition.
    ConditionalDeleteAcknowledged {
        /// Strong condition accepted by the provider.
        etag: String,
    },
    /// The provider conclusively reported absence for the exact deletion.
    NotFound,
    /// The provider rejected the reviewed condition without deleting an object.
    PreconditionFailed,
    /// Retains a provider-defined rejection that conclusively caused no effect.
    ///
    /// An adapter must have qualified the provider's negative acknowledgement
    /// semantics. A generic HTTP error, proxy response or timeout is insufficient.
    Rejected {
        /// Conclusive no-effect rejection category, excluding response details.
        class: ExternalRejection,
    },
}

/// Bounds nonsecret classes of conclusive provider rejection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExternalRejection {
    /// The actual provider refused the operation's authorization before effects.
    AuthorizationDenied,
    /// The actual provider rejected its request before any visible effect.
    InvalidRequest,
}

/// Retains exact effect identity and terminal response indefinitely.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExternalReceipt {
    mutation: ExternalMutation,
    outcome: ExternalOutcome,
}

impl ExternalReceipt {
    /// Returns the frozen intent whose receipt may clear a matching fence.
    pub(crate) fn mutation(&self) -> &ExternalMutation {
        &self.mutation
    }

    /// Returns the exact terminal evidence retained for replay.
    pub(crate) fn outcome(&self) -> &ExternalOutcome {
        &self.outcome
    }
}

/// Supplies durable storage while the caller holds the physical object's DO gate.
///
/// Writes must acknowledge durability before returning. `clear_pending` must
/// delete only the matching intent, and any storage failure must propagate.
/// Receipts are keyed by operation ID inside the pinned scope. Neither secrets,
/// request bodies nor provider signed URLs may be persisted by an adapter.
pub(crate) trait ExternalJournal {
    /// Loads the scope permanently pinned to this addressed journal.
    ///
    /// # Errors
    /// Returns an error for unavailable storage or malformed persisted identity.
    async fn scope(&mut self) -> Result<Option<ExternalObjectScope>>;

    /// Durably pins the initially empty journal to its addressed scope.
    ///
    /// # Errors
    /// Returns an error for conflicting scope or failed durable persistence.
    async fn pin_scope(&mut self, scope: &ExternalObjectScope) -> Result<()>;

    /// Loads any provider effect whose settlement is still unknown.
    ///
    /// # Errors
    /// Returns an error for unavailable storage or malformed persisted intent.
    async fn pending(&mut self) -> Result<Option<ExternalMutation>>;

    /// Loads terminal evidence by operation ID within the pinned scope.
    ///
    /// # Errors
    /// Returns an error for unavailable storage or malformed persisted evidence.
    async fn receipt(&mut self, operation_id: &str) -> Result<Option<ExternalReceipt>>;

    /// Durably records the exact intent before any provider effect.
    ///
    /// # Errors
    /// Returns an error for an existing intent or failed durable persistence.
    async fn write_pending(&mut self, mutation: &ExternalMutation) -> Result<()>;

    /// Durably records the exact terminal acknowledgement before unlocking.
    ///
    /// # Errors
    /// Returns an error for conflicting evidence or failed durable persistence.
    async fn write_receipt(&mut self, receipt: &ExternalReceipt) -> Result<()>;

    /// Clears only the intent matching its already persisted terminal receipt.
    ///
    /// # Errors
    /// Returns an error for missing receipt, different intent or failed persistence.
    async fn clear_pending(&mut self, mutation: &ExternalMutation) -> Result<()>;
}

/// Executes an effect under a durable fence or replays its exact terminal result.
///
/// The DO adapter must hold its gate throughout this function, including all
/// storage and provider awaits. A failed effect closure leaves a pending fence;
/// a timeout or HEAD cannot prove settlement. Conditional DELETE first dispatch
/// is disabled until the full external coordination contract is qualified.
///
/// # Errors
/// Returns an error for identity changes, unknown outcomes, disabled DELETE,
/// incompatible provider evidence, or journal/provider failure.
pub(crate) async fn mutate<J, F, Fut>(
    journal: &mut J,
    mutation: &ExternalMutation,
    effect: F,
) -> Result<ExternalOutcome>
where
    J: ExternalJournal,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<ExternalOutcome>>,
{
    pin(journal, &mutation.scope).await?;
    if let Some(receipt) = journal.receipt(&mutation.operation_id).await? {
        ensure!(
            receipt.mutation == *mutation,
            "external operation changed scope or payload"
        );
        validate_outcome(&mutation.effect, &receipt.outcome)?;
        if journal.pending().await?.as_ref() == Some(mutation) {
            journal.clear_pending(mutation).await?;
        }
        return Ok(receipt.outcome);
    }
    ensure!(
        journal.pending().await?.is_none(),
        "external mutation outcome is unknown; provider settlement is required"
    );
    ensure!(
        !matches!(mutation.effect, ExternalEffect::ConditionalDelete { .. }),
        "external conditional DELETE dispatch is not qualified"
    );

    journal.write_pending(mutation).await?;
    let outcome = effect().await?;
    validate_outcome(&mutation.effect, &outcome)?;
    journal
        .write_receipt(&ExternalReceipt {
            mutation: mutation.clone(),
            outcome: outcome.clone(),
        })
        .await?;
    journal.clear_pending(mutation).await?;
    Ok(outcome)
}

/// Observes a provider only when the pinned journal contains no unknown effect.
///
/// # Errors
/// Returns an error before provider I/O for a scope conflict or pending effect,
/// or propagates journal/provider failures. Observation never repairs a fence.
pub(crate) async fn observe<J, F, Fut, T>(
    journal: &mut J,
    scope: &ExternalObjectScope,
    effect: F,
) -> Result<T>
where
    J: ExternalJournal,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    pin(journal, scope).await?;
    ensure!(
        journal.pending().await?.is_none(),
        "external mutation outcome is unknown; provider settlement is required"
    );
    effect().await
}

async fn pin<J: ExternalJournal>(journal: &mut J, scope: &ExternalObjectScope) -> Result<()> {
    scope.guard_name()?;
    match journal.scope().await? {
        Some(existing) => ensure!(existing == *scope, "external guard scope changed"),
        None => journal.pin_scope(scope).await?,
    }
    Ok(())
}

fn validate_outcome(effect: &ExternalEffect, outcome: &ExternalOutcome) -> Result<()> {
    match (effect, outcome) {
        (_, ExternalOutcome::Rejected { .. }) => Ok(()),
        (ExternalEffect::Put { .. }, ExternalOutcome::PutAcknowledged)
        | (ExternalEffect::DeleteProbe, ExternalOutcome::ProbeDeleted) => Ok(()),
        (
            ExternalEffect::CompleteMultipart { .. },
            ExternalOutcome::MultipartCompleted { etag },
        ) => {
            ensure!(
                etag.len() <= 1024
                    && aos_hub_core::surface_write::strong_if_match_etag(etag).is_ok(),
                "invalid completed multipart ETag"
            );
            Ok(())
        }
        (
            ExternalEffect::ConditionalDelete { etag, .. },
            ExternalOutcome::ConditionalDeleteAcknowledged { etag: actual },
        ) if etag == actual => Ok(()),
        (
            ExternalEffect::ConditionalDelete { .. },
            ExternalOutcome::NotFound | ExternalOutcome::PreconditionFailed,
        ) => Ok(()),
        _ => bail!("external receipt has an incompatible provider outcome"),
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_path(value: &str, empty: bool) -> bool {
    (empty && value.is_empty())
        || (!value.is_empty()
            && !value.chars().any(char::is_control)
            && !value.contains('\\')
            && value
                .split('/')
                .all(|part| !matches!(part, "" | "." | "..")))
}

#[cfg(test)]
#[path = "external/tests.rs"]
mod tests;
