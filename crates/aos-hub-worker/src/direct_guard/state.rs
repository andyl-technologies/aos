//! Immutable physical reservation identity and settlement transitions.
//!
//! These transitions operate on durable records; a transport retry or elapsed
//! eligibility horizon never establishes a provider result or clears an owner.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use aos_hub_core::storage_work::StorageWorkKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Reads an exact acknowledged original without accepting an unknown effect.
///
/// # Errors
/// Returns an error for changed operation, intent, effect kind, pending attempt
/// or a missing positive terminal receipt. Expiration cannot change this result.
pub(crate) fn positive_effect_terminal<'a>(
    actual: &'a crate::direct_upload::journal::Effect,
    expected: &crate::direct_upload::journal::Effect,
) -> Result<&'a serde_json::Value> {
    ensure!(
        actual.operation_id == expected.operation_id
            && actual.intent_digest == expected.intent_digest
            && actual.immutable_read == expected.immutable_read
            && actual.pending_attempt.is_none(),
        "direct positive effect original changed or remains unknown"
    );
    actual
        .terminal
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("direct positive effect acknowledgement absent"))
}

/// Exact source identity retained before any final provider mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Source {
    /// Whole-object digest proven by the retained immutable read.
    pub(crate) sha256: String,
    /// Exact byte count proven by that same read.
    pub(crate) byte_size: WireInteger,
    /// Provider version or physical guard stamp of the positively closed source.
    pub(crate) incarnation: DirectObjectIncarnation,
}

/// Authenticates exact Native publication permission before provider dispatch.
///
/// # Errors
///
/// Returns an error for another signature key, request context, expired reply,
/// or a permission absent from Native's exact authenticated response.
pub(crate) fn authenticate_native_permission(
    key: &StorageWorkKey,
    permission: &DirectDestinationBaselinePermission,
    context: &DirectRequestContext,
    reply_body: &[u8],
    reply_signature: &str,
    latest_now: u64,
) -> Result<()> {
    let acknowledged =
        verify_direct_logical_reply(key, reply_signature, reply_body, context, latest_now)?;
    ensure!(
        acknowledged.reply.baseline_permissions.contains(permission),
        "direct authenticated Native publication permission absent"
    );
    Ok(())
}

/// Authenticates Native's durable target status against the exact public Complete.
///
/// # Errors
/// Returns an error for another public body, signature key, request context,
/// incarnation, or a reply lacking the exact durable committed target status.
pub(crate) fn authenticate_native_commit(
    key: &StorageWorkKey,
    owner: &Reservation,
    record: &DirectFinalGuardRecord,
    context: &DirectRequestContext,
    public_body: &[u8],
    reply_body: &[u8],
    reply_signature: &str,
    latest_now: u64,
) -> Result<Reservation> {
    ensure!(
        hex::encode(Sha256::digest(public_body)) == context.request_body_sha256
            && context.public_path == "/aos.hub.v1.DirectUploadService/CompleteBatch",
        "direct Native commit public context differs"
    );
    let batch: DirectBatch<DirectCompleteRequest> = decode_direct_control(public_body)?;
    ensure!(
        batch.items.contains(&owner.complete),
        "direct Native commit public Complete differs"
    );
    let acknowledged =
        verify_direct_logical_reply(key, reply_signature, reply_body, context, latest_now)?;
    ensure!(
        acknowledged
            .reply
            .sessions
            .iter()
            .any(|status| status.session == owner.complete.session
                && status.intent == owner.admission.intent
                && status.state == DirectSessionState::Committed
                && status.resource_version.get() > owner.complete.expected_resource_version.get()
                && status.placements
                    == owner
                        .complete
                        .manifests
                        .iter()
                        .map(|item| item.placement.clone())
                        .collect::<Vec<_>>()),
        "direct Native durable target acknowledgement absent"
    );
    owner.acknowledge_native(record)
}

/// One immutable owner of the permanent physical destination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reservation {
    /// Original server admission, including all selected placement identities.
    pub(crate) admission: DirectUploadAdmission,
    /// Full immutable Complete selected before final provider effects.
    pub(crate) complete: DirectCompleteRequest,
    /// Compact commitment to this placement within the original Complete.
    pub(crate) selected: DirectSelectedCompleteCommitment,
    /// Exact physical destination, protected profile, and reservation operation.
    pub(crate) binding: DirectDestinationBaselineBinding,
    /// Positively verified source retained before any final mutation.
    pub(crate) source: Source,
    /// First destination observation made while this owner held exclusion.
    pub(crate) baseline: Option<DirectDestinationBaselineEvidence>,
    /// Final incarnation from the actual positive provider acknowledgement.
    pub(crate) final_record: Option<DirectFinalGuardRecord>,
    /// Release flag set only after authenticated durable Native target commit.
    pub(crate) native_committed: bool,
}

impl Reservation {
    /// Checks the complete retained reservation without inferring settlement.
    ///
    /// # Errors
    /// Returns an error for inconsistent originals, source, or terminal records.
    pub(crate) fn validate(&self) -> Result<()> {
        self.binding.validate_for(
            &self.admission,
            &self.complete,
            &self.binding.deployment_id,
            &self.selected.protected_profile_digest,
        )?;
        self.selected.validate()?;
        ensure!(
            self.selected.session == self.complete.session
                && self.selected.operation_id == self.complete.operation_id
                && self.selected.expected_resource_version
                    == self.complete.expected_resource_version
                && self.selected.complete_intent_digest == self.complete.fingerprint()?
                && self.complete.manifests.contains(&self.selected.manifest)
                && self.selected.manifest.placement == self.binding.placement
                && self.source.sha256 == self.admission.intent.expected_sha256
                && self.source.byte_size == self.admission.intent.byte_size,
            "direct guard immutable source or selected Complete differs"
        );
        match (&self.source.incarnation, &self.binding.scope) {
            (
                DirectObjectIncarnation::ProviderVersion { version },
                DirectDestinationReservationScope::Managed { .. },
            ) => {
                ensure!(
                    aos_hub_core::storage_work::valid_provider_version(version),
                    "direct guard source provider incarnation invalid"
                );
            }
            (
                DirectObjectIncarnation::GuardStamp { stamp },
                DirectDestinationReservationScope::External {
                    physical_authority_id,
                },
            ) => {
                ensure!(
                    &stamp.physical_authority_id == physical_authority_id,
                    "direct guard source physical authority differs"
                );
            }
            _ => anyhow::bail!("direct guard source incarnation scope differs"),
        }
        if let Some(baseline) = &self.baseline {
            baseline.validate()?;
            ensure!(
                baseline.binding == self.binding,
                "direct guard baseline owner differs"
            );
        }
        if let Some(record) = &self.final_record {
            self.validate_final(record)?;
        }
        ensure!(
            !self.native_committed || self.final_record.is_some(),
            "direct guard Native commit lacks publication"
        );
        Ok(())
    }

    /// Checks that a retry preserves every original physical owner coordinate.
    ///
    /// # Errors
    /// Returns an error for invalid records or a changed immutable original.
    pub(crate) fn validate_original(&self, requested: &Self) -> Result<()> {
        self.validate()?;
        requested.validate()?;
        ensure!(
            self.admission == requested.admission
                && self.complete == requested.complete
                && self.selected == requested.selected
                && self.binding == requested.binding
                && self.source == requested.source,
            "direct guard original reservation changed"
        );
        Ok(())
    }

    /// Retains the first held baseline without replacing an earlier observation.
    ///
    /// # Errors
    /// Returns an error for a changed baseline or an already published owner.
    pub(crate) fn retain_baseline(
        &self,
        baseline: DirectDestinationBaselineEvidence,
    ) -> Result<Self> {
        baseline.validate()?;
        ensure!(
            baseline.binding == self.binding,
            "direct guard baseline scope differs"
        );
        ensure!(
            self.baseline.as_ref().is_none_or(|old| old == &baseline),
            "direct guard first baseline changed"
        );
        ensure!(
            self.final_record.is_none() && !self.native_committed,
            "direct guard baseline publication already closed"
        );
        let mut next = self.clone();
        next.baseline = Some(baseline);
        Ok(next)
    }

    /// Retains the exact positive provider publication while keeping exclusion.
    ///
    /// # Errors
    /// Returns an error for another source, final incarnation, or absent baseline.
    pub(crate) fn acknowledge_publication(&self, record: DirectFinalGuardRecord) -> Result<Self> {
        self.validate_final(&record)?;
        ensure!(
            self.baseline.is_some(),
            "direct guard publication lacks original baseline"
        );
        ensure!(
            self.final_record.as_ref().is_none_or(|old| old == &record),
            "direct guard final incarnation changed"
        );
        let mut next = self.clone();
        next.final_record = Some(record);
        Ok(next)
    }

    /// Releases a validated owner after its exact authenticated Native commit.
    ///
    /// The caller authenticates Native's durable acknowledgement before storing
    /// this transition. The transition itself matches the retained final record.
    ///
    /// # Errors
    /// Returns an error for an invalid owner or another final publication.
    pub(crate) fn acknowledge_native(&self, expected: &DirectFinalGuardRecord) -> Result<Self> {
        self.validate()?;
        ensure!(
            self.final_record.as_ref() == Some(expected),
            "direct guard Native acknowledgement publication differs"
        );
        let mut next = self.clone();
        next.native_committed = true;
        Ok(next)
    }

    fn validate_final(&self, record: &DirectFinalGuardRecord) -> Result<()> {
        record.validate()?;
        ensure!(
            record.reservation == self.binding
                && record.selected == self.selected
                && record.sha256 == self.source.sha256
                && record.byte_size == self.source.byte_size
                && record.source_incarnation == self.source.incarnation,
            "direct guard final original source differs"
        );
        Ok(())
    }
}
