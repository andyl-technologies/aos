//! Pure completion planning and canonical graph materialization.
//!
//! Method-specific plans contain only nonauthorizing durable observation facts.
//! Security custody supplies signed artifacts, and this module derives every
//! affected AOSSPL record before validating the complete prospective graph. It
//! owns no journal, key, descriptor, backend, or send authority.

use std::collections::BTreeMap;

use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SignedSourceExportLeaseV1, SignedSourceProviderReceiptV1, SignedSourceProviderStatusV1,
    SignedSourceReleaseReceiptV1, SourceProviderMethod, SourceProviderStatus,
    decode_acquire_response, decode_inventory_response, decode_release_response,
    digest_signed_export_lease, digest_signed_release_receipt,
    provider_response_artifact_digest_v1,
};

use super::LedgerFormatErrorV1;
use super::evidence::BackendEvidenceV1;
use super::format::{
    acquisition_key, authority_key, decode_record, encode_acquisition, encode_attempt,
    encode_authority, encode_decoded_record, encode_release, encode_session,
    encode_session_history, record_digest, session_history_key, session_key,
};
use super::model::{
    AcquisitionKeyV1, AcquisitionRecordV1, AttemptRecordV1, DecodedRecordV1, LeaseLineageV1,
    ProviderAcquisitionStateV1, ProviderAttemptStateV1, ProviderReleaseStateV1, ReleaseKeyV1,
    ReleaseRecordV1, SourceRootIdentityV1,
};
use super::reopen::ReopenIdentityV1;

/// Supplies durable acquisition facts whose signature-dependent fields are sealed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquireCompletionPatchV1 {
    acquisition_key: Vec<u8>,
    attempt_digest: ObjectDigest,
    lease_issue_generation: u64,
    proof_digest: ObjectDigest,
    resource_commitment: ObjectDigest,
    backend_evidence: Option<Vec<u8>>,
    reopen_identity: Option<Vec<u8>>,
    source_root: SourceRootIdentityV1,
}

impl AcquireCompletionPatchV1 {
    /// Constructs one nonauthorizing Active-acquisition completion patch.
    ///
    /// The evidence and reopen bytes are canonical durable observations, not
    /// live backend or descriptor authority.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for an empty key, sentinel digest, or
    /// malformed evidence/reopen encoding.
    pub fn new(
        acquisition_key: Vec<u8>,
        attempt_digest: ObjectDigest,
        lease_issue_generation: u64,
        proof_digest: ObjectDigest,
        resource_commitment: ObjectDigest,
        backend_evidence: Option<Vec<u8>>,
        reopen_identity: Option<Vec<u8>>,
        source_root: SourceRootIdentityV1,
    ) -> Result<Self, LedgerFormatErrorV1> {
        if acquisition_key.is_empty()
            || attempt_digest.as_bytes() == &[0; 32]
            || lease_issue_generation == 0
            || proof_digest.as_bytes() == &[0; 32]
            || resource_commitment.as_bytes() == &[0; 32]
        {
            return Err(LedgerFormatErrorV1::Corrupt("Acquire completion identity"));
        }
        if let Some(bytes) = &backend_evidence {
            BackendEvidenceV1::decode(bytes)?;
        }
        if let Some(bytes) = &reopen_identity {
            ReopenIdentityV1::decode(bytes)?;
        }
        Ok(Self {
            acquisition_key,
            attempt_digest,
            lease_issue_generation,
            proof_digest,
            resource_commitment,
            backend_evidence,
            reopen_identity,
            source_root,
        })
    }
}

/// Supplies durable Release facts whose signed receipt remains sealed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseCompletionPatchV1 {
    release_key: Vec<u8>,
    backend_evidence: Vec<u8>,
    observation_digest: ObjectDigest,
    released_seconds: i64,
}

impl ReleaseCompletionPatchV1 {
    /// Constructs one nonauthorizing Release tombstone patch.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for malformed evidence, a sentinel
    /// digest, invalid time, or empty key.
    pub fn new(
        release_key: Vec<u8>,
        backend_evidence: Vec<u8>,
        observation_digest: ObjectDigest,
        released_seconds: i64,
    ) -> Result<Self, LedgerFormatErrorV1> {
        BackendEvidenceV1::decode(&backend_evidence)?;
        if release_key.is_empty()
            || observation_digest.as_bytes() == &[0; 32]
            || released_seconds < 0
        {
            return Err(LedgerFormatErrorV1::Corrupt("Release completion identity"));
        }
        Ok(Self {
            release_key,
            backend_evidence,
            observation_digest,
            released_seconds,
        })
    }
}

/// Carries one pure completion mutation plan before signed artifacts exist.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CompletionMutationPlanV1 {
    purpose: Vec<u8>,
    method: SourceProviderMethod,
    class: CompletionPlanClassV1,
    attempt_key: Option<Vec<u8>>,
    acquire: Option<AcquireCompletionPatchV1>,
    release: Option<ReleaseCompletionPatchV1>,
    refresh_inventory_tombstones: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionPlanClassV1 {
    StatusOnly,
    Artifact,
    RecoveryArtifact,
}

impl CompletionMutationPlanV1 {
    /// Constructs a status-only Acquire completion from exact named record kinds.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for empty identities, duplicate keys,
    /// too many records, or an invalid inventory bound.
    fn acquire_status(attempt_key: Vec<u8>) -> Result<Self, LedgerFormatErrorV1> {
        Self::response_for_kinds(
            b"complete-acquire",
            SourceProviderMethod::Acquire,
            CompletionPlanClassV1::StatusOnly,
            attempt_key,
            None,
            None,
            None,
        )
    }

    /// Constructs a terminal Acquire completion from exact named record kinds.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for noncanonical or substituted records.
    fn acquire(
        attempt_key: Vec<u8>,
        patch: AcquireCompletionPatchV1,
        refresh_inventory_tombstones: usize,
    ) -> Result<Self, LedgerFormatErrorV1> {
        Self::response_for_kinds(
            b"complete-acquire",
            SourceProviderMethod::Acquire,
            CompletionPlanClassV1::Artifact,
            attempt_key,
            Some(patch),
            None,
            Some(refresh_inventory_tombstones),
        )
    }

    /// Constructs a superseding-lease Acquire completion from exact named record kinds.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for noncanonical or substituted records.
    fn acquire_rebind(
        attempt_key: Vec<u8>,
        patch: AcquireCompletionPatchV1,
        refresh_inventory_tombstones: usize,
    ) -> Result<Self, LedgerFormatErrorV1> {
        Self::response_for_kinds(
            b"complete-acquire-rebind",
            SourceProviderMethod::Acquire,
            CompletionPlanClassV1::Artifact,
            attempt_key,
            Some(patch),
            None,
            Some(refresh_inventory_tombstones),
        )
    }

    /// Constructs a status-only Release completion from exact named record kinds.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for noncanonical or substituted records.
    fn release_status(attempt_key: Vec<u8>) -> Result<Self, LedgerFormatErrorV1> {
        Self::response_for_kinds(
            b"complete-release",
            SourceProviderMethod::Release,
            CompletionPlanClassV1::StatusOnly,
            attempt_key,
            None,
            None,
            None,
        )
    }

    /// Constructs a terminal Release completion from exact named record kinds.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for noncanonical or substituted records.
    fn release(
        attempt_key: Vec<u8>,
        patch: ReleaseCompletionPatchV1,
        refresh_inventory_tombstones: usize,
    ) -> Result<Self, LedgerFormatErrorV1> {
        Self::response_for_kinds(
            b"complete-release",
            SourceProviderMethod::Release,
            CompletionPlanClassV1::Artifact,
            attempt_key,
            None,
            Some(patch),
            Some(refresh_inventory_tombstones),
        )
    }

    /// Constructs a status-only Inventory completion from its exact session-head rewrite.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for noncanonical or substituted records.
    fn inventory_status(attempt_key: Vec<u8>) -> Result<Self, LedgerFormatErrorV1> {
        Self::response_for_kinds(
            b"complete-inventory",
            SourceProviderMethod::Inventory,
            CompletionPlanClassV1::StatusOnly,
            attempt_key,
            None,
            None,
            None,
        )
    }

    /// Constructs a signed Inventory completion from its exact session-head rewrite.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for noncanonical or substituted records.
    fn inventory(attempt_key: Vec<u8>) -> Result<Self, LedgerFormatErrorV1> {
        Self::response_for_kinds(
            b"complete-inventory",
            SourceProviderMethod::Inventory,
            CompletionPlanClassV1::Artifact,
            attempt_key,
            None,
            None,
            None,
        )
    }

    /// Constructs a receipt-only recovery completion plan.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for empty identities, duplicate keys,
    /// too many records, or a missing Release patch.
    fn release_recovery(
        release: ReleaseCompletionPatchV1,
        refresh_inventory_tombstones: usize,
    ) -> Result<Self, LedgerFormatErrorV1> {
        let plan = Self {
            purpose: b"complete-pending-release".to_vec(),
            method: SourceProviderMethod::Release,
            class: CompletionPlanClassV1::RecoveryArtifact,
            attempt_key: None,
            acquire: None,
            release: Some(release),
            refresh_inventory_tombstones: Some(refresh_inventory_tombstones),
        };
        plan.validate_shape()?;
        Ok(plan)
    }

    fn response_for_kinds(
        purpose: &[u8],
        method: SourceProviderMethod,
        class: CompletionPlanClassV1,
        attempt_key: Vec<u8>,
        acquire: Option<AcquireCompletionPatchV1>,
        release: Option<ReleaseCompletionPatchV1>,
        refresh_inventory_tombstones: Option<usize>,
    ) -> Result<Self, LedgerFormatErrorV1> {
        let plan = Self {
            purpose: purpose.to_vec(),
            method,
            class,
            attempt_key: Some(attempt_key),
            acquire,
            release,
            refresh_inventory_tombstones,
        };
        plan.validate_shape()?;
        Ok(plan)
    }

    fn validate_shape(&self) -> Result<(), LedgerFormatErrorV1> {
        if self.purpose.is_empty()
            || self.attempt_key.as_ref().is_some_and(|key| key.is_empty())
            || usize::from(self.attempt_key.is_some())
                + 2 * usize::from(self.attempt_key.is_some())
                + usize::from(self.acquire.is_some())
                + usize::from(self.release.is_some())
                > crate::limits::MAXIMUM_TRANSACTION_RECORDS
            || self
                .refresh_inventory_tombstones
                .is_some_and(|value| value > crate::limits::MAXIMUM_INVENTORY_TOMBSTONES_PER_HOLDER)
        {
            return Err(LedgerFormatErrorV1::Corrupt("completion plan shape"));
        }
        let mut keys = std::collections::BTreeSet::new();
        for key in [
            self.attempt_key.as_deref(),
            self.acquire
                .as_ref()
                .map(|value| value.acquisition_key.as_slice()),
            self.release
                .as_ref()
                .map(|value| value.release_key.as_slice()),
        ]
        .into_iter()
        .flatten()
        {
            if !keys.insert(key) {
                return Err(LedgerFormatErrorV1::Corrupt("duplicate completion key"));
            }
        }
        Ok(())
    }

    /// Returns the exact transaction-purpose domain bytes.
    #[must_use]
    fn purpose(&self) -> &[u8] {
        &self.purpose
    }

    /// Borrows the exact reserved attempt key for a response completion.
    #[must_use]
    fn attempt_key(&self) -> Option<&[u8]> {
        self.attempt_key.as_deref()
    }

    /// Reports whether the sealed plan is the exact method/status shape requested by custody.
    #[must_use]
    const fn permits_response(&self, method: SourceProviderMethod, artifact: bool) -> bool {
        self.method as u8 == method as u8
            && matches!(
                (self.class, artifact),
                (CompletionPlanClassV1::StatusOnly, false)
                    | (CompletionPlanClassV1::Artifact, true)
            )
    }
}

macro_rules! response_plan {
    ($name:ident, $artifact:expr) => {
        impl $name {
            /// Borrows the exact reserved attempt key sealed into this plan.
            #[must_use]
            pub fn attempt_key(&self) -> &[u8] {
                match self.0.attempt_key() {
                    Some(key) => key,
                    None => &[],
                }
            }

            /// Finalizes this plan with exact signed response artifacts.
            ///
            /// # Errors
            ///
            /// Returns [`LedgerFormatErrorV1`] for any response, mutation, or
            /// prospective-graph mismatch.
            pub fn finalize<'record>(
                self,
                current_records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
                canonical_response: Vec<u8>,
                signed_lease: Option<SignedSourceExportLeaseV1>,
            ) -> Result<FinalizedCompletionV1, LedgerFormatErrorV1> {
                if !self.0.permits_response(self.0.method, $artifact) {
                    return Err(LedgerFormatErrorV1::Corrupt("completion plan class"));
                }
                finalize_response_completion(
                    current_records,
                    self.0,
                    canonical_response,
                    signed_lease,
                )
            }
        }
    };
}

/// Seals one status-only Acquire mutation shape.
pub struct AcquireStatusCompletionPlanV1(CompletionMutationPlanV1);

impl AcquireStatusCompletionPlanV1 {
    /// Constructs the exact status-only Acquire plan.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for substituted or noncanonical records.
    pub fn new(attempt_key: Vec<u8>) -> Result<Self, LedgerFormatErrorV1> {
        CompletionMutationPlanV1::acquire_status(attempt_key).map(Self)
    }
}
response_plan!(AcquireStatusCompletionPlanV1, false);

/// Seals one artifact-bearing Acquire or rebind mutation shape.
pub struct AcquireCompletionPlanV1(CompletionMutationPlanV1);

impl AcquireCompletionPlanV1 {
    /// Constructs the exact initial Acquire completion plan.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for substituted or noncanonical records.
    pub fn new(
        attempt_key: Vec<u8>,
        patch: AcquireCompletionPatchV1,
        maximum_tombstones: usize,
    ) -> Result<Self, LedgerFormatErrorV1> {
        CompletionMutationPlanV1::acquire(attempt_key, patch, maximum_tombstones).map(Self)
    }

    /// Constructs the exact superseding-lease rebind completion plan.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for substituted or noncanonical records.
    pub fn rebind(
        attempt_key: Vec<u8>,
        patch: AcquireCompletionPatchV1,
        maximum_tombstones: usize,
    ) -> Result<Self, LedgerFormatErrorV1> {
        CompletionMutationPlanV1::acquire_rebind(attempt_key, patch, maximum_tombstones).map(Self)
    }
}
response_plan!(AcquireCompletionPlanV1, true);

/// Seals one status-only Release mutation shape.
pub struct ReleaseStatusCompletionPlanV1(CompletionMutationPlanV1);

impl ReleaseStatusCompletionPlanV1 {
    /// Constructs the exact status-only Release plan.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for substituted or noncanonical records.
    pub fn new(attempt_key: Vec<u8>) -> Result<Self, LedgerFormatErrorV1> {
        CompletionMutationPlanV1::release_status(attempt_key).map(Self)
    }
}
response_plan!(ReleaseStatusCompletionPlanV1, false);

/// Seals one artifact-bearing Release mutation shape.
pub struct ReleaseCompletionPlanV1(CompletionMutationPlanV1);

impl ReleaseCompletionPlanV1 {
    /// Constructs the exact terminal Release plan.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for substituted or noncanonical records.
    pub fn new(
        attempt_key: Vec<u8>,
        patch: ReleaseCompletionPatchV1,
        maximum_tombstones: usize,
    ) -> Result<Self, LedgerFormatErrorV1> {
        CompletionMutationPlanV1::release(attempt_key, patch, maximum_tombstones).map(Self)
    }
}
response_plan!(ReleaseCompletionPlanV1, true);

/// Seals one status-only Inventory mutation shape.
pub struct InventoryStatusCompletionPlanV1(CompletionMutationPlanV1);

impl InventoryStatusCompletionPlanV1 {
    /// Constructs the exact status-only Inventory plan.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for substituted or noncanonical records.
    pub fn new(attempt_key: Vec<u8>) -> Result<Self, LedgerFormatErrorV1> {
        CompletionMutationPlanV1::inventory_status(attempt_key).map(Self)
    }
}
response_plan!(InventoryStatusCompletionPlanV1, false);

/// Seals one signed Inventory mutation shape.
pub struct InventoryCompletionPlanV1(CompletionMutationPlanV1);

impl InventoryCompletionPlanV1 {
    /// Constructs the exact signed Inventory plan.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for substituted or noncanonical records.
    pub fn new(attempt_key: Vec<u8>) -> Result<Self, LedgerFormatErrorV1> {
        CompletionMutationPlanV1::inventory(attempt_key).map(Self)
    }
}
response_plan!(InventoryCompletionPlanV1, true);

/// Seals one receipt-only Release recovery mutation shape.
pub struct ReleaseRecoveryCompletionPlanV1(CompletionMutationPlanV1);

impl ReleaseRecoveryCompletionPlanV1 {
    /// Constructs the exact receipt-only recovery plan.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for substituted or noncanonical records.
    pub fn new(
        patch: ReleaseCompletionPatchV1,
        maximum_tombstones: usize,
    ) -> Result<Self, LedgerFormatErrorV1> {
        CompletionMutationPlanV1::release_recovery(patch, maximum_tombstones).map(Self)
    }

    /// Finalizes this recovery plan with its exact signed receipt.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFormatErrorV1`] for any receipt or graph mismatch.
    pub fn finalize<'record>(
        self,
        current_records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
        signed_receipt: SignedSourceReleaseReceiptV1,
    ) -> Result<FinalizedCompletionV1, LedgerFormatErrorV1> {
        finalize_release_recovery(current_records, self.0, signed_receipt)
    }
}

/// Contains a finalized canonical mutation set and sealed response bytes.
pub struct FinalizedCompletionV1 {
    purpose: Vec<u8>,
    mutations: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    response: Option<Vec<u8>>,
    method: SourceProviderMethod,
    session_binding: ObjectDigest,
    response_sequence: u64,
}

impl core::fmt::Debug for FinalizedCompletionV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("FinalizedCompletionV1([redacted])")
    }
}

impl FinalizedCompletionV1 {
    /// Borrows the exact transaction purpose domain.
    #[must_use]
    pub fn purpose(&self) -> &[u8] {
        &self.purpose
    }

    /// Borrows the canonical mutations for protected commit construction.
    #[must_use]
    pub fn mutations(&self) -> &[(Vec<u8>, Option<Vec<u8>>)] {
        &self.mutations
    }

    /// Borrows the exact canonical response retained for postcommit handoff.
    #[must_use]
    pub fn response(&self) -> Option<&[u8]> {
        self.response.as_deref()
    }

    /// Returns the response method.
    #[must_use]
    pub const fn method(&self) -> SourceProviderMethod {
        self.method
    }

    /// Returns the response session binding.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session_binding
    }

    /// Returns the response sequence, or zero for receipt-only recovery.
    #[must_use]
    pub const fn response_sequence(&self) -> u64 {
        self.response_sequence
    }

    /// Consumes the finalized value into its sealed components.
    #[must_use]
    pub fn into_parts(self) -> (Vec<(Vec<u8>, Option<Vec<u8>>)>, Option<Vec<u8>>) {
        (self.mutations, self.response)
    }
}

/// Finalizes a response-bearing plan with exact signed artifacts.
///
/// # Errors
///
/// Returns [`LedgerFormatErrorV1`] for an artifact/plan mismatch, malformed
/// current graph, invalid reducer transition, or noncanonical result.
fn finalize_response_completion<'record>(
    current_records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    plan: CompletionMutationPlanV1,
    canonical_response: Vec<u8>,
    signed_lease: Option<SignedSourceExportLeaseV1>,
) -> Result<FinalizedCompletionV1, LedgerFormatErrorV1> {
    let purpose = plan.purpose.clone();
    let (signed_status, method) = decode_response(&canonical_response)?;
    let status = signed_status.subject();
    let attempt_key = plan
        .attempt_key
        .as_deref()
        .ok_or(LedgerFormatErrorV1::Corrupt("missing completion attempt"))?;
    let mut prospective = canonical_graph(current_records)?;

    let mut attempt = decode_attempt_from(&prospective, attempt_key)?;
    if attempt.state != ProviderAttemptStateV1::Reserved
        || attempt.method != method
        || status.request_id() != attempt.request_id
        || status.signed_request_digest() != attempt.signed_request_digest
        || status.provider_process_instance() != attempt.provider_process_instance
        || status.session_binding() != attempt.session_binding
    {
        return Err(LedgerFormatErrorV1::Corrupt("completion attempt binding"));
    }
    attempt.revision = attempt
        .revision
        .checked_add(1)
        .ok_or(LedgerFormatErrorV1::Corrupt("attempt revision exhausted"))?;
    attempt.state = ProviderAttemptStateV1::Completed;
    attempt.status = Some(status.status());
    attempt.response_sequence = Some(status.response_sequence());
    attempt.response_digest = Some(provider_response_artifact_digest_v1(
        method,
        &canonical_response,
    ));
    attempt.descriptor_commitment = status.descriptor_commitment();
    attempt.result_digest = Some(status.result_digest());
    if method == SourceProviderMethod::Inventory {
        let response = decode_inventory_response(&canonical_response)
            .map_err(|_| LedgerFormatErrorV1::Corrupt("Inventory response"))?;
        if let Some(inventory_bytes) = response.signed_inventory() {
            let inventory = aos_sandbox_source_provider_protocol::SignedSourceProviderInventoryV1::from_canonical_bytes(inventory_bytes)
                .map_err(|_| LedgerFormatErrorV1::Corrupt("Inventory artifact"))?;
            if inventory.subject().request_id() != attempt.request_id
                || inventory.subject().request_digest() != attempt.typed_request_digest
                || inventory.subject().holder_authority_id() != attempt.holder.authority_id()
                || inventory.subject().holder_generation() != attempt.holder.authority_generation()
                || inventory.subject().holder_authority_digest()
                    != attempt.holder.authority_digest()
                || inventory.subject().provider() != &attempt.provider
                || inventory.subject().provider_process_instance()
                    != attempt.provider_process_instance
            {
                return Err(LedgerFormatErrorV1::Corrupt("Inventory request lineage"));
            }
            super::reducer::validate_inventory_subject(
                inventory.subject(),
                prospective
                    .iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
                crate::limits::MAXIMUM_INVENTORY_TOMBSTONES_PER_HOLDER,
                crate::limits::MAXIMUM_INVENTORY_ENTRIES_PER_HOLDER,
            )?;
            attempt.response_catalog_generation = inventory.subject().catalog_generation();
            attempt.response_catalog_digest = inventory.subject().catalog_digest();
        } else {
            let authority = prospective
                .iter()
                .find_map(|(key, value)| match decode_record(key, value).ok()? {
                    DecodedRecordV1::Authority(value) => Some(value),
                    _ => None,
                })
                .ok_or(LedgerFormatErrorV1::Corrupt("Inventory authority"))?;
            attempt.response_catalog_generation = authority.catalog_generation;
            attempt.response_catalog_digest = authority.catalog_digest;
        }
    }
    attempt.completed_response = canonical_response.clone();
    prospective.insert(attempt_key.to_vec(), encode_attempt(&attempt));

    complete_current_session(&mut prospective, &attempt, status.response_sequence())?;
    synchronize_current_session_history(&mut prospective, &attempt)?;

    if let Some(patch) = plan.acquire.clone() {
        let receipt = response_acquire_receipt(&canonical_response)?;
        apply_acquire_patch(&mut prospective, patch, &attempt, signed_lease, receipt)?;
    } else if method == SourceProviderMethod::Acquire {
        apply_acquire_status(&mut prospective, &attempt, status.status())?;
    } else if signed_lease.is_some() {
        return Err(LedgerFormatErrorV1::Corrupt("unexpected signed lease"));
    }
    if plan.release.is_some() {
        let receipt = response_release_receipt(&canonical_response)?;
        apply_release_patch(&mut prospective, plan.release.clone(), Some(receipt))?;
    }
    if let Some(maximum_tombstones) = plan.refresh_inventory_tombstones {
        refresh_authority_inventory(&mut prospective, maximum_tombstones)?;
    }
    validate_final_graph(&prospective)?;
    crate::validate_prospective_records(
        prospective
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )?;
    let mutations = collect_mutations(plan, prospective)?;
    Ok(FinalizedCompletionV1 {
        purpose,
        mutations,
        response: Some(canonical_response),
        method,
        session_binding: status.session_binding(),
        response_sequence: status.response_sequence(),
    })
}

fn apply_acquire_status(
    graph: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    attempt: &AttemptRecordV1,
    status: SourceProviderStatus,
) -> Result<(), LedgerFormatErrorV1> {
    let (key, mut acquisition) = graph
        .iter()
        .find_map(|(key, value)| match decode_record(key, value).ok()? {
            DecodedRecordV1::Acquisition(acquisition)
                if acquisition.provider == attempt.provider
                    && acquisition.holder == attempt.holder
                    && acquisition.current_attempt_digest == attempt.attempt_digest =>
            {
                Some((key.clone(), acquisition))
            }
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt("Acquire status acquisition"))?;
    if acquisition.state != ProviderAcquisitionStateV1::Applying
        || status == SourceProviderStatus::Complete
    {
        return Err(LedgerFormatErrorV1::Corrupt("Acquire status transition"));
    }
    acquisition.revision =
        acquisition
            .revision
            .checked_add(1)
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "acquisition revision exhausted",
            ))?;
    acquisition.state = if status == SourceProviderStatus::Pending {
        ProviderAcquisitionStateV1::Pending
    } else {
        ProviderAcquisitionStateV1::Faulted
    };
    graph.insert(key, encode_acquisition(&acquisition));
    Ok(())
}

fn complete_current_session(
    graph: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    attempt: &AttemptRecordV1,
    response_sequence: u64,
) -> Result<(), LedgerFormatErrorV1> {
    let mut session = graph
        .iter()
        .find_map(|(key, value)| match decode_record(key, value).ok()? {
            DecodedRecordV1::Session(session)
                if session.provider == attempt.provider
                    && session.holder == attempt.holder
                    && session.session_binding == attempt.session_binding =>
            {
                Some(session)
            }
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt("completion current session"))?;
    if session.pending_attempt_digest != Some(attempt.attempt_digest)
        || session.next_response_sequence != response_sequence
    {
        return Err(LedgerFormatErrorV1::Corrupt("completion session sequence"));
    }
    session.revision = session
        .revision
        .checked_add(1)
        .ok_or(LedgerFormatErrorV1::Corrupt("session revision exhausted"))?;
    session.pending_attempt_digest = None;
    session.last_completed_attempt_digest = Some(attempt.attempt_digest);
    session.next_response_sequence = session
        .next_response_sequence
        .checked_add(1)
        .ok_or(LedgerFormatErrorV1::Corrupt("response sequence exhausted"))?;
    graph.insert(
        session_key(
            session.provider.authority_id(),
            session.holder.authority_id(),
        ),
        encode_session(&session),
    );
    Ok(())
}

/// Finalizes a receipt-only Release recovery plan.
///
/// # Errors
///
/// Returns [`LedgerFormatErrorV1`] for malformed artifacts/current graph,
/// invalid reducer joins, or a noncanonical prospective graph.
fn finalize_release_recovery<'record>(
    current_records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
    plan: CompletionMutationPlanV1,
    signed_receipt: SignedSourceReleaseReceiptV1,
) -> Result<FinalizedCompletionV1, LedgerFormatErrorV1> {
    let purpose = plan.purpose.clone();
    if plan.attempt_key.is_some() || plan.release.is_none() {
        return Err(LedgerFormatErrorV1::Corrupt("Release recovery plan"));
    }
    let mut prospective = canonical_graph(current_records)?;
    apply_release_patch(&mut prospective, plan.release.clone(), Some(signed_receipt))?;
    let maximum_tombstones = plan
        .refresh_inventory_tombstones
        .ok_or(LedgerFormatErrorV1::Corrupt("Release recovery inventory"))?;
    refresh_authority_inventory(&mut prospective, maximum_tombstones)?;
    validate_final_graph(&prospective)?;
    crate::validate_prospective_records(
        prospective
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )?;
    let mutations = collect_mutations(plan, prospective)?;
    Ok(FinalizedCompletionV1 {
        purpose,
        mutations,
        response: None,
        method: SourceProviderMethod::Release,
        session_binding: ObjectDigest::from_bytes([0; 32]),
        response_sequence: 0,
    })
}

fn decode_response(
    bytes: &[u8],
) -> Result<(SignedSourceProviderStatusV1, SourceProviderMethod), LedgerFormatErrorV1> {
    if let Ok(value) = decode_acquire_response(bytes) {
        return Ok((value.signed_status().clone(), SourceProviderMethod::Acquire));
    }
    if let Ok(value) = decode_release_response(bytes) {
        return Ok((value.signed_status().clone(), SourceProviderMethod::Release));
    }
    if let Ok(value) = decode_inventory_response(bytes) {
        return Ok((
            value.signed_status().clone(),
            SourceProviderMethod::Inventory,
        ));
    }
    Err(LedgerFormatErrorV1::Corrupt("canonical provider response"))
}

fn response_release_receipt(
    bytes: &[u8],
) -> Result<SignedSourceReleaseReceiptV1, LedgerFormatErrorV1> {
    let response = decode_release_response(bytes)
        .map_err(|_| LedgerFormatErrorV1::Corrupt("Release response"))?;
    let bytes = response
        .signed_receipt()
        .ok_or(LedgerFormatErrorV1::Corrupt("Release receipt"))?;
    SignedSourceReleaseReceiptV1::from_canonical_bytes(bytes)
        .map_err(|_| LedgerFormatErrorV1::Corrupt("Release receipt"))
}

fn response_acquire_receipt(
    bytes: &[u8],
) -> Result<SignedSourceProviderReceiptV1, LedgerFormatErrorV1> {
    let response = decode_acquire_response(bytes)
        .map_err(|_| LedgerFormatErrorV1::Corrupt("Acquire response"))?;
    let bytes = response
        .signed_receipt()
        .ok_or(LedgerFormatErrorV1::Corrupt("Acquire receipt"))?;
    SignedSourceProviderReceiptV1::from_canonical_bytes(bytes)
        .map_err(|_| LedgerFormatErrorV1::Corrupt("Acquire receipt"))
}

fn canonical_graph<'record>(
    records: impl IntoIterator<Item = (&'record [u8], &'record [u8])>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, LedgerFormatErrorV1> {
    let mut graph = BTreeMap::new();
    for (key, value) in records {
        let decoded = decode_record(key, value)?;
        if encode_decoded_record(&decoded) != value
            || graph.insert(key.to_vec(), value.to_vec()).is_some()
        {
            return Err(LedgerFormatErrorV1::Corrupt("noncanonical current graph"));
        }
    }
    Ok(graph)
}

fn synchronize_current_session_history(
    graph: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    attempt: &AttemptRecordV1,
) -> Result<(), LedgerFormatErrorV1> {
    let session = graph
        .iter()
        .find_map(|(key, value)| match decode_record(key, value).ok()? {
            DecodedRecordV1::Session(session)
                if session.provider == attempt.provider
                    && session.holder == attempt.holder
                    && session.session_binding == attempt.session_binding =>
            {
                Some(session)
            }
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt("completion current session"))?;
    let history_key = session_history_key(
        session.provider.authority_id(),
        session.holder.authority_id(),
        session.session_binding,
    );
    graph.insert(history_key, encode_session_history(&session));
    Ok(())
}

fn decode_attempt_from(
    graph: &BTreeMap<Vec<u8>, Vec<u8>>,
    key: &[u8],
) -> Result<AttemptRecordV1, LedgerFormatErrorV1> {
    match decode_record(
        key,
        graph
            .get(key)
            .ok_or(LedgerFormatErrorV1::Corrupt("missing completion attempt"))?,
    )? {
        DecodedRecordV1::Attempt(value) => Ok(value),
        _ => Err(LedgerFormatErrorV1::Corrupt("completion attempt kind")),
    }
}

fn apply_acquire_patch(
    graph: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    patch: AcquireCompletionPatchV1,
    attempt: &AttemptRecordV1,
    signed_lease: Option<SignedSourceExportLeaseV1>,
    signed_receipt: SignedSourceProviderReceiptV1,
) -> Result<(), LedgerFormatErrorV1> {
    let signed_lease = signed_lease.ok_or(LedgerFormatErrorV1::Corrupt("missing signed lease"))?;
    let lease = signed_lease.subject();
    let lease_bytes = signed_lease.to_canonical_bytes();
    let lease_digest = digest_signed_export_lease(&signed_lease);
    let receipt = signed_receipt.subject();
    let mut acquisition = match decode_record(
        &patch.acquisition_key,
        graph
            .get(&patch.acquisition_key)
            .ok_or(LedgerFormatErrorV1::Corrupt("missing acquisition"))?,
    )? {
        DecodedRecordV1::Acquisition(value) => value,
        _ => return Err(LedgerFormatErrorV1::Corrupt("completion acquisition kind")),
    };
    if patch.attempt_digest != attempt.attempt_digest
        || acquisition.provider != *lease.provider()
        || lease.request_id() != attempt.request_id
        || lease.request_digest() != attempt.typed_request_digest
        || signed_lease.signer().authority_id() != acquisition.provider.authority_id()
        || signed_lease.signer().authority_generation()
            != acquisition.provider.authority_generation()
        || signed_lease.signer().authority_digest() != acquisition.provider.authority_digest()
        || acquisition.holder.authority_id() != lease.holder_authority_id()
        || acquisition.holder.authority_generation() != lease.holder_generation()
        || acquisition.holder.authority_digest() != lease.holder_authority_digest()
        || receipt.request_id() != attempt.request_id
        || receipt.request_digest() != attempt.typed_request_digest
        || receipt.acquisition_id() != acquisition.acquisition_id
        || receipt.provider_process_instance() != attempt.provider_process_instance
        || receipt.lease_digest() != lease_digest
        || receipt.signed_export_lease() != lease_bytes
        || receipt.observed_proof_digest() != patch.proof_digest
        || receipt.kernel_boot_id() != patch.source_root.kernel_boot_id()
        || receipt.device() != patch.source_root.device()
        || receipt.inode() != patch.source_root.inode()
        || receipt.unique_mount_id() != patch.source_root.unique_mount_id()
        || signed_receipt.signer().authority_id() != acquisition.provider.authority_id()
        || signed_receipt.signer().authority_generation()
            != acquisition.provider.authority_generation()
        || signed_receipt.signer().authority_digest() != acquisition.provider.authority_digest()
    {
        return Err(LedgerFormatErrorV1::Corrupt("Acquire lease lineage"));
    }
    acquisition.revision =
        acquisition
            .revision
            .checked_add(1)
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "acquisition revision exhausted",
            ))?;
    acquisition.state = ProviderAcquisitionStateV1::Active;
    acquisition.current_attempt_digest = attempt.attempt_digest;
    acquisition.lease_attempt_digest = Some(attempt.attempt_digest);
    if acquisition
        .lease_history
        .last()
        .is_some_and(|prior| prior.issue_generation >= patch.lease_issue_generation)
    {
        return Err(LedgerFormatErrorV1::Corrupt("lease generation regression"));
    }
    acquisition.lease_issue_generation = patch.lease_issue_generation;
    acquisition.lease_id = Some(lease.lease_id());
    acquisition.lease_digest = Some(lease_digest);
    acquisition.lease_history.push(LeaseLineageV1 {
        issue_generation: acquisition.lease_issue_generation,
        lease_id: lease.lease_id(),
        lease_digest,
        attempt_digest: attempt.attempt_digest,
    });
    acquisition.resource_namespace_digest = lease.resource().resource_namespace_digest();
    acquisition.resource_id = lease.resource().resource_id();
    acquisition.resource_generation = lease.resource().resource_generation();
    acquisition.resource_digest = lease.resource().resource_digest();
    acquisition.catalog_generation = lease.resource().catalog_generation();
    acquisition.catalog_digest = lease.resource().catalog_digest();
    acquisition.selection_generation = lease.resource().selection_generation();
    acquisition.selection_digest = lease.resource().selection_digest();
    acquisition.proof_class = lease.proof().capability_bit().trailing_zeros() as u8 + 1;
    acquisition.proof_digest = patch.proof_digest;
    acquisition.resource_commitment = patch.resource_commitment;
    if let Some(bytes) = patch.backend_evidence {
        acquisition.backend_evidence = Some(BackendEvidenceV1::decode(&bytes)?);
    }
    if let Some(bytes) = patch.reopen_identity {
        acquisition.reopen_identity = Some(ReopenIdentityV1::decode(&bytes)?);
    }
    acquisition.source_root = Some(patch.source_root);
    acquisition.signed_lease = lease_bytes;
    graph.insert(patch.acquisition_key, encode_acquisition(&acquisition));
    let authority_key_value = authority_key(acquisition.provider.authority_id());
    let mut authority = match graph
        .get(&authority_key_value)
        .and_then(|bytes| decode_record(&authority_key_value, bytes).ok())
    {
        Some(DecodedRecordV1::Authority(authority)) => authority,
        _ => return Err(LedgerFormatErrorV1::Corrupt("Acquire authority head")),
    };
    if authority.last_lease_issue_generation.checked_add(1) != Some(patch.lease_issue_generation) {
        return Err(LedgerFormatErrorV1::Corrupt(
            "Acquire lease generation head",
        ));
    }
    authority.revision = authority
        .revision
        .checked_add(1)
        .ok_or(LedgerFormatErrorV1::Corrupt("authority revision exhausted"))?;
    authority.inventory_generation =
        authority
            .inventory_generation
            .checked_add(1)
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "inventory generation exhausted",
            ))?;
    authority.last_lease_issue_generation = patch.lease_issue_generation;
    graph.insert(authority_key_value, encode_authority(&authority));
    Ok(())
}

fn apply_release_patch(
    graph: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    patch: Option<ReleaseCompletionPatchV1>,
    signed_receipt: Option<SignedSourceReleaseReceiptV1>,
) -> Result<(), LedgerFormatErrorV1> {
    let patch = patch.ok_or(LedgerFormatErrorV1::Corrupt("missing Release patch"))?;
    let signed_receipt =
        signed_receipt.ok_or(LedgerFormatErrorV1::Corrupt("missing Release receipt"))?;
    let receipt = signed_receipt.subject();
    let mut release = match decode_record(
        &patch.release_key,
        graph
            .get(&patch.release_key)
            .ok_or(LedgerFormatErrorV1::Corrupt("missing Release"))?,
    )? {
        DecodedRecordV1::Release(value) => value,
        _ => return Err(LedgerFormatErrorV1::Corrupt("completion Release kind")),
    };
    let release_attempt = graph
        .iter()
        .find_map(|(key, value)| match decode_record(key, value).ok()? {
            DecodedRecordV1::Attempt(attempt)
                if attempt.attempt_digest == release.attempt_digest =>
            {
                Some(attempt)
            }
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt("Release receipt attempt"))?;
    if release.state != ProviderReleaseStateV1::Intent
        || release.lease_id != receipt.lease_id()
        || release.lease_digest != receipt.lease_digest()
        || release.release_generation != receipt.release_generation()
        || release.provider != *receipt.provider()
        || signed_receipt.signer().authority_id() != release.provider.authority_id()
        || signed_receipt.signer().authority_generation() != release.provider.authority_generation()
        || signed_receipt.signer().authority_digest() != release.provider.authority_digest()
        || receipt.request_id() != release_attempt.request_id
        || receipt.request_digest() != release_attempt.typed_request_digest
        || receipt.provider_process_instance() != release_attempt.provider_process_instance
    {
        return Err(LedgerFormatErrorV1::Corrupt("Release receipt lineage"));
    }
    release.revision = release
        .revision
        .checked_add(1)
        .ok_or(LedgerFormatErrorV1::Corrupt("Release revision exhausted"))?;
    release.state = ProviderReleaseStateV1::Tombstone;
    release.backend_evidence = Some(BackendEvidenceV1::decode(&patch.backend_evidence)?);
    release.release_observation_digest = Some(patch.observation_digest);
    release.released_seconds = Some(patch.released_seconds);
    release.receipt_digest = Some(digest_signed_release_receipt(&signed_receipt));
    release.signed_receipt = signed_receipt.to_canonical_bytes();
    let acquisition_key_value = AcquisitionKeyV1 {
        provider_id: release.provider.authority_id(),
        holder_id: release.holder.authority_id(),
        acquisition_id: release.acquisition_id,
    };
    let acquisition_record_key = acquisition_key(&acquisition_key_value);
    let mut acquisition = match graph
        .get(&acquisition_record_key)
        .and_then(|bytes| decode_record(&acquisition_record_key, bytes).ok())
    {
        Some(DecodedRecordV1::Acquisition(acquisition)) => acquisition,
        _ => return Err(LedgerFormatErrorV1::Corrupt("Release acquisition")),
    };
    if acquisition.state != ProviderAcquisitionStateV1::Releasing
        || acquisition.release_effect_id != Some(release.effect_id)
    {
        return Err(LedgerFormatErrorV1::Corrupt(
            "Release acquisition transition",
        ));
    }
    acquisition.revision =
        acquisition
            .revision
            .checked_add(1)
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "acquisition revision exhausted",
            ))?;
    acquisition.state = ProviderAcquisitionStateV1::Released;
    let acquisition_bytes = encode_acquisition(&acquisition);
    graph.insert(acquisition_record_key, acquisition_bytes.clone());
    release.acquisition_record_digest = record_digest(&acquisition_bytes)?;
    graph.insert(patch.release_key, encode_release(&release));
    let authority_key_value = authority_key(release.provider.authority_id());
    let mut authority = match graph
        .get(&authority_key_value)
        .and_then(|bytes| decode_record(&authority_key_value, bytes).ok())
    {
        Some(DecodedRecordV1::Authority(authority)) => authority,
        _ => return Err(LedgerFormatErrorV1::Corrupt("Release authority head")),
    };
    if authority.last_release_generation != release.release_generation {
        return Err(LedgerFormatErrorV1::Corrupt("Release generation head"));
    }
    authority.revision = authority
        .revision
        .checked_add(1)
        .ok_or(LedgerFormatErrorV1::Corrupt("authority revision exhausted"))?;
    authority.inventory_generation =
        authority
            .inventory_generation
            .checked_add(1)
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "inventory generation exhausted",
            ))?;
    graph.insert(authority_key_value, encode_authority(&authority));
    Ok(())
}

fn refresh_authority_inventory(
    graph: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    maximum_tombstones: usize,
) -> Result<(), LedgerFormatErrorV1> {
    let mut authority = graph
        .iter()
        .find_map(|(key, value)| match decode_record(key, value).ok()? {
            DecodedRecordV1::Authority(authority) => Some(authority),
            _ => None,
        })
        .ok_or(LedgerFormatErrorV1::Corrupt("missing authority"))?;
    let provider_id = authority.provider.authority_id();
    let (digest, count) = super::reducer::inventory_state_digest(
        provider_id,
        authority.catalog_generation,
        authority.catalog_digest,
        graph
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        maximum_tombstones,
    )?;
    authority.inventory_state_digest = digest;
    authority.active_lease_count = count;
    graph.insert(authority_key(provider_id), encode_authority(&authority));
    Ok(())
}

fn validate_final_graph(graph: &BTreeMap<Vec<u8>, Vec<u8>>) -> Result<(), LedgerFormatErrorV1> {
    let mut authority_count = 0_usize;
    let mut attempts = Vec::new();
    let mut acquisitions = Vec::new();
    let mut releases = Vec::new();
    for (key, value) in graph {
        let decoded = decode_record(key, value)?;
        if encode_decoded_record(&decoded) != *value {
            return Err(LedgerFormatErrorV1::Corrupt(
                "noncanonical completion graph",
            ));
        }
        match decoded {
            DecodedRecordV1::Authority(_) => authority_count += 1,
            DecodedRecordV1::Attempt(value) => attempts.push(value),
            DecodedRecordV1::Acquisition(value) => acquisitions.push(value),
            DecodedRecordV1::Release(value) => releases.push(value),
            _ => {}
        }
    }
    if authority_count != 1 {
        return Err(LedgerFormatErrorV1::Corrupt("completion authority head"));
    }
    for acquisition in &acquisitions {
        let attempt = attempts
            .iter()
            .find(|attempt| attempt.attempt_digest == acquisition.current_attempt_digest)
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "completion acquisition attempt",
            ))?;
        super::reducer::validate_acquisition_join(acquisition, attempt)?;
    }
    for release in &releases {
        let acquisition = acquisitions
            .iter()
            .find(|value| value.acquisition_id == release.acquisition_id)
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "completion Release acquisition",
            ))?;
        let attempt = attempts
            .iter()
            .find(|value| value.attempt_digest == release.attempt_digest)
            .ok_or(LedgerFormatErrorV1::Corrupt("completion Release attempt"))?;
        super::reducer::validate_release_join(acquisition, release, attempt)?;
        let key = acquisition_key(&AcquisitionKeyV1 {
            provider_id: release.provider.authority_id(),
            holder_id: release.holder.authority_id(),
            acquisition_id: release.acquisition_id,
        });
        let acquisition_digest = graph
            .get(&key)
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "completion Release acquisition bytes",
            ))
            .and_then(|bytes| record_digest(bytes))?;
        if release.state == ProviderReleaseStateV1::Tombstone
            && release.acquisition_record_digest != acquisition_digest
        {
            return Err(LedgerFormatErrorV1::Corrupt(
                "completion Release acquisition digest",
            ));
        }
    }
    Ok(())
}

fn collect_mutations(
    plan: CompletionMutationPlanV1,
    graph: BTreeMap<Vec<u8>, Vec<u8>>,
) -> Result<Vec<(Vec<u8>, Option<Vec<u8>>)>, LedgerFormatErrorV1> {
    let completion_attempt_key = plan.attempt_key.clone();
    let method = plan.method;
    let refreshes_inventory = plan.refresh_inventory_tombstones.is_some();
    let release_key_value = plan.release.as_ref().map(|value| value.release_key.clone());
    let mut keys = Vec::new();
    keys.extend(plan.attempt_key);
    keys.extend(plan.acquire.map(|value| value.acquisition_key));
    keys.extend(plan.release.map(|value| value.release_key));
    if let Some(attempt_key) = completion_attempt_key.as_deref() {
        let attempt = decode_attempt_from(&graph, attempt_key)?;
        keys.push(session_key(
            attempt.provider.authority_id(),
            attempt.holder.authority_id(),
        ));
        keys.push(session_history_key(
            attempt.provider.authority_id(),
            attempt.holder.authority_id(),
            attempt.session_binding,
        ));
        if method == SourceProviderMethod::Acquire {
            let acquisition_key = graph
                .iter()
                .find_map(|(key, value)| match decode_record(key, value).ok()? {
                    DecodedRecordV1::Acquisition(acquisition)
                        if acquisition.provider == attempt.provider
                            && acquisition.holder == attempt.holder
                            && acquisition.current_attempt_digest == attempt.attempt_digest =>
                    {
                        Some(key.clone())
                    }
                    _ => None,
                })
                .ok_or(LedgerFormatErrorV1::Corrupt(
                    "completion acquisition mutation",
                ))?;
            keys.push(acquisition_key);
        }
    }
    if let Some(release_key) = release_key_value {
        let release = match graph
            .get(&release_key)
            .and_then(|bytes| decode_record(&release_key, bytes).ok())
        {
            Some(DecodedRecordV1::Release(release)) => release,
            _ => return Err(LedgerFormatErrorV1::Corrupt("completion Release mutation")),
        };
        keys.push(acquisition_key(&AcquisitionKeyV1 {
            provider_id: release.provider.authority_id(),
            holder_id: release.holder.authority_id(),
            acquisition_id: release.acquisition_id,
        }));
    }
    if refreshes_inventory {
        let key = graph
            .iter()
            .find_map(|(key, value)| {
                matches!(decode_record(key, value), Ok(DecodedRecordV1::Authority(_)))
                    .then(|| key.clone())
            })
            .ok_or(LedgerFormatErrorV1::Corrupt(
                "completion authority mutation",
            ))?;
        keys.push(key);
    }
    keys.sort();
    keys.dedup();
    let mut mutations = Vec::with_capacity(keys.len());
    for key in keys {
        mutations.push((key.clone(), graph.get(&key).cloned()));
    }
    Ok(mutations)
}
