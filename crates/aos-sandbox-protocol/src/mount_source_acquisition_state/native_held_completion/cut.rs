//! Native-only immutable admission and disposition companion cuts.
//!
//! Cuts reproduce historical canonical bytes. They do not assert that those
//! bytes still occupy today's legacy keys and cannot supply a protected writer,
//! signer, clock, socket or manager hold.
//!
//! ```text
//! AOSMNC01 | version:u16=1 | kind:u8 | attempt_state:u8 | reserved[4] |
//! capture_transaction[16] | original_session_RecordRef[72] |
//! original_attempt_revision:u64 | original_attempt_digest[32] |
//! head_length:u32 | acquisition_witness_length:u32 |
//! canonical_Head_JSON | canonical_AcquisitionPredecessorWitness_JSON
//! ```
//!
//! Draft tag6 captures only consumed Pending revision2 in a Disposition cut;
//! tags1 through5 and their existing encodings remain unchanged.

use std::collections::BTreeMap;

use aos_sandbox_source_provider_protocol::native_held_completion::witness::{
    NativeHeldByteWitnessV1, NativeHeldRecordFamilyV1 as Family, native_held_record_byte_digest_v1,
};
use serde::{Serialize, de::DeserializeOwned};

use super::codec::Reader;
use crate::mount_source_acquisition_state::{
    AcquisitionPredecessorWitnessV2, AcquisitionRecoveryV2, MountSourceAcquisitionStateV2,
    ProviderAttemptStateV2, ProviderIntentV2, ProviderMethodV2, ProviderQueryOwnerV2,
    ProviderStatusV2, RecordRefV2, RecoveryResolutionV2, Result, SourceAcquisitionPhaseV2,
    SourceAcquisitionRowV2, SourceProviderHeadV2, SourceProviderQueryAttemptV2,
    SourceProviderSessionV2, StoredRecordV2, encode_mount_source_state_record_v2,
    format::state_error, record_digest,
};

/// Bounds the complete native cut, including both canonical typed JSON bodies.
pub const MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1: usize = 24_728;

/// Bounds a canonical native cut's complete typed provider Head body.
pub const MAXIMUM_ROOT_NATIVE_CUT_HEAD_BYTES_V1: usize = 8_192;

/// Bounds the closed PendingQuery acquisition predecessor projection.
pub const MAXIMUM_ROOT_NATIVE_CUT_ACQUISITION_BYTES_V1: usize = 16_384;

const CUT_HEADER_BYTES: usize = 152;

const _: () = assert!(
    MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1
        == CUT_HEADER_BYTES
            + MAXIMUM_ROOT_NATIVE_CUT_HEAD_BYTES_V1
            + MAXIMUM_ROOT_NATIVE_CUT_ACQUISITION_BYTES_V1
);

/// Names the distinct atomic owner append captured by a native cut.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootNativeCutKindV1 {
    /// Captures the post-reservation legacy companions of original Root1.
    Admission,
    /// Captures the original companions in the first irreversible R append.
    Disposition,
}

impl RootNativeCutKindV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Admission => 1,
            Self::Disposition => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AttemptCutState {
    Reserved,
    Complete,
    AbandonedUnresolved,
    Superseded,
    AbandonedResolved,
    Pending,
}

impl AttemptCutState {
    const fn tag(self) -> u8 {
        match self {
            Self::Reserved => 1,
            Self::Complete => 2,
            Self::AbandonedUnresolved => 3,
            Self::Superseded => 4,
            Self::AbandonedResolved => 5,
            Self::Pending => 6,
        }
    }

    const fn revision(self) -> u64 {
        match self {
            Self::Reserved => 1,
            Self::Complete | Self::AbandonedUnresolved | Self::Superseded | Self::Pending => 2,
            Self::AbandonedResolved => 3,
        }
    }

    fn from_state(state: &ProviderAttemptStateV2) -> Result<Self> {
        match state {
            ProviderAttemptStateV2::Reserved => Ok(Self::Reserved),
            ProviderAttemptStateV2::DispositionConsumed {
                status: ProviderStatusV2::Complete,
                ..
            } => Ok(Self::Complete),
            ProviderAttemptStateV2::DispositionConsumed {
                status: ProviderStatusV2::Pending,
                signed_result,
                ..
            } if signed_result.is_empty() => Ok(Self::Pending),
            ProviderAttemptStateV2::AbandonedIndeterminate {
                resolution: None, ..
            } => Ok(Self::AbandonedUnresolved),
            ProviderAttemptStateV2::SupersededIndeterminate { .. } => Ok(Self::Superseded),
            ProviderAttemptStateV2::AbandonedIndeterminate {
                resolution: Some(RecoveryResolutionV2::RetryAcquireSameIntent { .. }),
                ..
            } => Ok(Self::AbandonedResolved),
            _ => Err(state_error("native cut unsupported original attempt state")),
        }
    }
}

/// Retains a compact historical companion cut as nonauthorizing data.
///
/// Capture and decoding return only data; the nominated transaction must still
/// be joined to the actual complete graph and exact atomic owner proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeCutV1 {
    kind: RootNativeCutKindV1,
    attempt_state: AttemptCutState,
    capture_transaction: [u8; 16],
    original_session: RecordRefV2,
    original_attempt_revision: u64,
    original_attempt_digest: [u8; 32],
    head: SourceProviderHeadV2,
    acquisition: AcquisitionPredecessorWitnessV2,
}

/// Holds reconstructed historical records and their exact canonical witnesses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootNativeReconstructedCutV1 {
    pub(super) session: SourceProviderSessionV2,
    pub(super) attempt: SourceProviderQueryAttemptV2,
    pub(super) acquisition: SourceAcquisitionRowV2,
    pub(super) head: SourceProviderHeadV2,
    canonical: BTreeMap<Vec<u8>, Vec<u8>>,
    witnesses: [NativeHeldByteWitnessV1; 4],
}

impl RootNativeReconstructedCutV1 {
    /// Returns exact historical canonical Session, Attempt, Acquisition and Head.
    #[must_use]
    pub fn canonical_records(&self) -> &BTreeMap<Vec<u8>, Vec<u8>> {
        &self.canonical
    }

    /// Returns historical witnesses in the fixed Root family order.
    #[must_use]
    pub const fn witnesses(&self) -> &[NativeHeldByteWitnessV1; 4] {
        &self.witnesses
    }
}

impl RootNativeCutV1 {
    /// Returns the original owning-append classification.
    #[must_use]
    pub const fn kind(&self) -> RootNativeCutKindV1 {
        self.kind
    }

    /// Identifies the exact draft tag6 consumed-Pending disposition DATA.
    #[must_use]
    pub fn is_pending_disposition(&self) -> bool {
        self.kind == RootNativeCutKindV1::Disposition
            && self.attempt_state == AttemptCutState::Pending
    }

    /// Returns the capture proposal's actual transaction identity as data.
    #[must_use]
    pub const fn capture_transaction(&self) -> [u8; 16] {
        self.capture_transaction
    }

    /// Returns the immutable original Session reference.
    #[must_use]
    pub const fn original_session(&self) -> RecordRefV2 {
        self.original_session
    }

    /// Returns the exact original Attempt stamp at capture.
    #[must_use]
    pub fn original_attempt(&self, attempt_id: [u8; 32]) -> RecordRefV2 {
        RecordRefV2 {
            id: attempt_id,
            revision: self.original_attempt_revision,
            record_digest: self.original_attempt_digest,
        }
    }

    /// Returns the complete captured canonical Head body.
    #[must_use]
    pub const fn head(&self) -> &SourceProviderHeadV2 {
        &self.head
    }

    /// Returns the captured closed PendingQuery acquisition projection.
    #[must_use]
    pub const fn acquisition(&self) -> &AcquisitionPredecessorWitnessV2 {
        &self.acquisition
    }

    /// Captures exact canonical companions as nonauthorizing historical DATA.
    ///
    /// This reconstructs and compares the selected companions, but does not
    /// validate an arbitrary caller-supplied whole legacy graph or prove a
    /// committed atomic capture. The complete graph and native owner reducer
    /// must independently validate the actual before/after transition.
    ///
    /// # Errors
    ///
    /// Rejects absent originals, unsupported capture/state shapes, prohibited
    /// fields, noncanonical companions or captured digest/bound mismatches.
    pub fn capture(
        kind: RootNativeCutKindV1,
        capture_transaction: [u8; 16],
        legacy: &MountSourceAcquisitionStateV2,
        attempt_id: [u8; 32],
    ) -> Result<Self> {
        let attempt = legacy
            .provider_attempts
            .get(&attempt_id)
            .ok_or_else(|| state_error("native cut original Attempt absent"))?;
        let session = legacy
            .provider_sessions
            .get(&attempt.session_id)
            .filter(|session| session.record_digest == attempt.session_record_digest)
            .ok_or_else(|| state_error("native cut original Session absent"))?;
        let row = legacy
            .acquisitions
            .get(&attempt.owner.owner_id())
            .ok_or_else(|| state_error("native cut original Acquisition absent"))?;
        let head = legacy
            .provider_heads
            .get(&(
                attempt.scope.holder_authority_id,
                attempt.scope.provider_authority_id,
            ))
            .ok_or_else(|| state_error("native cut original Head absent"))?;
        if row.mount_release_request.is_some() || row.release_inventory_fence.is_some() {
            return Err(state_error(
                "native cut cannot omit Release request or fence bytes",
            ));
        }

        let value = Self {
            kind,
            attempt_state: AttemptCutState::from_state(&attempt.state)?,
            capture_transaction,
            original_session: RecordRefV2 {
                id: session.session_id,
                revision: session.revision,
                record_digest: session.record_digest,
            },
            original_attempt_revision: attempt.revision,
            original_attempt_digest: attempt.record_digest,
            head: head.clone(),
            acquisition: acquisition_projection(row),
        };
        let reconstructed = value.reconstruct(legacy, attempt_id)?;
        for (key, bytes) in reconstructed.canonical_records() {
            let actual = match crate::mount_source_acquisition_state::key_kind(key)? {
                crate::mount_source_acquisition_state::RecordKindV2::ProviderSession => {
                    StoredRecordV2::ProviderSession {
                        value: session.clone(),
                    }
                }
                crate::mount_source_acquisition_state::RecordKindV2::ProviderQueryAttempt => {
                    StoredRecordV2::ProviderQueryAttempt {
                        value: attempt.clone(),
                    }
                }
                crate::mount_source_acquisition_state::RecordKindV2::Acquisition => {
                    StoredRecordV2::Acquisition { value: row.clone() }
                }
                crate::mount_source_acquisition_state::RecordKindV2::ProviderHead => {
                    StoredRecordV2::ProviderHead {
                        value: head.clone(),
                    }
                }
                _ => return Err(state_error("native cut unexpected companion family")),
            };
            if encode_mount_source_state_record_v2(&actual)?.1 != *bytes {
                return Err(state_error(
                    "native cut capture is not the actual legacy successor",
                ));
            }
        }
        Ok(value)
    }

    /// Encodes only the fixed native cut and bounded canonical typed bodies.
    ///
    /// # Errors
    ///
    /// Rejects unknown phase shapes, sentinel stamps, prohibited acquisition
    /// fields or typed JSON bodies beyond their independent fixed bounds.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let head = canonical_json(&self.head, MAXIMUM_ROOT_NATIVE_CUT_HEAD_BYTES_V1)?;
        let acquisition = canonical_json(
            &self.acquisition,
            MAXIMUM_ROOT_NATIVE_CUT_ACQUISITION_BYTES_V1,
        )?;
        let mut bytes = b"AOSMNC01".to_vec();
        bytes.extend_from_slice(&[0, 1, self.kind.tag(), self.attempt_state.tag(), 0, 0, 0, 0]);
        bytes.extend_from_slice(&self.capture_transaction);
        bytes.extend_from_slice(&self.original_session.id);
        bytes.extend_from_slice(&self.original_session.revision.to_be_bytes());
        bytes.extend_from_slice(&self.original_session.record_digest);
        bytes.extend_from_slice(&self.original_attempt_revision.to_be_bytes());
        bytes.extend_from_slice(&self.original_attempt_digest);
        bytes.extend_from_slice(&(head.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(acquisition.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&head);
        bytes.extend_from_slice(&acquisition);
        if bytes.len() > MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1 {
            return Err(state_error("native cut complete byte limit"));
        }
        Ok(bytes)
    }

    /// Decodes a canonical native cut without constructing an owning proof.
    ///
    /// # Errors
    ///
    /// Rejects wrong magic/version/tags, reserved bytes, malformed or
    /// noncanonical typed JSON, overflowing lengths and bytes past the end.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1 {
            return Err(state_error("native cut complete byte limit"));
        }
        let mut reader = Reader::new(bytes);
        if reader.bytes(8)? != b"AOSMNC01" || reader.bytes(2)? != [0, 1] {
            return Err(state_error("native cut magic/version"));
        }
        let kind = match reader.array::<1>()?[0] {
            1 => RootNativeCutKindV1::Admission,
            2 => RootNativeCutKindV1::Disposition,
            _ => return Err(state_error("native cut kind")),
        };
        let attempt_state = match reader.array::<1>()?[0] {
            1 => AttemptCutState::Reserved,
            2 => AttemptCutState::Complete,
            3 => AttemptCutState::AbandonedUnresolved,
            4 => AttemptCutState::Superseded,
            5 => AttemptCutState::AbandonedResolved,
            6 => AttemptCutState::Pending,
            _ => return Err(state_error("native cut Attempt state")),
        };
        if reader.bytes(4)? != [0; 4] {
            return Err(state_error("native cut reserved bytes"));
        }
        let capture_transaction = reader.array()?;
        let original_session = RecordRefV2 {
            id: reader.array()?,
            revision: u64::from_be_bytes(reader.array()?),
            record_digest: reader.array()?,
        };
        let original_attempt_revision = u64::from_be_bytes(reader.array()?);
        let original_attempt_digest = reader.array()?;
        let head_length = reader.u32()?;
        let acquisition_length = reader.u32()?;
        if head_length > MAXIMUM_ROOT_NATIVE_CUT_HEAD_BYTES_V1
            || acquisition_length > MAXIMUM_ROOT_NATIVE_CUT_ACQUISITION_BYTES_V1
        {
            return Err(state_error("native cut nested body bound"));
        }
        let head = decode_json(reader.bytes(head_length)?)?;
        let acquisition = decode_json(reader.bytes(acquisition_length)?)?;
        reader.finish()?;
        let value = Self {
            kind,
            attempt_state,
            capture_transaction,
            original_session,
            original_attempt_revision,
            original_attempt_digest,
            head,
            acquisition,
        };
        if value.to_canonical_bytes()? != bytes {
            return Err(state_error("native cut canonical roundtrip"));
        }
        Ok(value)
    }

    /// Reconstructs exact historical bytes from retained immutable originals.
    ///
    /// The caller independently validates today's entire legacy graph before
    /// using this historical data. Reconstructed digests are compared against
    /// captured stamps; no mismatching record is restamped with `seal_record`.
    ///
    /// # Errors
    ///
    /// Rejects missing originals, unsupported state ancestry, changed immutable
    /// intent/lineage, captured self-digest mismatch or canonical byte overflow.
    pub fn reconstruct(
        &self,
        legacy: &MountSourceAcquisitionStateV2,
        attempt_id: [u8; 32],
    ) -> Result<RootNativeReconstructedCutV1> {
        self.validate_shape()?;
        let session = legacy
            .provider_sessions
            .get(&self.original_session.id)
            .filter(|session| {
                session.revision == self.original_session.revision
                    && session.record_digest == self.original_session.record_digest
            })
            .ok_or_else(|| state_error("native cut exact original Session absent"))?
            .clone();
        let current_attempt = legacy
            .provider_attempts
            .get(&attempt_id)
            .ok_or_else(|| state_error("native cut retained original Attempt absent"))?;
        if current_attempt.method != ProviderMethodV2::Acquire
            || current_attempt.attempt_number != 1
            || current_attempt.previous_attempt_id.is_some()
            || current_attempt.lineage_root_attempt_id != attempt_id
            || current_attempt.session_id != session.session_id
            || current_attempt.session_record_digest != session.record_digest
            || current_attempt.scope != session.scope
            || current_attempt.owner
                != (ProviderQueryOwnerV2::Acquire {
                    acquisition_id: self.acquisition.acquisition_id,
                })
        {
            return Err(state_error("native cut original immutable Attempt lineage"));
        }
        let mut attempt = current_attempt.clone();
        attempt.state = historical_state(self.attempt_state, current_attempt)?;
        attempt.revision = self.original_attempt_revision;
        attempt.record_digest = self.original_attempt_digest;
        let ProviderIntentV2::Acquire { value: intent } = &attempt.intent else {
            return Err(state_error("native cut original Acquire intent"));
        };
        let witness = &self.acquisition;
        let reference = self.original_attempt(attempt_id);
        if witness.scope != session.scope
            || witness.provider_acquisition
                != attempt
                    .provider_acquisition
                    .ok_or_else(|| state_error("native cut provider acquisition absent"))?
            || witness.acquire_intent_digest != attempt.immutable_intent_digest
            || witness.acquire_lineage.root != reference
            || witness.acquire_lineage.tail != reference
            || witness.acquire_lineage.next_attempt_number != 2
            || self.head.scope != session.scope
            || intent.acquisition_id != witness.acquisition_id
            || intent.scope != witness.scope
            || intent.assignment != witness.assignment
            || intent.mount_plan_digest != witness.mount_plan_digest
            || intent.ownership_lease_digest != witness.ownership_lease_digest
            || intent.prospective_mount_template_digest != witness.prospective_mount_template_digest
            || intent.source_binding_digest != witness.source_binding_digest
        {
            return Err(state_error(
                "native cut captured original intent or references changed",
            ));
        }
        match self.attempt_state {
            AttemptCutState::Reserved => {
                if self.head.pending_attempt != Some(reference)
                    || witness.recovery != AcquisitionRecoveryV2::Ready
                    || witness.acquire_terminal_attempt.is_some()
                    || witness.evidence.is_some()
                {
                    return Err(state_error("native cut original Reserved companions"));
                }
            }
            AttemptCutState::Complete => {
                if self.head.pending_attempt.is_some()
                    || witness.acquire_terminal_attempt != Some(reference)
                    || witness.recovery != AcquisitionRecoveryV2::Ready
                    || witness
                        .evidence
                        .as_ref()
                        .is_none_or(|evidence| evidence.acquire_attempt != reference)
                {
                    return Err(state_error("native cut original Complete companions"));
                }
            }
            // The decoder and reconstruction share the same closed tag6 shape.
            AttemptCutState::Pending => {}
            AttemptCutState::AbandonedUnresolved => {
                if witness.acquire_terminal_attempt.is_some()
                    || witness.evidence.is_some()
                    || witness.recovery
                        != (AcquisitionRecoveryV2::InventoryRequired {
                            root_attempt: reference,
                        })
                    || self
                        .head
                        .recovery_barrier
                        .as_ref()
                        .is_none_or(|barrier| barrier.root_attempt != reference)
                {
                    return Err(state_error("native cut original unresolved companions"));
                }
            }
            AttemptCutState::Superseded => {
                if witness.acquire_terminal_attempt.is_some()
                    || witness.evidence.is_some()
                    || witness.recovery != AcquisitionRecoveryV2::Ready
                    || self.head.recovery_barrier.is_some()
                {
                    return Err(state_error("native cut original superseded companions"));
                }
            }
            AttemptCutState::AbandonedResolved => {
                if witness.acquire_terminal_attempt.is_some()
                    || witness.evidence.is_some()
                    || witness.recovery
                        != (AcquisitionRecoveryV2::RetryPermitted {
                            root_attempt: reference,
                        })
                    || self.head.recovery_barrier.is_some()
                {
                    return Err(state_error("native cut exact absent-Inventory companions"));
                }
            }
        }
        let acquisition = reconstruct_acquisition(witness, intent);
        let records = [
            (
                Family::RootSession,
                StoredRecordV2::ProviderSession {
                    value: session.clone(),
                },
                session.record_digest,
            ),
            (
                Family::RootAttempt,
                StoredRecordV2::ProviderQueryAttempt {
                    value: attempt.clone(),
                },
                self.original_attempt_digest,
            ),
            (
                Family::RootAcquisition,
                StoredRecordV2::Acquisition {
                    value: acquisition.clone(),
                },
                witness.record.record_digest,
            ),
            (
                Family::RootHead,
                StoredRecordV2::ProviderHead {
                    value: self.head.clone(),
                },
                self.head.record_digest,
            ),
        ];
        let mut canonical = BTreeMap::new();
        let mut witnesses = Vec::with_capacity(4);
        for (family, record, captured_digest) in records {
            if record_digest(&record)? != captured_digest {
                return Err(state_error("native cut captured self-digest mismatch"));
            }
            let (key, value) = encode_mount_source_state_record_v2(&record)?;
            let digest = native_held_record_byte_digest_v1(family, &key, &value)
                .map_err(|_| state_error("native cut canonical byte witness digest"))?;
            witnesses.push(
                NativeHeldByteWitnessV1::new(family, key.clone(), digest)
                    .map_err(|_| state_error("native cut canonical witness key"))?,
            );
            canonical.insert(key, value);
        }
        Ok(RootNativeReconstructedCutV1 {
            session,
            attempt,
            acquisition,
            head: self.head.clone(),
            canonical,
            witnesses: witnesses
                .try_into()
                .map_err(|_| state_error("native cut witness count"))?,
        })
    }

    fn validate_shape(&self) -> Result<()> {
        let witness = &self.acquisition;
        if self.capture_transaction == [0; 16]
            || self.original_session.id == [0; 32]
            || self.original_session.revision == 0
            || self.original_session.record_digest == [0; 32]
            || self.original_attempt_revision != self.attempt_state.revision()
            || self.original_attempt_digest == [0; 32]
            || (self.kind == RootNativeCutKindV1::Admission
                && self.attempt_state != AttemptCutState::Reserved)
            || witness.record.id != witness.acquisition_id
            || witness.record.revision == 0
            || witness.record.record_digest == [0; 32]
            || witness.phase != SourceAcquisitionPhaseV2::PendingQuery
            || witness.release.is_some()
            || witness.release_authority.is_some()
            || witness.release_from_phase.is_some()
            || witness.release_intent_digest.is_some()
            || witness.release_lineage.is_some()
            || witness.release_terminal_attempt.is_some()
            || witness.release_inventory_fence.is_some()
            || witness.manager_custody.is_some()
            || witness.manager_custody_loss.is_some()
            || witness.descriptor_custody_digest.is_some()
            || witness.positive_custody_digest.is_some()
            || witness.consumption.is_some()
            || witness.release_proof.is_some()
            || witness.negative_custody_digest.is_some()
            || witness.faulted_from.is_some()
            || witness.fault_digest.is_some()
            || witness.retained_faulted_from.is_some()
            || witness.retained_fault_digest.is_some()
            || matches!(witness.recovery, AcquisitionRecoveryV2::Conflict { .. })
        {
            return Err(state_error("native cut closed shape or captured stamp"));
        }
        // Tag6 captures consumed original Pending, not a generic recovery
        // snapshot. Enforce its shape during decoding as well as reconstruction.
        let pending_reference = RecordRefV2 {
            id: witness.acquire_lineage.root.id,
            revision: self.original_attempt_revision,
            record_digest: self.original_attempt_digest,
        };
        if self.attempt_state == AttemptCutState::Pending
            && (self.kind != RootNativeCutKindV1::Disposition
                || self.head.pending_attempt.is_some()
                || self.head.recovery_barrier.is_some()
                || self.head.next_request_sequence != self.head.next_response_sequence
                || witness.acquire_terminal_attempt.is_some()
                || witness.evidence.is_some()
                || pending_reference.id == [0; 32]
                || witness.acquire_lineage.root != pending_reference
                || witness.acquire_lineage.tail != pending_reference
                || witness.acquire_lineage.next_attempt_number != 2
                || witness.recovery != AcquisitionRecoveryV2::Ready)
        {
            return Err(state_error("native cut original Pending companions"));
        }
        Ok(())
    }
}

fn historical_state(
    tag: AttemptCutState,
    current: &SourceProviderQueryAttemptV2,
) -> Result<ProviderAttemptStateV2> {
    if tag == AttemptCutState::Reserved {
        return Ok(ProviderAttemptStateV2::Reserved);
    }
    // Pending is retained original response custody DATA, never a projection
    // through a later no-dispatch settlement or another consumed status.
    if tag == AttemptCutState::Pending {
        if current.revision != 2 || AttemptCutState::from_state(&current.state)? != tag {
            return Err(state_error("native cut exact retained Pending2 absent"));
        }
        return Ok(current.state.clone());
    }
    let retained = match &current.state {
        ProviderAttemptStateV2::NativeNoDispatchSettled { prior_state, .. } => prior_state.as_ref(),
        state => state,
    };
    let mut historical = retained.clone();
    if tag == AttemptCutState::AbandonedUnresolved {
        if let ProviderAttemptStateV2::AbandonedIndeterminate { resolution, .. } = &mut historical {
            // The fully checked current graph proves the retained resolution.
            // Only this closed original unresolved projection removes it.
            *resolution = None;
        }
    }
    if AttemptCutState::from_state(&historical)? != tag {
        return Err(state_error(
            "native cut unavailable exact original state ancestry",
        ));
    }
    Ok(historical)
}

fn canonical_json<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| state_error("native cut typed JSON encode"))?;
    if bytes.len() > maximum {
        return Err(state_error("native cut typed JSON byte limit"));
    }
    Ok(bytes)
}

fn decode_json<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value =
        serde_json::from_slice(bytes).map_err(|_| state_error("native cut typed JSON decode"))?;
    if serde_json::to_vec(&value).map_err(|_| state_error("native cut typed JSON encode"))? != bytes
    {
        return Err(state_error("native cut noncanonical typed JSON"));
    }
    Ok(value)
}

fn acquisition_projection(row: &SourceAcquisitionRowV2) -> AcquisitionPredecessorWitnessV2 {
    AcquisitionPredecessorWitnessV2 {
        record: RecordRefV2 {
            id: row.acquisition_id,
            revision: row.revision,
            record_digest: row.record_digest,
        },
        acquisition_id: row.acquisition_id,
        provider_acquisition: row.provider_acquisition,
        phase: row.phase,
        scope: row.scope,
        acquire: row.acquire,
        acquire_intent_digest: row.acquire_intent_digest,
        acquire_lineage: row.acquire_lineage.clone(),
        acquire_terminal_attempt: row.acquire_terminal_attempt,
        release: row.release,
        release_authority: row.release_authority,
        release_from_phase: row.release_from_phase,
        release_intent_digest: row.release_intent_digest,
        release_lineage: row.release_lineage.clone(),
        release_terminal_attempt: row.release_terminal_attempt,
        release_inventory_fence: None,
        assignment: row.assignment,
        prospective_mount_template_digest: row.prospective_mount_template_digest,
        source_binding_digest: row.source_binding_digest,
        mount_plan_digest: row.mount_plan_digest,
        ownership_lease_digest: row.ownership_lease_digest,
        evidence: row.evidence.clone(),
        manager_custody: row.manager_custody,
        manager_custody_loss: row.manager_custody_loss,
        descriptor_custody_digest: row.descriptor_custody_digest,
        positive_custody_digest: row.positive_custody_digest,
        consumption: row.consumption.clone(),
        release_proof: row.release_proof.clone(),
        negative_custody_digest: row.negative_custody_digest,
        faulted_from: row.faulted_from,
        fault_digest: row.fault_digest,
        retained_faulted_from: row.retained_faulted_from,
        retained_fault_digest: row.retained_fault_digest,
        recovery: row.recovery.clone(),
    }
}

fn reconstruct_acquisition(
    witness: &AcquisitionPredecessorWitnessV2,
    intent: &crate::mount_source_acquisition_state::AcquireIntentV2,
) -> SourceAcquisitionRowV2 {
    SourceAcquisitionRowV2 {
        acquisition_id: witness.acquisition_id,
        provider_acquisition: witness.provider_acquisition,
        revision: witness.record.revision,
        phase: witness.phase,
        scope: witness.scope,
        acquire: witness.acquire,
        mount_acquire_request: intent.mount_request.clone(),
        acquire_intent_digest: witness.acquire_intent_digest,
        acquire_lineage: witness.acquire_lineage.clone(),
        acquire_terminal_attempt: witness.acquire_terminal_attempt,
        release: None,
        mount_release_request: None,
        release_authority: None,
        release_from_phase: None,
        release_intent_digest: None,
        release_lineage: None,
        release_terminal_attempt: None,
        release_inventory_fence: None,
        assignment: witness.assignment,
        prospective_mount_template: intent.prospective_mount_template.clone(),
        prospective_mount_template_digest: witness.prospective_mount_template_digest,
        source_binding: intent.source_binding.clone(),
        source_binding_digest: witness.source_binding_digest,
        mount_plan_digest: witness.mount_plan_digest,
        ownership_lease_digest: witness.ownership_lease_digest,
        evidence: witness.evidence.clone(),
        manager_custody: None,
        manager_custody_loss: None,
        descriptor_custody_digest: None,
        positive_custody_digest: None,
        consumption: None,
        release_proof: None,
        negative_custody_digest: None,
        faulted_from: None,
        fault_digest: None,
        retained_faulted_from: None,
        retained_fault_digest: None,
        recovery: witness.recovery.clone(),
        record_digest: witness.record.record_digest,
    }
}
