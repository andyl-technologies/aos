//! Preserves actual historical native demand beneath its original archive owner.
//!
//! These fixed numeric fields are DATA from the already admitted cold validator.
//! They are not the whole Source cold sum, a native allocation receipt, a signed
//! Prepare, model/Commit permission or an installed restoration action.

use crucible_node_provider::protocol_snapshot::owned11::{
    native::outer::NativeOwnedProtocol11AllocationDemand, outer::OwnedProtocol11DataLimits,
};

#[path = "complete_original_restoration_data/history.rs"]
mod history;

/// Retains one verified owner's detailed native-after demand without decoder banks.
///
/// Construction is crate-private and the archive validation scope accepts a row
/// only for its actual owner pointer. The Source retains the fixed row by owner
/// index; its native ticket lends that same row without decoding another graph.
/// A later installed window must still count actual fresh owners, all six input
/// banks, model/Control, mapping, proof/response/Commit and currentness phases.
#[derive(Clone, Copy)]
pub struct CompleteOriginalNativeRestorationData {
    native: NativeOwnedProtocol11AllocationDemand,
    limits: OwnedProtocol11DataLimits,
    input_lengths: [usize; 5],
    reference_identities: [[u8; 32]; 5],
    source_cold_requested_bytes: usize,
    mapping_reference_clone_bytes: usize,
    selected_owner: Option<crucible_node_provider::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreOwnerValidationStorage>,
    archived_validation: Option<CompleteOriginalArchivedValidationConstructionData>,
}

impl CompleteOriginalNativeRestorationData {
    /// Names fixed full-reference association views before the data walk.
    ///
    /// The hash is private correspondence DATA, not a protocol digest or issuer.
    pub fn reference_counter_scratch_data() -> usize {
        std::mem::size_of::<blake3::Hasher>()
            + std::mem::size_of::<[[u8; 32]; 5]>()
            + std::mem::size_of::<[&crucible_node_contract::ContentRef; 5]>()
            + std::mem::size_of::<[&str; 4]>()
            + std::mem::size_of::<std::array::IntoIter<&str, 4>>()
            + 2 * std::mem::size_of::<[u8; 8]>()
            + std::mem::size_of::<blake3::Hash>()
    }

    /// Compares all five original roles against their validated full references.
    ///
    /// Identity includes algorithm/domain/digest, media type and complete length;
    /// equal-length or equal-payload references cannot be substituted between
    /// roles. The actual source ticket lends this privately constructed row.
    ///
    /// # Errors
    /// Refuses another full reference, role order or complete extent.
    pub fn authenticate_original_references_data(
        &self,
        references: [&crucible_node_contract::ContentRef; 5],
    ) -> Result<(), crate::node_contract::RuntimeError> {
        if references.map(reference_identity) != self.reference_identities {
            return Err(crate::node_contract::RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Bounds the two actual full references copied into the future mapping.
    ///
    /// This is independently retained cold-validator DATA. It excludes the
    /// authority clone, identity Rc, mapping root and normalization output.
    pub fn mapping_reference_clone_bytes_data(&self) -> usize {
        self.mapping_reference_clone_bytes
    }

    /// Borrows the complete recorded native-after allocation demand as DATA.
    pub fn native_demand_data(&self) -> &NativeOwnedProtocol11AllocationDemand {
        &self.native
    }

    /// Returns the actual limits used by that original complete native decoder.
    pub fn native_decoder_limits_data(&self) -> OwnedProtocol11DataLimits {
        self.limits
    }

    /// Returns the separate whole Source cold-reconstruction DATA bound.
    ///
    /// This is the original known_requested calculation, explicitly distinct
    /// from native demand. A later action counts its own current owners beside
    /// any new cold reconstruction; this number is not native allocation credit.
    pub fn source_cold_construction_requested_bytes_data(&self) -> usize {
        self.source_cold_requested_bytes
    }

    /// Borrows the selected raw owner/model DATA row when a complete row fitted.
    ///
    /// Old classes and unavailable future construction return None. An installed
    /// action must refuse that missing row, never substitute zero or Source cold
    /// slack. Protocol reconstruction, mapping, proof and Commit stay separate.
    pub fn selected_owner_construction_data(&self) -> Option<&crucible_node_provider::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreOwnerValidationStorage>{
        self.selected_owner.as_ref()
    }

    /// Borrows the original complete historical validation workspace row.
    ///
    /// Missing data remains unavailable; callers must refuse instead of using a
    /// zero row or another owner's construction allowance. This is requested
    /// construction DATA, never a restored context or fresh input-custody proof.
    pub fn original_archived_validation_construction_data(
        &self,
    ) -> Option<&CompleteOriginalArchivedValidationConstructionData> {
        self.archived_validation.as_ref()
    }

    /// Returns the five original body extents before fresh mapping normalization.
    ///
    /// Order is native-after, Control, anchor, owner snapshot and signed journal.
    /// Equal contents remain distinct role banks. The sixth mapping is a new
    /// target original and is separately quoted by the later restoration action.
    pub fn archived_input_byte_extents_data(&self) -> [usize; 5] {
        self.input_lengths
    }
}

/// Borrows the exact cold-validator inputs while transferring their immutable DATA.
///
/// This nonconstructible wrapper lives only during the admitted archive callback.
/// It grants no restoration right and cannot outlive the owner/content loans.
pub struct ValidatedCompleteNativeRestorationData<'a> {
    data: CompleteOriginalNativeRestorationData,
    owner: &'a super::NativeOwnerState,
    content: &'a crate::node_state::VerifiedStateContent,
}

impl<'a> ValidatedCompleteNativeRestorationData<'a> {
    pub(crate) fn from_validated_native_data(
        native: NativeOwnedProtocol11AllocationDemand,
        limits: OwnedProtocol11DataLimits,
        input_lengths: [usize; 5],
        references: [&crucible_node_contract::ContentRef; 5],
        source_cold_requested_bytes: usize,
        mapping_reference_clone_bytes: usize,
        selected_owner: Option<crucible_node_provider::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreOwnerValidationStorage>,
        owner: &'a super::NativeOwnerState,
        content: &'a crate::node_state::VerifiedStateContent,
    ) -> Self {
        Self {
            data: CompleteOriginalNativeRestorationData {
                native,
                limits,
                input_lengths,
                reference_identities: references.map(reference_identity),
                source_cold_requested_bytes,
                mapping_reference_clone_bytes,
                selected_owner,
                archived_validation: None,
            },
            owner,
            content,
        }
    }

    pub(crate) fn with_archived_validation_data(
        mut self,
        data: CompleteOriginalArchivedValidationConstructionData,
    ) -> Self {
        self.data.archived_validation = Some(data);
        self
    }

    pub(super) fn into_original_data(
        self,
        owner: &super::NativeOwnerState,
        content: &crate::node_state::VerifiedStateContent,
    ) -> Result<CompleteOriginalNativeRestorationData, crate::node_contract::RuntimeError> {
        if !std::ptr::eq(self.owner, owner) || !std::ptr::eq(self.content, content) {
            return Err(crate::node_contract::RuntimeError::ForeignAuthority);
        }
        Ok(self.data)
    }
}

// The independent length prefix prevents concatenation ambiguity. This fixed
// Source-only association does not replace any normative CNP content digest.
pub(super) fn reference_identity(reference: &crucible_node_contract::ContentRef) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("core.original-restoration-body-reference/1");
    for text in [
        &reference.hash.algorithm,
        &reference.hash.domain,
        &reference.hash.digest,
        &reference.media_type,
    ]
    .map(String::as_str)
    {
        hash.update(&(text.len() as u64).to_le_bytes());
        hash.update(text.as_bytes());
    }
    hash.update(&reference.length.get().to_le_bytes());
    *hash.finalize().as_bytes()
}

/// Separates the actual signed-index construction phases before restoration.
///
/// The exact original index is counted without materializing it or issuing a
/// request. This row supplies no archive admission, signer or target permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteOriginalRestorationIndexConstructionData {
    value_bytes: usize,
    canonical_bytes: usize,
    result_reference_bytes: usize,
    fixed_scratch_bytes: usize,
    requested_bytes: usize,
}

impl CompleteOriginalRestorationIndexConstructionData {
    /// Returns the independent complete index construction requested bytes.
    pub fn requested_bytes(&self) -> usize {
        self.requested_bytes
    }

    /// Returns DOM, canonical, returned-reference and fixed-view terms separately.
    pub fn requested_terms_data(&self) -> [usize; 4] {
        [
            self.value_bytes,
            self.canonical_bytes,
            self.result_reference_bytes,
            self.fixed_scratch_bytes,
        ]
    }
}

impl super::NativeArchiveRecord {
    /// Names fixed original-index quote and identity-construction views.
    ///
    /// Counts the same real Hasher, ContentRef and local Value/Vec headers used
    /// by the complete signed-index identity producer. Decimal formatting is a
    /// separate explicit twenty-byte request, including during counting passes.
    pub fn original_restoration_index_counter_scratch_data() -> usize {
        std::mem::size_of::<CompleteOriginalRestorationIndexConstructionData>()
            + std::mem::size_of::<blake3::Hasher>()
            + std::mem::size_of::<crucible_node_contract::ContentRef>()
            + std::mem::size_of::<serde_json::Value>()
            + std::mem::size_of::<Vec<u8>>()
            + std::mem::size_of::<[usize; 4]>()
            + crate::node_contract::NodeRuntime::capture_serialization_counter_scratch_data()
            + 20
    }

    /// Quotes the same authenticated immutable index before a restoration effect.
    ///
    /// Both counting passes borrow the actual complete index, exactly as the
    /// later identity constructor does. No substituted index, cloned bank or
    /// configured maximum stands in for its actual serialized geometry. The
    /// enclosing installed window separately counts this record/content owner
    /// and every other live transaction owner before calling the real producer.
    ///
    /// # Errors
    /// Refuses absent/foreign selected-load admission, unsupported serialized
    /// data, arithmetic overflow or the independent complete requested bound.
    pub fn original_restoration_index_construction_storage_data(
        &self,
        maximum: usize,
    ) -> Result<CompleteOriginalRestorationIndexConstructionData, crate::node_contract::RuntimeError>
    {
        use crate::node_contract::{NodeRuntime, RuntimeError};
        self.authenticate_complete_load_admission()?;
        let fixed_scratch_bytes = Self::original_restoration_index_counter_scratch_data();
        if fixed_scratch_bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        let value_bytes = NodeRuntime::capture_serialization_storage(self.index.as_ref(), maximum)?;
        let canonical_bytes =
            NodeRuntime::capture_encoded_output_storage(self.index.as_ref(), maximum)?;
        // These are the exact four newly owned strings of the returned full
        // reference. They coexist with the Value and canonical index bank.
        let result_reference_bytes = "blake3-256".len()
            + "cnp.blob.v1".len()
            + 64
            + "application/vnd.crucible.native-signed-index-body.v3+json".len();
        let requested_bytes = [
            value_bytes,
            canonical_bytes,
            result_reference_bytes,
            fixed_scratch_bytes,
        ]
        .into_iter()
        .try_fold(0usize, |sum, term| {
            sum.checked_add(term).ok_or(RuntimeError::ResourceLimit)
        })?;
        if requested_bytes > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        self.authenticate_complete_load_admission()?;
        Ok(CompleteOriginalRestorationIndexConstructionData {
            value_bytes,
            canonical_bytes,
            result_reference_bytes,
            fixed_scratch_bytes,
            requested_bytes,
        })
    }
}

/// Retains actual checked workspace maxima from the original archive predicates.
///
/// The three predicates run sequentially, with their complete historical owners
/// separately retained. Each row includes its original decoder allowance and
/// concrete comparison leases. This fixed DATA cannot authenticate a fresh Hold,
/// grant Source effects, or stand in for current runtime and input-custody proof.
#[derive(Clone, Copy, Debug)]
pub struct CompleteOriginalArchivedValidationConstructionData {
    phases: [usize; 3],
    semantic_decode: usize,
    fixed_scratch: usize,
    requested: usize,
}

impl CompleteOriginalArchivedValidationConstructionData {
    pub(crate) fn from_validated_phases(
        phases: [usize; 3],
        semantic_decode: usize,
        fixed_scratch: usize,
    ) -> Result<Self, crate::node_contract::RuntimeError> {
        let requested = phases[0]
            .max(phases[1])
            .max(phases[2])
            .checked_add(semantic_decode)
            .and_then(|bytes| bytes.checked_add(fixed_scratch))
            .ok_or(crate::node_contract::RuntimeError::ResourceLimit)?;
        Ok(Self {
            phases,
            semantic_decode,
            fixed_scratch,
            requested,
        })
    }

    /// Returns sequential runtime, protocol and native workspace maxima.
    pub fn phase_requested_bytes_data(&self) -> [usize; 3] {
        self.phases
    }

    /// Returns the actual original semantic and ancestry decoder request.
    ///
    /// The selected validator decodes those same verified bodies temporarily;
    /// this term is independent from the already retained cold protocol owners.
    pub fn semantic_decode_requested_bytes_data(&self) -> usize {
        self.semantic_decode
    }

    /// Returns the independently named fixed counter and typed view headers.
    pub fn fixed_counter_scratch_bytes_data(&self) -> usize {
        self.fixed_scratch
    }

    /// Returns semantic decoding plus maximum validator workspace and fixed views.
    pub fn requested_bytes_data(&self) -> usize {
        self.requested
    }
}
