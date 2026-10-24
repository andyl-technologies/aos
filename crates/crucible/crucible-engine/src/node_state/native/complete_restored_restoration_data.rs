//! Retains the distinct native17 import geometry for its exact signed owner.
//!
//! Cached facts preserve the defining validator's full demand, limits and mapping
//! bound. They are not allocation credit, restoration context or live authority.

use super::{NativeOwnerState, VerifiedStateContent};
use crate::node_contract::RuntimeError;
use crucible_node_format::ContentRef;
use crucible_node_transport::protocol_snapshot::restored_settled17::{
    RestoredSettledNative17Input, RestoredSettledNativeImportGeometryData,
};

/// Keeps complete native17 geometry separate from old Owned11 reconstruction data.
///
/// No cloning, decoding or public construction can mint this archive-cache row.
/// Actual future allocation must be independently admitted with current owners.
pub struct CompleteRestoredSettledNativeRestorationData {
    geometry: RestoredSettledNativeImportGeometryData,
    input_lengths: [usize; 5],
    reference_identities: [[u8; 32]; 5],
    source_cold_requested_bytes: usize,
}

impl CompleteRestoredSettledNativeRestorationData {
    /// Names fixed complete cache construction and full-reference comparison views.
    pub fn counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<ValidatedCompleteRestoredSettledNativeRestorationData<'static>>()
            + size_of::<
                Result<
                    ValidatedCompleteRestoredSettledNativeRestorationData<'static>,
                    RuntimeError,
                >,
            >()
            + size_of::<[&ContentRef; 5]>()
            + size_of::<[usize; 5]>()
            + size_of::<std::array::IntoIter<usize, 5>>()
            + size_of::<std::slice::Iter<'static, &ContentRef>>()
            + size_of::<&&ContentRef>()
            + size_of::<(&&ContentRef, usize)>()
            + size_of::<Option<&[u8]>>()
            + size_of::<Result<&[u8], RuntimeError>>()
            + size_of::<&NativeOwnerState>()
            + size_of::<&VerifiedStateContent>()
            + size_of::<RestoredSettledNative17Input<'static>>()
            + size_of::<Result<(), crucible_node_transport::ProviderError>>()
            + super::CompleteOriginalNativeRestorationData::reference_counter_scratch_data()
            + RestoredSettledNativeImportGeometryData::counter_scratch_data()
    }

    /// Borrows actual explicit-family demand, limits and independently bound normalization.
    pub fn native_import_geometry_data(&self) -> &RestoredSettledNativeImportGeometryData {
        &self.geometry
    }

    /// Returns exact lengths in snapshot, current-protocol, Control, anchor, journal order.
    pub const fn archived_input_byte_extents_data(&self) -> [usize; 5] {
        self.input_lengths
    }

    /// Returns the exact archived Source-history decoder demand.
    ///
    /// This scalar is the saved final Source constructor R+T+S. It excludes
    /// Controller, Node, native, parent-group and fresh installation work, each
    /// of which requires its own independently admitted construction row.
    pub const fn source_cold_construction_requested_bytes_data(&self) -> usize {
        self.source_cold_requested_bytes
    }

    /// Compares all signed full references without substituting equal-length roles.
    ///
    /// # Errors
    /// Refuses any changed full reference or role order.
    pub fn authenticate_original_references_data(
        &self,
        references: [&ContentRef; 5],
    ) -> Result<(), RuntimeError> {
        if references.map(super::complete_original_restoration_data::reference_identity)
            != self.reference_identities
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

/// Lends one cache row only while its actual validated archive owners remain borrowed.
///
/// The whole signed archive validator accepts this only for the same owner and
/// verified content allocations; a portable row cannot choose its target slot.
pub struct ValidatedCompleteRestoredSettledNativeRestorationData<'a> {
    data: CompleteRestoredSettledNativeRestorationData,
    owner: &'a NativeOwnerState,
    content: &'a VerifiedStateContent,
}

impl<'a> ValidatedCompleteRestoredSettledNativeRestorationData<'a> {
    pub(crate) fn from_validated_native_data(
        geometry: RestoredSettledNativeImportGeometryData,
        references: [&ContentRef; 5],
        input_lengths: [usize; 5],
        source_cold_requested_bytes: usize,
        owner: &'a NativeOwnerState,
        content: &'a VerifiedStateContent,
    ) -> Result<Self, RuntimeError> {
        // These references must all be actual members of this already verified
        // signed closure, not merely equal digest/length labels from elsewhere.
        for (reference, length) in references.iter().zip(input_lengths) {
            let bytes = content.get(reference).ok_or(RuntimeError::InvalidReceipt)?;
            if bytes.len() != length {
                return Err(RuntimeError::InvalidReceipt);
            }
        }
        if references[0] != &owner.state {
            return Err(RuntimeError::ForeignAuthority);
        }
        let body = |reference| content.get(reference).ok_or(RuntimeError::InvalidReceipt);
        let actual = RestoredSettledNative17Input {
            snapshot: (references[0], body(references[0])?),
            current_protocol: (references[1], body(references[1])?),
            control: (references[2], body(references[2])?),
            anchor: (references[3], body(references[3])?),
            journal: (references[4], body(references[4])?),
        };
        geometry
            .authenticate_same_inputs_data(&actual, geometry.normalization_maximum_data())
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        Ok(Self {
            data: CompleteRestoredSettledNativeRestorationData {
                geometry,
                input_lengths,
                reference_identities: references
                    .map(super::complete_original_restoration_data::reference_identity),
                source_cold_requested_bytes,
            },
            owner,
            content,
        })
    }

    pub(super) fn into_restored_data(
        self,
        owner: &NativeOwnerState,
        content: &VerifiedStateContent,
    ) -> Result<CompleteRestoredSettledNativeRestorationData, RuntimeError> {
        if !std::ptr::eq(self.owner, owner) || !std::ptr::eq(self.content, content) {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(self.data)
    }
}
