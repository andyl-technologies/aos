//! Prices independently owned archive copies of genuine completed Source output.
//!
//! Native maxima come from the original completed startup's five-bank policy.
//! Final Controller/journal, semantic/Node, scope and prefix extents retain their
//! independent defining rows. Domination by a callback's remaining native limits
//! must pass before effects; these quantities never create Capture permission.

use super::{construction_quote::sum, finalization::FinalizationStorage};
use crate::{
    node_adapters::cnp::{CnpSemanticSource, PacketCompleteSemanticSource},
    node_contract::{
        InstalledOriginalLineageCapture, NativeCaptureLimits, NativeStateKey, NodeRuntime,
        RuntimeError,
    },
};
use crucible_node_contract::{Id, SchemaRef};
use crucible_node_provider::reference_packet::{
    continuation_contracts::PACKET_COMPLETE_LINEAGE_PROFILE,
    service::complete_restore::settled_recapture::PacketRestoredSettledCaptureOutputLimits,
};
use std::mem::size_of;

pub(super) const OUTPUT_COUNT: usize = 11;
pub(super) const EVIDENCE_COUNT: usize = 10;

// Ordered as state; control, before, anchor, after, Controller, semantic, Node,
// scope, prefix; and the independently owned final journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CaptureMaterializationStorage {
    bounds: [usize; OUTPUT_COUNT],
    pub(super) born: super::effect::CaptureBornStorage,
    pub(super) retained: usize,
    pub(super) transient: usize,
    pub(super) scratch: usize,
}

pub(super) type OutputMetadata<'a> = (&'a Id, &'a Vec<Id>, &'a Id, &'a Id, &'a SchemaRef);

/// Borrows the actual Source-bound preservation key without constructing one.
pub(super) fn output_metadata_data(
    source: &PacketCompleteSemanticSource,
) -> Result<OutputMetadata<'_>, RuntimeError> {
    source.storage_origin_with_error::<RuntimeError>()?;
    let installation = source.installation();
    if installation.profile.profile_id.as_str() != PACKET_COMPLETE_LINEAGE_PROFILE
        || installation
            .binding
            .compatibility
            .implementation
            .implementation_id
            != installation.provider.implementation.implementation_id
        || installation.owner.owner.participant_ids.as_slice()
            != std::slice::from_ref(&installation.descriptor.id)
    {
        return Err(RuntimeError::ForeignAuthority);
    }
    let schema = source
        .original_restored_settled_capture_schema_data()
        .map_err(|_| RuntimeError::UnsupportedFacet)?;
    Ok((
        &installation.owner.owner.id,
        &installation.owner.owner.participant_ids,
        &installation
            .binding
            .compatibility
            .implementation
            .implementation_id,
        &installation.profile.profile_id,
        schema,
    ))
}

impl CaptureMaterializationStorage {
    pub(super) fn quote_data(
        source: &PacketCompleteSemanticSource,
        native: &PacketRestoredSettledCaptureOutputLimits,
        finalization: &FinalizationStorage,
        semantic: usize,
        prefix: usize,
        ancestry: &super::ancestry::OriginalRestoredCaptureAncestry17Data<'_>,
        inherited: Option<&super::logical::OriginalSourceRestoredSettled17Read>,
        archive: &crate::node_state::CompleteOriginalRestorationSource,
        original_runtime_reference_bytes: usize,
        maximum: usize,
    ) -> Result<Self, RuntimeError> {
        native
            .validate_data()
            .map_err(|_| RuntimeError::InvalidReceipt)?;
        let convert = |value: crucible_node_contract::U64| {
            usize::try_from(value.get()).map_err(|_| RuntimeError::ResourceLimit)
        };
        let bounds = [
            convert(native.native_snapshot_bytes)?,
            convert(native.current_control_bytes)?,
            convert(native.native_before_bytes)?,
            convert(native.anchor_bytes)?,
            convert(native.native_after_bytes)?,
            finalization.controller_encoded,
            semantic,
            semantic,
            finalization.proof_encoded,
            prefix,
            finalization.journal_encoded,
        ];
        if bounds.contains(&0) {
            return Err(RuntimeError::ResourceLimit);
        }
        let metadata = output_metadata_data(source)?;
        let metadata = NodeRuntime::capture_native_output_metadata_clone_storage_data(
            metadata.0, metadata.1, metadata.2, metadata.3, metadata.4,
        )?;
        let born = super::effect::CaptureBornStorage::quote_data(
            source,
            ancestry,
            inherited,
            archive,
            original_runtime_reference_bytes,
            maximum,
        )?;
        let body_bytes = sum(&bounds, maximum)?;
        // Valid full ContentRef always uses blake3-256/cnp.blob.v1/64 hex.
        // Each role is checked against this exact media before its clone.
        let reference_bytes = sum(&media_types().map(reference_backing), maximum)?;
        let retained = sum(
            &[
                body_bytes,
                born.retained,
                reference_bytes,
                metadata,
                EVIDENCE_COUNT
                    .checked_mul(size_of::<crate::node_scheduling::InputPayload>())
                    .ok_or(RuntimeError::ResourceLimit)?,
                size_of::<InstalledOriginalLineageCapture>(),
            ],
            maximum,
        )?;
        // Copies write directly to their final retained Vec. Hash verification
        // allocates only one fixed HashRef spelling, never another body buffer.
        let transient = sum(
            &["blake3-256".len() + "cnp.blob.v1".len() + 64, born.transient],
            maximum,
        )?;
        let scratch = sum(&[Self::counter_scratch_data(), born.scratch], maximum)?;
        sum(&[retained, transient, scratch], maximum)?;
        Ok(Self {
            bounds,
            born,
            retained,
            transient,
            scratch,
        })
    }

    pub(super) fn bound_data(&self, index: usize) -> Result<usize, RuntimeError> {
        self.bounds
            .get(index)
            .copied()
            .ok_or(RuntimeError::InvalidReceipt)
    }

    /// Checks every required role against actual unchanged callback ceilings.
    pub(super) fn authenticate_limits_data(
        &self,
        limits: NativeCaptureLimits,
    ) -> Result<(), RuntimeError> {
        if limits.maximum_objects < OUTPUT_COUNT + 1
            || self.born.index_encoded > limits.maximum_record_bytes
            || self
                .bounds
                .iter()
                .any(|bound| *bound > limits.maximum_record_bytes)
        {
            return Err(RuntimeError::ResourceLimit);
        }
        let bodies = sum(&self.bounds, limits.maximum_total_record_bytes)?;
        sum(
            &[bodies, self.born.index_encoded],
            limits.maximum_total_record_bytes,
        )?;
        // This family returns no streamed artifacts. Both artifact debits are
        // exactly zero; neither supplied artifact ceiling is raised or reused.
        Ok(())
    }

    pub(super) fn counter_scratch_data() -> usize {
        size_of::<Self>()
            + size_of::<Result<Self, RuntimeError>>()
            + size_of::<OutputMetadata<'static>>()
            + size_of::<Result<OutputMetadata<'static>, RuntimeError>>()
            + size_of::<NativeCaptureLimits>()
            + size_of::<NativeStateKey>()
            + size_of::<[usize; OUTPUT_COUNT]>()
            + size_of::<[&str; OUTPUT_COUNT]>()
            + size_of::<std::array::IntoIter<usize, OUTPUT_COUNT>>()
            + size_of::<std::array::IntoIter<&str, OUTPUT_COUNT>>()
            + size_of::<std::slice::Iter<'static, usize>>()
            + size_of::<[usize; 5]>()
            + size_of::<std::array::IntoIter<usize, 5>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Result<usize, std::num::TryFromIntError>>()
            + PacketCompleteSemanticSource::original_restored_settled_capture_schema_counter_scratch_data()
            + crate::node_contract::opaque_owner_counter_scratch_data()
    }
}

pub(super) fn reference_backing(media: &str) -> usize {
    "blake3-256".len() + "cnp.blob.v1".len() + 64 + media.len()
}

pub(super) fn media_types() -> [&'static str; OUTPUT_COUNT] {
    use crucible_node_provider::protocol_snapshot::restored_journal17::RESTORED_SETTLED_SEMANTIC17_MEDIA;
    [
        "application/json",
        "application/json",
        "application/json",
        "application/json",
        "application/json",
        "application/json",
        RESTORED_SETTLED_SEMANTIC17_MEDIA,
        "application/json",
        "application/json",
        "application/json",
        "application/json",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> CaptureMaterializationStorage {
        CaptureMaterializationStorage {
            bounds: [3; OUTPUT_COUNT],
            born: super::super::effect::CaptureBornStorage::data_test_index_bound(3),
            retained: 0,
            transient: 0,
            scratch: 0,
        }
    }

    #[test]
    fn every_output_role_and_total_requires_independent_native_credit() {
        let limits = NativeCaptureLimits {
            maximum_record_bytes: 3,
            maximum_total_record_bytes: 36,
            maximum_objects: OUTPUT_COUNT + 1,
            maximum_artifact_bytes: 0,
            maximum_total_artifact_bytes: 0,
        };
        assert!(row().authenticate_limits_data(limits).is_ok());
        for index in 0..OUTPUT_COUNT {
            let mut changed = row();
            changed.bounds[index] = 4;
            assert!(changed.authenticate_limits_data(limits).is_err());
        }
        let mut larger_index = row();
        larger_index.born.index_encoded = 4;
        assert!(larger_index.authenticate_limits_data(limits).is_err());

        assert!(
            row()
                .authenticate_limits_data(NativeCaptureLimits {
                    maximum_total_record_bytes: 35,
                    ..limits
                })
                .is_err()
        );
        assert!(
            row()
                .authenticate_limits_data(NativeCaptureLimits {
                    maximum_objects: OUTPUT_COUNT,
                    ..limits
                })
                .is_err()
        );
    }
}
