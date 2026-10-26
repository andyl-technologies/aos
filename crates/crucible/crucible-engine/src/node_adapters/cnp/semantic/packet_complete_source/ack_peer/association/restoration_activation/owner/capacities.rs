//! Counts activation/upload phase banks, native partials and both World bodies.
//!
//! Origin checks precede record mutation. Saved source/controller pointers are
//! non-owning labels: they are neither dereferenced nor emitted as capacity rows.
//! Failed or unreserved state keeps backing without becoming eligible to sign.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values::{
    record_value_capacity_data_with_error, value_capacity_counter_scratch_data,
};
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_transport::retained_metadata::RetainedCaptureProtocolData;

impl OriginalSourceRestorationActivationAttempt {
    /// Checks only the retained original's creator process and thread.
    ///
    /// # Errors
    /// Refuses another process or thread without evaluating activation eligibility.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn check_capacity_creator_data(
        &self,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.thread != std::thread::current().id() {
            return Err(RuntimeError::ThreadAffinity);
        }
        Ok(())
    }

    /// Records all four phase groups and every independently retained child.
    ///
    /// # Errors
    /// Refuses another creator, exhausted row/depth bounds, unavailable physical
    /// backing or checked layout overflow. Earlier components remain retained.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        self.check_capacity_creator_data()?;
        let Self {
            process,
            thread,
            source,
            controller,
            binding,
            reserved,
            order,
            phases,
            uploads,
            world_bodies,
            upload_order,
        } = self;

        census.observe_inline_data(process);
        census.observe_inline_data(thread);
        census.observe_inline_data(source);
        census.observe_inline_data(controller);
        census.observe_inline_data(binding);
        census.observe_inline_data(reserved);

        let ActivationOrder {
            started,
            verified,
            failed,
        } = order;
        census.observe_inline_data(started);
        census.observe_inline_data(verified);
        census.observe_inline_data(failed);
        upload_order.record_inline_capacity_data(census);

        for phase in phases.iter().chain(uploads) {
            let ActivationPhase {
                banks,
                values,
                native_record,
                underlying,
            } = phase;
            for bank in banks {
                census.observe(bank)?;
            }
            for value in values.iter().flatten() {
                record_value_capacity_data_with_error::<RuntimeError>(value, 0, census)?;
            }
            census.observe_capture_protocol_data(
                RetainedCaptureProtocolData::RestorationNativeEvidence(
                    native_record.as_ref(),
                    underlying.as_ref(),
                ),
            )?;
        }
        if let Some(world_content::WorldUploadBodies {
            coordinator,
            manifest,
        }) = world_bodies
        {
            census.observe(coordinator)?;
            census.observe(manifest)?;
        }
        self.check_capacity_creator_data()
    }

    /// Names the actual borrowed phase roster and all nested observation controls.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn capacity_counter_scratch_data()
    -> usize {
        size_of::<&Self>()
            + size_of::<(
                &u32,
                &std::thread::ThreadId,
                &*const PacketCompleteSemanticSource,
                &*const CnpController,
                &blake3::Hash,
                &bool,
                &ActivationOrder,
                &[ActivationPhase; PHASES],
                &[ActivationPhase; 2],
                &Option<world_content::WorldUploadBodies>,
                &upload::UploadOrder,
            )>()
            + size_of::<(&[bool; PHASES], &[bool; PHASES], &bool)>()
            + size_of::<(
                &[Vec<u8>; BANKS],
                &[Option<serde_json::Value>; BANKS],
                &Option<PacketNativeRestoredRecord>,
                &Option<PacketNative5UnderlyingRecord>,
            )>()
            + size_of::<(
                &crate::node_scheduling::InputPayload,
                &crate::node_scheduling::InputPayload,
            )>()
            + size_of::<
                std::iter::Chain<
                    std::slice::Iter<'_, ActivationPhase>,
                    std::slice::Iter<'_, ActivationPhase>,
                >,
            >()
            + size_of::<std::slice::Iter<'_, Vec<u8>>>()
            + size_of::<std::iter::Flatten<std::slice::Iter<'_, Option<serde_json::Value>>>>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'_>>()
            + size_of::<Result<(), RuntimeError>>()
            + value_capacity_counter_scratch_data()
            + upload::UploadOrder::capacity_counter_scratch_data()
            + RetainedCaptureProtocolData::capacity_counter_scratch_data()
    }
}

#[cfg(test)]
#[path = "capacities/tests.rs"]
mod tests;
