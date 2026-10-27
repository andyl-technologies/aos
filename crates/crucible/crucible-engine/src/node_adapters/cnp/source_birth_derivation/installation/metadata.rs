//! Observes retained mechanism payloads and selected direct buffers as DATA.
//!
//! Each original strong view retains its own shared row and buffer population.
//! Descriptor/lease notification backing and opaque native runtime remain under
//! the same original deployment obligation. These facts do not close a complete
//! Source footprint, whole-native work bound or any lifecycle grant.

use super::*;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_host_resources::{DeploymentResourceLease, LinuxPureWorkerBufferCapacityData};
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts,
    records::{MetadataCapacityRecord, MetadataRecordKind, PacketRuntimeMetadataRecordBank},
};
use std::{alloc::Layout, mem::size_of};

impl VerifiedSourceBirthMechanism {
    /// Observes original fixed payloads and the retained direct buffer views.
    ///
    /// The enclosing holder separately counts this mechanism's actual Rc.
    /// Factory and independent program views repeat their rows; equal pointers
    /// or contents receive no discount. Failed or revoked originals remain DATA.
    /// Opaque descriptor, lease and runtime backing still requires the genuine
    /// original process reservation, which is never converted into a byte row.
    ///
    /// # Errors
    /// Refuses exhausted rows, unavailable physical backing or checked geometry
    /// and traversal-work overflow, preserving the emitted physical prefix.
    pub fn known_capacity_data(
        &self,
        maximum_rows: usize,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        let Self {
            supervisor,
            factory,
            program,
            bindings,
            limits,
            slots,
        } = self;
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum_rows, bank);
        census.observe_work_data(1)?;
        let supervisor = match supervisor {
            ProcessEnforcement::CreatorThread(original) => original.retained_payload_layout_data(),
            ProcessEnforcement::Deployment(original) => original.retained_payload_layout_data(),
        };
        record_shared(supervisor, &mut census)?;
        census.observe_inline_data(bindings)?;
        census.observe_inline_data(limits)?;
        census.observe_inline_data(slots)?;

        census.observe_work_data(1)?;
        for layout in factory.retained_shared_payload_layouts_data() {
            record_shared(layout, &mut census)?;
        }
        factory.observe_direct_buffers(&mut |buffer| record_buffer(buffer, &mut census))?;

        census.observe_work_data(1)?;
        record_shared(program.retained_payload_layout_data(), &mut census)?;
        program.observe_direct_buffers(&mut |buffer| record_buffer(buffer, &mut census))?;
        Ok(census.finish())
    }

    /// Names this fixed roster, direct-buffer callbacks and layout controls.
    ///
    /// Actual native authentication and opaque runtime retain their independent
    /// deployment contract; these controls do not quote that work or backing.
    pub fn known_capacity_counter_scratch_data() -> usize {
        OriginalOwnerCapacityMetadataData::counter_scratch_data()
            + LinuxPureWorkerBufferCapacityData::counter_scratch_data()
            + DeploymentResourceLease::retained_capacity_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<(
                &ProcessEnforcement,
                &LinuxPureWorkerFactory,
                &LinuxPureWorkerProgram,
                &SourceBirthInstallationBindings,
                &LinuxPureWorkerLimits,
                &usize,
            )>()
            + size_of::<&Rc<LinuxProcessSupervisor>>()
            + size_of::<&DeploymentResourceLease>()
            + size_of::<Layout>() * 3
            + size_of::<[Layout; 3]>()
            + size_of::<std::array::IntoIter<Layout, 3>>()
            + size_of::<LinuxPureWorkerBufferCapacityData>()
            + size_of::<&mut OriginalOwnerCapacityMetadataData<'static>>() * 2
            + size_of::<Option<&mut PacketRuntimeMetadataRecordBank>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<usize>() * 2
    }
}

fn record_shared(
    layout: Layout,
    census: &mut OriginalOwnerCapacityMetadataData<'_>,
) -> Result<(), RuntimeError> {
    census.record(MetadataCapacityRecord {
        kind: MetadataRecordKind::Shared,
        extent: layout.size(),
        element_bytes: 1,
        alignment: layout.align(),
    })
}

fn record_buffer(
    buffer: LinuxPureWorkerBufferCapacityData,
    census: &mut OriginalOwnerCapacityMetadataData<'_>,
) -> Result<(), RuntimeError> {
    census.observe_work_data(1)?;
    census.record(MetadataCapacityRecord {
        kind: MetadataRecordKind::Vector,
        extent: buffer.capacity,
        element_bytes: buffer.element_bytes,
        alignment: buffer.alignment,
    })
}
