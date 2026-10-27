//! Preserves the actual pre-report constructor Box and every retained child.
//!
//! Failed registrations, JSON values, coordinator DTOs and partial canonical
//! banks retain their defining capacity geometry. File/kernel resources remain
//! separate descriptor obligations. These DATA grant no Birth or Initial action.

use super::*;
use crate::node_adapters::cnp::semantic::packet_complete_source::retained_values;
use crate::node_contract::restored_owner_history::OriginalOwnerCapacityMetadataData;
use crucible_node_format::{ExtensionSelection, SemanticVersion};
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts,
    records::{MetadataCapacityRecord, MetadataRecordKind, PacketRuntimeMetadataRecordBank},
};
use std::mem::align_of;

impl PacketCompleteSemanticSource {
    /// Observes the original constructor Box and all present or failed children.
    ///
    /// Physical rows append without clearing earlier components. The original
    /// Source and constructor association are checked before touching the bank.
    /// Independent owning views receive no alias discount or lifecycle credit.
    ///
    /// # Errors
    /// Refuses foreign creator or constructor custody, unsupported nested DATA,
    /// checked geometry/work overflow, exhausted rows or unavailable backing.
    pub fn native_import18_birth_construction_capacity_data(
        &self,
        bank: Option<&mut PacketRuntimeMetadataRecordBank>,
    ) -> Result<RetainedProtocolMetadataFacts, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if let Some(owner) = &self.native_import18_birth_construction {
            if owner.identity.source != self as *const Self as usize
                || owner.identity.process != self.process
                || owner.identity.thread != self.thread
            {
                return Err(RuntimeError::ForeignAuthority);
            }
        }
        let maximum = bank.as_ref().map_or(usize::MAX, |bank| bank.maximum_rows());
        let mut census = OriginalOwnerCapacityMetadataData::new(maximum, bank);
        census.observe_inline_data(&self.native_import18_birth_construction.is_some())?;
        if let Some(owner) = &self.native_import18_birth_construction {
            // This row belongs to the actual Box slot, never to a detached
            // payload size or an operational process reservation.
            census.record(MetadataCapacityRecord {
                kind: MetadataRecordKind::Boxed,
                extent: size_of::<NativeImport18BirthConstruction>(),
                element_bytes: 1,
                alignment: align_of::<NativeImport18BirthConstruction>(),
            })?;
            owner.record_capacity_data(&mut census)?;
        }
        self.storage_origin_with_error::<RuntimeError>()?;
        Ok(census.finish())
    }
}

impl NativeImport18BirthConstruction {
    fn record_capacity_data(
        &self,
        census: &mut OriginalOwnerCapacityMetadataData<'_>,
    ) -> Result<(), RuntimeError> {
        let Self {
            identity,
            inputs_started,
            registration,
            private_launch,
            coordinator,
            source_value,
            registration_value,
            source_bank,
            registration_bank,
            private_birth,
            stage,
            failed,
        } = self;
        let Identity {
            source,
            process,
            thread,
            launch_operands,
        } = identity;
        census.observe_inline_data(source)?;
        census.observe_inline_data(process)?;
        census.observe_inline_data(thread)?;
        census.observe_inline_data(launch_operands)?;
        census.observe_inline_data(inputs_started)?;
        census.observe_inline_data(stage)?;
        census.observe_inline_data(failed)?;
        census.observe(private_launch)?;
        census.observe(source_bank)?;
        census.observe(registration_bank)?;
        private_birth.record_retained_capacity_data(census)?;

        census.observe_inline_data(&registration.is_some())?;
        if let Some(plan) = registration {
            record_registration_capacity_data(plan, census)?;
        }
        census.observe_inline_data(&coordinator.is_some())?;
        if let Some(coordinator) = coordinator {
            census.observe_native_coordinator_data(coordinator)?;
        }
        for value in [source_value, registration_value] {
            census.observe_inline_data(&value.is_some())?;
            if let Some(value) = value {
                retained_values::record_value_capacity_data_with_error::<RuntimeError>(
                    value, 0, census,
                )?;
            }
        }
        Ok(())
    }
}

/// Walks the original complete registration, including rejected extension DATA.
pub(super) fn record_registration_capacity_data(
    plan: &PacketCompleteAckHostRegistrationPlan,
    census: &mut OriginalOwnerCapacityMetadataData<'_>,
) -> Result<(), RuntimeError> {
    let PacketCompleteAckHostRegistrationPlan {
        connection_id,
        features,
        extensions,
        envelope_extensions,
    } = plan;
    census.observe(connection_id)?;
    census.observe(features)?;
    census.observe_vector_allocation_data(extensions)?;
    census.observe_work_data(1)?;
    for ExtensionSelection {
        declaration,
        identifier,
        semantic_version,
        schema_digest,
    } in extensions
    {
        census.observe_work_data(1)?;
        census.observe(declaration)?;
        census.observe(identifier)?;
        census.observe(schema_digest)?;
        let SemanticVersion {
            major,
            minor,
            patch,
            prerelease,
            build,
        } = semantic_version;
        census.observe_inline_data(major)?;
        census.observe_inline_data(minor)?;
        census.observe_inline_data(patch)?;
        census.observe(prerelease)?;
        census.observe(build)?;
    }
    census.observe(envelope_extensions)
}

/// Names the standalone registration byte observer and its defining field walk.
pub(super) fn registration_counter_scratch_data() -> usize {
    OriginalOwnerCapacityMetadataData::counter_scratch_data()
        + registration_field_counter_scratch_data()
        + size_of::<&PacketCompleteAckHostRegistrationPlan>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<usize, RuntimeError>>()
}

fn registration_field_counter_scratch_data() -> usize {
    size_of::<(&Id, &Vec<Id>, &Vec<ExtensionSelection>, &Vec<String>)>()
        + size_of::<(
            &ContentRef,
            &Id,
            &SemanticVersion,
            &crucible_node_format::HashRef,
        )>()
        + size_of::<(
            &crucible_node_format::U64,
            &crucible_node_format::U64,
            &crucible_node_format::U64,
            &Option<String>,
            &Option<String>,
        )>()
        + size_of::<std::slice::Iter<'static, ExtensionSelection>>()
        + size_of::<Result<(), RuntimeError>>()
}

/// Names concrete census, field-view, SDK and private-JSON observation controls.
pub(super) fn counter_scratch_data() -> usize {
    OriginalOwnerCapacityMetadataData::counter_scratch_data()
        + registration_field_counter_scratch_data()
        + retained_values::value_capacity_counter_scratch_data()
        + crucible_node_transport::retained_metadata::retained_native_coordinator_counter_scratch_data()
        + size_of::<&PacketCompleteSemanticSource>()
        + size_of::<Option<&Box<NativeImport18BirthConstruction>>>()
        + size_of::<&NativeImport18BirthConstruction>()
        + size_of::<(&Identity, &bool, &Option<PacketCompleteAckHostRegistrationPlan>, &Option<Id>,
            &Option<PacketNative5CoordinatorInstallation>, &Option<Value>, &Option<Value>,
            &Option<Vec<u8>>, &Option<Vec<u8>>, &NativeImport18PrivateBirthAttempt, &Stage, &bool)>()
        + size_of::<(&usize, &u32, &ThreadId, &[u8; 32])>()
        + NativeImport18PrivateBirthAttempt::capacity_counter_scratch_data()
        + size_of::<[&Option<Value>; 2]>()
        + size_of::<std::array::IntoIter<&'static Option<Value>, 2>>()
        + size_of::<&mut PacketRuntimeMetadataRecordBank>()
        + size_of::<RetainedProtocolMetadataFacts>()
        + size_of::<Result<RetainedProtocolMetadataFacts, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
}
