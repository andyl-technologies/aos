//! Conjoins completed cold owners with the actual installed static declaration.
//!
//! Factory accounting is admitted before its census. Each native import geometry
//! is built under its own fixed-workspace row from the same sealed five roles.
//! These results are immutable archive DATA and confer no fresh native rights.

use super::*;
use crate::node_adapters::cnp::{
    CnpSemanticInstallation, CnpSemanticSource, PacketCompleteSemanticSource,
};
use crate::node_contract::HostSchedulingSelection;
use crucible_node_provider::protocol_snapshot::restored_settled17::{
    RestoredSettledNative17Input, RestoredSettledNativeImportGeometryData,
};
use std::mem::size_of;

/// Borrows a completed archive declaration and its independently validated owners.
///
/// No constructor, clone or deserializer is available. The loan belongs to the
/// exact authenticated Index occurrence and cannot create fresh runtime custody.
pub struct CompletedRestoredSettledArchive17Declaration<'a> {
    archive: &'a NativeArchiveRecord,
    collection: &'a RetainedCold17Collection,
}

impl CompletedRestoredSettledArchive17Declaration<'_> {
    /// Borrows the exact signed archive occurrence which owns these DATA.
    pub fn archive_data(&self) -> &NativeArchiveRecord {
        self.archive
    }

    /// Returns the three exact native owner positions validated by the factory.
    ///
    /// # Errors
    /// Refuses a declaration whose completed private bank is unavailable.
    pub fn native_owner_indices_data(&self) -> Result<[usize; 3], RuntimeError> {
        self.collection.production_owner_indices_data()
    }
}

impl CompleteRestoredSettledArchiveValidation<'_> {
    /// Validates completed owners against genuine installed Source3/Host code.
    ///
    /// The census callback runs only after its declared prewalk workspace has
    /// been independently admitted. It must count the actual factory and all
    /// additional still-live owners, without decoding an archived component.
    /// Source installation operands are original immutable declarations, never
    /// reconstructed live historical Sources or fresh target permissions.
    ///
    /// # Errors
    /// Refuses foreign origin, incomplete static declarations, failed collectors,
    /// changed native roles, reused output slots or insufficient independent
    /// requested storage. The completed decoder owners remain in their bank.
    pub fn authenticate_production_declaration_data(
        &self,
        sources: [&PacketCompleteSemanticSource; 3],
        controller_executables: [&ContentRef; 3],
        host: &HostSchedulingSelection,
        factory_prewalk_transient: usize,
        factory_prewalk_scratch: usize,
        census_counter: impl FnOnce() -> Result<usize, StateError>,
        census: impl FnOnce() -> Result<usize, StateError>,
    ) -> Result<(), StateError> {
        self.validation_origin.authenticate(self.archive)?;
        let step = RestoredArchive17ValidationStep::ordinary_data(
            RestoredArchive17ValidationStage::FactoryPreparation,
        )?;
        let scratch = add(factory_prewalk_scratch, production_counter_scratch_data())?;
        // Captured under the actual preceding Core constructor's admitted census;
        // no recursive factory or collection walk precedes this prewalk.
        let prefix = add(
            self.terminal_prefix_retained_bytes,
            self.validation_additional_retained_bytes,
        )?;
        self.production_begin_data(step, prefix, factory_prewalk_transient, scratch)?;
        // The query returns actual fixed observer layouts without walking heap
        // capacities. Its controls are covered by the separate prewalk above.
        let counter = census_counter();
        self.validation_origin.authenticate(self.archive)?;
        let constructor_scratch = add(scratch, counter?)?;
        self.production_construct_data(
            step,
            prefix,
            0,
            factory_prewalk_transient,
            constructor_scratch,
        )?;
        let observed = census();
        self.validation_origin.authenticate(self.archive)?;
        let measured = observed?;
        let additional = add(measured, self.validation_additional_retained_bytes)?;
        // The census itself owns no heap. These pre-existing owners are then
        // included in every collector constructor before its first allocation.
        production_limit_data(
            self,
            &[
                self.terminal_prefix_retained_bytes,
                additional,
                factory_prewalk_transient,
                constructor_scratch,
            ],
        )?;
        if self.host.source != *host {
            return Err(refused("settled17 archived Host declaration differs"));
        }
        for source in sources {
            let source = source.installation();
            if self.graph.descriptor(&source.descriptor.id) != Some(&source.descriptor)
                || self.graph.binding(&source.descriptor.id) != Some(&source.binding)
            {
                return Err(refused("settled17 static Source graph declaration differs"));
            }
        }
        let host_node = &host.descriptor.id;
        if self.graph.descriptor(host_node) != Some(&host.descriptor)
            || self.graph.binding(host_node) != Some(&host.binding)
        {
            return Err(refused("settled17 static Host graph declaration differs"));
        }
        self.production_finish_data(step, prefix)?;
        self.collect_current_components_data(additional)?;

        let mut indices = [0usize; 3];
        for (index, expected_source) in sources.into_iter().enumerate() {
            let expected = expected_source.installation();
            let source_index = RestoredArchive17SourceIndex::from_data(index)?;
            let step = RestoredArchive17ValidationStep::ordinary_data(
                RestoredArchive17ValidationStage::FactoryNativeGeometry(source_index),
            )?;
            let prior = self.production_collection_cache_data()?;
            self.production_begin_data(step, prior, 0, production_counter_scratch_data())?;
            self.production_construct_data(step, prior, 0, 0, production_counter_scratch_data())?;
            {
                let bank = self
                    .collection
                    .try_borrow()
                    .map_err(|_| refused("settled17 production collection is busy"))?;
                let collection = bank
                    .as_ref()
                    .ok_or_else(|| refused("settled17 production collection absent"))?;
                let mut owners = self
                    .archive
                    .owners()
                    .iter()
                    .enumerate()
                    .filter(|(_, owner)| {
                        owner.owner == expected.owner.owner.id
                            && owner.participants.len() == 1
                            && owner.participants[0] == expected.descriptor.id
                    });
                let (owner_index, owner) = owners
                    .next()
                    .ok_or_else(|| refused("settled17 declared native owner absent"))?;
                if owners.next().is_some() || indices[..index].contains(&owner_index) {
                    return Err(refused("settled17 declared native owner is not unique"));
                }
                let member = collection
                    .member_data(self.archive, owner_index)
                    .map_err(crate::node_state::schema)?;
                let archived = member.source_history.original_installation_data();
                expected_source
                    .authenticate_archived_program17_data(&archived.launch.program)
                    .map_err(crate::node_state::schema)?;
                if &archived.launch.controller_executable != controller_executables[index] {
                    return Err(refused(
                        "settled17 archived controller executable differs from installed code",
                    ));
                }
                if archived.provider != expected.provider
                    || archived.profile != expected.profile
                    || archived.descriptor != expected.descriptor
                    || archived.binding != expected.binding
                    || archived.capabilities != expected.capabilities
                    || archived.exact_facet != expected.exact_facet
                    || archived.guarantees != expected.guarantees
                    || archived.owner != expected.owner
                    || archived.realize != expected.realize
                    || archived.admission != expected.admission
                    || archived.transaction != expected.transaction
                    || archived.gate != expected.gate
                    || archived.admission_receipt != expected.admission_receipt
                    || archived.world_binding_hash != expected.world_binding_hash
                    || archived.receipt_schema != expected.receipt_schema
                    || archived.maximum_operations != expected.maximum_operations
                    || archived.maximum_result_bytes != expected.maximum_result_bytes
                    || archived.maximum_authorization_bytes != expected.maximum_authorization_bytes
                    || archived.maximum_semantic_bytes != expected.maximum_semantic_bytes
                {
                    return Err(refused("settled17 original static installation differs"));
                }

                let body = |reference| {
                    self.content
                        .get(reference)
                        .ok_or_else(|| refused("settled17 native geometry role absent"))
                };
                let input = RestoredSettledNative17Input {
                    snapshot: (member.references[0], body(member.references[0])?),
                    current_protocol: (member.references[1], body(member.references[1])?),
                    control: (member.references[2], body(member.references[2])?),
                    anchor: (member.references[3], body(member.references[3])?),
                    journal: (member.references[4], body(member.references[4])?),
                };
                let normalization = usize::try_from(
                    member
                        .native
                        .archived_normalization_maximum_data()
                        .map_err(crate::node_state::schema)?
                        .get(),
                )
                .map_err(crate::node_state::schema)?;
                let geometry =
                    RestoredSettledNativeImportGeometryData::from_validated_settled17_data(
                        &input,
                        member.native,
                        &member.native_limits,
                        normalization,
                    )
                    .map_err(crate::node_state::schema)?;
                let source_decode = member
                    .source_decode_axes
                    .into_iter()
                    .try_fold(0usize, add)?;
                let data = ValidatedCompleteRestoredSettledNativeRestorationData::from_validated_native_data(
                    geometry, member.references,
                    [input.snapshot.1.len(), input.current_protocol.1.len(), input.control.1.len(),
                        input.anchor.1.len(), input.journal.1.len()],
                    source_decode, owner, self.content,
                ).map_err(crate::node_state::schema)?;
                self.retain_restored_settled_native_restoration_data(owner, data)
                    .map_err(crate::node_state::schema)?;
                indices[index] = owner_index;
            }
            // All private collection loans are gone before the full observer.
            self.production_finish_data(step, prior)?;
        }
        let mut bank = self
            .collection
            .try_borrow_mut()
            .map_err(|_| refused("settled17 production declaration bank is busy"))?;
        bank.as_mut()
            .ok_or_else(|| refused("settled17 production declaration absent"))?
            .complete_production_declaration_data(self.archive, indices)
            .map_err(crate::node_state::schema)?;
        drop(bank);
        self.validation_origin.authenticate(self.archive)
    }

    /// Lends the completed declaration under its same actual archive occurrence.
    ///
    /// # Errors
    /// Refuses foreign origin, a busy bank or missing genuine factory conjunction.
    pub fn with_completed_production_declaration_data<R>(
        &self,
        inspect: impl FnOnce(&CompletedRestoredSettledArchive17Declaration<'_>) -> Result<R, StateError>,
    ) -> Result<R, StateError> {
        self.validation_origin.authenticate(self.archive)?;
        let bank = self
            .collection
            .try_borrow()
            .map_err(|_| refused("settled17 completed declaration bank is busy"))?;
        let collection = bank
            .as_ref()
            .ok_or_else(|| refused("settled17 declaration absent"))?;
        collection
            .authenticate_production_declaration_data(self.archive)
            .map_err(crate::node_state::schema)?;
        let result = inspect(&CompletedRestoredSettledArchive17Declaration {
            archive: self.archive,
            collection,
        });
        self.validation_origin.authenticate(self.archive)?;
        result
    }

    fn production_collection_cache_data(&self) -> Result<usize, StateError> {
        let bank = self
            .collection
            .try_borrow()
            .map_err(|_| refused("settled17 production cache is busy"))?;
        let collection = bank
            .as_ref()
            .ok_or_else(|| refused("settled17 production cache absent"))?;
        collection
            .authenticate_completed_data(self.archive)
            .map_err(crate::node_state::schema)?;
        let cache = collection.production_cache_data();
        if self.terminal_admission.is_none() {
            add(cache, self.terminal_prefix_retained_bytes)
        } else {
            Ok(cache)
        }
    }

    fn production_begin_data(
        &self,
        step: RestoredArchive17ValidationStep,
        prior: usize,
        transient: usize,
        scratch: usize,
    ) -> Result<(), StateError> {
        production_limit_data(self, &[prior, transient, scratch])?;
        let result = match self.terminal_admission {
            Some(admission) => admission.begin_stage_data(
                RestoredArchive17ValidationPrewalkData::new_data(step, prior, transient, scratch)?,
            ),
            None => Ok(()),
        };
        self.validation_origin.authenticate(self.archive)?;
        result
    }

    fn production_construct_data(
        &self,
        step: RestoredArchive17ValidationStep,
        prior: usize,
        retained: usize,
        transient: usize,
        scratch: usize,
    ) -> Result<(), StateError> {
        production_limit_data(self, &[prior, retained, transient, scratch])?;
        let result = match self.terminal_admission {
            Some(admission) => admission.construct_stage_data(
                RestoredArchive17ValidationConstructionData::new_data(
                    step, prior, retained, transient, scratch,
                )?,
            ),
            None => Ok(()),
        };
        self.validation_origin.authenticate(self.archive)?;
        result
    }

    fn production_finish_data(
        &self,
        step: RestoredArchive17ValidationStep,
        actual: usize,
    ) -> Result<(), StateError> {
        let result = match self.terminal_admission {
            Some(admission) => admission.finish_stage_data(step, actual),
            None => Ok(()),
        };
        self.validation_origin.authenticate(self.archive)?;
        result
    }
}

fn production_limit_data(
    scope: &CompleteRestoredSettledArchiveValidation<'_>,
    terms: &[usize],
) -> Result<(), StateError> {
    let maximum = usize::try_from(scope.archive.limits.state.maximum_native_memory_bytes)
        .map_err(crate::node_state::schema)?
        .min(scope.archive.limits.state.maximum_total_content_bytes)
        .min(scope.archive.limits.native.maximum_total_record_bytes);
    let total = terms.iter().copied().try_fold(0usize, add)?;
    if total > maximum {
        return Err(refused(
            "settled17 production constructor exceeds independent storage",
        ));
    }
    Ok(())
}

fn add(left: usize, right: usize) -> Result<usize, StateError> {
    left.checked_add(right)
        .ok_or_else(|| refused("settled17 production accounting overflow"))
}

pub(super) fn production_counter_scratch_data() -> usize {
    CompleteRestoredSettledNativeRestorationData::counter_scratch_data()
        + PacketCompleteSemanticSource::archived_program17_counter_scratch_data()
        + size_of::<[&PacketCompleteSemanticSource; 3]>()
        + size_of::<[&ContentRef; 3]>()
        + crucible_node_provider::protocol_snapshot::restored_settled17::restored_settled_native17_counter_scratch_data()
        + size_of::<CompletedRestoredSettledArchive17Declaration<'static>>()
        + size_of::<[usize; 5]>()
        + size_of::<[usize; 4]>()
        + size_of::<&CnpSemanticInstallation>()
        + size_of::<RetainedCold17MemberView<'static>>()
        + size_of::<RestoredArchive17ValidationStep>()
        + size_of::<RestoredArchive17ValidationPrewalkData>()
        + size_of::<RestoredArchive17ValidationConstructionData>()
        + size_of::<Result<(), StateError>>()
        + size_of::<Result<usize, StateError>>()
        + size_of::<[usize; 3]>()
        + size_of::<std::cell::Ref<'static, Option<RetainedCold17Collection>>>()
        + size_of::<std::cell::RefMut<'static, Option<RetainedCold17Collection>>>()
        + size_of::<[&ContentRef; 5]>()
}
