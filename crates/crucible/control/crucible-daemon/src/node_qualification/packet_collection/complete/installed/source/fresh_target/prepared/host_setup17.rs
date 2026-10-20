//! Observes the complete retained prepared setup without cloning or live checks.
//!
//! Every field is destructured, including failed/incomplete Source-load slots.
//! The already-held capsule is joined by actual Rc identity and observed by the
//! enclosing action; this walk never reborrows its RefCell or resets an attempt.

use super::*;
use crate::node_qualification::packet_collection::complete::retained::Counter;
use crucible_engine::node_contract::{CollectingCompleteRestorationSource, RuntimeError};
use crucible_node_transport::retained_metadata::{
    RetainedProtocolMetadataFacts, observe_retained_native_launch,
    retained_native_launch_counter_scratch_data,
};
use std::mem::{size_of, size_of_val};

impl PreparedCompleteRestoration {
    pub(in crate::node_qualification::packet_collection::complete::installed::source::fresh_target) fn authenticate_host_setup17_target_data(
        &self,
        selection: &crucible_engine::node_contract::HostSchedulingSelection,
        resources: &crucible_node_format::ResourceLimits,
    ) -> Result<(), RuntimeError> {
        if !std::ptr::eq(selection, &self.selected.host)
            || !std::ptr::eq(resources, &self.selected.resources)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete::installed::source::fresh_target) fn charge_host_setup17_data(
        &self,
        counter: &mut Counter,
        original: Option<&Rc<RefCell<PacketCompleteRestorationPrebirth>>>,
    ) -> Result<(), RuntimeError> {
        let Self {
            selected,
            import18_selection: _,
            import18_templates,
            measurements,
            content,
            launches,
            directories,
            paths,
            receiver_group,
            receiver_reader,
            code_owners,
            code_authority,
            code_factory,
            code_plan,
            code_graph,
            prebirth,
            restored_prebirth_archive,
            restored_prebirth_slot_row: _,
            restored_prebirth_attempt,
            restored_prebirth_source,
            prebirth_attempted: _,
            prebirth_completed: _,
            installation_attempted: _,
        } = self;
        counter.add(size_of::<Option<Self>>()).map_err(limit)?;
        selected.charge_host_setup17_data(counter)?;
        import18_templates.charge_retained_data(counter)?;
        counter.charge(measurements).map_err(limit)?;
        if counter.rc(content).map_err(limit)? {
            counter.charge(content.as_ref()).map_err(limit)?;
        }
        for launch in launches {
            let facts =
                observe_retained_native_launch(launch).map_err(|_| RuntimeError::ResourceLimit)?;
            counter.metadata(&facts).map_err(limit)?;
        }
        counter.charge(directories).map_err(limit)?;
        counter.charge(paths).map_err(limit)?;
        counter
            .add(
                receiver_group
                    .original_retained_requested_storage_precredit_data(counter.remaining())?,
            )
            .map_err(limit)?;
        if let Some(reader) = receiver_reader {
            // Follow its actual private group even if another setup field ever
            // contains a different group. Equal values confer no alias discount.
            counter
                .add(
                    reader
                        .original_retained_requested_storage_precredit_data(counter.remaining())?,
                )
                .map_err(limit)?;
        }
        if let Some(owners) = code_owners {
            let CodeOwners { _graph, _host } = owners;
            _graph.charge_host_setup17_data(counter)?;
            let source = _host.source();
            if counter.rc(&source).map_err(limit)? {
                counter
                    .add(
                        source.retained_original_metadata_bytes_excluding_runtime_precredit_data(
                            counter.remaining(),
                        )?,
                    )
                    .map_err(limit)?;
            }
        }
        if counter.rc(code_authority).map_err(limit)? {
            counter
                .add(
                    code_authority
                        .original_retained_requested_storage_precredit_data(counter.remaining())?,
                )
                .map_err(limit)?;
        }
        counter
            .add(code_factory.retained_host_precredit_data(counter.remaining())?)
            .map_err(limit)?;
        if counter.rc(code_plan).map_err(limit)? {
            counter
                .add(code_plan.retained_allocation_bytes_excluding_authority_precredit_data()?)
                .map_err(limit)?;
        }
        if let Some(graph) = code_graph {
            if counter.rc(graph).map_err(limit)? {
                let inline = size_of_val(graph.as_ref());
                let demand = graph.original_retained_requested_storage_data(
                    counter
                        .remaining()
                        .checked_add(inline)
                        .ok_or(RuntimeError::ResourceLimit)?,
                )?;
                counter
                    .add(
                        demand
                            .checked_sub(inline)
                            .ok_or(RuntimeError::ResourceLimit)?,
                    )
                    .map_err(limit)?;
            }
        }
        match (prebirth.as_ref(), original) {
            (None, None) => {}
            (Some(capsule), Some(expected)) if Rc::ptr_eq(capsule, expected) => {
                // The enclosing action counts this SAME held capsule's children.
                // The true alias proof, rather than public bytes, permits reuse.
                counter.rc(capsule).map_err(limit)?;
            }
            _ => return Err(RuntimeError::ForeignAuthority),
        }
        if let Some(archive) = restored_prebirth_archive {
            let whole = archive.original_complete_load_retained_requested_storage_data()?;
            counter
                .add(
                    whole
                        .checked_sub(size_of_val(archive))
                        .ok_or(RuntimeError::ResourceLimit)?,
                )
                .map_err(limit)?;
        }
        if let Some(source) = restored_prebirth_source {
            // A completed Source may precede ticket issuance or survive an
            // unwound final guard. This is its real owner, not an empty phase.
            counter
                .add(
                    source.retained_restored_settled_prebirth_output_storage_data(
                        counter.remaining(),
                    )?,
                )
                .map_err(limit)?;
        }
        restored_load_slot::charge_retained_data(restored_prebirth_attempt, counter)?;
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete::installed::source::fresh_target) fn host_setup17_counter_scratch_data()
    -> Result<usize, RuntimeError> {
        let slot_scratch = match restored_load_slot::FIXED_CALLER_SCRATCH {
            Some(bytes) => bytes,
            None => return Err(RuntimeError::UnsupportedFacet),
        };
        let terms = [
            slot_scratch,
            retained_native_launch_counter_scratch_data(),
            import18_templates::Templates::retained_counter_scratch_data(),
            restored_load_slot::RETAINED_COUNTER_SCRATCH,
            PacketCompleteSemanticSource::retained_requested_storage_precredit_scratch_data(),
            CollectingCompleteRestorationSource::original_host17_preconstruction_counter_scratch_data(),
            PacketCompleteArchiveCodeFactory::retained_requested_storage_scratch_bytes()
                .map_err(|_| RuntimeError::ResourceLimit)?,
            CompleteArchiveCodeGraph::retained_requested_storage_scratch_bytes(),
            crucible_engine::node_state::complete_restored_settled_archive_validation_counter_scratch_data(
            ),
            HostSchedulingSource::retained_original_metadata_counter_scratch_data(),
            NativeArchiveRecord::original_complete_load_retained_counter_scratch_data(),
            size_of::<Counter>(),
            size_of::<RetainedProtocolMetadataFacts>(),
            size_of::<&Self>(),
            size_of::<&CollectingCompleteRestorationSource>(),
            size_of::<&crucible_engine::node_state::CompleteOriginalRestorationSource>(),
            size_of::<usize>(),
            size_of::<&CodeOwners>(),
            size_of::<&crucible_engine::node_adapters::cnp::PacketCompleteEffectReceiverReader>(),
            size_of::<&Rc<PacketCompleteEffectReceiverGroup>>(),
            size_of::<&Rc<InstalledPacketCompleteCollectionAuthority>>(),
            size_of::<&Rc<PacketCompleteArchiveCodeFactory>>(),
            size_of::<&Rc<InstalledConformancePlan>>(),
            size_of::<&Rc<CompleteArchiveCodeGraph>>(),
            size_of::<&NativeArchiveRecord>(),
            size_of::<Option<&Rc<RefCell<PacketCompleteRestorationPrebirth>>>>(),
            size_of::<Rc<HostSchedulingSource>>(),
            size_of::<&crucible_engine::node_state::CompleteRestoredSettledSourceLoadAttempt>(),
            size_of::<std::slice::Iter<'static, PacketNative5SourceLaunch>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
        ];
        terms.iter().try_fold(size_of_val(&terms), |total, bytes| {
            total.checked_add(*bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

fn limit(_: QualificationError) -> RuntimeError {
    RuntimeError::ResourceLimit
}

/// Exercises the actual unprepared code fixture; no ticket or live Source is forged.
#[cfg(test)]
pub(super) fn assert_actual_setup_census_data(owner: &mut PreparedCompleteRestoration) {
    use super::super::HostSource17SetupBorrow;
    let maximum = usize::try_from(owner.selected.resources.memory_bytes.get()).unwrap();
    assert!(maximum > 0);
    assert!(owner.prebirth.is_none());
    assert!(owner.restored_prebirth_archive.is_none());
    assert!(owner.restored_prebirth_slot_row.is_none());
    assert!(owner.restored_prebirth_attempt.is_none());
    assert!(
        size_of::<PreparedCompleteRestoration>()
            < size_of::<Option<CompleteRestoredSettledSourceLoadAttempt>>()
    );
    assert!(owner.restored_prebirth_source.is_none());
    let loan = HostSource17SetupBorrow::prepared_data(owner);
    loan.authenticate_target_data(&owner.selected.host, &owner.selected.resources)
        .unwrap();
    let copied_selection = owner.selected.host.clone();
    let copied_resources = owner.selected.resources.clone();
    assert!(
        loan.authenticate_target_data(&copied_selection, &owner.selected.resources)
            .is_err()
    );
    assert!(
        loan.authenticate_target_data(&owner.selected.host, &copied_resources)
            .is_err()
    );
    let mut measured = Counter::new(maximum);
    loan.charge_data(&mut measured, None).unwrap();
    let demand = measured.bytes();
    assert!(demand > size_of::<Option<PreparedCompleteRestoration>>());
    let mut exact = Counter::new(demand);
    loan.charge_data(&mut exact, None).unwrap();
    assert_eq!(exact.bytes(), demand);
    let mut short = Counter::new(demand - 1);
    assert!(loan.charge_data(&mut short, None).is_err());
    assert!(owner.prebirth.is_none());
    assert!(!owner.prebirth_attempted);

    let capacity = owner.selected.schema.capacity();
    let value = owner.selected.schema.clone();
    owner.selected.schema.reserve_exact(capacity + 31);
    let extra = owner.selected.schema.capacity() - capacity;
    assert!(extra > 0);
    assert_eq!(owner.selected.schema, value);
    let mut enlarged = Counter::new(maximum);
    HostSource17SetupBorrow::prepared_data(owner)
        .charge_data(&mut enlarged, None)
        .unwrap();
    assert_eq!(enlarged.bytes(), demand + extra);
    assert!(owner.prebirth.is_none());
    assert!(!owner.prebirth_attempted);
}
