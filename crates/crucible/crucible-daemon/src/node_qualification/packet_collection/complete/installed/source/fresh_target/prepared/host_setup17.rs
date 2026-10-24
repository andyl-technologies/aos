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

/// Stores each non-template Prepared field reference instead of a whole-owner reference.
///
/// The root inline header still belongs to Option<Prepared>; this view supplies
/// no smaller owner, detached partial, stored byte total or authority token.
struct PreparedSetupRemainder<'a> {
    selected: &'a Manifest,
    configuration_pin: &'a Option<InstalledCompleteSceneManifest>,
    import18_selection: &'a Option<import18_templates::Import18Selection>,
    measurements: &'a [PacketFixtureMeasurements; 3],
    content: &'a Rc<BTreeMap<ContentRef, Vec<u8>>>,
    launches: &'a PreparedLaunches,
    directories: &'a [PathBuf; 3],
    paths: &'a [PathBuf; 3],
    receiver_group: &'a Rc<PacketCompleteEffectReceiverGroup>,
    receiver_reader: &'a Option<PacketCompleteEffectReceiverReader>,
    code_owners: &'a Option<CodeOwners>,
    code_authority: &'a Rc<InstalledPacketCompleteCollectionAuthority>,
    code_factory: &'a Rc<PacketCompleteArchiveCodeFactory>,
    code_plan: &'a Rc<InstalledConformancePlan>,
    code_graph: &'a Option<Rc<CompleteArchiveCodeGraph>>,
    prebirth: &'a Option<Rc<RefCell<PacketCompleteRestorationPrebirth>>>,
    restored_prebirth_source: &'a Option<CollectingCompleteRestorationSource>,
    restored_prebirth_archive: &'a Option<NativeArchiveRecord>,
    restored_prebirth_slot_row: &'a Option<restored_load_slot::ConstructionData>,
    restored_prebirth_attempt: &'a Option<Box<Option<CompleteRestoredSettledSourceLoadAttempt>>>,
    prebirth_attempted: &'a bool,
    prebirth_completed: &'a bool,
    installation_attempted: &'a bool,
}

impl PreparedSetupRemainder<'_> {
    fn charge_before_templates_data(&self, counter: &mut Counter) -> Result<(), RuntimeError> {
        let selected = self.selected;
        counter
            .add(size_of::<Option<PreparedCompleteRestoration>>())
            .map_err(limit)?;
        selected.charge_host_setup17_data(counter)?;
        charge_configuration_pin_data(self.configuration_pin, counter)?;
        Ok(())
    }

    fn charge_after_templates_data(
        &self,
        counter: &mut Counter,
        original: Option<&Rc<RefCell<PacketCompleteRestorationPrebirth>>>,
    ) -> Result<(), RuntimeError> {
        // Copy the actual references out of the view. Destructuring &self would
        // add a reference layer and could select a different Owned operation.
        let Self {
            selected: _,
            configuration_pin: _,
            import18_selection: _,
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
            restored_prebirth_source,
            restored_prebirth_archive,
            restored_prebirth_slot_row: _,
            restored_prebirth_attempt,
            prebirth_attempted: _,
            prebirth_completed: _,
            installation_attempted: _,
        } = *self;
        counter.charge(measurements).map_err(limit)?;
        if counter.rc(content).map_err(limit)? {
            counter.charge(content.as_ref()).map_err(limit)?;
        }
        counter
            .add(launches.retained_allocation_data()?)
            .map_err(limit)?;
        for launch in launches.originals()? {
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
}

// These new field views are actual stack controls, not retained owner bytes.
// Every helper below is evaluated only in this const item; no runtime quote
// recursion, allocator supplier or future parser-state admission is introduced.
const fn prepared_field_references_data() -> usize {
    size_of::<&Manifest>()
        + size_of::<&Option<InstalledCompleteSceneManifest>>()
        + size_of::<&Option<import18_templates::Import18Selection>>()
        + size_of::<&[PacketFixtureMeasurements; 3]>()
        + size_of::<&Rc<BTreeMap<ContentRef, Vec<u8>>>>()
        + size_of::<&PreparedLaunches>()
        + size_of::<&[PathBuf; 3]>()
        + size_of::<&[PathBuf; 3]>()
        + size_of::<&Rc<PacketCompleteEffectReceiverGroup>>()
        + size_of::<&Option<PacketCompleteEffectReceiverReader>>()
        + size_of::<&Option<CodeOwners>>()
        + size_of::<&Rc<InstalledPacketCompleteCollectionAuthority>>()
        + size_of::<&Rc<PacketCompleteArchiveCodeFactory>>()
        + size_of::<&Rc<InstalledConformancePlan>>()
        + size_of::<&Option<Rc<CompleteArchiveCodeGraph>>>()
        + size_of::<&Option<Rc<RefCell<PacketCompleteRestorationPrebirth>>>>()
        + size_of::<&Option<CollectingCompleteRestorationSource>>()
        + size_of::<&Option<NativeArchiveRecord>>()
        + size_of::<&Option<restored_load_slot::ConstructionData>>()
        + size_of::<&Option<Box<Option<CompleteRestoredSettledSourceLoadAttempt>>>>()
        + size_of::<&bool>()
        + size_of::<&bool>()
        + size_of::<&bool>()
}

const fn prepared_suffix_references_data() -> usize {
    size_of::<&[PacketFixtureMeasurements; 3]>()
        + size_of::<&Rc<BTreeMap<ContentRef, Vec<u8>>>>()
        + size_of::<&PreparedLaunches>()
        + size_of::<&[PathBuf; 3]>()
        + size_of::<&[PathBuf; 3]>()
        + size_of::<&Rc<PacketCompleteEffectReceiverGroup>>()
        + size_of::<&Option<PacketCompleteEffectReceiverReader>>()
        + size_of::<&Option<CodeOwners>>()
        + size_of::<&Rc<InstalledPacketCompleteCollectionAuthority>>()
        + size_of::<&Rc<PacketCompleteArchiveCodeFactory>>()
        + size_of::<&Rc<InstalledConformancePlan>>()
        + size_of::<&Option<Rc<CompleteArchiveCodeGraph>>>()
        + size_of::<&Option<Rc<RefCell<PacketCompleteRestorationPrebirth>>>>()
        + size_of::<&Option<CollectingCompleteRestorationSource>>()
        + size_of::<&Option<NativeArchiveRecord>>()
        + size_of::<&Option<Box<Option<CompleteRestoredSettledSourceLoadAttempt>>>>()
}

pub(super) const fn runtime_try_controls_data<Output, Return>() -> usize {
    use std::{convert::Infallible, ops::ControlFlow};

    size_of::<Result<Output, RuntimeError>>() // Result::branch owned input
        + size_of::<Output>() // Ok binding
        + size_of::<Output>() // Continue owned input
        + size_of::<RuntimeError>() // Err binding
        + size_of::<RuntimeError>() // residual Err owned input
        + size_of::<Result<Infallible, RuntimeError>>() // residual initializer
        + size_of::<Result<Infallible, RuntimeError>>() // Break owned input
        + size_of::<ControlFlow<Result<Infallible, RuntimeError>, Output>>() // initializer
        + size_of::<ControlFlow<Result<Infallible, RuntimeError>, Output>>() // return
        + size_of::<Result<Infallible, RuntimeError>>() // FromResidual input
        + size_of::<RuntimeError>() // residual Err binding
        + size_of::<RuntimeError>() // identity From input
        + size_of::<RuntimeError>() // identity From return
        + size_of::<RuntimeError>() // outer Err owned input
        + size_of::<Result<Return, RuntimeError>>() // outer Err initializer
        + size_of::<Result<Return, RuntimeError>>() // FromResidual return
}

const PREPARED_PROJECTION_CONTROLS: usize = size_of::<&PreparedCompleteRestoration>() // additional projection receiver
    + prepared_field_references_data() // exhaustive reference bindings
    + prepared_field_references_data() // actual remainder field operands
    + size_of::<&import18_templates::Templates>() // exhaustive template reference binding
    + size_of::<&import18_templates::Templates>() // tuple template field operand
    + size_of::<&import18_templates::Templates>() // caller template binding
    + size_of::<PreparedSetupRemainder<'static>>() // remainder literal initializer
    + size_of::<PreparedSetupRemainder<'static>>() // tuple owned field operand
    + size_of::<PreparedSetupRemainder<'static>>() // caller remainder binding
    + size_of::<(PreparedSetupRemainder<'static>, &'static import18_templates::Templates)>() // tuple initializer
    + size_of::<(PreparedSetupRemainder<'static>, &'static import18_templates::Templates)>() // projection return
    + size_of::<(PreparedSetupRemainder<'static>, &'static import18_templates::Templates)>() // caller destructure input
    + size_of::<&PreparedSetupRemainder<'static>>() // prefix receiver
    + size_of::<&PreparedSetupRemainder<'static>>() // suffix receiver
    + prepared_suffix_references_data() // suffix's by-value reference bindings
    + size_of::<&Manifest>() // prefix selected binding
    + size_of::<&mut Counter>() * 3 // prefix/template/suffix helper arguments
    + size_of::<Option<&Rc<RefCell<PacketCompleteRestorationPrebirth>>>>() // suffix argument
    + size_of::<()>() // prefix Ok constructor owned unit operand
    + size_of::<Result<(), RuntimeError>>() // prefix Ok initializer
    + size_of::<Result<(), RuntimeError>>() // prefix return
    + size_of::<Result<(), RuntimeError>>() // suffix helper return
    + runtime_try_controls_data::<(), ()>() // new prefix propagation in wrapper
    + CONFIGURATION_PIN_CONTROLS
    + PREPARED_PROJECTION_QUOTE_CONTROLS;

// The inline pin is already in Option<Prepared>. This walk adds only actual
// original path/reference backing; neither digest nor path grants authority.
fn charge_configuration_pin_data(
    pin: &Option<InstalledCompleteSceneManifest>,
    counter: &mut Counter,
) -> Result<(), RuntimeError> {
    if let Some(InstalledCompleteSceneManifest { path, expected }) = pin {
        counter.charge(path).map_err(limit)?;
        counter.charge(expected).map_err(limit)?;
    }
    Ok(())
}

const CONFIGURATION_PIN_CONTROLS: usize = size_of::<&Option<InstalledCompleteSceneManifest>>() // walk receiver
    + size_of::<&mut Counter>() // actual counter loan
    + size_of::<&PathBuf>() // original path binding
    + size_of::<&crucible_node_format::ContentRef>() // original expected reference binding
    + size_of::<Result<(), RuntimeError>>() // helper return
    + size_of::<()>() // Ok input
    + size_of::<Result<(), RuntimeError>>() // Ok initializer
    + runtime_try_controls_data::<(), ()>() // helper propagation from prefix
    + runtime_try_controls_data::<(), ()>(); // each sequential mapped charge

// The declaration's actual term-array initializer/local and fold operands
// are named before that same existing counter getter constructs its array.
const PREPARED_PROJECTION_QUOTE_CONTROLS: usize = size_of::<[usize; 32]>() // changed initializer
    + size_of::<[usize; 32]>() // actual local
    + size_of::<&[usize]>()
    + size_of::<std::slice::Iter<'static, usize>>()
    + size_of::<&mut std::slice::Iter<'static, usize>>()
    + size_of::<&usize>()
    + size_of::<usize>() // fold total
    + size_of::<Option<usize>>() // checked addition
    + size_of::<Result<usize, RuntimeError>>();

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

    /// Projects all current fields for the ordinary shared census only.
    ///
    /// A later mutable-state driver must destructure disjoint fields itself;
    /// calling this shared whole-owner helper would borrow that state too.
    fn host_setup17_observation_parts_data(
        &self,
    ) -> (PreparedSetupRemainder<'_>, &import18_templates::Templates) {
        let Self {
            selected,
            configuration_pin,
            import18_selection,
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
            restored_prebirth_source,
            restored_prebirth_archive,
            restored_prebirth_slot_row,
            restored_prebirth_attempt,
            prebirth_attempted,
            prebirth_completed,
            installation_attempted,
        } = self;
        (
            PreparedSetupRemainder {
                selected,
                configuration_pin,
                import18_selection,
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
                restored_prebirth_source,
                restored_prebirth_archive,
                restored_prebirth_slot_row,
                restored_prebirth_attempt,
                prebirth_attempted,
                prebirth_completed,
                installation_attempted,
            },
            import18_templates,
        )
    }

    pub(in crate::node_qualification::packet_collection::complete::installed::source::fresh_target) fn charge_host_setup17_data(
        &self,
        counter: &mut Counter,
        original: Option<&Rc<RefCell<PacketCompleteRestorationPrebirth>>>,
    ) -> Result<(), RuntimeError> {
        let (remainder, templates) = self.host_setup17_observation_parts_data();
        remainder.charge_before_templates_data(counter)?;
        templates.charge_retained_data(counter)?;
        remainder.charge_after_templates_data(counter, original)
    }

    /// Keeps the pre-refactor defining walk as an independent test oracle.
    #[cfg(test)]
    pub(in crate::node_qualification::packet_collection::complete::installed::source::fresh_target) fn charge_unprojected_host_setup17_data(
        &self,
        counter: &mut Counter,
        original: Option<&Rc<RefCell<PacketCompleteRestorationPrebirth>>>,
    ) -> Result<(), RuntimeError> {
        let Self {
            selected,
            configuration_pin,
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
        charge_configuration_pin_data(configuration_pin, counter)?;
        import18_templates.charge_unprojected_retained_data(counter)?;
        counter.charge(measurements).map_err(limit)?;
        if counter.rc(content).map_err(limit)? {
            counter.charge(content.as_ref()).map_err(limit)?;
        }
        counter
            .add(launches.retained_allocation_data()?)
            .map_err(limit)?;
        for launch in launches.originals()? {
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
            PREPARED_PROJECTION_CONTROLS,
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
    assert_projected_setup_matches_original_data(owner);
    import18_templates::assert_projection_members_data(owner.launches.originals().unwrap());
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

/// Checks the genuine fixture against the exact pre-refactor walk and owners.
#[cfg(test)]
fn assert_projected_setup_matches_original_data(owner: &PreparedCompleteRestoration) {
    let mut original = Counter::new(usize::MAX);
    owner
        .charge_unprojected_host_setup17_data(&mut original, None)
        .unwrap();
    let demand = original.bytes();
    let (remainder, templates) = owner.host_setup17_observation_parts_data();
    assert!(std::ptr::eq(remainder.selected, &owner.selected));
    assert!(std::ptr::eq(
        remainder.configuration_pin,
        &owner.configuration_pin
    ));
    assert!(std::ptr::eq(
        remainder.import18_selection,
        &owner.import18_selection
    ));
    assert!(std::ptr::eq(remainder.measurements, &owner.measurements));
    assert!(std::ptr::eq(remainder.content, &owner.content));
    assert!(std::ptr::eq(remainder.launches, &owner.launches));
    assert!(std::ptr::eq(remainder.directories, &owner.directories));
    assert!(std::ptr::eq(remainder.paths, &owner.paths));
    assert!(std::ptr::eq(
        remainder.receiver_group,
        &owner.receiver_group
    ));
    assert!(std::ptr::eq(
        remainder.receiver_reader,
        &owner.receiver_reader
    ));
    assert!(std::ptr::eq(remainder.code_owners, &owner.code_owners));
    assert!(std::ptr::eq(
        remainder.code_authority,
        &owner.code_authority
    ));
    assert!(std::ptr::eq(remainder.code_factory, &owner.code_factory));
    assert!(std::ptr::eq(remainder.code_plan, &owner.code_plan));
    assert!(std::ptr::eq(remainder.code_graph, &owner.code_graph));
    assert!(std::ptr::eq(remainder.prebirth, &owner.prebirth));
    assert!(std::ptr::eq(
        remainder.restored_prebirth_source,
        &owner.restored_prebirth_source
    ));
    assert!(std::ptr::eq(
        remainder.restored_prebirth_archive,
        &owner.restored_prebirth_archive
    ));
    assert!(std::ptr::eq(
        remainder.restored_prebirth_slot_row,
        &owner.restored_prebirth_slot_row
    ));
    assert!(std::ptr::eq(
        remainder.restored_prebirth_attempt,
        &owner.restored_prebirth_attempt
    ));
    assert!(std::ptr::eq(
        remainder.prebirth_attempted,
        &owner.prebirth_attempted
    ));
    assert!(std::ptr::eq(
        remainder.prebirth_completed,
        &owner.prebirth_completed
    ));
    assert!(std::ptr::eq(
        remainder.installation_attempted,
        &owner.installation_attempted
    ));

    let mut prefix = Counter::new(usize::MAX);
    prefix
        .add(size_of::<Option<PreparedCompleteRestoration>>())
        .unwrap();
    owner
        .selected
        .charge_host_setup17_data(&mut prefix)
        .unwrap();
    let prefix_bytes = prefix.bytes();
    let restrictions = [0, prefix_bytes - 1, prefix_bytes, demand - 1, demand];
    for maximum in restrictions {
        let mut expected = Counter::new(maximum);
        let before = owner.charge_unprojected_host_setup17_data(&mut expected, None);
        let mut actual = Counter::new(maximum);
        let after = owner.charge_host_setup17_data(&mut actual, None);
        assert_eq!(before.is_ok(), after.is_ok());
        assert_eq!(expected.bytes(), actual.bytes());
    }

    let mut actual = Counter::new(demand);
    remainder.charge_before_templates_data(&mut actual).unwrap();
    assert_eq!(actual.bytes(), prefix_bytes);
    templates.charge_retained_data(&mut actual).unwrap();
    remainder
        .charge_after_templates_data(&mut actual, None)
        .unwrap();
    assert_eq!(actual.bytes(), demand);
    // These are actual roots visited by the same walk, not equal-value credits.
    assert!(!actual.rc(&owner.content).unwrap());
    assert!(!actual.rc(&owner.code_authority).unwrap());
    assert!(!actual.rc(&owner.code_plan).unwrap());
    assert!(!actual.rc(owner.code_graph.as_ref().unwrap()).unwrap());
    assert!(owner.prebirth.is_none());
    assert!(!owner.prebirth_attempted);
}

#[test]
fn pinned_configuration_observer_counts_actual_backing_with_exact_short_control() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("configuration.json");
    let bytes = b"{}";
    std::fs::write(&path, bytes).unwrap();
    let expected = crucible_node_format::canonical::content_ref(bytes, "application/json").unwrap();
    let mut pin = Some(InstalledCompleteSceneManifest::new(path, expected).unwrap());
    let mut measured = Counter::new(usize::MAX);
    charge_configuration_pin_data(&pin, &mut measured).unwrap();
    let actual = measured.bytes();
    assert!(actual > 0);

    let mut exact = Counter::new(actual);
    charge_configuration_pin_data(&pin, &mut exact).unwrap();
    assert_eq!(exact.bytes(), actual);
    let mut short = Counter::new(actual - 1);
    assert!(charge_configuration_pin_data(&pin, &mut short).is_err());

    let original = pin.as_ref().unwrap().path.clone();
    let before = pin.as_ref().unwrap().path.as_os_str().len();
    let old_capacity = pin.as_ref().unwrap().path.capacity();
    pin.as_mut().unwrap().path.reserve_exact(old_capacity + 31);
    assert_eq!(pin.as_ref().unwrap().path, original);
    assert_eq!(pin.as_ref().unwrap().path.as_os_str().len(), before);
    let extra = pin.as_ref().unwrap().path.capacity() - old_capacity;
    assert!(extra > 0);
    let mut grown = Counter::new(usize::MAX);
    charge_configuration_pin_data(&pin, &mut grown).unwrap();
    assert_eq!(grown.bytes(), actual + extra);
}
