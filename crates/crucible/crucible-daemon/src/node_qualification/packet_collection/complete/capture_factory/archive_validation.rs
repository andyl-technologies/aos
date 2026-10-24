//! Validates the actual first complete Capture before signing or cold adoption.
//!
//! Core authenticates the original writer or selected historical load. Every
//! native/host/common/registry body is conjoined under that scope. Data decoding
//! cannot create a native issuer, fresh target, allocation permission or Ready.

mod limits;

use super::*;
use crucible_engine::{
    node_adapters::cnp::{
        PacketCompleteArchivedOwnerData, PacketCompleteArchivedSemantics,
        PacketCompleteSemanticSource,
    },
    node_contract::{
        OriginalCaptureAttemptRecord, OriginalCaptureOwnerRecord, OriginalCaptureOwnerState,
    },
    node_state::{
        CompleteOriginalArchiveValidation, NativeOwnerState, ValidatedCompleteNativeRestorationData,
    },
};
use limits::{
    authenticate_host_record_extents, effective_archive_limits, requested_archive_maximum,
};

enum ArchiveSourceStoragePurpose<'a> {
    Live,
    Code {
        factory: &'a super::archive_code::PacketCompleteArchiveCodeFactory,
        graph: &'a Rc<crucible_engine::node_admission::CompleteArchiveCodeGraph>,
    },
}

impl PacketCompleteCaptureFactory {
    pub(super) fn authenticate_original_complete_archive(
        &self,
        scope: CompleteOriginalArchiveValidation<'_>,
    ) -> Result<(), StateError> {
        self.authenticate_original_complete_archive_for_purpose(
            scope,
            ArchiveSourceStoragePurpose::Live,
        )
    }

    pub(super) fn authenticate_original_complete_archive_code(
        &self,
        scope: CompleteOriginalArchiveValidation<'_>,
        factory: &super::archive_code::PacketCompleteArchiveCodeFactory,
        graph: &Rc<crucible_engine::node_admission::CompleteArchiveCodeGraph>,
    ) -> Result<(), StateError> {
        self.current()?;
        if scope.original_write_runtime_data()?.is_some() {
            return Err(refused(
                "archive code observer cannot authenticate a live writer",
            ));
        }
        factory.authenticate_cold_code_graph(self, graph, scope.graph)?;
        self.authenticate_original_complete_archive_for_purpose(
            scope,
            ArchiveSourceStoragePurpose::Code { factory, graph },
        )?;
        self.current()
    }

    fn authenticate_original_complete_archive_for_purpose(
        &self,
        scope: CompleteOriginalArchiveValidation<'_>,
        purpose: ArchiveSourceStoragePurpose<'_>,
    ) -> Result<(), StateError> {
        self.authenticate_storage_origin()?;
        let limits = effective_archive_limits(self.limits, scope.archive_limits_data()?);
        let maximum = requested_archive_maximum(limits)?;
        scope.authenticate_cold_inventory_limits_data(limits)?;
        self.authenticate_archive_graph_data(scope.graph)?;
        self.authenticate_archive_common_data(scope.runtime, scope.scheduling)?;
        let [attempt] = scope.administrative.attempts.as_slice() else {
            // These source banks are genuinely born one-shot. Another Capture
            // needs a new owning class; accepting only its latest row would lose
            // unvalidated earlier native snapshots and settlement journals.
            return Err(refused(
                "complete source supports one original Capture attempt only",
            ));
        };
        if attempt.capture_id != scope.archive.manifest().capture_id
            || attempt.source_activation != scope.runtime.source_activation
            || attempt.cut != scope.runtime.capture_cut
            || attempt.ordinal != scope.runtime.capture_ordinal
            || attempt.owners.len() != 4
            || scope.archive.owners().len() != 4
        {
            return Err(refused("complete archive administrative attempt differs"));
        }
        let host_owner = native_owner(&scope, &self.host.selection().owner.owner.id)?;
        self.authenticate_key(&self.host.selection().descriptor.id, &host_owner.key)?;
        let (host_settled, host_journal) = settled_owner(attempt, host_owner)?;
        authenticate_host_record_extents(
            &scope,
            [&attempt.source_runtime, &host_owner.state, host_journal],
            limits,
        )?;

        let live_runtime = scope.original_write_runtime_data()?;
        let daemon =
            self.actual_archive_daemon_requested_storage(maximum, live_runtime.is_some())?;
        let cache = self.records.try_borrow().map_err(error)?;
        let cache = cache
            .as_ref()
            .map(PacketCompleteCaptureRecords::retained_bytes)
            .transpose()?
            .unwrap_or(0);
        let code = match &purpose {
            ArchiveSourceStoragePurpose::Live => 0,
            ArchiveSourceStoragePurpose::Code { factory, graph } => {
                if live_runtime.is_some() {
                    return Err(refused(
                        "archive code data cannot substitute for live source owners",
                    ));
                }
                factory.authenticate_cold_code_graph(self, graph, scope.graph)?;
                factory.cold_additional_requested_storage_data(graph, maximum)?
            }
        };
        let mut retained = storage_sum([daemon, cache, code], maximum)?;
        if let Some(runtime) = live_runtime {
            // This fixed identity roster coexists with the actual daemon owners
            // throughout the callback. It is known requested scratch, not a
            // bound for erased callback or compiler-generated traversal frames.
            retained = storage_sum(
                [
                    retained,
                    crucible_engine::node_contract::NodeRuntime::original_retained_requested_storage_scratch_bytes(),
                ],
                maximum,
            )?;
            let available = maximum
                .checked_sub(retained)
                .ok_or_else(|| refused("complete runtime observer scratch exhausted"))?;
            let runtime = runtime
                .original_retained_requested_storage_data(available)
                .map_err(error)?;
            retained = storage_sum([retained, runtime], maximum)?;
        }
        for source in &self.authority.roster().sources {
            retained = storage_sum(
                [
                    retained,
                    match &purpose {
                        ArchiveSourceStoragePurpose::Live => source
                            .original_complete_retained_storage_data(maximum)
                            .and_then(|report| report.complete_requested_bytes()),
                        ArchiveSourceStoragePurpose::Code { .. } => {
                            source.original_complete_code_retained_storage_data(maximum)
                        }
                    }
                    .map_err(operation_failure)?,
                ],
                maximum,
            )?;
        }
        // These are actual known local owners, not a compiler-generated stack
        // bound. Every simultaneous protocol result is retained independently.
        retained = storage_sum(
            [
                retained,
                size_of::<[Option<PacketCompleteArchivedOwnerData<'_>>; 3]>(),
                size_of::<[Option<PacketCompleteArchivedSemantics>; 3]>(),
                size_of::<[usize; 3]>(),
                size_of::<[Option<ValidatedCompleteNativeRestorationData<'_>>; 3]>(),
                PacketCompleteSemanticSource::original_archived_restoration_validation_counter_scratch_data()
                    .map_err(operation_failure)?,
                size_of::<super::super::retained::Counter>(),
                // Both live and code-only validation can remeasure originals
                // while these local observers and retained owners coexist.
                PacketFixtureMeasurements::streaming_scratch_bytes(),
                PacketCompleteSemanticSource::original_complete_native_snapshot_schema_counter_scratch_data(),
            ],
            maximum,
        )?;
        let host = scope.decode_original_host_capture_data(
            host_owner,
            attempt,
            host_settled,
            retained,
            maximum,
        )?;
        if host.source != *self.host.selection() {
            return Err(refused(
                "complete archived Host2 selection differs from installed source",
            ));
        }
        retained = storage_sum(
            [
                retained,
                CompleteOriginalArchiveValidation::host_continuation_retained_allocation_bytes(
                    &host,
                )?,
                scope.retained_allocation_bytes_excluding_content()?,
            ],
            maximum,
        )?;

        let mut cold: [Option<PacketCompleteArchivedOwnerData<'_>>; 3] =
            std::array::from_fn(|_| None);
        let mut prepared = retained;
        for (source, slot) in self.authority.roster().sources.iter().zip(&mut cold) {
            let installed = source.installation();
            let owner = native_owner(&scope, &installed.owner.owner.id)?;
            self.authenticate_key(&installed.descriptor.id, &owner.key)?;
            let (_, journal) = settled_owner(attempt, owner)?;
            source
                .prepare_complete_archived_owner_data_into(
                    owner,
                    scope.runtime,
                    &attempt.source_runtime,
                    scope.content,
                    journal,
                    limits,
                    prepared,
                    slot,
                )
                .map_err(operation_failure)?;
            prepared = storage_sum(
                [
                    prepared,
                    slot.as_ref()
                        .ok_or_else(|| refused("complete cold owner slot absent"))?
                        .retained_data_bank_bytes()
                        .map_err(operation_failure)?,
                ],
                maximum,
            )?;
        }
        PacketCompleteArchivedOwnerData::reconstruct_group(&mut cold, retained)
            .map_err(operation_failure)?;
        let mut protocol_retained = storage_sum(
            [
                retained,
                scope.retained_verified_content_allocation_bytes()?,
            ],
            maximum,
        )?;
        for slot in &cold {
            protocol_retained = storage_sum(
                [
                    protocol_retained,
                    slot.as_ref()
                        .ok_or_else(|| refused("complete cold result absent"))?
                        .known_requested_bytes()
                        .map_err(operation_failure)?,
                ],
                maximum,
            )?;
        }
        let mut demands = [0usize; 3];
        for (slot, demand) in cold.iter().zip(&mut demands) {
            let journal = slot
                .as_ref()
                .ok_or_else(|| refused("complete cold journal absent"))?
                .journal()
                .map_err(operation_failure)?;
            *demand = PacketCompleteArchivedSemantics::decode_demand_data(
                body(&scope, &journal.semantic)?,
                body(&scope, &journal.ancestry)?,
                limits.state.maximum_record_bytes,
                maximum,
            )
            .map_err(operation_failure)?;
        }
        let complete = storage_sum([protocol_retained, storage_sum(demands, maximum)?], maximum)?;
        let mut semantics: [Option<PacketCompleteArchivedSemantics>; 3] =
            std::array::from_fn(|_| None);
        for ((slot, result), demand) in cold.iter().zip(&mut semantics).zip(demands) {
            let journal = slot
                .as_ref()
                .ok_or_else(|| refused("complete cold journal absent"))?
                .journal()
                .map_err(operation_failure)?;
            let other = complete
                .checked_sub(demand)
                .ok_or_else(|| refused("complete semantic demand accounting differs"))?;
            *result = Some(
                PacketCompleteArchivedSemantics::decode_data(
                    body(&scope, &journal.semantic)?,
                    body(&scope, &journal.ancestry)?,
                    limits.state.maximum_record_bytes,
                    other,
                    maximum,
                )
                .map_err(operation_failure)?,
            );
        }
        let mut restoration_data: [Option<ValidatedCompleteNativeRestorationData<'_>>; 3] =
            std::array::from_fn(|_| None);
        for (index, source) in self.authority.roster().sources.iter().enumerate() {
            let owner = cold[index]
                .as_ref()
                .ok_or_else(|| refused("complete cold owner absent"))?;
            let common = semantics[index]
                .as_ref()
                .ok_or_else(|| refused("complete cold semantics absent"))?;
            let other = complete
                .checked_sub(demands[index])
                .ok_or_else(|| refused("complete common demand accounting differs"))?;
            let native_other = complete
                .checked_sub(owner.known_requested_bytes().map_err(operation_failure)?)
                .ok_or_else(|| refused("complete native demand accounting differs"))?;
            restoration_data[index] = Some(
                source
                    .authenticate_archived_restoration_validation_data(
                        owner,
                        common,
                        scope.runtime,
                        limits.state.maximum_record_bytes,
                        other,
                        native_other,
                        maximum,
                    )
                    .map_err(operation_failure)?,
            );
            let installed = source.installation();
            let native = native_owner(&scope, &installed.owner.owner.id)?;
            let (settled, _) = settled_owner(attempt, native)?;
            let journal = owner.journal().map_err(operation_failure)?;
            let host = owner.host().map_err(operation_failure)?;
            let capture = host
                .custody
                .controller
                .get(&journal.confirmation.capture.capture_request_id)
                .ok_or_else(|| refused("complete native Capture original absent"))?;
            if capture.request.operation_id.0.as_ref() != Some(&settled.operation) {
                return Err(refused(
                    "complete native Capture crossed its reserved operation",
                ));
            }
        }
        // Purpose/currentness is not inferred from decoded graphs or a byte sum.
        // Reauthenticate the same actual writer/load origin after every parser.
        scope.original_write_runtime_data()?;
        if let ArchiveSourceStoragePurpose::Code { factory, graph } = purpose {
            factory.authenticate_cold_code_graph(self, graph, scope.graph)?;
            for source in &self.authority.roster().sources {
                source
                    .original_complete_code_retained_storage_data(maximum)
                    .map_err(operation_failure)?;
            }
        }
        self.authenticate_archive_graph_data(scope.graph)?;
        // Preserve the actual detailed native-after DATA before the temporary
        // cold owners disappear. Equal labels cannot choose another owner slot.
        for (source, data) in self
            .authority
            .roster()
            .sources
            .iter()
            .zip(&mut restoration_data)
        {
            let owner = native_owner(&scope, &source.installation().owner.owner.id)?;
            scope
                .retain_original_native_restoration_data(
                    owner,
                    data.take()
                        .ok_or_else(|| refused("complete validated restoration DATA absent"))?,
                )
                .map_err(error)?;
        }
        Ok(())
    }
}

fn storage_sum<const N: usize>(terms: [usize; N], maximum: usize) -> Result<usize, StateError> {
    terms.into_iter().try_fold(0usize, |total, next| {
        total
            .checked_add(next)
            .filter(|total| *total <= maximum)
            .ok_or_else(|| refused("complete archive coexisting requested storage exhausted"))
    })
}

fn native_owner<'a>(
    scope: &CompleteOriginalArchiveValidation<'a>,
    identity: &Id,
) -> Result<&'a NativeOwnerState, StateError> {
    let mut owners = scope
        .archive
        .owners()
        .iter()
        .filter(|owner| &owner.owner == identity);
    let owner = owners
        .next()
        .ok_or_else(|| refused("complete archive original owner absent"))?;
    if owners.next().is_some() {
        return Err(refused("complete archive original owner repeated"));
    }
    Ok(owner)
}

fn settled_owner<'a>(
    attempt: &'a OriginalCaptureAttemptRecord,
    owner: &NativeOwnerState,
) -> Result<(&'a OriginalCaptureOwnerRecord, &'a ContentRef), StateError> {
    let mut records = attempt
        .owners
        .iter()
        .filter(|record| record.owner.owner == owner.owner);
    let record = records
        .next()
        .ok_or_else(|| refused("complete administrative owner absent"))?;
    let OriginalCaptureOwnerState::Settled { snapshot, journal } = &record.state else {
        return Err(refused("complete administrative owner is unsettled"));
    };
    if records.next().is_some()
        || snapshot != &owner.state
        || record.participants != owner.participants
    {
        return Err(refused("complete administrative/native owner differs"));
    }
    Ok((record, journal))
}

fn body<'a>(
    scope: &CompleteOriginalArchiveValidation<'a>,
    reference: &ContentRef,
) -> Result<&'a [u8], StateError> {
    let bytes = scope
        .content
        .get(reference)
        .ok_or_else(|| refused("complete historical body absent"))?;
    // The private verified closure authenticates the complete reference before
    // exposing immutable bytes; hashing again would allocate temporary strings.
    Ok(bytes)
}
