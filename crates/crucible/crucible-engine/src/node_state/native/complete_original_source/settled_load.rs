//! Retains the actual signed archive and every current17 load partial before work.
//!
//! A completed strict archive validation moves once into a fresh Source owner.
//! Neither this attempt nor decoded facts create native registration, tickets,
//! a target Window, old Hold or resumed operation authority.

use super::*;
use crate::node_state::{
    CompleteRestoredSettledArchiveValidationAttempt, CompleteRestoredSettledValidatedArchiveData,
};

/// Keeps one actual current17 source-load attempt, including original failure.
#[must_use = "retain the signed archive and all failed load partials"]
pub struct CompleteRestoredSettledSourceLoadAttempt {
    archive: Option<NativeArchiveRecord>,
    validation: Option<CompleteRestoredSettledArchiveValidationAttempt>,
    validated: Option<CompleteRestoredSettledValidatedArchiveData>,
    failure: Option<StateError>,
    historical: Option<crate::node_state::CollectingCompleteCaptureProvenance>,
    process: u32,
    thread: ThreadId,
    completed: bool,
}

impl CompleteRestoredSettledSourceLoadAttempt {
    /// Borrows the full original refusal without cloning its retained strings.
    pub fn failure_data(&self) -> Option<&StateError> {
        self.failure.as_ref()
    }

    /// Counts actual failed/current load backing without parsing or callbacks.
    ///
    /// Repeated shared owners are conservative; no equal-data discount is taken.
    ///
    /// # Errors
    /// Refuses foreign origin, unresolved actual backing or checked overflow.
    pub fn retained_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        self.origin()?;
        let mut bytes = self.nonvalidation_requested_storage_data()?;
        let mut add = |next: usize| -> Result<(), RuntimeError> {
            bytes = bytes.checked_add(next).ok_or(RuntimeError::ResourceLimit)?;
            Ok(())
        };
        if let Some(archive) = &self.archive {
            add(archive.capture_owned_storage()?)?;
        }
        if let Some(validation) = &self.validation {
            add(validation.retained_requested_storage_data()?)?;
        }
        if let Some(data) = &self.validated {
            add(data.content.capture_owned_storage()?)?;
            add(data
                .collection
                .retained_requested_storage_data(usize::MAX)?)?;
            add(data.host.retained_requested_storage_data()?)?;
            add(crate::node_contract::NodeRuntime::capture_admin_storage(
                &data.administrative,
            )?)?;
            add(
                crate::node_contract::NodeRuntime::capture_reference_storage(
                    &data.runtime_reference,
                )?,
            )?;
            add(
                crate::node_contract::NodeRuntime::capture_reference_storage(
                    &data.checkpoint_reference,
                )?,
            )?;
            add(data
                .checkpoint
                .retained_backing_requested_bytes_data()
                .map_err(|_| RuntimeError::ResourceLimit)?)?;
            for row in data.restoration_data.iter().flatten() {
                add(row
                    .native_import_geometry_data()
                    .retained_requested_storage_data()
                    .map_err(|_| RuntimeError::ResourceLimit)?)?;
            }
        }

        Ok(bytes)
    }

    fn nonvalidation_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        let mut bytes = std::mem::size_of::<Self>();
        let mut add = |next: usize| -> Result<(), RuntimeError> {
            bytes = bytes.checked_add(next).ok_or(RuntimeError::ResourceLimit)?;
            Ok(())
        };
        if let Some(scope) = &self.historical {
            let crate::node_state::CollectingCompleteCaptureProvenance {
                schema,
                plan,
                refused,
                sources,
                world,
                ordinary_acceptance: _,
            } = scope;
            add(schema.capacity())?;
            add(crate::node_contract::NodeRuntime::capture_reference_storage(plan)?)?;
            add(crate::node_contract::NodeRuntime::capture_reference_storage(refused)?)?;
            add(sources
                .capacity()
                .checked_mul(std::mem::size_of::<ContentRef>())
                .ok_or(RuntimeError::ResourceLimit)?)?;
            for reference in sources {
                add(crate::node_contract::NodeRuntime::capture_reference_storage(reference)?)?;
            }
            add(crate::node_contract::NodeRuntime::capture_hash_storage(
                world,
            )?)?;
        }
        if let Some(error) = &self.failure {
            add(error.component.capacity())?;
            add(error.reason.capacity())?;
        }
        Ok(bytes)
    }

    fn origin(&self) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

impl CompleteOriginalRestorationSource {
    /// Retains a complete17 signed load before any validation or typed allocation.
    ///
    /// This crate-private boundary is called only after the actual archive-code
    /// graph/factory/plan association. Its own strict callback and selected-load
    /// checks remain mandatory. Output becomes Some before the final caller's
    /// fallible reauthentication; no failure can silently drop a completed Source.
    pub(crate) fn prepare_restored_settled_source_into(
        incoming: &mut Option<NativeArchiveRecord>,
        graph: &crate::node_admission::CompleteArchiveCodeGraph,
        factory: &dyn NativeWorldFactory,
        limits: HostSchedulingContinuationLimits,
        additional_retained_bytes: usize,
        pending: &mut Option<CompleteRestoredSettledSourceLoadAttempt>,
        output: &mut Option<Self>,
    ) -> Result<(), StateError> {
        if pending.is_some() || output.is_some() || incoming.is_none() {
            return Err(refused(
                "settled17 source load is occupied or already attempted",
            ));
        }
        *pending = Some(CompleteRestoredSettledSourceLoadAttempt {
            archive: incoming.take(),
            validation: None,
            validated: None,
            failure: None,
            historical: None,
            process: std::process::id(),
            thread: thread::current().id(),
            completed: false,
        });
        let owner = pending
            .as_mut()
            .ok_or_else(|| refused("settled17 load attempt absent"))?;
        let result = owner.prepare(graph, factory, limits, additional_retained_bytes, output);
        if let Err(error) = result {
            owner.failure = Some(error);
            return Err(refused(
                "settled17 source load failed; original error retained",
            ));
        }
        Ok(())
    }
}

impl CompleteRestoredSettledSourceLoadAttempt {
    fn prepare(
        &mut self,
        graph: &crate::node_admission::CompleteArchiveCodeGraph,
        factory: &dyn NativeWorldFactory,
        limits: HostSchedulingContinuationLimits,
        additional_retained_bytes: usize,
        output: &mut Option<CompleteOriginalRestorationSource>,
    ) -> Result<(), StateError> {
        self.origin().map_err(super::super::super::schema)?;
        if self.completed || self.failure.is_some() || self.validation.is_some() {
            return Err(refused("settled17 source load cannot be renewed"));
        }
        let archive = self
            .archive
            .as_ref()
            .ok_or_else(|| refused("settled17 signed load absent"))?;
        archive
            .authenticate_complete_load_admission()
            .map_err(super::super::super::schema)?;
        graph
            .plan()
            .reauthenticate()
            .map_err(super::super::super::schema)?;
        let local = self
            .nonvalidation_requested_storage_data()
            .map_err(super::super::super::schema)?;
        let before_provenance = additional_retained_bytes
            .checked_add(local)
            .ok_or_else(|| refused("settled17 caller storage overflow"))?;
        self.historical = Some(
            archive
                .complete_collecting_provenance_with_retained_data(before_provenance)?
                .ok_or_else(|| refused("settled17 collecting provenance absent"))?,
        );
        let historical = self
            .historical
            .as_ref()
            .ok_or_else(|| refused("settled17 collecting provenance absent"))?;
        let plan = graph.plan().evidence();
        if historical.plan != *plan.plan_ref
            || historical.refused != *plan.refused_ref
            || historical.sources != plan.sources
            || historical.world != *plan.world
        {
            return Err(refused("settled17 collecting plan differs"));
        }
        graph.authenticate_archive_source(factory, archive, historical)?;
        let source_roots = crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
            CompleteOriginalSource,
        >()
        .checked_add(
            crate::node_contract::NodeRuntime::capture_shared_allocation_storage::<
                crate::node_contract::HostSchedulingRestoredContinuationRecord17,
            >(),
        )
        .ok_or_else(|| refused("settled17 source root storage overflow"))?;
        let additional = additional_retained_bytes
            .checked_add(
                self.nonvalidation_requested_storage_data()
                    .map_err(super::super::super::schema)?,
            )
            .and_then(|bytes| bytes.checked_add(source_roots))
            .ok_or_else(|| refused("settled17 source construction storage overflow"))?;
        let mut host_rows = archive.owners().iter().filter(|owner| {
            owner.key.implementation.as_str() == "source-owned.host-scheduling-owner/2"
        });
        let host_row = host_rows
            .next()
            .ok_or_else(|| refused("settled17 Host role absent"))?;
        if host_rows.next().is_some()
            || limits.maximum_record_bytes == 0
            || usize::try_from(host_row.state.length.get()).map_err(super::super::super::schema)?
                > limits.maximum_record_bytes
        {
            return Err(refused(
                "settled17 Host exceeds the caller's independent record bound",
            ));
        }
        // The strict verified closure checks this exact fullref/body pair before
        // the Host decoder. A smaller caller record bound is never widened to
        // the archive-wide maximum used by the generic current17 scope.
        archive.complete_restored_settled_content_with_restoration_data_into(
            &graph.graph,
            factory,
            limits.lineage,
            additional,
            &mut self.validation,
        )?;
        let validation = self
            .validation
            .as_mut()
            .ok_or_else(|| refused("settled17 validation attempt absent"))?;
        self.validated = Some(validation.take_validated_data(archive)?);
        let data = self
            .validated
            .as_ref()
            .ok_or_else(|| refused("settled17 validated owners absent"))?;
        data.collection
            .authenticate_completed_data(archive)
            .map_err(super::super::super::schema)?;
        let maximum = archive
            .limits
            .state
            .maximum_total_content_bytes
            .min(archive.limits.native.maximum_total_record_bytes)
            .min(
                usize::try_from(archive.limits.state.maximum_native_memory_bytes)
                    .map_err(super::super::super::schema)?,
            );
        let requested = self.retained_requested_storage_data()
            .map_err(super::super::super::schema)?
            .checked_add(additional_retained_bytes)
            .and_then(|n| n.checked_add(source_roots))
            .and_then(|n| n.checked_add(
                crate::node_state::complete_restored_settled_archive_validation_counter_scratch_data()))
            .filter(|n| *n <= maximum)
            .ok_or_else(|| refused("settled17 Source publication exceeds independent storage row"))?;
        let _ = requested;
        // All validation/callbacks precede the final field moves. The destination
        // already exists and no fallible parser, hash, callback or I/O follows.
        let data = self
            .validated
            .take()
            .ok_or_else(|| refused("settled17 validated owners absent"))?;
        let archive = self
            .archive
            .take()
            .ok_or_else(|| refused("settled17 archive owner absent"))?;
        let CompleteRestoredSettledValidatedArchiveData {
            content,
            host,
            administrative,
            runtime_reference,
            checkpoint_reference,
            checkpoint,
            restoration_data,
            collection,
            lineage_limits,
        } = data;
        *output = Some(CompleteOriginalRestorationSource {
            inner: Rc::new(CompleteOriginalSource {
                archive,
                content,
                administrative,
                host: CompleteHostArchiveRecord::Settled17(Rc::new(host)),
                runtime: runtime_reference,
                coordinator_checkpoint: Some(CompleteCoordinatorArchiveRecord::Settled17 {
                    reference: checkpoint_reference,
                    checkpoint,
                }),
                purpose: CompleteOriginalSourcePurpose::new(Some(graph.plan().retained())),
                native_restoration_data: std::array::from_fn(|_| None),
                settled_restoration_data: restoration_data,
                restored_collection: RefCell::new(Some(collection)),
                validation_limits: HostSchedulingContinuationLimits {
                    maximum_record_bytes: limits.maximum_record_bytes,
                    lineage: lineage_limits,
                },
                process: std::process::id(),
                thread: thread::current().id(),
                host_issued: Cell::new(false),
                native_issued: Cell::new([false; 4]),
                target_started: Cell::new(false),
                target: RefCell::new(None),
                restoration_transactions: Cell::new(None),
            }),
        });
        self.completed = true;
        Ok(())
    }
}
