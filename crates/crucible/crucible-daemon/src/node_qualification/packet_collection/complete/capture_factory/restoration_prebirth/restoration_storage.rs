//! Observes the actual source-bound inactive capsule after graph construction.
//!
//! This path is distinct from the prebirth-only observer. The installed action
//! separately walks the same archive, Source3 and actual runtime; this callback
//! counts all remaining capsule/factory/graph/Host owning edges without replacing
//! a live owner with a constructor quote or an absent initial-phase bank.

use super::*;
use crate::node_qualification::QualificationError;
use crucible_engine::node_contract::{ActivationRecord, RuntimeError};
use std::mem::{size_of, size_of_val};

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn retained_restoration_holder_storage_data(
        &self,
        original: &Rc<RefCell<Self>>,
        archive: &crucible_engine::node_state::CompleteOriginalRestorationSource,
        runtime: &ConformanceRuntime,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.retained_restoration_holder_storage_for_scope_data(
            original, archive, runtime, plan, activation, maximum, None,
        )
    }

    pub(in crate::node_qualification::packet_collection::complete) fn retained_restoration_holder_storage_for_scope_data<
        'a,
    >(
        &self,
        original: &Rc<RefCell<Self>>,
        archive: &crucible_engine::node_state::CompleteOriginalRestorationSource,
        runtime: impl Into<crucible_engine::node_contract::ConformanceRuntimeObservation<'a>>,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
        maximum: usize,
        scope: Option<&crucible_engine::node_admission::OriginalRestorationConstructionScope<'_>>,
    ) -> Result<usize, RuntimeError> {
        let runtime = runtime.into();
        self.authenticate_restoration_storage_scope_data(
            archive, runtime, plan, activation, scope,
        )?;
        let Self {
            factory,
            code_graph,
            source,
            native,
            initial15_control: _,
            initial15_control_started: _,
            initial15_control_failed: _,
            host_ticket,
            host,
            host_attempted: _,
            source17_ticket_completion: _,
            host_source17_admission: _,
            fresh_graph,
            fresh_factory,
            binding_attempted: _,
            runtime_attempted: _,
            report_startup_holder,
            runtime: _,
            failed_runtime,
            publication,
            restored_results,
            restored_actions,
            process: _,
            thread: _,
        } = self;
        if failed_runtime.is_some() || host_ticket.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        // Occupied tickets retain the very archive counted independently by
        // Core. A moved slot is empty only after its genuine fixed-group move;
        // that group's actual root and IDs must be walked by the same holder.
        for ticket in native.iter().flatten() {
            ticket.authenticate_source(archive)?;
        }
        let mut counter = super::super::super::retained::Counter::new(maximum);
        if let Some(publication) = publication {
            counter
                .add(publication.retained_storage_data(counter.remaining())?)
                .map_err(storage_error)?;
        }
        if let Some(results) = restored_results {
            results
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .charge_retained_storage_data(&mut counter)?;
        }
        if restored_results.is_some() {
            Self::charge_restored_actions_data(restored_actions, &mut counter)?;
        }
        counter
            .add(
                self.initial15_control
                    .try_borrow()
                    .map_err(|_| RuntimeError::OwnerBusy)?
                    .retained_requested_storage_data(counter.remaining())?,
            )
            .map_err(storage_error)?;
        counter.rc(original).map_err(storage_error)?;
        if let Some(holder) = report_startup_holder {
            counter.weak(holder).map_err(storage_error)?;
        }
        counter
            .add(factory.retained_host_precredit_data(counter.remaining())?)
            .map_err(storage_error)?;
        counter.rc(code_graph).map_err(storage_error)?;
        let code_bytes = code_graph.original_retained_requested_storage_data(
            counter
                .remaining()
                .checked_add(size_of_val(code_graph.as_ref()))
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        counter
            .add(
                code_bytes
                    .checked_sub(size_of_val(code_graph.as_ref()))
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(storage_error)?;
        let host = host
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .source();
        if counter.rc(&host).map_err(storage_error)? {
            counter
                .add(
                    host.retained_restoration_metadata_bytes_excluding_runtime_precredit_data(
                        archive,
                        counter.remaining(),
                    )?,
                )
                .map_err(storage_error)?;
        }
        let graph = fresh_graph.as_ref().ok_or(RuntimeError::OwnerUnavailable)?;
        counter.rc(graph).map_err(storage_error)?;
        counter
            .add(graph.original_retained_storage_precredit_data(counter.remaining())?)
            .map_err(storage_error)?;
        let fresh = fresh_factory
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        counter
            .add(fresh.original_ticketed_unobserved_restoration_storage_data(
                archive,
                counter.remaining(),
            )?)
            .map_err(storage_error)?;
        source.authenticate_same_original_source_data(archive)?;
        self.authenticate_restoration_storage_scope_data(
            archive, runtime, plan, activation, scope,
        )?;
        Ok(counter.bytes())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_restoration_target_storage_data(
        &self,
        archive: &crucible_engine::node_state::CompleteOriginalRestorationSource,
        runtime: &ConformanceRuntime,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<(), RuntimeError> {
        if self.process != std::process::id() || self.thread != std::thread::current().id() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if !self.binding_attempted
            || !self.runtime_attempted
            || self.failed_runtime.is_some()
            || !self
                .runtime
                .as_ref()
                .is_some_and(|actual| std::ptr::eq(actual.as_ptr().cast_const(), runtime))
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let graph = self
            .fresh_graph
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !graph.plan().is_original_plan_data(plan) {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.factory
            .inner
            .authority
            .capture_graph_policy()
            .authenticate_retained_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.source
            .authenticate_same_original_source_data(archive)?;
        self.source
            .original_restoration_source_data(runtime, plan, activation)?;
        Ok(())
    }

    pub(in crate::node_qualification::packet_collection::complete) fn retained_restoration_holder_descriptor_data(
        &self,
        archive: &crucible_engine::node_state::CompleteOriginalRestorationSource,
        runtime: &ConformanceRuntime,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
    ) -> Result<usize, RuntimeError> {
        self.retained_restoration_holder_descriptor_for_scope_data(
            archive, runtime, plan, activation, None,
        )
    }

    pub(in crate::node_qualification::packet_collection::complete) fn retained_restoration_holder_descriptor_for_scope_data<
        'a,
    >(
        &self,
        archive: &crucible_engine::node_state::CompleteOriginalRestorationSource,
        runtime: impl Into<crucible_engine::node_contract::ConformanceRuntimeObservation<'a>>,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
        scope: Option<&crucible_engine::node_admission::OriginalRestorationConstructionScope<'_>>,
    ) -> Result<usize, RuntimeError> {
        let runtime = runtime.into();
        self.authenticate_restoration_storage_scope_data(
            archive, runtime, plan, activation, scope,
        )?;
        let Self {
            factory,
            code_graph: _,
            source: _,
            native,
            initial15_control: _,
            initial15_control_started: _,
            initial15_control_failed: _,
            host_ticket,
            host: _,
            host_attempted: _,
            source17_ticket_completion: _,
            host_source17_admission: _,
            fresh_graph: _,
            fresh_factory,
            binding_attempted: _,
            runtime_attempted: _,
            report_startup_holder: _,
            runtime: _,
            failed_runtime,
            publication,
            restored_results,
            restored_actions,
            process: _,
            thread: _,
        } = self;
        if failed_runtime.is_some() || host_ticket.is_some() {
            return Err(RuntimeError::UnsupportedFacet);
        }
        for ticket in native.iter().flatten() {
            ticket.authenticate_source(archive)?;
        }
        let code = factory
            .inner
            .authority
            .capture_graph_policy()
            .original_initial_retained_descriptors_data()?;
        let fresh = fresh_factory
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .original_unobserved_restoration_descriptor_data()?;
        // Core independently walks the actual runtime and Sources. The two
        // concrete factory policy views can conservatively repeat the same FD;
        // equal paths/hashes never justify a discount between actual owners.
        if let Some(publication) = publication {
            publication.authenticate_retained_directory_views_data()?;
        }
        if let Some(results) = restored_results {
            // Idle Directory configurations own no open descriptors. Refuse a
            // busy partial owner rather than omit its independently quoted work.
            let _results = results.try_borrow().map_err(|_| RuntimeError::OwnerBusy)?;
        }
        if restored_results.is_some() {
            let _actions = restored_actions
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?;
        }
        let descriptors = code.checked_add(fresh).ok_or(RuntimeError::ResourceLimit)?;
        self.authenticate_restoration_storage_scope_data(
            archive, runtime, plan, activation, scope,
        )?;
        Ok(descriptors)
    }

    pub(in crate::node_qualification::packet_collection::complete) fn restoration_holder_counter_scratch_data()
    -> usize {
        Self::initial15_control_counter_scratch_data()
            + HostSchedulingSource::retained_restoration_metadata_counter_scratch_data()
            + PacketCompleteCaptureFactory::original_ticketed_unobserved_counter_scratch_data()
            + size_of::<super::super::super::retained::Counter>()
            + size_of::<std::slice::Iter<'static, Option<CompleteOriginalNativeTicket>>>()
            + size_of::<
                std::iter::Flatten<std::slice::Iter<'static, Option<CompleteOriginalNativeTicket>>>,
            >()
            + size_of::<Rc<HostSchedulingSource>>()
            + size_of::<[usize; 4]>()
            + size_of::<Result<usize, RuntimeError>>()
    }
}

fn storage_error(_: QualificationError) -> RuntimeError {
    RuntimeError::ResourceLimit
}

impl PacketCompleteRestorationPrebirth {
    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_restoration_storage_scope_data<
        'a,
    >(
        &self,
        archive: &crucible_engine::node_state::CompleteOriginalRestorationSource,
        runtime: impl Into<crucible_engine::node_contract::ConformanceRuntimeObservation<'a>>,
        plan: &InstalledConformancePlan,
        activation: &ActivationRecord,
        scope: Option<&crucible_engine::node_admission::OriginalRestorationConstructionScope<'_>>,
    ) -> Result<(), RuntimeError> {
        let runtime = runtime.into();
        if let Some(scope) = scope
            && scope.phase()
                == crucible_engine::node_admission::OriginalRestorationConstructionPhase::Installed
        {
            if self.process != std::process::id()
                || self.thread != std::thread::current().id()
                || !self.binding_attempted
                || !self.runtime_attempted
                || self.failed_runtime.is_some()
                || !self.runtime.as_ref().is_some_and(|actual| {
                    runtime.is_original_runtime_data(actual.as_ptr().cast_const())
                })
                || !std::ptr::eq(scope.inputs().archive, archive)
                || !std::ptr::eq(scope.inputs().activation, activation)
                || !scope.plan().is_original_plan_data(plan)
            {
                return Err(RuntimeError::ForeignAuthority);
            }
            self.source
                .authenticate_same_original_source_data(archive)?;
            self.factory
                .inner
                .authority
                .capture_graph_policy()
                .authenticate_retained_origin_data()
                .map_err(|_| RuntimeError::ForeignAuthority)?;
            return scope.authenticate_original_runtime_data();
        }
        self.authenticate_restoration_target_storage_data(
            archive,
            runtime.original_whole_owner_data()?,
            plan,
            activation,
        )
    }
}
