//! Admits actual Host17 source copies before the later startup holder exists.
//!
//! The original code factory and prebirth capsule supply the actual existing
//! owners. This memory-only action opens no file, creates no process and grants
//! no native permission. The selected finite policy is retained before copying
//! and must match the later installed target holder without renewal.

use super::*;
use crate::node_qualification::packet_collection::complete::installed::HostSource17SetupBorrow;
use crucible::node_adapters::cnp::PacketCompleteSemanticSource;
use crucible::node_contract::{HostRestoredSource17ConstructionData, RuntimeError};
use crucible_node_contract::ResourceLimits;
use std::mem::{size_of, size_of_val};

type Counter = super::super::super::retained::Counter;

#[derive(Clone, Copy)]
struct Policy([U64; 8]);

impl Policy {
    fn read(resources: &ResourceLimits) -> Result<Self, RuntimeError> {
        let fields = [
            resources.cpu_budget_ns,
            resources.memory_bytes,
            resources.writable_bytes,
            resources.processes,
            resources.descriptors,
            resources.pending_events,
            resources.content_bytes,
            resources.maximum_operations,
        ];
        if !resources.extensions.is_empty()
            || resources.processes.get() < 3
            || fields.iter().any(|value| value.get() == 0)
            || usize::try_from(resources.memory_bytes.get()).is_err()
        {
            return Err(RuntimeError::ResourceLimit);
        }
        Ok(Self(fields))
    }

    fn maximum(self) -> Result<usize, RuntimeError> {
        usize::try_from(self.0[1].get()).map_err(|_| RuntimeError::ResourceLimit)
    }

    fn authenticate(self, resources: &ResourceLimits) -> Result<(), RuntimeError> {
        if self.0 != Self::read(resources)?.0 {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}

/// Retains the actual selected policy and every initialized construction stage.
///
/// Its fields are fixed DATA inside the real capsule. The containing Rc census
/// counts them whether the attempt succeeds or fails. The row never stands in
/// for a native mapping, active source registration or World publication.
pub(super) struct HostSource17Admission {
    policy: Policy,
    row: Option<HostRestoredSource17ConstructionData>,
    complete: bool,
}

impl PacketCompleteRestorationPrebirth {
    /// Identifies the actual once-issued Host ticket's historical family.
    ///
    /// # Errors
    /// Refuses foreign creation/code custody, incomplete current17 transfer or
    /// an absent original ticket.
    pub(in crate::node_qualification::packet_collection::complete) fn host_requires_restored_settled_construction_data(
        &self,
    ) -> Result<bool, RuntimeError> {
        self.construction_origin_data()?;
        if self.source17_ticket_completion == Some(false) {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.host_ticket
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .is_restored_settled_data()
    }

    /// Constructs the actual ticketed Host using its genuine historical family.
    ///
    /// Initial-family construction retains its existing API and checks. Current17
    /// construction stores the selected finite policy before its own quote and
    /// whole-owner admission, then copies private immutable code-source metadata
    /// into a distinct source. The ticket and output remain in this same capsule.
    /// A failed attempt stays spent and cannot replace its policy or source.
    ///
    /// # Errors
    /// Refuses foreign or busy custody, missing/reused tickets, incompatible
    /// actual template selection, changed policy, or insufficient admitted memory.
    pub(in crate::node_qualification::packet_collection::complete) fn prepare_original_host_for_target(
        original: &Rc<RefCell<Self>>,
        selection: &HostSchedulingSelection,
        resources: &ResourceLimits,
        setup: &HostSource17SetupBorrow<'_>,
    ) -> Result<(), StateError> {
        let mut held = original.try_borrow_mut().map_err(error)?;
        let restored = held
            .host_requires_restored_settled_construction_data()
            .map_err(error)?;
        if !restored {
            return held.prepare_original_host(selection.clone());
        }
        held.prepare_host_source17_data(original, selection, resources, setup)
            .map_err(error)
    }

    fn prepare_host_source17_data(
        &mut self,
        original: &Rc<RefCell<Self>>,
        selection: &HostSchedulingSelection,
        resources: &ResourceLimits,
        setup: &HostSource17SetupBorrow<'_>,
    ) -> Result<(), RuntimeError> {
        self.construction_origin_data()?;
        if self.host_attempted || self.binding_attempted {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.host_attempted = true;
        setup.authenticate_target_data(selection, resources)?;
        self.host_source17_admission = Some(HostSource17Admission {
            policy: Policy::read(resources)?,
            row: None,
            complete: false,
        });
        let policy = self
            .host_source17_admission
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .policy;
        let maximum = policy.maximum()?;
        let scratch = Self::host_source17_counter_scratch_data()?;
        if scratch > maximum {
            return Err(RuntimeError::ResourceLimit);
        }
        self.authenticate_host_source17_phase_data(selection)?;
        let template = Rc::clone(&self.factory.inner.host);
        let row = template.restored_source17_construction_data(
            self.host_ticket
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            maximum
                .checked_sub(scratch)
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        self.host_source17_admission
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .row = Some(row);

        // This is the real code-factory/capsule admission, not a successful
        // erased callback or a row used as an allocation permission by itself.
        self.factory.admit_host_source17_prebirth_data(
            original, self, selection, setup, &row, scratch, maximum,
        )?;
        HostSchedulingOwner::restore_complete_restored_settled_from_template_into(
            &template,
            &mut self.host_ticket,
            &row,
            &mut self.host,
        )?;
        self.host_source17_admission
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .complete = true;
        Ok(())
    }

    fn authenticate_host_source17_phase_data(
        &self,
        selection: &HostSchedulingSelection,
    ) -> Result<(), RuntimeError> {
        self.construction_origin_data()?;
        if self.source17_ticket_completion != Some(true)
            || !self.host_attempted
            || self.binding_attempted
            || self.runtime_attempted
            || self.host.is_some()
            || self.native.iter().any(Option::is_none)
            || self.host_ticket.is_none()
            || self.fresh_graph.is_some()
            || self.fresh_factory.is_some()
            || self.report_startup_holder.is_some()
            || self.runtime.is_some()
            || self.failed_runtime.is_some()
            || self.publication.is_some()
            || self.restored_results.is_some()
            || !self
                .restored_actions
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerBusy)?
                .is_empty()
            || selection != self.factory.inner.host.selection()
            || !self
                .code_graph
                .plan()
                .is_original_plan_data(&self.factory.inner.plan)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    /// Checks the same retained prebirth policy before target holder installation.
    ///
    /// Initial-family construction retains its existing resource checks. A
    /// completed Host17 source cannot silently acquire a different target policy.
    ///
    /// # Errors
    /// Refuses foreign origin, an incomplete retained Host17 construction, or
    /// target limits differing from the same original prebirth declaration.
    pub(in crate::node_qualification::packet_collection::complete) fn authenticate_host_source17_resources_data(
        &self,
        resources: &ResourceLimits,
    ) -> Result<(), RuntimeError> {
        self.construction_origin_data()?;
        if let Some(admission) = &self.host_source17_admission {
            if !admission.complete
                || admission.row.is_none()
                || self.host.is_none()
                || self.host_ticket.is_some()
            {
                return Err(RuntimeError::OutstandingObligations);
            }
            admission.policy.authenticate(resources)?;
        }
        Ok(())
    }

    fn host_source17_counter_scratch_data() -> Result<usize, RuntimeError> {
        let terms = [
            HostSchedulingSource::restored_source17_construction_counter_scratch_data(),
            CollectingCompleteRestorationSource::original_host17_preconstruction_counter_scratch_data(),
            CompleteArchiveCodeGraph::retained_requested_storage_scratch_bytes(),
            HostSource17SetupBorrow::counter_scratch_data()?,
            PacketCompleteSemanticSource::retained_requested_storage_precredit_scratch_data(),
            size_of::<Counter>(),
            size_of::<Counter>(),
            size_of::<HostSource17Admission>(),
            size_of::<HostRestoredSource17ConstructionData>(),
            size_of::<Policy>(),
            size_of::<[U64; 8]>(),
            size_of::<&ResourceLimits>(),
            size_of::<&HostSchedulingSelection>(),
            size_of::<&Self>(),
            size_of::<&Rc<RefCell<Self>>>(),
            size_of::<Rc<HostSchedulingSource>>(),
            size_of::<std::cell::RefMut<'static, Self>>(),
            size_of::<Result<std::cell::RefMut<'static, Self>, std::cell::BorrowMutError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<[usize; 4]>(),
        ];
        terms.iter().try_fold(size_of_val(&terms), |total, bytes| {
            total.checked_add(*bytes).ok_or(RuntimeError::ResourceLimit)
        })
    }
}

impl PacketCompleteArchiveCodeFactory {
    fn admit_host_source17_prebirth_data(
        self: &Rc<Self>,
        original: &Rc<RefCell<PacketCompleteRestorationPrebirth>>,
        held: &PacketCompleteRestorationPrebirth,
        selection: &HostSchedulingSelection,
        setup: &HostSource17SetupBorrow<'_>,
        row: &HostRestoredSource17ConstructionData,
        scratch: usize,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.authenticate_retained_code_origin_data()
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        if !Rc::ptr_eq(self, &held.factory) || !std::ptr::eq(original.as_ptr().cast_const(), held) {
            return Err(RuntimeError::ForeignAuthority);
        }
        held.authenticate_host_source17_phase_data(selection)?;
        let mut counter = Counter::new(
            maximum
                .checked_sub(scratch)
                .ok_or(RuntimeError::ResourceLimit)?,
        );
        counter
            .add(row.requested_bytes_data()?)
            .map_err(storage_error)?;
        counter.rc(original).map_err(storage_error)?;
        // The complete real Prepared/direct setup still coexists with this
        // construction. Its borrowed Host selection is included there; no
        // incoming selection clone is allocated before admission.
        setup.charge_data(&mut counter, Some(original))?;
        counter
            .add(self.retained_host_precredit_data(counter.remaining())?)
            .map_err(storage_error)?;
        counter.rc(&held.code_graph).map_err(storage_error)?;
        let graph_root = size_of_val(held.code_graph.as_ref());
        let graph = held.code_graph.original_retained_requested_storage_data(
            counter
                .remaining()
                .checked_add(graph_root)
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        counter
            .add(
                graph
                    .checked_sub(graph_root)
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .map_err(storage_error)?;
        counter
            .add(
                held.source
                    .retained_original_host17_preconstruction_storage_data(
                        held.host_ticket
                            .as_ref()
                            .ok_or(RuntimeError::OwnerUnavailable)?,
                        counter.remaining(),
                    )?,
            )
            .map_err(storage_error)?;
        held.authenticate_host_source17_phase_data(selection)
    }
}

fn storage_error(_: crate::node_qualification::QualificationError) -> RuntimeError {
    RuntimeError::ResourceLimit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resources() -> ResourceLimits {
        ResourceLimits {
            cpu_budget_ns: 10.into(),
            memory_bytes: 100_000.into(),
            writable_bytes: 10.into(),
            processes: 3.into(),
            descriptors: 32.into(),
            pending_events: 10.into(),
            content_bytes: 100_000.into(),
            maximum_operations: 10.into(),
            extensions: Default::default(),
        }
    }

    #[test]
    fn retained_policy_refuses_every_changed_target_budget() {
        let original = resources();
        let policy = Policy::read(&original).unwrap();
        assert!(policy.authenticate(&original).is_ok());
        for selected in 0..8 {
            let mut changed = original.clone();
            let fields = [
                &mut changed.cpu_budget_ns,
                &mut changed.memory_bytes,
                &mut changed.writable_bytes,
                &mut changed.processes,
                &mut changed.descriptors,
                &mut changed.pending_events,
                &mut changed.content_bytes,
                &mut changed.maximum_operations,
            ];
            *fields.into_iter().nth(selected).unwrap() = 999.into();
            assert!(policy.authenticate(&changed).is_err());
        }
    }

    #[test]
    fn prebirth_policy_refuses_zero_process_shortfall_and_extensions() {
        let mut changed = resources();
        changed.memory_bytes = 0.into();
        assert!(Policy::read(&changed).is_err());
        changed = resources();
        changed.processes = 2.into();
        assert!(Policy::read(&changed).is_err());
        changed = resources();
        changed
            .extensions
            .insert("unadmitted".into(), serde_json::Value::Bool(true));
        assert!(Policy::read(&changed).is_err());
    }
}
