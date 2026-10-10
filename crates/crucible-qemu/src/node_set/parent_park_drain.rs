//! Fixed park operations while the complete NodeSet retains its source.
//!
//! This adapter lends only operations on the actual installed source. It
//! neither extracts a Node nor supplies a contract, budget or native phase.

use std::sync::Arc;

use crucible_linux_resource::host_supervision::HostOperationGuard;
use crucible_linux_resource::ram_policy::{HostRamPolicyError, HostRamTarget};

use super::{QemuNodeSet, QemuNodeSetPreparedHotForkSource, QemuNodeSetPreparedHotForkTemplate};
use crate::qmp::parent_park_drain::QmpParentParkDrainReceipt;
use crate::{
    LinuxQemuAttemptHostOwner, OriginalActorParkCaller, OriginalActorParkImportError,
    OriginalActorParkImports, OriginalActorParkQuiescence, OriginalActorParkQuiescenceError,
};

/// Preserves the actual stopped-source action's initiating cause.
#[derive(Debug, thiserror::Error)]
pub enum OriginalParkSourceError {
    /// Existing NodeSet lookup could not lend the installed source.
    #[error(transparent)]
    Backend(#[from] crucible::BackendError),
    /// Installed source identity inspection failed.
    #[error(transparent)]
    Node(#[from] crate::QemuNodeError),
    /// The retained loan no longer designates this process.
    #[error("parent park source process changed")]
    ChangedProcess,
    /// Existing original-bound Pause or drain refused.
    #[error(transparent)]
    Pause(#[from] crate::QemuAsyncDriverRuntimeError),
    /// The same typed QMP channel refused.
    #[error(transparent)]
    Command(#[from] crate::QmpError),
}

/// Retains the exact prepared source coordinates and existing supervisor alias.
///
/// This move-only witness supplements the genuine host/Node/contract checks.
/// Its private fields never issue a native hold, process or clock authority.
/// The containing phase prepays its inline extent before the alias is retained.
pub struct OriginalParkSourceReborrowBinding {
    template_generation: u64,
    configuration: crucible::ContentHash,
    process_id: u32,
    start_time_ticks: u64,
    supervisor: crucible_linux_resource::host_supervision::HostOperationSupervisor,
}

impl QemuNodeSet {
    /// Lends the installed process to the fixed original-bound park adapter.
    ///
    /// This host-only check preserves the prepared token and pending ledger.
    /// Native template and hold revalidation runs inside the paired operation;
    /// constructing this loan performs no ambient QMP query or new operation.
    ///
    /// # Errors
    /// Refuses a missing source or a different retained process incarnation.
    pub fn prepared_parent_park_source<'a>(
        &'a mut self,
        prepared: &'a QemuNodeSetPreparedHotForkTemplate,
    ) -> Result<QemuNodeSetPreparedHotForkSource<'a>, OriginalParkSourceError> {
        let current = self.process_identity(&prepared.node)?;
        if current != prepared.source_process {
            return Err(OriginalParkSourceError::ChangedProcess);
        }
        let source = self.node_mut(&prepared.node)?;
        Ok(QemuNodeSetPreparedHotForkSource { source, prepared })
    }
}

impl QemuNodeSetPreparedHotForkSource<'_> {
    /// Returns the prepared token's node designation without issuing ownership.
    #[must_use]
    pub const fn node(&self) -> &crucible::NodeId {
        &self.prepared.node
    }

    /// Retains the current prepared identity without a new supervisor or deadline.
    ///
    /// # Errors
    /// Refuses a changed process or source without its existing supervisor.
    pub fn retain_parent_park_reborrow_binding(
        &self,
    ) -> Result<OriginalParkSourceReborrowBinding, OriginalParkSourceError> {
        self.verify_park_process()?;
        let supervisor = self
            .source
            .host_operation_supervisor()
            .ok_or(OriginalParkSourceError::ChangedProcess)?;
        Ok(OriginalParkSourceReborrowBinding {
            template_generation: self.prepared.template_generation,
            configuration: self.prepared.configuration(),
            process_id: self.prepared.source_process.process_id,
            start_time_ticks: self.prepared.source_process.start_time_ticks,
            supervisor: supervisor.clone(),
        })
    }

    /// Refuses rearm, source replacement or a changed supervisor before re-entry.
    ///
    /// This verifies retained coordinates only; the fixed provider separately
    /// authenticates the actual Node, host, decoder, Preparation and contract.
    ///
    /// # Errors
    /// Refuses any changed retained identity or current process incarnation.
    pub fn verify_parent_park_reborrow_binding(
        &self,
        binding: &OriginalParkSourceReborrowBinding,
    ) -> Result<(), OriginalParkSourceError> {
        self.verify_park_process()?;
        if self.prepared.template_generation != binding.template_generation
            || self.prepared.configuration() != binding.configuration
            || self.prepared.source_process.process_id != binding.process_id
            || self.prepared.source_process.start_time_ticks != binding.start_time_ticks
            || self.source.host_operation_supervisor() != Some(&binding.supervisor)
        {
            return Err(OriginalParkSourceError::ChangedProcess);
        }
        Ok(())
    }

    /// Checks the factory-issued complete parent against the installed source.
    ///
    /// # Errors
    /// Refuses absent or different actual RAM registration ownership.
    pub fn verify_original_park_parent(
        &self,
        parent: &HostRamTarget,
    ) -> Result<(), HostRamPolicyError> {
        self.source.verify_original_park_parent(parent)
    }

    /// Verifies the installed Node and its actual host before stage publication.
    ///
    /// # Errors
    /// Refuses a different Node slot, host, decoder, Preparation or contract.
    pub fn verify_original_park_binding(
        &self,
        host: &LinuxQemuAttemptHostOwner,
        decoder: &OriginalActorParkCaller,
        original: &Arc<HostOperationGuard>,
    ) -> Result<(), OriginalActorParkQuiescenceError> {
        self.source
            .verify_original_park_binding(host, decoder, original)
    }

    /// Enters the actual decoder's phase using this source's retained host slot.
    ///
    /// # Errors
    /// Refuses actual slot, decoder, Preparation, account or event admission.
    pub fn enter_original_park_quiescence(
        &self,
        host: &LinuxQemuAttemptHostOwner,
        decoder: &OriginalActorParkCaller,
        original: &Arc<HostOperationGuard>,
    ) -> Result<OriginalActorParkQuiescence, OriginalActorParkQuiescenceError> {
        self.source
            .enter_original_park_quiescence(host, decoder, original)
    }

    /// Prepays and seals the two retained bases and same host process event.
    ///
    /// # Errors
    /// Refuses the actual binding, original credit, descriptor or paired cuts.
    pub fn prepare_original_park_imports(
        &self,
        host: &LinuxQemuAttemptHostOwner,
        decoder: &OriginalActorParkCaller,
        original: &Arc<HostOperationGuard>,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<OriginalActorParkImports, OriginalActorParkImportError> {
        self.source
            .prepare_original_park_imports(host, decoder, original, actor, family)
    }

    fn verify_park_process(&self) -> Result<(), OriginalParkSourceError> {
        if self.source.process_identity()? != self.prepared.source_process {
            return Err(OriginalParkSourceError::ChangedProcess);
        }
        Ok(())
    }

    /// Pauses and drains under both actual entered original policies.
    ///
    /// # Errors
    /// Refuses process replacement, either original, drain or ordinary stop.
    pub fn pause_parent_park_under_originals(
        &mut self,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<u64, OriginalParkSourceError> {
        self.verify_park_process()?;
        self.source.pause_for_parent_park(actor, family)
    }

    /// Imports the retained pair and invokes the actual acquire command once.
    ///
    /// # Errors
    /// Refuses process replacement, pair cuts, imports or native receipt.
    pub fn acquire_parent_park_under_originals(
        &mut self,
        imports: &OriginalActorParkImports,
        correlation: u64,
        stopped: u64,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<QmpParentParkDrainReceipt, OriginalParkSourceError> {
        self.verify_park_process()?;
        Ok(self
            .source
            .acquire_parent_park(imports, correlation, stopped, actor, family)?)
    }

    /// Queries the retained owner using its exact acquisition coordinates.
    ///
    /// # Errors
    /// Refuses changed process, originals, receipt or native owner identity.
    pub fn query_parent_park_under_originals(
        &mut self,
        retained: &QmpParentParkDrainReceipt,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<QmpParentParkDrainReceipt, OriginalParkSourceError> {
        self.verify_park_process()?;
        Ok(self
            .source
            .retained_parent_park(retained, false, actor, family)?)
    }

    /// Relinquishes only the owner established by the retained acquisition.
    ///
    /// # Errors
    /// Refuses changed process, either original, native refusal or uncertainty.
    pub fn relinquish_parent_park_under_originals(
        &mut self,
        retained: &QmpParentParkDrainReceipt,
        actor: &HostOperationGuard,
        family: &HostOperationGuard,
    ) -> Result<QmpParentParkDrainReceipt, OriginalParkSourceError> {
        self.verify_park_process()?;
        Ok(self
            .source
            .retained_parent_park(retained, true, actor, family)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crucible::{ContentHash, EventLog, NodeId};
    use crucible_linux_resource::host_supervision::{
        HostOperationBudgets, HostOperationSupervisor,
    };

    // The actual scripted source and installed NodeSet exercise retained
    // identity checks. They do not issue a native park or process entitlement.
    #[test]
    fn reborrow_binding_refuses_equal_budget_supervisor_and_changed_template() {
        let mut nodes = QemuNodeSet::new();
        let node = NodeId {
            name: String::from("node-a"),
        };
        nodes.insert(
            node.clone(),
            crate::scripted_hot_fork_source_for_test(crate::QemuTestHotForkOutcome::Forked)
                .expect("scripted source"),
        );
        let mut token = nodes
            .prepare_retained_hot_fork_template(
                &node,
                ContentHash::from_bytes(b"retained parent identity"),
                EventLog::new(),
                crate::QemuLaunchResourceRequirements::from_vm_shape(128, 1, true),
                &[],
                64 * 1024 * 1024,
            )
            .expect("prepared source");
        let original = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )
        .expect("original supervisor");
        nodes
            .attach_retained_source_supervisor(&token, original.clone())
            .expect("attach original");
        let binding = nodes
            .prepared_parent_park_source(&token)
            .expect("installed source")
            .retain_parent_park_reborrow_binding()
            .expect("retained binding");
        nodes
            .prepared_parent_park_source(&token)
            .expect("same source")
            .verify_parent_park_reborrow_binding(&binding)
            .expect("same allocation");

        let different = HostOperationSupervisor::new(
            HostOperationBudgets::default(),
            Some(Duration::from_secs(2)),
        )
        .expect("equal-budget different supervisor");
        assert_ne!(original, different);
        nodes
            .attach_retained_source_supervisor(&token, different)
            .expect("attach different supervisor");
        assert!(matches!(
            nodes
                .prepared_parent_park_source(&token)
                .expect("installed source")
                .verify_parent_park_reborrow_binding(&binding),
            Err(OriginalParkSourceError::ChangedProcess),
        ));

        nodes
            .attach_retained_source_supervisor(&token, original)
            .expect("restore same allocation");
        let generation = token.template_generation;
        token.template_generation = generation.checked_add(1).expect("next generation");
        assert!(matches!(
            nodes
                .prepared_parent_park_source(&token)
                .expect("installed source")
                .verify_parent_park_reborrow_binding(&binding),
            Err(OriginalParkSourceError::ChangedProcess),
        ));
        token.template_generation = generation;
        nodes
            .prepared_parent_park_source(&token)
            .expect("restored source")
            .verify_parent_park_reborrow_binding(&binding)
            .expect("exact restored binding");
    }
}
