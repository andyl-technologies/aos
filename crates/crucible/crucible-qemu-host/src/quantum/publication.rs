//! Borrows the live Source and the driver's same Quantum through publication.
//!
//! The context cannot create an Original or clone a producing Source. Its
//! mapping comparison only corroborates two actual views of the same setup;
//! real retained lenders grant the command's semantic custody independently.

use crucible_host_resources::host_supervision::{HostOperationGuard, HostSupervisionError};
use crucible_qemu_protocol::boundary_action::ActionBinding;
use crucible_qemu_shmem::{
    CommittedSchedulerAdvance, MappedSetupRegion, NodeSlot, PreparedSchedulerAdvance,
    SetupRegionBackingIdentity,
};

use super::QemuQuantumError;
use crate::spawn::source_supervision::ActionSourceProducer;

/// Borrows a live Source and its caller's existing Quantum for one handoff.
///
/// Only an installed runtime constructs this context. Scripted channels may
/// omit it; a channel that receives it must preserve the actual Source handoff
/// or refuse before its scheduler effects.
#[must_use]
pub struct QemuQuantumPublication<'operation> {
    source: &'operation mut ActionSourceProducer,
    mapping: &'operation MappedSetupRegion,
    slot: u32,
    original: &'operation HostOperationGuard,
}

impl<'operation> QemuQuantumPublication<'operation> {
    pub(crate) fn new(
        source: &'operation mut ActionSourceProducer,
        mapping: &'operation MappedSetupRegion,
        slot: u32,
        original: &'operation HostOperationGuard,
    ) -> Self {
        Self {
            source,
            mapping,
            slot,
            original,
        }
    }

    /// Compares the actual mapped channel with the runtime's independent view.
    pub(crate) fn corroborate_mapping(
        &self,
        backing: SetupRegionBackingIdentity,
        slot: u32,
    ) -> Result<(), QemuQuantumError> {
        if self.slot != slot || self.mapping.backing_identity() != backing {
            return Err(refusal(
                "bind actual Quantum publisher mapping",
                HostSupervisionError::Unavailable,
            ));
        }
        Ok(())
    }

    pub(super) fn retain(
        &mut self,
        actual_node: &NodeSlot,
        prepared: &PreparedSchedulerAdvance<'_>,
        ceiling: u64,
        stop: crate::QemuQuantumStopCondition,
    ) -> Result<ActionBinding, QemuQuantumError> {
        if !prepared.belongs_to(actual_node) {
            return Err(refusal(
                "bind actual Quantum scheduler writer",
                HostSupervisionError::Unavailable,
            ));
        }
        self.original
            .wait_slice()
            .map_err(|source| refusal("check Quantum before lender birth", source))?;
        let binding = self
            .source
            .begin_quantum_action(
                self.mapping,
                self.slot,
                self.original,
                prepared,
                ceiling,
                stop,
            )
            .map_err(|source| refusal("retain actual Quantum lenders", source))?;
        self.source
            .begin_quantum_publication(binding)
            .map_err(|source| refusal("seal actual Quantum publication", source))?;
        self.original
            .wait_slice()
            .map_err(|source| refusal("check Quantum before tuple commit", source))?;
        Ok(binding)
    }

    pub(super) fn publish(
        &mut self,
        binding: ActionBinding,
        actual_node: &NodeSlot,
        committed: &CommittedSchedulerAdvance<'_>,
    ) -> Result<(), QemuQuantumError> {
        let publication = self
            .source
            .commit_quantum_publication(binding, actual_node, committed);
        // Both independent posts run after the session mutex and complete
        // collector locks have been released. Neither creates another offer.
        let original_post = self.original.wait_slice().err();
        let cohort_post = self.source.refresh_action().err();
        let recorded =
            self.source
                .record_quantum_publication_posts(binding, original_post, cohort_post);
        if publication.is_err()
            || original_post.is_some()
            || cohort_post.is_some()
            || recorded.is_err()
        {
            self.source.deny_quantum_publication(binding);
        }
        publication.map_err(|source| refusal("publish actual Quantum command", source))?;
        recorded.map_err(|source| refusal("retain actual Quantum publication posts", source))?;
        if let Some(source) = original_post.or(cohort_post) {
            return Err(refusal("post actual Quantum command publication", source));
        }
        let notification = self.source.notify_quantum_publication(binding);
        if notification.is_err() {
            self.source.deny_quantum_publication(binding);
        }
        notification.map_err(|source| refusal("notify actual Quantum command publication", source))
    }
}

fn refusal(operation: &'static str, source: HostSupervisionError) -> QemuQuantumError {
    QemuQuantumError::OperationalSupervision { operation, source }
}
