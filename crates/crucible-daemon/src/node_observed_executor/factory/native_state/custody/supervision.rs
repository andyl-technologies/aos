//! Authenticates original journals before a reclaimed capsule changes custodian.
//!
//! Supervisor custody continues to consume the installed original owner credit.
//! A later fresh archive reopening and the same actual kernel release proof are
//! required before the supervisor can release that complete original capsule.

use crucible::{
    node_adapters::gem5::{Gem5AuthenticatedContinuation, authenticate_gem5_continuation},
    node_admission::AdmittedGraph,
    node_contract::{SavedRuntimeActivation, SavedRuntimeResult},
    node_state::{NativeArchiveRecord, NativeWorldFactory, StateRequirements, VerifiedCapture},
};
use crucible_node_contract::{ContentRef, Id, U64};
use crucible_node_provider::gem5::Gem5PreparationCustody;

use super::{Entry, NativeCustodyError};

/// Retains source-authenticated complete history, never a reconstructed ACK list.
pub(in crate::node_observed_executor::factory::native_state) struct AuthenticatedSupervision {
    archive: NativeArchiveRecord,
    verified: VerifiedCapture,
    native: Gem5AuthenticatedContinuation,
}

impl AuthenticatedSupervision {
    pub(in crate::node_observed_executor::factory::native_state) fn authenticate(
        archive: NativeArchiveRecord,
        graph: &AdmittedGraph,
        factory: &dyn NativeWorldFactory,
        requirements: StateRequirements,
        maximum_microsteps: U64,
    ) -> Result<Self, NativeCustodyError> {
        let refuse =
            || NativeCustodyError::Refused("original supervisor source authentication differs");
        if graph.node_ids().count() != 4 || archive.owners().len() != 4 {
            return Err(NativeCustodyError::Refused(
                "supervisor requires the selected complete four-owner source",
            ));
        }

        // Existing archive admission charges its complete typed closure. These
        // additional bounds conservatively charge retained native associations
        // as well as original bytes before the extra runtime/native copies;
        // streamed CPU images are pinned descriptors rather than byte clones.
        let coordinator_bytes = archive.manifest().coordinator_state_ref.length.get();
        let cpu = archive
            .owners()
            .iter()
            .find(|owner| owner.participants.len() == 1 && owner.participants[0].as_str() == "cpu")
            .ok_or(NativeCustodyError::Refused("original CPU history absent"))?;
        let additional = cpu.evidence.iter().try_fold(
            cpu.state
                .length
                .get()
                .checked_mul(8)
                .ok_or(NativeCustodyError::Refused(
                    "supervisor native association credit overflow",
                ))?
                .checked_add(coordinator_bytes.checked_mul(3).ok_or(
                    NativeCustodyError::Refused("supervisor runtime credit overflow"),
                )?)
                .ok_or(NativeCustodyError::Refused(
                    "supervisor record credit overflow",
                ))?,
            |bytes, reference| {
                bytes
                    .checked_add(reference.length.get().checked_mul(8).ok_or(
                        NativeCustodyError::Refused(
                            "supervisor evidence association credit overflow",
                        ),
                    )?)
                    .ok_or(NativeCustodyError::Refused(
                        "supervisor evidence credit overflow",
                    ))
            },
        )?;
        if coordinator_bytes > 16 * 1024 * 1024
            || cpu.evidence.len() > 65_536
            || additional > 256 * 1024 * 1024
        {
            return Err(NativeCustodyError::Refused(
                "supervisor retained history exceeds credit",
            ));
        }

        let verified = archive
            .admit(graph, requirements, factory)
            .map_err(|_| refuse())?;
        let runtime = archive.runtime_snapshot().map_err(|_| refuse())?;
        let source = archive
            .authenticated_source(&cpu.owner, &runtime, verified.content())
            .map_err(|_| refuse())?;
        let native = authenticate_gem5_continuation(
            &source,
            &Id::new("cpu").map_err(|_| refuse())?,
            maximum_microsteps,
        )
        .map_err(|_| refuse())?;
        if !verified.pending_native_acknowledgements().is_empty()
            || native.record().pending_prefix().is_some()
            || runtime.operations.iter().any(|operation| {
                let SavedRuntimeResult::Acknowledged(outcome) = &operation.result else {
                    return true;
                };
                operation.scheduling_commit.as_ref().is_none_or(|commit| {
                    commit.operation != operation.operation
                        || commit.node != operation.route.node
                        || commit.retained_outputs != outcome.retained_outputs
                })
            })
        {
            return Err(NativeCustodyError::Refused(
                "original operation, publication or private ACK remains unresolved",
            ));
        }
        Ok(Self {
            archive,
            verified,
            native,
        })
    }

    pub(super) fn artifact(&self) -> &ContentRef {
        self.archive.artifact()
    }

    pub(super) fn same_original(&self, other: &Self) -> bool {
        self.archive.artifact() == other.archive.artifact()
            && self.archive.manifest() == other.archive.manifest()
            && self.archive.owners() == other.archive.owners()
            && self.native.runtime() == other.native.runtime()
            && self
                .native
                .record()
                .native_prefixes()
                .eq(other.native.record().native_prefixes())
    }

    pub(super) fn validate_entry(&self, entry: &mut Entry) -> Result<(), NativeCustodyError> {
        let fail =
            || NativeCustodyError::Refused("supervisor original capsule or release proof differs");
        if entry.in_flight
            || entry.scope.publication != crucible::node_state::PublicationKnowledge::Committed
            || self.native.runtime().source_activation
                != SavedRuntimeActivation::from(&entry.scope.activation)
        {
            return Err(fail());
        }
        let (reference, bytes) = entry.proof.as_ref().ok_or_else(fail)?;
        reference.verify(bytes).map_err(|_| fail())?;
        let custody = entry.custody.as_mut().ok_or_else(fail)?;
        if custody.launch.owner != entry.scope.owner.owner
            || custody.launch.incarnation != entry.scope.owner.incarnation
            || custody.launch.generation != entry.scope.owner.generation
            || custody.unresolved.is_some()
            || custody.unresolved_capture.is_some()
            || custody.pending.is_some()
            || custody.boundary.as_ref() != Some(self.native.record().native_boundary())
            || custody.last_acknowledged.as_ref() != self.native.record().last_acknowledged()
            || !custody
                .completed
                .values()
                .eq(self.native.record().native_prefixes())
        {
            return Err(fail());
        }
        let Gem5PreparationCustody::Validated(session) = &custody.preparation else {
            return Err(fail());
        };
        for (reference, bytes) in [session.packet(), session.transcript()] {
            if self.verified.content().get(reference) != Some(bytes) {
                return Err(fail());
            }
        }
        let actual = custody
            .poll_reclamation()
            .map_err(|_| fail())?
            .ok_or_else(fail)?;
        if actual.owner() != &entry.scope.owner.owner
            || actual.incarnation() != &entry.scope.owner.incarnation
            || actual.generation() != entry.scope.owner.generation
            || actual.evidence() != (reference, bytes.as_slice())
        {
            return Err(fail());
        }
        Ok(())
    }
}

pub(super) struct SupervisedEntry {
    pub(super) original: Entry,
    pub(super) source: AuthenticatedSupervision,
}
