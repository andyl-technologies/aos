//! Admits one same-runtime restoration transaction and retains its partial owners.
//!
//! The installed window conjoins actual Source3, archive tickets, target runtime,
//! cold owners and separately named future transfer phases. Opaque once claims
//! gate the same CNP node's Prepare, input publication and Commit. Post-Commit
//! inspection repeats actual Source-fenced journal/model predicates; it creates
//! no final lineage context or readiness permission. Final four-owner scope and
//! common-runtime installation remain distinct required mechanisms.

use super::InstalledConformancePlan;
use crate::{
    node_adapters::cnp::PacketCompleteSemanticSource,
    node_contract::{ActivationRecord, ConformanceRuntime, RuntimeError},
    node_state::{CompleteOriginalNativeTicket, CompleteOriginalRestorationSource},
};
use crucible_node_contract::{ContentRef, Id};
use std::rc::{Rc, Weak};

/// Borrows independently issued originals for one selected restoration target.
///
/// Constructing these argument loans grants no permission. Core authenticates
/// the native ticket against the signed archive and actual inactive runtime;
/// the installed concrete holder authenticates its exact private target capsule.
pub struct OriginalRestorationConstructionInputs<'a> {
    /// Borrows the complete actual registered three-Source reconstruction roster.
    pub sources: &'a [Rc<PacketCompleteSemanticSource>; 3],
    /// Borrows the actual completed same-holder SDK roots, including remaining
    /// native/report/launch/wire commitments that current capacities do not erase.
    pub sdks: [&'a crate::node_adapters::cnp::PacketCompleteOriginalHostSdk; 3],
    /// Borrows its same immutable typed launches in original roster order.
    pub launches:
        &'a [crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch; 3],
    /// Borrows the three actual original canonical nested launch5 banks.
    pub encoded_launches: [&'a [u8]; 3],
    /// Borrows the same archive's three native tickets without transferring them.
    pub tickets: [&'a CompleteOriginalNativeTicket; 3],
    /// Selects the existing node to dispatch after whole-group admission.
    /// This index is routing DATA and supplies no Source or owner authority.
    pub selected: usize,
    /// Borrows already retained assigned Prepare IDs for the three controllers.
    pub prepare_ids: &'a [Id; 3],
    /// Borrows distinct retained assigned Commit IDs in the same owner order.
    pub commit_ids: &'a [Id; 3],
    /// Borrows the actual fresh Source registered on the installed holder.
    pub source: &'a Rc<PacketCompleteSemanticSource>,
    /// Borrows the same registered immutable typed launch retained before Child.
    pub launch: &'a crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch,
    /// Borrows that holder's original canonical nested launch5 bank.
    /// The concrete raw callback must compare its actual pointer and length.
    pub encoded_launch: &'a [u8],
    /// Borrows the actual completely verified signed archive allocation.
    pub archive: &'a CompleteOriginalRestorationSource,
    /// Borrows its same original native owner ticket before transfer.
    pub ticket: &'a CompleteOriginalNativeTicket,
    /// Borrows actual complete-restoration owners for this construction phase.
    /// Installed observations retain real field loans and a current runtime loan;
    /// cold construction also retains its genuine original whole-wrapper loan.
    pub runtime: crate::node_contract::ConformanceRuntimeObservation<'a>,
    /// Borrows the proposal already installed on that exact runtime barrier.
    pub activation: &'a ActivationRecord,
    /// Borrows the three exact signed local journal roles in native owner order.
    pub journals: [&'a ContentRef; 3],
    /// Names the original signed owner's exact settlement journal role.
    pub journal: &'a ContentRef,
    /// Borrows the already retained unique Prepare request identifier.
    pub prepare_id: &'a Id,
    /// Borrows the distinct already retained unique Commit request identifier.
    pub commit_id: &'a Id,
}

impl OriginalRestorationConstructionInputs<'_> {
    pub(crate) fn selected_inputs_data(
        &self,
        selected: usize,
    ) -> Result<OriginalRestorationConstructionInputs<'_>, RuntimeError> {
        let inputs = OriginalRestorationConstructionInputs {
            sources: self.sources,
            sdks: self.sdks,
            launches: self.launches,
            encoded_launches: self.encoded_launches,
            tickets: self.tickets,
            selected,
            prepare_ids: self.prepare_ids,
            commit_ids: self.commit_ids,
            source: self
                .sources
                .get(selected)
                .ok_or(RuntimeError::ForeignAuthority)?,
            launch: self
                .launches
                .get(selected)
                .ok_or(RuntimeError::ForeignAuthority)?,
            encoded_launch: *self
                .encoded_launches
                .get(selected)
                .ok_or(RuntimeError::ForeignAuthority)?,
            archive: self.archive,
            ticket: *self
                .tickets
                .get(selected)
                .ok_or(RuntimeError::ForeignAuthority)?,
            runtime: self.runtime,
            activation: self.activation,
            journals: self.journals,
            journal: *self
                .journals
                .get(selected)
                .ok_or(RuntimeError::ForeignAuthority)?,
            prepare_id: self
                .prepare_ids
                .get(selected)
                .ok_or(RuntimeError::ForeignAuthority)?,
            commit_id: self
                .commit_ids
                .get(selected)
                .ok_or(RuntimeError::ForeignAuthority)?,
        };
        inputs.authenticate_original_group_data()?;
        Ok(inputs)
    }

    pub(crate) fn authenticate_original_group_data(&self) -> Result<(), RuntimeError> {
        let source = self
            .sources
            .get(self.selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let launch = self
            .launches
            .get(self.selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let encoded = self
            .encoded_launches
            .get(self.selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let ticket = self
            .tickets
            .get(self.selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if !Rc::ptr_eq(source, self.source)
            || !std::ptr::eq(launch, self.launch)
            || !std::ptr::eq(*ticket, self.ticket)
            || !std::ptr::eq(encoded.as_ptr(), self.encoded_launch.as_ptr())
            || encoded.len() != self.encoded_launch.len()
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.journals[self.selected] != self.journal
            || !std::ptr::eq(&self.prepare_ids[self.selected], self.prepare_id)
            || !std::ptr::eq(&self.commit_ids[self.selected], self.commit_id)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        for index in 0..3 {
            if self.prepare_ids[index] == self.commit_ids[index] {
                return Err(RuntimeError::InvalidReceipt);
            }
            self.tickets[index].authenticate_source(self.archive)?;
            if self.encoded_launches[index].is_empty() {
                return Err(RuntimeError::OwnerUnavailable);
            }
            for prior in 0..index {
                if Rc::ptr_eq(&self.sources[prior], &self.sources[index])
                    || self.tickets[prior].is_original_restoration_owner_data(self.tickets[index])
                {
                    return Err(RuntimeError::ForeignAuthority);
                }
            }
        }
        Ok(())
    }
}

#[path = "restoration_construction/node.rs"]
mod node;
pub(crate) use node::OriginalRestorationSigningCollector;
pub use node::{OriginalRestorationNodeConstructionData, OriginalRestorationNodeInputs};

#[path = "restoration_construction/construction_inputs.rs"]
mod construction_inputs;
pub(crate) use construction_inputs::OriginalRestorationSigningConstructionInputs;

#[path = "restoration_construction/claim.rs"]
mod claim;
pub(crate) use claim::{
    OriginalRestorationMappingInputs, OriginalRestorationSigningInputs,
    OriginalRestorationTransactionClaim, OriginalRestorationTransactionPhase,
};
#[path = "restoration_construction/inspection.rs"]
mod inspection;
pub(crate) use inspection::OriginalRestorationTransactionInspection;

#[path = "restoration_construction/window.rs"]
mod window;
pub use window::{
    CompleteOriginalRestorationWindow, OriginalRestorationConstructionPhase,
    OriginalRestorationConstructionPolicy, OriginalRestorationConstructionScope,
    OriginalRestorationConstructionStorage, OriginalRestorationMemberScope,
};
#[path = "restoration_construction/target.rs"]
mod target;
#[path = "restoration_construction/transaction_group.rs"]
mod transaction_group;
pub use target::CompleteOriginalRestorationTransactionTarget;

pub use window::OriginalRestorationNodeDispatch;

pub use window::OriginalRestorationNodeContinuationInspection;

pub use window::OriginalRestorationHostContinuationInspection;

#[path = "restoration_construction/activation.rs"]
mod activation;
#[path = "restoration_construction/observation.rs"]
mod observation;
pub use observation::OriginalInstalledRestorationObservationClaim;
pub(crate) use observation::{
    OriginalInstalledRestorationObservationSigningConstructionInputs,
    OriginalInstalledRestorationObservationSigningInputs,
};

pub use activation::{
    OriginalInstalledRestorationActivationClaim, OriginalInstalledRestorationActivationPhase,
};
pub(crate) use activation::{
    OriginalInstalledRestorationActivationSigningConstructionInputs,
    OriginalInstalledRestorationActivationSigningInputs,
};

pub use window::OriginalRestorationCoordinatorConstructionData;

pub(crate) use window::{
    OriginalRestoredSuffixCheckpointData, OriginalRestoredSuffixConstructionData,
    OriginalRestoredSuffixSeedClaim,
};

pub use window::{
    OriginalRestoredInitialSchedulingAdmission, OriginalRestoredSchedulingObservationAdmission,
    OriginalRestoredSchedulingObservationClaim,
    OriginalRestoredSchedulingObservationConstructionData,
};

pub use window::{
    OriginalRestoredProducerExecutionAdmission, OriginalRestoredProducerExecutionClaim,
    OriginalRestoredProducerExecutionConstructionData,
    OriginalRestoredProducerPublisherConstructionScope,
};

pub(crate) use window::ProducerExecutionPhase;

pub use window::OriginalRestoredInput17ConstructionData;

pub use window::{OriginalRestoredCaptureClaim, OriginalRestoredCaptureRequestData};
pub(crate) use window::{
    OriginalRestoredCaptureImportedOwnerInputs, OriginalRestoredCaptureSigningInputs,
};
