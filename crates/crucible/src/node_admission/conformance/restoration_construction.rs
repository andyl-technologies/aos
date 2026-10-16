//! Borrows actual same-runtime inputs for prospective restoration DATA.
//!
//! These loans let Core inspect the same runtime-owned node and preserve actual
//! archive construction facts. They create no installed window, target binding,
//! signer, upload, Commit or final context. Those mechanisms remain separate
//! prerequisites before any live restoration effect.

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
    /// Borrows its same immutable typed launches in original roster order.
    pub launches: &'a [crucible_node_provider::reference_packet::service::PacketNative5SourceLaunch; 3],
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
    /// Borrows the actual inactive complete-restoration runtime before Commit.
    pub runtime: &'a ConformanceRuntime,
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
    pub(crate) fn authenticate_original_group_data(&self) -> Result<(), RuntimeError> {
        let source = self.sources.get(self.selected).ok_or(RuntimeError::ForeignAuthority)?;
        let launch = self.launches.get(self.selected).ok_or(RuntimeError::ForeignAuthority)?;
        let encoded = self.encoded_launches.get(self.selected).ok_or(RuntimeError::ForeignAuthority)?;
        let ticket = self.tickets.get(self.selected).ok_or(RuntimeError::ForeignAuthority)?;
        if !Rc::ptr_eq(source, self.source) || !std::ptr::eq(launch, self.launch)
            || !std::ptr::eq(*ticket, self.ticket)
            || !std::ptr::eq(encoded.as_ptr(), self.encoded_launch.as_ptr())
            || encoded.len() != self.encoded_launch.len() {
            return Err(RuntimeError::ForeignAuthority);
        }
        if self.journals[self.selected] != self.journal
            || !std::ptr::eq(&self.prepare_ids[self.selected], self.prepare_id)
            || !std::ptr::eq(&self.commit_ids[self.selected], self.commit_id) {
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
                    || self.tickets[prior].is_original_restoration_owner_data(self.tickets[index]) {
                    return Err(RuntimeError::ForeignAuthority);
                }
            }
        }
        Ok(())
    }
}


#[path = "restoration_construction/node.rs"]
mod node;
pub use node::{OriginalRestorationNodeConstructionData, OriginalRestorationNodeInputs};
