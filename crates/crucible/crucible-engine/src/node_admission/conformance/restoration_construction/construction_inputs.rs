//! Borrows real retained originals for prospective Source signer DATA.
//!
//! This view contains no claim or permission. Its collector runs before the
//! effect-bearing transaction is issued, after any cold owners have their own
//! genuine construction admission. A quote must not allocate a request, compute
//! an index identity, sign, publish, renew Query or manufacture a final context.

use super::*;
use crucible_node_transport::reference_packet::service::{
    PacketNative5SourceLaunch, complete_restore::transfer::PacketCompleteRestoreInputAllocation,
};

/// Borrows the same originals used by the later admitted signing loan.
///
/// All fields are inert DATA. The installed collector authenticates actual
/// ticket/archive/Source/activation associations independently; accepting a
/// value of this type cannot authorize a Source effect. The future mapping
/// extent comes from the real fixed Source mapping bank, before that mapping
/// exists. The allocation is the retained output of the actual native quote.
pub(crate) struct OriginalRestorationSigningConstructionInputs<'a> {
    pub(crate) source: &'a Rc<PacketCompleteSemanticSource>,
    pub(crate) controller: &'a crucible_node_transport::client::CnpController,
    pub(crate) query: &'a crucible_node_transport::client::OriginalFreshRestoreQuery,
    pub(crate) binding_quote:
        &'a crucible_node_transport::client::OriginalFreshRestorePrepareBindingStorageData,
    pub(crate) archive: &'a CompleteOriginalRestorationSource,
    pub(crate) ticket: &'a CompleteOriginalNativeTicket,
    pub(crate) plan: &'a InstalledConformancePlan,
    pub(crate) activation: &'a ActivationRecord,
    pub(crate) launch: &'a PacketNative5SourceLaunch,
    pub(crate) journal: &'a crate::node_adapters::cnp::PacketCompleteSettledJournal,
    pub(crate) journal_reference: &'a ContentRef,
    pub(crate) capture_terminal: &'a crucible_node_transport::envelope::Envelope,
    pub(crate) native_allocation: &'a PacketCompleteRestoreInputAllocation,
    pub(crate) prepare_id: &'a Id,
    pub(crate) commit_id: &'a Id,
    pub(crate) maximum_mapping_bytes: usize,
    pub(crate) maximum_record_bytes: usize,
    pub(crate) observed_other_retained_bytes: usize,
}
