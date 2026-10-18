//! Conjoins complete historical native proofs and assigned request chronology.
//!
//! These checks consume borrowed DATA. They reconstruct no native phase owner,
//! SDK transaction, current process association, signer or restoration right.
//! The enclosing graph supplies its private original birth key and separately
//! proves the actual SDK four-output/literal-frame relationships. Failure owners
//! remain representable even when these complete-history predicates refuse.

use crate::ProviderError;
use crate::bodies::ResponseBody;
use crate::envelope::Envelope;
use crate::protocol_snapshot::owned11::state::HistoricalAuthority;
use crate::reference_packet::control::{
    CurrentControl17Data, PacketControlSelection, PacketNative5UnderlyingRecord,
};
use crate::reference_packet::service::ack_emitter::{
    PacketCanonicalAckAdmissionContext, PacketCanonicalAckAdmissionProof,
};
use crate::reference_packet::service::complete_restore::{
    PacketNativeRestoredCommitHold, PacketNativeRestoredRecord,
    transfer::{
        PacketCompleteRestoreCommitContext, PacketCompleteRestoreCommitRequest,
        PacketCompleteRestorePrepareContext, PacketCompleteRestorePrepareRequest,
        PacketCompleteRestoreTransferProof,
    },
};
use crucible_node_contract::U64;
use serde_json::Value;

mod ack;
#[path = "historical_auth/construction.rs"]
pub(crate) mod construction;
mod observation;
mod shared;
mod transfer;

pub(crate) use ack::authenticate_historical_ack_data;
pub(crate) use observation::{
    authenticate_historical_activation_data, authenticate_historical_restored_observation_data,
};
pub(crate) use transfer::{
    authenticate_historical_commit_data, authenticate_historical_prepare_data,
};

/// Borrows a complete original and correlated terminal without claiming custody.
#[derive(Clone, Copy)]
pub struct HistoricalCompletedPair17<'a> {
    /// Borrows the actual complete assigned original, including its proof.
    pub original: &'a Envelope,
    /// Borrows the actual complete terminal, including its receipt.
    pub terminal: &'a Envelope,
}

/// Borrows the Source's independently retained first-observation DATA owners.
///
/// No key, native phase owner or SDK capability is part of this public input.
/// The sealed native graph supplies its own historical counterparts privately.
pub struct HistoricalRestoredObservation17Data<'a> {
    /// Borrows actual completed SDK ACK, Prepare and Commit journal pairs.
    ///
    /// Native separately checks these against its immutable literal banks and
    /// typed caches before borrowing them for historical MAC-chain validation.
    pub association: &'a crate::protocol_snapshot::current_controller17::ValidatedHistoricalRestorationAssociation17,
    /// Borrows the actual Source owner's full common-scope binding digest.
    pub binding: &'a [u8; 32],
    /// Borrows the actual assigned Observe request from the Controller history.
    pub original: &'a Envelope,
    /// Borrows its actual correlated completed terminal.
    pub terminal: &'a Envelope,
    /// Borrows the independently retained typed response for that same pair.
    pub response: &'a ResponseBody,
    /// Borrows the complete restored proof named by the terminal measurement.
    pub record: &'a PacketNativeRestoredRecord,
    /// Borrows the full producer or reactive record named by that proof.
    pub underlying: &'a PacketNative5UnderlyingRecord,
}

/// Selects independently admitted frame and referenced-proof construction bounds.
#[derive(Clone, Copy)]
pub(crate) struct HistoricalAuthLimits17 {
    pub(crate) maximum_frame_bytes: usize,
    pub(crate) maximum_evidence_bytes: usize,
}

/// Borrows complete original normalization inputs, never digest-only labels.
pub(crate) struct HistoricalAckBindings17<'a> {
    pub(crate) birth_association: &'a Value,
    pub(crate) kernel_binding: &'a Value,
    pub(crate) policy_binding: &'a Value,
    pub(crate) host_registration: &'a Value,
    pub(crate) native_registration: &'a Value,
    pub(crate) authority: &'a HistoricalAuthority,
    pub(crate) controller_pid: U64,
    pub(crate) controller_uid: U64,
    pub(crate) controller_executable: &'a crucible_node_contract::ContentRef,
    pub(crate) hello_request_literal: &'a [u8],
    pub(crate) hello_response_literal: &'a [u8],
}

/// Borrows only the three actual stages consumed by restoration verification.
///
/// Historical upload banks remain in their original complete wire evidence.
/// This view neither substitutes empty uploads nor reconstructs their owners.
pub(crate) struct HistoricalRestorationStages17<'a> {
    pub(crate) arm: &'a super::current_stages::CurrentActivation17,
    pub(crate) world: &'a super::current_stages::CurrentActivation17,
    pub(crate) first_observation: &'a super::current_stages::CurrentFirstObservation17,
}

/// Borrows the exact ACK context, proof, selected tuple and original pair.
pub(crate) struct HistoricalAck17<'a> {
    pub(crate) context: &'a PacketCanonicalAckAdmissionContext,
    pub(crate) proof: &'a PacketCanonicalAckAdmissionProof,
    pub(crate) pair: HistoricalCompletedPair17<'a>,
    pub(crate) selection: &'a PacketControlSelection,
    pub(crate) native_pid: U64,
    pub(crate) bindings: HistoricalAckBindings17<'a>,
}

/// Borrows the retained Prepare proof and its actual completed pair.
pub(crate) struct HistoricalPrepare17<'a> {
    pub(crate) request: &'a PacketCompleteRestorePrepareRequest,
    pub(crate) context: &'a PacketCompleteRestorePrepareContext,
    pub(crate) proof: &'a PacketCompleteRestoreTransferProof,
    pub(crate) pair: HistoricalCompletedPair17<'a>,
}

/// Borrows the retained Commit, its completed pair and immutable held evidence.
pub(crate) struct HistoricalCommit17<'a> {
    pub(crate) request: &'a PacketCompleteRestoreCommitRequest,
    pub(crate) context: &'a PacketCompleteRestoreCommitContext,
    pub(crate) proof: &'a PacketCompleteRestoreTransferProof,
    pub(crate) pair: HistoricalCompletedPair17<'a>,
    pub(crate) held: &'a PacketNativeRestoredCommitHold,
}

/// Borrows the complete earlier restoration chain and current cached originals.
pub(crate) struct HistoricalRestoration17<'a> {
    pub(crate) ack: HistoricalAck17<'a>,
    pub(crate) prepare: HistoricalPrepare17<'a>,
    pub(crate) commit: HistoricalCommit17<'a>,
    pub(crate) canonical_mapping: &'a [u8],
    pub(crate) control: &'a CurrentControl17Data,
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("complete historical native17 correspondence")
}

/// Names concrete borrowed inputs and independently bounded result/serializer views.
pub(crate) fn historical_auth17_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<HistoricalAuthLimits17>()
        + size_of::<HistoricalCompletedPair17<'static>>()
        + size_of::<HistoricalRestoredObservation17Data<'static>>()
        + size_of::<HistoricalAckBindings17<'static>>()
        + size_of::<HistoricalAck17<'static>>()
        + size_of::<HistoricalPrepare17<'static>>()
        + size_of::<HistoricalCommit17<'static>>()
        + size_of::<HistoricalRestoration17<'static>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<ResponseBody, ProviderError>>()
        + size_of::<Result<Vec<u8>, ProviderError>>()
        + size_of::<Result<[u8; 32], ProviderError>>()
        + size_of::<Result<PacketNative5UnderlyingRecord, ProviderError>>()
        + size_of::<[u8; 32]>()
        + size_of::<blake3::Hash>()
        + shared::counter_scratch_data()
        + ack::counter_scratch_data()
        + size_of::<crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestorePrepareReceipt>()
        + size_of::<crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreCommitReceipt>()
        + size_of::<crate::reference_packet::service::complete_restore::activation::PacketRestorationActivationCommand>()
        + crate::reference_packet::service::complete_restore::activation::restoration_activation_protocol_counter_scratch_data()
        + crate::reference_packet::service::complete_restore::restoration_observe::restoration_observe_protocol_counter_scratch_data()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual assigned-envelope DATA fixture observations"
)]
mod tests;
