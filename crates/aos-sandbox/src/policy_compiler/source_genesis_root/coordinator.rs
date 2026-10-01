//! Actual gen1 genesis completion under Controller, Source and original Root.
//!
//! The fixed administrative credential pair selects an attempt. Real named
//! writers, independently selected Root code/policy and per-fragment original
//! peer custody authorize each phase. Root opens last and remains held through
//! Controller floor ACK, Source ACK, Controller Complete and Root Finish.
//! Failure drops that stream without guessing which durable suffix committed;
//! restart rejoins the same retained input and owner records, never a fresh seed.

use aos_sandbox_core::ObjectDigest;
use ed25519_dalek::SigningKey;

use crate::Journal;
use crate::hierarchy::controller_genesis::require_controller;
use crate::hierarchy::controller_genesis_input::{
    ControllerSourceGenesisInputErrorV1, ProvisionedControllerSourceGenesisInputV1,
};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::hierarchy::protected_journal::retained_tree_inventory_data_v1;
use crate::hierarchy::source_genesis::{
    acknowledge_source_tree_genesis_v1, append_source_tree_genesis_v1,
    observe_retained_source_genesis_v1, observe_source_genesis_attempt_v1,
};
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::normal_root::ProductionControllerNormalRootProfileV1;

use super::controller_readback::{
    sign_controller_source_genesis_completion_readback_v1,
    sign_controller_source_genesis_readback_v1,
};
use super::flight::{OriginalRootGenesisFlightV1, OriginalRootGenesisReplyV1};
use super::wire::RootSourceGenesisFrameKindV1 as Phase;

/// Completes a genuinely provisioned initial Source genesis on one Root flight.
///
/// The production executor supplies its retained Source owner and the existing
/// Controller-purpose credential signer. Neither supplied signatures nor the
/// returned completion digest grant ancestry or a live Root read. Only the
/// private flight can construct the borrowed intent/floor consumed here.
/// Later semantic generations deliberately lack an admission producer.
///
/// # Errors
///
/// Rejects changed original credentials, unsafe named writers, stale selected
/// image/policy or Root peer, unavailable current admission for fresh appends,
/// conflicting historical attempts, exhausted reserved suffixes, or any lost,
/// malformed, late or ambiguous phase. Partial durable progress remains fenced
/// for exact restart recovery; success requires the final original-stream ACK.
pub fn coordinate_provisioned_source_genesis_v1(
    journal: &mut Journal,
    source: &mut ProtectedSourceDomainJournalOwnerV1,
    input: &ProvisionedControllerSourceGenesisInputV1,
    profile: &ProductionControllerNormalRootProfileV1,
    signer_generation: u64,
    signer: &SigningKey,
) -> Result<ObjectDigest, ControllerSourceGenesisInputErrorV1> {
    input.recheck()?;
    let uid = journal
        .protected_owner_uid()
        .map_err(SourceGenesisErrorV1::from)?;
    require_controller(journal, uid)?;
    source
        .require_fixed_named_writer_v1()
        .map_err(SourceGenesisErrorV1::from)?;

    // Both enclosing writers are retained before Root opens last. No epoch,
    // acceptance or Source mutation occurs before independent original-peer
    // admission. The flight's deadline starts before connecting, not at ACK.
    let flight = OriginalRootGenesisFlightV1::connect(profile)?;
    let original = observe_source_genesis_attempt_v1(source, uid, input.project())?;
    // Source replay may outlive the admitted peer or original deadline. Check
    // that same flight again before authorization retention or acceptance.
    flight.recheck()?;
    let mut controller = input.hold(journal)?;
    let prepare = sign_controller_source_genesis_readback_v1(
        &controller,
        &original,
        flight.nonce(),
        signer_generation,
        signer,
    )?;
    flight.send_phase(Phase::Prepare, &prepare)?;
    let reply = flight.receive_reply(&controller)?;
    drop(original);

    let floor = match reply {
        OriginalRootGenesisReplyV1::Prepared(intent) => {
            // Historical Prepared retains Root's original durable intent
            // nonce. A new flight nonce only correlates this transport; it
            // must never regenerate the immutable Source attempt identity.
            let prepared = append_source_tree_genesis_v1(source, &controller, &intent)?;
            let anchor = sign_controller_source_genesis_readback_v1(
                &controller,
                &prepared,
                flight.nonce(),
                signer_generation,
                signer,
            )?;
            flight.send_phase(Phase::Anchor, &anchor)?;
            let floor = flight.receive_floor(&controller)?;
            drop(prepared);
            floor
        }
        OriginalRootGenesisReplyV1::Anchored(floor) => floor,
    };

    controller.accept_root_floor_v1(&floor)?;
    let acknowledged = acknowledge_source_tree_genesis_v1(source, &controller, &floor)?;
    controller.complete_source_ack_v1(&acknowledged, &floor)?;
    let complete = sign_controller_source_genesis_completion_readback_v1(
        &controller,
        &acknowledged,
        flight.nonce(),
        signer_generation,
        signer,
    )?;
    flight.send_phase(Phase::Complete, &complete)?;
    let completed = flight.receive_completed(&floor)?;
    drop(acknowledged);

    // Root still retains its current floor on this original Completed flight.
    // Reborrow the same Source writer for complete inventory and actual ACK
    // readback; the private ancestry loan cannot outlive this window.
    {
        let inventory =
            retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
        let acknowledged = observe_retained_source_genesis_v1(
            &inventory,
            completed.source_uid(),
            input.project(),
        )?;
        super::super::public_create_source::consume_completed_gen1_ancestry_v1(
            &controller,
            &acknowledged,
            &inventory,
            &completed,
        )?;
    }

    flight.finish(completed)?;
    input.recheck()?;
    Ok(floor.floor().digest())
}
