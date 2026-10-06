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

/// Parks the real configured pair and writers before the existing signer callback.
///
/// The signing key is a short callback argument and never a field of this owner.
/// An unfinished invocation aborts before any original resource field drops.
#[must_use = "retain the failed configured genesis invocation until termination"]
pub struct OriginalConfiguredProjectGenesisInvocationV3<'writers, 'profile> {
    journal: Option<&'writers mut Journal>,
    source: Option<&'writers mut ProtectedSourceDomainJournalOwnerV1>,
    input: &'writers ProvisionedControllerSourceGenesisInputV1,
    profile: &'profile ProductionControllerNormalRootProfileV1,
    controller: Option<Result<crate::hierarchy::controller_genesis::HeldControllerSourceGenesisV1<'writers>, ControllerSourceGenesisInputErrorV1>>,
    raw: Option<std::os::fd::OwnedFd>,
    adopted: Option<aos_sandbox_linux::unix_stream::RetainedUnixStream>,
    flight: Option<OriginalRootGenesisFlightV1<'profile>>,
    hello: Vec<u8>,
    hello_received: Option<Result<aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk, aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
    connection: Option<Result<(), SourceGenesisErrorV1>>,
    signatures: [Option<Result<[u8; super::controller_readback::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1], SourceGenesisErrorV1>>; 3],
    signature_posts: [Vec<Result<(), SourceGenesisErrorV1>>; 3],
    io: [super::flight::ProjectGenesisFlightIoV3; 8],
    append: crate::hierarchy::source_genesis::SourceProjectGenesisMutationV3,
    acknowledge: crate::hierarchy::source_genesis::SourceProjectGenesisMutationV3,
    floor_ack: crate::hierarchy::controller_genesis::ControllerProjectGenesisMutationV3,
    complete: crate::hierarchy::controller_genesis::ControllerProjectGenesisMutationV3,
    action: Option<Result<ObjectDigest, ControllerSourceGenesisInputErrorV1>>,
    signer_admission: Option<Result<(), std::io::Error>>,
    owner_posts: Vec<Result<(), SourceGenesisErrorV1>>,
    clock_posts: Vec<Result<(), SourceGenesisErrorV1>>,
    first_failure: Option<ConfiguredProjectGenesisSiteV3>,
    armed: bool,
}

#[derive(Clone, Copy)]
enum ConfiguredProjectGenesisSiteV3 {
    Action, Signer, Connection, Controller, Signature(usize), SignaturePost(usize, usize),
    Io(usize), Append, FloorAck, Acknowledge, Complete, OwnerPost(usize), ClockPost(usize),
}

/// Keeps the failed whole configured invocation resident through worker termination.
#[must_use = "the failed original configured genesis loan must terminate"]
pub struct FailedConfiguredProjectGenesisInvocationV3<'writers, 'profile> {
    original: OriginalConfiguredProjectGenesisInvocationV3<'writers, 'profile>,
}

impl<'writers, 'profile> OriginalConfiguredProjectGenesisInvocationV3<'writers, 'profile> {
    /// Parks the genuine executor Source field and Controller writer without effects.
    pub fn park(
        journal: &'writers mut Journal, source: &'writers mut ProtectedSourceDomainJournalOwnerV1,
        input: &'writers ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile ProductionControllerNormalRootProfileV1,
    ) -> Self {
        Self::park_inner(journal, Some(source), input, profile)
    }

    fn park_inner(
        journal: &'writers mut Journal, source: Option<&'writers mut ProtectedSourceDomainJournalOwnerV1>,
        input: &'writers ProvisionedControllerSourceGenesisInputV1,
        profile: &'profile ProductionControllerNormalRootProfileV1,
    ) -> Self {
        Self {
            journal: Some(journal), source, input, profile, controller: None,
            raw: None, adopted: None, flight: None, hello: Vec::new(), hello_received: None, connection: None,
            signatures: std::array::from_fn(|_| None), signature_posts: std::array::from_fn(|_| Vec::new()),
            io: std::array::from_fn(|_| super::flight::ProjectGenesisFlightIoV3::default()),
            append: crate::hierarchy::source_genesis::SourceProjectGenesisMutationV3::new(),
            acknowledge: crate::hierarchy::source_genesis::SourceProjectGenesisMutationV3::new(),
            floor_ack: crate::hierarchy::controller_genesis::ControllerProjectGenesisMutationV3::new(),
            complete: crate::hierarchy::controller_genesis::ControllerProjectGenesisMutationV3::new(),
            action: None, signer_admission: None, owner_posts: Vec::new(), clock_posts: Vec::new(),
            first_failure: None, armed: true,
        }
    }

    /// Runs once with the existing temporary Controller signer callback loan.
    pub fn run_with_signer(&mut self, generation: u64, signer: &SigningKey) {
        if self.action.is_some() || self.signer_admission.is_some() { return; }
        self.action = Some(self.run_steps(generation, signer));
        if self.action.as_ref().is_some_and(Result::is_err) && self.first_failure.is_none() {
            self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Action);
        }
        self.posts();
    }

    /// Parks actual fixed-signer admission failure without borrowing a dropped key.
    pub fn fail_signer_admission(&mut self, error: std::io::Error) {
        if self.signer_admission.is_some() { return; }
        self.signer_admission = Some(Err(error));
        if self.first_failure.is_none() { self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Signer); }
        self.posts();
    }

    fn posts(&mut self) {
        let controller = match &self.controller {
            Some(Ok(controller)) => controller.recheck(),
            _ => self.journal.as_deref().map_or(Ok(()), |journal| journal.ensure_healthy().map_err(SourceGenesisErrorV1::from)),
        };
        let index = self.owner_posts.len();
        self.owner_posts.push(controller);
        if self.first_failure.is_none() && self.owner_posts[index].is_err() { self.first_failure = Some(ConfiguredProjectGenesisSiteV3::OwnerPost(index)); }
        if let Some(source) = self.source.as_deref() {
            let index = self.owner_posts.len();
            self.owner_posts.push(source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from));
            if self.first_failure.is_none() && self.owner_posts[index].is_err() { self.first_failure = Some(ConfiguredProjectGenesisSiteV3::OwnerPost(index)); }
        }
        let index = self.owner_posts.len();
        self.owner_posts.push(self.input.recheck().map_err(|_| SourceGenesisErrorV1::Stale));
        if self.first_failure.is_none() && self.owner_posts[index].is_err() { self.first_failure = Some(ConfiguredProjectGenesisSiteV3::OwnerPost(index)); }
        if let Some(flight) = &self.flight {
            let index = self.owner_posts.len();
            self.owner_posts.push(if self.action.as_ref().is_some_and(Result::is_ok) {
                flight.original_terminal_clock().map(|_| ())
            } else { flight.first_successor_clock().map(|_| ()) });
            if self.first_failure.is_none() && self.owner_posts[index].is_err() { self.first_failure = Some(ConfiguredProjectGenesisSiteV3::OwnerPost(index)); }
            let index = self.clock_posts.len();
            self.clock_posts.push(flight.observe_first_successor_clock().map(|_| ()));
            if self.first_failure.is_none() && self.clock_posts[index].is_err() { self.first_failure = Some(ConfiguredProjectGenesisSiteV3::ClockPost(index)); }
        }
    }

    fn run_steps(&mut self, generation: u64, signer: &SigningKey) -> Result<ObjectDigest, ControllerSourceGenesisInputErrorV1> {
        self.input.recheck()?;
        let journal = self.journal.as_deref().ok_or(SourceGenesisErrorV1::Stale)?;
        let uid = journal.protected_owner_uid().map_err(SourceGenesisErrorV1::from)?;
        require_controller(journal, uid)?;
        self.source.as_deref().ok_or(SourceGenesisErrorV1::Stale)?.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from)?;
        // Seed/current-policy acceptance is independently authorized and fully
        // suffix-preflighted by the existing genuine input supplier. Retain
        // its whole Result before Root opens last; it makes no Root clock claim.
        let original_journal = self.journal.take().ok_or(SourceGenesisErrorV1::Stale)?;
        self.controller = Some(self.input.hold(original_journal));
        if self.controller.as_ref().is_some_and(Result::is_err) {
            self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Controller);
            return Err(SourceGenesisErrorV1::Stale.into());
        }
        self.connection = Some(OriginalRootGenesisFlightV1::connect_project_genesis_parked_v3(
            self.profile, &mut self.raw, &mut self.adopted, &mut self.flight, &mut self.hello, &mut self.hello_received, uid,
        ));
        if self.connection.as_ref().is_some_and(Result::is_err) {
            self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Connection);
            return Err(SourceGenesisErrorV1::Stale.into());
        }
        let flight = self.flight.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        let source = self.source.as_deref_mut().ok_or(SourceGenesisErrorV1::Stale)?;
        // Both genuine Source loans stay short and end before taking the
        // Controller phase owner or attempting Source mutation.
        {
            let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
            let observed = crate::hierarchy::source_genesis::observe_project_genesis_v3(&inventory, flight.first_successor_source_uid()?, self.input.project())?;
            observed.recheck()?;
            flight.first_successor_clock()?;
        }
        let controller = self.controller.as_mut().and_then(|result| result.as_mut().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        {
            let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
            let observed = crate::hierarchy::source_genesis::observe_project_genesis_v3(&inventory, flight.first_successor_source_uid()?, self.input.project())?;
            if let Err(site) = super::controller_readback::capture_project_genesis_readback_v3(controller, &observed, generation, signer, flight, false, &mut self.signatures[0], &mut self.signature_posts[0]) {
                self.first_failure = Some(signature_failure_site_v3(0, site));
                return Err(SourceGenesisErrorV1::Stale.into());
            }
        }
        let packet = self.signatures[0].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        if flight.send_project_genesis_phase_v3(Phase::Prepare, packet, &mut self.io[0]).is_err() {
            self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Io(0)); return Err(SourceGenesisErrorV1::Stale.into());
        }
        let phase = match flight.receive_project_genesis_phase_v3(&[Phase::Prepared, Phase::Anchored], &mut self.io[1]) {
            Ok(phase) => phase,
            Err(()) => { self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Io(1)); return Err(SourceGenesisErrorV1::Stale.into()); }
        };
        let reply = flight.project_genesis_reply_from_received_v3(controller, phase, &self.io[1].payload)?;
        let floor = match reply {
            super::flight::OriginalRootProjectGenesisReplyV3::Prepared(intent) => {
                if crate::hierarchy::source_genesis::append_source_project_genesis_v3(source, controller, &intent, &mut self.append).is_err() {
                    self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Append); return Err(SourceGenesisErrorV1::Stale.into());
                }
                {
                    let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
                    let observed = crate::hierarchy::source_genesis::observe_project_genesis_v3(&inventory, flight.first_successor_source_uid()?, self.input.project())?;
                    if let Err(site) = super::controller_readback::capture_project_genesis_readback_v3(controller, &observed, generation, signer, flight, false, &mut self.signatures[1], &mut self.signature_posts[1]) {
                        self.first_failure = Some(signature_failure_site_v3(1, site)); return Err(SourceGenesisErrorV1::Stale.into());
                    }
                }
                let packet = self.signatures[1].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
                if flight.send_project_genesis_phase_v3(Phase::Anchor, packet, &mut self.io[2]).is_err() {
                    self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Io(2)); return Err(SourceGenesisErrorV1::Stale.into());
                }
                if flight.receive_project_genesis_phase_v3(&[Phase::Anchored], &mut self.io[3]).is_err() {
                    self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Io(3)); return Err(SourceGenesisErrorV1::Stale.into());
                }
                flight.project_genesis_floor_from_received_v3(controller, &self.io[3].payload)?
            }
            super::flight::OriginalRootProjectGenesisReplyV3::Anchored(floor) => floor,
        };
        {
            let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
            let observed = crate::hierarchy::source_genesis::observe_project_genesis_v3(&inventory, floor.source_uid(), self.input.project())?;
            if controller.settle_project_genesis_v3(&observed, &floor, false, &mut self.floor_ack).is_err() {
                self.first_failure = Some(ConfiguredProjectGenesisSiteV3::FloorAck); return Err(SourceGenesisErrorV1::Stale.into());
            }
        }
        if crate::hierarchy::source_genesis::acknowledge_source_project_genesis_v3(source, controller, &floor, &mut self.acknowledge).is_err() {
            self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Acknowledge); return Err(SourceGenesisErrorV1::Stale.into());
        }
        {
            let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
            let observed = crate::hierarchy::source_genesis::observe_project_genesis_v3(&inventory, floor.source_uid(), self.input.project())?;
            if controller.settle_project_genesis_v3(&observed, &floor, true, &mut self.complete).is_err() {
                self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Complete); return Err(SourceGenesisErrorV1::Stale.into());
            }
            if let Err(site) = super::controller_readback::capture_project_genesis_readback_v3(controller, &observed, generation, signer, flight, true, &mut self.signatures[2], &mut self.signature_posts[2]) {
                self.first_failure = Some(signature_failure_site_v3(2, site)); return Err(SourceGenesisErrorV1::Stale.into());
            }
        }
        let packet = self.signatures[2].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        if flight.send_project_genesis_phase_v3(Phase::Complete, packet, &mut self.io[4]).is_err() {
            self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Io(4)); return Err(SourceGenesisErrorV1::Stale.into());
        }
        if flight.receive_project_genesis_phase_v3(&[Phase::Completed], &mut self.io[5]).is_err() {
            self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Io(5)); return Err(SourceGenesisErrorV1::Stale.into());
        }
        let completed = flight.completed_project_genesis_from_received_v3(&floor, &self.io[5].payload)?;
        {
            let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
            let observed = crate::hierarchy::source_genesis::observe_project_genesis_v3(&inventory, completed.source_uid(), self.input.project())?;
            super::super::public_create_source::consume_completed_project_genesis_ancestry_v3(controller, &observed, &inventory, &completed)?;
        }
        if flight.send_project_genesis_phase_v3(Phase::Finish, completed.floor().digest().as_bytes(), &mut self.io[6]).is_err() {
            self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Io(6)); return Err(SourceGenesisErrorV1::Stale.into());
        }
        if flight.receive_project_genesis_phase_v3(&[Phase::Finish], &mut self.io[7]).is_err() {
            self.first_failure = Some(ConfiguredProjectGenesisSiteV3::Io(7)); return Err(SourceGenesisErrorV1::Stale.into());
        }
        if self.io[7].payload != completed.floor().digest().as_bytes() { return Err(SourceGenesisErrorV1::Conflict.into()); }
        self.input.recheck()?;
        Ok(floor.floor().digest())
    }

    /// Returns success or the whole resident failed original without a local drop.
    pub fn into_outcome(mut self) -> Result<ObjectDigest, FailedConfiguredProjectGenesisInvocationV3<'writers, 'profile>> {
        if self.first_failure.is_none() {
            if let Some(Ok(digest)) = &self.action { let digest = *digest; self.armed = false; return Ok(digest); }
        }
        Err(FailedConfiguredProjectGenesisInvocationV3 { original: self })
    }
}

fn signature_failure_site_v3(
    index: usize, site: super::controller_readback::ProjectGenesisSignatureFailureV3,
) -> ConfiguredProjectGenesisSiteV3 {
    match site {
        super::controller_readback::ProjectGenesisSignatureFailureV3::Signature => ConfiguredProjectGenesisSiteV3::Signature(index),
        super::controller_readback::ProjectGenesisSignatureFailureV3::Post(post) => ConfiguredProjectGenesisSiteV3::SignaturePost(index, post),
        super::controller_readback::ProjectGenesisSignatureFailureV3::Refused => ConfiguredProjectGenesisSiteV3::Action,
    }
}

impl FailedConfiguredProjectGenesisInvocationV3<'_, '_> {
    /// Borrows the exact first resident cause without observations or clones.
    pub fn first_cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let original = &self.original;
        match original.first_failure? {
            ConfiguredProjectGenesisSiteV3::Action => original.action.as_ref()?.as_ref().err().map(|e| e as _),
            ConfiguredProjectGenesisSiteV3::Signer => original.signer_admission.as_ref()?.as_ref().err().map(|e| e as _),
            ConfiguredProjectGenesisSiteV3::Connection => original.hello_received.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _)
                .or_else(|| original.connection.as_ref()?.as_ref().err().map(|e| e as _)),
            ConfiguredProjectGenesisSiteV3::Controller => original.controller.as_ref()?.as_ref().err().map(|e| e as _),
            ConfiguredProjectGenesisSiteV3::Signature(index) => original.signatures.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
            ConfiguredProjectGenesisSiteV3::SignaturePost(index, post) => original.signature_posts.get(index)?.get(post)?.as_ref().err().map(|e| e as _),
            ConfiguredProjectGenesisSiteV3::Io(index) => original.io.get(index)?.error(),
            ConfiguredProjectGenesisSiteV3::Append => original.append.error(),
            ConfiguredProjectGenesisSiteV3::FloorAck => original.floor_ack.error(),
            ConfiguredProjectGenesisSiteV3::Acknowledge => original.acknowledge.error(),
            ConfiguredProjectGenesisSiteV3::Complete => original.complete.error(),
            ConfiguredProjectGenesisSiteV3::OwnerPost(index) => original.owner_posts.get(index)?.as_ref().err().map(|e| e as _),
            ConfiguredProjectGenesisSiteV3::ClockPost(index) => original.clock_posts.get(index)?.as_ref().err().map(|e| e as _),
        }
    }
}

impl Drop for OriginalConfiguredProjectGenesisInvocationV3<'_, '_> {
    fn drop(&mut self) { if self.armed { std::process::abort(); } }
}

pub(crate) fn unavailable_project_genesis_v3<'writers, 'profile>(
    journal: &'writers mut Journal, input: &'writers ProvisionedControllerSourceGenesisInputV1,
    profile: &'profile ProductionControllerNormalRootProfileV1,
) -> FailedConfiguredProjectGenesisInvocationV3<'writers, 'profile> {
    let mut original = OriginalConfiguredProjectGenesisInvocationV3::park_inner(journal, None, input, profile);
    original.action = Some(Err(SourceGenesisErrorV1::AdmissionClosed.into()));
    original.first_failure = Some(ConfiguredProjectGenesisSiteV3::Action);
    FailedConfiguredProjectGenesisInvocationV3 { original }
}

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
