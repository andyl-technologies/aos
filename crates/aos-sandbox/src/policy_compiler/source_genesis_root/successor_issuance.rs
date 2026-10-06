//! Resident issuance on the original completed generation-one Root flight.
//!
//! The state borrows the actual Controller and Source writers, selected
//! profile and parked credential owner. Its raw/adopted/validated descriptions
//! remain resident across every failed crossing. Only this implementation can
//! mark success, after exact durable delivery and SAME-flight Finish.

use std::os::fd::OwnedFd;

use aos_sandbox_core::{DesiredGeneration, RawPairedClockSample};
use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use ed25519_dalek::SigningKey;

use crate::Journal;
use crate::hierarchy::codec::tree_commitment_v1;
use crate::hierarchy::controller_genesis::{
    HeldControllerSourceGenesisV1, hold_existing_completed_source_genesis_v2,
};
use crate::hierarchy::genesis_profile::{SourceGenesisErrorV1, take};
use crate::hierarchy::model::SandboxTreeRecordV1;
use crate::hierarchy::protected_journal::{
    RetainedTreeInventoryDataV1, retained_tree_inventory_data_v1,
};
use crate::hierarchy::source_genesis::observe_retained_source_genesis_v1;
use crate::hierarchy::source_successor::{
    BODY_BYTES, SourceSuccessorApprovalDataV2, SourceSuccessorIntentDataV2,
};
use crate::journal::controller_source_successor_issuance::PublicationCustodyV2;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::normal_root::{
    ProductionControllerNormalRootProfileV1, SourceSuccessorCredentialCustodyV2,
    SourceSuccessorCredentialErrorV2,
};

use super::controller_readback::{
    sign_controller_source_genesis_completion_readback_v1,
    sign_controller_source_genesis_readback_v1,
};
use super::flight::{
    CompletedRootSourceGenesisFloorV1, OriginalRootGenesisFlightV1, OriginalRootGenesisReplyV1,
    CompletedRootSourceProjectGenesisFloorV3,
};
use super::wire::RootSourceGenesisFrameKindV1 as WirePhase;

/// Identifies the first failed original issuance boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceSuccessorIssuancePhaseV2 {
    /// Genuine credential/Controller signer admission has not completed.
    Admission,
    /// The original Root connection or its received completion failed.
    Root,
    /// Actual current context derivation or immutable saved replay failed.
    Derivation,
    /// Complete native preflight or atomic Controller retention failed.
    Retention,
    /// Fixed no-replace publication or exact delivery readback failed.
    Delivery,
    /// Final current checks or SAME-flight Finish failed.
    Finish,
    /// An armed attempt unwound or was abandoned.
    Abandoned,
}

#[derive(Debug, thiserror::Error)]
enum IssuerCause {
    #[error(transparent)]
    Owner(#[from] SourceGenesisErrorV1),
    #[error(transparent)]
    Credential(#[from] SourceSuccessorCredentialErrorV2),
}

/// Parks a new project issuer only after the configured genesis flight ended.
///
/// Its credentials and Root connection are fresh originals. The completed
/// genesis DATA returned by that earlier flight is deliberately not an input.
#[must_use = "retain the project issuer through exact Finish or termination"]
pub struct OriginalSourceProjectSuccessorInvocationV3<'writers, 'profile, 'credentials> {
    journal: Option<&'writers mut Journal>,
    source: Option<&'writers mut ProtectedSourceDomainJournalOwnerV1>,
    profile: &'profile ProductionControllerNormalRootProfileV1,
    credentials: &'credentials mut SourceSuccessorCredentialCustodyV2<'profile>,
    controller: Option<Result<HeldControllerSourceGenesisV1<'writers>, SourceGenesisErrorV1>>,
    raw: Option<OwnedFd>,
    adopted: Option<RetainedUnixStream>,
    flight: Option<OriginalRootGenesisFlightV1<'profile>>,
    hello: Vec<u8>,
    hello_received: Option<Result<aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk, aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
    connection: Option<Result<(), SourceGenesisErrorV1>>,
    signatures: [Option<Result<[u8; super::controller_readback::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1], SourceGenesisErrorV1>>; 2],
    signature_posts: [Vec<Result<(), SourceGenesisErrorV1>>; 2],
    io: [super::flight::ProjectGenesisFlightIoV3; 6],
    signing: Option<Result<SourceSuccessorApprovalDataV2, SourceSuccessorCredentialErrorV2>>,
    contexts: [Option<Result<(), IssuerCause>>; 4],
    stages: [Option<Result<(), IssuerCause>>; 4],
    saved: crate::hierarchy::controller_genesis::ControllerProjectIssuanceMutationV3,
    delivered: crate::hierarchy::controller_genesis::ControllerProjectIssuanceMutationV3,
    publication: PublicationCustodyV2,
    action: Option<Result<SourceSuccessorApprovalDataV2, IssuerCause>>,
    signer_admission: Option<Result<(), std::io::Error>>,
    posts: Vec<Result<(), SourceGenesisErrorV1>>,
    credential_posts: Vec<Result<(), SourceSuccessorCredentialErrorV2>>,
    first_failure: Option<ProjectIssuerSiteV3>,
    armed: bool,
}

#[derive(Clone, Copy)]
enum ProjectIssuerSiteV3 {
    Action, Controller, Connection, Signature(usize), SignaturePost(usize, usize), Io(usize),
    Signing, Context(usize), Stage(usize), Saved, Delivered, OwnerPost(usize), CredentialPost(usize), Signer,
}

/// Retains every failed project issuer original until deliberate termination.
#[must_use = "the failed project issuer must terminate without releasing originals"]
pub struct FailedSourceProjectSuccessorInvocationV3<'writers, 'profile, 'credentials> {
    original: OriginalSourceProjectSuccessorInvocationV3<'writers, 'profile, 'credentials>,
}

impl<'writers, 'profile, 'credentials> OriginalSourceProjectSuccessorInvocationV3<'writers, 'profile, 'credentials> {
    /// Parks the actual executor writers, new credentials and selected profile.
    pub fn park(
        journal: &'writers mut Journal, source: &'writers mut ProtectedSourceDomainJournalOwnerV1,
        profile: &'profile ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Self {
        Self::park_inner(journal, Some(source), profile, credentials)
    }

    fn park_inner(
        journal: &'writers mut Journal, source: Option<&'writers mut ProtectedSourceDomainJournalOwnerV1>,
        profile: &'profile ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Self {
        Self {
            journal: Some(journal), source, profile, credentials, controller: None,
            raw: None, adopted: None, flight: None, hello: Vec::new(), hello_received: None, connection: None,
            signatures: std::array::from_fn(|_| None), signature_posts: std::array::from_fn(|_| Vec::new()),
            io: std::array::from_fn(|_| super::flight::ProjectGenesisFlightIoV3::default()),
            signing: None, contexts: std::array::from_fn(|_| None), stages: std::array::from_fn(|_| None),
            saved: crate::hierarchy::controller_genesis::ControllerProjectIssuanceMutationV3::new(),
            delivered: crate::hierarchy::controller_genesis::ControllerProjectIssuanceMutationV3::new(),
            publication: PublicationCustodyV2::new(), action: None, signer_admission: None,
            posts: Vec::new(), credential_posts: Vec::new(), first_failure: None, armed: true,
        }
    }

    /// Runs once inside the unchanged fixed Controller signer callback.
    pub fn run_with_controller_signer(&mut self, generation: u64, signer: &SigningKey) {
        if self.action.is_some() || self.signer_admission.is_some() { return; }
        self.action = Some(self.run_steps(generation, signer));
        if self.action.as_ref().is_some_and(Result::is_err) && self.first_failure.is_none() {
            self.first_failure = Some(ProjectIssuerSiteV3::Action);
        }
        self.final_posts();
    }

    /// Parks the fixed signer's real admission error on the prearmed owner.
    pub fn fail_controller_signer_admission(&mut self, cause: std::io::Error) {
        if self.signer_admission.is_some() { return; }
        self.signer_admission = Some(Err(cause));
        if self.first_failure.is_none() { self.first_failure = Some(ProjectIssuerSiteV3::Signer); }
        self.final_posts();
    }

    fn final_posts(&mut self) {
        if let Some(source) = self.source.as_deref() {
            let index = self.posts.len();
            self.posts.push(source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from));
            if self.posts[index].is_err() && self.first_failure.is_none() { self.first_failure = Some(ProjectIssuerSiteV3::OwnerPost(index)); }
        }
        if let Some(Ok(controller)) = &self.controller {
            let index = self.posts.len();
            self.posts.push(controller.recheck());
            if self.posts[index].is_err() && self.first_failure.is_none() { self.first_failure = Some(ProjectIssuerSiteV3::OwnerPost(index)); }
        }
        let index = self.credential_posts.len();
        self.credential_posts.push(self.credentials.recheck());
        if self.credential_posts[index].is_err() && self.first_failure.is_none() { self.first_failure = Some(ProjectIssuerSiteV3::CredentialPost(index)); }
        if let Some(flight) = &self.flight {
            let index = self.posts.len();
            self.posts.push(if self.action.as_ref().is_some_and(Result::is_ok) {
                flight.original_terminal_clock().map(|_| ())
            } else { flight.first_successor_clock().map(|_| ()) });
            if self.posts[index].is_err() && self.first_failure.is_none() { self.first_failure = Some(ProjectIssuerSiteV3::OwnerPost(index)); }
            let index = self.posts.len();
            self.posts.push(flight.observe_first_successor_clock().map(|_| ()));
            if self.posts[index].is_err() && self.first_failure.is_none() { self.first_failure = Some(ProjectIssuerSiteV3::OwnerPost(index)); }
        }
    }

    fn run_steps(&mut self, generation: u64, signer: &SigningKey) -> Result<SourceSuccessorApprovalDataV2, IssuerCause> {
        self.credentials.recheck()?;
        let intent = self.credentials.intent()?;
        let project = intent.project();
        let journal = self.journal.as_deref().ok_or(SourceGenesisErrorV1::Stale)?;
        let uid = journal.protected_owner_uid().map_err(SourceGenesisErrorV1::from)?;
        journal.require_git_coverage_new_admission_v1().map_err(SourceGenesisErrorV1::from)?;
        let journal = self.journal.take().ok_or(SourceGenesisErrorV1::Stale)?;
        self.controller = Some(hold_existing_completed_source_genesis_v2(journal, project));
        if self.controller.as_ref().is_some_and(Result::is_err) {
            self.first_failure = Some(ProjectIssuerSiteV3::Controller); return Err(SourceGenesisErrorV1::Stale.into());
        }
        let controller = self.controller.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        let source = self.source.as_deref_mut().ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
        source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from)?;
        {
            let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
            let source_uid = inventory.journal().protected_owner_uid().map_err(SourceGenesisErrorV1::from)?;
            let observed = crate::hierarchy::source_genesis::observe_project_genesis_v3(&inventory, source_uid, project)?;
            controller.recheck_completed_project_genesis_v3(&observed)?;
        }
        // This is a NEW Root-last flight after genesis Finish and fresh issuer
        // credential park. No earlier completed proof or deadline is accepted.
        self.connection = Some(OriginalRootGenesisFlightV1::connect_project_genesis_parked_v3(
            self.profile, &mut self.raw, &mut self.adopted, &mut self.flight, &mut self.hello, &mut self.hello_received, uid,
        ));
        if self.connection.as_ref().is_some_and(Result::is_err) {
            self.first_failure = Some(ProjectIssuerSiteV3::Connection); return Err(SourceGenesisErrorV1::Stale.into());
        }
        let flight = self.flight.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
        let observed = crate::hierarchy::source_genesis::observe_project_genesis_v3(&inventory, flight.first_successor_source_uid()?, project)?;
        for (index, complete) in [false, true].into_iter().enumerate() {
            if let Err(site) = super::controller_readback::capture_project_genesis_readback_v3(controller, &observed, generation, signer, flight, complete, &mut self.signatures[index], &mut self.signature_posts[index]) {
                self.first_failure = Some(project_issuer_signature_site(index, site));
                return Err(SourceGenesisErrorV1::Stale.into());
            }
            let packet = self.signatures[index].as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
            let phase = if complete { WirePhase::Complete } else { WirePhase::Prepare };
            if flight.send_project_genesis_phase_v3(phase, packet, &mut self.io[index * 2]).is_err() {
                self.first_failure = Some(ProjectIssuerSiteV3::Io(index * 2)); return Err(SourceGenesisErrorV1::Stale.into());
            }
            let expected = if complete { WirePhase::Completed } else { WirePhase::Anchored };
            if flight.receive_project_genesis_phase_v3(&[expected], &mut self.io[index * 2 + 1]).is_err() {
                self.first_failure = Some(ProjectIssuerSiteV3::Io(index * 2 + 1)); return Err(SourceGenesisErrorV1::Stale.into());
            }
        }
        let floor = flight.project_genesis_floor_from_received_v3(controller, &self.io[1].payload)?;
        let completed = flight.completed_project_genesis_from_received_v3(&floor, &self.io[3].payload)?;
        super::super::public_create_source::consume_completed_project_genesis_ancestry_v3(controller, &observed, &inventory, &completed)?;
        let issuer_generation = self.credentials.issuer_generation()?;
        let clock = completed.signing_boundary_clock()?;
        let body = derive_body_with_completed(controller, &inventory, CompletedGenesisRecipeV3::ProjectV3(&completed), intent, issuer_generation, clock)?;
        self.signing = Some(match controller.retained_project_successor_approval_v3()? {
            Some(packet) => {
                (|| {
                    self.credentials.verify_saved(&packet)?;
                    require_saved_context(&packet, &body, clock)?;
                    Ok(packet)
                })()
            }
            None => {
                let cut = SourceSuccessorSigningCutV3 { controller, inventory: &inventory, completed: &completed };
                self.credentials.sign_project_approval_v3(&body, &cut)
            }
        });
        if self.signing.as_ref().is_some_and(Result::is_err) {
            self.first_failure.get_or_insert(ProjectIssuerSiteV3::Signing);
        }
        // Park the genuine signing/replay Result before observing every still
        // available owner, original floor and credential independently.
        project_issuer_posts(controller, &observed, &completed, self.credentials, &mut self.posts, &mut self.credential_posts, &mut self.first_failure);
        if self.first_failure.is_some() { return Err(SourceGenesisErrorV1::Stale.into()); }
        let packet = self.signing.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(SourceGenesisErrorV1::Stale)?.clone();
        for index in 0..4 {
            self.contexts[index] = Some(recheck_project_issuer_context(controller, &inventory, &completed, self.credentials, &packet));
            if self.contexts[index].as_ref().is_some_and(Result::is_err) { self.first_failure.get_or_insert(ProjectIssuerSiteV3::Context(index)); }
            project_issuer_posts(controller, &observed, &completed, self.credentials, &mut self.posts, &mut self.credential_posts, &mut self.first_failure);
            if self.first_failure.is_some() { return Err(SourceGenesisErrorV1::Stale.into()); }
            match index {
                0 => {
                    if controller.retain_project_successor_issuance_v3(&packet, &observed, &completed, crate::journal::controller_source_successor_issuance::Transition::ProjectSave(project), &mut self.saved).is_err() {
                        self.first_failure = Some(ProjectIssuerSiteV3::Saved);
                    }
                }
                1 => {
                    self.stages[index] = Some(controller.publish_project_successor_issuance_v3(&packet, &mut self.publication).map_err(Into::into));
                    if self.stages[index].as_ref().is_some_and(Result::is_err) { self.first_failure = Some(ProjectIssuerSiteV3::Stage(index)); }
                }
                2 => {
                    if controller.retain_project_successor_issuance_v3(&packet, &observed, &completed, crate::journal::controller_source_successor_issuance::Transition::ProjectDelivered(project), &mut self.delivered).is_err() {
                        self.first_failure = Some(ProjectIssuerSiteV3::Delivered);
                    }
                }
                _ => {
                    self.stages[index] = Some(controller.recheck_project_successor_publication_v3(&packet, &mut self.publication).map_err(Into::into));
                    if self.stages[index].as_ref().is_some_and(Result::is_err) { self.first_failure = Some(ProjectIssuerSiteV3::Stage(index)); }
                }
            }
            project_issuer_posts(controller, &observed, &completed, self.credentials, &mut self.posts, &mut self.credential_posts, &mut self.first_failure);
            if self.first_failure.is_some() { return Err(SourceGenesisErrorV1::Stale.into()); }
        }
        if flight.send_project_genesis_phase_v3(WirePhase::Finish, completed.floor().digest().as_bytes(), &mut self.io[4]).is_err() {
            self.first_failure = Some(ProjectIssuerSiteV3::Io(4)); return Err(SourceGenesisErrorV1::Stale.into());
        }
        if flight.receive_project_genesis_phase_v3(&[WirePhase::Finish], &mut self.io[5]).is_err() {
            self.first_failure = Some(ProjectIssuerSiteV3::Io(5)); return Err(SourceGenesisErrorV1::Stale.into());
        }
        if self.io[5].payload != completed.floor().digest().as_bytes() { return Err(SourceGenesisErrorV1::Conflict.into()); }
        Ok(packet)
    }

    /// Returns completed approval DATA or the whole resident failed owner.
    ///
    /// # Errors
    /// Retains every incomplete flight, original writer and negative result.
    pub fn into_outcome(mut self) -> Result<SourceSuccessorApprovalDataV2, FailedSourceProjectSuccessorInvocationV3<'writers, 'profile, 'credentials>> {
        if self.first_failure.is_none() {
            if let Some(Ok(packet)) = &self.action { let packet = packet.clone(); self.armed = false; return Ok(packet); }
        }
        Err(FailedSourceProjectSuccessorInvocationV3 { original: self })
    }
}

fn recheck_project_issuer_context(
    controller: &HeldControllerSourceGenesisV1<'_>, inventory: &RetainedTreeInventoryDataV1<'_>,
    completed: &CompletedRootSourceProjectGenesisFloorV3<'_, '_>, credentials: &mut SourceSuccessorCredentialCustodyV2<'_>,
    packet: &SourceSuccessorApprovalDataV2,
) -> Result<(), IssuerCause> {
    credentials.recheck()?;
    let clock = completed.signing_boundary_clock()?;
    let body = derive_body_with_completed(controller, inventory, CompletedGenesisRecipeV3::ProjectV3(completed), credentials.intent()?, credentials.issuer_generation()?, clock)?;
    require_saved_context(packet, &body, clock)?;
    credentials.verify_saved(packet)?;
    completed.recheck().map_err(Into::into)
}

fn project_issuer_posts(
    controller: &HeldControllerSourceGenesisV1<'_>, source: &crate::hierarchy::source_genesis::HeldSourceProjectGenesisObservationV3<'_>,
    completed: &CompletedRootSourceProjectGenesisFloorV3<'_, '_>, credentials: &mut SourceSuccessorCredentialCustodyV2<'_>,
    posts: &mut Vec<Result<(), SourceGenesisErrorV1>>, credential_posts: &mut Vec<Result<(), SourceSuccessorCredentialErrorV2>>,
    first: &mut Option<ProjectIssuerSiteV3>,
) {
    park_project_issuer_post(posts, first, controller.recheck());
    park_project_issuer_post(posts, first, source.recheck());
    park_project_issuer_post(posts, first, completed.recheck());
    park_project_issuer_post(posts, first, completed.signing_boundary_clock().map(|_| ()));
    let index = credential_posts.len(); credential_posts.push(credentials.recheck());
    if credential_posts[index].is_err() && first.is_none() { *first = Some(ProjectIssuerSiteV3::CredentialPost(index)); }
}

fn park_project_issuer_post(
    posts: &mut Vec<Result<(), SourceGenesisErrorV1>>, first: &mut Option<ProjectIssuerSiteV3>,
    result: Result<(), SourceGenesisErrorV1>,
) {
    let index = posts.len(); posts.push(result);
    if posts[index].is_err() && first.is_none() { *first = Some(ProjectIssuerSiteV3::OwnerPost(index)); }
}

fn project_issuer_signature_site(
    index: usize, site: super::controller_readback::ProjectGenesisSignatureFailureV3,
) -> ProjectIssuerSiteV3 {
    match site {
        super::controller_readback::ProjectGenesisSignatureFailureV3::Signature => ProjectIssuerSiteV3::Signature(index),
        super::controller_readback::ProjectGenesisSignatureFailureV3::Post(post) => ProjectIssuerSiteV3::SignaturePost(index, post),
        super::controller_readback::ProjectGenesisSignatureFailureV3::Refused => ProjectIssuerSiteV3::Action,
    }
}

impl FailedSourceProjectSuccessorInvocationV3<'_, '_, '_> {
    /// Borrows the same resident chronological cause without new observations.
    pub fn first_cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let original = &self.original;
        match original.first_failure? {
            ProjectIssuerSiteV3::Action => original.action.as_ref()?.as_ref().err().map(|e| e as _),
            ProjectIssuerSiteV3::Controller => original.controller.as_ref()?.as_ref().err().map(|e| e as _),
            ProjectIssuerSiteV3::Connection => original.hello_received.as_ref().and_then(|r| r.as_ref().err()).map(|e| e as _)
                .or_else(|| original.connection.as_ref()?.as_ref().err().map(|e| e as _)),
            ProjectIssuerSiteV3::Signature(index) => original.signatures.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
            ProjectIssuerSiteV3::SignaturePost(index, post) => original.signature_posts.get(index)?.get(post)?.as_ref().err().map(|e| e as _),
            ProjectIssuerSiteV3::Io(index) => original.io.get(index)?.error(),
            ProjectIssuerSiteV3::Signing => original.signing.as_ref()?.as_ref().err().map(|e| e as _),
            ProjectIssuerSiteV3::Context(index) => original.contexts.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
            ProjectIssuerSiteV3::Stage(index) => original.stages.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
            ProjectIssuerSiteV3::Saved => original.saved.error(), ProjectIssuerSiteV3::Delivered => original.delivered.error(),
            ProjectIssuerSiteV3::OwnerPost(index) => original.posts.get(index)?.as_ref().err().map(|e| e as _),
            ProjectIssuerSiteV3::CredentialPost(index) => original.credential_posts.get(index)?.as_ref().err().map(|e| e as _),
            ProjectIssuerSiteV3::Signer => original.signer_admission.as_ref()?.as_ref().err().map(|e| e as _),
        }
    }

    /// Terminates while every original borrower and negative result is resident.
    pub fn terminate_failed(self) -> ! { std::process::exit(1) }
}

impl Drop for OriginalSourceProjectSuccessorInvocationV3<'_, '_, '_> {
    fn drop(&mut self) { if self.armed { self.credentials.end_failed(); std::process::abort(); } }
}

pub(crate) fn unavailable_project_issuer_v3<'writers, 'profile, 'credentials>(
    journal: &'writers mut Journal, profile: &'profile ProductionControllerNormalRootProfileV1,
    credentials: &'credentials mut SourceSuccessorCredentialCustodyV2<'profile>,
) -> FailedSourceProjectSuccessorInvocationV3<'writers, 'profile, 'credentials> {
    let mut original = OriginalSourceProjectSuccessorInvocationV3::park_inner(journal, None, profile, credentials);
    original.action = Some(Err(SourceGenesisErrorV1::AdmissionClosed.into()));
    original.first_failure = Some(ProjectIssuerSiteV3::Action);
    FailedSourceProjectSuccessorInvocationV3 { original }
}

/// Parks one original issuer attempt over the SAME genuine resident writers.
///
/// Parking establishes negative custody only, not eligibility or authority.
/// The installed executor supplies its own actual Source field and Journal;
/// there is no decoded-data, supplied-FD or scalar-current-head constructor.
/// Dropping an unfinished attempt aborts before its resource fields drop.
#[must_use = "the resident issuer must be completed or deliberately terminated"]
pub struct OriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials> {
    journal: &'writers mut Journal,
    source: Option<&'writers mut ProtectedSourceDomainJournalOwnerV1>,
    profile: &'profile ProductionControllerNormalRootProfileV1,
    credentials: &'credentials mut SourceSuccessorCredentialCustodyV2<'profile>,
    raw: Option<OwnedFd>,
    adopted: Option<RetainedUnixStream>,
    flight: Option<OriginalRootGenesisFlightV1<'profile>>,
    publication: PublicationCustodyV2,
    phase: SourceSuccessorIssuancePhaseV2,
    first_cause: Option<(SourceSuccessorIssuancePhaseV2, IssuerCause)>,
    cleanup_debt: Option<SourceGenesisErrorV1>,
    completed: Option<SourceSuccessorApprovalDataV2>,
    started: bool,
    armed: bool,
}

/// Retains first cause and all original issuer custody until process termination.
///
/// This failure cannot be retried, decoded or converted to a current floor.
/// An abandoned failure aborts; the installed caller must deliberately consume
/// it while the enclosing Controller and credential resources are resident.
#[must_use = "the failed original administrative invocation must terminate"]
pub struct FailedOriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials> {
    original: OriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials>,
}

// Only this owner composition can construct the cut. Its fields borrow the
// real originals, not a snapshot/permit or caller-supplied currentness check.
pub(crate) struct SourceSuccessorSigningCutV2<'cut, 'controller, 'source, 'completed, 'flight> {
    controller: &'cut HeldControllerSourceGenesisV1<'controller>,
    inventory: &'cut RetainedTreeInventoryDataV1<'source>,
    completed: &'cut CompletedRootSourceGenesisFloorV1<'completed, 'flight>,
}

pub(crate) struct SourceSuccessorSigningCutV3<'cut, 'controller, 'source, 'completed, 'flight> {
    controller: &'cut HeldControllerSourceGenesisV1<'controller>,
    inventory: &'cut RetainedTreeInventoryDataV1<'source>,
    completed: &'cut CompletedRootSourceProjectGenesisFloorV3<'completed, 'flight>,
}

#[derive(Clone, Copy)]
enum CompletedGenesisRecipeV3<'cut, 'completed, 'flight> {
    StrictV2(&'cut CompletedRootSourceGenesisFloorV1<'completed, 'flight>),
    ProjectV3(&'cut CompletedRootSourceProjectGenesisFloorV3<'completed, 'flight>),
}

impl CompletedGenesisRecipeV3<'_, '_, '_> {
    fn recheck(self) -> Result<(), SourceGenesisErrorV1> {
        match self { Self::StrictV2(proof) => proof.recheck(), Self::ProjectV3(proof) => proof.recheck() }
    }

    fn floor(&self) -> &super::records::SourceHierarchyFloorRecordV1 {
        match self { Self::StrictV2(proof) => proof.floor(), Self::ProjectV3(proof) => proof.floor() }
    }
}

impl SourceSuccessorSigningCutV3<'_, '_, '_, '_, '_> {
    pub(crate) fn recheck_before_signature(
        &self, prepared: &[u8; BODY_BYTES], intent: SourceSuccessorIntentDataV2, issuer_generation: u64,
    ) -> Result<(), SourceGenesisErrorV1> {
        let clock = self.completed.signing_boundary_clock()?;
        let current = derive_body_with_completed(
            self.controller, self.inventory, CompletedGenesisRecipeV3::ProjectV3(self.completed),
            intent, issuer_generation, clock,
        )?;
        self.inventory.recheck().map_err(SourceGenesisErrorV1::from)?;
        self.controller.recheck()?;
        let clock = self.completed.signing_boundary_clock()?;
        require_body_context(prepared, &current, clock)
    }
}

impl SourceSuccessorSigningCutV2<'_, '_, '_, '_, '_> {
    pub(crate) fn recheck_before_signature(
        &self,
        prepared: &[u8; BODY_BYTES],
        intent: SourceSuccessorIntentDataV2,
        issuer_generation: u64,
    ) -> Result<(), SourceGenesisErrorV1> {
        let derivation_clock = self.completed.signing_boundary_clock()?;
        let current = derive_body(
            self.controller,
            self.inventory,
            self.completed,
            intent,
            issuer_generation,
            derivation_clock,
        )?;

        self.inventory.recheck().map_err(SourceGenesisErrorV1::from)?;
        self.controller.recheck()?;

        // The last pair follows the expensive context and original-flight
        // observations. Expiry/continuity checks are pure; crypto follows this
        // method without another profile, descriptor or owner observation.
        let clock = self.completed.signing_boundary_clock()?;
        require_body_context(prepared, &current, clock)
    }
}

impl<'writers, 'profile, 'credentials>
    OriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials>
{
    /// Parks the production executor's real writers before fallible checks.
    ///
    /// No packet, epoch, Root connection or signing effect occurs here.
    pub fn park(
        journal: &'writers mut Journal,
        source: &'writers mut ProtectedSourceDomainJournalOwnerV1,
        profile: &'profile ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Self {
        Self::park_inner(journal, Some(source), profile, credentials)
    }

    fn park_inner(
        journal: &'writers mut Journal,
        source: Option<&'writers mut ProtectedSourceDomainJournalOwnerV1>,
        profile: &'profile ProductionControllerNormalRootProfileV1,
        credentials: &'credentials mut SourceSuccessorCredentialCustodyV2<'profile>,
    ) -> Self {
        Self {
            journal,
            source,
            profile,
            credentials,
            raw: None,
            adopted: None,
            flight: None,
            publication: PublicationCustodyV2::new(),
            phase: SourceSuccessorIssuancePhaseV2::Admission,
            first_cause: None,
            cleanup_debt: None,
            completed: None,
            started: false,
            armed: true,
        }
    }

    /// Runs the exact owner composition inside the existing fixed signer loan.
    ///
    /// Errors are latched on this resident attempt, not returned as a lossy
    /// ordinary Result. Calling twice irreversibly fails the same invocation.
    pub fn run_with_controller_signer(&mut self, generation: u64, signer: &SigningKey) {
        if self.started || self.first_cause.is_some() {
            self.fail(SourceGenesisErrorV1::Conflict.into());
            return;
        }
        self.started = true;
        match self.run(generation, signer) {
            Ok(packet) => self.completed = Some(packet),
            Err(cause) => self.fail(cause),
        }
    }

    /// Latches failure of the unchanged fixed Controller signer admission.
    ///
    /// This is a destructive negative operation, not an admission constructor.
    pub fn fail_controller_signer_admission(&mut self, cause: std::io::Error) {
        self.fail(SourceGenesisErrorV1::Transport(cause).into());
    }

    /// Returns only completed public DATA or the retaining terminal failure.
    ///
    /// # Errors
    /// Returns a must-use failed original owner for every incomplete or failed
    /// invocation. Only successful internal Finish can disarm the Drop fence.
    pub fn into_outcome(
        mut self,
    ) -> Result<
        SourceSuccessorApprovalDataV2,
        FailedOriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials>,
    > {
        if self.first_cause.is_none() {
            if let Some(packet) = self.completed.take() {
                self.armed = false;
                return Ok(packet);
            }
            self.fail(SourceGenesisErrorV1::AdmissionClosed.into());
        }
        Err(FailedOriginalSourceSuccessorInvocationV2 { original: self })
    }

    fn fail(&mut self, cause: IssuerCause) {
        if self.first_cause.is_none() {
            self.first_cause = Some((self.phase, cause));
        }
        self.completed = None;
        self.credentials.end_failed();

        if self.cleanup_debt.is_none() {
            let result = if let Some(flight) = &self.flight {
                flight.end_failed()
            } else if let Some(raw) = &self.raw {
                rustix::net::shutdown(raw, rustix::net::Shutdown::Both)
                    .map_err(|error| SourceGenesisErrorV1::Transport(std::io::Error::from(error)))
            } else {
                Ok(())
            };
            self.cleanup_debt = result.err();
        }
    }

    fn run(
        &mut self,
        generation: u64,
        signer: &SigningKey,
    ) -> Result<SourceSuccessorApprovalDataV2, IssuerCause> {
        self.credentials.recheck()?;
        self.journal.require_git_coverage_new_admission_v1()
            .map_err(SourceGenesisErrorV1::from)?;
        let intent = self.credentials.intent()?;
        let source = self.source.as_deref_mut()
            .ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
        source.require_fixed_named_writer_v1().map_err(SourceGenesisErrorV1::from)?;
        let controller = hold_existing_completed_source_genesis_v2(self.journal, intent.project())?;
        let inventory = retained_tree_inventory_data_v1(source).map_err(SourceGenesisErrorV1::from)?;
        let acknowledged = observe_retained_source_genesis_v1(
            &inventory, controller.uid(), intent.project(),
        )?;
        controller.recheck_completed_source_ack(&acknowledged)?;

        self.phase = SourceSuccessorIssuancePhaseV2::Root;
        OriginalRootGenesisFlightV1::connect_parked(
            self.profile, &mut self.raw, &mut self.adopted, &mut self.flight,
        )?;
        let flight = self.flight.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        let prepare = sign_controller_source_genesis_readback_v1(
            &controller, &acknowledged, flight.nonce(), generation, signer,
        )?;
        flight.send_phase(WirePhase::Prepare, &prepare)?;
        let floor = match flight.receive_reply(&controller)? {
            OriginalRootGenesisReplyV1::Anchored(floor) => floor,
            OriginalRootGenesisReplyV1::Prepared(_) => {
                return Err(SourceGenesisErrorV1::AdmissionClosed.into());
            }
        };
        let complete = sign_controller_source_genesis_completion_readback_v1(
            &controller, &acknowledged, flight.nonce(), generation, signer,
        )?;
        flight.send_phase(WirePhase::Complete, &complete)?;
        let completed = flight.receive_completed(&floor)?;
        super::super::public_create_source::consume_completed_gen1_ancestry_v1(
            &controller, &acknowledged, &inventory, &completed,
        )?;

        self.phase = SourceSuccessorIssuancePhaseV2::Derivation;
        let clock = flight.issuance_clock()?;
        let issuer_generation = self.credentials.issuer_generation()?;
        let body = derive_body(
            &controller, &inventory, &completed, intent, issuer_generation, clock,
        )?;
        let packet = if let Some(saved) = controller.retained_successor_approval_v2()? {
            self.credentials.verify_saved(&saved)?;
            require_saved_context(&saved, &body, clock)?;
            saved
        } else {
            let signing_cut = SourceSuccessorSigningCutV2 {
                controller: &controller,
                inventory: &inventory,
                completed: &completed,
            };
            self.credentials.sign_approval(&body, &signing_cut)?
        };
        recheck_current_context(
            &controller, &inventory, &completed, flight, self.credentials, &packet,
        )?;

        self.phase = SourceSuccessorIssuancePhaseV2::Retention;
        controller.preflight_successor_issuance_v2(&packet)?;
        recheck_current_context(
            &controller, &inventory, &completed, flight, self.credentials, &packet,
        )?;
        controller.save_successor_issuance_v2(&packet)?;
        recheck_current_context(
            &controller, &inventory, &completed, flight, self.credentials, &packet,
        )?;

        self.phase = SourceSuccessorIssuancePhaseV2::Delivery;
        controller.publish_successor_issuance_v2(&packet, &mut self.publication)?;
        recheck_current_context(
            &controller, &inventory, &completed, flight, self.credentials, &packet,
        )?;
        controller.complete_successor_delivery_v2(&packet, &mut self.publication)?;

        self.phase = SourceSuccessorIssuancePhaseV2::Finish;
        recheck_current_context(
            &controller, &inventory, &completed, flight, self.credentials, &packet,
        )?;
        flight.finish(completed)?;
        Ok(packet)
    }
}

impl FailedOriginalSourceSuccessorInvocationV2<'_, '_, '_> {
    /// Borrows the first typed phase/cause, never a cleanup replacement.
    pub fn first_cause(
        &self,
    ) -> Option<(SourceSuccessorIssuancePhaseV2, &(dyn std::error::Error + 'static))> {
        self.original.first_cause.as_ref().map(|(phase, cause)| {
            let source: &(dyn std::error::Error + 'static) = match cause {
                IssuerCause::Owner(cause) => cause,
                IssuerCause::Credential(cause) => cause,
            };
            (*phase, source)
        })
    }

    /// Borrows separately retained shutdown debt without changing first cause.
    pub fn cleanup_debt(&self) -> Option<&SourceGenesisErrorV1> {
        self.original.cleanup_debt.as_ref()
    }

    /// Deliberately terminates while all original writer/carrier borrows remain.
    pub fn terminate_failed(self) -> ! {
        std::process::exit(1)
    }
}

impl Drop for OriginalSourceSuccessorInvocationV2<'_, '_, '_> {
    fn drop(&mut self) {
        if self.armed {
            // No allocation, panic or ordinary field drop precedes the fence.
            if self.first_cause.is_none() {
                self.phase = SourceSuccessorIssuancePhaseV2::Abandoned;
                self.first_cause = Some((self.phase, SourceGenesisErrorV1::AdmissionClosed.into()));
            }
            self.credentials.end_failed();
            if let Some(raw) = &self.raw {
                let _ = rustix::net::shutdown(raw, rustix::net::Shutdown::Both);
            }
            std::process::abort();
        }
    }
}

pub(crate) fn unavailable<'writers, 'profile, 'credentials>(
    journal: &'writers mut Journal,
    profile: &'profile ProductionControllerNormalRootProfileV1,
    credentials: &'credentials mut SourceSuccessorCredentialCustodyV2<'profile>,
) -> FailedOriginalSourceSuccessorInvocationV2<'writers, 'profile, 'credentials> {
    let mut original = OriginalSourceSuccessorInvocationV2::park_inner(
        journal, None, profile, credentials,
    );
    original.fail(SourceGenesisErrorV1::AdmissionClosed.into());
    FailedOriginalSourceSuccessorInvocationV2 { original }
}

fn derive_body(
    controller: &HeldControllerSourceGenesisV1<'_>,
    inventory: &RetainedTreeInventoryDataV1<'_>,
    completed: &CompletedRootSourceGenesisFloorV1<'_, '_>,
    intent: SourceSuccessorIntentDataV2,
    issuer_generation: u64,
    clock: RawPairedClockSample,
) -> Result<[u8; BODY_BYTES], SourceGenesisErrorV1> {
    derive_body_with_completed(controller, inventory, CompletedGenesisRecipeV3::StrictV2(completed), intent, issuer_generation, clock)
}

fn derive_body_with_completed(
    controller: &HeldControllerSourceGenesisV1<'_>, inventory: &RetainedTreeInventoryDataV1<'_>,
    completed: CompletedGenesisRecipeV3<'_, '_, '_>, intent: SourceSuccessorIntentDataV2,
    issuer_generation: u64, clock: RawPairedClockSample,
) -> Result<[u8; BODY_BYTES], SourceGenesisErrorV1> {
    completed.recheck()?;
    let floor = completed.floor();
    let (tree, tree_head, lineage_head) = inventory.trees()?
        .find(|(tree, _, _)| tree.project() == intent.project())
        .ok_or(SourceGenesisErrorV1::Stale)?;
    if tree.tree_generation().get() != 1
        || tree.records().next().is_some()
        || tree.tombstones().next().is_some()
        || tree_head != floor.tree_head()
        || lineage_head != floor.lineage_head()
        || floor.project() != intent.project()
    {
        return Err(SourceGenesisErrorV1::Stale);
    }
    let (
        publisher_generation, publisher_head, publisher_revision,
        authorization_head, limits, authorization,
    ) = controller.current_successor_authorization_v2()?;
    if limits != tree.limits() {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let record = SandboxTreeRecordV1::new(
        intent.project(), intent.sandbox(), None, DesiredGeneration::new(1), None,
    )
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let next = tree.insert(record, tree.tree_generation(), None)
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    let epoch = controller.acceptance().seed_claims()?.epoch().checked_add(1)
        .ok_or(SourceGenesisErrorV1::NonCanonical)?;
    let issued = u64::try_from(clock.wall_seconds()).map_err(|_| SourceGenesisErrorV1::AdmissionClosed)?;
    let expires = issued.checked_add(u64::from(intent.validity_seconds()))
        .ok_or(SourceGenesisErrorV1::NonCanonical)?;

    let mut body = [0; BODY_BYTES];
    body[..16].copy_from_slice(b"AOSCSA02\0\x02\0\0\0\0\0\0");
    body[16..24].copy_from_slice(&issuer_generation.to_be_bytes());
    body[24..32].copy_from_slice(&epoch.to_be_bytes());
    body[32..64].copy_from_slice(&floor.instance());
    body[64..80].copy_from_slice(intent.project().as_bytes());
    body[80..96].copy_from_slice(&intent.request());
    body[96..112].copy_from_slice(intent.sandbox().as_bytes());
    body[112..144].copy_from_slice(floor.roles().as_bytes());
    body[144..176].copy_from_slice(floor.digest().as_bytes());
    body[176..208].copy_from_slice(controller.completed_record_commitment_v2()?.as_bytes());
    body[208..216].copy_from_slice(&publisher_generation.to_be_bytes());
    body[216..248].copy_from_slice(publisher_head.as_bytes());
    body[248..280].copy_from_slice(publisher_revision.as_bytes());
    body[280..312].copy_from_slice(authorization_head.as_bytes());
    body[312..536].copy_from_slice(&authorization);
    body[536..568].copy_from_slice(tree_head.as_bytes());
    body[568..600].copy_from_slice(lineage_head.as_bytes());
    body[600..632].copy_from_slice(
        tree_commitment_v1(tree).map_err(|_| SourceGenesisErrorV1::NonCanonical)?.as_bytes(),
    );
    body[632..640].copy_from_slice(&1_u64.to_be_bytes());
    body[640..648].copy_from_slice(&next.tree_generation().get().to_be_bytes());
    let ceilings = [
        limits.maximum_project_roots(),
        limits.maximum_project_sandboxes(),
        limits.maximum_project_live_sandboxes(),
        limits.maximum_depth(),
        limits.maximum_children_per_parent(),
        limits.maximum_descendants(),
        limits.maximum_live_descendants(),
    ];
    for (index, ceiling) in ceilings.into_iter().enumerate() {
        let ceiling = u32::try_from(ceiling)
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        body[648 + index * 4..652 + index * 4].copy_from_slice(&ceiling.to_be_bytes());
    }
    body[680..712].copy_from_slice(
        tree_commitment_v1(&next).map_err(|_| SourceGenesisErrorV1::NonCanonical)?.as_bytes(),
    );
    body[712..728].copy_from_slice(&clock.host_boot_id());
    body[728..736].copy_from_slice(&clock.boottime_nanoseconds().to_be_bytes());
    body[736..744].copy_from_slice(&issued.to_be_bytes());
    body[744..752].copy_from_slice(&expires.to_be_bytes());
    body[752..832].copy_from_slice(intent.as_bytes());
    crate::hierarchy::source_successor::validate_body(&body)?;
    controller.recheck()?;
    completed.recheck()?;
    Ok(body)
}

fn require_saved_context(
    packet: &SourceSuccessorApprovalDataV2,
    current: &[u8],
    clock: RawPairedClockSample,
) -> Result<(), SourceGenesisErrorV1> {
    require_body_context(packet.body(), current, clock)
}

fn require_body_context(
    saved: &[u8],
    current: &[u8],
    clock: RawPairedClockSample,
) -> Result<(), SourceGenesisErrorV1> {
    let current_wall = u64::try_from(clock.wall_seconds())
        .map_err(|_| SourceGenesisErrorV1::AdmissionClosed)?;
    if saved.len() != BODY_BYTES
        || current.len() != BODY_BYTES
        || saved[..712] != current[..712]
        || saved[752..] != current[752..]
        || saved[712..728] != clock.host_boot_id()
        || u64::from_be_bytes(take(saved, 744)?) <= current_wall
    {
        return Err(SourceGenesisErrorV1::Stale);
    }
    // The prepared/saved original pair is comparison DATA, not a clock loan.
    // Only the same original flight supplies the independently obtained later
    // sample; construction here cannot revive an owner or renew its deadline.
    let original = RawPairedClockSample::new_untrusted(
        clock.provenance(), take(saved, 712)?,
        i64::try_from(u64::from_be_bytes(take(saved, 736)?)).map_err(|_| SourceGenesisErrorV1::NonCanonical)?,
        u64::from_be_bytes(take(saved, 728)?),
    ).map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
    original.validate_later_sample(clock).map_err(|_| SourceGenesisErrorV1::AdmissionClosed)
}

fn recheck_current_context(
    controller: &HeldControllerSourceGenesisV1<'_>,
    inventory: &RetainedTreeInventoryDataV1<'_>,
    completed: &CompletedRootSourceGenesisFloorV1<'_, '_>,
    flight: &OriginalRootGenesisFlightV1<'_>,
    credentials: &mut SourceSuccessorCredentialCustodyV2<'_>,
    packet: &SourceSuccessorApprovalDataV2,
) -> Result<(), IssuerCause> {
    credentials.recheck()?;
    let clock = flight.issuance_clock()?;
    let current = derive_body(
        controller,
        inventory,
        completed,
        credentials.intent()?,
        credentials.issuer_generation()?,
        clock,
    )?;
    require_saved_context(packet, &current, clock)?;
    credentials.verify_saved(packet)?;
    completed.recheck().map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::RawClockProvenance;
    use crate::hierarchy::source_successor::tests::approval_fixture;

    fn clock(boot: u8, wall: i64, boottime: u64) -> RawPairedClockSample {
        RawPairedClockSample::new_untrusted(
            RawClockProvenance::new_untrusted([1; 16]).unwrap(),
            [boot; 16], wall, boottime,
        ).unwrap()
    }

    #[test]
    fn saved_reexecution_uses_immutable_context_and_never_renews_expiry() {
        let (packet, _) = approval_fixture();
        let current = take::<BODY_BYTES>(packet.body(), 0).unwrap();

        assert!(require_saved_context(&packet, &current, clock(12, 1_000, 1_000_000_000)).is_ok());
        assert!(require_saved_context(&packet, &current, clock(12, 1_001, 2_000_000_000)).is_ok());
        assert!(require_saved_context(&packet, &current, clock(12, 1_300, 301_000_000_000)).is_err());
        assert_eq!(&packet.body()[744..752], &1_300_u64.to_be_bytes());
    }

    #[test]
    fn saved_reexecution_rejects_every_current_owner_head_and_intent_substitution() {
        let (packet, _) = approval_fixture();
        let now = clock(12, 1_001, 2_000_000_000);

        for offset in [
            16, 24, 32, 64, 80, 96, 112, 144, 176, 208, 216, 248, 280,
            312, 536, 568, 600, 632, 640, 648, 680, 752,
        ] {
            let mut current = take::<BODY_BYTES>(packet.body(), 0).unwrap();
            current[offset] ^= 1;
            assert!(require_saved_context(&packet, &current, now).is_err(), "{offset}");
        }
    }

    #[test]
    fn saved_reexecution_rejects_boot_wall_boottime_rollback_and_clock_divergence() {
        let (packet, _) = approval_fixture();
        for changed in [
            clock(13, 1_001, 2_000_000_000),
            clock(12, 999, 2_000_000_000),
            clock(12, 1_001, 999_999_999),
            clock(12, 1_100, 2_000_000_000),
        ] {
            assert!(require_saved_context(&packet, packet.body(), changed).is_err());
        }
    }

    #[test]
    fn prepared_body_expiry_uses_the_last_pair_after_owner_observations() {
        let (packet, _) = approval_fixture();
        let prepared = packet.body();
        let early = clock(12, 1_000, 1_000_000_000);
        let after_observations = clock(12, 1_300, 301_000_000_000);

        assert!(require_body_context(prepared, prepared, early).is_ok());
        assert!(require_body_context(prepared, prepared, after_observations).is_err());
        assert_eq!(&prepared[744..752], &1_300_u64.to_be_bytes());
    }

    #[test]
    fn prepared_body_refuses_width_and_unsigned_owner_context_substitutions() {
        let (packet, _) = approval_fixture();
        let prepared = packet.body();
        let now = clock(12, 1_001, 2_000_000_000);
        let mut oversized = prepared.to_vec();
        oversized.push(0);

        assert!(require_body_context(&prepared[..BODY_BYTES - 1], prepared, now).is_err());
        assert!(require_body_context(&oversized, prepared, now).is_err());

        for offset in [32, 144, 176, 536, 568, 680, 752] {
            let mut current = take::<BODY_BYTES>(prepared, 0).unwrap();
            current[offset] ^= 1;

            assert!(require_body_context(prepared, &current, now).is_err(), "{offset}");
        }
    }
}
