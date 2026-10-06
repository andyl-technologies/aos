//! Actual fixed Root writer for initial instance, intent, and semantic CAS.
//!
//! Each method retains the real protected Root journal. Returned records are
//! data only: the client separately proves the actual Root sender on its same
//! original flight before any Source append or ACK can consume a live token.
//! This local profile assumes protected Root state is not rolled back with the
//! whole host disk. Diagnostic frame sequence never orders a semantic floor.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aos_sandbox_core::ProjectId;
use ed25519_dalek::VerifyingKey;

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::hierarchy::source_genesis::SourceTreeGenesisStateV1;
use crate::journal::{
    Journal, JournalRecord, JournalTransaction, ProtectedJournalNamesV1, RecordNamespace,
};

use super::super::PinnedSourceHoldReadbackSignerV1;
use super::super::controller_readback_session::fresh_root_nonce;
use super::super::deployment_head::{
    HEAD_KEY, SIGNER_PINS_KEY, decode_policy_signer_pins_v1, verify_historical_packet,
};
use super::super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::super::source_genesis_readback::{
    SourceTreeGenesisChallengeV1, SourceTreeGenesisIntentContextV1,
    VerifiedSourceTreeGenesisReadbackV1, verify_source_tree_genesis_readback_v2,
};
use super::capacity;
use super::controller_readback::{self, VerifiedControllerSourceGenesisReadbackV1};
use super::pins::RootGenesisRolePinsV1;
use super::records::{
    FLOOR_PREFIX, INSTANCE_KEY, INTENT_PREFIX, PINS_KEY, RootSourceGenesisIntentRecordV1,
    SourceHierarchyFloorRecordV1, decode_instance, instance_bytes, project_key,
};

pub(super) const INSTANCE_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.source-genesis.root-instance-transaction.v1\0";
const MAXIMUM_PROJECTS: usize = 4096;

/// Retains only the fixed Root writer, pinned roles, and one original flight nonce.
///
/// This is the Root daemon's store owner, not a transferable Source authority.
/// The normal daemon acquires it last after Controller and Source are held.
pub struct RootSourceGenesisAuthorityV1 {
    pub(super) journal: Journal,
    pub(super) pins: RootGenesisRolePinsV1,
    pub(super) names: ProtectedJournalNamesV1,
    pub(super) nonce: [u8; 16],
    pub(super) controller_uid: u32,
    pub(super) source_uid: u32,
    pub(super) accepted: Option<VerifiedControllerSourceGenesisReadbackV1>,
    genesis_recipe: RootGenesisOwnerRecipeV3,
    pub(super) successor_recipe: super::wire::FirstSuccessorWireRecipeV3,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RootGenesisOwnerRecipeV3 { StrictV1, ProjectV3 }

/// Retains actual selected Root mutations, source verification and clock debts.
#[derive(Default)]
pub struct RootProjectGenesisMutationResultsV3 {
    source: Option<Result<super::super::VerifiedSourceProjectGenesisReadbackV3, super::super::SourceHoldReadbackErrorV1>>,
    preparation: Option<Result<(), SourceGenesisErrorV1>>,
    transaction: Option<JournalTransaction>,
    prepared: Option<crate::journal::PreparedGlobalCapacityReservationV1>,
    reservation: Option<crate::journal::GlobalCapacityReservationV1>,
    native_prepare: Option<Result<(crate::journal::CommitResult, crate::journal::GlobalCapacityReservationV1), crate::JournalError>>,
    native_anchor: Option<Result<crate::journal::CommitResult, crate::JournalError>>,
    intent: Option<RootSourceGenesisIntentRecordV1>,
    floor: Option<SourceHierarchyFloorRecordV1>,
    readback: Option<Result<(), SourceGenesisErrorV1>>,
    post: Option<Result<(), SourceGenesisErrorV1>>,
    clock_post: Option<Result<aos_sandbox_core::RawPairedClockSample, SourceGenesisErrorV1>>,
    first_failure: Option<RootProjectGenesisSiteV3>,
}

#[derive(Clone, Copy)]
enum RootProjectGenesisSiteV3 { Source, Preparation, NativePrepare, NativeAnchor, Readback, Post, Clock }

impl RootProjectGenesisMutationResultsV3 {
    /// Creates a single-use inert custody reservoir.
    pub fn new() -> Self { Self::default() }

    /// Borrows the original first failing Result without another observation.
    pub fn error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_failure? {
            RootProjectGenesisSiteV3::Source => self.source.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisSiteV3::Preparation => self.preparation.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisSiteV3::NativePrepare => self.native_prepare.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisSiteV3::NativeAnchor => self.native_anchor.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisSiteV3::Readback => self.readback.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisSiteV3::Post => self.post.as_ref()?.as_ref().err().map(|e| e as _),
            RootProjectGenesisSiteV3::Clock => self.clock_post.as_ref()?.as_ref().err().map(|e| e as _),
        }
    }

    fn latch(&mut self, site: RootProjectGenesisSiteV3, failed: bool) {
        if failed && self.first_failure.is_none() { self.first_failure = Some(site); }
    }

    fn posts(&mut self, owner: &RootSourceGenesisAuthorityV1, clock: &aos_sandbox_core::RawPairedClockSample, deadline: std::time::Instant) {
        self.post = Some(owner.recheck());
        self.latch(RootProjectGenesisSiteV3::Post, self.post.as_ref().is_some_and(Result::is_err));
        self.clock_post = Some(super::flight::observe_root_first_source_successor_clock_v2(Some(*clock)).and_then(|current| {
            if std::time::Instant::now() >= deadline { return Err(SourceGenesisErrorV1::Stale); }
            Ok(current)
        }));
        self.latch(RootProjectGenesisSiteV3::Clock, self.clock_post.as_ref().is_some_and(Result::is_err));
    }
}

/// Parks the actual fixed Root open Result before later pins/history checks.
///
/// This keeps an already returned Journal resident even when a subsequent
/// credential, physical-name or history observation fails. The Journal's own
/// lower pre-return protected-open prefixes remain its existing boundary.
#[derive(Default)]
pub struct RootFirstSourceSuccessorOpeningV2 {
    native: Option<Result<(Journal, crate::journal::RecoveryReport), crate::journal::JournalError>>,
    pins: Option<Result<RootGenesisRolePinsV1, SourceGenesisErrorV1>>,
    named: Option<Result<ProtectedJournalNamesV1, crate::journal::JournalError>>,
    nonce: Option<Result<[u8; 16], SourceGenesisErrorV1>>,
    checks: Vec<Result<(), SourceGenesisErrorV1>>,
}

impl RootFirstSourceSuccessorOpeningV2 {
    /// Creates an inert unused opening reservoir.
    pub fn new() -> Self { Self::default() }

    /// Opens the same real fixed Root writer for explicit mixed successor use.
    ///
    /// # Errors
    /// Retains all original opening results on any actual owner/pin failure.
    pub fn open_project_successor_into_v3(
        &mut self, owner: &mut Option<RootSourceGenesisAuthorityV1>, controller_uid: u32, source_uid: u32,
    ) -> Result<(), ()> {
        self.open_into(owner, controller_uid, source_uid)?;
        let actual = owner.as_mut().ok_or(())?;
        actual.successor_recipe = super::wire::FirstSuccessorWireRecipeV3::MixedV3;
        Ok(())
    }

    /// Opens and parks only the existing fixed protected Root journal.
    ///
    /// # Errors
    /// Returns a marker while actual native/pin/history Results remain resident.
    pub fn open_into(
        &mut self, owner: &mut Option<RootSourceGenesisAuthorityV1>,
        controller_uid: u32, source_uid: u32,
    ) -> Result<(), ()> {
        if self.native.is_some() || owner.is_some() || controller_uid == 0 || source_uid == 0 { return Err(()); }
        self.native = Some(Journal::open_existing_protected_at(
            Path::new(PROTECTED_POLICY_ROOT), POLICY_AUTHORITY_JOURNAL, policy_authority_journal_limits(),
        ));
        let journal = self.native.as_ref().and_then(|result| result.as_ref().ok()).map(|(journal, _)| journal).ok_or(())?;
        self.checks.push(capacity::require_owner(journal).map_err(SourceGenesisErrorV1::from));
        self.pins = Some(RootGenesisRolePinsV1::load(journal));
        self.named = Some(journal.protected_writer_physical_names_v1());
        self.nonce = Some(fresh_root_nonce());
        if let Some(Ok(pins)) = &self.pins { self.checks.push(validate_history(journal, pins)); }
        if self.error().is_some() { return Err(()); }
        let names = *self.named.as_ref().and_then(|result| result.as_ref().ok()).ok_or(())?;
        let nonce = *self.nonce.as_ref().and_then(|result| result.as_ref().ok()).ok_or(())?;
        let returned = self.native.take();
        match returned {
            Some(Ok((journal, recovery))) => {
                let retained_pins = self.pins.take();
                match retained_pins {
                    Some(Ok(pins)) => {
                        // All fallible work precedes this final owner transfer.
                        *owner = Some(RootSourceGenesisAuthorityV1 {
                            journal, pins, names, nonce, controller_uid, source_uid, accepted: None,
                            genesis_recipe: RootGenesisOwnerRecipeV3::StrictV1,
                            successor_recipe: super::wire::FirstSuccessorWireRecipeV3::StrictV2,
                        });
                        drop(recovery);
                        Ok(())
                    }
                    returned => { self.pins = returned; self.native = Some(Ok((journal, recovery))); Err(()) }
                }
            }
            returned => { self.native = returned; Err(()) }
        }
    }

    /// Borrows first native or later independent opening failure without loss.
    pub fn error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(Err(error)) = &self.native { return Some(error); }
        if let Some(Err(error)) = self.checks.first() { return Some(error); }
        if let Some(Err(error)) = &self.pins { return Some(error); }
        if let Some(Err(error)) = &self.named { return Some(error); }
        if let Some(Err(error)) = &self.nonce { return Some(error); }
        for check in self.checks.iter().skip(1) { if let Err(error) = check { return Some(error); } }
        None
    }

    /// Opens the same fixed genuine Root owner for the closed project purpose.
    ///
    /// # Errors
    /// Returns a marker retaining actual opening Results; never provisions roles.
    pub fn open_project_genesis_into_v3(
        &mut self, owner: &mut Option<RootSourceGenesisAuthorityV1>, controller_uid: u32, source_uid: u32,
    ) -> Result<(), ()> {
        self.open_into(owner, controller_uid, source_uid)?;
        let actual = owner.as_mut().ok_or(())?;
        actual.genesis_recipe = RootGenesisOwnerRecipeV3::ProjectV3;
        Ok(())
    }
}

// This is a short loan from the same actual Root writer. The added Controller
// fields are projections of a packet already checked by the sole old decoder,
// not a new parser, sequence-based authority or detachable current-floor token.
pub(in crate::policy_compiler) struct Q04RootGen1CutLoanV1<'root> {
    owner: &'root RootSourceGenesisAuthorityV1,
    current: super::CurrentRootSourceGenesisFloorV1<'root>,
    controller_sequence: u64,
    controller_names: ProtectedJournalNamesV1,
}

impl Q04RootGen1CutLoanV1<'_> {
    pub(in crate::policy_compiler) fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        self.current.recheck()
    }

    pub(in crate::policy_compiler) fn floor(&self) -> &SourceHierarchyFloorRecordV1 {
        self.current.floor()
    }

    pub(in crate::policy_compiler) fn controller_names(&self) -> ProtectedJournalNamesV1 {
        self.controller_names
    }

    pub(in crate::policy_compiler) fn controller_coordinates(
        &self,
    ) -> Result<(ProtectedJournalNamesV1, u64), super::super::create_q04::CreateQ04ErrorV1> {
        self.recheck()?;
        let coordinates = (self.controller_names, self.controller_sequence);
        self.recheck()?;
        Ok(coordinates)
    }

    // Equality DATA from the actual fresh signed Controller/Source pair
    // already joined by require_same_source_cut and the anchored floor.
    pub(in crate::policy_compiler) fn source_coordinates(
        &self,
    ) -> Result<(ProtectedJournalNamesV1, u64), super::super::create_q04::CreateQ04ErrorV1> {
        self.recheck()?;
        let accepted = self.owner.accepted.as_ref()
            .ok_or(super::super::create_q04::CreateQ04ErrorV1::ChangedCut)?;
        let coordinates = (accepted.source_names, accepted.source_sequence);
        self.recheck()?;
        Ok(coordinates)
    }

    // The actual Root pin verifies this distinct Q04 packet. Its sequence is
    // compared to a fresh completed gen1 observation under the same original
    // nonce; an old held signature is never treated as current after a write.
    pub(in crate::policy_compiler) fn acknowledgement<'packet>(
        &self,
        kind: super::super::create_q04::Q04AcknowledgementKindV1,
        packet: &'packet [u8],
        identity: &super::super::create_q04::Q04CutIdentityV1,
        original_controller_names: ProtectedJournalNamesV1,
    ) -> Result<super::super::create_q04::Q04AcknowledgementV1<'packet>, super::super::create_q04::CreateQ04ErrorV1> {
        use super::super::create_q04::{CreateQ04ErrorV1, Q04AcknowledgementV1};

        self.recheck()?;
        self.owner.recheck()?;
        let packet = Q04AcknowledgementV1::verify(kind, packet, &self.owner.pins.controller, identity)?;
        if identity.nonce() != self.owner.nonce
            || identity.controller_uid() != self.owner.controller_uid
            || identity.bytes()[84..88] != self.owner.source_uid.to_be_bytes()
            || self.floor().digest() != identity.gen1_floor()
            || self.floor().project() != identity.project()
            || packet.controller_sequence() != self.controller_sequence
            || self.controller_names != original_controller_names
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck()?;
        self.owner.recheck()?;
        Ok(packet)
    }

    // Signature provenance and original named/sequence equality are separate
    // from any held proof. This read-only prehold purpose never issues a Stage
    // or permits publication; the original Root flight retains all packets.
    pub(in crate::policy_compiler) fn prehold_input<'packet>(
        &self,
        packet: &'packet [u8],
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
    ) -> Result<
        (
            super::super::create_q04::Q04PreholdInputDataV1<'packet>,
            super::super::VerifiedControllerProjectAdmissionV1,
        ),
        super::super::create_q04::CreateQ04ErrorV1,
    > {
        self.recheck()?;
        let checked = self.owner.q04_verify_prehold_input(packet, stage, self)?;
        self.recheck()?;
        Ok(checked)
    }

    pub(in crate::policy_compiler) fn verify_claim<'packet>(
        &self,
        packet: &'packet [u8],
        identity: &super::super::create_q04::Q04CutIdentityV1,
    ) -> Result<
        super::super::create_q04::Q04ClaimV1<'packet>,
        super::super::create_q04::CreateQ04ErrorV1,
    > {
        self.recheck()?;
        let claim = self.owner.q04_verify_claim(packet, identity)?;
        self.recheck()?;
        Ok(claim)
    }

    pub(in crate::policy_compiler) fn controller_cut(
        &self,
        current_packet: &[u8],
        held_packet: &[u8],
        proposed: &[u8],
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
        identity: &super::super::create_q04::Q04CutIdentityV1,
    ) -> Result<
        (
            super::super::VerifiedControllerProjectAdmissionV1,
            super::super::VerifiedControllerHoldReadbackV1,
        ),
        super::super::create_q04::CreateQ04ErrorV1,
    > {
        self.owner.q04_verify_controller_cut(
            current_packet, held_packet, proposed, self, stage, identity,
        )
    }

    // This retains only signature provenance from the original prehold/C1
    // packets. The distinct current ACK above must establish the later live
    // Controller cut; this projection cannot replace that actual observation.
    pub(in crate::policy_compiler) fn original_controller_provenance(
        &self,
        current_packet: &[u8],
        held_packet: &[u8],
        proposed: &[u8],
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
        identity: &super::super::create_q04::Q04CutIdentityV1,
        original_next: u64,
    ) -> Result<(super::super::VerifiedControllerProjectAdmissionV1,
        super::super::VerifiedControllerHoldReadbackV1), super::super::create_q04::CreateQ04ErrorV1> {
        self.owner.q04_verify_controller_cut_for(
            current_packet, held_packet, proposed, self, stage, identity,
            Q04ControllerPacketPositionV1::OriginalHeld { original_next },
        )
    }

    pub(in crate::policy_compiler) fn signed_project_sources(
        &self,
        project_input: &[u8],
        deployment_inputs: &super::super::PolicyDeploymentInputsV1<'_>,
        now_unix_seconds: i64,
    ) -> Result<
        (
            super::super::VerifiedSignedProjectPolicySourceV2,
            super::super::PolicyDeploymentHeadV1,
            super::super::PolicyDeploymentSourcesV1,
        ),
        super::super::create_q04::CreateQ04ErrorV1,
    > {
        self.recheck()?;
        let sources = self.owner.q04_signed_project_sources(
            project_input, deployment_inputs, now_unix_seconds,
        )?;
        self.recheck()?;
        Ok(sources)
    }

    pub(in crate::policy_compiler) fn cache_cut(
        &self,
        packet: &[u8],
        proposed: &[u8],
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
        identity: &super::super::create_q04::Q04CutIdentityV1,
        cache_uid: u32,
    ) -> Result<
        crate::cache_residency::VerifiedClosedCacheOwnerReadbackV2,
        super::super::create_q04::CreateQ04ErrorV1,
    > {
        self.recheck()?;
        let cache = self.owner.q04_verify_cache_cut(packet, proposed, stage, identity, cache_uid)?;
        self.recheck()?;
        Ok(cache)
    }

    pub(in crate::policy_compiler) fn original_cache_provenance(
        &self,
        packet: &[u8],
        proposed: &[u8],
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
        identity: &super::super::create_q04::Q04CutIdentityV1,
        cache_uid: u32,
    ) -> Result<crate::cache_residency::VerifiedClosedCacheOwnerReadbackV2,
        super::super::create_q04::CreateQ04ErrorV1> {
        self.recheck()?;
        let observed = self.owner.q04_verify_original_cache_packet(packet, proposed, stage, identity, cache_uid)?;
        self.recheck()?;
        Ok(observed)
    }
}

enum Q04ControllerPacketPositionV1 {
    CurrentHeld,
    OriginalHeld { original_next: u64 },
}

impl RootSourceGenesisAuthorityV1 {
    pub(super) fn require_strict_genesis_recipe_v1(&self) -> Result<(), SourceGenesisErrorV1> {
        if self.genesis_recipe != RootGenesisOwnerRecipeV3::StrictV1 { return Err(SourceGenesisErrorV1::Conflict); }
        Ok(())
    }
    pub(crate) fn require_project_genesis_current_deployment_v3(journal: &Journal) -> Result<i64, SourceGenesisErrorV1> {
        require_current_deployment(journal)
    }

    /// Admits only the signed selected project on this actual project-purpose owner.
    ///
    /// # Errors
    /// Rejects strict packets, changed role pins/cuts, global Empty, different
    /// instances, or a cold unreceipted intent. Intent792 cannot renew admission.
    pub fn accept_controller_project_genesis_v3(
        &mut self, packet: &[u8],
    ) -> Result<(super::super::SourceProjectGenesisChallengeV3, SourceTreeGenesisIntentContextV1), SourceGenesisErrorV1> {
        self.recheck()?;
        if self.genesis_recipe != RootGenesisOwnerRecipeV3::ProjectV3 { return Err(SourceGenesisErrorV1::Conflict); }
        let accepted = controller_readback::verify_project_genesis_v3(
            packet, &self.pins.controller, self.nonce, self.controller_uid, self.source_uid,
        )?;
        self.pins.verify_administrative_input(&accepted.acceptance)?;
        let project = accepted.acceptance.project();
        let instance = decode_instance(self.journal.get(RecordNamespace::DesiredState, INSTANCE_KEY).ok_or(SourceGenesisErrorV1::Conflict)?)?;
        if accepted.source_instance != Some(instance)
            || self.accepted.as_ref().is_some_and(|prior| prior.acceptance != accepted.acceptance
                || prior.source_names != accepted.source_names
                || prior.historical && !accepted.historical || prior.completed && !accepted.completed)
        { return Err(SourceGenesisErrorV1::Conflict); }
        let prior_floor = self.floor(project)?;
        let prior_intent = self.intent(project)?;
        let intent_digest = if accepted.vacant {
            // A new transport cannot recover boot/D/expiry from Intent792.
            // Keep the old intent/reservation debt instead of reissuing it.
            if prior_intent.is_some() || prior_floor.is_some() { return Err(SourceGenesisErrorV1::AdmissionClosed); }
            require_current_deployment(&self.journal)?;
            None
        } else {
            Some(if let Some(floor) = &prior_floor {
                if floor.receipt().acceptance_digest() != accepted.acceptance.digest() { return Err(SourceGenesisErrorV1::Conflict); }
                floor.receipt().intent_digest()
            } else {
                let intent = prior_intent.as_ref().ok_or(SourceGenesisErrorV1::Conflict)?;
                require_acceptance(intent, &accepted, self.source_uid)?;
                intent.digest()
            })
        };
        let context = SourceTreeGenesisIntentContextV1::new(self.source_uid, self.pins.digest(), accepted.acceptance.clone())?;
        let challenge = super::super::SourceProjectGenesisChallengeV3::new(self.nonce, project, intent_digest)
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        self.accepted = Some(accepted);
        self.recheck()?;
        Ok((challenge, context))
    }

    /// Compares the accepted project's retained floor for selected routing only.
    ///
    /// This DATA result neither constructs a current floor nor permits append.
    /// An active intent without a floor must still use the Prepared handshake.
    ///
    /// # Errors
    /// Rejects a non-project owner, missing acceptance or changed full history.
    pub fn project_genesis_floor_present_v3(&self) -> Result<bool, SourceGenesisErrorV1> {
        self.recheck()?;
        if self.genesis_recipe != RootGenesisOwnerRecipeV3::ProjectV3 {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let accepted = self.accepted.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        let present = self.floor(accepted.acceptance.project())?.is_some();
        self.recheck()?;
        Ok(present)
    }

    fn verify_project_genesis_source_v3(
        &self, packet: &[u8], resident: &mut RootProjectGenesisMutationResultsV3,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        if self.genesis_recipe != RootGenesisOwnerRecipeV3::ProjectV3 || resident.source.is_some() { return Err(SourceGenesisErrorV1::Conflict); }
        let accepted = self.accepted.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        let project = accepted.acceptance.project();
        let intent = if accepted.historical {
            let floor = self.floor(project)?;
            let original = self.intent(project)?;
            Some(floor.map(|floor| floor.receipt().intent_digest())
                .or_else(|| original.map(|intent| intent.digest())).ok_or(SourceGenesisErrorV1::Conflict)?)
        } else { None };
        let challenge = super::super::SourceProjectGenesisChallengeV3::new(self.nonce, project, intent)
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        resident.source = Some(super::super::verify_source_project_genesis_readback_v3(packet, &self.pins.source, challenge));
        resident.latch(RootProjectGenesisSiteV3::Source, resident.source.as_ref().is_some_and(Result::is_err));
        let observed = resident.source.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
        let instance = decode_instance(self.journal.get(RecordNamespace::DesiredState, INSTANCE_KEY).ok_or(SourceGenesisErrorV1::Conflict)?)?;
        if observed.project() != project || observed.instance() != instance
            || observed.names() != accepted.source_names || observed.journal_sequence() != accepted.source_sequence
            || accepted.vacant != (observed.state() == SourceTreeGenesisStateV1::VacantProject)
        { return Err(SourceGenesisErrorV1::Stale); }
        if let Some(receipt) = observed.receipt() {
            if receipt.acceptance_digest() != accepted.acceptance.digest()
                || &receipt.seed_packet() != accepted.acceptance.seed_packet()
                || receipt.auth_packet() != accepted.acceptance.auth_packet()
            { return Err(SourceGenesisErrorV1::Conflict); }
            SourceTreeGenesisIntentContextV1::new(self.source_uid, self.pins.digest(), accepted.acceptance.clone())?
                .require_actual_receipt(receipt, self.intent(project)?.as_ref().map(RootSourceGenesisIntentRecordV1::nonce))?;
        }
        Ok(())
    }

    /// Prepares genuine selected genesis with the existing purpose-six reservation.
    ///
    /// # Errors
    /// Returns a marker retaining source/native/owner/clock Results and buffers.
    /// Cold vacancy with an old intent is fenced; historical Source receipts
    /// permit only the same original settlement suffix.
    pub fn prepare_project_genesis_v3(
        &mut self, packet: &[u8], original: &aos_sandbox_core::RawPairedClockSample,
        deadline: std::time::Instant, resident: &mut RootProjectGenesisMutationResultsV3,
    ) -> Result<RootSourceGenesisIntentRecordV1, ()> {
        if resident.preparation.is_some() { return Err(()); }
        resident.preparation = Some((|| {
            self.verify_project_genesis_source_v3(packet, resident)?;
            let accepted = self.accepted.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
            let project = accepted.acceptance.project();
            if self.floor(project)?.is_some() { return Err(SourceGenesisErrorV1::Conflict); }
            if let Some(intent) = self.intent(project)? {
                require_acceptance(&intent, accepted, self.source_uid)?;
                let receipt = resident.source.as_ref().and_then(|result| result.as_ref().ok()).and_then(|observed| observed.receipt())
                    .ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
                if receipt.intent_digest() != intent.digest() || receipt.instance() != intent.instance() { return Err(SourceGenesisErrorV1::Conflict); }
                resident.intent = Some(intent);
                return Ok(());
            }
            if !accepted.vacant || accepted.historical
                || self.journal.records(RecordNamespace::DesiredState).any(|(key, _)| key.starts_with(INTENT_PREFIX))
                || self.journal.records(RecordNamespace::DesiredState).filter(|(key, _)| key.starts_with(FLOOR_PREFIX)).count() >= MAXIMUM_PROJECTS
            { return Err(SourceGenesisErrorV1::Conflict); }
            require_current_deployment(&self.journal)?;
            let instance = decode_instance(self.journal.get(RecordNamespace::DesiredState, INSTANCE_KEY).ok_or(SourceGenesisErrorV1::Conflict)?)?;
            let intent = RootSourceGenesisIntentRecordV1::new(instance, self.source_uid, self.nonce, accepted.acceptance.clone(), self.pins.digest())?;
            let prepared = self.journal.prepare_global_capacity_reservation_v1(capacity::request(&intent), capacity::admission_id(&intent))?;
            let transaction = JournalTransaction::new(capacity::admission_id(&intent), vec![
                JournalRecord::put(RecordNamespace::DesiredState, capacity::intent_key(&intent), intent.record_bytes().to_vec()),
                prepared.record().clone(),
            ])?;
            self.journal.preflight_root_project_genesis_prepared_v3(&prepared, &transaction, project)?;
            resident.intent = Some(intent);
            resident.transaction = Some(transaction);
            resident.prepared = Some(prepared);
            self.recheck()?;
            require_current_deployment(&self.journal)?;
            Ok(())
        })());
        resident.latch(RootProjectGenesisSiteV3::Preparation, resident.preparation.as_ref().is_some_and(Result::is_err));
        if resident.first_failure.is_none() {
            if let (Some(prepared), Some(transaction), Some(intent)) = (resident.prepared.take(), &resident.transaction, &resident.intent) {
                resident.native_prepare = Some(self.journal.commit_root_project_genesis_prepared_v3(prepared, transaction, intent.project(), original, deadline));
                resident.latch(RootProjectGenesisSiteV3::NativePrepare, resident.native_prepare.as_ref().is_some_and(Result::is_err));
            }
        }
        resident.readback = Some((|| {
            let intent = resident.intent.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
            if self.intent(intent.project())?.as_ref() != Some(intent) { return Err(SourceGenesisErrorV1::Stale); }
            Ok(())
        })());
        resident.latch(RootProjectGenesisSiteV3::Readback, resident.readback.as_ref().is_some_and(Result::is_err));
        resident.posts(self, original, deadline);
        if resident.error().is_some() { Err(()) } else { resident.intent.as_ref().cloned().ok_or(()) }
    }

    /// Anchors only the actual selected Source receipt with its original suffix.
    ///
    /// # Errors
    /// Returns a marker retaining all Results; conflicting or ambiguous progress
    /// remains fenced and cannot be retried on this reservoir.
    pub fn anchor_project_genesis_v3(
        &mut self, packet: &[u8], original: &aos_sandbox_core::RawPairedClockSample,
        deadline: std::time::Instant, resident: &mut RootProjectGenesisMutationResultsV3,
    ) -> Result<SourceHierarchyFloorRecordV1, ()> {
        if resident.preparation.is_some() { return Err(()); }
        resident.preparation = Some((|| {
            self.verify_project_genesis_source_v3(packet, resident)?;
            let accepted = self.accepted.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
            let observed = resident.source.as_ref().and_then(|result| result.as_ref().ok()).ok_or(SourceGenesisErrorV1::Stale)?;
            let receipt = observed.receipt().ok_or(SourceGenesisErrorV1::Conflict)?.clone();
            let floor = SourceHierarchyFloorRecordV1::new(receipt, self.pins.digest())?;
            if let Some(prior) = self.floor(floor.project())? {
                if prior != floor { return Err(SourceGenesisErrorV1::Conflict); }
                resident.floor = Some(prior);
                return Ok(());
            }
            let intent = self.intent(floor.project())?.ok_or(SourceGenesisErrorV1::Conflict)?;
            require_acceptance(&intent, accepted, self.source_uid)?;
            if floor.receipt().intent_digest() != intent.digest() { return Err(SourceGenesisErrorV1::Conflict); }
            let identity = self.journal.root_source_genesis_capacity_identity_v1(&capacity::request(&intent), capacity::admission_id(&intent))?;
            let reservation = self.journal.recover_global_capacity_reservation_v1(identity)?;
            let transaction = JournalTransaction::new(capacity::floor_transaction_id(&floor), vec![
                JournalRecord::put(RecordNamespace::DesiredState, capacity::floor_key(&floor), floor.record_bytes().to_vec()),
                JournalRecord::delete(RecordNamespace::DesiredState, capacity::intent_key(&intent)), reservation.settlement_record(),
            ])?;
            self.journal.preflight_root_project_genesis_anchor_v3(&reservation, &transaction, floor.project())?;
            resident.transaction = Some(transaction);
            resident.reservation = Some(reservation);
            resident.floor = Some(floor);
            self.recheck()?;
            Ok(())
        })());
        resident.latch(RootProjectGenesisSiteV3::Preparation, resident.preparation.as_ref().is_some_and(Result::is_err));
        if resident.first_failure.is_none() {
            if let (Some(reservation), Some(transaction), Some(floor)) = (resident.reservation.take(), &resident.transaction, &resident.floor) {
                resident.native_anchor = Some(self.journal.commit_root_project_genesis_anchor_v3(reservation, transaction, floor.project(), original, deadline));
                resident.latch(RootProjectGenesisSiteV3::NativeAnchor, resident.native_anchor.as_ref().is_some_and(Result::is_err));
            }
        }
        resident.readback = Some((|| {
            let floor = resident.floor.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
            if self.floor(floor.project())?.as_ref() != Some(floor) || self.intent(floor.project())?.is_some() {
                return Err(SourceGenesisErrorV1::Stale);
            }
            Ok(())
        })());
        resident.latch(RootProjectGenesisSiteV3::Readback, resident.readback.as_ref().is_some_and(Result::is_err));
        resident.posts(self, original, deadline);
        if resident.error().is_some() { Err(()) } else { resident.floor.as_ref().cloned().ok_or(()) }
    }

    /// Rejoins actual Controller Complete and Source ACK under the selected owner.
    ///
    /// # Errors
    /// Rejects missing completion, changed selected floor/reader or actual ACK.
    pub fn confirm_project_genesis_ack_v3(
        &self, packet: &[u8], floor: &SourceHierarchyFloorRecordV1,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        if self.genesis_recipe != RootGenesisOwnerRecipeV3::ProjectV3 { return Err(SourceGenesisErrorV1::Conflict); }
        let accepted = self.accepted.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        if !accepted.completed || self.floor(accepted.acceptance.project())?.as_ref() != Some(floor) { return Err(SourceGenesisErrorV1::Conflict); }
        let challenge = super::super::SourceProjectGenesisChallengeV3::new(self.nonce, floor.project(), Some(floor.receipt().intent_digest()))
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        let observed = super::super::verify_source_project_genesis_readback_v3(packet, &self.pins.source, challenge)
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        if observed.state() != SourceTreeGenesisStateV1::Anchored || observed.receipt() != Some(floor.receipt())
            || observed.names() != accepted.source_names || observed.journal_sequence() != accepted.source_sequence
            || observed.ack_floor_digest() != Some(floor.digest()) || observed.ack_record_digest().is_none()
        { return Err(SourceGenesisErrorV1::Stale); }
        self.recheck()
    }
    pub(in crate::policy_compiler) fn q04_before_rows(
        &self,
    ) -> Result<
        (u64, ProtectedJournalNamesV1, aos_sandbox_core::ObjectDigest),
        super::super::create_q04::CreateQ04ErrorV1,
    > {
        self.recheck()?;
        self.journal.q04_root_before_rows_v1()
    }

    // Only the actual original Root owner checks its entire eligible native
    // suffix. This is nonissuing capacity DATA, not an exported reservation,
    // floor certificate or permission to append future shaped packets.
    pub(in crate::policy_compiler) fn q04_preflight_authority_suffix(
        &self,
        before: (u64, ProtectedJournalNamesV1, aos_sandbox_core::ObjectDigest),
        transactions: &[JournalTransaction],
    ) -> Result<(), super::super::create_q04::CreateQ04ErrorV1> {
        use super::super::create_q04::CreateQ04ErrorV1;

        self.recheck()?;
        if transactions.is_empty() || self.q04_before_rows()? != before
            || self.journal.all_records().any(|(namespace, key, _)| {
                namespace == RecordNamespace::DesiredState && key.starts_with(b"\0aos-q04-root-")
            })
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.journal.preflight_root_q04_capacity_v1(transactions)?;
        self.recheck()?;
        if self.q04_before_rows()? != before {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(())
    }

    // This is a fixed action of the original Root owner, not a Journal getter
    // or caller-provided permission. The enclosing attempt parks the returned
    // outcome before invoking any postappend floor/native/clock bookend.
    pub(in crate::policy_compiler) fn q04_append_original_binding_prefix(
        &mut self,
        history: &super::super::create_q04::Q04RootAuthorityHistoryV1,
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
        source_packet: &[u8],
        original: &super::super::create_q04::RootOriginalInputLoanV1<'_, '_>,
        index: usize,
    ) -> Result<crate::journal::CommitResult, super::super::create_q04::CreateQ04ErrorV1> {
        use super::super::create_q04::CreateQ04ErrorV1;

        self.recheck()?;
        let current = self.current_anchored_floor(source_packet)?;
        current.recheck()?;
        if current.floor().digest() != history.identity().gen1_floor()
            || current.floor().project() != stage.project()
            || stage.staged().challenge() != self.nonce
            || stage.staged().base().next_generation() != history.identity().epoch()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        drop(current);
        history.require_fixed_original(&self.journal)?;
        let stage_index = history.transactions().iter()
            .position(|transaction| transaction.id() == stage.transaction().id())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        stage.require_original_row(&self.journal, index > stage_index)?;
        original.recheck_cut(history.identity())?;
        self.journal.commit_root_q04_original_v1(history, index, original)
    }

    pub(in crate::policy_compiler) fn q04_recheck_original_binding_prefix(
        &self,
        history: &super::super::create_q04::Q04RootAuthorityHistoryV1,
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
        source_packet: &[u8],
    ) -> Result<(), super::super::create_q04::CreateQ04ErrorV1> {
        use super::super::create_q04::CreateQ04ErrorV1;

        self.recheck()?;
        history.require_fixed_original(&self.journal)?;
        let current = self.current_anchored_floor(source_packet)?;
        current.recheck()?;
        if current.floor().digest() != history.identity().gen1_floor()
            || current.floor().project() != stage.project()
            || stage.staged().challenge() != self.nonce
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let stage_index = history.transactions().iter()
            .position(|transaction| transaction.id() == stage.transaction().id())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        stage.require_original_row(&self.journal, history.committed() > stage_index)?;
        self.recheck()?;
        Ok(())
    }

    fn q04_verify_prehold_input<'packet>(
        &self,
        packet: &'packet [u8],
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
        gen1: &Q04RootGen1CutLoanV1<'_>,
    ) -> Result<
        (
            super::super::create_q04::Q04PreholdInputDataV1<'packet>,
            super::super::VerifiedControllerProjectAdmissionV1,
        ),
        super::super::create_q04::CreateQ04ErrorV1,
    > {
        use super::super::create_q04::{CreateQ04ErrorV1, Q04PreholdInputDataV1};
        use super::super::public_create_source::{
            HistoricalCreateProjectSourceHeadsV1, create_project_source_commitment_v1,
        };

        self.recheck()?;
        gen1.recheck()?;
        if !std::ptr::eq(gen1.owner, self) || stage.staged().challenge() != self.nonce {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        // The distinct whole-row DATA signature is verified before any
        // projection. It cannot replace CTP03's purpose or current gen1.
        let request = Q04PreholdInputDataV1::verify(packet, &self.pins.controller)?;
        let fields = request.fields();
        let metadata = fields[0];
        let challenge = super::super::staged_closed_policy_signer_challenge_v2(
            stage.staged(), fields[4],
        )?;
        let controller = super::super::verify_controller_project_admission_readback_v1(
            fields[5], &self.pins.controller,
            super::super::ControllerProjectAdmissionChallengeV1::new(challenge.nonce(), challenge.cut())?,
            self.controller_uid,
        )?;
        let accepted = self.accepted.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let names = ProtectedJournalNamesV1::from_bytes(&metadata[176..224])?;
        let source_names = ProtectedJournalNamesV1::from_bytes(&metadata[224..272])?;
        let sequence = u64::from_be_bytes(crate::hierarchy::genesis_profile::take(metadata, 464)?);
        let source_sequence = u64::from_be_bytes(crate::hierarchy::genesis_profile::take(metadata, 472)?);
        if !accepted.completed
            || controller.project() != gen1.floor().project()
            || controller.project() != stage.project()
            || controller.journal_sequence() != gen1.controller_sequence
            || sequence != gen1.controller_sequence
            || names != gen1.controller_names
            || source_names != accepted.source_names
            || source_sequence != accepted.source_sequence
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }

        let proposal = super::super::binding_v2::ClosedPolicyRootBindingV2::q04_decode(fields[4])?;
        let source = controller.source_commitment();
        let view = proposal.q04_fields(&source);
        let expected_source = create_project_source_commitment_v1(
            *view.operation, *view.operation_revision, *view.accepted_generation,
            *view.sandbox, *view.project,
            HistoricalCreateProjectSourceHeadsV1 {
                projection_revision: *view.projection_revision,
                publisher_generation: controller.publisher_generation(),
                publisher_digest: controller.publisher_digest(),
                cache_domain_head: controller.cache_domain_head(),
                revocation_scope: controller.revocation_scope(),
                revocation_generation: controller.revocation_generation(),
                revocation_head: controller.revocation_head(),
            },
        );
        if *view.operation != controller.operation()
            || *view.sandbox != controller.sandbox()
            || *view.project != controller.project()
            || *view.accepted_generation != 1
            || *view.publisher_generation != controller.publisher_generation()
            || *view.publisher_head != controller.publisher_digest()
            || *view.cache_domain_head != controller.cache_domain_head()
            || *view.revocation_head != controller.revocation_head()
            || *view.ancestry != gen1.floor().tree_head()
            || expected_source != controller.source_commitment()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        gen1.recheck()?;
        self.recheck()?;
        Ok((request, controller))
    }

    // This mode never prepares or repairs genesis. It must already have the
    // exact settled generation-one floor under the verified historical input.
    pub(in crate::policy_compiler) fn q04_require_existing_completed_floor(
        &self,
        project: ProjectId,
    ) -> Result<(), super::super::create_q04::CreateQ04ErrorV1> {
        use super::super::create_q04::CreateQ04ErrorV1;

        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let floor = self.floor(project)?.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if !accepted.historical
            || accepted.vacant
            || accepted.acceptance.project() != project
            || floor.semantic_revision() != 1
            || floor.predecessor().is_some()
            || floor.receipt().acceptance_digest() != accepted.acceptance.digest()
            || floor.roles() != self.pins.digest()
            || self.intent(project)?.is_some()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck()?;
        Ok(())
    }

    // Every permitted Controller/Source self-write requires a newly produced
    // matching Complete packet and Source observation. The old owner engine
    // repeats nonce/pins/full acceptance/named Source sequence/ACK joins; only
    // afterwards may the extra already-verified Controller fields be viewed.
    pub(in crate::policy_compiler) fn q04_refresh_completed_gen1(
        &mut self,
        controller_packet: &[u8],
        source_packet: &[u8],
    ) -> Result<Q04RootGen1CutLoanV1<'_>, super::super::create_q04::CreateQ04ErrorV1> {
        self.accept_controller_readback(controller_packet)?;
        self.q04_require_completed_controller_packet()?;
        let current = self.current_anchored_floor(source_packet)?;
        current.recheck()?;
        let controller_sequence = u64::from_be_bytes(
            crate::hierarchy::genesis_profile::take::<8>(controller_packet, 32)?,
        );
        let names_offset = controller_packet.len() - 192;
        let controller_names = ProtectedJournalNamesV1::from_bytes(
            &controller_packet[names_offset..names_offset + 48],
        )?;
        Ok(Q04RootGen1CutLoanV1 {
            owner: self,
            current,
            controller_sequence,
            controller_names,
        })
    }

    pub(in crate::policy_compiler) fn q04_require_completed_controller_packet(
        &self,
    ) -> Result<(), super::super::create_q04::CreateQ04ErrorV1> {
        if !self.accepted.as_ref().is_some_and(|accepted| accepted.completed) {
            return Err(super::super::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        Ok(())
    }

    // Verification lends only the actual independent Root pin. The complete
    // packet remains in its original flight owner's buffer and success is DATA,
    // not a detachable currentness or writer capability.
    pub(in crate::policy_compiler) fn q04_verify_claim<'packet>(
        &self,
        packet: &'packet [u8],
        identity: &super::super::create_q04::Q04CutIdentityV1,
    ) -> Result<
        super::super::create_q04::Q04ClaimV1<'packet>,
        super::super::create_q04::CreateQ04ErrorV1,
    > {
        self.recheck()?;
        if identity.nonce() != self.nonce
            || identity.controller_uid() != self.controller_uid
            || identity.bytes()[84..88] != self.source_uid.to_be_bytes()
        {
            return Err(super::super::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        let claim = super::super::create_q04::Q04ClaimV1::verify(
            packet,
            &self.pins.controller,
            identity,
        )?;
        self.recheck()?;
        Ok(claim)
    }

    // The two real Controller-purpose packets share the Root-created nonce
    // and actual Stage cut. The old current signer is never called under a
    // hold: its prehold packet is retained and joined to the fresh held packet.
    pub(in crate::policy_compiler) fn q04_verify_controller_cut(
        &self,
        current_packet: &[u8],
        held_packet: &[u8],
        proposed: &[u8],
        gen1: &Q04RootGen1CutLoanV1<'_>,
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
        identity: &super::super::create_q04::Q04CutIdentityV1,
    ) -> Result<
        (
            super::super::VerifiedControllerProjectAdmissionV1,
            super::super::VerifiedControllerHoldReadbackV1,
        ),
        super::super::create_q04::CreateQ04ErrorV1,
    > {
        self.q04_verify_controller_cut_for(current_packet, held_packet, proposed,
            gen1, stage, identity, Q04ControllerPacketPositionV1::CurrentHeld)
    }

    #[allow(clippy::too_many_arguments)]
    fn q04_verify_controller_cut_for(
        &self,
        current_packet: &[u8],
        held_packet: &[u8],
        proposed: &[u8],
        gen1: &Q04RootGen1CutLoanV1<'_>,
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
        identity: &super::super::create_q04::Q04CutIdentityV1,
        position: Q04ControllerPacketPositionV1,
    ) -> Result<(super::super::VerifiedControllerProjectAdmissionV1,
        super::super::VerifiedControllerHoldReadbackV1), super::super::create_q04::CreateQ04ErrorV1> {
        use super::super::create_q04::CreateQ04ErrorV1;

        self.recheck()?;
        gen1.recheck()?;
        if !std::ptr::eq(gen1.owner, self)
            || gen1.floor().digest() != identity.gen1_floor()
            || stage.staged().challenge() != self.nonce
            || identity.nonce() != self.nonce
            || identity.controller_uid() != self.controller_uid
            || identity.project() != stage.project()
            || identity.epoch() != stage.staged().base().next_generation()
            || super::super::closed_policy_binding_digest_v2(proposed)? != identity.binding()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        // Stage's record cut authenticates its original reservation. The
        // Controller/Cache signer cut additionally binds the complete B664;
        // derive it once through the existing sole challenge recipe.
        let challenge = super::super::staged_closed_policy_signer_challenge_v2(
            stage.staged(), proposed,
        )?;
        let current = super::super::verify_controller_project_admission_readback_v1(
            current_packet,
            &self.pins.controller,
            super::super::ControllerProjectAdmissionChallengeV1::new(challenge.nonce(), challenge.cut())?,
            self.controller_uid,
        )?;
        let held = super::super::verify_controller_hold_readback_v1(
            held_packet,
            &self.pins.controller,
            super::super::ControllerHoldReadbackChallengeV1::new(challenge.nonce(), challenge.cut())?,
            self.controller_uid,
        )?;
        let accepted = self.accepted.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if !accepted.completed
            || accepted.acceptance.project() != current.project()
            || current.project() != identity.project()
            || current.operation() != identity.operation()
            || current.sandbox() != identity.sandbox()
            || held.operation() != current.operation()
            || held.sandbox() != current.sandbox()
            || held.source() != current.source_commitment()
            || current.journal_sequence() > held.journal_sequence()
            || held.binding() != identity.binding()
            || held.epoch() != identity.epoch()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        match position {
            Q04ControllerPacketPositionV1::CurrentHeld => {
                if held.journal_sequence() != gen1.controller_sequence {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
            }
            Q04ControllerPacketPositionV1::OriginalHeld { original_next } => {
                if current.journal_sequence() != original_next
                    || held.journal_sequence() != original_next.checked_add(5)
                        .ok_or(CreateQ04ErrorV1::Bounds)?
                    || held.journal_sequence() >= gen1.controller_sequence
                {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
            }
        }
        gen1.recheck()?;
        self.recheck()?;
        Ok((current, held))
    }

    // Source reconstruction reads the independently retained actual Root
    // records/pins. It never adopts a supplied key, a Controller journal or a
    // serialized cache-domain brand. Returned values are signed provenance.
    pub(in crate::policy_compiler) fn q04_signed_project_sources(
        &self,
        project_input: &[u8],
        deployment_inputs: &super::super::PolicyDeploymentInputsV1<'_>,
        now_unix_seconds: i64,
    ) -> Result<
        (
            super::super::VerifiedSignedProjectPolicySourceV2,
            super::super::PolicyDeploymentHeadV1,
            super::super::PolicyDeploymentSourcesV1,
        ),
        super::super::create_q04::CreateQ04ErrorV1,
    > {
        use super::super::create_q04::CreateQ04ErrorV1;
        use super::super::project_source_v2::{HEAD_KEY_V2, INPUT_KEY_V2};

        self.recheck()?;
        let namespace = RecordNamespace::DesiredState;
        let pins = self.journal.get(namespace, SIGNER_PINS_KEY)
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let (deployment_generation, deployment_key, project_generation, project_key) =
            decode_policy_signer_pins_v1(pins)?;
        let deployment_packet = self.journal.get(namespace, HEAD_KEY)
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let deployment = super::super::verify_policy_deployment_head_v1(
            deployment_packet,
            deployment_inputs,
            &deployment_key,
            now_unix_seconds,
        )?;
        let decoded = super::super::decode_policy_deployment_sources_v1(
            deployment_inputs,
            deployment,
        )?;
        let project_packet = self.journal.get(namespace, HEAD_KEY_V2)
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if self.journal.get(namespace, INPUT_KEY_V2) != Some(project_input) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let project = super::super::verify_signed_project_policy_source_v2(
            project_packet,
            project_input,
            &project_key,
            now_unix_seconds,
        )?;
        if project.head().deployment_signer_generation() != deployment_generation
            || project.head().project_signer_generation() != project_generation
            || project.head().prerequisite_claims()[1] != deployment.packet_digest()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck()?;
        Ok((project, deployment, decoded))
    }

    // This uses the actual Root-retained Cache pin and the unchanged fixed
    // read-only replay engine. It does not invent a spent V8 challenge or a
    // physical writer lease; the original Q04 caller retains those writers.
    pub(in crate::policy_compiler) fn q04_verify_cache_cut(
        &self,
        packet: &[u8],
        proposed: &[u8],
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
        identity: &super::super::create_q04::Q04CutIdentityV1,
        cache_uid: u32,
    ) -> Result<
        crate::cache_residency::VerifiedClosedCacheOwnerReadbackV2,
        super::super::create_q04::CreateQ04ErrorV1,
    > {
        use super::super::cache_readback_pin::CACHE_PIN_KEY;
        use super::super::create_q04::CreateQ04ErrorV1;

        self.recheck()?;
        if identity.nonce() != self.nonce
            || identity.project() != stage.project()
            || identity.epoch() != stage.staged().base().next_generation()
            || super::super::closed_policy_binding_digest_v2(proposed)? != identity.binding()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let credential = self.journal.get(RecordNamespace::DesiredState, CACHE_PIN_KEY)
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let before = super::super::read_fixed_policy_cache_hold_v1()?;
        let observed = self.q04_verify_original_cache_packet(packet, proposed, stage, identity, cache_uid)?;
        if observed.hold() != before.hold
            || observed.quota_digest() != before.replay.quota_digest
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }

        self.recheck()?;
        let after = super::super::read_fixed_policy_cache_hold_v1()?;
        if before != after
            || self.journal.get(RecordNamespace::DesiredState, CACHE_PIN_KEY) != Some(credential)
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck()?;
        Ok(observed)
    }

    // This authenticates only the original Cache packet. Terminal consumers
    // separately replay its actual fixed four-journal Q04 released/clear cut;
    // the old held bytes can never stand in for a current Cache observation.
    fn q04_verify_original_cache_packet(
        &self,
        packet: &[u8],
        proposed: &[u8],
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
        identity: &super::super::create_q04::Q04CutIdentityV1,
        cache_uid: u32,
    ) -> Result<crate::cache_residency::VerifiedClosedCacheOwnerReadbackV2,
        super::super::create_q04::CreateQ04ErrorV1> {
        use super::super::cache_readback_pin::CACHE_PIN_KEY;
        use super::super::create_q04::CreateQ04ErrorV1;

        self.recheck()?;
        if cache_uid == 0 || identity.controller_uid() != self.controller_uid
            || identity.nonce() != self.nonce || identity.project() != stage.project()
            || identity.epoch() != stage.staged().base().next_generation()
            || super::super::closed_policy_binding_digest_v2(proposed)? != identity.binding()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let pin = self.journal.get(RecordNamespace::DesiredState, CACHE_PIN_KEY)
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let signer = crate::cache_residency::PinnedCacheOwnerReadbackSignerV1::decode(pin)?;
        let challenge = super::super::staged_closed_policy_signer_challenge_v2(stage.staged(), proposed)?;
        // The signed physical root belongs to the actual Controller. The
        // separate Cache-view UID still governs named journal/idmap checks.
        let observed = crate::cache_residency::verify_closed_cache_owner_readback_v2(
            packet, &signer,
            crate::cache_residency::CacheOwnerReadbackChallengeV1::new(challenge.nonce(), challenge.cut())?,
            self.controller_uid,
        )?;
        if !observed.hold().is_held() || observed.hold().project() != identity.project()
            || observed.hold().binding() != identity.binding() || observed.hold().epoch() != identity.epoch()
            || observed.quota_digest() != identity.cache_quota()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck()?;
        Ok(observed)
    }

    // Preview borrows the actual completed gen1 owner before lending its same
    // journal to the existing binding engine. No current-floor loan survives
    // that mutable borrow and the returned Stage recipe confers no authority.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::policy_compiler) fn q04_preview_stage(
        &mut self,
        source_packet: &[u8],
        expected_deployment_packet: &[u8],
        deployment_signer_generation: u64,
        deployment_key: &VerifyingKey,
        project_packet: &[u8],
        project_input: &[u8],
        project_signer_generation: u64,
        project_key: &VerifyingKey,
        controller_gid: u32,
        now_unix_seconds: i64,
    ) -> Result<
        super::super::binding_v2::Q04RootStageRecipeV1,
        super::super::create_q04::CreateQ04ErrorV1,
    > {
        let project = {
            let current = self.current_anchored_floor(source_packet)?;
            current.recheck()?;
            current.floor().project()
        };
        let recipe = super::super::binding_v2::q04_preview_stage_in_journal_v1(
            &mut self.journal,
            expected_deployment_packet,
            deployment_signer_generation,
            deployment_key,
            project_packet,
            project_input,
            project_signer_generation,
            project_key,
            self.controller_uid,
            controller_gid,
            now_unix_seconds,
            self.nonce,
        )?;
        if recipe.project() != project || recipe.staged().challenge() != self.nonce {
            return Err(super::super::create_q04::CreateQ04ErrorV1::ChangedCut);
        }

        self.current_anchored_floor(source_packet)?.recheck()?;
        Ok(recipe)
    }

    // The actual daemon's retained input bytes are verified against the same
    // independently pinned Root rows. The returned encoding is nonissuing
    // Preview DATA; neither a future native head nor a detached Cut enters it.
    pub(in crate::policy_compiler) fn q04_encode_preview(
        &self,
        output: &mut Vec<u8>,
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
        inputs: &super::super::PolicyDeploymentInputsV1<'_>,
        project_input: &[u8],
        original_clock: aos_sandbox_core::RawPairedClockSample,
        now_unix_seconds: i64,
    ) -> Result<(), super::super::create_q04::CreateQ04ErrorV1> {
        use super::super::create_q04::CreateQ04ErrorV1;
        use super::super::project_source_v2::{HEAD_KEY_V2, INPUT_KEY_V2};

        self.recheck()?;
        let (project, _, _) = self.q04_signed_project_sources(project_input, inputs, now_unix_seconds)?;
        if project.head().project() != stage.project()
            || stage.staged().challenge() != self.nonce
            || self.journal.get(RecordNamespace::DesiredState, INPUT_KEY_V2) != Some(project_input)
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let (sequence, names, before_rows) = self.journal.q04_root_before_rows_v1()?;
        let deadline = original_clock.boottime_nanoseconds().checked_add(65_000_000_000)
            .ok_or(CreateQ04ErrorV1::Bounds)?;
        let mut metadata = [0; 120];
        metadata[..16].copy_from_slice(&original_clock.host_boot_id());
        metadata[16..24].copy_from_slice(&original_clock.boottime_nanoseconds().to_be_bytes());
        metadata[24..32].copy_from_slice(&deadline.to_be_bytes());
        metadata[32..40].copy_from_slice(&sequence.to_be_bytes());
        metadata[40..88].copy_from_slice(&names.to_bytes());
        metadata[88..120].copy_from_slice(before_rows.as_bytes());
        let staged = stage.preview_fields();
        let deployment_packet = self.journal.get(RecordNamespace::DesiredState, HEAD_KEY)
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let project_packet = self.journal.get(RecordNamespace::DesiredState, HEAD_KEY_V2)
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        super::super::create_q04::encode_q04_preview_body_v1(
            output,
            [
                &metadata, &staged, deployment_packet,
                inputs.node, inputs.site, inputs.backend, inputs.catalogs,
                project_packet, project_input,
            ],
            self.nonce,
        )?;
        self.recheck()?;
        if self.journal.q04_root_before_rows_v1()? != (sequence, names, before_rows) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(())
    }

    /// Opens the actual fixed protected Root owner for one genesis flight.
    ///
    /// Both UIDs come from the daemon's privileged service configuration, not
    /// request claims. No instance is created merely by opening this owner.
    ///
    /// # Errors
    /// Rejects non-Root/wrong fixed custody, unsafe names, malformed retained
    /// instance/history, missing independent role pins, or changed credentials.
    pub fn open_fixed(controller_uid: u32, source_uid: u32) -> Result<Self, SourceGenesisErrorV1> {
        if controller_uid == 0 || source_uid == 0 {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
        let (journal, _) = Journal::open_protected_at(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_AUTHORITY_JOURNAL,
            policy_authority_journal_limits(),
        )?;
        capacity::require_owner(&journal)?;
        let pins = RootGenesisRolePinsV1::load(&journal)?;
        validate_history(&journal, &pins)?;
        let names = journal.protected_writer_physical_names_v1()?;
        let owner = Self {
            journal,
            pins,
            names,
            nonce: fresh_root_nonce()?,
            controller_uid,
            source_uid,
            accepted: None,
            genesis_recipe: RootGenesisOwnerRecipeV3::StrictV1,
            successor_recipe: super::wire::FirstSuccessorWireRecipeV3::StrictV2,
        };
        owner.recheck()?;
        Ok(owner)
    }

    /// Returns the Root-created challenge for this one original stream flight.
    #[must_use]
    pub const fn nonce(&self) -> [u8; 16] {
        self.nonce
    }

    /// Borrows the independently pinned Source role for the existing signer RPC.
    ///
    /// This public key does not grant mutation, ancestry or live Root custody.
    #[must_use]
    pub const fn source_readback_pin(&self) -> &PinnedSourceHoldReadbackSignerV1 {
        &self.pins.source
    }

    /// Derives comparison data from the exact retained intent or semantic floor.
    ///
    /// The signer treats this as untrusted data and rejoins its actual receipt.
    /// This projection never supplies the original pending nonce: only the
    /// Source journal retains it after Root settles and deletes its intent.
    ///
    /// # Errors
    /// Rejects missing/foreign historical acceptance, changed Root custody,
    /// conflicting intent/floor roles, or mismatched original accepted input.
    pub fn source_genesis_intent_context_v1(
        &self,
    ) -> Result<SourceTreeGenesisIntentContextV1, SourceGenesisErrorV1> {
        self.require_strict_genesis_recipe_v1()?;
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        if !accepted.historical {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let project = accepted.acceptance.project();
        let context = if let Some(intent) = self.intent(project)? {
            require_acceptance(&intent, accepted, self.source_uid)?;
            SourceTreeGenesisIntentContextV1::new(
                intent.source_uid(),
                intent.roles(),
                intent.accepted_input().clone(),
            )?
        } else {
            let floor = self.floor(project)?.ok_or(SourceGenesisErrorV1::Conflict)?;
            let context = SourceTreeGenesisIntentContextV1::new(
                self.source_uid,
                floor.roles(),
                accepted.acceptance.clone(),
            )?;
            context.require_actual_receipt(floor.receipt(), None)?;
            context
        };
        self.recheck()?;
        Ok(context)
    }

    /// Returns the currently held deployment expiry, or zero for exact history.
    ///
    /// # Errors
    /// Rejects missing accepted input, unsafe Root custody, or unavailable
    /// current deployment authority for a genuinely new Source append.
    pub fn current_admission_expiry(&self) -> Result<i64, SourceGenesisErrorV1> {
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        if accepted.historical {
            return Ok(0);
        }
        require_current_deployment(&self.journal)
    }

    /// Rejoins an existing floor with the actual signed Source receipt, if present.
    ///
    /// The returned record is data only. This cannot turn a missing floor or
    /// per-project lookup into an Empty observation or a prepare authority.
    ///
    /// # Errors
    /// Rejects a missing/foreign accepted input or an existing floor without
    /// its exact Source signer observation under this original flight nonce.
    pub fn recover_floor(
        &mut self,
        source_packet: Option<&[u8]>,
    ) -> Result<Option<SourceHierarchyFloorRecordV1>, SourceGenesisErrorV1> {
        self.recheck()?;
        let project = self
            .accepted
            .as_ref()
            .ok_or(SourceGenesisErrorV1::Stale)?
            .acceptance
            .project();
        if self.floor(project)?.is_none() {
            return Ok(None);
        }
        self.anchor(source_packet.ok_or(SourceGenesisErrorV1::Conflict)?)
            .map(Some)
    }

    /// Rejoins exact fixed names, current independent pins, and semantic state.
    ///
    /// # Errors
    /// Rejects replaced names, poisoned custody, changed role pins, or a
    /// malformed/foreign Root instance, intent, floor, or reserved suffix.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        capacity::require_owner(&self.journal)?;
        self.pins.recheck(&self.journal)?;
        if self.journal.protected_writer_physical_names_v1()? != self.names {
            return Err(SourceGenesisErrorV1::Stale);
        }
        validate_history(&self.journal, &self.pins)
    }

    /// Selects the exact Source read-only probe after genuine Controller verification.
    ///
    /// Historical probes can only name an existing intent or floor. An absent
    /// project never converts a signed query or NotFound into genesis authority.
    ///
    /// # Errors
    /// Rejects signature/nonce/UID/input substitution or foreign retained work.
    pub fn accept_controller_readback(
        &mut self,
        packet: &[u8],
    ) -> Result<Option<(Option<ProjectId>, SourceTreeGenesisChallengeV1)>, SourceGenesisErrorV1>
    {
        self.accept_controller_readback_for_scope(packet, true)
    }

    /// Selects only exact already materialized history for credential recovery.
    ///
    /// # Errors
    /// Rejects all Empty/vacant current-admission packets, even if a retained
    /// deployment HEAD has not expired, as well as foreign historical custody.
    pub fn accept_historical_controller_readback(
        &mut self,
        packet: &[u8],
    ) -> Result<Option<(Option<ProjectId>, SourceTreeGenesisChallengeV1)>, SourceGenesisErrorV1>
    {
        self.accept_controller_readback_for_scope(packet, false)
    }

    fn accept_controller_readback_for_scope(
        &mut self,
        packet: &[u8],
        permit_current: bool,
    ) -> Result<Option<(Option<ProjectId>, SourceTreeGenesisChallengeV1)>, SourceGenesisErrorV1>
    {
        self.require_strict_genesis_recipe_v1()?;
        self.recheck()?;
        let accepted = controller_readback::verify(
            packet,
            &self.pins.controller,
            self.nonce,
            self.controller_uid,
            self.source_uid,
        )?;
        if !permit_current && !accepted.historical {
            return Err(SourceGenesisErrorV1::AdmissionClosed);
        }
        self.pins
            .verify_administrative_input(&accepted.acceptance)?;
        // Global Empty can recover an instance/intent created before the first
        // Source append. It cannot reset custody after any project was anchored.
        // Later projects require the distinct actual same-instance vacant cut.
        if accepted.source_instance.is_none()
            && self
                .journal
                .records(RecordNamespace::DesiredState)
                .any(|(key, _)| key.starts_with(FLOOR_PREFIX))
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        if self.accepted.as_ref().is_some_and(|prior| {
            prior.acceptance != accepted.acceptance
                || prior.source_names != accepted.source_names
                || prior.historical && !accepted.historical
                || prior.completed && !accepted.completed
        }) {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let project = accepted.acceptance.project();
        if accepted.vacant {
            let instance = self
                .journal
                .get(RecordNamespace::DesiredState, INSTANCE_KEY)
                .map(decode_instance)
                .transpose()?;
            if instance.is_none()
                || accepted.source_instance != instance
                || self.floor(project)?.is_some()
            {
                return Err(SourceGenesisErrorV1::Conflict);
            }
            if let Some(intent) = self.intent(project)? {
                require_acceptance(&intent, &accepted, self.source_uid)?;
            }
            self.accepted = Some(accepted);
            return Ok(None);
        }
        let intent_digest = if accepted.historical {
            if let Some(floor) = self.floor(project)? {
                if floor.receipt().acceptance_digest() != accepted.acceptance.digest() {
                    return Err(SourceGenesisErrorV1::Conflict);
                }
                Some(floor.receipt().intent_digest())
            } else {
                Some(
                    self.intent(project)?
                        .ok_or(SourceGenesisErrorV1::Conflict)?
                        .digest(),
                )
            }
        } else {
            None
        };
        let challenge = SourceTreeGenesisChallengeV1::new(self.nonce, intent_digest)
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        self.accepted = Some(accepted);
        Ok(Some((intent_digest.map(|_| project), challenge)))
    }

    /// Durably prepares the exact capacity-backed intent from both owner readbacks.
    ///
    /// Instance creation requires the actual Source signer's global Empty
    /// observation joined to the held Source cut. It cannot adopt preexisting
    /// Tree/lineage/receipt custody. Existing prepared materialization permits
    /// exact historical recovery, never a new expired genesis.
    ///
    /// # Errors
    /// Rejects mismatched Source cut/signature, orphan materialization, changed
    /// authority or history, unavailable positive deployment, or insufficient
    /// intent/floor suffix capacity before any Source mutation.
    pub fn prepare(
        &mut self,
        source_packet: Option<&[u8]>,
    ) -> Result<RootSourceGenesisIntentRecordV1, SourceGenesisErrorV1> {
        self.require_strict_genesis_recipe_v1()?;
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        let project = accepted.acceptance.project();
        if self.floor(project)?.is_some() {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let prior = self.intent(project)?;
        let challenge = SourceTreeGenesisChallengeV1::new(
            self.nonce,
            accepted
                .historical
                .then(|| prior.as_ref().map(RootSourceGenesisIntentRecordV1::digest))
                .flatten(),
        )
        .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        let observed = if accepted.vacant {
            if source_packet.is_some() {
                return Err(SourceGenesisErrorV1::NonCanonical);
            }
            let instance = self
                .journal
                .get(RecordNamespace::DesiredState, INSTANCE_KEY)
                .map(decode_instance)
                .transpose()?;
            if instance.is_none() || accepted.source_instance != instance {
                return Err(SourceGenesisErrorV1::Conflict);
            }
            None
        } else {
            let observed = verify_source_tree_genesis_readback_v2(
                source_packet.ok_or(SourceGenesisErrorV1::NonCanonical)?,
                &self.pins.source,
                challenge,
            )
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
            require_same_source_cut(accepted, &observed)?;
            Some(observed)
        };
        if let Some(intent) = prior {
            require_acceptance(&intent, accepted, self.source_uid)?;
            if let Some(receipt) = observed
                .as_ref()
                .and_then(VerifiedSourceTreeGenesisReadbackV1::receipt)
            {
                if receipt.intent_digest() != intent.digest()
                    || receipt.instance() != intent.instance()
                    || receipt.acceptance_digest() != intent.acceptance()
                {
                    return Err(SourceGenesisErrorV1::Conflict);
                }
            } else {
                if accepted.historical {
                    return Err(SourceGenesisErrorV1::Conflict);
                }
                require_current_deployment(&self.journal)?;
            }
            self.recheck()?;
            return Ok(intent);
        }
        if accepted.historical
            || observed
                .as_ref()
                .is_some_and(|observed| observed.state() != SourceTreeGenesisStateV1::Empty)
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        // Refuse a foreign flight and the exact project ceiling before writing
        // even an instance or intent. Postcommit replay is not an admission cut.
        if self
            .journal
            .records(RecordNamespace::DesiredState)
            .any(|(key, _)| key.starts_with(INTENT_PREFIX))
            || self
                .journal
                .records(RecordNamespace::DesiredState)
                .filter(|(key, _)| key.starts_with(FLOOR_PREFIX))
                .count()
                >= MAXIMUM_PROJECTS
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        require_current_deployment(&self.journal)?;
        let acceptance = accepted.acceptance.clone();
        self.ensure_initial_instance()?;
        let instance = decode_instance(
            self.journal
                .get(RecordNamespace::DesiredState, INSTANCE_KEY)
                .ok_or(SourceGenesisErrorV1::Stale)?,
        )?;
        let intent = RootSourceGenesisIntentRecordV1::new(
            instance,
            self.source_uid,
            self.nonce,
            acceptance,
            self.pins.digest(),
        )?;
        let request = capacity::request(&intent);
        let prepared = self
            .journal
            .prepare_global_capacity_reservation_v1(request, capacity::admission_id(&intent))?;
        let transaction = JournalTransaction::new(
            capacity::admission_id(&intent),
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    capacity::intent_key(&intent),
                    intent.record_bytes().to_vec(),
                ),
                prepared.record().clone(),
            ],
        )?;
        {
            let authority = self
                .journal
                .claim_global_capacity_reservation_authority(request.purpose)?;
            authority.preflight_global_capacity_reservation_v1(&prepared, &transaction)?;
        }
        self.recheck()?;
        require_current_deployment(&self.journal)?;
        self.journal
            .commit_global_capacity_reservation_v1(prepared, &transaction)?;
        if self.intent(project)? != Some(intent.clone()) {
            return Err(SourceGenesisErrorV1::Stale);
        }
        self.recheck()?;
        Ok(intent)
    }

    /// Atomically anchors the exact actual Source receipt using its reserved suffix.
    ///
    /// # Errors
    /// Rejects a mismatched original signed observation/cut, missing intent,
    /// changed semantic predecessor or instance, conflicting floor, or failed
    /// durable readback. Exact replay does not append or increment a frame floor.
    pub fn anchor(
        &mut self,
        source_packet: &[u8],
    ) -> Result<SourceHierarchyFloorRecordV1, SourceGenesisErrorV1> {
        self.require_strict_genesis_recipe_v1()?;
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        let project = accepted.acceptance.project();
        let prior_floor = self.floor(project)?;
        let intent = self.intent(project)?;
        let intent_digest = prior_floor
            .as_ref()
            .map(|floor| floor.receipt().intent_digest())
            .or_else(|| intent.as_ref().map(RootSourceGenesisIntentRecordV1::digest))
            .ok_or(SourceGenesisErrorV1::Conflict)?;
        let challenge = SourceTreeGenesisChallengeV1::new(self.nonce, Some(intent_digest))
            .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        let observed =
            verify_source_tree_genesis_readback_v2(source_packet, &self.pins.source, challenge)
                .map_err(|_| SourceGenesisErrorV1::Stale)?;
        require_same_source_cut(accepted, &observed)?;
        let receipt = observed
            .receipt()
            .ok_or(SourceGenesisErrorV1::Conflict)?
            .clone();
        if receipt.acceptance_digest() != accepted.acceptance.digest()
            || &receipt.seed_packet() != accepted.acceptance.seed_packet()
            || receipt.auth_packet() != accepted.acceptance.auth_packet()
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let floor = SourceHierarchyFloorRecordV1::new(receipt, self.pins.digest())?;
        if let Some(prior) = prior_floor {
            if prior != floor {
                return Err(SourceGenesisErrorV1::Conflict);
            }
            self.recheck()?;
            return Ok(prior);
        }
        let intent = intent.ok_or(SourceGenesisErrorV1::Conflict)?;
        require_acceptance(&intent, accepted, self.source_uid)?;
        let request = capacity::request(&intent);
        let identity = self
            .journal
            .root_source_genesis_capacity_identity_v1(&request, capacity::admission_id(&intent))?;
        let reservation = self
            .journal
            .recover_global_capacity_reservation_v1(identity)?;
        let transaction = JournalTransaction::new(
            capacity::floor_transaction_id(&floor),
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    capacity::floor_key(&floor),
                    floor.record_bytes().to_vec(),
                ),
                JournalRecord::delete(RecordNamespace::DesiredState, capacity::intent_key(&intent)),
                reservation.settlement_record(),
            ],
        )?;
        self.recheck()?;
        {
            let mut authority = self
                .journal
                .claim_global_capacity_reservation_authority(request.purpose)?;
            let preflight = authority.preflight_reserved_terminal_v1(&reservation, &transaction)?;
            authority.commit_reserved_terminal_v1(&preflight, reservation, &transaction)?;
        }
        if self.floor(project)? != Some(floor.clone()) || self.intent(project)?.is_some() {
            return Err(SourceGenesisErrorV1::Stale);
        }
        self.recheck()?;
        Ok(floor)
    }

    /// Rejoins durable Controller completion and Source ACK with the exact floor.
    ///
    /// This is the Root server's final observation, not a factory for Source
    /// or Controller proofs. Only the dedicated owner-derived final readback
    /// attests the actual Controller Complete row joined to this Source ACK;
    /// ordinary historical acceptance readback cannot authorize final release.
    ///
    /// # Errors
    /// Rejects absent or changed floors, an unanchored Source observation,
    /// missing Controller completion, mismatched original receipt/cuts, or a
    /// different durable Source ACK.
    pub fn confirm_source_ack(
        &self,
        source_packet: &[u8],
        floor: &SourceHierarchyFloorRecordV1,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.require_strict_genesis_recipe_v1()?;
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(SourceGenesisErrorV1::Stale)?;
        if !accepted.completed || self.floor(accepted.acceptance.project())?.as_ref() != Some(floor)
        {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        let challenge =
            SourceTreeGenesisChallengeV1::new(self.nonce, Some(floor.receipt().intent_digest()))
                .map_err(|_| SourceGenesisErrorV1::NonCanonical)?;
        let observed =
            verify_source_tree_genesis_readback_v2(source_packet, &self.pins.source, challenge)
                .map_err(|_| SourceGenesisErrorV1::Stale)?;
        require_same_source_cut(accepted, &observed)?;
        super::current::require_anchored_observation(&observed, floor)?;
        self.recheck()
    }

    fn ensure_initial_instance(&mut self) -> Result<(), SourceGenesisErrorV1> {
        if self
            .journal
            .get(RecordNamespace::DesiredState, INSTANCE_KEY)
            .is_some()
        {
            return Ok(());
        }
        // This method is called only after independent signed global Empty and
        // held Controller/Source cut joins. No caller can supply the instance.
        let mut instance = [0; 32];
        instance[..16].copy_from_slice(&fresh_root_nonce()?);
        instance[16..].copy_from_slice(&fresh_root_nonce()?);
        let bytes = instance_bytes(instance)?;
        let digest = crate::hierarchy::genesis_profile::hash(INSTANCE_TRANSACTION_DOMAIN, &bytes);
        let mut id = [0; 16];
        id.copy_from_slice(&digest.as_bytes()[..16]);
        let transaction = JournalTransaction::new(
            id,
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    INSTANCE_KEY.to_vec(),
                    bytes.to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    PINS_KEY.to_vec(),
                    self.pins.record_bytes().to_vec(),
                ),
            ],
        )?;
        self.recheck()?;
        self.journal
            .preflight_transactions(std::slice::from_ref(&transaction))?;
        self.journal
            .commit_root_source_genesis_initialization_v1(&transaction)?;
        if self
            .journal
            .get(RecordNamespace::DesiredState, INSTANCE_KEY)
            != Some(bytes.as_slice())
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        self.recheck()
    }

    fn intent(
        &self,
        project: ProjectId,
    ) -> Result<Option<RootSourceGenesisIntentRecordV1>, SourceGenesisErrorV1> {
        self.journal
            .get(
                RecordNamespace::DesiredState,
                &project_key(INTENT_PREFIX, project),
            )
            .map(RootSourceGenesisIntentRecordV1::from_record_bytes)
            .transpose()
    }

    pub(super) fn floor(
        &self,
        project: ProjectId,
    ) -> Result<Option<SourceHierarchyFloorRecordV1>, SourceGenesisErrorV1> {
        // Revision one is historical once any exact successor obligation exists.
        // It must never certify a populated current Tree or a Q04/gen1 loan.
        if super::successor_owner::retained_root_first_successor_v2(&self.journal, project)?.is_some() {
            return Err(SourceGenesisErrorV1::AdmissionClosed);
        }
        self.journal
            .get(
                RecordNamespace::DesiredState,
                &project_key(FLOOR_PREFIX, project),
            )
            .map(SourceHierarchyFloorRecordV1::from_record_bytes)
            .transpose()
    }
}

fn require_acceptance(
    intent: &RootSourceGenesisIntentRecordV1,
    accepted: &VerifiedControllerSourceGenesisReadbackV1,
    source_uid: u32,
) -> Result<(), SourceGenesisErrorV1> {
    if intent.accepted_input() != &accepted.acceptance || intent.source_uid() != source_uid {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    Ok(())
}

fn require_same_source_cut(
    controller: &VerifiedControllerSourceGenesisReadbackV1,
    source: &VerifiedSourceTreeGenesisReadbackV1,
) -> Result<(), SourceGenesisErrorV1> {
    if controller.source_names != source.names()
        || controller.source_sequence != source.journal_sequence()
    {
        return Err(SourceGenesisErrorV1::Stale);
    }
    if controller.source_instance != source.receipt().map(|receipt| receipt.instance()) {
        return Err(SourceGenesisErrorV1::Stale);
    }
    Ok(())
}

pub(super) fn require_current_deployment(journal: &Journal) -> Result<i64, SourceGenesisErrorV1> {
    let namespace = RecordNamespace::DesiredState;
    let (generation, key, _, _) = decode_policy_signer_pins_v1(
        journal
            .get(namespace, SIGNER_PINS_KEY)
            .ok_or(SourceGenesisErrorV1::AdmissionClosed)?,
    )
    .map_err(|_| SourceGenesisErrorV1::AdmissionClosed)?;
    let packet = journal
        .get(namespace, HEAD_KEY)
        .ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
    verify_historical_packet(packet, &key).map_err(|_| SourceGenesisErrorV1::AdmissionClosed)?;
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| SourceGenesisErrorV1::AdmissionClosed)?
            .as_secs(),
    )
    .map_err(|_| SourceGenesisErrorV1::AdmissionClosed)?;
    let read = |offset| crate::hierarchy::genesis_profile::take::<8>(packet, offset);
    let expires = i64::from_be_bytes(read(24)?);
    if u64::from_be_bytes(read(8)?) != generation
        || i64::from_be_bytes(read(16)?) > now
        || now >= expires
    {
        return Err(SourceGenesisErrorV1::AdmissionClosed);
    }
    Ok(expires)
}

/// Reports genuine retained Root intent/floor history for the recovery listener.
///
/// Absence is only startup routing data. A retained instance alone cannot
/// reconstruct Source custody or authorize a fresh expired administrative input.
///
/// # Errors
/// Rejects unsafe fixed Root custody, malformed retained history or changed
/// independently pinned roles. It grants no fresh deployment currentness.
pub fn fixed_root_source_genesis_recovery_available_v1() -> Result<bool, SourceGenesisErrorV1> {
    let (journal, _) = Journal::open_protected_at(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        policy_authority_journal_limits(),
    )?;
    capacity::require_owner(&journal)?;
    let retained = journal
        .records(RecordNamespace::DesiredState)
        .any(|(key, _)| key.starts_with(INTENT_PREFIX) || key.starts_with(FLOOR_PREFIX));
    if !retained {
        return Ok(false);
    }
    let pins = RootGenesisRolePinsV1::load(&journal)?;
    validate_history(&journal, &pins)?;
    Ok(true)
}

pub(super) fn validate_history(
    journal: &Journal,
    pins: &RootGenesisRolePinsV1,
) -> Result<(), SourceGenesisErrorV1> {
    let namespace = RecordNamespace::DesiredState;
    let instance = journal
        .get(namespace, INSTANCE_KEY)
        .map(decode_instance)
        .transpose()?;
    let retained_pins = journal.get(namespace, PINS_KEY);
    if instance.is_some() != retained_pins.is_some()
        || retained_pins.is_some_and(|bytes| bytes != pins.record_bytes())
    {
        return Err(SourceGenesisErrorV1::Stale);
    }
    let mut intents = 0_usize;
    let mut floors = 0_usize;
    let mut capacities = journal.root_source_genesis_capacity_ids_v1()?;
    for (key, value) in journal.records(namespace) {
        if key.starts_with(INTENT_PREFIX) {
            let intent = RootSourceGenesisIntentRecordV1::from_record_bytes(value)?;
            if instance != Some(intent.instance())
                || key != capacity::intent_key(&intent)
                || intent.roles() != pins.digest()
                || journal
                    .get(namespace, &project_key(FLOOR_PREFIX, intent.project()))
                    .is_some()
            {
                return Err(SourceGenesisErrorV1::Stale);
            }
            pins.verify_administrative_input(intent.accepted_input())?;
            let capacity_id = journal.root_source_genesis_capacity_identity_v1(
                &capacity::request(&intent),
                capacity::admission_id(&intent),
            )?;
            let position = capacities
                .iter()
                .position(|candidate| *candidate == capacity_id)
                .ok_or(SourceGenesisErrorV1::Stale)?;
            capacities.remove(position);
            intents += 1;
        } else if key.starts_with(FLOOR_PREFIX) {
            let floor = SourceHierarchyFloorRecordV1::from_record_bytes(value)?;
            if instance != Some(floor.instance())
                || key != capacity::floor_key(&floor)
                || floor.roles() != pins.digest()
            {
                return Err(SourceGenesisErrorV1::Stale);
            }
            floors += 1;
        }
        if intents > 1 || floors > MAXIMUM_PROJECTS {
            return Err(SourceGenesisErrorV1::NonCanonical);
        }
    }
    if !capacities.is_empty() {
        return Err(SourceGenesisErrorV1::Stale);
    }
    super::successor_owner::validate_root_first_successor_journal_v2(journal)?;
    Ok(())
}
