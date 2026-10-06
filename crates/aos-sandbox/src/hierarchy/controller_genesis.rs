//! Held Controller acceptance of genuine initial Source administrative inputs.
//!
//! The producer verifies both fixed issuer roles against actual publisher and
//! project-authorization state. Its borrowed owner remains held through Root
//! admission, Source append, Root-floor acceptance, and the actual Source ACK.
//! No public request, decoded receipt, or initiating capability can construct
//! this writer custody. Completion records are provenance, not Create gates.

use std::cell::RefCell;
use std::path::Path;

use aos_sandbox_core::{ObjectDigest, ProjectId};

use super::genesis_profile::{
    ControllerSourceGenesisAcceptanceRecordV1, SourceGenesisErrorV1, digest_at,
};
use super::source_genesis::{
    HeldSourceTreeGenesisObservationV1, SourceTreeGenesisReceiptV1, SourceTreeGenesisStateV1,
};
use crate::controller_service::journal::production_journal_limits;
use crate::journal::controller_source_genesis::{
    self as records, ControllerSourceGenesisTransition as Transition,
};
use crate::journal::{Journal, ProtectedJournalNamesV1};
use crate::journal::controller_source_successor_issuance::PublicationCustodyV2;
use crate::policy_compiler::{RootSourceGenesisFloorProofV1, SourceHierarchyFloorRecordV1};
use crate::publisher_policy::{PublisherPolicyLimits, PublisherPolicyStore};

const CONTROLLER_ROOT: &str = "/var/lib/aos/sandboxd";
const CONTROLLER_JOURNAL: &str = "controller.journal";

/// Retains one selected initial-project settlement and its independent debts.
#[cfg(target_os = "linux")]
#[derive(Default)]
pub(crate) struct ControllerProjectGenesisMutationV3 {
    preparation: Option<Result<Option<crate::journal::JournalTransaction>, SourceGenesisErrorV1>>,
    native: Option<Result<crate::journal::CommitResult, crate::JournalError>>,
    readback: Option<Result<(), SourceGenesisErrorV1>>,
    posts: [Option<Result<(), SourceGenesisErrorV1>>; 4],
    first_failure: Option<ControllerProjectGenesisSiteV3>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum ControllerProjectGenesisSiteV3 { Preparation, Native, Readback, Post(usize) }

#[cfg(target_os = "linux")]
#[derive(Default)]
pub(crate) struct ControllerProjectIssuanceMutationV3 {
    preparation: Option<Result<Option<crate::JournalTransaction>, SourceGenesisErrorV1>>,
    native: Option<Result<crate::CommitResult, crate::JournalError>>,
    readback: Option<Result<(), SourceGenesisErrorV1>>,
    posts: [Option<Result<(), SourceGenesisErrorV1>>; 4],
    first_failure: Option<ControllerProjectGenesisSiteV3>,
}

#[cfg(target_os = "linux")]
impl ControllerProjectIssuanceMutationV3 {
    pub(crate) fn new() -> Self { Self::default() }

    pub(crate) fn error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_failure? {
            ControllerProjectGenesisSiteV3::Preparation => self.preparation.as_ref()?.as_ref().err().map(|e| e as _),
            ControllerProjectGenesisSiteV3::Native => self.native.as_ref()?.as_ref().err().map(|e| e as _),
            ControllerProjectGenesisSiteV3::Readback => self.readback.as_ref()?.as_ref().err().map(|e| e as _),
            ControllerProjectGenesisSiteV3::Post(index) => self.posts.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
        }
    }

    fn latch(&mut self, site: ControllerProjectGenesisSiteV3, failed: bool) {
        if failed && self.first_failure.is_none() { self.first_failure = Some(site); }
    }
}

#[cfg(target_os = "linux")]
impl ControllerProjectGenesisMutationV3 {
    pub(crate) fn new() -> Self { Self::default() }

    pub(crate) fn error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first_failure? {
            ControllerProjectGenesisSiteV3::Preparation => self.preparation.as_ref()?.as_ref().err().map(|e| e as _),
            ControllerProjectGenesisSiteV3::Native => self.native.as_ref()?.as_ref().err().map(|e| e as _),
            ControllerProjectGenesisSiteV3::Readback => self.readback.as_ref()?.as_ref().err().map(|e| e as _),
            ControllerProjectGenesisSiteV3::Post(index) => self.posts.get(index)?.as_ref()?.as_ref().err().map(|e| e as _),
        }
    }

    fn latch(&mut self, site: ControllerProjectGenesisSiteV3, failed: bool) {
        if failed && self.first_failure.is_none() { self.first_failure = Some(site); }
    }
}

// This issuer path may only reborrow a real already completed predecessor.
// It never accepts a new seed, runs genesis recovery or appends a bootstrap row.
#[cfg(target_os = "linux")]
pub(crate) fn hold_existing_completed_source_genesis_v2(
    journal: &mut Journal,
    project: ProjectId,
) -> Result<HeldControllerSourceGenesisV1<'_>, SourceGenesisErrorV1> {
    let uid = journal.protected_owner_uid()?;
    require_controller(journal, uid)?;
    if records::pending(journal)?.is_some() {
        return Err(SourceGenesisErrorV1::AdmissionClosed);
    }
    let row = records::rows(journal, project)?.ok_or(SourceGenesisErrorV1::AdmissionClosed)?;
    if row.ack.is_none() || row.complete.is_none() {
        return Err(SourceGenesisErrorV1::AdmissionClosed);
    }
    let names = journal.protected_writer_physical_names_v1()?;
    let held = HeldControllerSourceGenesisV1 {
        journal: RefCell::new(journal),
        acceptance: row.acceptance,
        uid,
        names,
    };
    held.recheck()?;
    Ok(held)
}

/// Retains the actual fixed Controller writer and original accepted input.
///
/// Interior borrowing permits readback rechecks through a shared owner borrow;
/// it neither releases nor duplicates the exclusive Journal writer. Durable
/// phase changes require this owner's mutable borrow and typed live proofs.
pub struct HeldControllerSourceGenesisV1<'controller> {
    journal: RefCell<&'controller mut Journal>,
    acceptance: ControllerSourceGenesisAcceptanceRecordV1,
    uid: u32,
    names: ProtectedJournalNamesV1,
}

/// Accepts or exact-replays the actual independently signed administrative input.
///
/// This startup-only composition is not a public Create endpoint. Source must
/// remain separately held, then Root must be acquired last on one authenticated
/// flight before any Source Tree mutation.
///
/// # Errors
/// Rejects wrong fixed Controller ownership, foreign pending work, substituted
/// inputs, missing or changed issuer/publisher custody, or insufficient space
/// for acceptance, Root-floor ACK, and actual Source-ACK completion together.
pub fn hold_controller_source_genesis_v1(
    journal: &mut Journal,
    project: ProjectId,
    seed: [u8; 224],
    authorization: [u8; 224],
) -> Result<HeldControllerSourceGenesisV1<'_>, SourceGenesisErrorV1> {
    let uid = journal.protected_owner_uid()?;
    require_controller(journal, uid)?;
    if records::pending(journal)?.is_some_and(|pending| pending.project() != project) {
        return Err(SourceGenesisErrorV1::Conflict);
    }
    let current = records::rows(journal, project)?;
    let acceptance = if let Some(row) = current {
        if row.acceptance.seed_packet() != &seed || row.acceptance.auth_packet() != &authorization {
            return Err(SourceGenesisErrorV1::Conflict);
        }
        row.acceptance
    } else {
        let acceptance = PublisherPolicyStore::load(journal, PublisherPolicyLimits::default())?
            .prepare_source_genesis_acceptance_from_fixed_issuers_v1(
                project,
                seed,
                authorization,
            )?;
        let accept = records::acceptance_transaction(&acceptance)?;
        // These are size-only prospective ACKs. No authorizing token or durable
        // state is created from their placeholder commitments.
        let prospective_ack = records::ack_bytes(
            acceptance.digest(),
            ObjectDigest::from_bytes([1; 32]),
            ObjectDigest::from_bytes([2; 32]),
        )?;
        let prospective_complete = records::complete_bytes(
            &prospective_ack,
            ObjectDigest::from_bytes([3; 32]),
            ObjectDigest::from_bytes([1; 32]),
        )?;
        journal.preflight_controller_source_genesis_transitions(
            &[
                accept.clone(),
                records::ack_transaction(project, &prospective_ack)?,
                records::complete_transaction(project, &prospective_complete)?,
            ],
            &[
                Transition::Accept,
                Transition::FloorAck,
                Transition::Complete,
            ],
        )?;
        require_controller(journal, uid)?;
        journal.commit_controller_source_genesis_transition(&accept, Transition::Accept)?;
        let retained = records::rows(journal, project)?.ok_or(SourceGenesisErrorV1::Stale)?;
        if retained.acceptance != acceptance
            || retained.ack.is_some()
            || retained.complete.is_some()
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        acceptance
    };
    let names = journal.protected_writer_physical_names_v1()?;
    let held = HeldControllerSourceGenesisV1 {
        journal: RefCell::new(journal),
        acceptance,
        uid,
        names,
    };
    held.recheck()?;
    Ok(held)
}

impl HeldControllerSourceGenesisV1<'_> {
    #[cfg(target_os = "linux")]
    pub(crate) fn retained_project_successor_approval_v3(
        &self,
    ) -> Result<Option<super::source_successor::SourceSuccessorApprovalDataV2>, SourceGenesisErrorV1> {
        self.recheck()?;
        let journal = self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?;
        Ok(crate::journal::controller_source_successor_issuance::retained_project_v3(&journal, self.acceptance.project())?
            .map(|saved| saved.packet))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retain_project_successor_issuance_v3(
        &self,
        packet: &super::source_successor::SourceSuccessorApprovalDataV2,
        source: &super::source_genesis::HeldSourceProjectGenesisObservationV3<'_>,
        completed: &crate::policy_compiler::CompletedRootSourceProjectGenesisFloorV3<'_, '_>,
        phase: crate::journal::controller_source_successor_issuance::Transition,
        resident: &mut ControllerProjectIssuanceMutationV3,
    ) -> Result<(), ()> {
        use crate::journal::controller_source_successor_issuance::{IssuanceKeyRecipeV3, Transition};
        if resident.preparation.is_some() { return Err(()); }
        resident.preparation = Some((|| {
            self.recheck()?;
            source.recheck()?;
            completed.recheck()?;
            self.recheck_completed_project_genesis_v3(source)?;
            let project = self.acceptance.project();
            if phase.recipe() != IssuanceKeyRecipeV3::ProjectV3(project)
                || !matches!(phase, Transition::ProjectSave(_) | Transition::ProjectDelivered(_))
                || packet.intent()?.project() != project || completed.floor().project() != project
                || packet.body()[144..176] != completed.floor().digest().as_bytes()[..]
                || source.receipt() != Some(completed.floor().receipt())
            { return Err(SourceGenesisErrorV1::Conflict); }
            let journal = self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?;
            journal.preflight_project_successor_issuance_v3(packet)?;
            journal.prepare_project_successor_issuance_v3(packet, phase).map_err(Into::into)
        })());
        resident.latch(ControllerProjectGenesisSiteV3::Preparation, resident.preparation.as_ref().is_some_and(Result::is_err));
        if let Some(Ok(Some(transaction))) = &resident.preparation {
            match self.journal.try_borrow_mut() {
                Ok(mut journal) => resident.native = Some(journal.commit_project_successor_issuance_v3(transaction, phase, completed)),
                Err(_) => resident.readback = Some(Err(SourceGenesisErrorV1::Stale)),
            }
            resident.latch(ControllerProjectGenesisSiteV3::Native, resident.native.as_ref().is_some_and(Result::is_err));
            resident.latch(ControllerProjectGenesisSiteV3::Readback, resident.readback.as_ref().is_some_and(Result::is_err));
        }
        if resident.first_failure.is_none() {
            resident.readback = Some((|| {
                let journal = self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?;
                let actual = crate::journal::controller_source_successor_issuance::retained_project_v3(&journal, self.acceptance.project())?
                    .ok_or(SourceGenesisErrorV1::Stale)?;
                if actual.packet != *packet || matches!(phase, Transition::ProjectDelivered(_)) && !actual.delivered {
                    return Err(SourceGenesisErrorV1::Stale);
                }
                Ok(())
            })());
            resident.latch(ControllerProjectGenesisSiteV3::Readback, resident.readback.as_ref().is_some_and(Result::is_err));
        }
        resident.posts[0] = Some(self.recheck());
        resident.latch(ControllerProjectGenesisSiteV3::Post(0), resident.posts[0].as_ref().is_some_and(Result::is_err));
        resident.posts[1] = Some(source.recheck());
        resident.latch(ControllerProjectGenesisSiteV3::Post(1), resident.posts[1].as_ref().is_some_and(Result::is_err));
        resident.posts[2] = Some(completed.recheck());
        resident.latch(ControllerProjectGenesisSiteV3::Post(2), resident.posts[2].as_ref().is_some_and(Result::is_err));
        resident.posts[3] = Some(completed.signing_boundary_clock().map(|_| ()));
        resident.latch(ControllerProjectGenesisSiteV3::Post(3), resident.posts[3].as_ref().is_some_and(Result::is_err));
        if resident.first_failure.is_some() { Err(()) } else { Ok(()) }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn publish_project_successor_issuance_v3(
        &self, packet: &super::source_successor::SourceSuccessorApprovalDataV2, custody: &mut PublicationCustodyV2,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?.publish_project_successor_v3(packet, custody)?;
        self.recheck()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn recheck_project_successor_publication_v3(
        &self, packet: &super::source_successor::SourceSuccessorApprovalDataV2, custody: &mut PublicationCustodyV2,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?.recheck_project_successor_publication_v3(packet, custody)?;
        self.recheck()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn settle_project_genesis_v3(
        &mut self,
        source: &super::source_genesis::HeldSourceProjectGenesisObservationV3<'_>,
        root: &crate::policy_compiler::RootSourceProjectGenesisFloorProofV3<'_>,
        complete: bool,
        resident: &mut ControllerProjectGenesisMutationV3,
    ) -> Result<(), ()> {
        if resident.preparation.is_some() { return Err(()); }
        let mut expected = None;
        resident.preparation = Some((|| {
            self.recheck()?;
            source.recheck()?;
            root.recheck()?;
            require_floor(&self.acceptance, root.floor())?;
            if source.project() != self.acceptance.project()
                || source.receipt() != Some(root.floor().receipt())
            { return Err(SourceGenesisErrorV1::Stale); }
            let journal = self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?;
            let rows = records::rows(&journal, self.acceptance.project())?.ok_or(SourceGenesisErrorV1::Stale)?;
            let (bytes, prior, transaction) = if complete {
                if source.state() != SourceTreeGenesisStateV1::Anchored
                    || source.ack_floor_digest() != Some(root.floor().digest())
                { return Err(SourceGenesisErrorV1::Stale); }
                let ack = rows.ack.ok_or(SourceGenesisErrorV1::Stale)?;
                let bytes = records::complete_bytes(&ack, source.ack_record_digest().ok_or(SourceGenesisErrorV1::Stale)?, root.floor().digest())?;
                let transaction = records::complete_transaction(self.acceptance.project(), &bytes)?;
                (bytes, rows.complete, transaction)
            } else {
                let bytes = records::ack_bytes(self.acceptance.digest(), root.floor().digest(), root.floor().receipt_digest())?;
                let transaction = records::ack_transaction(self.acceptance.project(), &bytes)?;
                (bytes, rows.ack, transaction)
            };
            expected = Some(bytes);
            match prior {
                Some(prior) if prior == bytes => Ok(None),
                Some(_) => Err(SourceGenesisErrorV1::Conflict),
                None => Ok(Some(transaction)),
            }
        })());
        resident.latch(ControllerProjectGenesisSiteV3::Preparation, resident.preparation.as_ref().is_some_and(Result::is_err));
        if let Some(Ok(Some(transaction))) = &resident.preparation {
            match self.journal.try_borrow_mut() {
                Ok(mut journal) => resident.native = Some(journal.commit_controller_project_genesis_v3(
                    transaction, if complete { Transition::Complete } else { Transition::FloorAck }, root,
                )),
                Err(_) => resident.readback = Some(Err(SourceGenesisErrorV1::Stale)),
            }
            resident.latch(ControllerProjectGenesisSiteV3::Native, resident.native.as_ref().is_some_and(Result::is_err));
            resident.latch(ControllerProjectGenesisSiteV3::Readback, resident.readback.as_ref().is_some_and(Result::is_err));
        }
        if resident.first_failure.is_none() {
            resident.readback = Some((|| {
                let journal = self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?;
                let rows = records::rows(&journal, self.acceptance.project())?.ok_or(SourceGenesisErrorV1::Stale)?;
                let actual = if complete { rows.complete } else { rows.ack };
                if actual != expected { return Err(SourceGenesisErrorV1::Stale); }
                Ok(())
            })());
            resident.latch(ControllerProjectGenesisSiteV3::Readback, resident.readback.as_ref().is_some_and(Result::is_err));
        }
        resident.posts[0] = Some(self.recheck());
        resident.latch(ControllerProjectGenesisSiteV3::Post(0), resident.posts[0].as_ref().is_some_and(Result::is_err));
        resident.posts[1] = Some(source.recheck());
        resident.latch(ControllerProjectGenesisSiteV3::Post(1), resident.posts[1].as_ref().is_some_and(Result::is_err));
        resident.posts[2] = Some(root.recheck());
        resident.latch(ControllerProjectGenesisSiteV3::Post(2), resident.posts[2].as_ref().is_some_and(Result::is_err));
        resident.posts[3] = Some(root.independent_clock_v3());
        resident.latch(ControllerProjectGenesisSiteV3::Post(3), resident.posts[3].as_ref().is_some_and(Result::is_err));
        if resident.error().is_some() { Err(()) } else { Ok(()) }
    }

    pub(crate) fn recheck_completed_project_genesis_v3(
        &self,
        source: &super::source_genesis::HeldSourceProjectGenesisObservationV3<'_>,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        source.recheck()?;
        if source.project() != self.acceptance.project() || source.state() != SourceTreeGenesisStateV1::Anchored {
            return Err(SourceGenesisErrorV1::Stale);
        }
        let journal = self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?;
        require_completed_source_ack(&journal, &self.acceptance,
            source.receipt().ok_or(SourceGenesisErrorV1::Stale)?,
            source.ack_floor_digest().ok_or(SourceGenesisErrorV1::Stale)?,
            source.ack_record_digest().ok_or(SourceGenesisErrorV1::Stale)?,
        )?;
        source.recheck()?;
        self.recheck()
    }
    /// Borrows the immutable exact administrative acceptance.
    #[must_use]
    pub const fn acceptance(&self) -> &ControllerSourceGenesisAcceptanceRecordV1 {
        &self.acceptance
    }

    /// Returns the physical names of the still-held Controller writer.
    #[must_use]
    pub const fn names(&self) -> ProtectedJournalNamesV1 {
        self.names
    }

    /// Rejoins fixed named custody, both issuers, and the actual retained graph.
    ///
    /// # Errors
    /// Rejects a poisoned/replaced writer, substituted original input, changed
    /// fixed issuer pins, or invalid immutable historical provenance. Old
    /// publisher/admin heads are never claimed current by this method.
    pub fn recheck(&self) -> Result<(), SourceGenesisErrorV1> {
        let mut journal = self
            .journal
            .try_borrow_mut()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        require_controller(&journal, self.uid)?;
        if journal.protected_writer_physical_names_v1()? != self.names {
            return Err(SourceGenesisErrorV1::Stale);
        }
        let retained = records::rows(&journal, self.acceptance.project())?
            .ok_or(SourceGenesisErrorV1::Stale)?;
        if retained.acceptance != self.acceptance {
            return Err(SourceGenesisErrorV1::Stale);
        }
        let store = PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default())?;
        store
            .recheck_historical_source_genesis_acceptance_from_fixed_issuers_v1(&self.acceptance)?;
        Ok(())
    }

    /// Separately checks current administrative custody before a new append.
    ///
    /// Historical `recheck` permits only exact recovery of retained provenance;
    /// this method cannot promote an old publisher or administrative head.
    ///
    /// # Errors
    /// Rejects changed issuer pins, publisher or authorization heads, or writer
    /// custody. Root must also authenticate its current positive deployment.
    pub fn recheck_current_admission(&self) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        let mut journal = self
            .journal
            .try_borrow_mut()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let store = PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default())?;
        if store.current_source_genesis_acceptance_from_fixed_issuers_v1(
            self.acceptance.project(),
            *self.acceptance.seed_packet(),
            *self.acceptance.auth_packet(),
        )? != self.acceptance
        {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }

    /// Durably accepts the exact floor while its original Root flight is held.
    ///
    /// # Errors
    /// Rejects detached/foreign Root custody, changed original receipt or
    /// Controller state, a conflicting retained ACK, or failed durable readback.
    pub fn accept_root_floor_v1(
        &mut self,
        proof: &RootSourceGenesisFloorProofV1<'_>,
    ) -> Result<(), SourceGenesisErrorV1> {
        proof.recheck()?;
        self.recheck()?;
        let floor = proof.floor();
        require_floor(&self.acceptance, floor)?;
        let ack = records::ack_bytes(
            self.acceptance.digest(),
            floor.digest(),
            floor.receipt_digest(),
        )?;
        {
            let mut journal = self
                .journal
                .try_borrow_mut()
                .map_err(|_| SourceGenesisErrorV1::Stale)?;
            let current = records::rows(&journal, self.acceptance.project())?
                .ok_or(SourceGenesisErrorV1::Stale)?;
            if let Some(prior) = current.ack {
                if prior != ack {
                    return Err(SourceGenesisErrorV1::Conflict);
                }
            } else {
                let transaction = records::ack_transaction(self.acceptance.project(), &ack)?;
                require_controller(&journal, self.uid)?;
                proof.recheck()?;
                journal.commit_controller_source_genesis_transition(
                    &transaction,
                    Transition::FloorAck,
                )?;
            }
            if records::rows(&journal, self.acceptance.project())?.and_then(|row| row.ack)
                != Some(ack)
            {
                return Err(SourceGenesisErrorV1::Stale);
            }
        }
        proof.recheck()?;
        self.recheck()
    }

    /// Returns only the actual durably accepted floor-ACK record commitment.
    ///
    /// # Errors
    /// Rejects changed held custody or an absent actual floor ACK.
    pub fn accepted_floor_digest(&self) -> Result<ObjectDigest, SourceGenesisErrorV1> {
        self.recheck()?;
        let journal = self
            .journal
            .try_borrow()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let ack = records::rows(&journal, self.acceptance.project())?
            .and_then(|row| row.ack)
            .ok_or(SourceGenesisErrorV1::Stale)?;
        Ok(records::ack_digest(&ack))
    }

    /// Validates the exact borrowed Controller join at the Source ACK boundary.
    ///
    /// # Errors
    /// Rejects an unaccepted/foreign floor, substituted original receipt, or
    /// changed writer/administrative custody. This method accepts no raw ACK.
    pub fn validate_source_ack(
        &self,
        receipt: &SourceTreeGenesisReceiptV1,
        floor: &SourceHierarchyFloorRecordV1,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        require_floor(&self.acceptance, floor)?;
        if receipt != floor.receipt() {
            return Err(SourceGenesisErrorV1::Stale);
        }
        let journal = self
            .journal
            .try_borrow()
            .map_err(|_| SourceGenesisErrorV1::Stale)?;
        let ack = records::rows(&journal, self.acceptance.project())?
            .and_then(|row| row.ack)
            .ok_or(SourceGenesisErrorV1::Stale)?;
        if digest_at(&ack, 48) != floor.digest() || digest_at(&ack, 80) != receipt.digest() {
            return Err(SourceGenesisErrorV1::Stale);
        }
        Ok(())
    }

    /// Completes bootstrap only from actual held Source ACK readback.
    ///
    /// # Errors
    /// Rejects absent/foreign Source ACK or Root flight, changed original owner
    /// state, contradictory replay, or any final append/readback failure.
    pub fn complete_source_ack_v1(
        &mut self,
        source: &HeldSourceTreeGenesisObservationV1<'_>,
        proof: &RootSourceGenesisFloorProofV1<'_>,
    ) -> Result<(), SourceGenesisErrorV1> {
        proof.recheck()?;
        source.recheck()?;
        let receipt = source.receipt().ok_or(SourceGenesisErrorV1::Stale)?;
        self.validate_source_ack(receipt, proof.floor())?;
        if source.ack_floor_digest() != Some(proof.floor().digest()) {
            return Err(SourceGenesisErrorV1::Stale);
        }
        let source_ack = source
            .ack_record_digest()
            .ok_or(SourceGenesisErrorV1::Stale)?;
        {
            let mut journal = self
                .journal
                .try_borrow_mut()
                .map_err(|_| SourceGenesisErrorV1::Stale)?;
            let row = records::rows(&journal, self.acceptance.project())?
                .ok_or(SourceGenesisErrorV1::Stale)?;
            let ack = row.ack.ok_or(SourceGenesisErrorV1::Stale)?;
            let complete = records::complete_bytes(&ack, source_ack, proof.floor().digest())?;
            if let Some(prior) = row.complete {
                if prior != complete {
                    return Err(SourceGenesisErrorV1::Conflict);
                }
            } else {
                proof.recheck()?;
                source.recheck()?;
                require_controller(&journal, self.uid)?;
                journal.commit_controller_source_genesis_transition(
                    &records::complete_transaction(self.acceptance.project(), &complete)?,
                    Transition::Complete,
                )?;
            }
            if records::rows(&journal, self.acceptance.project())?.and_then(|row| row.complete)
                != Some(complete)
            {
                return Err(SourceGenesisErrorV1::Stale);
            }
        }
        proof.recheck()?;
        source.recheck()?;
        self.recheck()
    }

    // Final readback alone requires Complete; historical readback deliberately
    // stays usable after Source ACK but before this Controller append.
    pub(crate) fn recheck_completed_source_ack(
        &self,
        source: &HeldSourceTreeGenesisObservationV1<'_>,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        source.recheck()?;
        if source.state() != SourceTreeGenesisStateV1::Anchored {
            return Err(SourceGenesisErrorV1::Stale);
        }
        {
            let journal = self
                .journal
                .try_borrow()
                .map_err(|_| SourceGenesisErrorV1::Stale)?;
            require_completed_source_ack(
                &journal,
                &self.acceptance,
                source.receipt().ok_or(SourceGenesisErrorV1::Stale)?,
                source
                    .ack_floor_digest()
                    .ok_or(SourceGenesisErrorV1::Stale)?,
                source
                    .ack_record_digest()
                    .ok_or(SourceGenesisErrorV1::Stale)?,
            )?;
        }
        source.recheck()?;
        self.recheck()
    }

    pub(crate) fn snapshot_sequence(&self) -> Result<u64, SourceGenesisErrorV1> {
        self.recheck()?;
        Ok(self
            .journal
            .try_borrow()
            .map_err(|_| SourceGenesisErrorV1::Stale)?
            .snapshot_sequence())
    }

    pub(crate) const fn uid(&self) -> u32 {
        self.uid
    }

    // The existing Complete decoder validates this checksum before it is read.
    // This is its actual retained commitment, not a new genesis receipt.
    #[cfg(target_os = "linux")]
    pub(crate) fn completed_record_commitment_v2(
        &self,
    ) -> Result<ObjectDigest, SourceGenesisErrorV1> {
        self.recheck()?;
        let journal = self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?;
        let complete = records::rows(&journal, self.acceptance.project())?
            .and_then(|row| row.complete)
            .ok_or(SourceGenesisErrorV1::Stale)?;
        Ok(digest_at(&complete, 112))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn current_successor_authorization_v2(
        &self,
    ) -> Result<
        (u64, ObjectDigest, ObjectDigest, ObjectDigest, super::model::TreeLimitsV1, [u8; 224]),
        SourceGenesisErrorV1,
    > {
        self.recheck()?;
        let mut journal = self.journal.try_borrow_mut().map_err(|_| SourceGenesisErrorV1::Stale)?;
        let current = PublisherPolicyStore::load(&mut journal, PublisherPolicyLimits::default())?
            .current_source_successor_authorization_v2(self.acceptance.project())?;
        Ok((
            current.publisher_generation,
            current.publisher_head,
            current.publisher_revision,
            current.authorization_head,
            current.limits,
            current.packet,
        ))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retained_successor_approval_v2(
        &self,
    ) -> Result<Option<super::source_successor::SourceSuccessorApprovalDataV2>, SourceGenesisErrorV1> {
        self.recheck()?;
        let journal = self.journal.try_borrow().map_err(|_| SourceGenesisErrorV1::Stale)?;
        Ok(crate::journal::controller_source_successor_issuance::retained(&journal)?
            .map(|saved| saved.packet))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn preflight_successor_issuance_v2(
        &self,
        packet: &super::source_successor::SourceSuccessorApprovalDataV2,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        self.journal.try_borrow()
            .map_err(|_| SourceGenesisErrorV1::Stale)?
            .preflight_source_successor_issuance_v2(packet)?;
        self.recheck()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn save_successor_issuance_v2(
        &self,
        packet: &super::source_successor::SourceSuccessorApprovalDataV2,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        self.journal.try_borrow_mut()
            .map_err(|_| SourceGenesisErrorV1::Stale)?
            .save_source_successor_issuance_v2(packet)?;
        self.recheck()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn publish_successor_issuance_v2(
        &self,
        packet: &super::source_successor::SourceSuccessorApprovalDataV2,
        custody: &mut PublicationCustodyV2,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        self.journal.try_borrow()
            .map_err(|_| SourceGenesisErrorV1::Stale)?
            .publish_source_successor_v2(packet, custody)?;
        self.recheck()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn complete_successor_delivery_v2(
        &self,
        packet: &super::source_successor::SourceSuccessorApprovalDataV2,
        custody: &mut PublicationCustodyV2,
    ) -> Result<(), SourceGenesisErrorV1> {
        self.recheck()?;
        let mut journal = self.journal.try_borrow_mut().map_err(|_| SourceGenesisErrorV1::Stale)?;
        journal.recheck_source_successor_publication_v2(packet, custody)?;
        journal.complete_source_successor_delivery_v2(packet)?;
        journal.recheck_source_successor_publication_v2(packet, custody)?;
        drop(journal);
        self.recheck()
    }
}

/// Rechecks only the fixed genuine Controller writer location and ownership.
///
/// # Errors
///
/// Rejects root ownership, another protected location or lost named custody.
pub(crate) fn require_controller(journal: &Journal, uid: u32) -> Result<(), SourceGenesisErrorV1> {
    if uid == 0 {
        return Err(SourceGenesisErrorV1::Stale);
    }
    journal.require_protected_named_location(
        Path::new(CONTROLLER_ROOT),
        CONTROLLER_JOURNAL,
        uid,
        production_journal_limits(),
    )?;
    Ok(())
}

fn require_floor(
    acceptance: &ControllerSourceGenesisAcceptanceRecordV1,
    floor: &SourceHierarchyFloorRecordV1,
) -> Result<(), SourceGenesisErrorV1> {
    let receipt = floor.receipt();
    if floor.project() != acceptance.project()
        || receipt.acceptance_digest() != acceptance.digest()
        || &receipt.seed_packet() != acceptance.seed_packet()
        || &receipt.auth_packet() != acceptance.auth_packet()
    {
        return Err(SourceGenesisErrorV1::Stale);
    }
    Ok(())
}

// This reads actual durable Controller rows. The caller separately retains and
// authenticates both owner cuts; the comparison itself creates no live proof.
fn require_completed_source_ack(
    journal: &Journal,
    acceptance: &ControllerSourceGenesisAcceptanceRecordV1,
    receipt: &SourceTreeGenesisReceiptV1,
    floor: ObjectDigest,
    source_ack: ObjectDigest,
) -> Result<(), SourceGenesisErrorV1> {
    let row = records::rows(journal, acceptance.project())?.ok_or(SourceGenesisErrorV1::Stale)?;
    let ack = row.ack.ok_or(SourceGenesisErrorV1::Stale)?;
    if row.acceptance != *acceptance
        || receipt.project() != acceptance.project()
        || receipt.acceptance_digest() != acceptance.digest()
        || &receipt.seed_packet() != acceptance.seed_packet()
        || &receipt.auth_packet() != acceptance.auth_packet()
        || digest_at(&ack, 48) != floor
        || digest_at(&ack, 80) != receipt.digest()
        || row.complete != Some(records::complete_bytes(&ack, source_ack, floor)?)
    {
        return Err(SourceGenesisErrorV1::Stale);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
