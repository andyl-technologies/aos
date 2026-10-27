//! Joins the actual completed generation-one floor to one accepted Root flight.
//!
//! Canonical Controller and Source signature codecs remain in LedgerReplay.
//! Only this native role combines those comparison values with the independently
//! held pins, complete resident history, original nonce and accepted endpoint.
//! A loan borrows the same flight and never adopts a decoded floor as custody.

use aos_sandbox_model::{ProjectId, RecordNamespace, ResourceDimension as D, ResourceVector};
use aos_sandbox_ledger_replay::replay::root_genesis_records::{
    FLOOR_PREFIX, INTENT_PREFIX, RootSourceGenesisIntentRecordV1, SourceHierarchyFloorRecordV1,
    project_key,
};
use aos_sandbox_ledger_replay::replay::root_successor;
use aos_sandbox_ledger_replay::source_signer_data::controller_genesis_readback::{
    CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2, ControllerGenesisReadbackDataV1,
    ControllerGenesisReadbackRecipeV3, RESOURCE_DOMAIN_V2,
    verify_controller_source_genesis_readback_v1,
};
use aos_sandbox_ledger_replay::source_signer_data::{
    SOURCE_TREE_GENESIS_READBACK_BYTES_V2, SourceTreeGenesisChallengeV1,
    SourceTreeGenesisIntentContextV1, SourceTreeGenesisReadbackPacketV2, SourceTreeGenesisStateV1,
    verify_source_tree_genesis_readback_v2,
};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

use super::RootAuthorityOriginalV1;
use super::error::RootAuthorityErrorV1;
use super::q04::RootAuthorityQ04FlightOriginalV1;
use crate::native::PolicyNativeJournalErrorV1;

/// Borrows one completed floor under its genuine resident Authority and flight.
///
/// This value has no supplied-parts constructor, clone, serialization or writer
/// projection. Its Controller and Source coordinates are comparison DATA from
/// the freshly verified pair; they do not lend either other owner's journal.
#[must_use = "retain the real Authority and same accepted flight through Finish"]
pub struct RootAuthorityGen1LoanV1<'loan, 'origin, 'startup> {
    pub(super) current: RootAuthorityCurrentGen1LoanV1<'loan, 'origin, 'startup>,
    pub(super) controller_sequence: u64,
    pub(super) controller_names: ProtectedJournalNamesV1,
}

// Stage and binding gates use this same finite owner/ACK loan. The public Q04
// loan adds the real freshly verified Controller coordinates without copying
// another floor owner or constructing one from supplied success DATA.
pub(super) struct RootAuthorityCurrentGen1LoanV1<'loan, 'origin, 'startup> {
    pub(super) owner: RootAuthorityGen1OwnerLoanV1<'loan, 'origin, 'startup>,
    floor: SourceHierarchyFloorRecordV1,
    source: SourceTreeGenesisReadbackPacketV2,
}

impl RootAuthorityCurrentGen1LoanV1<'_, '_, '_> {
    pub(super) const fn floor(&self) -> &SourceHierarchyFloorRecordV1 {
        &self.floor
    }

    pub(super) fn into_append_observation_v1(
        self,
    ) -> (
        SourceHierarchyFloorRecordV1,
        SourceTreeGenesisReadbackPacketV2,
    ) {
        (self.floor, self.source)
    }

    pub(super) fn recheck(&self) -> Result<(), RootAuthorityErrorV1> {
        self.owner
            .confirm_gen1_ack_v1(self.source.as_ref(), &self.floor)
    }
}

impl RootAuthorityOriginalV1 {
    fn gen1_intent_v1(
        &self,
        project: ProjectId,
    ) -> Result<Option<RootSourceGenesisIntentRecordV1>, RootAuthorityErrorV1> {
        self.journal
            .get(
                RecordNamespace::DesiredState,
                &project_key(INTENT_PREFIX, project),
            )
            .map(RootSourceGenesisIntentRecordV1::from_record_bytes)
            .transpose()
            .map_err(Into::into)
    }

    fn gen1_floor_v1(
        &self,
        project: ProjectId,
    ) -> Result<Option<SourceHierarchyFloorRecordV1>, RootAuthorityErrorV1> {
        gen1_floor_in_journal_v1(&self.journal, project)
    }
}

impl RootAuthorityQ04FlightOriginalV1<'_, '_, '_> {
    fn gen1_observation_demand_v1(&self) -> Result<ResourceVector, RootAuthorityErrorV1> {
        gen1_observation_demand_for_v1(&self.authority.journal)
    }

    fn admit_gen1_observation_v1(&self) -> Result<(), RootAuthorityErrorV1> {
        self.require_ready()?;
        self.authority
            .journal
            .admit_role_observation_v1(self.gen1_observation_demand_v1()?)?;
        Ok(())
    }

    /// Copies the nonce created once under this actual accepted native origin.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or reentered native flight association.
    pub fn nonce_data_v1(&self) -> Result<[u8; 16], RootAuthorityErrorV1> {
        self.require_ready()?;
        self.nonce
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .copied()
            .ok_or(RootAuthorityErrorV1::Stale)
    }

    fn accepted_v1(&self) -> Result<&ControllerGenesisReadbackDataV1, RootAuthorityErrorV1> {
        self.require_ready()?;
        self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)
    }

    /// Verifies a historical Controller observation against the held Root pins.
    ///
    /// This selected existing-gen1 purpose refuses Empty, vacant or newly
    /// admitted genesis. A later Complete observation may advance the same
    /// acceptance and sequence; it cannot replace its source names or regress
    /// an already completed observation.
    ///
    /// # Errors
    /// Preserves native, financial and canonical signature failures and refuses
    /// a foreign nonce, UID, administrative input, floor or saved role tuple.
    pub fn accept_historical_controller_readback_v1(
        &mut self,
        packet: &[u8],
    ) -> Result<(ProjectId, SourceTreeGenesisChallengeV1), RootAuthorityErrorV1> {
        self.admit_gen1_observation_v1()?;
        self.authority.recheck()?;
        let identities = self.identities.ok_or(RootAuthorityErrorV1::Stale)?;
        let pin = self.authority.pins.controller()?;
        let accepted = verify_controller_source_genesis_readback_v1(
            packet,
            pin.generation(),
            pin.verifying_key(),
            self.nonce_data_v1()?,
            identities[0],
            identities[2],
            ControllerGenesisReadbackRecipeV3::StrictV1,
        )?;
        if !accepted.historical {
            return Err(RootAuthorityErrorV1::AdmissionClosed);
        }
        self.authority
            .pins
            .verify_administrative_input(&accepted.acceptance)?;
        if accepted.vacant || accepted.source_instance.is_none() {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        if self.accepted.as_ref().is_some_and(|prior| {
            prior.acceptance != accepted.acceptance
                || prior.source_names != accepted.source_names
                || prior.historical && !accepted.historical
                || prior.completed && !accepted.completed
        }) {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let project = accepted.acceptance.project();
        let intent_digest = if let Some(floor) = self.authority.gen1_floor_v1(project)? {
            if floor.receipt().acceptance_digest() != accepted.acceptance.digest() {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            floor.receipt().intent_digest()
        } else {
            self.authority
                .gen1_intent_v1(project)?
                .ok_or(RootAuthorityErrorV1::Conflict)?
                .digest()
        };
        let challenge =
            SourceTreeGenesisChallengeV1::new(self.nonce_data_v1()?, Some(intent_digest))?;
        self.accepted = Some(accepted);
        Ok((project, challenge))
    }

    /// Requires the existing settled revision-one floor for this selected purpose.
    ///
    /// # Errors
    /// Refuses missing or foreign historical input, successor obligations,
    /// an unmatched role tuple, a vacant observation or an unsettled intent.
    pub fn require_existing_completed_floor_v1(
        &self,
        project: ProjectId,
    ) -> Result<(), RootAuthorityErrorV1> {
        self.admit_gen1_observation_v1()?;
        self.authority.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut)?;
        let floor = self
            .authority
            .gen1_floor_v1(project)?
            .ok_or(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut)?;
        if !accepted.historical
            || accepted.vacant
            || accepted.acceptance.project() != project
            || floor.semantic_revision() != 1
            || floor.predecessor().is_some()
            || floor.receipt().acceptance_digest() != accepted.acceptance.digest()
            || floor.roles() != self.authority.pins.digest()?
            || self.authority.gen1_intent_v1(project)?.is_some()
        {
            return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
        }
        self.authority.recheck()
    }

    /// Requires an actual Controller Complete from this same accepted flight.
    ///
    /// # Errors
    /// Refuses a missing observation or a signed historical preparation only.
    pub fn require_completed_controller_packet_v1(&self) -> Result<(), RootAuthorityErrorV1> {
        if !self.accepted.as_ref().is_some_and(|accepted| accepted.completed) {
            return Err(crate::q04_data::PolicyQ04DataErrorV1::ChangedCut.into());
        }
        Ok(())
    }

    /// Constructs the exact Source context from this actual retained floor.
    ///
    /// # Errors
    /// Refuses absent acceptance, changed history, foreign source UID or a
    /// context whose actual retained receipt does not match this same floor.
    pub fn source_genesis_intent_context_v1(
        &self,
    ) -> Result<SourceTreeGenesisIntentContextV1, RootAuthorityErrorV1> {
        self.admit_gen1_observation_v1()?;
        self.authority.recheck()?;
        let accepted = self.accepted_v1()?;
        let project = accepted.acceptance.project();
        let source_uid = self.identities.ok_or(RootAuthorityErrorV1::Stale)?[2];
        let context = if let Some(intent) = self.authority.gen1_intent_v1(project)? {
            if intent.source_uid() != source_uid || intent.accepted_input() != &accepted.acceptance
            {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            SourceTreeGenesisIntentContextV1::new(
                source_uid,
                intent.roles(),
                intent.accepted_input().clone(),
            )?
        } else {
            let floor = self
                .authority
                .gen1_floor_v1(project)?
                .ok_or(RootAuthorityErrorV1::Conflict)?;
            let context = SourceTreeGenesisIntentContextV1::new(
                source_uid,
                floor.roles(),
                accepted.acceptance.clone(),
            )?;
            context.require_actual_receipt(floor.receipt(), None)?;
            context
        };
        self.authority.recheck()?;
        Ok(context)
    }

    /// Rejoins the existing floor to the actual nonce-bound Source receipt.
    ///
    /// This selected existing-floor purpose never appends or creates a missing
    /// floor. Preparation may precede Source ACK; the completed loan below
    /// separately requires the actual durable ACK and Controller Complete.
    ///
    /// # Errors
    /// Refuses a missing saved floor or different signed source names,
    /// sequence, instance, administrative acceptance or receipt commitment.
    pub fn recover_existing_floor_v1(
        &self,
        source: &[u8],
    ) -> Result<SourceHierarchyFloorRecordV1, RootAuthorityErrorV1> {
        self.admit_gen1_observation_v1()?;
        self.authority.recheck()?;
        let accepted = self.accepted_v1()?;
        let floor = self
            .authority
            .gen1_floor_v1(accepted.acceptance.project())?
            .ok_or(RootAuthorityErrorV1::Conflict)?;
        let challenge = SourceTreeGenesisChallengeV1::new(
            self.nonce_data_v1()?,
            Some(floor.receipt().intent_digest()),
        )?;
        let observed = verify_source_tree_genesis_readback_v2(
            source,
            self.authority.pins.source()?,
            challenge,
        )?;
        if accepted.source_names != observed.names()
            || accepted.source_sequence != observed.journal_sequence()
            || accepted.source_instance != observed.receipt().map(|receipt| receipt.instance())
        {
            return Err(RootAuthorityErrorV1::Stale);
        }
        let receipt = observed
            .receipt()
            .ok_or(RootAuthorityErrorV1::Conflict)?
            .clone();
        if receipt.acceptance_digest() != accepted.acceptance.digest()
            || &receipt.seed_packet() != accepted.acceptance.seed_packet()
            || receipt.auth_packet() != accepted.acceptance.auth_packet()
        {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let observed_floor =
            SourceHierarchyFloorRecordV1::new(receipt, self.authority.pins.digest()?)?;
        if observed_floor != floor {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        self.authority.recheck()?;
        Ok(floor)
    }

    /// Borrows the independent public Source verification DATA from this owner.
    ///
    /// # Errors
    /// Refuses incomplete native flight or pin construction.
    pub fn source_readback_pin_data_v1(
        &self,
    ) -> Result<
        &aos_sandbox_ledger_replay::source_signer_data::PinnedSourceHoldReadbackSignerV1,
        RootAuthorityErrorV1,
    > {
        self.require_ready()?;
        self.authority.pins.source()
    }

    pub(super) fn confirm_gen1_ack_v1(
        &self,
        packet: &[u8],
        floor: &SourceHierarchyFloorRecordV1,
    ) -> Result<(), RootAuthorityErrorV1> {
        self.gen1_owner_loan_v1()?
            .confirm_gen1_ack_v1(packet, floor)
    }
}

impl<'authority, 'origin, 'startup>
    RootAuthorityQ04FlightOriginalV1<'authority, 'origin, 'startup>
{
    pub(super) fn gen1_owner_loan_v1(
        &self,
    ) -> Result<RootAuthorityGen1OwnerLoanV1<'_, 'origin, 'startup>, RootAuthorityErrorV1> {
        self.require_ready()?;
        Ok(RootAuthorityGen1OwnerLoanV1 {
            journal: &self.authority.journal,
            pins: &self.authority.pins,
            current: &self.authority.current,
            names: self.authority.names,
            origin: self.origin,
            nonce: self.nonce_data_v1()?,
            identities: self.identities.ok_or(RootAuthorityErrorV1::Stale)?,
            accepted: self.accepted_v1()?,
        })
    }

    pub(super) fn current_anchored_floor_v1(
        &self,
        source_packet: &[u8],
    ) -> Result<RootAuthorityCurrentGen1LoanV1<'_, 'origin, 'startup>, RootAuthorityErrorV1> {
        self.authority.recheck()?;
        let owner = self.gen1_owner_loan_v1()?;
        owner.admit_gen1_observation_v1()?;
        let accepted = owner.accepted_v1()?;
        if !accepted.completed {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let floor = owner
            .gen1_floor_v1(accepted.acceptance.project())?
            .ok_or(RootAuthorityErrorV1::Conflict)?;
        owner.confirm_gen1_ack_v1(source_packet, &floor)?;
        let source = SourceTreeGenesisReadbackPacketV2::from_packet_bytes(source_packet)?;
        let current = RootAuthorityCurrentGen1LoanV1 {
            owner,
            floor,
            source,
        };
        current.recheck()?;
        Ok(current)
    }

    /// Borrows the actual settled floor after fresh Controller and Source joins.
    ///
    /// # Errors
    /// Refuses a missing Complete, changed original acceptance, malformed
    /// packet, changed saved floor or different source receipt/sequence/ACK.
    pub fn refresh_completed_gen1_v1(
        &mut self,
        controller: &[u8],
        source: &[u8],
    ) -> Result<RootAuthorityGen1LoanV1<'_, 'origin, 'startup>, RootAuthorityErrorV1> {
        self.accept_historical_controller_readback_v1(controller)?;
        self.completed_gen1_after_accepted_v1(controller, source)
    }

    // Only genuine finite role entrypoints call this after strict same-flight
    // Controller acceptance. It does not install or adopt a supplied gen1 cut.
    pub(super) fn completed_gen1_after_accepted_v1(
        &self,
        controller: &[u8],
        source: &[u8],
    ) -> Result<RootAuthorityGen1LoanV1<'_, 'origin, 'startup>, RootAuthorityErrorV1> {
        let accepted = self.accepted_v1()?;
        if !accepted.completed {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let current = self.current_anchored_floor_v1(source)?;
        current.recheck()?;
        let controller_sequence =
            u64::from_be_bytes(aos_sandbox_ledger_replay::data::take(controller, 32)?);
        let names_offset = controller
            .len()
            .checked_sub(192)
            .ok_or(RootAuthorityErrorV1::NonCanonical)?;
        let controller_names =
            ProtectedJournalNamesV1::from_bytes(&controller[names_offset..names_offset + 48])
                .map_err(
                    aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from,
                )?;
        Ok(RootAuthorityGen1LoanV1 {
            current,
            controller_sequence,
            controller_names,
        })
    }
}

impl RootAuthorityGen1LoanV1<'_, '_, '_> {
    /// Borrows the logical floor while retaining its genuine native association.
    #[must_use]
    pub const fn floor(&self) -> &SourceHierarchyFloorRecordV1 {
        self.current.floor()
    }

    /// Rechecks the same accepted flight, complete history and signed Source ACK.
    ///
    /// # Errors
    /// Preserves the actual native or canonical observation failure.
    pub fn recheck(&self) -> Result<(), RootAuthorityErrorV1> {
        self.current.recheck()
    }

    /// Observes the complete native Authority before-state under this gen1 loan.
    ///
    /// # Errors
    /// Preserves original gen1, full native replay and fixed-name failures, or
    /// refuses a changed held state between the two original owner bookends.
    pub fn q04_before_rows_v1(
        &self,
    ) -> Result<(u64, ProtectedJournalNamesV1, aos_sandbox_model::ObjectDigest), RootAuthorityErrorV1>
    {
        self.recheck()?;
        let before = self.current.owner.journal.q04_before_rows_v1()?;
        self.recheck()?;
        Ok(before)
    }

    /// Copies the fresh Controller physical-name and sequence comparison.
    ///
    /// # Errors
    /// Refuses a changed actual gen1 association before or after the projection.
    pub fn controller_coordinates(
        &self,
    ) -> Result<(ProtectedJournalNamesV1, u64), RootAuthorityErrorV1> {
        self.recheck()?;
        let result = (self.controller_names, self.controller_sequence);
        self.recheck()?;
        Ok(result)
    }

    /// Copies the fresh Source physical-name and sequence comparison.
    ///
    /// # Errors
    /// Refuses a changed actual gen1 association before or after the projection.
    pub fn source_coordinates(
        &self,
    ) -> Result<(ProtectedJournalNamesV1, u64), RootAuthorityErrorV1> {
        self.recheck()?;
        let accepted = self.current.owner.accepted_v1()?;
        let result = (accepted.source_names, accepted.source_sequence);
        self.recheck()?;
        Ok(result)
    }
}

impl<'loan, 'origin, 'startup> RootAuthorityGen1LoanV1<'loan, 'origin, 'startup> {
    // Native sibling roles borrow this actual accepted origin. Its own closed
    // methods enforce native loans and their currentness/post order; this is
    // never a raw stream, supplied-parts constructor or public role installer.
    pub(in crate::native) fn original_transport_v1(
        &self,
    ) -> Result<
        aos_sandbox_broker::receiving::RootQ04OriginBorrowerV1<'origin, 'startup>,
        RootAuthorityErrorV1,
    > {
        // This loan already came from the genuine current-gen1 constructor.
        // Copy its same external Origin without inserting another readiness,
        // elapsed-time or financial-health observation at an inert join.
        Ok(self.current.owner.origin)
    }

    // This copies the retained pair only; it does not observe or renew a clock.
    pub(in crate::native) fn original_clock_data_v1(
        &self,
    ) -> Result<(aos_sandbox_model::RawPairedClockSample, std::time::Instant), RootAuthorityErrorV1>
    {
        Ok(self
            .current
            .owner
            .origin
            .try_borrow_mut()?
            .retained_original_clock_data_v1()?)
    }
}

fn gen1_floor_in_journal_v1(
    journal: &crate::native::journal::RootPolicyJournalV1,
    project: ProjectId,
) -> Result<Option<SourceHierarchyFloorRecordV1>, RootAuthorityErrorV1> {
    // The original strict fold examines the complete canonical state. A
    // successor obligation makes revision one historical for this purpose.
    let retained = root_successor::rows(journal.read_view().state())?;
    let original = retained
        .intent
        .or_else(|| retained.archive.map(|archive| archive.original));
    if original.is_some_and(|original| original.project() == project) {
        return Err(RootAuthorityErrorV1::AdmissionClosed);
    }
    journal
        .get(
            RecordNamespace::DesiredState,
            &project_key(FLOOR_PREFIX, project),
        )
        .map(SourceHierarchyFloorRecordV1::from_record_bytes)
        .transpose()
        .map_err(Into::into)
}

fn gen1_observation_demand_for_v1(
    journal: &crate::native::journal::RootPolicyJournalV1,
) -> Result<ResourceVector, RootAuthorityErrorV1> {
    let overflow = || PolicyNativeJournalErrorV1::geometry();
    // Retain the actual canonical family bounds instead of an unrelated
    // transport ceiling: accepted input, receipt/floor backing, both
    // signature preimages and the Source context can coexist here. Fixed
    // arrays and Result/move carriers are counted separately below.
    let backing = CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2
            .checked_add(SOURCE_TREE_GENESIS_READBACK_BYTES_V2)
            .and_then(|bytes| bytes.checked_add(aos_sandbox_protocol::source_genesis_acceptance::CONTROLLER_SOURCE_GENESIS_ACCEPTANCE_BYTES_V2))
            .and_then(|bytes| bytes.checked_add(aos_sandbox_ledger_replay::genesis::SOURCE_TREE_GENESIS_RECEIPT_BYTES_V2))
            .and_then(|bytes| bytes.checked_add(aos_sandbox_ledger_replay::replay::root_genesis_records::SOURCE_HIERARCHY_FLOOR_BYTES_V2))
            .and_then(|bytes| bytes.checked_add(RESOURCE_DOMAIN_V2.len()))
            .and_then(|bytes| bytes.checked_mul(3))
            .ok_or_else(overflow)?;
    let bytes = std::mem::size_of::<ControllerGenesisReadbackDataV1>()
        .checked_mul(3)
        .and_then(|bytes| {
            bytes.checked_add(
                std::mem::size_of::<RootAuthorityGen1LoanV1<'_, '_, '_>>().checked_mul(3)?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                std::mem::size_of::<SourceTreeGenesisIntentContextV1>().checked_mul(3)?,
            )
        })
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<sha2::Sha256>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<u8>>().checked_mul(12)?))
        .and_then(|bytes| bytes.checked_add(backing))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(overflow)?;
    aos_sandbox_ledger_replay::geometry::complete_replay_demand_v1(
        journal.read_view().state(),
        None,
    )?
    .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
    .map_err(|_| overflow().into())
}

// Actual private component borrows permit a final gen1 check while the same
// journal is immutably reborrowed inside its mutable append scope. There is no
// public constructor, arbitrary journal getter or DATA-success adopter.
pub(super) struct RootAuthorityGen1OwnerLoanV1<'owner, 'origin, 'startup> {
    pub(super) journal: &'owner crate::native::journal::RootPolicyJournalV1,
    pub(super) pins: &'owner super::pins::RootAuthorityPinsOriginalV1,
    pub(super) current: &'owner super::currentness::RootAuthorityCurrentCustodyV1,
    pub(super) names: ProtectedJournalNamesV1,
    pub(super) origin: aos_sandbox_broker::receiving::RootQ04OriginBorrowerV1<'origin, 'startup>,
    pub(super) nonce: [u8; 16],
    pub(super) identities: [u32; 4],
    pub(super) accepted: &'owner ControllerGenesisReadbackDataV1,
}

impl RootAuthorityGen1OwnerLoanV1<'_, '_, '_> {
    pub(super) fn recheck(&self) -> Result<(), RootAuthorityErrorV1> {
        super::currentness::require_current_v1(self.journal, self.pins, self.names, self.current)
    }

    pub(super) fn same_owner_v1(&self, other: &Self) -> bool {
        std::ptr::eq(self.journal, other.journal)
            && std::ptr::eq(self.pins, other.pins)
            && std::ptr::eq(self.current, other.current)
            && self.origin.same_origin_v1(&other.origin)
            && std::ptr::eq(self.accepted, other.accepted)
            && self.nonce == other.nonce
            && self.identities == other.identities
    }

    pub(super) fn nonce_data_v1(&self) -> Result<[u8; 16], RootAuthorityErrorV1> {
        Ok(self.nonce)
    }

    pub(super) fn accepted_v1(
        &self,
    ) -> Result<&ControllerGenesisReadbackDataV1, RootAuthorityErrorV1> {
        Ok(self.accepted)
    }

    pub(super) fn gen1_floor_v1(
        &self,
        project: ProjectId,
    ) -> Result<Option<SourceHierarchyFloorRecordV1>, RootAuthorityErrorV1> {
        gen1_floor_in_journal_v1(self.journal, project)
    }

    fn admit_gen1_observation_v1(&self) -> Result<(), RootAuthorityErrorV1> {
        self.journal
            .admit_role_observation_v1(gen1_observation_demand_for_v1(self.journal)?)?;
        Ok(())
    }

    pub(super) fn confirm_gen1_ack_v1(
        &self,
        packet: &[u8],
        floor: &SourceHierarchyFloorRecordV1,
    ) -> Result<(), RootAuthorityErrorV1> {
        self.admit_gen1_observation_v1()?;
        self.recheck()?;
        let accepted = self.accepted_v1()?;
        if !accepted.completed
            || self.gen1_floor_v1(accepted.acceptance.project())?.as_ref() != Some(floor)
        {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let challenge = SourceTreeGenesisChallengeV1::new(
            self.nonce_data_v1()?,
            Some(floor.receipt().intent_digest()),
        )?;
        let observed =
            verify_source_tree_genesis_readback_v2(packet, self.pins.source()?, challenge)?;
        if accepted.source_names != observed.names()
            || accepted.source_sequence != observed.journal_sequence()
            || accepted.source_instance != observed.receipt().map(|receipt| receipt.instance())
        {
            return Err(RootAuthorityErrorV1::Stale);
        }
        if floor.semantic_revision() != 1
            || floor.predecessor().is_some()
            || observed.state() != SourceTreeGenesisStateV1::Anchored
            || observed.receipt() != Some(floor.receipt())
            || observed.ack_floor_digest() != Some(floor.digest())
            || observed.ack_record_digest().is_none()
        {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        self.recheck()?;
        Ok(())
    }
}
