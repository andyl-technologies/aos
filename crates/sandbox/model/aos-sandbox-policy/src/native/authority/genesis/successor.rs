//! Owns the genuine ordinary Root successor context and its archive joins.
//!
//! Canonical saved-family and signature mechanics remain shared DATA engines.
//! Only the actual private session owns the independent Authority writer and
//! lends a fresh nonce/clock crossing; an archived intent grants no new work.

use aos_sandbox_model::{ObjectDigest, ProjectId, RecordNamespace};
use aos_sandbox_ledger_replay::replay::phase_records::{
    RootFirstSourceSuccessorFloorFieldsV2, RootFirstSourceSuccessorFloorV2,
    RootFirstSourceSuccessorIntentFieldsV2, RootFirstSourceSuccessorIntentV2,
    SourceFirstSuccessorReceiptV2,
};
use aos_sandbox_ledger_replay::replay::root_genesis_records::{
    FLOOR_PREFIX, INSTANCE_KEY, PINS_KEY, SourceHierarchyFloorRecordV1, decode_instance,
};
use aos_sandbox_ledger_replay::replay::root_successor::{
    self as canonical, INTENT_PREFIX, PREFIX, ProjectRowsV3, RootFirstSourceSuccessorArchiveV2,
    Rows, SUCCESSOR_FLOOR_PREFIX,
};
use aos_sandbox_ledger_replay::replay::source_tree_successor::{
    FirstSourceSuccessorNativePhaseV2 as Phase, capacity_request,
    first_source_successor_capacity_delete_v2, first_source_successor_capacity_identity_v2,
    first_source_successor_capacity_record_v2, require_exact_capacity_family,
    sizing_capacity_delete, touches_capacity_purpose, transaction_id,
};
use aos_sandbox_protocol::domain_ledger::capacity::{
    GlobalCapacityReservationPurposeV1 as Purpose, GlobalCapacityReservationRequestV1,
};
use aos_sandbox_broker::canonical_journal::CommitResult;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use aos_sandbox_protocol::source_genesis_wire::FirstSuccessorWireRecipeV3;
use std::collections::BTreeMap;

use super::super::RootAuthorityErrorV1;
use super::{RootFirstSuccessorMutationResultsV2, RootSourceGenesisAuthorityV1};
use crate::native::{PolicyNativeJournalErrorV1, journal::RootPolicyJournalV1};

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

pub(super) fn journal_state(journal: &RootPolicyJournalV1) -> &State {
    journal.read_view().state()
}

pub(super) fn project_rows_v3(
    state: &State,
    project: Option<ProjectId>,
) -> Result<ProjectRowsV3, RootAuthorityErrorV1> {
    canonical::project_rows_v3(state, project).map_err(RootAuthorityErrorV1::from)
}

fn rows(state: &State) -> Result<Rows, RootAuthorityErrorV1> {
    canonical::rows(state).map_err(RootAuthorityErrorV1::from)
}

fn require_predecessor(
    state: &State,
    intent: &RootFirstSourceSuccessorIntentV2,
) -> Result<(), RootAuthorityErrorV1> {
    canonical::require_predecessor(state, intent).map_err(RootAuthorityErrorV1::from)
}

pub(super) fn root_capacity_request(
    intent: &RootFirstSourceSuccessorIntentV2,
) -> Result<GlobalCapacityReservationRequestV1, RootAuthorityErrorV1> {
    canonical::root_capacity_request(intent).map_err(RootAuthorityErrorV1::from)
}

pub(super) fn intent_key(intent: &RootFirstSourceSuccessorIntentV2) -> Vec<u8> {
    canonical::intent_key(intent)
}

pub(super) fn floor_key(floor: &RootFirstSourceSuccessorFloorV2) -> Vec<u8> {
    canonical::floor_key(floor)
}

pub(super) fn require_receipt_intent(
    receipt: &SourceFirstSuccessorReceiptV2,
    intent: &RootFirstSourceSuccessorIntentV2,
) -> Result<(), RootAuthorityErrorV1> {
    canonical::require_receipt_intent(receipt, intent).map_err(RootAuthorityErrorV1::from)
}

pub(super) fn retained_root_first_successor_v2(
    journal: &RootPolicyJournalV1,
    project: ProjectId,
) -> Result<Option<RootFirstSourceSuccessorIntentV2>, RootAuthorityErrorV1> {
    let retained = rows(journal_state(journal))?;
    let original = retained
        .intent
        .or_else(|| retained.archive.map(|archive| archive.original));
    Ok(original.filter(|original| original.project() == project))
}

fn project_saved_rows_v3(
    journal: &RootPolicyJournalV1,
    project: ProjectId,
) -> Result<ProjectRowsV3, RootAuthorityErrorV1> {
    project_rows_v3(journal_state(journal), Some(project))
}

// Both variants are authenticated comparison DATA. Selecting this codec does
// not construct a writer, Root floor loan or original flight.
pub(super) enum SourceSuccessorComparisonV3 {
    Strict(aos_sandbox_ledger_replay::source_signer_data::VerifiedSourceFirstSuccessorReadbackV2),
    Mixed(
        aos_sandbox_ledger_replay::source_signer_data::VerifiedSourceProjectContinuationReadbackV3,
    ),
}

impl SourceSuccessorComparisonV3 {
    pub(super) fn phase(
        &self,
    ) -> aos_sandbox_ledger_replay::source_signer_data::SourceFirstSuccessorReadbackPhaseV2 {
        match self {
            Self::Strict(data) => data.phase(),
            Self::Mixed(data) => data.phase(),
        }
    }

    pub(super) fn names(
        &self,
    ) -> aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1 {
        match self {
            Self::Strict(data) => data.names(),
            Self::Mixed(data) => data.names(),
        }
    }

    pub(super) fn sequence(&self) -> u64 {
        match self {
            Self::Strict(data) => data.sequence(),
            Self::Mixed(data) => data.sequence(),
        }
    }

    pub(super) fn receipt(&self) -> Option<&SourceFirstSuccessorReceiptV2> {
        match self {
            Self::Strict(data) => data.receipt(),
            Self::Mixed(data) => data.receipt(),
        }
    }

    pub(super) fn ack(
        &self,
    ) -> Option<&aos_sandbox_ledger_replay::replay::phase_records::SourceFirstSuccessorAckV2> {
        match self {
            Self::Strict(data) => data.ack(),
            Self::Mixed(data) => data.ack(),
        }
    }

    pub(super) fn genesis_receipt(
        &self,
    ) -> &aos_sandbox_ledger_replay::genesis::SourceTreeGenesisReceiptV1 {
        match self {
            Self::Strict(data) => data.genesis_receipt(),
            Self::Mixed(data) => data.genesis_receipt(),
        }
    }
}

impl RootSourceGenesisAuthorityV1 {
    pub(super) fn require_successor_recipe_v3(
        &self,
        recipe: FirstSuccessorWireRecipeV3,
    ) -> Result<(), RootAuthorityErrorV1> {
        if self.successor_recipe != recipe {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        Ok(())
    }

    pub(super) fn successor_rows_for_project_v3(
        &self,
        project: ProjectId,
    ) -> Result<Rows, RootAuthorityErrorV1> {
        match self.successor_recipe {
            FirstSuccessorWireRecipeV3::StrictV2 => {
                rows(&journal_state(&self.authority.journal)).map_err(Into::into)
            }
            FirstSuccessorWireRecipeV3::MixedV3 => {
                let mut family = project_saved_rows_v3(&self.authority.journal, project)?;
                Ok(Rows {
                    intent: family.intent,
                    archive: family.archives.remove(&project),
                })
            }
        }
    }

    pub(super) fn retained_successor_for_project_v3(
        &self,
        project: ProjectId,
    ) -> Result<Option<RootFirstSourceSuccessorIntentV2>, RootAuthorityErrorV1> {
        if self.successor_recipe == FirstSuccessorWireRecipeV3::StrictV2 {
            return retained_root_first_successor_v2(&self.authority.journal, project);
        }
        let retained = self.successor_rows_for_project_v3(project)?;
        Ok(retained
            .intent
            .or_else(|| retained.archive.map(|archive| archive.original)))
    }

    /// Compares every retained archive before selecting immutable intent DATA.
    ///
    /// Absence remains absence: this never constructs a new admission context,
    /// Root floor loan, writer permission or renewed original nonce/deadline.
    ///
    /// # Errors
    /// Returns a marker while the supplied single-use reservoir retains the
    /// actual comparison cause and every independent owner/name/watermark post.
    pub fn retained_project_successor_context_v3(
        &self,
        project: ProjectId,
        results: &mut RootFirstSuccessorMutationResultsV2,
    ) -> Result<Option<RootFirstSourceSuccessorIntentV2>, ()> {
        self.compare_retained_project_successor_v3(project, None, results)
    }

    /// Compares one exact historical archive against the complete actual map.
    ///
    /// # Errors
    /// Returns a retaining marker for missing/changed archive, original intent,
    /// predecessor, role or capacity joins, or independent post-observation debt.
    pub fn compare_project_successor_archive_v3(
        &self,
        context: &RootFirstSourceSuccessorIntentV2,
        floor: &RootFirstSourceSuccessorFloorV2,
        results: &mut RootFirstSuccessorMutationResultsV2,
    ) -> Result<(), ()> {
        self.compare_retained_project_successor_v3(
            context.project(),
            Some((context, floor)),
            results,
        )
        .map(|_| ())
    }

    /// Selects only an existing immutable intent/archive for historical recovery.
    ///
    /// # Errors
    /// Rejects absent work rather than constructing fresh admission context.
    pub fn historical_first_source_successor_context_v2(
        &self,
        controller_packet: &[u8],
    ) -> Result<RootFirstSourceSuccessorIntentV2, RootAuthorityErrorV1> {
        self.require_successor_recipe_v3(FirstSuccessorWireRecipeV3::StrictV2)?;
        self.historical_successor_context_with_recipe_v3(controller_packet)
    }

    /// Selects an immutable selected-project admission without renewing it.
    ///
    /// # Errors
    /// Rejects missing historical work, foreign framing or any changed join.
    pub fn historical_project_successor_context_v3(
        &self,
        controller_packet: &[u8],
    ) -> Result<RootFirstSourceSuccessorIntentV2, RootAuthorityErrorV1> {
        self.require_successor_recipe_v3(FirstSuccessorWireRecipeV3::MixedV3)?;
        self.historical_successor_context_with_recipe_v3(controller_packet)
    }

    pub(super) fn historical_successor_context_with_recipe_v3(
        &self,
        controller_packet: &[u8],
    ) -> Result<RootFirstSourceSuccessorIntentV2, RootAuthorityErrorV1> {
        let controller = self.verify_first_successor_controller(controller_packet)?;
        let original = self
            .retained_successor_for_project_v3(controller.packet.intent()?.project())?
            .ok_or(RootAuthorityErrorV1::AdmissionClosed)?;
        let checked = self.successor_context_with_recipe_v3(controller_packet)?;
        if checked != original {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        Ok(original)
    }

    /// Selects the original intent or derives new comparison context from custody.
    ///
    /// An archived intent is returned byte-for-byte. A newly constructed value
    /// is only Source-signer comparison DATA until native Prepare has committed.
    ///
    /// # Errors
    /// Rejects foreign observations, pins, fixed roles or semantic predecessors.
    pub fn first_source_successor_context_v2(
        &self,
        controller_packet: &[u8],
    ) -> Result<RootFirstSourceSuccessorIntentV2, RootAuthorityErrorV1> {
        self.require_successor_recipe_v3(FirstSuccessorWireRecipeV3::StrictV2)?;
        self.successor_context_with_recipe_v3(controller_packet)
    }

    /// Derives selected comparison context under the actual mixed Root owner.
    ///
    /// # Errors
    /// Rejects incomplete histories, changed roles, signature or predecessor.
    pub fn project_successor_context_v3(
        &self,
        controller_packet: &[u8],
    ) -> Result<RootFirstSourceSuccessorIntentV2, RootAuthorityErrorV1> {
        self.require_successor_recipe_v3(FirstSuccessorWireRecipeV3::MixedV3)?;
        self.successor_context_with_recipe_v3(controller_packet)
    }

    pub(super) fn successor_context_with_recipe_v3(
        &self,
        controller_packet: &[u8],
    ) -> Result<RootFirstSourceSuccessorIntentV2, RootAuthorityErrorV1> {
        self.recheck()?;
        let controller = self.verify_first_successor_controller(controller_packet)?;
        self.authority
            .pins
            .verify_first_source_successor_v2(&controller.packet)?;
        let project = controller.packet.intent()?.project();
        if let Some(original) = self.retained_successor_for_project_v3(project)? {
            if original.approval_packet() != &controller.packet
                || original.begin() != controller.begin.digest()
                || original.source_uid() != self.source_uid
                || controller
                    .root_intent
                    .is_some_and(|digest| digest != original.digest())
            {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            self.recheck()?;
            return Ok(original);
        }
        if controller.phase
            != crate::controller_successor_data::ControllerObservationPhaseV2::Before
        {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let clock = super::clock::kernel_pair()?;
        crate::controller_successor_data::require_approval_clock(&controller.packet, clock)?;
        let signed_deadline = controller
            .packet
            .issued_boottime()?
            .checked_add(
                u64::from(controller.packet.intent()?.validity_seconds())
                    .checked_mul(1_000_000_000)
                    .ok_or(RootAuthorityErrorV1::NonCanonical)?,
            )
            .ok_or(RootAuthorityErrorV1::NonCanonical)?;
        let custody_bound = clock
            .boottime_nanoseconds()
            .checked_add(60_000_000_000)
            .ok_or(RootAuthorityErrorV1::NonCanonical)?;
        let original =
            RootFirstSourceSuccessorIntentV2::new(RootFirstSourceSuccessorIntentFieldsV2 {
                nonce: self.nonce,
                approval: controller.packet.clone(),
                begin: controller.begin.digest(),
                source_uid: self.source_uid,
                source_names: controller.source_names,
                predecessor_floor: controller.begin.predecessor_floor(),
                predecessor_revision: 1,
                old_tree_head: controller.begin.old_tree_head(),
                old_lineage_head: controller.begin.old_lineage_head(),
                next_tree_commit: controller.begin.next_tree_commit(),
                roles: self.authority.pins.digest()?,
                boot: clock.host_boot_id(),
                boottime_deadline: signed_deadline.min(custody_bound),
                expires_wall: controller.packet.expires_wall()?,
            })
            .map_err(RootAuthorityErrorV1::from)?;
        require_predecessor(&journal_state(&self.authority.journal), &original)?;
        self.recheck()?;
        Ok(original)
    }

    pub(super) fn verify_first_successor_controller(
        &self,
        bytes: &[u8],
    ) -> Result<
        crate::controller_successor_data::VerifiedControllerFirstSuccessorObservationV2,
        RootAuthorityErrorV1,
    > {
        self.recheck()?;
        let controller = match self.successor_recipe {
            FirstSuccessorWireRecipeV3::StrictV2 => {
                crate::controller_successor_data::verify_controller_first_successor_readback_v2(
                    bytes,
                    self.authority.pins.controller()?,
                    self.nonce,
                    self.controller_uid,
                    self.source_uid,
                )?
            }
            FirstSuccessorWireRecipeV3::MixedV3 => {
                crate::controller_successor_data::verify_controller_project_successor_readback_v3(
                    bytes,
                    self.authority.pins.controller()?,
                    self.nonce,
                    self.controller_uid,
                    self.source_uid,
                )?
                .data
            }
        };
        self.authority
            .pins
            .verify_first_source_successor_v2(&controller.packet)?;
        self.recheck()?;
        Ok(controller)
    }

    pub(super) fn observe_first_successor_source(
        &self,
        context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8],
        source_packet: &[u8],
    ) -> Result<SourceSuccessorComparisonV3, RootAuthorityErrorV1> {
        let controller = self.verify_first_successor_controller(controller_packet)?;
        if context.approval_packet() != &controller.packet
            || context.begin() != controller.begin.digest()
            || context.roles() != self.authority.pins.digest()?
            || context.source_uid() != self.source_uid
        {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let resource = context.approval_packet().has_resource_authorization();
        let source = match (self.successor_recipe, resource) {
            (FirstSuccessorWireRecipeV3::StrictV2, false) => SourceSuccessorComparisonV3::Strict(
                aos_sandbox_ledger_replay::source_signer_data::verify_source_first_successor_readback_v2(source_packet, self.authority.pins.source()?, self.nonce, context)?,
            ),
            (FirstSuccessorWireRecipeV3::MixedV3, false) => SourceSuccessorComparisonV3::Mixed(
                aos_sandbox_ledger_replay::source_signer_data::verify_source_project_continuation_readback_v3(source_packet, self.authority.pins.source()?, self.nonce, context)?,
            ),
            (FirstSuccessorWireRecipeV3::StrictV2, true) => SourceSuccessorComparisonV3::Strict(
                aos_sandbox_ledger_replay::source_signer_data::source_successor_readback::verify_source_resource_first_successor_readback_v4(source_packet, self.authority.pins.source()?, self.nonce, context)?,
            ),
            (FirstSuccessorWireRecipeV3::MixedV3, true) => SourceSuccessorComparisonV3::Mixed(
                aos_sandbox_ledger_replay::source_signer_data::source_successor_readback::verify_source_resource_project_continuation_readback_v5(source_packet, self.authority.pins.source()?, self.nonce, context)?,
            ),
        };
        if source.names() != controller.source_names
            || source.sequence() != controller.source_sequence
            || source.receipt() != controller.receipt.as_ref()
            || source.ack() != controller.ack.as_ref()
            || source.genesis_receipt().instance() != context.instance()
            || source.genesis_receipt().tree_head() != context.old_tree_head()
            || source.genesis_receipt().lineage_head() != context.old_lineage_head()
        {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        self.recheck()?;
        Ok(source)
    }

    pub(super) fn require_first_successor_admission(
        &self,
        intent: &RootFirstSourceSuccessorIntentV2,
    ) -> Result<(), RootAuthorityErrorV1> {
        self.recheck()?;
        super::deployment::require_current_deployment(&self.authority.journal)?;
        let clock = super::clock::kernel_pair()?;
        crate::controller_successor_data::require_approval_clock(intent.approval_packet(), clock)?;
        if clock.host_boot_id() != intent.boot()
            || clock.boottime_nanoseconds() >= intent.boottime_deadline()
            || u64::try_from(clock.wall_seconds())
                .map_err(|_| RootAuthorityErrorV1::AdmissionClosed)?
                >= intent.expires_wall()
        {
            return Err(RootAuthorityErrorV1::AdmissionClosed);
        }
        Ok(())
    }

    /// Rejoins genuine Controller Complete, Source ACK and the full current archive.
    ///
    /// # Errors
    /// Rejects absent or changed completion, current observation or archive.
    pub fn confirm_first_successor_ack_v2(
        &self,
        context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8],
        source_packet: &[u8],
        floor: &RootFirstSourceSuccessorFloorV2,
    ) -> Result<[u8; 96], RootAuthorityErrorV1> {
        self.require_successor_recipe_v3(FirstSuccessorWireRecipeV3::StrictV2)?;
        self.confirm_successor_ack_with_recipe_v3(context, controller_packet, source_packet, floor)
    }

    /// Rejoins the selected Complete, Source ACK and full current Root archive.
    ///
    /// # Errors
    /// Rejects a foreign codec, project, role, current observation or archive.
    pub fn confirm_project_successor_ack_v3(
        &self,
        context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8],
        source_packet: &[u8],
        floor: &RootFirstSourceSuccessorFloorV2,
    ) -> Result<[u8; 96], RootAuthorityErrorV1> {
        self.require_successor_recipe_v3(FirstSuccessorWireRecipeV3::MixedV3)?;
        self.confirm_successor_ack_with_recipe_v3(context, controller_packet, source_packet, floor)
    }

    pub(super) fn confirm_successor_ack_with_recipe_v3(
        &self,
        context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8],
        source_packet: &[u8],
        floor: &RootFirstSourceSuccessorFloorV2,
    ) -> Result<[u8; 96], RootAuthorityErrorV1> {
        let source =
            self.observe_first_successor_source(context, controller_packet, source_packet)?;
        let controller = self.verify_first_successor_controller(controller_packet)?;
        let complete = controller
            .complete
            .as_ref()
            .ok_or(RootAuthorityErrorV1::Conflict)?;
        let ack = source.ack().ok_or(RootAuthorityErrorV1::Conflict)?;
        if controller.phase != crate::controller_successor_data::ControllerObservationPhaseV2::Completed
            || source.phase() != aos_sandbox_ledger_replay::source_signer_data::SourceFirstSuccessorReadbackPhaseV2::Anchored
            || complete.floor() != floor.digest() || complete.ack() != ack.digest()
            || source.receipt() != Some(floor.receipt())
        {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let archive = self
            .successor_rows_for_project_v3(context.project())?
            .archive
            .ok_or(RootAuthorityErrorV1::Conflict)?;
        if &archive.floor != floor || &archive.original != context {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let mut payload = [0; 96];
        payload[..32].copy_from_slice(floor.digest().as_bytes());
        payload[32..64].copy_from_slice(complete.digest().as_bytes());
        payload[64..].copy_from_slice(ack.digest().as_bytes());
        self.recheck()?;
        Ok(payload)
    }

    /// Borrows current populated floor custody after genuine completion joins.
    ///
    /// # Errors
    /// Rejects a changed full archive or either actual fresh observation.
    pub fn current_anchored_first_successor_floor_v2<'root>(
        &'root self,
        context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8],
        source_packet: &[u8],
        floor: &RootFirstSourceSuccessorFloorV2,
    ) -> Result<super::current::CurrentRootFirstSourceSuccessorFloorV2<'root>, RootAuthorityErrorV1>
    {
        let completion =
            self.confirm_first_successor_ack_v2(context, controller_packet, source_packet, floor)?;
        let archive = rows(&journal_state(&self.authority.journal))?
            .archive
            .ok_or(RootAuthorityErrorV1::Conflict)?;
        super::current::CurrentRootFirstSourceSuccessorFloorV2::from_completed_owner(
            self, archive, completion,
        )
    }

    pub(super) fn require_current_first_successor_archive_v2(
        &self,
        archive: &RootFirstSourceSuccessorArchiveV2,
    ) -> Result<(), RootAuthorityErrorV1> {
        self.require_successor_recipe_v3(FirstSuccessorWireRecipeV3::StrictV2)?;
        self.recheck()?;
        if rows(&journal_state(&self.authority.journal))?
            .archive
            .as_ref()
            != Some(archive)
        {
            return Err(RootAuthorityErrorV1::Stale);
        }
        self.recheck()
    }

    /// Borrows the selected populated current floor under the real mixed owner.
    ///
    /// # Errors
    /// Rejects a changed full family, fresh completion join or selected archive.
    pub fn current_project_successor_floor_v3<'root>(
        &'root self,
        context: &RootFirstSourceSuccessorIntentV2,
        controller_packet: &[u8],
        source_packet: &[u8],
        floor: &RootFirstSourceSuccessorFloorV2,
    ) -> Result<super::current::CurrentRootProjectSuccessorFloorV3<'root>, RootAuthorityErrorV1>
    {
        let completion = self.confirm_project_successor_ack_v3(
            context,
            controller_packet,
            source_packet,
            floor,
        )?;
        let archive = self
            .successor_rows_for_project_v3(context.project())?
            .archive
            .ok_or(RootAuthorityErrorV1::Conflict)?;
        super::current::CurrentRootProjectSuccessorFloorV3::from_completed_owner(
            self, archive, completion,
        )
    }

    pub(super) fn require_current_project_successor_archive_v3(
        &self,
        archive: &RootFirstSourceSuccessorArchiveV2,
    ) -> Result<(), RootAuthorityErrorV1> {
        self.require_successor_recipe_v3(FirstSuccessorWireRecipeV3::MixedV3)?;
        self.recheck()?;
        if self
            .successor_rows_for_project_v3(archive.original.project())?
            .archive
            .as_ref()
            != Some(archive)
        {
            return Err(RootAuthorityErrorV1::Stale);
        }
        self.recheck()
    }
}
