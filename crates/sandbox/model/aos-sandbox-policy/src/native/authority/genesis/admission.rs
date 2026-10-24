//! Retains ordinary genesis admission on the same actual Authority owner.
//!
//! Signed packets are comparison inputs. Native admission also retains the real
//! independent role pins, complete saved history and the original flight nonce.

use aos_sandbox_model::{ObjectDigest, ProjectId, RecordNamespace};
use aos_sandbox_ledger_replay::genesis::SourceTreeGenesisReceiptV1;
use aos_sandbox_ledger_replay::replay::root_genesis_records::project_key;
use aos_sandbox_ledger_replay::replay::root_genesis_records::{
    FLOOR_PREFIX, INSTANCE_KEY, INTENT_PREFIX, PINS_KEY, RootSourceGenesisIntentRecordV1,
    SourceHierarchyFloorRecordV1, decode_instance, instance_bytes,
};
use aos_sandbox_ledger_replay::source_signer_data::source_genesis_readback::SourceTreeGenesisStateV1;
use aos_sandbox_ledger_replay::source_signer_data::{
    PinnedSourceHoldReadbackSignerV1, SourceTreeGenesisChallengeV1,
    SourceTreeGenesisIntentContextV1, VerifiedSourceTreeGenesisReadbackV1,
    verify_source_tree_genesis_readback_v2,
};
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};

use crate::native::authority::RootAuthorityErrorV1;
use crate::native::journal::RootPolicyJournalV1;

use super::controller_readback;
use super::deployment::require_current_deployment;
use super::{
    MAXIMUM_PROJECTS, RootGenesisOwnerRecipeV3, RootProjectGenesisMutationResultsV3,
    RootProjectGenesisSiteV3, RootSourceGenesisAuthorityV1,
};
use aos_sandbox_ledger_replay::source_signer_data::controller_genesis_readback::ControllerGenesisReadbackDataV1 as VerifiedControllerSourceGenesisReadbackV1;

impl RootSourceGenesisAuthorityV1 {
    pub(super) fn require_strict_genesis_recipe_v1(&self) -> Result<(), RootAuthorityErrorV1> {
        if self.genesis_recipe != RootGenesisOwnerRecipeV3::StrictV1 {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        Ok(())
    }

    /// Admits only the signed selected project on this actual project-purpose owner.
    ///
    /// # Errors
    /// Rejects strict packets, changed role pins/cuts, global Empty, different
    /// instances, or a cold unreceipted intent. Intent792 cannot renew admission.
    pub fn accept_controller_project_genesis_v3(
        &mut self,
        packet: &[u8],
    ) -> Result<
        (
            aos_sandbox_ledger_replay::source_signer_data::SourceProjectGenesisChallengeV3,
            SourceTreeGenesisIntentContextV1,
        ),
        RootAuthorityErrorV1,
    > {
        self.recheck()?;
        if self.genesis_recipe != RootGenesisOwnerRecipeV3::ProjectV3 {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let accepted = controller_readback::verify_project_genesis_v3(
            packet,
            self.authority.pins.controller()?,
            self.nonce,
            self.controller_uid,
            self.source_uid,
        )?;
        self.authority
            .pins
            .verify_administrative_input(&accepted.acceptance)?;
        let project = accepted.acceptance.project();
        let instance = decode_instance(
            self.authority
                .journal
                .get(RecordNamespace::DesiredState, INSTANCE_KEY)
                .ok_or(RootAuthorityErrorV1::Conflict)?,
        )?;
        if accepted.source_instance != Some(instance)
            || self.accepted.as_ref().is_some_and(|prior| {
                prior.acceptance != accepted.acceptance
                    || prior.source_names != accepted.source_names
                    || prior.historical && !accepted.historical
                    || prior.completed && !accepted.completed
            })
        {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let prior_floor = self.floor(project)?;
        let prior_intent = self.intent(project)?;
        let intent_digest = if accepted.vacant {
            // A new transport cannot recover boot/D/expiry from Intent792.
            // Keep the old intent/reservation debt instead of reissuing it.
            if prior_intent.is_some() || prior_floor.is_some() {
                return Err(RootAuthorityErrorV1::AdmissionClosed);
            }
            require_current_deployment(&self.authority.journal)?;
            None
        } else {
            Some(if let Some(floor) = &prior_floor {
                if floor.receipt().acceptance_digest() != accepted.acceptance.digest() {
                    return Err(RootAuthorityErrorV1::Conflict);
                }
                floor.receipt().intent_digest()
            } else {
                let intent = prior_intent
                    .as_ref()
                    .ok_or(RootAuthorityErrorV1::Conflict)?;
                require_acceptance(intent, &accepted, self.source_uid)?;
                intent.digest()
            })
        };
        let context = SourceTreeGenesisIntentContextV1::new(
            self.source_uid,
            self.authority.pins.digest()?,
            accepted.acceptance.clone(),
        )?;
        let challenge =
            aos_sandbox_ledger_replay::source_signer_data::SourceProjectGenesisChallengeV3::new(
                self.nonce,
                project,
                intent_digest,
            )
            .map_err(|_| RootAuthorityErrorV1::NonCanonical)?;
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
    pub fn project_genesis_floor_present_v3(&self) -> Result<bool, RootAuthorityErrorV1> {
        self.recheck()?;
        if self.genesis_recipe != RootGenesisOwnerRecipeV3::ProjectV3 {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        let present = self.floor(accepted.acceptance.project())?.is_some();
        self.recheck()?;
        Ok(present)
    }

    pub(super) fn verify_project_genesis_source_v3(
        &self,
        packet: &[u8],
        resident: &mut RootProjectGenesisMutationResultsV3,
    ) -> Result<(), RootAuthorityErrorV1> {
        self.recheck()?;
        if self.genesis_recipe != RootGenesisOwnerRecipeV3::ProjectV3 || resident.source.is_some() {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        let project = accepted.acceptance.project();
        let intent = if accepted.historical {
            let floor = self.floor(project)?;
            let original = self.intent(project)?;
            Some(
                floor
                    .map(|floor| floor.receipt().intent_digest())
                    .or_else(|| original.map(|intent| intent.digest()))
                    .ok_or(RootAuthorityErrorV1::Conflict)?,
            )
        } else {
            None
        };
        let challenge =
            aos_sandbox_ledger_replay::source_signer_data::SourceProjectGenesisChallengeV3::new(
                self.nonce, project, intent,
            )
            .map_err(|_| RootAuthorityErrorV1::NonCanonical)?;
        resident.source = Some(aos_sandbox_ledger_replay::source_signer_data::verify_source_project_genesis_readback_v3(packet, self.authority.pins.source()?, challenge));
        resident.latch(
            RootProjectGenesisSiteV3::Source,
            resident.source.as_ref().is_some_and(Result::is_err),
        );
        let observed = resident
            .source
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(RootAuthorityErrorV1::Stale)?;
        let instance = decode_instance(
            self.authority
                .journal
                .get(RecordNamespace::DesiredState, INSTANCE_KEY)
                .ok_or(RootAuthorityErrorV1::Conflict)?,
        )?;
        if observed.project() != project
            || observed.instance() != instance
            || observed.names() != accepted.source_names
            || observed.journal_sequence() != accepted.source_sequence
            || accepted.vacant != (observed.state() == SourceTreeGenesisStateV1::VacantProject)
        {
            return Err(RootAuthorityErrorV1::Stale);
        }
        if let Some(receipt) = observed.receipt() {
            if receipt.acceptance_digest() != accepted.acceptance.digest()
                || &receipt.seed_packet() != accepted.acceptance.seed_packet()
                || receipt.auth_packet() != accepted.acceptance.auth_packet()
            {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            self.require_retained_project_genesis_receipt_v3(receipt)?;
        }
        Ok(())
    }

    // Root joins its own durable intent or settled floor. Source's independent
    // replay instead joins its complete pending fence; a nonce is neither.
    pub(super) fn require_retained_project_genesis_receipt_v3(
        &self,
        receipt: &SourceTreeGenesisReceiptV1,
    ) -> Result<(), RootAuthorityErrorV1> {
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        let project = accepted.acceptance.project();
        let intent = self.intent(project)?;
        if let Some(intent) = intent.as_ref() {
            require_acceptance(intent, accepted, self.source_uid)?;
        }

        let floor = if intent.is_none() {
            self.floor(project)?
        } else {
            None
        };
        require_receipt_matches_retained_root(
            receipt,
            intent.as_ref(),
            floor.as_ref(),
            self.authority.pins.digest()?,
        )
        .map_err(RootAuthorityErrorV1::from)
    }

    /// Accepts only the full-resource Global family on the same strict Root owner.
    ///
    /// # Errors
    /// Rejects truncated/foreign packets, vacancy purpose, changed original
    /// Source cut or administrative input, and fresh admission in historical mode.
    pub fn accept_controller_resource_global_v2(
        &mut self,
        packet: &[u8],
        historical: bool,
    ) -> Result<(Option<ProjectId>, SourceTreeGenesisChallengeV1), RootAuthorityErrorV1> {
        if packet.len() != aos_sandbox_protocol::source_genesis_geometry::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V2 {
            return Err(RootAuthorityErrorV1::NonCanonical);
        }
        let probe = self.accept_controller_readback_for_scope(packet, !historical)?;
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        if accepted.acceptance.resource_envelope().is_none() || accepted.vacant {
            return Err(RootAuthorityErrorV1::AdmissionClosed);
        }
        probe.ok_or(RootAuthorityErrorV1::Conflict)
    }

    /// Observes the exact retained Global floor after genuine Controller acceptance.
    ///
    /// # Errors
    /// Rejects unavailable strict full-resource admission, vacancy or changed Root custody.
    pub fn resource_global_floor_present_v2(&self) -> Result<bool, RootAuthorityErrorV1> {
        self.require_strict_genesis_recipe_v1()?;
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        if accepted.vacant || accepted.acceptance.resource_envelope().is_none() {
            return Err(RootAuthorityErrorV1::AdmissionClosed);
        }
        let present = self.floor(accepted.acceptance.project())?.is_some();
        self.recheck()?;
        Ok(present)
    }

    pub(super) fn require_global_native_cut_v2(&self) -> Result<(), RootAuthorityErrorV1> {
        self.require_strict_genesis_recipe_v1()?;
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        if accepted.vacant || accepted.acceptance.resource_envelope().is_none() {
            return Err(RootAuthorityErrorV1::AdmissionClosed);
        }
        Ok(())
    }

    pub(super) fn verify_global_genesis_source_v2(
        &self,
        packet: &[u8],
        resident: &mut RootProjectGenesisMutationResultsV3,
    ) -> Result<(), RootAuthorityErrorV1> {
        self.require_strict_genesis_recipe_v1()?;
        self.recheck()?;
        if resident.global_source.is_some() {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        if accepted.vacant || accepted.acceptance.resource_envelope().is_none() {
            return Err(RootAuthorityErrorV1::AdmissionClosed);
        }
        let intent = if accepted.historical {
            let floor = self.floor(accepted.acceptance.project())?;
            let prior = self.intent(accepted.acceptance.project())?;
            Some(
                floor
                    .map(|floor| floor.receipt().intent_digest())
                    .or_else(|| prior.map(|prior| prior.digest()))
                    .ok_or(RootAuthorityErrorV1::Conflict)?,
            )
        } else {
            None
        };
        let challenge = SourceTreeGenesisChallengeV1::new(self.nonce, intent)
            .map_err(|_| RootAuthorityErrorV1::NonCanonical)?;
        resident.global_source = Some(verify_source_tree_genesis_readback_v2(
            packet,
            self.authority.pins.source()?,
            challenge,
        ));
        resident.latch(
            RootProjectGenesisSiteV3::GlobalSource,
            resident.global_source.as_ref().is_some_and(Result::is_err),
        );
        let observed = resident
            .global_source
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(RootAuthorityErrorV1::Stale)?;
        require_same_source_cut(accepted, observed)?;
        if let Some(receipt) = observed.receipt() {
            if receipt.acceptance_digest() != accepted.acceptance.digest()
                || &receipt.seed_packet() != accepted.acceptance.seed_packet()
                || receipt.auth_packet() != accepted.acceptance.auth_packet()
            {
                return Err(RootAuthorityErrorV1::Conflict);
            }
        }
        Ok(())
    }

    /// Returns the Root-created challenge for this one original stream flight.
    #[must_use]
    pub const fn nonce(&self) -> [u8; 16] {
        self.nonce
    }

    /// Borrows the independently pinned Source role for the existing signer RPC.
    ///
    /// This public key does not grant mutation, ancestry or live Root custody.
    ///
    /// # Errors
    /// Refuses an incomplete or failed independently held Source credential.
    #[must_use]
    pub fn source_readback_pin(
        &self,
    ) -> Result<&PinnedSourceHoldReadbackSignerV1, RootAuthorityErrorV1> {
        self.authority.pins.source()
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
    ) -> Result<SourceTreeGenesisIntentContextV1, RootAuthorityErrorV1> {
        self.require_strict_genesis_recipe_v1()?;
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        if !accepted.historical {
            return Err(RootAuthorityErrorV1::Conflict);
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
            let floor = self.floor(project)?.ok_or(RootAuthorityErrorV1::Conflict)?;
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
    pub fn current_admission_expiry(&self) -> Result<i64, RootAuthorityErrorV1> {
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        if accepted.historical {
            return Ok(0);
        }
        require_current_deployment(&self.authority.journal)
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
    ) -> Result<Option<SourceHierarchyFloorRecordV1>, RootAuthorityErrorV1> {
        self.recheck()?;
        let project = self
            .accepted
            .as_ref()
            .ok_or(RootAuthorityErrorV1::Stale)?
            .acceptance
            .project();
        if self.floor(project)?.is_none() {
            return Ok(None);
        }
        self.anchor(source_packet.ok_or(RootAuthorityErrorV1::Conflict)?)
            .map(Some)
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
    ) -> Result<Option<(Option<ProjectId>, SourceTreeGenesisChallengeV1)>, RootAuthorityErrorV1>
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
    ) -> Result<Option<(Option<ProjectId>, SourceTreeGenesisChallengeV1)>, RootAuthorityErrorV1>
    {
        self.accept_controller_readback_for_scope(packet, false)
    }

    pub(super) fn accept_controller_readback_for_scope(
        &mut self,
        packet: &[u8],
        permit_current: bool,
    ) -> Result<Option<(Option<ProjectId>, SourceTreeGenesisChallengeV1)>, RootAuthorityErrorV1>
    {
        self.require_strict_genesis_recipe_v1()?;
        self.recheck()?;
        let accepted = controller_readback::verify(
            packet,
            self.authority.pins.controller()?,
            self.nonce,
            self.controller_uid,
            self.source_uid,
        )?;
        if !permit_current && !accepted.historical {
            return Err(RootAuthorityErrorV1::AdmissionClosed);
        }
        self.authority
            .pins
            .verify_administrative_input(&accepted.acceptance)?;
        // Global Empty can recover an instance/intent created before the first
        // Source append. It cannot reset custody after any project was anchored.
        // Later projects require the distinct actual same-instance vacant cut.
        if accepted.source_instance.is_none()
            && self.authority
                .journal
                .records(RecordNamespace::DesiredState)
                .any(|(key, _)| key.starts_with(FLOOR_PREFIX))
        {
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
        if accepted.vacant {
            let instance = self.authority
                .journal
                .get(RecordNamespace::DesiredState, INSTANCE_KEY)
                .map(decode_instance)
                .transpose()?;
            if instance.is_none()
                || accepted.source_instance != instance
                || self.floor(project)?.is_some()
            {
                return Err(RootAuthorityErrorV1::Conflict);
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
                    return Err(RootAuthorityErrorV1::Conflict);
                }
                Some(floor.receipt().intent_digest())
            } else {
                Some(
                    self.intent(project)?
                        .ok_or(RootAuthorityErrorV1::Conflict)?
                        .digest(),
                )
            }
        } else {
            None
        };
        let challenge = SourceTreeGenesisChallengeV1::new(self.nonce, intent_digest)
            .map_err(|_| RootAuthorityErrorV1::NonCanonical)?;
        self.accepted = Some(accepted);
        Ok(Some((intent_digest.map(|_| project), challenge)))
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
    ) -> Result<(), RootAuthorityErrorV1> {
        self.require_strict_genesis_recipe_v1()?;
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        if !accepted.completed || self.floor(accepted.acceptance.project())?.as_ref() != Some(floor)
        {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let challenge =
            SourceTreeGenesisChallengeV1::new(self.nonce, Some(floor.receipt().intent_digest()))
                .map_err(|_| RootAuthorityErrorV1::NonCanonical)?;
        let observed = verify_source_tree_genesis_readback_v2(
            source_packet,
            self.authority.pins.source()?,
            challenge,
        )
        .map_err(|_| RootAuthorityErrorV1::Stale)?;
        require_same_source_cut(accepted, &observed)?;
        super::current::require_anchored_observation(&observed, floor)?;
        self.recheck()
    }

    pub(super) fn intent(
        &self,
        project: ProjectId,
    ) -> Result<Option<RootSourceGenesisIntentRecordV1>, RootAuthorityErrorV1> {
        self.authority
            .journal
            .get(
                RecordNamespace::DesiredState,
                &project_key(INTENT_PREFIX, project),
            )
            .map(RootSourceGenesisIntentRecordV1::from_record_bytes)
            .transpose()
            .map_err(RootAuthorityErrorV1::from)
    }

    pub(super) fn floor(
        &self,
        project: ProjectId,
    ) -> Result<Option<SourceHierarchyFloorRecordV1>, RootAuthorityErrorV1> {
        // A retained successor obligation closes revision one's current floor.
        // Decoded generation-one DATA cannot renew a populated Tree/Q04 loan.
        if super::successor::retained_root_first_successor_v2(
            &self.authority.journal,
            project,
        )?
        .is_some()
        {
            return Err(RootAuthorityErrorV1::AdmissionClosed);
        }
        self.authority
            .journal
            .get(
                RecordNamespace::DesiredState,
                &project_key(FLOOR_PREFIX, project),
            )
            .map(SourceHierarchyFloorRecordV1::from_record_bytes)
            .transpose()
            .map_err(RootAuthorityErrorV1::from)
    }
}

use aos_sandbox_ledger_replay::replay::root_genesis_records::require_receipt_matches_retained_root_v1 as require_receipt_matches_retained_root;

pub(super) fn require_acceptance(
    intent: &RootSourceGenesisIntentRecordV1,
    accepted: &VerifiedControllerSourceGenesisReadbackV1,
    source_uid: u32,
) -> Result<(), RootAuthorityErrorV1> {
    if intent.accepted_input() != &accepted.acceptance || intent.source_uid() != source_uid {
        return Err(RootAuthorityErrorV1::Conflict);
    }
    Ok(())
}

pub(super) fn require_same_source_cut(
    controller: &VerifiedControllerSourceGenesisReadbackV1,
    source: &VerifiedSourceTreeGenesisReadbackV1,
) -> Result<(), RootAuthorityErrorV1> {
    if controller.source_names != source.names()
        || controller.source_sequence != source.journal_sequence()
    {
        return Err(RootAuthorityErrorV1::Stale);
    }
    if controller.source_instance != source.receipt().map(|receipt| receipt.instance()) {
        return Err(RootAuthorityErrorV1::Stale);
    }
    Ok(())
}
