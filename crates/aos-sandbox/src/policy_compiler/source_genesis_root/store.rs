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
    VerifiedSourceTreeGenesisReadbackV1, verify_source_tree_genesis_readback_v1,
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
    journal: Journal,
    pins: RootGenesisRolePinsV1,
    names: ProtectedJournalNamesV1,
    nonce: [u8; 16],
    controller_uid: u32,
    source_uid: u32,
    pub(super) accepted: Option<VerifiedControllerSourceGenesisReadbackV1>,
}

impl RootSourceGenesisAuthorityV1 {
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
            let observed = verify_source_tree_genesis_readback_v1(
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
            verify_source_tree_genesis_readback_v1(source_packet, &self.pins.source, challenge)
                .map_err(|_| SourceGenesisErrorV1::Stale)?;
        require_same_source_cut(accepted, &observed)?;
        let receipt = observed
            .receipt()
            .ok_or(SourceGenesisErrorV1::Conflict)?
            .clone();
        if receipt.acceptance_digest() != accepted.acceptance.digest()
            || &receipt.seed_packet() != accepted.acceptance.seed_packet()
            || &receipt.auth_packet() != accepted.acceptance.auth_packet()
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
            verify_source_tree_genesis_readback_v1(source_packet, &self.pins.source, challenge)
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

fn require_current_deployment(journal: &Journal) -> Result<i64, SourceGenesisErrorV1> {
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

fn validate_history(
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
    Ok(())
}
