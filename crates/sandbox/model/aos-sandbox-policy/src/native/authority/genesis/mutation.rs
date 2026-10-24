//! Retains ordinary genesis mutations on the same actual Authority owner.
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

use super::admission::{require_acceptance, require_same_source_cut};
use super::controller_readback;
use super::deployment::require_current_deployment;
use super::{INSTANCE_TRANSACTION_DOMAIN, RootProjectGenesisSiteV3};
use super::{MAXIMUM_PROJECTS, RootGenesisOwnerRecipeV3, RootSourceGenesisAuthorityV1};
use aos_sandbox_broker::root_nonce::fresh_root_nonce;

use super::{GlobalRootGenesisNativeCutV2, RootProjectGenesisMutationResultsV3};

impl RootSourceGenesisAuthorityV1 {
    pub(super) fn ensure_global_instance_retained_v2(
        &mut self,
        original: &aos_sandbox_model::RawPairedClockSample,
        deadline: std::time::Instant,
        resident: &mut RootProjectGenesisMutationResultsV3,
    ) -> Result<(), RootAuthorityErrorV1> {
        if resident.instance_preparation.is_some() {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        resident.instance_preparation = Some((|| {
            if self
                .authority
                .journal
                .get(RecordNamespace::DesiredState, INSTANCE_KEY)
                .is_some()
            {
                return Ok(());
            }
            let mut instance = [0; 32];
            instance[..16].copy_from_slice(&fresh_root_nonce()?);
            instance[16..].copy_from_slice(&fresh_root_nonce()?);
            let bytes = instance_bytes(instance)?;
            let digest = aos_sandbox_ledger_replay::data::hash(INSTANCE_TRANSACTION_DOMAIN, &bytes);
            let mut id = [0; 16];
            id.copy_from_slice(&digest.as_bytes()[..16]);
            resident.instance_transaction = Some(JournalTransaction::new(
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
                        self.authority.pins.record_bytes()?.to_vec(),
                    ),
                ],
            )?);
            self.recheck()?;
            Ok(())
        })());
        resident.latch(
            RootProjectGenesisSiteV3::InstancePreparation,
            resident
                .instance_preparation
                .as_ref()
                .is_some_and(Result::is_err),
        );
        if resident.first_failure.is_none() {
            if let Some(transaction) = &resident.instance_transaction {
                let returned = self.commit_global_genesis_v2(
                    transaction,
                    super::native_cut::RootGenesisCapacityBorrowV1::Initialize,
                    original,
                    deadline,
                    &mut resident.instance_crossing,
                    &mut resident.instance_advisory,
                );
                resident.instance_native = Some(returned);
                resident.latch(
                    RootProjectGenesisSiteV3::InstanceNative,
                    resident
                        .instance_native
                        .as_ref()
                        .is_some_and(Result::is_err),
                );
            }
        }
        resident.instance_readback = Some((|| {
            let bytes = self
                .authority
                .journal
                .get(RecordNamespace::DesiredState, INSTANCE_KEY)
                .ok_or(RootAuthorityErrorV1::Stale)?;
            decode_instance(bytes)?;
            if let Some(transaction) = &resident.instance_transaction {
                if transaction.records().first().and_then(JournalRecord::value) != Some(bytes) {
                    return Err(RootAuthorityErrorV1::Stale);
                }
            }
            self.recheck()
        })());
        resident.latch(
            RootProjectGenesisSiteV3::InstanceReadback,
            resident
                .instance_readback
                .as_ref()
                .is_some_and(Result::is_err),
        );
        if resident.first_failure.is_some() {
            Err(RootAuthorityErrorV1::Stale)
        } else {
            Ok(())
        }
    }

    /// Prepares strict resource-bearing Global genesis with its real native outcomes retained.
    ///
    /// # Errors
    /// Retains source verification, instance creation, reservation, readback and
    /// original-clock failures. An old intent permits only exact recovery.
    pub fn prepare_global_genesis_v2(
        &mut self,
        packet: &[u8],
        original: &aos_sandbox_model::RawPairedClockSample,
        deadline: std::time::Instant,
        resident: &mut RootProjectGenesisMutationResultsV3,
    ) -> Result<RootSourceGenesisIntentRecordV1, ()> {
        if resident.preparation.is_some() {
            return Err(());
        }
        let preparation = (|| {
            self.verify_global_genesis_source_v2(packet, resident)?;
            let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
            let project = accepted.acceptance.project();
            if self.floor(project)?.is_some() {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            if let Some(intent) = self.intent(project)? {
                require_acceptance(&intent, accepted, self.source_uid)?;
                let receipt = resident
                    .global_source
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .and_then(VerifiedSourceTreeGenesisReadbackV1::receipt);
                match receipt {
                    Some(receipt)
                        if receipt.intent_digest() == intent.digest()
                            && receipt.instance() == intent.instance()
                            && receipt.acceptance_digest() == intent.acceptance() => {}
                    None if !accepted.historical => {
                        require_current_deployment(&self.authority.journal)?;
                    }
                    _ => return Err(RootAuthorityErrorV1::Conflict),
                }
                resident.intent = Some(intent);
                return Ok(());
            }
            let observed = resident
                .global_source
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(RootAuthorityErrorV1::Stale)?;
            if accepted.historical
                || observed.state() != SourceTreeGenesisStateV1::Empty
                || self
                    .authority
                    .journal
                    .records(RecordNamespace::DesiredState)
                    .any(|(key, _)| key.starts_with(INTENT_PREFIX))
                || self
                    .authority
                    .journal
                    .records(RecordNamespace::DesiredState)
                    .filter(|(key, _)| key.starts_with(FLOOR_PREFIX))
                    .count()
                    >= MAXIMUM_PROJECTS
            {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            require_current_deployment(&self.authority.journal)?;
            let acceptance = accepted.acceptance.clone();
            self.ensure_global_instance_retained_v2(original, deadline, resident)?;
            let instance = decode_instance(
                self.authority
                    .journal
                    .get(RecordNamespace::DesiredState, INSTANCE_KEY)
                    .ok_or(RootAuthorityErrorV1::Stale)?,
            )?;
            let intent = RootSourceGenesisIntentRecordV1::new(
                instance,
                self.source_uid,
                self.nonce,
                acceptance,
                self.authority.pins.digest()?,
            )?;
            resident.prepared = Some(super::capacity::PreparedRootGenesisCapacityOriginalV1::new());
            let prepared = resident
                .prepared
                .as_mut()
                .ok_or(RootAuthorityErrorV1::Stale)?;
            prepared
                .prepare_once(
                    &self.authority,
                    super::super::capacity::request(&intent),
                    super::super::capacity::admission_id(&intent),
                )
                .map_err(|()| RootAuthorityErrorV1::Stale)?;
            let prepared = resident
                .prepared
                .as_ref()
                .ok_or(RootAuthorityErrorV1::Stale)?;
            let transaction = JournalTransaction::new(
                super::super::capacity::admission_id(&intent),
                vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        aos_sandbox_ledger_replay::replay::root_genesis_capacity::intent_key(
                            &intent,
                        ),
                        intent.record_bytes().to_vec(),
                    ),
                    prepared.record()?.clone(),
                ],
            )?;
            self.preflight_genesis_v1(
                &transaction,
                super::advisory::RootGenesisAdvisoryRecipeV1::GlobalPrepared(prepared),
                &mut resident.first_advisory,
            )?;
            resident.intent = Some(intent);
            resident.transaction = Some(transaction);
            self.recheck()?;
            require_current_deployment(&self.authority.journal)?;
            Ok(())
        })();
        resident.preparation = Some(preparation);
        resident.latch(
            RootProjectGenesisSiteV3::Preparation,
            resident.preparation.as_ref().is_some_and(Result::is_err),
        );
        if resident.first_failure.is_none() {
            if let (Some(prepared), Some(transaction)) = (&resident.prepared, &resident.transaction)
            {
                resident.native_prepare = Some(
                    self.commit_global_genesis_v2(
                        transaction,
                        super::native_cut::RootGenesisCapacityBorrowV1::Prepared(prepared),
                        original,
                        deadline,
                        &mut resident.prepare_crossing,
                        &mut resident.commit_advisory,
                    )
                    .and_then(|committed| Ok((committed, prepared.retained_after_commit_v1()?))),
                );
                resident.latch(
                    RootProjectGenesisSiteV3::NativePrepare,
                    resident.native_prepare.as_ref().is_some_and(Result::is_err),
                );
            }
        }
        resident.readback = Some((|| {
            let intent = resident
                .intent
                .as_ref()
                .ok_or(RootAuthorityErrorV1::Stale)?;
            if self.intent(intent.project())?.as_ref() != Some(intent) {
                return Err(RootAuthorityErrorV1::Stale);
            }
            Ok(())
        })());
        resident.latch(
            RootProjectGenesisSiteV3::Readback,
            resident.readback.as_ref().is_some_and(Result::is_err),
        );
        resident.posts(self, original, deadline);
        if resident.error().is_some() {
            Err(())
        } else {
            resident.intent.as_ref().cloned().ok_or(())
        }
    }

    /// Anchors the same Global receipt without releasing uncertain original custody.
    ///
    /// # Errors
    /// Retains every verification/native/readback result; exact prior floors
    /// are compared without another append or renewed original deadline.
    pub fn anchor_global_genesis_v2(
        &mut self,
        packet: &[u8],
        original: &aos_sandbox_model::RawPairedClockSample,
        deadline: std::time::Instant,
        resident: &mut RootProjectGenesisMutationResultsV3,
    ) -> Result<SourceHierarchyFloorRecordV1, ()> {
        if resident.preparation.is_some() {
            return Err(());
        }
        resident.preparation = Some((|| {
            self.verify_global_genesis_source_v2(packet, resident)?;
            let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
            let receipt = resident
                .global_source
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .and_then(VerifiedSourceTreeGenesisReadbackV1::receipt)
                .ok_or(RootAuthorityErrorV1::Conflict)?
                .clone();
            let floor = SourceHierarchyFloorRecordV1::new(receipt, self.authority.pins.digest()?)?;
            if let Some(prior) = self.floor(floor.project())? {
                if prior != floor {
                    return Err(RootAuthorityErrorV1::Conflict);
                }
                resident.floor = Some(prior);
                return Ok(());
            }
            let intent = self
                .intent(floor.project())?
                .ok_or(RootAuthorityErrorV1::Conflict)?;
            require_acceptance(&intent, accepted, self.source_uid)?;
            if floor.receipt().intent_digest() != intent.digest() {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            let identity = super::capacity::RootGenesisCapacityOriginalV1::identity_for_v1(
                &self.authority,
                &super::super::capacity::request(&intent),
                super::super::capacity::admission_id(&intent),
                &mut resident.recovery_owner,
            )?;
            let reservation = super::capacity::RootGenesisCapacityOriginalV1::recover_v1(
                &self.authority,
                identity,
            )?;
            let transaction = JournalTransaction::new(
                super::super::capacity::floor_transaction_id(&floor),
                vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        aos_sandbox_ledger_replay::replay::root_genesis_capacity::floor_key(&floor),
                        floor.record_bytes().to_vec(),
                    ),
                    JournalRecord::delete(
                        RecordNamespace::DesiredState,
                        aos_sandbox_ledger_replay::replay::root_genesis_capacity::intent_key(
                            &intent,
                        ),
                    ),
                    reservation.settlement_record(),
                ],
            )?;
            self.preflight_genesis_v1(
                &transaction,
                super::advisory::RootGenesisAdvisoryRecipeV1::GlobalAnchor(&reservation),
                &mut resident.first_advisory,
            )?;
            resident.transaction = Some(transaction);
            resident.reservation = Some(reservation);
            resident.floor = Some(floor);
            self.recheck()
        })());
        resident.latch(
            RootProjectGenesisSiteV3::Preparation,
            resident.preparation.as_ref().is_some_and(Result::is_err),
        );
        if resident.first_failure.is_none() {
            if let (Some(reservation), Some(transaction)) =
                (&resident.reservation, &resident.transaction)
            {
                resident.native_anchor = Some(self.commit_global_genesis_v2(
                    transaction,
                    super::native_cut::RootGenesisCapacityBorrowV1::Anchor(reservation),
                    original,
                    deadline,
                    &mut resident.anchor_crossing,
                    &mut resident.commit_advisory,
                ));
                resident.latch(
                    RootProjectGenesisSiteV3::NativeAnchor,
                    resident.native_anchor.as_ref().is_some_and(Result::is_err),
                );
            }
        }
        resident.readback = Some((|| {
            let floor = resident.floor.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
            if self.floor(floor.project())?.as_ref() != Some(floor)
                || self.intent(floor.project())?.is_some()
            {
                return Err(RootAuthorityErrorV1::Stale);
            }
            Ok(())
        })());
        resident.latch(
            RootProjectGenesisSiteV3::Readback,
            resident.readback.as_ref().is_some_and(Result::is_err),
        );
        resident.posts(self, original, deadline);
        if resident.error().is_some() {
            Err(())
        } else {
            resident.floor.as_ref().cloned().ok_or(())
        }
    }

    /// Prepares genuine selected genesis with the existing purpose-six reservation.
    ///
    /// # Errors
    /// Returns a marker retaining source/native/owner/clock Results and buffers.
    /// Cold vacancy with an old intent is fenced; historical Source receipts
    /// permit only the same original settlement suffix.
    pub fn prepare_project_genesis_v3(
        &mut self,
        packet: &[u8],
        original: &aos_sandbox_model::RawPairedClockSample,
        deadline: std::time::Instant,
        resident: &mut RootProjectGenesisMutationResultsV3,
    ) -> Result<RootSourceGenesisIntentRecordV1, ()> {
        if resident.preparation.is_some() {
            return Err(());
        }
        resident.preparation = Some((|| {
            self.verify_project_genesis_source_v3(packet, resident)?;
            let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
            let project = accepted.acceptance.project();
            if self.floor(project)?.is_some() {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            if let Some(intent) = self.intent(project)? {
                require_acceptance(&intent, accepted, self.source_uid)?;
                let receipt = resident
                    .source
                    .as_ref()
                    .and_then(|result| result.as_ref().ok())
                    .and_then(|observed| observed.receipt())
                    .ok_or(RootAuthorityErrorV1::AdmissionClosed)?;
                if receipt.intent_digest() != intent.digest()
                    || receipt.instance() != intent.instance()
                {
                    return Err(RootAuthorityErrorV1::Conflict);
                }
                resident.intent = Some(intent);
                return Ok(());
            }
            if !accepted.vacant
                || accepted.historical
                || self
                    .authority
                    .journal
                    .records(RecordNamespace::DesiredState)
                    .any(|(key, _)| key.starts_with(INTENT_PREFIX))
                || self
                    .authority
                    .journal
                    .records(RecordNamespace::DesiredState)
                    .filter(|(key, _)| key.starts_with(FLOOR_PREFIX))
                    .count()
                    >= MAXIMUM_PROJECTS
            {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            require_current_deployment(&self.authority.journal)?;
            let instance = decode_instance(
                self.authority
                    .journal
                    .get(RecordNamespace::DesiredState, INSTANCE_KEY)
                    .ok_or(RootAuthorityErrorV1::Conflict)?,
            )?;
            let intent = RootSourceGenesisIntentRecordV1::new(
                instance,
                self.source_uid,
                self.nonce,
                accepted.acceptance.clone(),
                self.authority.pins.digest()?,
            )?;
            resident.prepared = Some(super::capacity::PreparedRootGenesisCapacityOriginalV1::new());
            let prepared = resident
                .prepared
                .as_mut()
                .ok_or(RootAuthorityErrorV1::Stale)?;
            prepared
                .prepare_once(
                    &self.authority,
                    super::super::capacity::request(&intent),
                    super::super::capacity::admission_id(&intent),
                )
                .map_err(|()| RootAuthorityErrorV1::Stale)?;
            let prepared = resident
                .prepared
                .as_ref()
                .ok_or(RootAuthorityErrorV1::Stale)?;
            let transaction = JournalTransaction::new(
                super::super::capacity::admission_id(&intent),
                vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        aos_sandbox_ledger_replay::replay::root_genesis_capacity::intent_key(
                            &intent,
                        ),
                        intent.record_bytes().to_vec(),
                    ),
                    prepared.record()?.clone(),
                ],
            )?;
            self.preflight_genesis_v1(
                &transaction,
                super::advisory::RootGenesisAdvisoryRecipeV1::ProjectPrepared(project, prepared),
                &mut resident.first_advisory,
            )?;
            resident.intent = Some(intent);
            resident.transaction = Some(transaction);
            self.recheck()?;
            require_current_deployment(&self.authority.journal)?;
            Ok(())
        })());
        resident.latch(
            RootProjectGenesisSiteV3::Preparation,
            resident.preparation.as_ref().is_some_and(Result::is_err),
        );
        if resident.first_failure.is_none() {
            if let (Some(prepared), Some(transaction), Some(intent)) =
                (&resident.prepared, &resident.transaction, &resident.intent)
            {
                resident.native_prepare = Some(
                    self.commit_project_genesis_v3(
                        transaction,
                        super::native_cut::RootGenesisCapacityBorrowV1::Prepared(prepared),
                        intent.project(),
                        original,
                        deadline,
                        &mut resident.prepare_crossing,
                        &mut resident.commit_advisory,
                    )
                    .and_then(|committed| Ok((committed, prepared.retained_after_commit_v1()?))),
                );
                resident.latch(
                    RootProjectGenesisSiteV3::NativePrepare,
                    resident.native_prepare.as_ref().is_some_and(Result::is_err),
                );
            }
        }
        resident.readback = Some((|| {
            let intent = resident
                .intent
                .as_ref()
                .ok_or(RootAuthorityErrorV1::Stale)?;
            if self.intent(intent.project())?.as_ref() != Some(intent) {
                return Err(RootAuthorityErrorV1::Stale);
            }
            Ok(())
        })());
        resident.latch(
            RootProjectGenesisSiteV3::Readback,
            resident.readback.as_ref().is_some_and(Result::is_err),
        );
        resident.posts(self, original, deadline);
        if resident.error().is_some() {
            Err(())
        } else {
            resident.intent.as_ref().cloned().ok_or(())
        }
    }

    /// Anchors only the actual selected Source receipt with its original suffix.
    ///
    /// # Errors
    /// Returns a marker retaining all Results; conflicting or ambiguous progress
    /// remains fenced and cannot be retried on this reservoir.
    pub fn anchor_project_genesis_v3(
        &mut self,
        packet: &[u8],
        original: &aos_sandbox_model::RawPairedClockSample,
        deadline: std::time::Instant,
        resident: &mut RootProjectGenesisMutationResultsV3,
    ) -> Result<SourceHierarchyFloorRecordV1, ()> {
        if resident.preparation.is_some() {
            return Err(());
        }
        resident.preparation = Some((|| {
            self.verify_project_genesis_source_v3(packet, resident)?;
            let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
            let observed = resident
                .source
                .as_ref()
                .and_then(|result| result.as_ref().ok())
                .ok_or(RootAuthorityErrorV1::Stale)?;
            let receipt = observed
                .receipt()
                .ok_or(RootAuthorityErrorV1::Conflict)?
                .clone();
            let floor = SourceHierarchyFloorRecordV1::new(receipt, self.authority.pins.digest()?)?;
            if let Some(prior) = self.floor(floor.project())? {
                if prior != floor {
                    return Err(RootAuthorityErrorV1::Conflict);
                }
                resident.floor = Some(prior);
                return Ok(());
            }
            let intent = self
                .intent(floor.project())?
                .ok_or(RootAuthorityErrorV1::Conflict)?;
            require_acceptance(&intent, accepted, self.source_uid)?;
            if floor.receipt().intent_digest() != intent.digest() {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            let identity = super::capacity::RootGenesisCapacityOriginalV1::identity_for_v1(
                &self.authority,
                &super::super::capacity::request(&intent),
                super::super::capacity::admission_id(&intent),
                &mut resident.recovery_owner,
            )?;
            let reservation = super::capacity::RootGenesisCapacityOriginalV1::recover_v1(
                &self.authority,
                identity,
            )?;
            let transaction = JournalTransaction::new(
                super::super::capacity::floor_transaction_id(&floor),
                vec![
                    JournalRecord::put(
                        RecordNamespace::DesiredState,
                        aos_sandbox_ledger_replay::replay::root_genesis_capacity::floor_key(&floor),
                        floor.record_bytes().to_vec(),
                    ),
                    JournalRecord::delete(
                        RecordNamespace::DesiredState,
                        aos_sandbox_ledger_replay::replay::root_genesis_capacity::intent_key(
                            &intent,
                        ),
                    ),
                    reservation.settlement_record(),
                ],
            )?;
            self.preflight_genesis_v1(
                &transaction,
                super::advisory::RootGenesisAdvisoryRecipeV1::ProjectAnchor(
                    floor.project(),
                    &reservation,
                ),
                &mut resident.first_advisory,
            )?;
            resident.transaction = Some(transaction);
            resident.reservation = Some(reservation);
            resident.floor = Some(floor);
            self.recheck()?;
            Ok(())
        })());
        resident.latch(
            RootProjectGenesisSiteV3::Preparation,
            resident.preparation.as_ref().is_some_and(Result::is_err),
        );
        if resident.first_failure.is_none() {
            if let (Some(reservation), Some(transaction), Some(floor)) = (
                &resident.reservation,
                &resident.transaction,
                &resident.floor,
            ) {
                resident.native_anchor = Some(self.commit_project_genesis_v3(
                    transaction,
                    super::native_cut::RootGenesisCapacityBorrowV1::Anchor(reservation),
                    floor.project(),
                    original,
                    deadline,
                    &mut resident.anchor_crossing,
                    &mut resident.commit_advisory,
                ));
                resident.latch(
                    RootProjectGenesisSiteV3::NativeAnchor,
                    resident.native_anchor.as_ref().is_some_and(Result::is_err),
                );
            }
        }
        resident.readback = Some((|| {
            let floor = resident.floor.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
            if self.floor(floor.project())?.as_ref() != Some(floor)
                || self.intent(floor.project())?.is_some()
            {
                return Err(RootAuthorityErrorV1::Stale);
            }
            Ok(())
        })());
        resident.latch(
            RootProjectGenesisSiteV3::Readback,
            resident.readback.as_ref().is_some_and(Result::is_err),
        );
        resident.posts(self, original, deadline);
        if resident.error().is_some() {
            Err(())
        } else {
            resident.floor.as_ref().cloned().ok_or(())
        }
    }

    /// Rejoins actual Controller Complete and Source ACK under the selected owner.
    ///
    /// # Errors
    /// Rejects missing completion, changed selected floor/reader or actual ACK.
    pub fn confirm_project_genesis_ack_v3(
        &self,
        packet: &[u8],
        floor: &SourceHierarchyFloorRecordV1,
    ) -> Result<(), RootAuthorityErrorV1> {
        self.recheck()?;
        if self.genesis_recipe != RootGenesisOwnerRecipeV3::ProjectV3 {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        if !accepted.completed || self.floor(accepted.acceptance.project())?.as_ref() != Some(floor)
        {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let challenge =
            aos_sandbox_ledger_replay::source_signer_data::SourceProjectGenesisChallengeV3::new(
                self.nonce,
                floor.project(),
                Some(floor.receipt().intent_digest()),
            )
            .map_err(|_| RootAuthorityErrorV1::NonCanonical)?;
        let observed = aos_sandbox_ledger_replay::source_signer_data::verify_source_project_genesis_readback_v3(packet, self.authority.pins.source()?, challenge)
            .map_err(|_| RootAuthorityErrorV1::Stale)?;
        if observed.state() != SourceTreeGenesisStateV1::Anchored
            || observed.receipt() != Some(floor.receipt())
            || observed.names() != accepted.source_names
            || observed.journal_sequence() != accepted.source_sequence
            || observed.ack_floor_digest() != Some(floor.digest())
            || observed.ack_record_digest().is_none()
        {
            return Err(RootAuthorityErrorV1::Stale);
        }
        self.recheck()
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
    ) -> Result<RootSourceGenesisIntentRecordV1, RootAuthorityErrorV1> {
        self.require_strict_genesis_recipe_v1()?;
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        let project = accepted.acceptance.project();
        if self.floor(project)?.is_some() {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        let prior = self.intent(project)?;
        let challenge = SourceTreeGenesisChallengeV1::new(
            self.nonce,
            accepted
                .historical
                .then(|| prior.as_ref().map(RootSourceGenesisIntentRecordV1::digest))
                .flatten(),
        )
        .map_err(|_| RootAuthorityErrorV1::NonCanonical)?;
        let observed = if accepted.vacant {
            if source_packet.is_some() {
                return Err(RootAuthorityErrorV1::NonCanonical);
            }
            let instance = self
                .authority
                .journal
                .get(RecordNamespace::DesiredState, INSTANCE_KEY)
                .map(decode_instance)
                .transpose()?;
            if instance.is_none() || accepted.source_instance != instance {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            None
        } else {
            let observed = verify_source_tree_genesis_readback_v2(
                source_packet.ok_or(RootAuthorityErrorV1::NonCanonical)?,
                self.authority.pins.source()?,
                challenge,
            )
            .map_err(|_| RootAuthorityErrorV1::Stale)?;
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
                    return Err(RootAuthorityErrorV1::Conflict);
                }
            } else {
                if accepted.historical {
                    return Err(RootAuthorityErrorV1::Conflict);
                }
                require_current_deployment(&self.authority.journal)?;
            }
            self.recheck()?;
            return Ok(intent);
        }
        if accepted.historical
            || observed
                .as_ref()
                .is_some_and(|observed| observed.state() != SourceTreeGenesisStateV1::Empty)
        {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        // Refuse a foreign flight and the exact project ceiling before writing
        // even an instance or intent. Postcommit replay is not an admission cut.
        if self
            .authority
            .journal
            .records(RecordNamespace::DesiredState)
            .any(|(key, _)| key.starts_with(INTENT_PREFIX))
            || self
                .authority
                .journal
                .records(RecordNamespace::DesiredState)
                .filter(|(key, _)| key.starts_with(FLOOR_PREFIX))
                .count()
                >= MAXIMUM_PROJECTS
        {
            return Err(RootAuthorityErrorV1::Conflict);
        }
        require_current_deployment(&self.authority.journal)?;
        let acceptance = accepted.acceptance.clone();
        self.ensure_initial_instance()?;
        let instance = decode_instance(
            self.authority
                .journal
                .get(RecordNamespace::DesiredState, INSTANCE_KEY)
                .ok_or(RootAuthorityErrorV1::Stale)?,
        )?;
        let intent = RootSourceGenesisIntentRecordV1::new(
            instance,
            self.source_uid,
            self.nonce,
            acceptance,
            self.authority.pins.digest()?,
        )?;
        let request = super::super::capacity::request(&intent);
        super::strict_custody::begin_once_v1(&mut self.strict.preparation)?;
        let prepared_result = {
            let original = super::strict_custody::entered_mut_v1(&mut self.strict.preparation)?;
            (|| {
                original
                    .prepared
                    .prepare_once(
                        &self.authority,
                        request,
                        super::super::capacity::admission_id(&intent),
                    )
                    .map_err(|()| RootAuthorityErrorV1::Stale)?;
                original.transaction = Some(JournalTransaction::new(
                    super::super::capacity::admission_id(&intent),
                    vec![
                        JournalRecord::put(
                            RecordNamespace::DesiredState,
                            aos_sandbox_ledger_replay::replay::root_genesis_capacity::intent_key(
                                &intent,
                            ),
                            intent.record_bytes().to_vec(),
                        ),
                        original.prepared.record()?.clone(),
                    ],
                )?);
                let transaction = original
                    .transaction
                    .as_ref()
                    .ok_or(RootAuthorityErrorV1::Stale)?;
                let mut advisory = super::advisory::RootGenesisAdvisoryCutV1 {
                    recipe: super::advisory::RootGenesisAdvisoryRecipeV1::GlobalPrepared(
                        &original.prepared,
                    ),
                    transaction,
                    native: &mut original.advisory,
                };
                self.authority.journal.preflight_genesis_advisory_v1(
                    std::slice::from_ref(transaction),
                    &mut advisory,
                )?;
                Ok(())
            })()
        };
        super::strict_custody::finish_body_v1(&mut self.strict.preparation, prepared_result)?;
        self.recheck()?;
        require_current_deployment(&self.authority.journal)?;
        let committed_result = {
            let original = super::strict_custody::entered_mut_v1(&mut self.strict.preparation)?;
            (|| {
                let transaction = original
                    .transaction
                    .as_ref()
                    .ok_or(RootAuthorityErrorV1::Stale)?;
                let cut = super::native_cut::RootStrictGenesisNativeCutV1 {
                    scope: super::native_cut::RootGenesisMutationScopeV1 {
                        capacity: super::native_cut::RootGenesisCapacityBorrowV1::Prepared(
                            &original.prepared,
                        ),
                        transaction,
                        native: &mut original.crossing,
                    },
                };
                original.native = Some(self.authority.journal.commit_with_role_gate_v1(
                    transaction,
                    crate::native::append::PolicyMutationGateV1::GenesisStrict(cut),
                ));
                if !matches!(original.native, Some(Ok(_))) {
                    return Err(RootAuthorityErrorV1::Stale);
                }
                original.admission = Some(original.prepared.retained_after_commit_v1());
                if !matches!(original.admission, Some(Ok(_))) {
                    return Err(RootAuthorityErrorV1::Stale);
                }
                Ok(())
            })()
        };
        super::strict_custody::finish_body_v1(&mut self.strict.preparation, committed_result)?;
        if self.intent(project)?.as_ref() != Some(&intent) {
            return Err(RootAuthorityErrorV1::Stale);
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
    ) -> Result<SourceHierarchyFloorRecordV1, RootAuthorityErrorV1> {
        self.require_strict_genesis_recipe_v1()?;
        self.recheck()?;
        let accepted = self.accepted.as_ref().ok_or(RootAuthorityErrorV1::Stale)?;
        let project = accepted.acceptance.project();
        let prior_floor = self.floor(project)?;
        let intent = self.intent(project)?;
        let intent_digest = prior_floor
            .as_ref()
            .map(|floor| floor.receipt().intent_digest())
            .or_else(|| intent.as_ref().map(RootSourceGenesisIntentRecordV1::digest))
            .ok_or(RootAuthorityErrorV1::Conflict)?;
        let challenge = SourceTreeGenesisChallengeV1::new(self.nonce, Some(intent_digest))
            .map_err(|_| RootAuthorityErrorV1::NonCanonical)?;
        let observed = verify_source_tree_genesis_readback_v2(
            source_packet,
            self.authority.pins.source()?,
            challenge,
        )
        .map_err(|_| RootAuthorityErrorV1::Stale)?;
        require_same_source_cut(accepted, &observed)?;
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
        let floor = SourceHierarchyFloorRecordV1::new(receipt, self.authority.pins.digest()?)?;
        if let Some(prior) = prior_floor {
            if prior != floor {
                return Err(RootAuthorityErrorV1::Conflict);
            }
            self.recheck()?;
            return Ok(prior);
        }
        let intent = intent.ok_or(RootAuthorityErrorV1::Conflict)?;
        require_acceptance(&intent, accepted, self.source_uid)?;
        let request = super::super::capacity::request(&intent);
        super::strict_custody::begin_once_v1(&mut self.strict.anchoring)?;
        let prepared_result = {
            let original = super::strict_custody::entered_mut_v1(&mut self.strict.anchoring)?;
            (|| {
                let identity = super::capacity::RootGenesisCapacityOriginalV1::identity_for_v1(
                    &self.authority,
                    &request,
                    super::super::capacity::admission_id(&intent),
                    &mut original.recovery_owner,
                )?;
                original.reservation =
                    Some(super::capacity::RootGenesisCapacityOriginalV1::recover_v1(
                        &self.authority,
                        identity,
                    )?);
                let reservation = original
                    .reservation
                    .as_ref()
                    .ok_or(RootAuthorityErrorV1::Stale)?;
                original.transaction = Some(JournalTransaction::new(
                    super::super::capacity::floor_transaction_id(&floor),
                    vec![
                        JournalRecord::put(
                            RecordNamespace::DesiredState,
                            aos_sandbox_ledger_replay::replay::root_genesis_capacity::floor_key(
                                &floor,
                            ),
                            floor.record_bytes().to_vec(),
                        ),
                        JournalRecord::delete(
                            RecordNamespace::DesiredState,
                            aos_sandbox_ledger_replay::replay::root_genesis_capacity::intent_key(
                                &intent,
                            ),
                        ),
                        reservation.settlement_record(),
                    ],
                )?);
                Ok(())
            })()
        };
        super::strict_custody::finish_body_v1(&mut self.strict.anchoring, prepared_result)?;
        self.recheck()?;
        let committed_result = {
            let original = super::strict_custody::entered_mut_v1(&mut self.strict.anchoring)?;
            (|| {
                let transaction = original
                    .transaction
                    .as_ref()
                    .ok_or(RootAuthorityErrorV1::Stale)?;
                let reservation = original
                    .reservation
                    .as_ref()
                    .ok_or(RootAuthorityErrorV1::Stale)?;
                let mut advisory = super::advisory::RootGenesisAdvisoryCutV1 {
                    recipe: super::advisory::RootGenesisAdvisoryRecipeV1::GlobalAnchor(reservation),
                    transaction,
                    native: &mut original.advisory,
                };
                self.authority.journal.preflight_genesis_advisory_v1(
                    std::slice::from_ref(transaction),
                    &mut advisory,
                )?;
                let cut = super::native_cut::RootStrictGenesisNativeCutV1 {
                    scope: super::native_cut::RootGenesisMutationScopeV1 {
                        capacity: super::native_cut::RootGenesisCapacityBorrowV1::Anchor(
                            reservation,
                        ),
                        transaction,
                        native: &mut original.crossing,
                    },
                };
                original.native = Some(self.authority.journal.commit_with_role_gate_v1(
                    transaction,
                    crate::native::append::PolicyMutationGateV1::GenesisStrict(cut),
                ));
                if !matches!(original.native, Some(Ok(_))) {
                    return Err(RootAuthorityErrorV1::Stale);
                }
                Ok(())
            })()
        };
        super::strict_custody::finish_body_v1(&mut self.strict.anchoring, committed_result)?;
        if self.floor(project)?.as_ref() != Some(&floor) || self.intent(project)?.is_some() {
            return Err(RootAuthorityErrorV1::Stale);
        }
        self.recheck()?;
        Ok(floor)
    }

    pub(super) fn ensure_initial_instance(&mut self) -> Result<(), RootAuthorityErrorV1> {
        if self
            .authority
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
        let digest = aos_sandbox_ledger_replay::data::hash(INSTANCE_TRANSACTION_DOMAIN, &bytes);
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
                    self.authority.pins.record_bytes()?.to_vec(),
                ),
            ],
        )?;
        self.recheck()?;
        super::strict_custody::begin_once_v1(&mut self.strict.initialization)?;
        let returned = {
            let original = super::strict_custody::entered_mut_v1(&mut self.strict.initialization)?;
            original.transaction = Some(transaction);
            (|| {
                let transaction = original
                    .transaction
                    .as_ref()
                    .ok_or(RootAuthorityErrorV1::Stale)?;
                self.authority
                    .journal
                    .preflight_transactions(std::slice::from_ref(transaction))?;
                let cut = super::native_cut::RootStrictGenesisNativeCutV1 {
                    scope: super::native_cut::RootGenesisMutationScopeV1 {
                        capacity: super::native_cut::RootGenesisCapacityBorrowV1::Initialize,
                        transaction,
                        native: &mut original.crossing,
                    },
                };
                original.native = Some(self.authority.journal.commit_with_role_gate_v1(
                    transaction,
                    crate::native::append::PolicyMutationGateV1::GenesisStrict(cut),
                ));
                if !matches!(original.native, Some(Ok(_))) {
                    return Err(RootAuthorityErrorV1::Stale);
                }
                Ok(())
            })()
        };
        super::strict_custody::finish_body_v1(&mut self.strict.initialization, returned)?;
        if self
            .authority
            .journal
            .get(RecordNamespace::DesiredState, INSTANCE_KEY)
            != Some(bytes.as_slice())
        {
            return Err(RootAuthorityErrorV1::Stale);
        }
        self.recheck()
    }
}
