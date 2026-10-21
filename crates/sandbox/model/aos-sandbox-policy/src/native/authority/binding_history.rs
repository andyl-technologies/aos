//! Retains the earned native Root Q04 history and actual append Results.
//!
//! Passive suffix recipes cannot construct this role. Its private admission
//! follows the same authenticated held compilation and real current-gen1 cut;
//! each later event must be verified before its one next member is eligible.
//! Native append Results remain resident before later owner or clock checks.

use aos_sandbox_ledger_replay::controller_policy_hold::ControllerPolicyHoldCodecV1;

use sha2::Digest;

use super::RootAuthorityErrorV1;
use crate::native::PolicyNativeJournalErrorV1 as NativeError;
use crate::native::journal::RootPolicyJournalV1;
use crate::q04_data::{
    PolicyQ04DataErrorV1, Q04AcknowledgementKindV1, Q04AcknowledgementV1, RootQ04RecordKeyV1,
    RootQ04SuffixDataV1, capacity_shape_digest, root_capacity_acknowledgement, root_phase_record,
    root_record,
};
use aos_sandbox_model::{ObjectDigest, RecordNamespace};
use aos_sandbox_protocol::domain_ledger::create_q04_history::{
    Q04CutIdentityV1, Q04RootDecisionV1, Q04TransactionOwnerV1,
    root_consumed_gate_record_v1 as root_consumed_gate_record,
};
use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};

fn changed() -> RootAuthorityErrorV1 {
    PolicyQ04DataErrorV1::ChangedCut.into()
}

fn bounds() -> RootAuthorityErrorV1 {
    PolicyQ04DataErrorV1::Bounds.into()
}

// Callers first perform the canonical exact-width decode. This private view
// only projects fixed fields from those same retained, already checked bytes.
fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> [u8; N] {
    let mut output = [0; N];
    output.copy_from_slice(&bytes[offset..offset + N]);
    output
}

/// Retains one authentically earned Root Q04 suffix and its native outcomes.
///
/// Construction and eligibility changes remain private to the actual native
/// Authority and Work; historical recipes and public getters grant no mutation.
pub struct RootAuthorityQ04HistoryV1 {
    identity: Q04CutIdentityV1,
    original: (u64, ProtectedJournalNamesV1, ObjectDigest),
    controller_before: (ProtectedJournalNamesV1, u64),
    target_before: (u64, ProtectedJournalNamesV1, ObjectDigest),
    forecast_named: std::sync::OnceLock<super::names::RootAuthorityNamesOriginalV1>,
    decision_entered: bool,
    decision: Option<Result<Q04RootDecisionV1, RootAuthorityErrorV1>>,
    consumed_gate: Option<aos_sandbox_protocol::domain_ledger::create_q04_history::Q04EffectSubgateV1>,
    suffix: RootQ04SuffixDataV1,
    pub(super) preflight: Option<Result<(), RootAuthorityErrorV1>>,
    cause: std::sync::OnceLock<RootAuthorityErrorV1>,
    pub(super) commits:
        Vec<Option<Result<aos_sandbox_broker::canonical_journal::CommitResult, NativeError>>>,
    committed: usize,
    eligible_end: usize,
    actual_acknowledgements: usize,
}

impl RootAuthorityQ04HistoryV1 {
    fn park(
        identity: &Q04CutIdentityV1,
        original: (u64, ProtectedJournalNamesV1, ObjectDigest),
        controller_before: (ProtectedJournalNamesV1, u64),
        target_before: (u64, ProtectedJournalNamesV1, ObjectDigest),
    ) -> Self {
        Self {
            identity: identity.clone(),
            original,
            controller_before,
            target_before,
            forecast_named: std::sync::OnceLock::new(),
            decision_entered: false,
            decision: None,
            consumed_gate: None,
            suffix: RootQ04SuffixDataV1::default(),
            preflight: None,
            cause: std::sync::OnceLock::new(),
            commits: Vec::new(),
            committed: 0,
            eligible_end: 0,
            actual_acknowledgements: 0,
        }
    }

    /// Borrows the original immutable comparison identity.
    #[must_use]
    pub fn identity(&self) -> &Q04CutIdentityV1 {
        &self.identity
    }

    /// Borrows the Decision formed from this history's actual publication receipt.
    ///
    /// This comparison DATA grants neither append eligibility nor a response.
    #[must_use]
    pub fn decision_data_v1(&self) -> Option<&Q04RootDecisionV1> {
        self.decision.as_ref()?.as_ref().ok()
    }

    /// Borrows the same earned consumed gate as nonauthorizing comparison DATA.
    #[must_use]
    pub fn consumed_gate_data_v1(
        &self,
    ) -> Option<&aos_sandbox_protocol::domain_ledger::create_q04_history::Q04EffectSubgateV1> {
        self.consumed_gate.as_ref()
    }

    /// Borrows the same canonical suffix as nonauthorizing historical DATA.
    #[must_use]
    pub fn transactions(&self) -> &[JournalTransaction] {
        &self.suffix.transactions
    }

    /// Returns the count advanced only from resident successful native Results.
    #[must_use]
    pub fn committed(&self) -> usize {
        self.committed
    }

    /// Returns the count advanced only by strictly authenticated original ACKs.
    ///
    /// This historical count performs no IO and grants no append eligibility
    /// or terminal clearance. The actual enclosing flight keeps its ordered
    /// gen1, publication, native-name and final-clock observations.
    #[must_use]
    pub fn actual_acknowledgement_count_v1(&self) -> usize {
        self.actual_acknowledgements
    }

    /// Returns the canonical boundary after R1, Claim groups, Stage and R2.
    ///
    /// This nonissuing index copies no native result and grants no mutation.
    ///
    /// # Errors
    /// Refuses checked group-count arithmetic overflow.
    pub fn binding_prefix_end(&self) -> Result<usize, RootAuthorityErrorV1> {
        // R1, every complete Claim group, the existing Stage, then R2.
        let groups = self.suffix.chunks.len().checked_add(127).ok_or(bounds())? / 128;
        groups.checked_add(3).ok_or(bounds())
    }

    /// Borrows one actual canonical Root phase as historical comparison DATA.
    #[must_use]
    pub fn phase_record_v1(
        &self,
        phase: u8,
    ) -> Option<&aos_sandbox_protocol::domain_ledger::create_q04_history::Q04PhaseRecordV1> {
        let index = usize::from(phase.checked_sub(1)?);
        self.suffix
            .phases
            .get(index)
            .filter(|record| record.phase() == phase)
    }

    /// Copies the original Root native before-state as nonauthorizing DATA.
    #[must_use]
    pub const fn original_before_data_v1(&self) -> (u64, ProtectedJournalNamesV1, ObjectDigest) {
        self.original
    }

    pub(in crate::native) const fn controller_before_data_v1(
        &self,
    ) -> (ProtectedJournalNamesV1, u64) {
        self.controller_before
    }

    pub(in crate::native) fn require_fixed_original(
        &self,
        journal: &RootPolicyJournalV1,
    ) -> Result<(), RootAuthorityErrorV1> {
        journal.require_native_original()?;
        if !self.suffix.complete || journal.q04_physical_names_v1()? != self.original.1 {
            return Err(changed());
        }
        if self.committed == 0 && journal.q04_before_rows_v1()? != self.original {
            return Err(changed());
        }
        journal.require_q04_native_recipe_prefix_v1(
            &self.suffix.transactions[..self.committed],
            self.original.0,
        )?;
        self.require_prefix_rows(journal.all_records(), self.committed)?;
        Ok(())
    }

    pub(super) fn require_original_stage_row_v1(
        &self,
        journal: &RootPolicyJournalV1,
        stage: &crate::q04_data::Q04RootStageRecipeV1,
        prefix: usize,
    ) -> Result<(), RootAuthorityErrorV1> {
        let stage_index = self
            .transactions()
            .iter()
            .position(|transaction| transaction.id() == stage.transaction().id())
            .ok_or_else(changed)?;
        stage.require_original_row_data_v1(
            journal.get(RecordNamespace::DesiredState, crate::q04_data::STAGE_KEY),
            prefix > stage_index,
        )?;
        Ok(())
    }

    pub(in crate::native) fn require_transition(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
        index: usize,
    ) -> Result<(), NativeError> {
        if !self.suffix.complete || self.suffix.transactions.get(index) != Some(transaction) {
            return Err(NativeError::boundary());
        }
        self.require_prefix_rows(
            state
                .iter()
                .map(|((namespace, key), value)| (*namespace, key.as_slice(), value.as_slice())),
            index,
        )
    }

    // Complete Q04 materialization must equal this same original prefix.
    // Old binding/Stage fields use the existing recipes, never a new parser.
    pub(in crate::native) fn require_prefix_rows<'row>(
        &self,
        rows: impl Iterator<Item = (RecordNamespace, &'row [u8], &'row [u8])> + Clone,
        prefix: usize,
    ) -> Result<(), NativeError> {
        if prefix > self.suffix.transactions.len() {
            return Err(NativeError::boundary());
        }
        let expected = |namespace, key: &[u8]| {
            self.suffix.transactions[..prefix]
                .iter()
                .rev()
                .flat_map(|transaction| transaction.records().iter().rev())
                .find(|record| record.namespace() == namespace && record.key() == key)
        };
        for (namespace, key, value) in rows.clone() {
            if key.starts_with(b"\0aos-q04-root-")
                && (namespace != RecordNamespace::DesiredState
                    || expected(namespace, key).and_then(JournalRecord::value) != Some(value))
            {
                return Err(NativeError::boundary());
            }
        }
        for transaction in &self.suffix.transactions[..prefix] {
            for record in transaction.records() {
                let Some(latest) = expected(record.namespace(), record.key()) else {
                    return Err(NativeError::boundary());
                };
                if rows
                    .clone()
                    .find(|(namespace, key, _)| {
                        *namespace == record.namespace() && *key == record.key()
                    })
                    .map(|(_, _, value)| value)
                    != latest.value()
                {
                    return Err(NativeError::boundary());
                }
            }
        }
        Ok(())
    }

    pub(in crate::native) fn may_append(&self, index: usize) -> bool {
        index == self.committed && index < self.eligible_end
    }

    // Only the owning Root action advances this after its real successful
    // CommitResult is already parked. Native postchecks still follow before
    // any next phase, decision or response is allowed.
    pub(in crate::native) fn advance_parked_commit(&mut self) -> Result<(), RootAuthorityErrorV1> {
        if !self.may_append(self.committed)
            || !matches!(self.commits.get(self.committed), Some(Some(Ok(_))))
        {
            return Err(changed());
        }
        self.committed = self.committed.checked_add(1).ok_or_else(bounds)?;
        Ok(())
    }

    pub(in crate::native) fn retain_gate_failure_v1(&self, error: RootAuthorityErrorV1) {
        if self.cause.set(error).is_err() {
            std::process::abort();
        }
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause
            .get()
            .map(|cause| cause as _)
            .or_else(|| self.forecast_named.get()
                .and_then(super::names::RootAuthorityNamesOriginalV1::failure))
            .or_else(|| self.decision.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as _))
            .or_else(|| {
                self.preflight
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.commits
                    .iter()
                    .filter_map(|result| result.as_ref())
                    .find_map(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
    }

    fn admit_actual_acknowledgement(
        &mut self,
        acknowledgement: &Q04AcknowledgementV1<'_>,
        controller_before_sequence: u64,
    ) -> Result<(), RootAuthorityErrorV1> {
        let packet_index = match acknowledgement.kind() {
            Q04AcknowledgementKindV1::Policy => 0,
            Q04AcknowledgementKindV1::Release => 1,
            Q04AcknowledgementKindV1::Settlement => 2,
            Q04AcknowledgementKindV1::Clearance => 3,
        };
        let transaction_index = self
            .binding_prefix_end()?
            .checked_add(1 + packet_index)
            .ok_or(bounds())?;
        if self.actual_acknowledgements != packet_index
            || self.committed != transaction_index
            || self.eligible_end != transaction_index
        {
            return Err(changed());
        }
        let packet = self.suffix.packets.get_mut(packet_index).ok_or(changed())?;
        if packet.len() != acknowledgement.bytes().len() {
            return Err(changed());
        }
        packet.copy_from_slice(acknowledgement.bytes());
        self.actual_acknowledgements += 1;
        self.refresh_acknowledgement_suffix(packet_index, controller_before_sequence)?;
        self.eligible_end = transaction_index.checked_add(1).ok_or(bounds())?;
        Ok(())
    }

    // Only uncommitted capacity members are rewritten. Every authentic packet
    // remains in the original parent too; changed future IDs/heads are recipes,
    // not observations. The same real Journal repeats the entire remaining
    // encoded suffix preflight before admitting this one actual next append.
    fn refresh_acknowledgement_suffix(
        &mut self,
        first: usize,
        controller_before_sequence: u64,
    ) -> Result<(), RootAuthorityErrorV1> {
        let identity = &self.identity;
        let decision = Q04RootDecisionV1::decode(
            self.suffix
                .transactions
                .get(self.binding_prefix_end()?)
                .and_then(|transaction| transaction.records().first())
                .and_then(JournalRecord::value)
                .ok_or(changed())?,
            identity,
        )?;
        let gate = root_consumed_gate_record(identity, &decision)?;
        let r3 = self.suffix.phases.get(2).ok_or(changed())?;
        let mut pairs = [ObjectDigest::from_bytes([0; 32]); 6];
        for (index, pair) in pairs.iter_mut().enumerate() {
            *pair = if index % 2 == 0 {
                ObjectDigest::from_bytes(fixed(r3.bytes(), 288 + index * 32))
            } else {
                capacity_shape_digest(identity, u8::try_from(index + 1).map_err(|_| bounds())?)?
            };
        }
        if self.actual_acknowledgements >= 3 {
            let packet = self.suffix.packets.get(2).ok_or(changed())?;
            for (index, pair) in pairs.iter_mut().enumerate() {
                *pair = ObjectDigest::from_bytes(fixed(packet, 344 + index * 32));
            }
        }
        let first_transaction = self.binding_prefix_end()?.checked_add(1).ok_or(bounds())?;
        let released_binding = self
            .suffix
            .transactions
            .get(first_transaction + 1)
            .and_then(|transaction| transaction.records().first())
            .cloned()
            .ok_or(changed())?;
        let zero = ObjectDigest::from_bytes([0; 32]);
        for (index, kind) in [
            Q04AcknowledgementKindV1::Policy,
            Q04AcknowledgementKindV1::Release,
            Q04AcknowledgementKindV1::Settlement,
            Q04AcknowledgementKindV1::Clearance,
        ]
        .into_iter()
        .enumerate()
        .skip(first)
        {
            if index >= self.actual_acknowledgements {
                let packet = self.suffix.packets.get_mut(index).ok_or(changed())?;
                packet.clear();
                root_capacity_acknowledgement(
                    packet,
                    kind,
                    identity,
                    controller_before_sequence,
                    gate.digest(),
                    pairs,
                )?;
            }
            let packet = self.suffix.packets.get(index).ok_or(changed())?;
            let digest = ObjectDigest::from_bytes(sha2::Sha256::digest(packet).into());
            let prior = self.suffix.phases.get(index + 2).ok_or(changed())?;
            let mut events = [decision.digest(), gate.digest(), zero, zero, zero];
            if index >= 1 {
                events[2] = if self.actual_acknowledgements >= 2 {
                    ObjectDigest::from_bytes(
                        sha2::Sha256::digest(self.suffix.packets.get(1).ok_or(changed())?).into(),
                    )
                } else {
                    capacity_shape_digest(identity, 7)?
                };
            }
            if index >= 2 {
                events[2] = self.suffix.phases.get(4).ok_or(changed())?.digest();
            }
            if index >= 3 {
                events[3] = prior.digest();
                events[4] = if self.actual_acknowledgements == 4 {
                    ObjectDigest::from_bytes(fixed(packet, 632))
                } else {
                    capacity_shape_digest(identity, 8)?
                };
            }
            let phase = u8::try_from(index + 4).map_err(|_| bounds())?;
            let transaction_id =
                Q04TransactionOwnerV1::Root.transaction_id(identity, phase, prior.digest())?;
            let record = root_phase_record(
                identity,
                phase,
                transaction_id,
                self.original.2,
                Some(prior.digest()),
                events,
                pairs,
                Some(digest),
            )?;
            record.require_successor(prior)?;
            let mut records = Vec::new();
            records.try_reserve_exact(if phase == 5 { 3 } else { 2 })?;
            if phase == 5 {
                records.push(released_binding.clone());
            }
            records.push(root_record(
                RootQ04RecordKeyV1::Packet(kind.phase()),
                identity,
                packet,
            )?);
            records.push(root_record(
                RootQ04RecordKeyV1::Phase(phase),
                identity,
                record.bytes(),
            )?);
            self.suffix.transactions[first_transaction + index] =
                JournalTransaction::new(transaction_id, records)?;
            self.suffix.phases[index + 3] = record;
        }
        Ok(())
    }
}

impl super::RootAuthorityQ04FlightOriginalV1<'_, '_, '_> {
    // The actual Work invokes this only after retaining both authenticated
    // compilations. It does not accept a suffix or a supplied eligibility bit.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::native) fn admit_q04_history_v1(
        &mut self,
        work: &mut crate::native::target::RootPolicyPublicationWorkV1<'_>,
        stage: &crate::q04_data::Q04RootStageRecipeV1,
        claim_packet: &[u8],
        request_packet: &[u8],
        preview_packet: &[u8],
        controller_packet: &[u8],
        source_packet: &[u8],
    ) -> Result<(), ()> {
        // Forecast refusal bars positive history admission, but cannot close
        // the generic owner recheck used by independently owed after paths.
        if self.require_positive_prehold_forecast_v1().is_err() {
            if !self.forecast.is_refused_v1() {
                self.history_admission = Some(Err(changed()));
            }
            return Err(());
        }
        if self.history.is_some() || self.history_admission.is_some() {
            return Err(());
        }
        let receipt_bytes =
            crate::native::target::RootPolicyPublicationWorkV1::held_history_receipt_bytes_v1()
                .and_then(|bytes| u64::try_from(bytes).ok());
        let Some(receipt_bytes) = receipt_bytes else {
            self.history_admission = Some(Err(NativeError::geometry().into()));
            return Err(());
        };
        let receipt_admission = self.authority.journal.admit_role_observation_v1(
            aos_sandbox_model::ResourceVector::ZERO.with(
                aos_sandbox_model::ResourceDimension::MemoryBytes,
                receipt_bytes,
            ),
        );
        if let Err(error) = receipt_admission {
            self.history_admission = Some(Err(error.into()));
            return Err(());
        }
        let expected_root = work.prehold_root_before_data_v1();
        let before = match (|| {
            let expected = expected_root.ok_or_else(changed)?;
            let before = self.q04_before_rows()?;
            if before != expected { return Err(changed()); }
            Ok(before)
        })() {
            Ok(before) => before,
            Err(error) => {
                self.history_admission = Some(Err(error));
                return Err(());
            }
        };
        // Preserve old Root-before-Target short circuit: a changed Root never
        // enters this independently owed Target capture or receipt factory.
        let receipt = work.held_history_input_v1()?;
        let identity = receipt.identity;
        let returned = (|| {
            let preview = crate::q04_data::Q04PreviewV1::decode(preview_packet, identity.nonce())?;
            let root_metadata = preview.fields()[0];
            if root_metadata[32..40] != before.0.to_be_bytes()
                || root_metadata[40..88] != before.1.to_bytes()
                || root_metadata[88..120] != *before.2.as_bytes()
            {
                return Err(changed());
            }
            let (claim, pairs) = {
                let gen1 = self.refresh_completed_gen1_v1(controller_packet, source_packet)?;
                let claim = gen1.verify_claim(claim_packet, identity)?;
                if claim.bytes().len() != receipt.claim_length
                    || claim.fields()[8] != receipt.binding
                {
                    return Err(changed());
                }
                let fields = claim.fields();
                let (controller, held) =
                    gen1.controller_cut(fields[9], fields[10], fields[8], stage, identity)?;
                let cache = gen1.cache_cut(
                    fields[12],
                    fields[8],
                    stage,
                    identity,
                    gen1.current.owner.identities[3],
                )?;
                let controller_hold =
                    aos_sandbox_ledger_replay::controller_policy_hold::ControllerPolicyHoldV1::new(
                        held.operation(),
                        held.sandbox(),
                        held.source(),
                        held.binding(),
                        held.epoch(),
                    )?;
                let source_hold = aos_sandbox_protocol::domain_ledger::source_policy_hold::SourceDomainPolicyHoldV1::new(
                    controller.operation(), controller.sandbox(), controller.source_commitment(),
                    gen1.floor().tree_head(), identity.binding(), identity.epoch(),
                )?;
                let zero = ObjectDigest::from_bytes([0; 32]);
                let pairs = [
                    controller_hold.record_digest()?,
                    zero,
                    source_hold.record_digest()?,
                    zero,
                    cache.hold().record_digest()?,
                    zero,
                ];
                gen1.recheck()?;
                (claim, pairs)
            };
            let request = crate::q04_data::Q04PreholdInputDataV1::decode(request_packet)?;
            // The same genuine journal pays the complete future representation
            // before the empty History or any of its dynamic buffers is made.
            let suffix_bytes = RootQ04SuffixDataV1::receiving_bytes_v1(receipt.claim_length, stage)
                .ok_or_else(NativeError::geometry)?;
            let chunks = usize::from(
                aos_sandbox_protocol::domain_ledger::create_q04_history::claim_chunk_count(
                    receipt.claim_length,
                )?,
            );
            let transaction_count = chunks
                .checked_add(127)
                .and_then(|chunks| (chunks / 128).checked_add(8))
                .ok_or_else(NativeError::geometry)?;
            let commit_slots = transaction_count
                .checked_mul(std::mem::size_of::<
                    Option<
                        Result<aos_sandbox_broker::canonical_journal::CommitResult, NativeError>,
                    >,
                >())
                .and_then(|bytes| bytes.checked_mul(3))
                .ok_or_else(NativeError::geometry)?;
            let bytes = std::mem::size_of::<RootAuthorityQ04HistoryV1>()
                .checked_mul(3)
                .and_then(|bytes| bytes.checked_add(suffix_bytes))
                .and_then(|bytes| bytes.checked_add(commit_slots))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(NativeError::geometry)?;
            self.authority.journal.admit_role_observation_v1(
                aos_sandbox_model::ResourceVector::ZERO
                    .with(aos_sandbox_model::ResourceDimension::MemoryBytes, bytes),
            )?;
            let metadata = request.fields()[0];
            let controller_before = (
                ProtectedJournalNamesV1::from_bytes(&metadata[176..224]).map_err(
                    aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from,
                )?,
                u64::from_be_bytes(fixed(metadata, 464)),
            );
            self.history = Some(RootAuthorityQ04HistoryV1::park(
                identity,
                before,
                controller_before,
                receipt.target_before,
            ));
            let history = self.history.as_mut().ok_or_else(changed)?;
            history.suffix.form(
                crate::q04_data::RootQ04SuffixInputDataV1 {
                    identity: &history.identity,
                    binding: receipt.binding,
                    root_before: before.2,
                    root_sequence: before.0,
                    state_sequence: receipt.target_before.0,
                    claim_length: receipt.claim_length,
                    claim: Some(&claim),
                    held_pairs: Some(pairs),
                },
                stage,
                &request,
                &preview,
                source_packet,
            )?;
            history.eligible_end = history.binding_prefix_end()?;
            if history.transactions().len() != transaction_count {
                return Err(changed());
            }
            history
                .commits
                .try_reserve_exact(history.transactions().len())?;
            history
                .commits
                .resize_with(history.transactions().len(), || None);
            // This same complete initial suffix was independently forecast in
            // the old owner before the outer identity/clock bookend. Retain
            // its native result here; a later per-member preflight cannot
            // substitute for this earlier full prospective observation.
            history.preflight = Some(super::forecast::preflight_authority_suffix_v1(
                self.authority, before, history.transactions(), &history.forecast_named,
            ));
            Ok(())
        })();
        self.history_admission = Some(returned);
        if matches!(self.history_admission, Some(Ok(())))
            && self.history.as_ref().is_some_and(|history| {
                matches!(history.preflight, Some(Ok(())))
            })
        {
            Ok(())
        } else {
            Err(())
        }
    }
}

impl super::RootAuthorityQ04FlightOriginalV1<'_, '_, '_> {
    /// Borrows this native flight's retained Q04 history as comparison DATA.
    ///
    /// # Errors
    /// Refuses missing or failed genuine held-compilation admission.
    pub fn q04_history_v1(&self) -> Result<&RootAuthorityQ04HistoryV1, RootAuthorityErrorV1> {
        self.require_ready()?;
        if !matches!(self.history_admission, Some(Ok(()))) {
            return Err(changed());
        }
        self.history.as_ref().ok_or_else(changed)
    }

    /// Authenticates the real next ACK before changing native history eligibility.
    ///
    /// # Errors
    /// Preserves current gen1/signature/financial failures and rejects a foreign
    /// original Controller cut, out-of-order ACK or changed earned history.
    pub fn admit_next_q04_acknowledgement_v1(
        &mut self,
        kind: Q04AcknowledgementKindV1,
        frame: &[u8],
        prehold_packet: &[u8],
        stage: &crate::q04_data::Q04RootStageRecipeV1,
        controller_packet: &[u8],
        source_packet: &[u8],
    ) -> Result<(), RootAuthorityErrorV1> {
        let history = self.q04_history_v1()?;
        if history.failure_v1().is_some() { return Err(changed()); }
        let controls = std::mem::size_of::<Q04AcknowledgementV1<'_>>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                crate::q04_data::Q04PreholdInputDataV1<'_>,
            >().checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(NativeError::geometry)?;
        let bytes = RootQ04SuffixDataV1::receiving_bytes_v1(history.suffix.claim.len(), stage)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| bytes.checked_add(controls))
            .ok_or_else(NativeError::geometry)?;
        self.authority.journal.admit_role_observation_v1(
            aos_sandbox_model::ResourceVector::ZERO.with(
                aos_sandbox_model::ResourceDimension::MemoryBytes, bytes,
            ),
        )?;
        self.accept_historical_controller_readback_v1(controller_packet)?;
        let (acknowledgement, original_next) = {
            // Exactly the old refresh boundary precedes either pure decoder.
            let gen1 = self.completed_gen1_after_accepted_v1(controller_packet, source_packet)?;
            let original = crate::q04_data::Q04PreholdInputDataV1::decode(prehold_packet)?;
            let metadata = original.fields()[0];
            let original_names = ProtectedJournalNamesV1::from_bytes(&metadata[176..224])
                .map_err(aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from)?;
            let original_next = u64::from_be_bytes(fixed(metadata, 464));
            let history = self.q04_history_v1()?;
            if history.controller_before != (original_names, original_next) { return Err(changed()); }
            use aos_sandbox_protocol::source_genesis_wire::{
                RootCreateQ04TransferKindV1 as Transfer,
                Q04TransferWireErrorV1 as WireError,
                decode_root_create_q04_transfer_v1,
            };
            let transfer = match kind {
                Q04AcknowledgementKindV1::Policy => Transfer::PolicyAcknowledgement,
                Q04AcknowledgementKindV1::Release => Transfer::ReleaseAcknowledgement,
                Q04AcknowledgementKindV1::Settlement => Transfer::SettlementAcknowledgement,
                Q04AcknowledgementKindV1::Clearance => Transfer::ClearanceAcknowledgement,
            };
            let packet = decode_root_create_q04_transfer_v1(frame, transfer, history.identity.nonce())
                .map_err(|error| match error {
                    WireError::ChangedCut => changed(),
                    WireError::Allocation(error) => RootAuthorityErrorV1::Allocation(error),
                })?;
            (gen1.acknowledgement(kind, packet, &history.identity, original_names)?, original_next)
        };
        self.history.as_mut().ok_or_else(changed)?
            .admit_actual_acknowledgement(&acknowledgement, original_next)
    }
}

impl super::RootAuthorityQ04FlightOriginalV1<'_, '_, '_> {
    /// Rechecks the actual committed Root prefix under its original Stage and gen1.
    ///
    /// # Errors
    /// Preserves same-owner, full native membership and Source ACK failures and
    /// rejects any changed floor, nonce, Stage row or retained transaction prefix.
    pub fn q04_recheck_original_binding_prefix_v1(
        &self,
        stage: &crate::q04_data::Q04RootStageRecipeV1,
        source_packet: &[u8],
    ) -> Result<(), RootAuthorityErrorV1> {
        self.recheck()?;
        let history = self.q04_history_v1()?;
        history.require_fixed_original(&self.authority.journal)?;
        let current = self.current_anchored_floor_v1(source_packet)?;
        current.recheck()?;
        super::append_context::require_stage_cut_v1(
            current.floor(),
            self.nonce_data_v1()?,
            history.identity(),
            stage,
        )?;
        history.require_original_stage_row_v1(
            &self.authority.journal,
            stage,
            history.committed(),
        )?;
        self.recheck()
    }
}

impl super::RootAuthorityQ04FlightOriginalV1<'_, '_, '_> {
    // Work calls this only after its fresh Decision-boundary publication
    // readback. The private receipt cannot be constructed from capacity DATA.
    pub(in crate::native) fn admit_q04_decision_v1(
        &mut self,
        work: &mut crate::native::target::RootPolicyPublicationWorkV1<'_>,
        stage: &crate::q04_data::Q04RootStageRecipeV1,
        source_packet: &[u8],
    ) -> Result<(), ()> {
        let ready = (|| {
            let history = self.q04_history_v1()?;
            if history.decision_entered || history.failure_v1().is_some()
                || history.committed() != history.binding_prefix_end()?
            { return Err(changed()); }
            Ok(())
        })();
        if let Err(error) = ready {
            self.history_admission = Some(Err(error));
            return Err(());
        }
        let Some(history) = self.history.as_mut() else { return Err(()); };
        history.decision_entered = true;
        let bytes = crate::native::target::RootPolicyPublicationWorkV1::
            publication_receipt_bytes_v1()
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Q04RootDecisionV1>()
                .checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                Result<Q04RootDecisionV1, RootAuthorityErrorV1>,
            >().checked_mul(3)?))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<
                aos_sandbox_protocol::domain_ledger::create_q04_history::Q04EffectSubgateV1,
            >().checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok());
        let admission = bytes.ok_or_else(NativeError::geometry).and_then(|bytes| {
            self.authority.journal.admit_role_observation_v1(
                aos_sandbox_model::ResourceVector::ZERO.with(
                    aos_sandbox_model::ResourceDimension::MemoryBytes, bytes,
                ),
            )
        });
        if let Err(error) = admission {
            history.decision = Some(Err(error.into()));
            return Err(());
        }
        let receipt = work.publication_receipt_v1()?;
        let returned = (|| {
            self.q04_recheck_original_binding_prefix_v1(stage, source_packet)?;
            let history = self.history.as_ref().ok_or_else(changed)?;
            let end = history.binding_prefix_end()?;
            if receipt.identity != history.identity()
                || receipt.target_before != history.target_before
                || receipt.transaction != history.identity.policy_transaction()
                || receipt.current != history.identity.policy_current()
                || receipt.sequence != history.target_before.0.checked_add(6).ok_or_else(bounds)?
                || crate::q04_data::closed_policy_binding_digest_v2(receipt.binding)?
                    != history.identity.binding()
            { return Err(changed()); }
            let binding = history.transactions().get(end.checked_sub(1).ok_or_else(bounds)?)
                .ok_or_else(changed)?;
            let committed = history.commits.get(end - 1)
                .and_then(|result| result.as_ref()).and_then(|result| result.as_ref().ok())
                .ok_or_else(changed)?;
            let r2 = history.suffix.phases.get(1).ok_or_else(changed)?;
            if committed.commit_sequence < history.original.0
                || r2.native_transaction_id() != *binding.id()
            { return Err(changed()); }
            crate::q04_data::root_decision_record(
                &history.identity, *binding.id(),
                receipt.sequence.checked_sub(1).ok_or_else(bounds)?, history.original.0,
                ObjectDigest::from_bytes(fixed(r2.bytes(), 352)),
                ObjectDigest::from_bytes(fixed(r2.bytes(), 416)),
            ).map_err(Into::into)
        })();
        let Some(history) = self.history.as_mut() else { return Err(()); };
        history.decision = Some(returned);
        let result = (|| {
            let decision = history.decision.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or_else(changed)?;
            let index = history.binding_prefix_end()?;
            let transaction = history.transactions().get(index).ok_or_else(changed)?;
            if history.committed != index || transaction.records().len() != 2
                || transaction.records()[0].value() != Some(decision.bytes().as_slice())
                || history.suffix.phases.get(2).is_none_or(|phase| {
                    phase.bytes()[96..128] != *decision.digest().as_bytes()
                })
            { return Err(changed()); }
            history.consumed_gate = Some(root_consumed_gate_record(&history.identity, decision)?);
            history.eligible_end = index.checked_add(1).ok_or_else(bounds)?;
            Ok(())
        })();
        if let Err(error) = result {
            if history.failure_v1().is_none() { history.retain_gate_failure_v1(error); }
            return Err(());
        }
        Ok(())
    }
}
