//! Same-original-flight Root custody for the generation-one Q04 continuation.
//!
//! One local owner parks its accepted socket before clock, peer, adoption or
//! native-open checks. Successful opens are parked immediately. Short floor
//! loans end before mutation; no decoded Claim, copied head or public callback
//! supplies an independent owner. Durable policy admission is a subgate only.

use std::cell::{Cell, RefCell};
use std::net::Shutdown;
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use aos_sandbox_core::format::descriptor_for_bytes;
use aos_sandbox_core::{MediaType, ObjectDescriptor, ObjectDigest, PortableMediaType, RawPairedClockSample};
use aos_sandbox_linux::unix_stream::{RetainedUnixStream, UnixStreamSubjectChunk};
use sha2::Digest as _;

use crate::journal::{Journal, JournalRecord, JournalTransaction, RecordNamespace};
use crate::normal_root::{OriginalControllerPolicyPeerV1, ProductionNormalRootStartupV1};

use super::super::protected_owner::{
    POLICY_STATE_JOURNAL, PROTECTED_POLICY_ROOT, policy_state_journal_limits,
};
use super::super::source_genesis_root::{
    Q04RootGen1CutLoanV1, RootCreateQ04TransferKindV1, RootSourceGenesisAuthorityV1,
    RootSourceGenesisFrameKindV1, ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1,
    ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1,
    decode_root_create_q04_transfer_v1, decode_root_source_genesis_frame_v2, encode_root_create_q04_transfer_v1,
    encode_root_source_genesis_frame_v2, original_root_kernel_pair_v1,
    require_open_receive_queue, wait_original_root_v1,
};
use super::super::{
    PolicyDeploymentHeadV1, PolicyDeploymentInputsV1, PolicyPublicationPrerequisitesV1,
    VerifiedControllerHoldReadbackV1, VerifiedControllerProjectAdmissionV1,
    VerifiedSignedProjectPolicySourceV2, PinnedSourceHoldReadbackSignerV1,
    SourceHierarchyFloorRecordV1, SourceTreeGenesisChallengeV1, SourceTreeGenesisIntentContextV1,
    SOURCE_TREE_GENESIS_READBACK_BYTES_V1, normalized_policy_input_digest_v1,
};
use aos_sandbox_policy::{
    AuthenticatedCacheDomainV1, AuthenticatedSandboxProjectRelationV1, CacheDomainBindingV1,
    CacheDomainVerifierV1, CompiledPolicyCandidateV1, PolicyCompilerInputV1, PolicyCompilerV1,
    SandboxProjectRelationVerifierV1,
};
use super::{CreateQ04ErrorV1, Q04CutIdentityV1};

const MAXIMUM_ROOT_FLIGHT: Duration = Duration::from_secs(65);
const MAXIMUM_SOURCE_OBSERVATIONS: usize = 16;

/// Selects the existing-only generation-one Q04 continuation on the fixed socket.
pub const ROOT_CREATE_Q04_QUERY_MAGIC_V1: &[u8; 8] = b"AOSSGQ04";

#[derive(Clone, Copy, Eq, PartialEq)]
enum RootQ04PreludePhaseV1 {
    Parked,
    Hello,
    PreparedSource,
    Anchored,
    CompletedSource,
    Completed,
    Preview,
    Prefunded,
    RefreshedSource,
    BindingHeld,
    PolicyCommitted,
    Decided,
    PolicyAcknowledged,
    ReleaseAuthorized,
    Settled,
    FinalClearance,
}

#[derive(Clone, Copy)]
enum RootSourceObservationPurposeV1 {
    Preparation,
    Completion,
    Refresh,
}

#[derive(Clone, Copy)]
enum RootControllerFrameSlotV1 {
    Prepare,
    Complete,
    Refresh,
    Prehold,
    Claim,
    Acknowledgement,
}

// These identities are selected by the actual privileged daemon configuration
// after its startup admission. A client Claim does not populate them.
struct RootServiceIdentitiesV1 {
    controller_uid: u32,
    controller_gid: u32,
    source_uid: u32,
    cache_uid: u32,
}

// Derived comparison DATA stays separate from original owner custody. The
// retained compiler result is reused by publication preview, not recompiled
// or promoted to a VerifiedPublication merely to serialize the binding.
struct RootCompilerInputDataV1 {
    input: PolicyCompilerInputV1,
    prerequisites: PolicyPublicationPrerequisitesV1,
    normalized: ObjectDigest,
    candidate: CompiledPolicyCandidateV1,
    binding: Vec<u8>,
}

// The independent compiler recipe keeps the exact original row comparisons.
// It is not a verified publication, a Controller ledger or a Root decision.
struct RootPreholdCompilationV1 {
    data: RootCompilerInputDataV1,
    validator: super::super::PolicyCompilerReplayValidatorV1,
    before_controller: ObjectDigest,
    effect_plan: ObjectDigest,
    operation_revision: ObjectDigest,
    desired_precondition: ObjectDigest,
    controller: VerifiedControllerProjectAdmissionV1,
}

struct RootPreholdPublicationPlanV1 {
    compilation: RootPreholdCompilationV1,
    capacity: super::super::protected_journal::Q04PublicationCapacityV1,
    identity: Option<Q04CutIdentityV1>,
    state_before: (u64, crate::journal::ProtectedJournalNamesV1, ObjectDigest),
    root_before: (u64, crate::journal::ProtectedJournalNamesV1, ObjectDigest),
    original_precut: ObjectDigest,
    policy_before: ObjectDigest,
    independent_recipe: ObjectDigest,
    gen1_floor: ObjectDigest,
    claim_length: usize,
    authority_suffix: RootPreholdAuthoritySuffixV1,
}

// These are canonical, fixed-width capacity shapes, not signed packets or
// observations of future commits. The original attempt owns every partial
// buffer before construction; there is deliberately no commit/extraction API.
#[derive(Default)]
struct RootPreholdAuthoritySuffixV1 {
    claim: Vec<u8>,
    packets: Vec<Vec<u8>>,
    phases: Vec<super::Q04PhaseRecordV1>,
    chunks: Vec<Vec<u8>>,
    transactions: Vec<JournalTransaction>,
    preflight: Option<Result<(), CreateQ04ErrorV1>>,
    complete: bool,
}

struct RootPreholdAuthorityInputV1<'plan> {
    identity: &'plan Q04CutIdentityV1,
    binding: &'plan [u8],
    root_before: ObjectDigest,
    root_sequence: u64,
    state_sequence: u64,
    claim_length: usize,
    claim: Option<&'plan super::Q04ClaimV1<'plan>>,
    held_pairs: Option<[ObjectDigest; 6]>,
}

// Only the actual Root attempt constructs this history after authenticating
// its complete held Claim. Future packets in `suffix` remain capacity DATA;
// each live phase must replace them with its real observed event first.
pub(crate) struct Q04RootAuthorityHistoryV1 {
    identity: Q04CutIdentityV1,
    original: (u64, crate::journal::ProtectedJournalNamesV1, ObjectDigest),
    suffix: RootPreholdAuthoritySuffixV1,
    committed: usize,
    eligible_end: usize,
    actual_acknowledgements: usize,
}

impl Q04RootAuthorityHistoryV1 {
    fn park(
        identity: &Q04CutIdentityV1,
        original: (u64, crate::journal::ProtectedJournalNamesV1, ObjectDigest),
    ) -> Self {
        Self {
            identity: identity.clone(), original,
            suffix: RootPreholdAuthoritySuffixV1::default(),
            committed: 0,
            eligible_end: 0,
            actual_acknowledgements: 0,
        }
    }

    pub(crate) fn identity(&self) -> &Q04CutIdentityV1 {
        &self.identity
    }

    pub(crate) fn transactions(&self) -> &[JournalTransaction] {
        &self.suffix.transactions
    }

    pub(crate) fn committed(&self) -> usize {
        self.committed
    }

    fn binding_prefix_end(&self) -> Result<usize, CreateQ04ErrorV1> {
        // R1, every complete Claim group, the existing Stage, then R2.
        let groups = self.suffix.chunks.len().checked_add(127)
            .ok_or(CreateQ04ErrorV1::Bounds)? / 128;
        groups.checked_add(3).ok_or(CreateQ04ErrorV1::Bounds)
    }

    pub(crate) fn require_fixed_original(&self, journal: &Journal) -> Result<(), CreateQ04ErrorV1> {
        require_root_q04_fixed_writer(journal)?;
        if !self.suffix.complete || journal.protected_writer_physical_names_v1()? != self.original.1
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        if self.committed == 0 && journal.q04_root_before_rows_v1()? != self.original {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        journal.require_q04_native_recipe_prefix_v1(
            &self.suffix.transactions[..self.committed], self.original.0,
        )?;
        journal.require_root_q04_materialized_prefix_v1(self, self.committed)
    }

    pub(crate) fn require_transition(
        &self,
        state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
        transaction: &JournalTransaction,
        index: usize,
    ) -> Result<(), crate::journal::JournalError> {
        if !self.suffix.complete || self.suffix.transactions.get(index) != Some(transaction) {
            return Err(crate::journal::JournalError::ProtectedBoundary);
        }
        self.require_prefix_rows(state.iter().map(|((namespace, key), value)| {
            (*namespace, key.as_slice(), value.as_slice())
        }), index)
    }

    // Complete Q04 materialization must equal this same original prefix.
    // Old binding/Stage fields use the existing recipes, never a new parser.
    pub(crate) fn require_prefix_rows<'row>(
        &self,
        rows: impl Iterator<Item = (RecordNamespace, &'row [u8], &'row [u8])> + Clone,
        prefix: usize,
    ) -> Result<(), crate::journal::JournalError> {
        if prefix > self.suffix.transactions.len() {
            return Err(crate::journal::JournalError::ProtectedBoundary);
        }
        let expected = |namespace, key: &[u8]| {
            self.suffix.transactions[..prefix].iter().rev()
                .flat_map(|transaction| transaction.records().iter().rev())
                .find(|record| record.namespace() == namespace && record.key() == key)
        };
        for (namespace, key, value) in rows.clone() {
            if key.starts_with(b"\0aos-q04-root-")
                && (namespace != RecordNamespace::DesiredState
                    || expected(namespace, key).and_then(JournalRecord::value) != Some(value))
            {
                return Err(crate::journal::JournalError::ProtectedBoundary);
            }
        }
        for transaction in &self.suffix.transactions[..prefix] {
            for record in transaction.records() {
                let Some(latest) = expected(record.namespace(), record.key()) else {
                    return Err(crate::journal::JournalError::ProtectedBoundary);
                };
                if rows.clone().find(|(namespace, key, _)| {
                    *namespace == record.namespace() && *key == record.key()
                }).map(|(_, _, value)| value) != latest.value()
                {
                    return Err(crate::journal::JournalError::ProtectedBoundary);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn may_append(&self, index: usize) -> bool {
        index == self.committed && index < self.eligible_end
    }

    // Only the owning Root action advances this after its real successful
    // CommitResult is already parked. Native postchecks still follow before
    // any next phase, decision or response is allowed.
    fn advance_parked_commit(&mut self) {
        self.committed += 1;
    }

    fn admit_actual_acknowledgement(
        &mut self,
        acknowledgement: &super::Q04AcknowledgementV1<'_>,
        controller_before_sequence: u64,
    ) -> Result<(), CreateQ04ErrorV1> {
        let packet_index = match acknowledgement.kind() {
            super::Q04AcknowledgementKindV1::Policy => 0,
            super::Q04AcknowledgementKindV1::Release => 1,
            super::Q04AcknowledgementKindV1::Settlement => 2,
            super::Q04AcknowledgementKindV1::Clearance => 3,
        };
        let transaction_index = self.binding_prefix_end()?.checked_add(1 + packet_index)
            .ok_or(CreateQ04ErrorV1::Bounds)?;
        if self.actual_acknowledgements != packet_index || self.committed != transaction_index
            || self.eligible_end != transaction_index
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let packet = self.suffix.packets.get_mut(packet_index).ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if packet.len() != acknowledgement.bytes().len() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        packet.copy_from_slice(acknowledgement.bytes());
        self.actual_acknowledgements += 1;
        self.refresh_acknowledgement_suffix(packet_index, controller_before_sequence)?;
        self.eligible_end = transaction_index.checked_add(1).ok_or(CreateQ04ErrorV1::Bounds)?;
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
    ) -> Result<(), CreateQ04ErrorV1> {
        let identity = &self.identity;
        let decision = super::Q04RootDecisionV1::decode(
            self.suffix.transactions.get(self.binding_prefix_end()?)
                .and_then(|transaction| transaction.records().first()).and_then(JournalRecord::value)
                .ok_or(CreateQ04ErrorV1::ChangedCut)?, identity,
        )?;
        let gate = root_consumed_gate_record(identity, &decision)?;
        let r3 = self.suffix.phases.get(2).ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let mut pairs = [ObjectDigest::from_bytes([0; 32]); 6];
        for (index, pair) in pairs.iter_mut().enumerate() {
            *pair = if index % 2 == 0 {
                ObjectDigest::from_bytes(super::fixed(r3.bytes(), 288 + index * 32))
            } else {
                capacity_shape_digest(identity, u8::try_from(index + 1).map_err(|_| CreateQ04ErrorV1::Bounds)?)?
            };
        }
        if self.actual_acknowledgements >= 3 {
            let packet = self.suffix.packets.get(2).ok_or(CreateQ04ErrorV1::ChangedCut)?;
            for (index, pair) in pairs.iter_mut().enumerate() {
                *pair = ObjectDigest::from_bytes(super::fixed(packet, 344 + index * 32));
            }
        }
        let first_transaction = self.binding_prefix_end()?.checked_add(1).ok_or(CreateQ04ErrorV1::Bounds)?;
        let released_binding = self.suffix.transactions.get(first_transaction + 1)
            .and_then(|transaction| transaction.records().first()).cloned()
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let zero = ObjectDigest::from_bytes([0; 32]);
        for (index, kind) in [
            super::Q04AcknowledgementKindV1::Policy,
            super::Q04AcknowledgementKindV1::Release,
            super::Q04AcknowledgementKindV1::Settlement,
            super::Q04AcknowledgementKindV1::Clearance,
        ].into_iter().enumerate().skip(first) {
            if index >= self.actual_acknowledgements {
                let packet = self.suffix.packets.get_mut(index).ok_or(CreateQ04ErrorV1::ChangedCut)?;
                packet.clear();
                root_capacity_acknowledgement(packet, kind, identity, controller_before_sequence, gate.digest(), pairs)?;
            }
            let packet = self.suffix.packets.get(index).ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let digest = ObjectDigest::from_bytes(sha2::Sha256::digest(packet).into());
            let prior = self.suffix.phases.get(index + 2).ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let mut events = [decision.digest(), gate.digest(), zero, zero, zero];
            if index >= 1 {
                events[2] = if self.actual_acknowledgements >= 2 {
                    ObjectDigest::from_bytes(sha2::Sha256::digest(
                        self.suffix.packets.get(1).ok_or(CreateQ04ErrorV1::ChangedCut)?,
                    ).into())
                } else {
                    capacity_shape_digest(identity, 7)?
                };
            }
            if index >= 2 {
                events[2] = self.suffix.phases.get(4).ok_or(CreateQ04ErrorV1::ChangedCut)?.digest();
            }
            if index >= 3 {
                events[3] = prior.digest();
                events[4] = if self.actual_acknowledgements == 4 {
                    ObjectDigest::from_bytes(super::fixed(packet, 632))
                } else {
                    capacity_shape_digest(identity, 8)?
                };
            }
            let phase = u8::try_from(index + 4).map_err(|_| CreateQ04ErrorV1::Bounds)?;
            let transaction_id = super::Q04TransactionOwnerV1::Root.transaction_id(identity, phase, prior.digest())?;
            let record = root_phase_record(identity, phase, transaction_id, self.original.2,
                Some(prior.digest()), events, pairs, Some(digest))?;
            record.require_successor(prior)?;
            let mut records = Vec::new();
            records.try_reserve_exact(if phase == 5 { 3 } else { 2 })?;
            if phase == 5 {
                records.push(released_binding.clone());
            }
            records.push(root_record(RootQ04RecordKeyV1::Packet(kind.phase()), identity, packet)?);
            records.push(root_record(RootQ04RecordKeyV1::Phase(phase), identity, record.bytes())?);
            self.suffix.transactions[first_transaction + index] = JournalTransaction::new(transaction_id, records)?;
            self.suffix.phases[index + 3] = record;
        }
        Ok(())
    }
}

pub(crate) fn require_root_q04_fixed_writer(journal: &Journal) -> Result<(), crate::journal::JournalError> {
    journal.require_protected_named_location(
        Path::new(PROTECTED_POLICY_ROOT),
        super::super::protected_owner::POLICY_AUTHORITY_JOURNAL,
        0,
        super::super::protected_owner::policy_authority_journal_limits(),
    )
}

pub(crate) fn require_root_q04_ordinary_boundary(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), crate::journal::JournalError> {
    if state.keys().any(|(_, key)| key.starts_with(b"\0aos-q04-root-"))
        || transaction.records().iter().any(|record| record.key().starts_with(b"\0aos-q04-root-"))
    {
        return Err(crate::journal::JournalError::ProtectedBoundary);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum RootQ04RecordKeyV1 {
    Cut,
    Phase(u8),
    Decision,
    Packet(u8),
    ClaimIndex,
    ClaimChunk(u16),
}

impl RootQ04RecordKeyV1 {
    fn encode(self, nonce: [u8; 16]) -> Result<Vec<u8>, CreateQ04ErrorV1> {
        let prefix: &[u8] = match self {
            Self::Cut => b"\0aos-q04-root-cut-v1\0",
            Self::Phase(_) => b"\0aos-q04-root-phase-v1\0",
            Self::Decision => b"\0aos-q04-root-decision-v1\0",
            Self::Packet(_) => b"\0aos-q04-root-packet-v1\0",
            Self::ClaimIndex => b"\0aos-q04-root-claim-index-v1\0",
            Self::ClaimChunk(_) => b"\0aos-q04-root-claim-v1\0",
        };
        if nonce == [0; 16]
            || matches!(self, Self::Phase(0 | 8..=u8::MAX) | Self::Packet(0 | 5..=u8::MAX))
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let mut key = Vec::new();
        key.try_reserve_exact(prefix.len() + 18)?;
        key.extend_from_slice(prefix);
        key.extend_from_slice(&nonce);
        match self {
            Self::Phase(phase) | Self::Packet(phase) => key.push(phase),
            Self::ClaimChunk(chunk) => key.extend_from_slice(&chunk.to_be_bytes()),
            _ => {}
        }
        Ok(key)
    }
}

impl RootPreholdAuthoritySuffixV1 {
    // There is no authentic future signature at prehold. These exact codec
    // shapes traverse the sole Claim/chunk/native encoders to bound every
    // eligible fixed-width variation. They may never be offered to commit.
    fn form(
        &mut self,
        plan: RootPreholdAuthorityInputV1<'_>,
        stage: &super::super::binding_v2::Q04RootStageRecipeV1,
        request: &super::Q04PreholdInputDataV1<'_>,
        preview: &super::Q04PreviewV1<'_>,
        source_packet: &[u8],
    ) -> Result<(), CreateQ04ErrorV1> {
        use super::{Q04ClaimStorageRecipeV1, Q04ClaimV1, Q04TransactionOwnerV1};

        let identity = plan.identity;
        if self.complete || !self.claim.is_empty() || !self.transactions.is_empty()
            || !self.chunks.is_empty() || !self.phases.is_empty() || !self.packets.is_empty()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let original = request.fields();
        let inputs = preview.fields();
        let held_controller_shape = [0; super::super::CLOSED_CONTROLLER_HOLD_READBACK_BYTES_V1];
        let held_cache_shape = [0; crate::cache_residency::CLOSED_CACHE_OWNER_READBACK_BYTES_V2];
        if let Some(claim) = plan.claim {
            self.claim.try_reserve_exact(claim.bytes().len())?;
            self.claim.extend_from_slice(claim.bytes());
        } else {
            super::encode_q04_claim_body_v1(&mut self.claim, [
                original[1], original[2], original[3], inputs[3], inputs[4], inputs[5], inputs[6],
                inputs[8], plan.binding, original[5], &held_controller_shape,
                source_packet, &held_cache_shape, identity.bytes(),
            ], identity)?;
            self.claim.try_reserve_exact(64)?;
            self.claim.extend_from_slice(&[0; 64]);
        }
        if self.claim.len() != plan.claim_length {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let claim = Q04ClaimV1::decode(&self.claim, identity)?;
        let storage = Q04ClaimStorageRecipeV1::new(&claim, identity)?;
        let count = storage.chunk_count();
        let groups = count.checked_add(127).ok_or(CreateQ04ErrorV1::Bounds)? / 128;
        self.transactions.try_reserve_exact(8 + usize::from(groups))?;
        self.chunks.try_reserve_exact(usize::from(count))?;
        self.phases.try_reserve_exact(7)?;
        self.packets.try_reserve_exact(4)?;

        let mut pairs = [ObjectDigest::from_bytes([0; 32]); 6];
        for (index, pair) in pairs.iter_mut().enumerate() {
            *pair = capacity_shape_digest(identity, u8::try_from(index + 1)
                .map_err(|_| CreateQ04ErrorV1::Bounds)?)?;
        }
        if let Some(actual) = plan.held_pairs {
            // Only held fields have been observed at this boundary. Future
            // released representatives remain noncommitting capacity DATA.
            for index in [0, 2, 4] {
                pairs[index] = actual[index];
            }
        }
        let r1_id = Q04TransactionOwnerV1::Root.transaction_id(identity, 1, plan.root_before)?;
        let r1 = root_phase_record(identity, 1, r1_id, plan.root_before, None,
            [ObjectDigest::from_bytes([0; 32]); 5], pairs, None)?;
        self.transactions.push(JournalTransaction::new(r1_id, vec![
            root_record(RootQ04RecordKeyV1::Cut, identity, identity.bytes())?,
            root_record(RootQ04RecordKeyV1::Phase(1), identity, r1.bytes())?,
            root_record(RootQ04RecordKeyV1::ClaimIndex, identity, storage.index_bytes())?,
        ])?);
        self.phases.push(r1);

        for chunk in 0..count {
            // The same parent owns the empty chunk before its first growth.
            self.chunks.push(Vec::new());
            storage.encode_chunk(chunk, self.chunks.last_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?)?;
        }
        for group in 0..groups {
            let first = usize::from(group) * 128;
            let last = self.chunks.len().min(first + 128);
            let mut records = Vec::new();
            records.try_reserve_exact(last - first)?;
            for chunk in first..last {
                records.push(root_record(RootQ04RecordKeyV1::ClaimChunk(
                    u16::try_from(chunk).map_err(|_| CreateQ04ErrorV1::Bounds)?,
                ), identity, &self.chunks[chunk])?);
            }
            let id = root_claim_group_id(identity, group,
                self.phases.first().ok_or(CreateQ04ErrorV1::ChangedCut)?.digest())?;
            self.transactions.push(JournalTransaction::new(id, records)?);
        }
        self.transactions.push(stage.transaction().clone());

        let (mut qualified, released) = stage.q04_binding_capacity_records(plan.binding)?;
        let r2 = self.next_phase(identity, 2, plan.root_before,
            [ObjectDigest::from_bytes([0; 32]); 5], pairs, None)?;
        qualified.push(root_record(RootQ04RecordKeyV1::Phase(2), identity, r2.bytes())?);
        self.transactions.push(JournalTransaction::new(r2.native_transaction_id(), qualified)?);
        self.phases.push(r2);

        // The capacity decision points to the earlier R2 recipe, never its
        // own R3 transaction. The live decision must instead consume actual
        // qualified-CAS and policy-state committed native readbacks.
        let decision = root_decision_record(identity,
            self.phases.last().ok_or(CreateQ04ErrorV1::ChangedCut)?.native_transaction_id(),
            plan.state_sequence.checked_add(5).ok_or(CreateQ04ErrorV1::Bounds)?,
            plan.root_sequence, pairs[2], pairs[4])?;
        let gate = root_consumed_gate_record(identity, &decision)?;
        let zero = ObjectDigest::from_bytes([0; 32]);
        let mut events = [decision.digest(), zero, zero, zero, zero];
        let r3 = self.next_phase(identity, 3, plan.root_before, events, pairs, None)?;
        self.transactions.push(JournalTransaction::new(r3.native_transaction_id(), vec![
            root_record(RootQ04RecordKeyV1::Decision, identity, decision.bytes())?,
            root_record(RootQ04RecordKeyV1::Phase(3), identity, r3.bytes())?,
        ])?);
        self.phases.push(r3);

        let controller_next = u64::from_be_bytes(super::fixed(original[0], 464));
        for (index, kind) in [
            super::Q04AcknowledgementKindV1::Policy,
            super::Q04AcknowledgementKindV1::Release,
            super::Q04AcknowledgementKindV1::Settlement,
            super::Q04AcknowledgementKindV1::Clearance,
        ].into_iter().enumerate() {
            self.packets.push(Vec::new());
            root_capacity_acknowledgement(self.packets.last_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?,
                kind, identity, controller_next,
                gate.digest(), pairs)?;
            events[1] = gate.digest();
            if index == 1 {
                events[2] = capacity_shape_digest(identity, 7)?;
            } else if index == 2 {
                events[2] = self.phases.last().ok_or(CreateQ04ErrorV1::ChangedCut)?.digest();
            } else if index == 3 {
                events[3] = self.phases.last().ok_or(CreateQ04ErrorV1::ChangedCut)?.digest();
                events[4] = capacity_shape_digest(identity, 8)?;
            }
            let acknowledgement = ObjectDigest::from_bytes(sha2::Sha256::digest(
                self.packets.last().ok_or(CreateQ04ErrorV1::ChangedCut)?.as_slice(),
            ).into());
            let phase = u8::try_from(index + 4).map_err(|_| CreateQ04ErrorV1::Bounds)?;
            let record = self.next_phase(identity, phase, plan.root_before, events, pairs,
                Some(acknowledgement))?;
            let mut records = Vec::new();
            records.try_reserve_exact(if phase == 5 { 3 } else { 2 })?;
            if phase == 5 {
                records.push(released.clone());
            }
            records.push(root_record(RootQ04RecordKeyV1::Packet(kind.phase()), identity,
                self.packets.last().ok_or(CreateQ04ErrorV1::ChangedCut)?)?);
            records.push(root_record(RootQ04RecordKeyV1::Phase(phase), identity, record.bytes())?);
            self.transactions.push(JournalTransaction::new(record.native_transaction_id(), records)?);
            self.phases.push(record);
        }

        let records = self.transactions.iter().try_fold(0_usize, |sum, transaction| {
            sum.checked_add(transaction.records().len()).ok_or(CreateQ04ErrorV1::Bounds)
        })?;
        if self.transactions.len() != 8 + usize::from(groups)
            || records != 19 + usize::from(count)
            || self.phases.len() != 7 || self.packets.len() != 4
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.complete = true;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn next_phase(
        &self,
        identity: &Q04CutIdentityV1,
        phase: u8,
        before: ObjectDigest,
        events: [ObjectDigest; 5],
        pairs: [ObjectDigest; 6],
        acknowledgement: Option<ObjectDigest>,
    ) -> Result<super::Q04PhaseRecordV1, CreateQ04ErrorV1> {
        let prior = self.phases.last().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let transaction = super::Q04TransactionOwnerV1::Root.transaction_id(identity, phase, prior.digest())?;
        let record = root_phase_record(identity, phase, transaction, before, Some(prior.digest()),
            events, pairs, acknowledgement)?;
        record.require_successor(prior)?;
        Ok(record)
    }
}

fn root_record(
    key: RootQ04RecordKeyV1,
    identity: &Q04CutIdentityV1,
    value: &[u8],
) -> Result<JournalRecord, CreateQ04ErrorV1> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(value.len())?;
    bytes.extend_from_slice(value);
    Ok(JournalRecord::put(RecordNamespace::DesiredState, key.encode(identity.nonce())?, bytes))
}

// Opaque nonzero representatives only fill fields whose future authentic
// values have fixed widths. They are not an authority/readback substitute.
pub(crate) fn capacity_shape_digest(identity: &Q04CutIdentityV1, field: u8) -> Result<ObjectDigest, CreateQ04ErrorV1> {
    use sha2::{Digest as _, Sha256};

    let digest = ObjectDigest::from_bytes(Sha256::new()
        .chain_update(b"aos.sandbox.create-q04.capacity-shape.v1\0")
        .chain_update(identity.bytes()).chain_update([field]).finalize().into());
    if digest.as_bytes() == &[0; 32] {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    Ok(digest)
}

fn root_claim_group_id(
    identity: &Q04CutIdentityV1,
    group: u16,
    intent: ObjectDigest,
) -> Result<[u8; 16], CreateQ04ErrorV1> {
    use sha2::{Digest as _, Sha256};

    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.create-q04.transaction.root-claim-group.v1\0")
        .chain_update(identity.digest().as_bytes()).chain_update(group.to_be_bytes())
        .chain_update(intent.as_bytes()).finalize();
    let id = super::fixed(&digest, 0);
    if id == [0; 16] {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    Ok(id)
}

// These field-to-body constructors are the one Root record recipe. They
// validate canonical DATA only; the live action separately supplies genuine
// earlier native events, current owner loans and authenticated packets.
#[allow(clippy::too_many_arguments)]
fn root_phase_record(
    identity: &Q04CutIdentityV1,
    phase: u8,
    transaction: [u8; 16],
    before: ObjectDigest,
    predecessor: Option<ObjectDigest>,
    events: [ObjectDigest; 5],
    pairs: [ObjectDigest; 6],
    acknowledgement: Option<ObjectDigest>,
) -> Result<super::Q04PhaseRecordV1, CreateQ04ErrorV1> {
    let mut body = [0; super::PHASE_BYTES];
    body[16..48].copy_from_slice(identity.digest().as_bytes());
    body[48..64].copy_from_slice(&identity.stage_id());
    if let Some(predecessor) = predecessor {
        body[64..96].copy_from_slice(predecessor.as_bytes());
    }
    for (index, event) in events.into_iter().enumerate() {
        body[96 + index * 32..128 + index * 32].copy_from_slice(event.as_bytes());
    }
    for (index, pair) in pairs.into_iter().enumerate() {
        if index % 2 == 0 || phase >= 6 {
            body[288 + index * 32..320 + index * 32].copy_from_slice(pair.as_bytes());
        }
    }
    if let Some(acknowledgement) = acknowledgement {
        body[480..512].copy_from_slice(acknowledgement.as_bytes());
    }
    body[512..544].copy_from_slice(before.as_bytes());
    body[544..560].copy_from_slice(&transaction);
    Ok(super::Q04PhaseRecordV1::from_body(super::Q04PhaseOwnerV1::Root, phase, body, identity)?)
}

pub(super) fn root_decision_record(
    identity: &Q04CutIdentityV1,
    earlier_authority_transaction: [u8; 16],
    state_commit_sequence: u64,
    authority_before_sequence: u64,
    source_held: ObjectDigest,
    cache_held: ObjectDigest,
) -> Result<super::Q04RootDecisionV1, CreateQ04ErrorV1> {
    let mut body = [0; super::DECISION_BYTES];
    body[16..48].copy_from_slice(identity.digest().as_bytes());
    body[48..64].copy_from_slice(&earlier_authority_transaction);
    body[64..80].copy_from_slice(&identity.publication_id());
    body[80..112].copy_from_slice(identity.policy_transaction().as_bytes());
    body[112..120].copy_from_slice(&state_commit_sequence.to_be_bytes());
    body[120..152].copy_from_slice(identity.policy_current().as_bytes());
    body[152..184].copy_from_slice(identity.binding().as_bytes());
    body[184..216].copy_from_slice(identity.gate_identity().as_bytes());
    body[216..248].copy_from_slice(source_held.as_bytes());
    body[248..280].copy_from_slice(cache_held.as_bytes());
    body[280..312].copy_from_slice(identity.cache_quota().as_bytes());
    body[312..320].copy_from_slice(&authority_before_sequence.to_be_bytes());
    body[320..352].copy_from_slice(identity.before_controller_rows().as_bytes());
    Ok(super::Q04RootDecisionV1::from_body(body, identity)?)
}

pub(crate) fn root_consumed_gate_record(
    identity: &Q04CutIdentityV1,
    decision: &super::Q04RootDecisionV1,
) -> Result<super::Q04EffectSubgateV1, CreateQ04ErrorV1> {
    let mut body = [0; super::GATE_BYTES];
    body[16..48].copy_from_slice(identity.digest().as_bytes());
    body[48..80].copy_from_slice(identity.binding().as_bytes());
    body[80..96].copy_from_slice(&identity.publication_id());
    body[96..128].copy_from_slice(identity.policy_current().as_bytes());
    body[128..160].copy_from_slice(decision.digest().as_bytes());
    body[160..176].copy_from_slice(&identity.stage_id());
    body[176..184].copy_from_slice(&identity.accepted_generation().to_be_bytes());
    body[184] = 1;
    body[224..256].copy_from_slice(identity.gen1_floor().as_bytes());
    let gate = super::Q04EffectSubgateV1::from_body(body)?;
    gate.require_identity(identity, decision)?;
    Ok(gate)
}

fn root_capacity_acknowledgement(
    output: &mut Vec<u8>,
    kind: super::Q04AcknowledgementKindV1,
    identity: &Q04CutIdentityV1,
    controller_before_sequence: u64,
    consumed_gate: ObjectDigest,
    pairs: [ObjectDigest; 6],
) -> Result<(), CreateQ04ErrorV1> {
    if !output.is_empty() {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    let frames = match kind {
        super::Q04AcknowledgementKindV1::Policy => 9,
        super::Q04AcknowledgementKindV1::Release => 15,
        super::Q04AcknowledgementKindV1::Settlement => 20,
        super::Q04AcknowledgementKindV1::Clearance => 27,
    };
    let next_sequence = controller_before_sequence.checked_add(frames).ok_or(CreateQ04ErrorV1::Bounds)?;
    let clear_fields = if kind == super::Q04AcknowledgementKindV1::Clearance {
        Some([
            capacity_shape_digest(identity, 9)?, capacity_shape_digest(identity, 10)?,
            capacity_shape_digest(identity, 11)?, capacity_shape_digest(identity, 12)?,
        ])
    } else {
        None
    };
    super::encode_q04_acknowledgement_data_v1(
        output, kind, identity, next_sequence, consumed_gate, pairs, clear_fields,
    )?;
    output.extend_from_slice(&[0; 64]);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn require_terminal_pairs(
    identity: &Q04CutIdentityV1,
    acknowledgement: &super::Q04AcknowledgementV1<'_>,
    controller: VerifiedControllerProjectAdmissionV1,
    original_held: VerifiedControllerHoldReadbackV1,
    floor: &SourceHierarchyFloorRecordV1,
    original_cache: crate::cache_residency::VerifiedClosedCacheOwnerReadbackV2,
    observed_cache: &crate::cache_residency::CacheResidencyRootReadOnlyPolicyHoldV1,
    release: &super::Q04PhaseRecordV1,
    settlement: Option<&super::Q04PhaseRecordV1>,
) -> Result<(), CreateQ04ErrorV1> {
    let (_, _, _, expected) = terminal_hold_pair_recipes(
        identity, controller, original_held, floor, original_cache,
    )?;
    let packet = acknowledgement.bytes();
    for (index, digest) in expected.iter().enumerate() {
        if packet[344 + index * 32..376 + index * 32] != *digest.as_bytes() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
    }
    if observed_cache.hold.is_held() || observed_cache.hold.record_digest()? != expected[5]
        || observed_cache.replay.quota_digest != identity.cache_quota()
        || release.phase() != 5
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    if acknowledgement.kind() == super::Q04AcknowledgementKindV1::Clearance {
        let settlement = settlement.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if settlement.phase() != 6 || settlement.bytes()[160..192] != *release.digest().as_bytes()
            || packet[536..568] != *settlement.digest().as_bytes()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
    }
    Ok(())
}

fn terminal_hold_pair_recipes(
    identity: &Q04CutIdentityV1,
    controller: VerifiedControllerProjectAdmissionV1,
    original_held: VerifiedControllerHoldReadbackV1,
    floor: &SourceHierarchyFloorRecordV1,
    original_cache: crate::cache_residency::VerifiedClosedCacheOwnerReadbackV2,
) -> Result<(crate::journal::ControllerPolicyHoldV1, crate::journal::SourceDomainPolicyHoldV1,
    crate::journal::CachePolicyHoldV1, [ObjectDigest; 6]), CreateQ04ErrorV1> {
    let controller_hold = crate::journal::ControllerPolicyHoldV1::new(
        original_held.operation(), original_held.sandbox(), original_held.source(),
        original_held.binding(), original_held.epoch(),
    )?;
    let source_hold = crate::journal::SourceDomainPolicyHoldV1::new(
        controller.operation(), controller.sandbox(), controller.source_commitment(),
        floor.tree_head(), identity.binding(), identity.epoch(),
    )?;
    let cache_hold = original_cache.hold();
    let expected = [controller_hold.record_digest()?, controller_hold.q04_released_record_digest()?,
        source_hold.record_digest()?, source_hold.q04_released_record_digest()?,
        cache_hold.record_digest()?, cache_hold.q04_released_record_digest()?];
    Ok((controller_hold, source_hold, cache_hold, expected))
}

#[allow(clippy::too_many_arguments)]
fn require_original_lower_clearance_recipe(
    gen1: &Q04RootGen1CutLoanV1<'_>,
    history: &Q04RootAuthorityHistoryV1,
    prehold_metadata: &[u8],
    claim_fields: &[&[u8]; 14],
    acknowledgement: &super::Q04AcknowledgementV1<'_>,
    controller: VerifiedControllerProjectAdmissionV1,
    original_held: VerifiedControllerHoldReadbackV1,
    original_cache: crate::cache_residency::VerifiedClosedCacheOwnerReadbackV2,
) -> Result<(), CreateQ04ErrorV1> {
    if acknowledgement.kind() != super::Q04AcknowledgementKindV1::Clearance
        || history.committed != history.binding_prefix_end()?.checked_add(4).ok_or(CreateQ04ErrorV1::Bounds)?
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    gen1.recheck()?;
    let identity = history.identity();
    let root_five = history.suffix.phases.get(4).ok_or(CreateQ04ErrorV1::ChangedCut)?;
    let root_six = history.suffix.phases.get(5).ok_or(CreateQ04ErrorV1::ChangedCut)?;
    if root_five.phase() != 5 || root_six.phase() != 6
        || root_six.bytes()[160..192] != *root_five.digest().as_bytes()
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    let (_, source_hold, cache_hold, pairs) = terminal_hold_pair_recipes(
        identity, controller, original_held, gen1.floor(), original_cache,
    )?;
    let source_names =
        crate::journal::ProtectedJournalNamesV1::from_bytes(&prehold_metadata[224..272])
            .map_err(crate::journal::JournalError::from)?;
    let source_next = u64::from_be_bytes(super::fixed(prehold_metadata, 472));
    let cache_names =
        crate::journal::ProtectedJournalNamesV1::from_bytes(&prehold_metadata[272..320])
            .map_err(crate::journal::JournalError::from)?;
    let cache_next = u64::from_be_bytes(super::fixed(prehold_metadata, 480));
    let observed_source = gen1.source_coordinates()?;
    if observed_source != (source_names, source_next.checked_add(11).ok_or(CreateQ04ErrorV1::Bounds)?) {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    // Cache's actual clear membership was independently replayed through the
    // same fixed read-only engine. These hashes use its exact native recipe,
    // not a new serializer or a checksum promoted to authority.
    let cache_clear = crate::journal::q04_cache_clear_recipe_digest_data_v1(
        identity, cache_names, cache_next, cache_hold, root_five.digest(),
    )?;
    let source_clear = crate::journal::q04_source_clear_recipe_digest_data_v1(
        identity, source_names, source_next, source_hold, root_five.digest(),
    )?;
    let decision = super::Q04RootDecisionV1::decode(
        history.suffix.transactions[history.binding_prefix_end()?].records()[0]
            .value().ok_or(CreateQ04ErrorV1::ChangedCut)?, identity,
    )?;
    let consumed = root_consumed_gate_record(identity, &decision)?;
    let events = super::Q04ControllerPhaseEventsV1 {
        decision: decision.digest(), consumed_gate: consumed.digest(),
        release: root_five.digest(), settlement: root_six.digest(),
        clearance: ObjectDigest::from_bytes([0; 32]), final_root: ObjectDigest::from_bytes([0; 32]),
        pairs,
        policy_ack: history.suffix.phases[3].acknowledgement(),
        release_ack: root_five.acknowledgement(),
        settlement_ack: root_six.acknowledgement(),
        clearance_ack: ObjectDigest::from_bytes([0; 32]),
    };
    let mut prior = None;
    for phase in 1..=6 {
        prior = Some(super::controller_phase_recipe_v1(identity, phase, prior.as_ref(), &events)?);
    }
    let prior_c_six = prior.ok_or(CreateQ04ErrorV1::ChangedCut)?;
    let status_three = consumed.next_status_recipe(events.release_ack)?
        .next_status_recipe(events.settlement_ack)?;
    let rows = crate::reconciler::read_original_q04_rows_v1(
        claim_fields[0], claim_fields[1], claim_fields[2], crate::reconciler::Q04OriginalRowBindingV1 {
            operation: identity.operation(), sandbox: identity.sandbox(), project: identity.project(),
            accepted_generation: identity.accepted_generation(), desired_precondition: identity.desired_precondition(),
        },
    )?;
    let effect = rows.applying_effect_with_gate(&status_three)?;
    let clearance = super::lower_clearance_recipe_digest_v1(
        identity, root_six, cache_clear, source_clear, &prior_c_six, &effect,
    )?;
    let packet = acknowledgement.bytes();
    if packet[568..600] != *cache_clear.as_bytes() || packet[600..632] != *source_clear.as_bytes()
        || packet[632..664] != *clearance.as_bytes()
    {
        return Err(CreateQ04ErrorV1::ChangedCut);
    }
    gen1.recheck()?;
    Ok(())
}

// The fields deliberately have no Clone, reset, extraction or Drop adapter.
// The first actual cause and original I/O result remain in this same owner.
/// Retains the original accepted Q04 stream and actual fixed Root owners.
///
/// This negative-custody owner grants no publication, Create or live floor
/// authority. Its selected caller keeps it resident through final clearance;
/// abandoning an uncleared attempt terminates the process before owner drops.
/// Lower accepted-stream discrimination and opener/RPC pre-return prefixes are
/// not recovered by this owner.
pub struct OriginalRootCreateQ04AttemptV1<'startup> {
    startup: Option<&'startup ProductionNormalRootStartupV1>,
    identities: RootServiceIdentitiesV1,
    original: UnixStream,
    stream: Option<RetainedUnixStream>,
    peer: Option<OriginalControllerPolicyPeerV1<'startup>>,
    root: Option<RootSourceGenesisAuthorityV1>,
    state: Option<Journal>,
    clock: Option<RawPairedClockSample>,
    started: Option<Instant>,
    cause: RefCell<Option<CreateQ04ErrorV1>>,
    postcheck_debt: RefCell<Option<CreateQ04ErrorV1>>,
    received: Option<Result<UnixStreamSubjectChunk, aos_sandbox_linux::seqpacket::RetainedSeqpacketReceiveErrorV1>>,
    request: [u8; 32],
    phase: RootQ04PreludePhaseV1,
    controller_frame: Vec<u8>,
    completion_frame: Vec<u8>,
    refresh_frames: Vec<Vec<u8>>,
    sent: Vec<u8>,
    sent_progress: Cell<usize>,
    send_result: RefCell<Option<Result<usize, rustix::io::Errno>>>,
    shutdown_result: Option<Result<(), std::io::Error>>,
    source_received: Option<Result<super::super::SourceTreeGenesisReadbackPacketV2, std::io::Error>>,
    source_observations: Vec<super::super::SourceTreeGenesisReadbackPacketV2>,
    source_resource_posts: Vec<RootResourceSourcePostsV2>,
    floor: Option<SourceHierarchyFloorRecordV1>,
    stage: Option<super::super::binding_v2::Q04RootStageRecipeV1>,
    preview: Vec<u8>,
    preview_chunk: Vec<u8>,
    prehold: Vec<u8>,
    prehold_frame: Vec<u8>,
    prehold_plan: Option<Result<RootPreholdPublicationPlanV1, CreateQ04ErrorV1>>,
    prehold_reply: Option<super::Q04PreholdPublicationDataV1>,
    controller_clock: Option<[u8; 32]>,
    claim: Vec<u8>,
    claim_frame: Vec<u8>,
    claim_source_observation: Option<usize>,
    held_compilation: Option<Result<RootCompilerInputDataV1, CreateQ04ErrorV1>>,
    root_history: Option<Q04RootAuthorityHistoryV1>,
    root_commits: Vec<Option<Result<crate::journal::CommitResult, CreateQ04ErrorV1>>>,
    publication: Option<super::super::protected_journal::Q04PolicyPublicationAttemptV1>,
    publication_preparation: Option<Result<super::super::PreparedPolicyPublicationV1, CreateQ04ErrorV1>>,
    publication_native: Option<JournalTransaction>,
    publication_result: Option<Result<(), CreateQ04ErrorV1>>,
    publication_readback: Option<Result<super::super::protected_journal::Q04PolicyPublicationReadbackV1, CreateQ04ErrorV1>>,
    decision: Option<Result<super::Q04RootDecisionV1, CreateQ04ErrorV1>>,
    consumed_gate: Option<super::Q04EffectSubgateV1>,
    acknowledgement_frames: Vec<Vec<u8>>,
    cache_terminal_outcomes: Vec<crate::cache_residency::Q04RootCacheTerminalOutcomeV1>,
    refresh_resume: Option<RootQ04PreludePhaseV1>,
    controller_complete: Vec<u8>,
    source_complete: Vec<u8>,
    cleared: bool,
}

impl<'startup> OriginalRootCreateQ04AttemptV1<'startup> {
    // Only the selected daemon branch moves its actual accepted socket here.
    // Construction is infallible and precedes the first clock/peer/open effect.
    fn park(
        original: UnixStream,
        startup: Option<&'startup ProductionNormalRootStartupV1>,
        identities: RootServiceIdentitiesV1,
        request: [u8; 32],
    ) -> Self {
        Self {
            startup,
            identities,
            original,
            stream: None,
            peer: None,
            root: None,
            state: None,
            clock: None,
            started: None,
            cause: RefCell::new(None),
            postcheck_debt: RefCell::new(None),
            received: None,
            request,
            phase: RootQ04PreludePhaseV1::Parked,
            controller_frame: Vec::new(),
            completion_frame: Vec::new(),
            refresh_frames: Vec::new(),
            sent: Vec::new(),
            sent_progress: Cell::new(0),
            send_result: RefCell::new(None),
            shutdown_result: None,
            source_received: None,
            source_observations: Vec::new(),
            source_resource_posts: Vec::new(),
            floor: None,
            stage: None,
            preview: Vec::new(),
            preview_chunk: Vec::new(),
            prehold: Vec::new(),
            prehold_frame: Vec::new(),
            prehold_plan: None,
            prehold_reply: None,
            controller_clock: None,
            claim: Vec::new(),
            claim_frame: Vec::new(),
            claim_source_observation: None,
            held_compilation: None,
            root_history: None,
            root_commits: Vec::new(),
            publication: None,
            publication_preparation: None,
            publication_native: None,
            publication_result: None,
            publication_readback: None,
            decision: None,
            consumed_gate: None,
            acknowledgement_frames: Vec::new(),
            cache_terminal_outcomes: Vec::new(),
            refresh_resume: None,
            controller_complete: Vec::new(),
            source_complete: Vec::new(),
            cleared: false,
        }
    }

    /// Parks the selected daemon's actual stream before any Q04 admission effect.
    ///
    /// Identities are the existing privileged daemon configuration, not client
    /// Claim fields. Construction is infallible; [`Self::begin_existing_gen1`]
    /// performs the genuine startup, original peer and fixed-owner checks.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        original: UnixStream,
        startup: Option<&'startup ProductionNormalRootStartupV1>,
        request: [u8; 32],
        controller_uid: u32,
        controller_gid: u32,
        source_uid: u32,
        cache_uid: u32,
    ) -> Self {
        Self::park(original, startup, RootServiceIdentitiesV1 {
            controller_uid, controller_gid, source_uid, cache_uid,
        }, request)
    }

    /// Begins only an existing completed gen1 flight without issuing a new Stage.
    ///
    /// # Errors
    /// Retains the first actual startup, peer, clock, fixed-open or transport
    /// failure. The caller must not retry, release or drop the failed attempt.
    pub fn begin_existing_gen1(&mut self) -> Result<(), ()> {
        let outcome = self.begin_original_existing_gen1();
        self.retain_outcome(outcome)
    }

    fn begin_original_existing_gen1(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::Parked
            || self.request[..8] != *ROOT_CREATE_Q04_QUERY_MAGIC_V1
            || self.request[8..24] == [0; 16]
            || self.request[24..32] != [0; 8]
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.admit_original()?;
        let root = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        self.sent.try_reserve_exact(56)?;
        self.sent.resize(56, 0);
        self.sent[..8].copy_from_slice(ROOT_SOURCE_GENESIS_HELLO_MAGIC_V1);
        self.sent[8..10].copy_from_slice(&1_u16.to_be_bytes());
        self.sent[16..32].copy_from_slice(&self.request[8..24]);
        self.sent[32..48].copy_from_slice(&root.nonce());
        self.sent[48..52].copy_from_slice(&self.identities.source_uid.to_be_bytes());
        self.sent[52..56].copy_from_slice(&self.identities.controller_uid.to_be_bytes());
        self.write_original(&self.sent)?;
        self.phase = RootQ04PreludePhaseV1::Hello;
        Ok(())
    }

    /// Lends the exact Source request selected by the original Prepare packet.
    ///
    /// # Errors
    /// Retains a malformed/nonhistorical packet, missing existing floor or
    /// original owner/clock failure. Global Empty and new genesis are refused.
    pub fn read_existing_source_preparation(
        &mut self,
    ) -> Result<RootCreateQ04SourceObservationLoanV1<'_, 'startup>, ()> {
        let prepared = self.prepare_source_observation(RootSourceObservationPurposeV1::Preparation);
        let (project, challenge, context) = self.retain_outcome(prepared)?;
        self.source_observation_loan(project, challenge, context, RootSourceObservationPurposeV1::Preparation)
    }

    /// Lends the exact Source request selected by actual Controller Complete.
    ///
    /// # Errors
    /// Retains changed completion, current gen1 or original transport custody.
    /// The returned loan must park the actual RPC result before postchecks.
    pub fn read_existing_source_completion(
        &mut self,
    ) -> Result<RootCreateQ04SourceObservationLoanV1<'_, 'startup>, ()> {
        let prepared = self.prepare_source_observation(RootSourceObservationPurposeV1::Completion);
        let (project, challenge, context) = self.retain_outcome(prepared)?;
        self.source_observation_loan(project, challenge, context, RootSourceObservationPurposeV1::Completion)
    }

    /// Refreshes completed gen1 from a new actual packet on the same held flight.
    ///
    /// This read-only request issues no Stage, hold, publication or phase
    /// authorization. Later purpose-specific actions still compare their real
    /// native history and owner cuts. Every earlier complete packet remains
    /// resident; the actual returned Source result must be parked in the loan.
    ///
    /// # Errors
    /// Retains a wrong phase, full bounded history, changed genuine Complete,
    /// Source/floor, original peer, startup or original cutoff.
    pub fn read_current_gen1_refresh(
        &mut self,
    ) -> Result<RootCreateQ04SourceObservationLoanV1<'_, 'startup>, ()> {
        let prepared = self.prepare_source_observation(RootSourceObservationPurposeV1::Refresh);
        let (project, challenge, context) = self.retain_outcome(prepared)?;
        self.source_observation_loan(project, challenge, context, RootSourceObservationPurposeV1::Refresh)
    }

    fn prepare_source_observation(
        &mut self,
        purpose: RootSourceObservationPurposeV1,
    ) -> Result<(
        aos_sandbox_core::ProjectId,
        SourceTreeGenesisChallengeV1,
        SourceTreeGenesisIntentContextV1,
    ), CreateQ04ErrorV1> {
        let expected = match purpose {
            RootSourceObservationPurposeV1::Preparation => RootQ04PreludePhaseV1::Hello,
            RootSourceObservationPurposeV1::Completion => RootQ04PreludePhaseV1::Anchored,
            RootSourceObservationPurposeV1::Refresh => {
                if self.refresh_resume.is_some() || !matches!(self.phase,
                    RootQ04PreludePhaseV1::Preview | RootQ04PreludePhaseV1::Prefunded
                    | RootQ04PreludePhaseV1::Decided | RootQ04PreludePhaseV1::PolicyAcknowledged
                    | RootQ04PreludePhaseV1::ReleaseAuthorized | RootQ04PreludePhaseV1::Settled
                    | RootQ04PreludePhaseV1::FinalClearance)
                {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
                self.refresh_resume = Some(self.phase);
                self.phase
            }
        };
        if self.phase != expected
            || self.source_received.is_some()
            || self.source_observations.len() >= MAXIMUM_SOURCE_OBSERVATIONS
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        // Reserve before the RPC: moving its returned fixed packet later is
        // infallible. This is bounded storage, not a heap/kernel funding claim.
        self.source_observations.try_reserve_exact(1)?;
        if matches!(purpose, RootSourceObservationPurposeV1::Completion) {
            if !self.controller_complete.is_empty() || !self.source_complete.is_empty() {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            let bytes = if self.floor.as_ref().is_some_and(|floor| floor.receipt().auth_packet().len() == 400) {
                super::super::SOURCE_TREE_GENESIS_READBACK_BYTES_V2
            } else {
                SOURCE_TREE_GENESIS_READBACK_BYTES_V1
            };
            self.source_complete.try_reserve_exact(bytes)?;
        }
        let slot = match purpose {
            RootSourceObservationPurposeV1::Preparation => RootControllerFrameSlotV1::Prepare,
            RootSourceObservationPurposeV1::Completion => RootControllerFrameSlotV1::Complete,
            RootSourceObservationPurposeV1::Refresh => {
                if self.refresh_frames.len() >= MAXIMUM_SOURCE_OBSERVATIONS - 2
                    || super::require_genesis_observation_pair_widths(
                        &self.controller_complete, &self.source_complete,
                    ).is_err()
                {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
                self.refresh_frames.try_reserve_exact(1)?;
                // The new partial buffer is owned before the first receive.
                self.refresh_frames.push(Vec::new());
                RootControllerFrameSlotV1::Refresh
            }
        };
        self.receive_original_genesis_frame(slot)?;
        self.recheck_original()?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let packet = match purpose {
            RootSourceObservationPurposeV1::Preparation => decode_root_source_genesis_frame_v2(
                &self.controller_frame, RootSourceGenesisFrameKindV1::Prepare, root.nonce(),
            )?,
            RootSourceObservationPurposeV1::Completion => decode_root_source_genesis_frame_v2(
                &self.completion_frame, RootSourceGenesisFrameKindV1::Complete, root.nonce(),
            )?,
            RootSourceObservationPurposeV1::Refresh => decode_root_create_q04_transfer_v1(
                self.refresh_frames.last().ok_or(CreateQ04ErrorV1::ChangedCut)?,
                RootCreateQ04TransferKindV1::SourceRefresh, root.nonce(),
            )?,
        };
        let (project, challenge) = root.accept_historical_controller_readback(packet)?
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let project = project.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        // Reuse the same original intent/floor projection. A historical
        // acceptance without an actual settled floor is not this purpose.
        let context = root.source_genesis_intent_context_v1()?;
        root.q04_require_existing_completed_floor(project)?;
        if !matches!(purpose, RootSourceObservationPurposeV1::Preparation) {
            root.q04_require_completed_controller_packet()?;
            if matches!(purpose, RootSourceObservationPurposeV1::Completion) {
                self.controller_complete.try_reserve_exact(packet.len())?;
            }
            // The complete original frame is still in its own retained slot.
            // Replacing this current view cannot discard any earlier packet.
            self.controller_complete.clear();
            self.controller_complete.extend_from_slice(packet);
        }
        self.recheck_original()?;
        Ok((project, challenge, context))
    }

    fn source_observation_loan(
        &mut self,
        project: aos_sandbox_core::ProjectId,
        challenge: SourceTreeGenesisChallengeV1,
        context: SourceTreeGenesisIntentContextV1,
        purpose: RootSourceObservationPurposeV1,
    ) -> Result<RootCreateQ04SourceObservationLoanV1<'_, 'startup>, ()> {
        let resource_posts = if context.has_resource_authorization() {
            if self.cause.borrow().is_some() || self.postcheck_debt.borrow().is_some()
                || self.source_resource_posts.len() >= MAXIMUM_SOURCE_OBSERVATIONS {
                self.cause.borrow_mut().get_or_insert(CreateQ04ErrorV1::ChangedCut);
                return Err(());
            }
            if self.source_resource_posts.try_reserve_exact(1).map_err(|error| {
                self.cause.borrow_mut().get_or_insert(error.into());
            }).is_err() {
                return Err(());
            }
            self.source_resource_posts.push(RootResourceSourcePostsV2::default());
            self.source_resource_posts.last_mut()
        } else {
            None
        };
        // All slot checks preceded the potentially effectful RPC. The loan
        // contains disjoint original borrows, not a self-reference or getter.
        let (Some(startup), Some(root), Some(state), Some(stream), Some(peer), Some(clock), Some(started)) = (
            self.startup, self.root.as_mut(), self.state.as_ref(), self.stream.as_ref(),
            self.peer.as_ref(), self.clock, self.started,
        ) else {
            self.cause.borrow_mut().get_or_insert(CreateQ04ErrorV1::ChangedCut);
            return Err(());
        };
        Ok(RootCreateQ04SourceObservationLoanV1 {
            root,
            original: RootOriginalInputLoanV1 {
                startup, stream, peer, state, clock, started, cause: &self.cause,
            },
            project,
            challenge,
            context,
            purpose,
            received: &mut self.source_received,
            observations: &mut self.source_observations,
            resource_posts,
            source_complete: &mut self.source_complete,
            controller_complete: &self.controller_complete,
            floor: &mut self.floor,
            phase: &mut self.phase,
            postcheck_debt: &self.postcheck_debt,
            finished: false,
        })
    }

    /// Sends the actual existing semantic floor on this same held stream.
    ///
    /// # Errors
    /// Retains missing Source observation, replaced floor or transport/cutoff.
    pub fn send_existing_anchor(&mut self) -> Result<(), ()> {
        let outcome = self.send_original_existing_anchor();
        self.retain_outcome(outcome)
    }

    fn send_original_existing_anchor(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::PreparedSource {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck_original()?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let source = self.source_observations.last().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let floor = root.recover_floor(Some(source.as_ref()))?
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if self.floor.as_ref() != Some(&floor) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.sent = encode_root_source_genesis_frame_v2(
            RootSourceGenesisFrameKindV1::Anchored, root.nonce(), floor.record_bytes(),
        )?;
        self.write_original(&self.sent)?;
        self.phase = RootQ04PreludePhaseV1::Anchored;
        Ok(())
    }

    /// Confirms current gen1 and returns Root's exact original Source packet.
    ///
    /// # Errors
    /// Retains changed durable Complete/Source ACK/floor or original I/O.
    /// This continuation does not accept ordinary genesis Finish or release Root.
    pub fn send_existing_completion(&mut self) -> Result<(), ()> {
        let outcome = self.send_original_existing_completion();
        self.retain_outcome(outcome)
    }

    fn send_original_existing_completion(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::CompletedSource {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck_original()?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let current = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        current.recheck()?;
        if self.floor.as_ref() != Some(current.floor()) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let digest = current.floor().digest();
        drop(current);
        self.sent = encode_root_source_genesis_frame_v2(
            RootSourceGenesisFrameKindV1::Completed, root.nonce(), digest.as_bytes(),
        )?;
        self.write_original(&self.sent)?;
        self.sent.clear();
        encode_root_create_q04_transfer_v1(
            &mut self.sent, RootCreateQ04TransferKindV1::SourceObservation,
            self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.nonce(),
            &self.source_complete,
        )?;
        self.write_original(&self.sent)?;
        self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?.recheck()?;
        self.recheck_original()?;
        self.phase = RootQ04PreludePhaseV1::Completed;
        Ok(())
    }

    /// Sends only the latest genuine Root-returned Source observation.
    ///
    /// # Errors
    /// Retains mismatched current gen1/Complete/Source, changed floor or
    /// original transport/owner/cutoff. This does not advance durable Q04 phase.
    pub fn send_current_gen1_refresh(&mut self) -> Result<(), ()> {
        let outcome = self.send_original_current_gen1_refresh();
        self.retain_outcome(outcome)
    }

    fn send_original_current_gen1_refresh(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::RefreshedSource || self.refresh_frames.is_empty() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck_original()?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let current = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        current.recheck()?;
        if self.floor.as_ref() != Some(current.floor()) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        drop(current);
        let nonce = root.nonce();
        self.sent.clear();
        encode_root_create_q04_transfer_v1(
            &mut self.sent, RootCreateQ04TransferKindV1::SourceObservation, nonce, &self.source_complete,
        )?;
        self.write_original(&self.sent)?;
        self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?.recheck()?;
        self.recheck_original()?;
        self.phase = self.refresh_resume.take().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        Ok(())
    }

    /// Sends authentic nonissuing input DATA under the same existing gen1 cut.
    ///
    /// The bytes and role keys come from the daemon's retained fixed input
    /// credentials. The original Root writer independently compares its own
    /// signed heads/pins and reserves its nonce/Stage recipe without appending.
    /// This does not establish a logical hold, publication or funded suffix.
    ///
    /// # Errors
    /// Retains missing/changed fixed sources, unavailable original Stage base,
    /// malformed canonical Preview, buffer failure or original transport loss.
    #[allow(clippy::too_many_arguments)]
    pub fn send_nonissuing_preview(
        &mut self,
        deployment_packet: &[u8],
        deployment_signer_generation: u64,
        deployment_key: &ed25519_dalek::VerifyingKey,
        project_source: Option<(&[u8], &[u8])>,
        project_signer_generation: u64,
        project_key: &ed25519_dalek::VerifyingKey,
        inputs: &PolicyDeploymentInputsV1<'_>,
    ) -> Result<(), ()> {
        let outcome = match project_source {
            Some((project_packet, project_input)) => self.send_original_nonissuing_preview(
                deployment_packet, deployment_signer_generation, deployment_key,
                project_packet, project_input, project_signer_generation, project_key, inputs,
            ),
            None => Err(CreateQ04ErrorV1::ChangedCut),
        };
        self.retain_outcome(outcome)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_original_nonissuing_preview(
        &mut self,
        deployment_packet: &[u8],
        deployment_signer_generation: u64,
        deployment_key: &ed25519_dalek::VerifyingKey,
        project_packet: &[u8],
        project_input: &[u8],
        project_signer_generation: u64,
        project_key: &ed25519_dalek::VerifyingKey,
        inputs: &PolicyDeploymentInputsV1<'_>,
    ) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::Completed
            || self.stage.is_some()
            || !self.preview.is_empty()
            || !self.preview_chunk.is_empty()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck_original()?;
        let now = self.current_original_clock()?.wall_seconds();
        let original = self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let nonce = root.nonce();
        self.stage = Some(root.q04_preview_stage(
            &self.source_complete, deployment_packet, deployment_signer_generation, deployment_key,
            project_packet, project_input, project_signer_generation, project_key,
            self.identities.controller_gid, now,
        )?);
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        root.q04_encode_preview(&mut self.preview, stage, inputs, project_input, original, now)?;
        self.recheck_original()?;

        let preview = super::Q04PreviewV1::decode(&self.preview, nonce)?;
        let transfer = super::Q04PreviewTransferRecipeV1::new(&preview)?;
        self.sent.clear();
        encode_root_create_q04_transfer_v1(
            &mut self.sent, RootCreateQ04TransferKindV1::PreviewIndex, nonce, transfer.index_bytes(),
        )?;
        self.write_original(&self.sent)?;
        for index in 0..transfer.chunk_count() {
            transfer.encode_chunk(index, &mut self.preview_chunk)?;
            self.sent.clear();
            encode_root_create_q04_transfer_v1(
                &mut self.sent, RootCreateQ04TransferKindV1::PreviewChunk, nonce, &self.preview_chunk,
            )?;
            self.write_original(&self.sent)?;
            self.preview_chunk.clear();
        }
        self.recheck_original()?;
        self.phase = RootQ04PreludePhaseV1::Preview;
        Ok(())
    }

    fn receive_original_exact(
        &mut self,
        length: usize,
        slot: RootControllerFrameSlotV1,
    ) -> Result<(), CreateQ04ErrorV1> {
        self.receive_original_exact_with_header(length, slot, false)
    }

    fn receive_original_genesis_frame(
        &mut self, slot: RootControllerFrameSlotV1,
    ) -> Result<(), CreateQ04ErrorV1> {
        let length = ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1
            + super::super::source_genesis_root::CONTROLLER_SOURCE_GENESIS_READBACK_BYTES_V1;
        self.receive_original_exact_with_header(length, slot, true)
    }

    fn receive_original_exact_with_header(
        &mut self,
        mut length: usize,
        slot: RootControllerFrameSlotV1,
        mut genesis_header: bool,
    ) -> Result<(), CreateQ04ErrorV1> {
        if length == 0 || length > 4096 || self.received.is_some()
            || !self.controller_frame_buffer(slot)?.is_empty()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.controller_frame_buffer_mut(slot)?.try_reserve_exact(length)?;
        loop {
            let copied = self.controller_frame_buffer(slot)?.len();
            if copied == length {
                if !genesis_header { break; }
                // This is the old fixed receive's final owner/clock post.
                // Even malformed sizing DATA cannot move ahead of that post.
                self.recheck_original()?;
                // The original legacy receive/allocation schedule finishes
                // before DATA framing can select the resource-only extension.
                let header = &self.controller_frame_buffer(slot)?[..ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1];
                let resource_version = match slot {
                    RootControllerFrameSlotV1::Refresh => [0, 3],
                    _ => [0, 2],
                };
                if header[8..10] != resource_version {
                    return Ok(());
                }
                let nonce = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.nonce();
                let payload_bytes = match slot {
                    RootControllerFrameSlotV1::Prepare => super::super::source_genesis_root::strict_genesis_payload_bytes_from_header(
                        header, RootSourceGenesisFrameKindV1::Prepare, nonce,
                    ).map_err(CreateQ04ErrorV1::from),
                    RootControllerFrameSlotV1::Complete => super::super::source_genesis_root::strict_genesis_payload_bytes_from_header(
                        header, RootSourceGenesisFrameKindV1::Complete, nonce,
                    ).map_err(CreateQ04ErrorV1::from),
                    RootControllerFrameSlotV1::Refresh => super::super::source_genesis_root::q04_genesis_refresh_payload_bytes_from_header(header, nonce),
                    _ => Err(CreateQ04ErrorV1::ChangedCut),
                }?;
                genesis_header = false;
                let complete_length = ROOT_SOURCE_GENESIS_FRAME_HEADER_BYTES_V1 + payload_bytes;
                if complete_length == length { return Ok(()); }
                if complete_length != length + 176 {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
                self.controller_frame_buffer_mut(slot)?.try_reserve_exact(176)?;
                length = complete_length;
            }
            self.recheck_original()?;
            self.received = Some(self.stream.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?
                .try_receive_subject_chunk_retaining(length - copied));
            let nonconsuming = self.received.as_ref().is_some_and(|result| result.as_ref()
                .is_err_and(|error| error.is_nonconsuming_would_block() || error.is_nonconsuming_interrupted()));
            if nonconsuming {
                self.received = None;
                self.wait_original(rustix::event::PollFlags::IN)?;
                continue;
            }
            if matches!(self.received, Some(Err(_))) {
                return match self.received.take() {
                    Some(Err(error)) => Err(error.into()),
                    returned => {
                        self.received = returned;
                        Err(CreateQ04ErrorV1::ChangedCut)
                    }
                };
            }
            let chunk = self.received.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let stream = self.stream.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
            self.peer.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.require_chunk(stream, chunk)?;
            if chunk.payload().is_empty() || chunk.payload().len() > length - copied {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            let output = match slot {
                RootControllerFrameSlotV1::Prepare => &mut self.controller_frame,
                RootControllerFrameSlotV1::Complete => &mut self.completion_frame,
                RootControllerFrameSlotV1::Refresh => self.refresh_frames.last_mut()
                    .ok_or(CreateQ04ErrorV1::ChangedCut)?,
                RootControllerFrameSlotV1::Prehold => &mut self.prehold_frame,
                RootControllerFrameSlotV1::Claim => &mut self.claim_frame,
                RootControllerFrameSlotV1::Acknowledgement => self.acknowledgement_frames.last_mut()
                    .ok_or(CreateQ04ErrorV1::ChangedCut)?,
            };
            output.extend_from_slice(chunk.payload());
            self.recheck_original()?;
            self.received = None;
        }
        self.recheck_original()
    }

    fn read_original_prehold_data(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::Preview
            || !self.prehold.is_empty() || !self.prehold_frame.is_empty()
            || self.prehold_plan.is_some() || self.controller_clock.is_some()
            || !self.refresh_frames.is_empty()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.receive_original_exact(32 + super::PREVIEW_INDEX_BYTES, RootControllerFrameSlotV1::Prehold)?;
        let nonce = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.nonce();
        let index = decode_root_create_q04_transfer_v1(
            &self.prehold_frame, RootCreateQ04TransferKindV1::PreholdIndex, nonce,
        )?;
        let (total, count) = super::prehold_index_shape(index)?;
        let original_index: [u8; super::PREVIEW_INDEX_BYTES] = index.try_into()
            .map_err(|_| CreateQ04ErrorV1::Bounds)?;
        self.prehold.try_reserve_exact(total)?;
        self.prehold_frame.clear();
        for number in 0..count {
            let offset = usize::from(number).checked_mul(super::CLAIM_CHUNK_BYTES)
                .ok_or(CreateQ04ErrorV1::Bounds)?;
            let payload = total.checked_sub(offset).ok_or(CreateQ04ErrorV1::Bounds)?
                .min(super::CLAIM_CHUNK_BYTES);
            self.receive_original_exact(
                32 + super::CLAIM_CHUNK_PREFIX_BYTES + payload, RootControllerFrameSlotV1::Prehold,
            )?;
            let bytes = decode_root_create_q04_transfer_v1(
                &self.prehold_frame, RootCreateQ04TransferKindV1::PreholdChunk, nonce,
            )?;
            super::Q04PreholdChunkV1::decode(bytes, &original_index)?.append_to(&mut self.prehold)?;
            self.recheck_original()?;
            self.prehold_frame.clear();
        }
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let current = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        let (request, _) = current.prehold_input(&self.prehold, stage)?;
        super::Q04PreholdTransferRecipeV1::verify_index(&original_index, &request)?;
        let origin: [u8; 32] = request.fields()[0][..32].try_into()
            .map_err(|_| CreateQ04ErrorV1::Bounds)?;
        current.recheck()?;
        drop(current);
        let clock = self.current_original_clock()?;
        let root_start = self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?.boottime_nanoseconds();
        if origin[..16] != clock.host_boot_id()
            || u64::from_be_bytes(super::fixed(&origin, 16)) > root_start
            || clock.boottime_nanoseconds() >= u64::from_be_bytes(super::fixed(&origin, 24))
        {
            return Err(CreateQ04ErrorV1::Expired);
        }
        // The authenticated client origin is adopted once. Every subsequent
        // slow owner check samples both original cuts; neither is renewed.
        self.controller_clock = Some(origin);
        self.recheck_original()
    }

    /// Preflights and returns nonissuing publication DATA on the original flight.
    ///
    /// Root checks its own complete eligible authority suffix and actual
    /// four-member policy-state recipe. This grants no reservation, logical
    /// hold, publication, effect or public Create outcome.
    ///
    /// # Errors
    /// Retains actual receive/compiler/native/send failures and separate final
    /// readback debt. A partial or late response cannot authorize a retry.
    pub fn prepare_publication_data(&mut self) -> Result<(), ()> {
        let returned = self.prepare_original_publication_data();
        if returned.is_err() {
            let _ = self.retain_outcome(returned);
            if let Err(debt) = self.recheck_original_owned() {
                self.postcheck_debt.get_mut().get_or_insert(debt);
            }
            return Err(());
        }
        self.retain_outcome(returned)
    }

    fn prepare_original_publication_data(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.prehold_reply.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.read_original_prehold_data()?;
        self.park_original_prehold_plan()?;

        let request = super::Q04PreholdInputDataV1::decode(&self.prehold)?;
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let preview = super::Q04PreviewV1::decode(&self.preview, stage.staged().challenge())?;
        let plan = self.prehold_plan.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        plan.authority_suffix.form(RootPreholdAuthorityInputV1 {
            identity: plan.identity.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            binding: &plan.compilation.data.binding,
            root_before: plan.root_before.2,
            root_sequence: plan.root_before.0,
            state_sequence: plan.state_before.0,
            claim_length: plan.claim_length,
            claim: None,
            held_pairs: None,
        }, stage, &request, &preview, &self.source_complete)?;

        // This Result is parked in the same original attempt before any
        // later source/name/clock check. A capacity shape is never committed.
        let returned = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_preflight_authority_suffix(plan.root_before, &plan.authority_suffix.transactions);
        plan.authority_suffix.preflight = Some(returned);
        match plan.authority_suffix.preflight.as_ref() {
            Some(Ok(())) => {}
            _ => {
                if let Some(Err(first)) = plan.authority_suffix.preflight.take() {
                    self.cause.get_mut().get_or_insert(first);
                }
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        self.require_prehold_originals()?;

        let reply = self.publication_data_reply()?;
        self.prehold_reply = Some(reply);
        self.sent.clear();
        encode_root_create_q04_transfer_v1(
            &mut self.sent, RootCreateQ04TransferKindV1::PreholdRecipe,
            self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.nonce(),
            self.prehold_reply.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.bytes(),
        )?;
        self.require_prehold_originals()?;
        self.write_original(&self.sent)?;
        self.require_prehold_originals()?;
        self.phase = RootQ04PreludePhaseV1::Prefunded;
        Ok(())
    }

    fn publication_data_reply(&self) -> Result<super::Q04PreholdPublicationDataV1, CreateQ04ErrorV1> {
        let plan = self.prehold_plan.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let identity = plan.identity.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if !plan.authority_suffix.complete || !matches!(plan.authority_suffix.preflight.as_ref(), Some(Ok(()))) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let request = super::Q04PreholdInputDataV1::decode(&self.prehold)?;
        let mut body = [0; super::PREHOLD_RESPONSE_BYTES];
        body[16..32].copy_from_slice(&identity.nonce());
        body[32..64].copy_from_slice(request.digest().as_bytes());
        body[64..96].copy_from_slice(plan.original_precut.as_bytes());
        body[96..128].copy_from_slice(plan.policy_before.as_bytes());
        body[128..144].copy_from_slice(&identity.stage_id());
        body[144..160].copy_from_slice(&identity.publication_id());
        body[160..192].copy_from_slice(plan.capacity.transaction_digest().as_bytes());
        body[192..224].copy_from_slice(plan.capacity.current_envelope_digest().as_bytes());
        body[224..256].copy_from_slice(plan.independent_recipe.as_bytes());
        body[256..288].copy_from_slice(plan.root_before.2.as_bytes());
        body[288..320].copy_from_slice(plan.compilation.before_controller.as_bytes());
        body[320..352].copy_from_slice(identity.gen1_floor().as_bytes());
        body[352..384].copy_from_slice(identity.ancestry().as_bytes());
        body[384..392].copy_from_slice(&plan.root_before.0.to_be_bytes());
        body[392..400].copy_from_slice(&plan.state_before.0.to_be_bytes());
        body[400..448].copy_from_slice(&plan.state_before.1.to_bytes());
        body[448..452].copy_from_slice(&u32::try_from(plan.claim_length)
            .map_err(|_| CreateQ04ErrorV1::Bounds)?.to_be_bytes());
        let count = super::claim_chunk_count(plan.claim_length)?;
        body[452..454].copy_from_slice(&count.to_be_bytes());
        body[454..456].copy_from_slice(&(count.checked_add(127)
            .ok_or(CreateQ04ErrorV1::Bounds)? / 128).to_be_bytes());

        // The adapter's sole S::order recipe is Candidate/Diagnostics/Effect/
        // Current. These are actual durable members, not reducer-body widths.
        let members = plan.capacity.journal_records();
        if members.len() != 4 {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        for (index, member) in members.iter().enumerate() {
            let length = u32::try_from(member.value().ok_or(CreateQ04ErrorV1::ChangedCut)?.len())
                .map_err(|_| CreateQ04ErrorV1::Bounds)?;
            let start = 456 + index * 4;
            body[start..start + 4].copy_from_slice(&length.to_be_bytes());
        }
        super::Q04PreholdPublicationDataV1::from_body(body, identity.nonce())
            .map_err(CreateQ04ErrorV1::from)
    }

    fn require_prehold_originals(&mut self) -> Result<(), CreateQ04ErrorV1> {
        self.recheck_original()?;
        let plan = self.prehold_plan.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if self.state.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.q04_root_before_rows_v1()?
                != plan.state_before
            || self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.q04_before_rows()?
                != plan.root_before
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let gen1 = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        let (request, controller) = gen1.prehold_input(&self.prehold, stage)?;
        let original = RootOriginalInputLoanV1 {
            startup: self.startup.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            stream: self.stream.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            peer: self.peer.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            state: self.state.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            clock: self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            started: self.started.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            cause: &self.cause,
        };
        let now = original.recheck()?.wall_seconds();
        let preview = super::Q04PreviewV1::decode(&self.preview, stage.staged().challenge())?;
        let fields = preview.fields();
        let deployment_inputs = PolicyDeploymentInputsV1 {
            node: fields[3], site: fields[4], backend: fields[5], catalogs: fields[6],
        };
        let (project, deployment_head, _) = gen1.signed_project_sources(fields[8], &deployment_inputs, now)?;
        let current = RootCurrentInputVerifierV1 {
            original: RootCurrentOwnerLoanV1::Input(original), gen1: &gen1, stage, controller, project: &project,
            deployment_head, project_input: fields[8], deployment_inputs,
            controller_packet: request.fields()[5], proposed: request.fields()[4],
            purpose: RootInputCurrentPurposeV1::Prehold { request_packet: &self.prehold },
        };
        current.recheck()?;
        if controller != plan.compilation.controller
            || gen1.floor().digest() != plan.gen1_floor
            || gen1.floor().tree_head() != plan.compilation.data.prerequisites.ancestry_head()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        drop(current);
        drop(gen1);
        self.recheck_original()
    }

    // The actual plan is parked before any post-adapter named/native/clock
    // checks. There is still no DATA reply until Root's complete eligible
    // authority suffix also passes its same original Journal preflight.
    fn park_original_prehold_plan(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.prehold_plan.is_some() || self.prehold.is_empty() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let returned = self.form_original_prehold_plan();
        self.prehold_plan = Some(returned);
        if matches!(self.prehold_plan, Some(Err(_))) {
            match self.prehold_plan.take() {
                Some(Err(first)) => {
                    self.cause.get_mut().get_or_insert(first);
                }
                original => {
                    self.prehold_plan = original;
                    self.cause.get_mut().get_or_insert(CreateQ04ErrorV1::ChangedCut);
                }
            }
            if let Err(debt) = self.recheck_original_owned() {
                self.postcheck_debt.get_mut().get_or_insert(debt);
            }
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let plan = self.prehold_plan.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let identity = self.prehold_identity(
            &plan.compilation, &plan.capacity, plan.capacity.transaction_id(),
            plan.original_precut, plan.root_before.2, plan.gen1_floor,
            plan.compilation.data.prerequisites.ancestry_head(),
        )?;
        self.prehold_plan.as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?.identity = Some(identity);
        let plan = self.prehold_plan.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if self.state.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.q04_root_before_rows_v1()?
                != plan.state_before
            || self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.q04_before_rows()?
                != plan.root_before
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let gen1 = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        let (_, controller) = gen1.prehold_input(
            &self.prehold, self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
        )?;
        if controller != plan.compilation.controller
            || gen1.floor().digest() != plan.identity.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.gen1_floor()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        gen1.recheck()?;
        drop(gen1);
        self.recheck_original()
    }

    fn form_original_prehold_plan(&mut self) -> Result<RootPreholdPublicationPlanV1, CreateQ04ErrorV1> {
        self.recheck_original()?;
        // Capture the original actual state before borrowing its adapter.
        // Its complete retained rows count toward every native bound.
        let state_before = self.state.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_root_before_rows_v1()?;
        let root_before = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_before_rows()?;
        let compilation = self.reconstruct_prehold_input()?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let nonce = root.nonce();
        let gen1 = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        let floor = gen1.floor().digest();
        let ancestry = gen1.floor().tree_head();
        gen1.recheck()?;
        drop(gen1);
        let request = super::Q04PreholdInputDataV1::decode(&self.prehold)?;
        let preview = super::Q04PreviewV1::decode(&self.preview, nonce)?;
        let root_metadata = preview.fields()[0];
        if root_metadata[32..40] != root_before.0.to_be_bytes()
            || root_metadata[40..88] != root_before.1.to_bytes()
            || root_metadata[88..120] != *root_before.2.as_bytes()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let original_precut = super::q04_original_precut_digest_v1(
            &request, &preview, &self.controller_complete, &self.source_complete,
            state_before.1, state_before.0,
        )?;
        let request_fields = request.fields();
        let preview_fields = preview.fields();
        let claim_length = request_fields[1..4].iter()
            .chain(preview_fields[3..7].iter())
            .chain(std::iter::once(&preview_fields[8]))
            .try_fold(2504_usize + self.source_complete.len(), |sum, field| sum.checked_add(field.len()).ok_or(CreateQ04ErrorV1::Bounds))?;
        if claim_length > super::MAXIMUM_CLAIM_BYTES {
            return Err(CreateQ04ErrorV1::Bounds);
        }

        let state = self.state.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let adapter = super::super::PolicyCompilerProtectedJournalV1::claim(
            state, compilation.validator.clone(),
        )?;
        let recipe = adapter.q04_independent_recipe(
            &compilation.data.input, &compilation.data.candidate, &compilation.data.prerequisites,
        )?;
        let policy_before = recipe.before_digest();
        let independent_recipe = recipe.recipe_digest();
        let seed = super::q04_publication_precut_seed_v1(
            original_precut, root_before.2, compilation.before_controller, floor, ancestry, policy_before,
        )?;
        let publication = recipe.initial_transaction_id(seed, nonce)?;
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if publication == *stage.transaction().id() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let returned = adapter.q04_capacity_plan(
            publication, recipe, &compilation.data.input,
            &compilation.data.candidate, &compilation.data.prerequisites,
        );
        // End this actual mutable adapter loan before the caller's original
        // named/native/sequence/gen1/clock bookends. No Journal getter is used.
        drop(adapter);
        let capacity = returned?;
        Ok(RootPreholdPublicationPlanV1 {
            compilation, capacity, identity: None, state_before, root_before,
            original_precut, policy_before, independent_recipe, gen1_floor: floor, claim_length,
            authority_suffix: RootPreholdAuthoritySuffixV1::default(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn prehold_identity(
        &self,
        compilation: &RootPreholdCompilationV1,
        capacity: &super::super::protected_journal::Q04PublicationCapacityV1,
        publication: [u8; 16],
        original_precut: ObjectDigest,
        root_before: ObjectDigest,
        floor: ObjectDigest,
        ancestry: ObjectDigest,
    ) -> Result<Q04CutIdentityV1, CreateQ04ErrorV1> {
        let request = super::Q04PreholdInputDataV1::decode(&self.prehold)?;
        let metadata = request.fields()[0];
        let root = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let original = self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let digests = [
            compilation.operation_revision, compilation.desired_precondition, compilation.effect_plan,
            compilation.before_controller, floor, ancestry, original_precut,
            super::super::closed_policy_binding_digest_v2(&compilation.data.binding)?,
            compilation.data.normalized,
            compilation.data.candidate.commitment().digest(), capacity.transaction_digest(),
            capacity.current_envelope_digest(), ObjectDigest::from_bytes(super::fixed(metadata, 144)), root_before,
        ];
        super::encode_q04_cut_recipe_v1(super::Q04CutRecipeV1 {
            nonce: root.nonce(),
            project: compilation.controller.project(),
            operation: compilation.controller.operation(),
            sandbox: compilation.controller.sandbox(),
            controller_uid: self.identities.controller_uid,
            source_uid: self.identities.source_uid,
            controller_metadata: metadata,
            root_boot: original.host_boot_id(),
            root_started: original.boottime_nanoseconds(),
            handoff_epoch: stage.staged().base().next_generation(),
            stage: *stage.transaction().id(),
            publication,
            digests,
        })
    }

    fn controller_frame_buffer(&self, slot: RootControllerFrameSlotV1) -> Result<&Vec<u8>, CreateQ04ErrorV1> {
        match slot {
            RootControllerFrameSlotV1::Prepare => Ok(&self.controller_frame),
            RootControllerFrameSlotV1::Complete => Ok(&self.completion_frame),
            RootControllerFrameSlotV1::Refresh => self.refresh_frames.last().ok_or(CreateQ04ErrorV1::ChangedCut),
            RootControllerFrameSlotV1::Prehold => Ok(&self.prehold_frame),
            RootControllerFrameSlotV1::Claim => Ok(&self.claim_frame),
            RootControllerFrameSlotV1::Acknowledgement => self.acknowledgement_frames.last()
                .ok_or(CreateQ04ErrorV1::ChangedCut),
        }
    }

    fn controller_frame_buffer_mut(&mut self, slot: RootControllerFrameSlotV1) -> Result<&mut Vec<u8>, CreateQ04ErrorV1> {
        match slot {
            RootControllerFrameSlotV1::Prepare => Ok(&mut self.controller_frame),
            RootControllerFrameSlotV1::Complete => Ok(&mut self.completion_frame),
            RootControllerFrameSlotV1::Refresh => self.refresh_frames.last_mut().ok_or(CreateQ04ErrorV1::ChangedCut),
            RootControllerFrameSlotV1::Prehold => Ok(&mut self.prehold_frame),
            RootControllerFrameSlotV1::Claim => Ok(&mut self.claim_frame),
            RootControllerFrameSlotV1::Acknowledgement => self.acknowledgement_frames.last_mut()
                .ok_or(CreateQ04ErrorV1::ChangedCut),
        }
    }

    fn wait_original(&self, interest: rustix::event::PollFlags) -> Result<(), CreateQ04ErrorV1> {
        self.recheck_original()?;
        let stream = self.stream.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let started = self.started.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        wait_original_root_v1(stream.as_fd(), interest, started + MAXIMUM_ROOT_FLIGHT)?;
        self.recheck_original()
    }

    fn write_original(&self, bytes: &[u8]) -> Result<(), CreateQ04ErrorV1> {
        if bytes.is_empty() || bytes.len() > 4096 || self.send_result.borrow().is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.sent_progress.set(0);
        while self.sent_progress.get() < bytes.len() {
            self.recheck_original()?;
            let stream = self.stream.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
            *self.send_result.borrow_mut() = Some(rustix::net::send(
                stream.as_fd(), &bytes[self.sent_progress.get()..],
                rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
            ));
            let returned = self.send_result.borrow().as_ref().copied()
                .ok_or(CreateQ04ErrorV1::ChangedCut)?;
            match returned {
                Ok(0) => return Err(CreateQ04ErrorV1::ChangedCut),
                Ok(count) => self.sent_progress.set(self.sent_progress.get()
                    .checked_add(count).filter(|total| *total <= bytes.len())
                    .ok_or(CreateQ04ErrorV1::ChangedCut)?),
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {
                    *self.send_result.borrow_mut() = None;
                    self.wait_original(rustix::event::PollFlags::OUT)?;
                    continue;
                }
                Err(error) => return Err(std::io::Error::from(error).into()),
            }
            self.recheck_original()?;
            *self.send_result.borrow_mut() = None;
        }
        self.recheck_original()
    }

    fn admit(&mut self) -> Result<(), ()> {
        let outcome = self.admit_original();
        self.retain_outcome(outcome)
    }

    fn admit_original(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.cause.borrow().is_some()
            || self.started.is_some()
            || self.clock.is_some()
            || self.stream.is_some()
            || self.root.is_some()
            || self.state.is_some()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        if self.identities.controller_uid == 0
            || self.identities.controller_gid == 0
            || self.identities.source_uid == 0
            || self.identities.cache_uid == 0
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.started = Some(Instant::now());
        self.clock = Some(original_root_kernel_pair_v1()?);
        self.startup.ok_or(CreateQ04ErrorV1::ChangedCut)?.recheck()?;

        // The original std owner remains parked if adoption of the same OFD's
        // CLOEXEC duplicate fails. This creates no second socket/connection.
        let duplicate = rustix::io::fcntl_dupfd_cloexec(&self.original, 0)
            .map_err(std::io::Error::from)?;
        self.stream = Some(RetainedUnixStream::from_owned(duplicate)?);
        let stream = self.stream.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        stream.enable_subject_reporting()?;
        let peer = self.startup.ok_or(CreateQ04ErrorV1::ChangedCut)?.observe_controller_policy_peer(stream)?;
        if stream.peer().credentials().uid() != self.identities.controller_uid
            || stream.peer().credentials().gid() != self.identities.controller_gid
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.peer = Some(peer);
        self.recheck_original()?;

        // Root opens last. This is the same authority journal used by gen1
        // and binding CAS, not the ordinary compiler owner's second opener.
        self.root = Some(RootSourceGenesisAuthorityV1::open_fixed(
            self.identities.controller_uid,
            self.identities.source_uid,
        )?);
        self.recheck_original()?;
        let (state, _) = Journal::open_protected_at(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_STATE_JOURNAL,
            policy_state_journal_limits(),
        )?;
        self.state = Some(state);
        self.recheck_original()
    }

    fn recheck_original(&self) -> Result<(), CreateQ04ErrorV1> {
        if self.cause.borrow().is_some() || self.postcheck_debt.borrow().is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck_original_owned()
    }

    fn recheck_original_owned(&self) -> Result<(), CreateQ04ErrorV1> {
        self.startup.ok_or(CreateQ04ErrorV1::ChangedCut)?.recheck()?;
        let stream = self.stream.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let peer = self.peer.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        peer.recheck_stream(stream)?;
        require_open_receive_queue(stream.as_fd())?;
        if let Some(root) = &self.root {
            root.recheck()?;
        }
        if let Some(state) = &self.state {
            state.require_protected_named_location(
                Path::new(PROTECTED_POLICY_ROOT),
                POLICY_STATE_JOURNAL,
                0,
                policy_state_journal_limits(),
            )?;
        }
        let current = self.current_original_clock()?;
        if let Some(origin) = &self.controller_clock {
            if origin[..16] != current.host_boot_id()
                || current.boottime_nanoseconds() >= u64::from_be_bytes(super::fixed(origin, 24))
            {
                return Err(CreateQ04ErrorV1::Expired);
            }
        }
        Ok(())
    }

    // Sample after all potentially slow owner checks. Neither the monotonic
    // cut nor its paired BOOTTIME/wall/boot origin is renewed at a phase.
    fn current_original_clock(&self) -> Result<RawPairedClockSample, CreateQ04ErrorV1> {
        let original = self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let started = self.started.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        recheck_original_clock(original, started)
    }

    fn require_identity_clock(&self, identity: &Q04CutIdentityV1) -> Result<(), CreateQ04ErrorV1> {
        self.recheck_original()?;
        let original = self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if identity.bytes()[112..128] != original.host_boot_id()
            || identity.bytes()[144..152] != original.boottime_nanoseconds().to_be_bytes()
            || identity.controller_uid() != self.identities.controller_uid
            || identity.bytes()[84..88] != self.identities.source_uid.to_be_bytes()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.current_original_clock()?;
        Ok(())
    }

    /// Retains the exact authenticated held Claim on this original stream.
    ///
    /// This only reconstructs and compares input DATA under genuine current
    /// Controller/Source/Cache/Root loans. No Stage, publication or decision is
    /// committed by receiving it.
    ///
    /// # Errors
    /// Retains incomplete chunks, original subjects, canonical/signature/model
    /// failures and final readback debt. Failure never permits retry or release.
    pub fn receive_held_claim(&mut self) -> Result<(), ()> {
        let returned = self.receive_original_held_claim();
        if returned.is_err() {
            let _ = self.retain_outcome(returned);
            if let Err(debt) = self.recheck_original_owned() {
                self.postcheck_debt.get_mut().get_or_insert(debt);
            }
            return Err(());
        }
        self.retain_outcome(returned)
    }

    fn receive_original_held_claim(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::Prefunded || !self.claim.is_empty()
            || !self.claim_frame.is_empty() || self.held_compilation.is_some()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let plan = self.prehold_plan.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        // This fixed canonical copy is comparison DATA, not a cloned owner,
        // floor loan, current packet or authority. Original owners recheck at
        // every receive and again before authentication below.
        let identity = plan.identity.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.clone();
        let claim_length = plan.claim_length;
        self.require_identity_clock(&identity)?;
        self.receive_original_exact(32 + super::CLAIM_INDEX_BYTES, RootControllerFrameSlotV1::Claim)?;
        let bytes = decode_root_create_q04_transfer_v1(
            &self.claim_frame, RootCreateQ04TransferKindV1::ClaimIndex, identity.nonce(),
        )?;
        let (total, count) = super::claim_index_shape(bytes, &identity)?;
        if total != claim_length {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let index: [u8; super::CLAIM_INDEX_BYTES] = bytes.try_into().map_err(|_| CreateQ04ErrorV1::Bounds)?;
        self.claim.try_reserve_exact(total)?;
        self.claim_frame.clear();
        for chunk in 0..count {
            let offset = usize::from(chunk).checked_mul(super::CLAIM_CHUNK_BYTES)
                .ok_or(CreateQ04ErrorV1::Bounds)?;
            let length = total.checked_sub(offset).ok_or(CreateQ04ErrorV1::Bounds)?
                .min(super::CLAIM_CHUNK_BYTES);
            self.receive_original_exact(32 + super::CLAIM_CHUNK_PREFIX_BYTES + length,
                RootControllerFrameSlotV1::Claim)?;
            let bytes = decode_root_create_q04_transfer_v1(
                &self.claim_frame, RootCreateQ04TransferKindV1::ClaimChunk, identity.nonce(),
            )?;
            super::Q04ClaimChunkV1::decode(bytes, &index, &identity)?.append_to(&mut self.claim)?;
            self.require_identity_clock(&identity)?;
            self.claim_frame.clear();
        }
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let gen1 = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        let claim = gen1.verify_claim(&self.claim, &identity)?;
        super::Q04ClaimStorageRecipeV1::verify_index(&index, &claim, &identity)?;
        let request = super::Q04PreholdInputDataV1::decode(&self.prehold)?;
        let preview = super::Q04PreviewV1::decode(&self.preview, identity.nonce())?;
        let original = request.fields();
        let signed = preview.fields();
        let fields = claim.fields();
        if fields[..3] != original[1..4] || fields[3..7] != signed[3..7]
            || fields[7] != signed[8] || fields[8] != original[4]
            || fields[11] != self.source_complete.as_slice()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        gen1.recheck()?;
        drop(gen1);
        self.claim_source_observation = Some(self.source_observations.len().checked_sub(1)
            .ok_or(CreateQ04ErrorV1::ChangedCut)?);
        if self.source_observations.get(self.claim_source_observation
            .ok_or(CreateQ04ErrorV1::ChangedCut)?).map(|packet| packet.as_ref())
            != Some(self.source_complete.as_slice())
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }

        let returned = self.reconstruct_original_input();
        self.held_compilation = Some(returned);
        let (Some(Ok(held)), Some(Ok(plan))) = (&self.held_compilation, &self.prehold_plan) else {
            if let Some(Err(first)) = self.held_compilation.take() {
                self.cause.get_mut().get_or_insert(first);
            }
            return Err(CreateQ04ErrorV1::ChangedCut);
        };
        if held.binding != plan.compilation.data.binding
            || held.normalized != plan.compilation.data.normalized
            || held.candidate.commitment() != plan.compilation.data.candidate.commitment()
            || held.prerequisites != plan.compilation.data.prerequisites
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.require_identity_clock(&identity)
    }

    /// Commits only the actual Claim, reserved Stage, and held Root binding.
    ///
    /// Every append uses this original flight and the same native journal
    /// engine. This prefix is not an executed qualification gate, a policy
    /// decision, Controller clearance, or a successful public Create.
    ///
    /// # Errors
    /// Retains the original append outcome and first typed cause before any
    /// later native, name, floor or clock check. No failed prefix is retried.
    pub fn commit_held_root_binding(&mut self) -> Result<(), ()> {
        let returned = self.commit_original_binding_prefix();
        if returned.is_err() {
            let _ = self.retain_outcome(returned);
            if let Err(debt) = self.recheck_original_owned() {
                self.postcheck_debt.get_mut().get_or_insert(debt);
            }
            return Err(());
        }
        self.retain_outcome(returned)
    }

    fn park_original_root_history(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::Prefunded || self.root_history.is_some()
            || !self.root_commits.is_empty() || !matches!(self.held_compilation, Some(Ok(_)))
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.require_original_held_input_cut()?;
        let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let identity = plan.identity.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.q04_before_rows()? != plan.root_before
            || self.state.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.q04_root_before_rows_v1()?
                != plan.state_before
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }

        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let gen1 = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let claim = gen1.verify_claim(&self.claim, identity)?;
        let fields = claim.fields();
        let (controller, held) = gen1.controller_cut(fields[9], fields[10], fields[8], stage, identity)?;
        let cache = gen1.cache_cut(fields[12], fields[8], stage, identity, self.identities.cache_uid)?;
        let controller_hold = crate::journal::ControllerPolicyHoldV1::new(
            held.operation(), held.sandbox(), held.source(), held.binding(), held.epoch(),
        )?;
        // This is the sole old Source record recipe, not an independent Source
        // authority. Its live cut is the same authenticated completed flight;
        // Controller remains responsible for retaining the real Source writer.
        let source_hold = crate::journal::SourceDomainPolicyHoldV1::new(
            controller.operation(), controller.sandbox(), controller.source_commitment(),
            gen1.floor().tree_head(), identity.binding(), identity.epoch(),
        )?;
        let zero = ObjectDigest::from_bytes([0; 32]);
        let pairs = [controller_hold.record_digest()?, zero, source_hold.record_digest()?, zero,
            cache.hold().record_digest()?, zero];
        gen1.recheck()?;
        drop(gen1);

        // The actual parent owns this empty history before any growth. Only
        // its initial binding prefix is eligible for commit; all later shaped
        // packets must first be replaced by their real predecessor events.
        self.root_history = Some(Q04RootAuthorityHistoryV1::park(identity, plan.root_before));
        let history = self.root_history.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let request = super::Q04PreholdInputDataV1::decode(&self.prehold)?;
        let preview = super::Q04PreviewV1::decode(&self.preview, identity.nonce())?;
        history.suffix.form(RootPreholdAuthorityInputV1 {
            identity: &history.identity,
            binding: &plan.compilation.data.binding,
            root_before: plan.root_before.2,
            root_sequence: plan.root_before.0,
            state_sequence: plan.state_before.0,
            claim_length: plan.claim_length,
            claim: Some(&claim),
            held_pairs: Some(pairs),
        }, stage, &request, &preview, &self.source_complete)?;
        history.eligible_end = history.binding_prefix_end()?;
        self.root_commits.try_reserve_exact(history.transactions().len())?;
        self.root_commits.resize_with(history.transactions().len(), || None);
        let returned = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_preflight_authority_suffix(plan.root_before, history.transactions());
        history.suffix.preflight = Some(returned);
        if let Some(Err(first)) = history.suffix.preflight.take() {
            self.cause.get_mut().get_or_insert(first);
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.require_identity_clock(identity)
    }

    fn commit_original_binding_prefix(&mut self) -> Result<(), CreateQ04ErrorV1> {
        self.park_original_root_history()?;
        loop {
            let history = self.root_history.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
            if history.committed() == history.binding_prefix_end()? {
                break;
            }
            self.append_one_original_root_prefix()?;
        }
        self.phase = RootQ04PreludePhaseV1::BindingHeld;
        self.require_original_held_input_cut()
    }

    fn append_one_original_root_prefix(&mut self) -> Result<(), CreateQ04ErrorV1> {
        self.require_original_held_input_cut()?;
        self.append_parked_original_root_commit()?;
        let history = self.root_history.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let returned = self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_recheck_original_binding_prefix(history,
                self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &self.source_complete);
        if let Err(debt) = returned {
            self.postcheck_debt.get_mut().get_or_insert(debt);
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.require_identity_clock(history.identity())
    }

    fn append_parked_original_root_commit(&mut self) -> Result<(), CreateQ04ErrorV1> {
        let history = self.root_history.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let index = history.committed();
        let slot = self.root_commits.get_mut(index).ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if slot.is_some() || !history.may_append(index) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let original = RootOriginalInputLoanV1 {
            startup: self.startup.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            stream: self.stream.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            peer: self.peer.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            state: self.state.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            clock: self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            started: self.started.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            cause: &self.cause,
        };
        // All slot and original-owner checks precede the lower call. The full
        // returned Result is immediately parked; no postcheck, callback or
        // allocation intervenes between return and this assignment.
        *slot = Some(self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_append_original_binding_prefix(
                history, self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
                &self.source_complete, &original, index,
            ));
        drop(original);
        if !matches!(slot, Some(Ok(_))) {
            if let Some(Err(first)) = slot.take() {
                self.cause.get_mut().get_or_insert(first);
            }
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.root_history.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?.advance_parked_commit();
        Ok(())
    }

    fn require_original_held_input_cut(&mut self) -> Result<(), CreateQ04ErrorV1> {
        self.recheck_original()?;
        let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let identity = plan.identity.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        self.require_identity_clock(identity)?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let gen1 = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        let claim = gen1.verify_claim(&self.claim, identity)?;
        let fields = claim.fields();
        if fields[11] != self.source_complete.as_slice() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let (controller, held) = gen1.controller_cut(fields[9], fields[10], fields[8], stage, identity)?;
        let original = RootOriginalInputLoanV1 {
            startup: self.startup.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            stream: self.stream.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            peer: self.peer.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            state: self.state.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            clock: self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            started: self.started.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            cause: &self.cause,
        };
        let now = original.recheck_cut(identity)?.wall_seconds();
        let inputs = PolicyDeploymentInputsV1 {
            node: fields[3], site: fields[4], backend: fields[5], catalogs: fields[6],
        };
        let (project, deployment_head, _) = gen1.signed_project_sources(fields[7], &inputs, now)?;
        let cache = gen1.cache_cut(fields[12], fields[8], stage, identity, self.identities.cache_uid)?;
        let current = RootCurrentInputVerifierV1 {
            original: RootCurrentOwnerLoanV1::Input(original), gen1: &gen1, stage,
            controller, project: &project, deployment_head, project_input: fields[7],
            deployment_inputs: inputs, controller_packet: fields[9], proposed: fields[8],
            purpose: RootInputCurrentPurposeV1::Held {
                identity, held, held_packet: fields[10], cache_packet: fields[12],
                cache, cache_uid: self.identities.cache_uid,
            },
        };
        current.recheck()
    }

    /// Publishes the exact policy recipe while this original binding stays held.
    ///
    /// The actual strict adapter outcome, native recipe, and complete replay
    /// remain resident. Success here is only policy durability; Controller's
    /// Effect and the public Create are still Applying and pending.
    ///
    /// # Errors
    /// Retains the actual prepared/applied/ambiguous outcome and first cause.
    /// A late or failed postcheck cannot issue a Decision or release owners.
    pub fn publish_held_policy(&mut self) -> Result<(), ()> {
        let returned = self.publish_original_held_policy();
        if returned.is_err() {
            let _ = self.retain_outcome(returned);
            if let Err(debt) = self.recheck_original_owned() {
                self.postcheck_debt.get_mut().get_or_insert(debt);
            }
            return Err(());
        }
        self.retain_outcome(returned)
    }

    fn prepare_original_policy_publication(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::BindingHeld
            || self.publication.is_some() || self.publication_preparation.is_some()
            || self.publication_native.is_some()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.require_original_held_input_cut()?;
        self.publication_preparation = Some(self.form_original_policy_publication());
        let prepared = match self.publication_preparation.take() {
            Some(Ok(prepared)) => prepared,
            Some(Err(first)) => {
                self.cause.get_mut().get_or_insert(first);
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            None => return Err(CreateQ04ErrorV1::ChangedCut),
        };
        self.publication = Some(super::super::protected_journal::Q04PolicyPublicationAttemptV1::park(prepared));

        // This copies the SAME four already encoded native members as bounded
        // comparison DATA; no payload, reducer or publication serializer is
        // invoked again. It is not a reservation or a second commit route.
        let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        self.publication_native = Some(JournalTransaction::new(
            plan.capacity.transaction_id(), plan.capacity.journal_records().to_vec(),
        )?);
        self.require_original_held_input_cut()
    }

    fn form_original_policy_publication(
        &mut self,
    ) -> Result<super::super::PreparedPolicyPublicationV1, CreateQ04ErrorV1> {
        self.recheck_original()?;
        let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let identity = plan.identity.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if self.state.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.q04_root_before_rows_v1()?
            != plan.state_before
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let data = match self.held_compilation.take() {
            Some(Ok(data)) => data,
            Some(Err(first)) => return Err(first),
            None => return Err(CreateQ04ErrorV1::ChangedCut),
        };
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let gen1 = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        let claim = gen1.verify_claim(&self.claim, identity)?;
        let fields = claim.fields();
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let (controller, held) = gen1.controller_cut(fields[9], fields[10], fields[8], stage, identity)?;
        let original = RootOriginalPublicationLoanV1 {
            startup: self.startup.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            stream: self.stream.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            peer: self.peer.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            clock: self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            started: self.started.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            cause: &self.cause,
        };
        let now = original.recheck()?.wall_seconds();
        let inputs = PolicyDeploymentInputsV1 {
            node: fields[3], site: fields[4], backend: fields[5], catalogs: fields[6],
        };
        let (project, deployment_head, _) = gen1.signed_project_sources(fields[7], &inputs, now)?;
        let cache = gen1.cache_cut(fields[12], fields[8], stage, identity, self.identities.cache_uid)?;
        let current = RootCurrentInputVerifierV1 {
            original: RootCurrentOwnerLoanV1::Publication(original), gen1: &gen1, stage,
            controller, project: &project, deployment_head, project_input: fields[7],
            deployment_inputs: inputs, controller_packet: fields[9], proposed: fields[8],
            purpose: RootInputCurrentPurposeV1::Held {
                identity, held, held_packet: fields[10], cache_packet: fields[12],
                cache, cache_uid: self.identities.cache_uid,
            },
        };
        current.recheck()?;
        let verified = super::super::protected_journal::VerifiedPolicyPublicationV1::authenticate(
            &data.input, data.candidate, data.prerequisites, &current,
        )?;
        let adapter = super::super::PolicyCompilerProtectedJournalV1::claim(
            self.state.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?, plan.compilation.validator.clone(),
        )?;
        adapter.q04_current_plan(identity.publication_id(), verified, &plan.capacity).map_err(Into::into)
    }

    fn publish_original_held_policy(&mut self) -> Result<(), CreateQ04ErrorV1> {
        self.prepare_original_policy_publication()?;
        if self.publication_result.is_some() || self.publication_readback.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.require_original_held_input_cut()?;
        // The strict donor itself parks Prepared/Pending/Applied and its real
        // cause before it returns. This parent additionally parks the full
        // returned classification before any original owner postcheck.
        self.publication_result = Some(self.invoke_original_policy_publication());
        if !matches!(self.publication_result, Some(Ok(()))) {
            if let Some(Err(first)) = self.publication_result.take() {
                self.cause.get_mut().get_or_insert(first);
            }
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.publication_readback = Some(self.read_original_policy_publication());
        if !matches!(self.publication_readback, Some(Ok(_))) {
            if let Some(Err(first)) = self.publication_readback.take() {
                self.cause.get_mut().get_or_insert(first);
            }
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.require_original_held_input_cut()?;
        self.phase = RootQ04PreludePhaseV1::PolicyCommitted;
        self.recheck_original()
    }

    fn invoke_original_policy_publication(&mut self) -> Result<(), CreateQ04ErrorV1> {
        let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let identity = plan.identity.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let history = self.root_history.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if history.committed() != history.binding_prefix_end()? {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        root.q04_recheck_original_binding_prefix(history,
            self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &self.source_complete)?;
        let gen1 = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        let claim = gen1.verify_claim(&self.claim, identity)?;
        let fields = claim.fields();
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let (controller, held) = gen1.controller_cut(fields[9], fields[10], fields[8], stage, identity)?;
        let original = RootOriginalPublicationLoanV1 {
            startup: self.startup.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            stream: self.stream.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            peer: self.peer.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            clock: self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            started: self.started.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            cause: &self.cause,
        };
        let now = original.recheck()?.wall_seconds();
        let inputs = PolicyDeploymentInputsV1 {
            node: fields[3], site: fields[4], backend: fields[5], catalogs: fields[6],
        };
        let (project, deployment_head, _) = gen1.signed_project_sources(fields[7], &inputs, now)?;
        let cache = gen1.cache_cut(fields[12], fields[8], stage, identity, self.identities.cache_uid)?;
        let current = RootCurrentInputVerifierV1 {
            original: RootCurrentOwnerLoanV1::Publication(original), gen1: &gen1, stage,
            controller, project: &project, deployment_head, project_input: fields[7],
            deployment_inputs: inputs, controller_packet: fields[9], proposed: fields[8],
            purpose: RootInputCurrentPurposeV1::Held {
                identity, held, held_packet: fields[10], cache_packet: fields[12],
                cache, cache_uid: self.identities.cache_uid,
            },
        };
        current.recheck()?;
        let mut adapter = super::super::PolicyCompilerProtectedJournalV1::claim(
            self.state.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?, plan.compilation.validator.clone(),
        )?;
        adapter.q04_commit_original(
            self.publication.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?, &current,
        ).map_err(Into::into)
    }

    fn read_original_policy_publication(
        &mut self,
    ) -> Result<super::super::protected_journal::Q04PolicyPublicationReadbackV1, CreateQ04ErrorV1> {
        self.recheck_original()?;
        self.read_original_policy_publication_body()
    }

    fn read_original_policy_publication_body(
        &mut self,
    ) -> Result<super::super::protected_journal::Q04PolicyPublicationReadbackV1, CreateQ04ErrorV1> {
        let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let original = self.publication_native.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let state = self.state.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if state.protected_writer_physical_names_v1()? != plan.state_before.1
            || state.snapshot_sequence() != plan.state_before.0.checked_add(6).ok_or(CreateQ04ErrorV1::Bounds)?
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        state.require_q04_native_recipe_prefix_v1(std::slice::from_ref(original), plan.state_before.0)?;
        let adapter = super::super::PolicyCompilerProtectedJournalV1::claim(state, plan.compilation.validator.clone())?;
        let returned = adapter.q04_observe_original_publication(
            self.publication.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &plan.capacity,
        );
        drop(adapter);
        returned.map_err(Into::into)
    }

    /// Commits and sends the real decision on this same original Root flight.
    ///
    /// The decision names the already committed R2 binding and the actual
    /// policy-state transaction. It is neither a future native observation
    /// nor a successful Create or a permission to release the lower owners.
    ///
    /// # Errors
    /// Retains the original decision, native outcome, transport cause and
    /// later readback debt. Failure leaves the same whole attempt closed.
    pub fn publish_decision(&mut self) -> Result<(), ()> {
        let returned = self.publish_original_decision();
        self.retain_outcome(returned)
    }

    fn publish_original_decision(&mut self) -> Result<(), CreateQ04ErrorV1> {
        if self.phase != RootQ04PreludePhaseV1::PolicyCommitted
            || self.decision.is_some() || self.consumed_gate.is_some()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.require_original_held_input_cut()?;
        // This parent owns the complete returned preparation before any
        // final native, owner or clock check can fail.
        self.decision = Some(self.form_original_decision());
        let decision = match self.decision.as_ref() {
            Some(Ok(decision)) => decision,
            _ => {
                if let Some(Err(first)) = self.decision.take() {
                    self.cause.get_mut().get_or_insert(first);
                }
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        };
        let history = self.root_history.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let index = history.binding_prefix_end()?;
        let transaction = history.transactions().get(index).ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if history.committed() != index || transaction.records().len() != 2
            || transaction.records()[0].value() != Some(decision.bytes().as_slice())
            || history.suffix.phases.get(2).is_none_or(|phase| {
                phase.bytes()[96..128] != *decision.digest().as_bytes()
            })
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        // Only this genuine owning action can admit the next exact recipe.
        // Capacity-shaped future ACK phases remain ineligible for append.
        self.consumed_gate = Some(root_consumed_gate_record(history.identity(), decision)?);
        history.eligible_end = index.checked_add(1).ok_or(CreateQ04ErrorV1::Bounds)?;
        self.append_one_original_root_prefix()?;
        self.require_original_held_input_cut()?;
        let identity = self.root_history.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.identity();
        self.require_identity_clock(identity)?;
        self.sent.clear();
        encode_root_create_q04_transfer_v1(
            &mut self.sent, RootCreateQ04TransferKindV1::Decision, identity.nonce(),
            self.decision.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(CreateQ04ErrorV1::ChangedCut)?.bytes(),
        )?;
        self.write_original(&self.sent)?;
        self.require_original_held_input_cut()?;
        self.phase = RootQ04PreludePhaseV1::Decided;
        Ok(())
    }

    fn form_original_decision(&mut self) -> Result<super::Q04RootDecisionV1, CreateQ04ErrorV1> {
        self.require_original_held_input_cut()?;
        let publication = self.read_original_policy_publication()?;
        let plan = self.prehold_plan.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let identity = plan.identity.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let history = self.root_history.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let end = history.binding_prefix_end()?;
        if history.committed() != end || publication.transaction != identity.policy_transaction()
            || publication.current != identity.policy_current()
            || publication.sequence != plan.state_before.0.checked_add(6).ok_or(CreateQ04ErrorV1::Bounds)?
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?
            .q04_recheck_original_binding_prefix(history,
                self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &self.source_complete)?;
        let binding_transaction = history.transactions().get(end - 1)
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let committed = self.root_commits.get(end - 1)
            .and_then(|result| result.as_ref()).and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if committed.commit_sequence < history.original.0 {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let r2 = history.suffix.phases.get(1).ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if r2.native_transaction_id() != *binding_transaction.id() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        // NEXT is a comparison to the complete original native COMMIT audit;
        // the retained strict outcome is still owned by this same attempt.
        root_decision_record(identity, *binding_transaction.id(),
            publication.sequence.checked_sub(1).ok_or(CreateQ04ErrorV1::Bounds)?,
            history.original.0,
            ObjectDigest::from_bytes(super::fixed(r2.bytes(), 352)),
            ObjectDigest::from_bytes(super::fixed(r2.bytes(), 416)))
    }

    /// Consumes the real policy ACK and returns the committed Root4 phase.
    ///
    /// The selected caller first refreshes gen1 after Controller's C2 write.
    /// Both the received packet and the native result remain in this attempt.
    ///
    /// # Errors
    /// Retains wrong phase, signature/current-cut mismatch, original I/O cause
    /// and postcheck debt without releasing or reconstructing an owner.
    pub fn consume_policy_acknowledgement(&mut self) -> Result<(), ()> {
        let returned = self.consume_original_held_acknowledgement(super::Q04AcknowledgementKindV1::Policy);
        self.retain_outcome(returned)
    }

    /// Consumes the real release ACK and returns logical Root5 authorization.
    ///
    /// This authorizes only the exact lower ReleasedPending transitions. The
    /// original Root writers, stream and clock remain resident through final
    /// settlement; a logical release is not disposal, cleanup or Drain.
    ///
    /// # Errors
    /// Retains wrong phase, changed original owners, stale current ACK, native
    /// ambiguity, transport error or expired original cut.
    pub fn authorize_lower_release(&mut self) -> Result<(), ()> {
        let returned = self.consume_original_held_acknowledgement(super::Q04AcknowledgementKindV1::Release);
        self.retain_outcome(returned)
    }

    /// Commits settlement after exact lower ReleasedPending observations.
    ///
    /// Root retains its original writer pair and stream. The returned Root6
    /// record permits only the same in-cut lower clearance sequence, not a
    /// generic currentness token, disposal acknowledgement or successful Create.
    ///
    /// # Errors
    /// Retains stale/mixed lower cuts, wrong signed packet, original native or
    /// transport failure, late cutoff and separate physical readback debt.
    pub fn settle_lower_release(&mut self) -> Result<(), ()> {
        let returned = self.consume_original_held_acknowledgement(super::Q04AcknowledgementKindV1::Settlement);
        self.retain_outcome(returned)
    }

    /// Commits Root7 only after the genuine lower clear observations.
    ///
    /// The original Root writer remains owned after this method. Final
    /// bounded response/shutdown must complete before that owner can end.
    ///
    /// # Errors
    /// Retains incomplete/ambiguous clears, changed same-flight observations,
    /// native failure, transport failure or the expired original cutoff.
    pub fn acknowledge_lower_clearance(&mut self) -> Result<(), ()> {
        let returned = self.consume_original_held_acknowledgement(super::Q04AcknowledgementKindV1::Clearance);
        self.retain_outcome(returned)
    }

    /// Ends this original stream only after the actual C8 gen1 refresh.
    ///
    /// Root7 has already been sent. The same Root writers remain held while
    /// Controller commits C8 and returns its fresh signed Complete. Shutdown
    /// is a terminal transport action, not resource retirement or Drain.
    ///
    /// # Errors
    /// Retains wrong/missing C8, changed native/publication/name/clock cuts,
    /// the actual shutdown error, and separate final-bookend debt.
    pub fn finish_original_clearance(&mut self) -> Result<(), ()> {
        let prepared = (|| {
            if self.phase != RootQ04PreludePhaseV1::FinalClearance
                || self.refresh_frames.len() != 11 || self.shutdown_result.is_some()
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            self.recheck_original()?;
            let history = self.root_history.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
            if history.committed() != history.transactions().len()
                || history.actual_acknowledgements != 4
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            let original = super::Q04PreholdInputDataV1::decode(&self.prehold)?;
            let metadata = original.fields()[0];
            let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
            let gen1 = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
            if gen1.controller_coordinates()? != (
                crate::journal::ProtectedJournalNamesV1::from_bytes(&metadata[176..224])
                    .map_err(crate::journal::JournalError::from)?,
                u64::from_be_bytes(super::fixed(metadata, 464)).checked_add(31).ok_or(CreateQ04ErrorV1::Bounds)?,
            ) || gen1.source_coordinates()? != (
                crate::journal::ProtectedJournalNamesV1::from_bytes(&metadata[224..272])
                    .map_err(crate::journal::JournalError::from)?,
                u64::from_be_bytes(super::fixed(metadata, 472)).checked_add(11).ok_or(CreateQ04ErrorV1::Bounds)?,
            ) {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            gen1.recheck()?;
            drop(gen1);
            self.recheck_final_named_native_cut()?;
            self.recheck_original()
        })();
        self.retain_outcome(prepared)?;
        self.shutdown_result = Some(self.original.shutdown(std::net::Shutdown::Both));
        let final_bookend = self.recheck_final_named_native_cut();
        if let Err(debt) = final_bookend {
            self.postcheck_debt.get_mut().get_or_insert(debt);
        }
        if self.cause.get_mut().is_some() || self.postcheck_debt.get_mut().is_some()
            || !matches!(self.shutdown_result, Some(Ok(())))
        {
            return Err(());
        }
        self.cleared = true;
        Ok(())
    }

    /// Borrows the actual terminal shutdown result without replacing its cause.
    ///
    /// Earlier original failures and final-bookend debt stay in their distinct
    /// resident slots. A shutdown error is neither expected EOF nor retirement.
    pub fn shutdown_result(&self) -> Option<&Result<(), std::io::Error>> {
        self.shutdown_result.as_ref()
    }

    fn recheck_final_named_native_cut(&mut self) -> Result<(), CreateQ04ErrorV1> {
        self.startup.ok_or(CreateQ04ErrorV1::ChangedCut)?.recheck()?;
        let stream = self.stream.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        stream.revalidate_original()?;
        self.peer.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.recheck_stream(stream)?;
        let history = self.root_history.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        self.root.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.q04_recheck_original_binding_prefix(
            history, self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &self.source_complete,
        )?;
        let original = self.publication_readback.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let expected = (original.sequence, original.transaction, original.current);
        let current = self.read_original_policy_publication_body()?;
        if (current.sequence, current.transaction, current.current) != expected {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let now = self.current_original_clock()?;
        let controller = self.controller_clock.ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if controller[..16] != now.host_boot_id()
            || now.boottime_nanoseconds() >= u64::from_be_bytes(super::fixed(&controller, 24))
        {
            return Err(CreateQ04ErrorV1::Expired);
        }
        Ok(())
    }

    fn consume_original_held_acknowledgement(
        &mut self,
        kind: super::Q04AcknowledgementKindV1,
    ) -> Result<(), CreateQ04ErrorV1> {
        let (expected_phase, next_phase, request, response, packet_index) = match kind {
            super::Q04AcknowledgementKindV1::Policy => (
                RootQ04PreludePhaseV1::Decided, RootQ04PreludePhaseV1::PolicyAcknowledged,
                RootCreateQ04TransferKindV1::PolicyAcknowledgement, RootCreateQ04TransferKindV1::PolicyAccepted, 0,
            ),
            super::Q04AcknowledgementKindV1::Release => (
                RootQ04PreludePhaseV1::PolicyAcknowledged, RootQ04PreludePhaseV1::ReleaseAuthorized,
                RootCreateQ04TransferKindV1::ReleaseAcknowledgement, RootCreateQ04TransferKindV1::ReleaseAuthorized, 1,
            ),
            super::Q04AcknowledgementKindV1::Settlement => (
                RootQ04PreludePhaseV1::ReleaseAuthorized, RootQ04PreludePhaseV1::Settled,
                RootCreateQ04TransferKindV1::SettlementAcknowledgement, RootCreateQ04TransferKindV1::Settled, 2,
            ),
            super::Q04AcknowledgementKindV1::Clearance => (
                RootQ04PreludePhaseV1::Settled, RootQ04PreludePhaseV1::FinalClearance,
                RootCreateQ04TransferKindV1::ClearanceAcknowledgement, RootCreateQ04TransferKindV1::FinalClearance, 3,
            ),
        };
        if self.phase != expected_phase || self.acknowledgement_frames.len() != packet_index {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck_original()?;
        self.acknowledgement_frames.try_reserve_exact(1)?;
        self.acknowledgement_frames.push(Vec::new());
        self.receive_original_exact(32 + kind.body_bytes() + 64, RootControllerFrameSlotV1::Acknowledgement)?;
        self.require_terminal_held_input_cut(kind)?;

        let history = self.root_history.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let gen1 = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        let original = super::Q04PreholdInputDataV1::decode(&self.prehold)?;
        let metadata = original.fields()[0];
        let original_names =
            crate::journal::ProtectedJournalNamesV1::from_bytes(&metadata[176..224])
                .map_err(crate::journal::JournalError::from)?;
        let original_next = u64::from_be_bytes(super::fixed(metadata, 464));
        let packet = decode_root_create_q04_transfer_v1(
            self.acknowledgement_frames.get(packet_index).ok_or(CreateQ04ErrorV1::ChangedCut)?,
            request, history.identity().nonce(),
        )?;
        let acknowledgement = gen1.acknowledgement(kind, packet, history.identity(), original_names)?;
        history.admit_actual_acknowledgement(&acknowledgement, original_next)?;
        drop(gen1);

        self.append_one_original_terminal_held_phase(kind)?;
        self.require_terminal_held_input_cut(kind)?;
        let history = self.root_history.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let phase = history.suffix.phases.get(packet_index + 3).ok_or(CreateQ04ErrorV1::ChangedCut)?;
        self.sent.clear();
        encode_root_create_q04_transfer_v1(&mut self.sent, response, history.identity().nonce(), phase.bytes())?;
        self.write_original(&self.sent)?;
        self.require_terminal_held_input_cut(kind)?;
        self.phase = next_phase;
        Ok(())
    }

    fn append_one_original_terminal_held_phase(
        &mut self,
        kind: super::Q04AcknowledgementKindV1,
    ) -> Result<(), CreateQ04ErrorV1> {
        self.require_terminal_held_input_cut(kind)?;
        self.append_parked_original_root_commit()?;
        if let Err(debt) = self.require_terminal_held_input_cut(kind) {
            self.postcheck_debt.get_mut().get_or_insert(debt);
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(())
    }

    fn require_terminal_held_input_cut(
        &mut self,
        kind: super::Q04AcknowledgementKindV1,
    ) -> Result<(), CreateQ04ErrorV1> {
        self.recheck_original()?;
        let publication = self.read_original_policy_publication()?;
        let terminal_cache = if matches!(kind, super::Q04AcknowledgementKindV1::Settlement
            | super::Q04AcknowledgementKindV1::Clearance)
        {
            Some(self.park_current_terminal_cache(kind)?)
        } else {
            None
        };
        let history = self.root_history.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let identity = history.identity();
        self.require_identity_clock(identity)?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        root.q04_recheck_original_binding_prefix(history,
            self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &self.source_complete)?;
        let gen1 = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        let claim = gen1.verify_claim(&self.claim, identity)?;
        let fields = claim.fields();
        if self.source_observations.get(self.claim_source_observation.ok_or(CreateQ04ErrorV1::ChangedCut)?)
            .map(|packet| packet.as_ref()) != Some(fields[11])
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let (packet_index, frames, request) = match kind {
            super::Q04AcknowledgementKindV1::Policy => (0, 9, RootCreateQ04TransferKindV1::PolicyAcknowledgement),
            super::Q04AcknowledgementKindV1::Release => (1, 15, RootCreateQ04TransferKindV1::ReleaseAcknowledgement),
            super::Q04AcknowledgementKindV1::Settlement => (2, 20, RootCreateQ04TransferKindV1::SettlementAcknowledgement),
            super::Q04AcknowledgementKindV1::Clearance => (3, 27, RootCreateQ04TransferKindV1::ClearanceAcknowledgement),
        };
        let prehold = super::Q04PreholdInputDataV1::decode(&self.prehold)?;
        let metadata = prehold.fields()[0];
        let original_next = u64::from_be_bytes(super::fixed(metadata, 464));
        let original_names =
            crate::journal::ProtectedJournalNamesV1::from_bytes(&metadata[176..224])
                .map_err(crate::journal::JournalError::from)?;
        let packet = decode_root_create_q04_transfer_v1(
            self.acknowledgement_frames.get(packet_index).ok_or(CreateQ04ErrorV1::ChangedCut)?,
            request, identity.nonce(),
        )?;
        let acknowledgement = gen1.acknowledgement(kind, packet, identity, original_names)?;
        if acknowledgement.controller_sequence() != original_next.checked_add(frames).ok_or(CreateQ04ErrorV1::Bounds)?
            || packet[280..312] != *self.consumed_gate.as_ref()
                .ok_or(CreateQ04ErrorV1::ChangedCut)?.digest().as_bytes()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let (controller, held) = gen1.original_controller_provenance(
            fields[9], fields[10], fields[8], stage, identity, original_next,
        )?;
        let original = RootOriginalInputLoanV1 {
            startup: self.startup.ok_or(CreateQ04ErrorV1::ChangedCut)?, stream: self.stream.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            peer: self.peer.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            state: self.state.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            clock: self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            started: self.started.ok_or(CreateQ04ErrorV1::ChangedCut)?, cause: &self.cause,
        };
        let inputs = PolicyDeploymentInputsV1 {
            node: fields[3], site: fields[4], backend: fields[5], catalogs: fields[6],
        };
        let (project, deployment_head, _) = gen1.signed_project_sources(fields[7], &inputs,
            original.recheck_cut(identity)?.wall_seconds())?;
        let cache = if terminal_cache.is_some() {
            gen1.original_cache_provenance(fields[12], fields[8], stage, identity, self.identities.cache_uid)?
        } else {
            gen1.cache_cut(fields[12], fields[8], stage, identity, self.identities.cache_uid)?
        };
        let purpose = if let Some(index) = terminal_cache {
            let observed = self.cache_terminal_outcomes.get(index)
                .and_then(|outcome| outcome.readback.as_ref().ok()).ok_or(CreateQ04ErrorV1::ChangedCut)?;
            require_terminal_pairs(identity, &acknowledgement, controller, held, gen1.floor(), cache, observed,
                history.suffix.phases.get(4).ok_or(CreateQ04ErrorV1::ChangedCut)?,
                history.suffix.phases.get(5))?;
            if kind == super::Q04AcknowledgementKindV1::Clearance {
                require_original_lower_clearance_recipe(
                    &gen1, history, metadata, fields, &acknowledgement, controller, held, cache,
                )?;
            }
            RootInputCurrentPurposeV1::TerminalReleased {
                identity, held, held_packet: fields[10], cache_packet: fields[12], cache,
                cache_uid: self.identities.cache_uid, kind, acknowledgement: packet,
                original_next, original_names, observed,
            }
        } else {
            RootInputCurrentPurposeV1::TerminalHeld {
                identity, held, held_packet: fields[10], cache_packet: fields[12], cache,
                cache_uid: self.identities.cache_uid, kind, acknowledgement: packet,
                original_next, original_names,
            }
        };
        let current = RootCurrentInputVerifierV1 {
            original: RootCurrentOwnerLoanV1::Input(original), gen1: &gen1, stage,
            controller, project: &project, deployment_head, project_input: fields[7],
            deployment_inputs: inputs, controller_packet: fields[9], proposed: fields[8],
            purpose,
        };
        current.recheck()?;
        drop(current);
        drop(gen1);
        let after = self.read_original_policy_publication()?;
        if publication.sequence != after.sequence || publication.transaction != after.transaction
            || publication.current != after.current
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        if let Some(before) = terminal_cache {
            let after = self.park_current_terminal_cache(kind)?;
            if self.cache_terminal_outcomes.get(before).and_then(|outcome| outcome.readback.as_ref().ok())
                != self.cache_terminal_outcomes.get(after).and_then(|outcome| outcome.readback.as_ref().ok())
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        self.require_identity_clock(self.root_history.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.identity())
    }

    fn park_current_terminal_cache(
        &mut self,
        kind: super::Q04AcknowledgementKindV1,
    ) -> Result<usize, CreateQ04ErrorV1> {
        let phase = match kind {
            super::Q04AcknowledgementKindV1::Settlement => crate::journal::Q04CacheTerminalPhaseV1::Released,
            super::Q04AcknowledgementKindV1::Clearance => crate::journal::Q04CacheTerminalPhaseV1::Cleared,
            _ => return Err(CreateQ04ErrorV1::ChangedCut),
        };
        if self.cache_terminal_outcomes.len() >= 32 {
            return Err(CreateQ04ErrorV1::Bounds);
        }
        self.cache_terminal_outcomes.try_reserve_exact(1)?;
        let history = self.root_history.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let identity = history.identity();
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        root.q04_recheck_original_binding_prefix(history,
            self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, &self.source_complete)?;
        let gen1 = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        let claim = gen1.verify_claim(&self.claim, identity)?;
        let fields = claim.fields();
        let cache = gen1.original_cache_provenance(fields[12], fields[8],
            self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?, identity, self.identities.cache_uid)?;
        let prehold = super::Q04PreholdInputDataV1::decode(&self.prehold)?;
        let metadata = prehold.fields()[0];
        let release = history.suffix.phases.get(4).ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let required = history.binding_prefix_end()?.checked_add(match kind {
            super::Q04AcknowledgementKindV1::Settlement => 3,
            super::Q04AcknowledgementKindV1::Clearance => 4,
            _ => return Err(CreateQ04ErrorV1::ChangedCut),
        }).ok_or(CreateQ04ErrorV1::Bounds)?;
        if release.phase() != 5 || history.committed() < required
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let request = crate::cache_residency::Q04RootCacheTerminalRequestV1 {
            identity, phase,
            original_names: crate::journal::ProtectedJournalNamesV1::from_bytes(&metadata[272..320])
                .map_err(crate::journal::JournalError::from)?,
            original_next: u64::from_be_bytes(super::fixed(metadata, 480)),
            held: cache.hold(), release_authorization: release.digest(),
        };
        // Capacity was reserved before the reader. Parking the whole returned
        // outcome invokes no allocation, callback or fallible owner check.
        self.cache_terminal_outcomes.push(crate::cache_residency::replay_fixed_root_q04_terminal_cache_journals_v1(
            &gen1, &request,
        ));
        drop(gen1);
        let index = self.cache_terminal_outcomes.len() - 1;
        let outcome = self.cache_terminal_outcomes.get_mut(index).ok_or(CreateQ04ErrorV1::ChangedCut)?;
        if outcome.readback.is_err() {
            let stopped = std::mem::replace(&mut outcome.readback, Err(CreateQ04ErrorV1::ChangedCut));
            if let Err(first) = stopped {
                self.cause.get_mut().get_or_insert(first);
            }
        }
        if outcome.final_mount.is_err() {
            let stopped = std::mem::replace(&mut outcome.final_mount, Ok(()));
            if let Err(debt) = stopped {
                if self.cause.get_mut().is_none() {
                    self.cause.get_mut().get_or_insert(debt.into());
                } else {
                    self.postcheck_debt.get_mut().get_or_insert(debt.into());
                }
            }
        }
        self.require_identity_clock(self.root_history.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?.identity())?;
        if self.cause.get_mut().is_some() || self.postcheck_debt.get_mut().is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        Ok(index)
    }

    // Only this same attempt's original retained fields supply the inputs.
    // The short genuine gen1 loan ends before any later Root action; returned
    // compiler DATA must be parked before the caller's final bookends.
    fn reconstruct_original_input(
        &mut self,
    ) -> Result<RootCompilerInputDataV1, CreateQ04ErrorV1> {
        let plan = self.prehold_plan.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let identity = plan.identity.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        self.require_identity_clock(identity)?;
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let gen1 = root.q04_refresh_completed_gen1(
            &self.controller_complete,
            &self.source_complete,
        )?;
        let claim = gen1.verify_claim(&self.claim, identity)?;
        let fields = claim.fields();
        // Claim11 must be the complete actual Source observation returned by
        // Root on this same held flight, not merely a separately valid signed
        // packet or a copied floor/hash selected by Controller.
        if fields[11] != self.source_complete.as_slice() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        crate::reconciler::validate_original_claim_rows_v1(
            fields[0], fields[1], fields[2], identity,
        )?;
        let (controller, held) = gen1.controller_cut(
            fields[9], fields[10], fields[8], stage, identity,
        )?;
        let original = RootOriginalInputLoanV1 {
            startup: self.startup.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            stream: self.stream.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            peer: self.peer.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            state: self.state.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            clock: self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            started: self.started.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            cause: &self.cause,
        };
        let now = original.recheck()?.wall_seconds();
        let deployment_inputs = PolicyDeploymentInputsV1 {
            node: fields[3],
            site: fields[4],
            backend: fields[5],
            catalogs: fields[6],
        };
        let (project, deployment_head, deployment) = gen1.signed_project_sources(
            fields[7], &deployment_inputs, now,
        )?;
        let cache = gen1.cache_cut(
            fields[12], fields[8], stage, identity, self.identities.cache_uid,
        )?;
        let current = RootCurrentInputVerifierV1 {
            original: RootCurrentOwnerLoanV1::Input(original),
            gen1: &gen1,
            stage,
            controller,
            project: &project,
            deployment_head,
            project_input: fields[7],
            deployment_inputs,
            controller_packet: fields[9],
            proposed: fields[8],
            purpose: RootInputCurrentPurposeV1::Held {
                identity, held, held_packet: fields[10], cache_packet: fields[12],
                cache, cache_uid: self.identities.cache_uid,
            },
        };
        current.recheck()?;

        let (input, prerequisites, normalized, candidate) = current.compile_authenticated_input(&deployment)?;

        // The original closed producer owns the sole barrier/Effect-TX/B664
        // serializer. These borrowed fields are independently authenticated
        // above; the new view grants no authority and fabricates no local
        // CurrentCreateProjectPolicySourceV1 or Controller journal.
        let source = controller.source_commitment();
        let operation = controller.operation();
        let operation_revision = identity.operation_revision();
        let generation = identity.accepted_generation();
        let sandbox = controller.sandbox();
        let project_id = controller.project();
        let projection = identity.desired_precondition();
        let publisher_generation = controller.publisher_generation();
        let publisher_head = controller.publisher_digest();
        let cache_domain = controller.cache_domain_head();
        let revocation = controller.revocation_head();
        let ancestry = gen1.floor().tree_head();
        let partition = cache.hold().partition();
        let physical_cache = cache.hold().cache_head();
        let view = super::super::binding_v2::ClosedCreateProposalFieldViewV2 {
            source_commitment: &source,
            operation: &operation,
            operation_revision: &operation_revision,
            accepted_generation: &generation,
            sandbox: &sandbox,
            project: &project_id,
            projection_revision: &projection,
            publisher_generation: &publisher_generation,
            publisher_head: &publisher_head,
            cache_domain_head: &cache_domain,
            revocation_head: &revocation,
            ancestry: &ancestry,
            physical_partition: &partition,
            physical_cache: &physical_cache,
        };
        let checked_draft = super::super::public_create_source::parentless_explicit_draft_digest_v2(
            source, project.head().packet_digest(), project.head().input_digest(),
            prerequisites.digest(), normalized,
        );
        let binding = super::super::binding_v2::encode_closed_proposal_fields(
            &view, project.head().packet_digest(), project.head().input_digest(),
            deployment_head, normalized, candidate.commitment().digest(),
            stage.staged().base(), checked_draft,
        )?;
        if binding.as_slice() != fields[8]
            || super::super::closed_policy_binding_digest_v2(&binding)? != identity.binding()
            || identity.bytes()[456..488] != *normalized.as_bytes()
            || identity.bytes()[488..520] != *candidate.commitment().digest().as_bytes()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        current.recheck()?;
        Ok(RootCompilerInputDataV1 { input, prerequisites, normalized, candidate, binding })
    }

    // Before any logical hold, only the actual pinned original Controller
    // DATA and signed Root inputs may form an inert compiler recipe. No held
    // packet, Cache authority or future native head is invented here.
    fn reconstruct_prehold_input(&mut self) -> Result<RootPreholdCompilationV1, CreateQ04ErrorV1> {
        self.recheck_original()?;
        let stage = self.stage.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let request_packet = self.prehold.as_slice();
        let root = self.root.as_mut().ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let gen1 = root.q04_refresh_completed_gen1(&self.controller_complete, &self.source_complete)?;
        let (request, controller) = gen1.prehold_input(request_packet, stage)?;
        let fields = request.fields();
        let source = controller.source_commitment();
        let proposal = super::super::binding_v2::ClosedPolicyRootBindingV2::q04_decode(fields[4])?;
        let view = proposal.q04_fields(&source);
        let rows = crate::reconciler::read_original_q04_rows_v1(
            fields[1], fields[2], fields[3], crate::reconciler::Q04OriginalRowBindingV1 {
                operation: *view.operation,
                sandbox: *view.sandbox,
                project: *view.project,
                accepted_generation: *view.accepted_generation,
                desired_precondition: *view.projection_revision,
            },
        )?;
        let before_controller = rows.before;
        let effect_plan = rows.effect_plan_digest()?;
        let original = RootOriginalInputLoanV1 {
            startup: self.startup.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            stream: self.stream.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            peer: self.peer.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            state: self.state.as_ref().ok_or(CreateQ04ErrorV1::ChangedCut)?,
            clock: self.clock.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            started: self.started.ok_or(CreateQ04ErrorV1::ChangedCut)?,
            cause: &self.cause,
        };
        let now = original.recheck()?.wall_seconds();
        let preview = super::Q04PreviewV1::decode(&self.preview, stage.staged().challenge())?;
        let signed = preview.fields();
        let deployment_inputs = PolicyDeploymentInputsV1 {
            node: signed[3], site: signed[4], backend: signed[5], catalogs: signed[6],
        };
        let (project, deployment_head, deployment) =
            gen1.signed_project_sources(signed[8], &deployment_inputs, now)?;
        let current = RootCurrentInputVerifierV1 {
            original: RootCurrentOwnerLoanV1::Input(original), gen1: &gen1, stage, controller, project: &project,
            deployment_head, project_input: signed[8], deployment_inputs,
            controller_packet: fields[5], proposed: fields[4],
            purpose: RootInputCurrentPurposeV1::Prehold { request_packet },
        };
        current.recheck()?;
        let (input, prerequisites, normalized, candidate) = current.compile_authenticated_input(&deployment)?;
        let checked_draft = super::super::public_create_source::parentless_explicit_draft_digest_v2(
            source, project.head().packet_digest(), project.head().input_digest(),
            prerequisites.digest(), normalized,
        );
        let binding = super::super::binding_v2::encode_closed_proposal_fields(
            &view, project.head().packet_digest(), project.head().input_digest(),
            deployment_head, normalized, candidate.commitment().digest(),
            stage.staged().base(), checked_draft,
        )?;
        if binding.as_slice() != fields[4] {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        current.recheck()?;
        let validator = super::super::PolicyCompilerReplayValidatorV1::authenticate(
            [prerequisites.clone()], &current,
        )?;
        current.recheck()?;
        Ok(RootPreholdCompilationV1 {
            data: RootCompilerInputDataV1 { input, prerequisites, normalized, candidate, binding },
            validator,
            before_controller, effect_plan,
            operation_revision: *view.operation_revision,
            desired_precondition: *view.projection_revision,
            controller,
        })
    }

    fn retain_outcome<T>(&self, outcome: Result<T, CreateQ04ErrorV1>) -> Result<T, ()> {
        match outcome {
            Ok(value) if self.cause.borrow().is_none() && self.postcheck_debt.borrow().is_none() => Ok(value),
            Ok(_) => Err(()),
            Err(error) => {
                let mut cause = self.cause.borrow_mut();
                if cause.is_none() {
                    *cause = Some(error);
                }
                Err(())
            }
        }
    }
}

// The actual resource-only observation reserves all independent Result owners
// before the RPC. The paired sample remains whole and runs last even on Err.
#[derive(Default)]
struct RootResourceSourcePostsV2 {
    owners: [Option<Result<(), CreateQ04ErrorV1>>; 5],
    clock: Option<Result<RawPairedClockSample, CreateQ04ErrorV1>>,
}

/// Lends one actual Root-selected request to the unchanged fixed Source RPC.
///
/// The loan exposes only existing request/key DATA. It retains the actual Root
/// owner and original stream/startup/state loans; it cannot clone, extract or
/// manufacture an authority. Its caller parks the actual returned `Result`
/// through [`Self::park_result`] or [`Self::park_result_v2`] before postchecks.
pub struct RootCreateQ04SourceObservationLoanV1<'attempt, 'startup> {
    root: &'attempt mut RootSourceGenesisAuthorityV1,
    original: RootOriginalInputLoanV1<'attempt, 'startup>,
    project: aos_sandbox_core::ProjectId,
    challenge: SourceTreeGenesisChallengeV1,
    context: SourceTreeGenesisIntentContextV1,
    purpose: RootSourceObservationPurposeV1,
    received: &'attempt mut Option<Result<super::super::SourceTreeGenesisReadbackPacketV2, std::io::Error>>,
    observations: &'attempt mut Vec<super::super::SourceTreeGenesisReadbackPacketV2>,
    resource_posts: Option<&'attempt mut RootResourceSourcePostsV2>,
    source_complete: &'attempt mut Vec<u8>,
    controller_complete: &'attempt [u8],
    floor: &'attempt mut Option<SourceHierarchyFloorRecordV1>,
    phase: &'attempt mut RootQ04PreludePhaseV1,
    postcheck_debt: &'attempt RefCell<Option<CreateQ04ErrorV1>>,
    finished: bool,
}

impl RootCreateQ04SourceObservationLoanV1<'_, '_> {
    /// Borrows the same independently pinned Root request inputs.
    ///
    /// The returned project/context are comparison DATA for the old RPC;
    /// signature verification is not currentness or permission to mutate.
    #[must_use]
    pub fn request(&self) -> (
        SourceTreeGenesisChallengeV1,
        aos_sandbox_core::ProjectId,
        &SourceTreeGenesisIntentContextV1,
        &PinnedSourceHoldReadbackSignerV1,
    ) {
        (self.challenge, self.project, &self.context, self.root.source_readback_pin())
    }

    /// Parks the real returned packet or first I/O cause before postchecks.
    ///
    /// # Errors
    /// Retains the RPC's actual error and separately records a later original
    /// owner/clock check failure. The enclosing attempt remains closed; this
    /// does not repair the old RPC's callee-local pre-return custody gap.
    pub fn park_result(
        self,
        returned: Result<[u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1], std::io::Error>,
    ) -> Result<(), ()> {
        self.park_result_v2(returned.map(super::super::SourceTreeGenesisReadbackPacketV2::Legacy))
    }

    /// Parks the full resource packet before all independent owner posts.
    ///
    /// # Errors
    /// Retains the actual RPC cause, Root post and original-flight post without
    /// renewing the deadline. The original clock-bearing post runs last.
    pub fn park_result_v2(
        mut self,
        returned: Result<super::super::SourceTreeGenesisReadbackPacketV2, std::io::Error>,
    ) -> Result<(), ()> {
        *self.received = Some(returned);
        if matches!(self.received, Some(Err(_))) {
            match self.received.take() {
                Some(Err(error)) => {
                    self.original.cause.borrow_mut().get_or_insert(error.into());
                }
                original => *self.received = original,
            }
        }
        // A negative result still gets physical postchecks without renewing
        // availability. Their error is debt, never a replacement first cause.
        if let Some(posts) = self.resource_posts.as_mut() {
            posts.owners[0] = Some(self.root.recheck().map_err(CreateQ04ErrorV1::from));
            self.original.recheck_resource_posts(posts);
            for result in posts.owners.iter_mut() {
                if result.as_ref().is_some_and(Result::is_err) {
                    let mut cause = self.original.cause.borrow_mut();
                    let mut debt = self.postcheck_debt.borrow_mut();
                    let destination = if cause.is_none() { &mut *cause } else { &mut *debt };
                    // If both error owners are occupied, the complete later
                    // result remains in this original attempt's parked slot.
                    if destination.is_none() {
                        if let Some(Err(error)) = result.take() {
                            *destination = Some(error);
                        }
                    }
                }
            }
            if posts.clock.as_ref().is_some_and(Result::is_err) {
                let mut cause = self.original.cause.borrow_mut();
                let mut debt = self.postcheck_debt.borrow_mut();
                let destination = if cause.is_none() { &mut *cause } else { &mut *debt };
                if destination.is_none() {
                    if let Some(Err(error)) = posts.clock.take() {
                        *destination = Some(error);
                    }
                }
            }
        } else {
            let checked = self.root.recheck().map_err(CreateQ04ErrorV1::from)
                .and_then(|()| self.original.recheck_owned().map(|_| ()));
            if let Err(error) = checked {
                self.retain_error(error);
            }
        }
        if self.original.cause.borrow().is_none() {
            let accepted = self.accept_original_packet();
            if let Err(error) = accepted {
                self.retain_error(error);
            }
        }
        self.finished = true;
        if self.original.cause.borrow().is_some() || self.postcheck_debt.borrow().is_some() {
            Err(())
        } else {
            Ok(())
        }
    }

    fn accept_original_packet(&mut self) -> Result<(), CreateQ04ErrorV1> {
        self.root.q04_require_existing_completed_floor(self.project)?;
        let packet = self.received.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let completed = !matches!(self.purpose, RootSourceObservationPurposeV1::Preparation);
        let floor = if completed {
            let current = self.root.q04_refresh_completed_gen1(self.controller_complete, packet.as_ref())?;
            current.recheck()?;
            current.floor().clone()
        } else {
            self.root.recover_floor(Some(packet.as_ref()))?
                .ok_or(CreateQ04ErrorV1::ChangedCut)?
        };
        if self.floor.as_ref().is_some_and(|prior| prior != &floor) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.root.recheck()?;
        self.original.recheck()?;

        if completed {
            self.source_complete.clear();
            self.source_complete.extend_from_slice(packet.as_ref());
        }
        *self.floor = Some(floor);
        // Capacity and slot vacancy were checked before invocation. This
        // final move invokes no callback and allocates no storage.
        match self.received.take() {
            Some(Ok(packet)) => self.observations.push(packet),
            original => {
                *self.received = original;
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        *self.phase = match self.purpose {
            RootSourceObservationPurposeV1::Preparation => RootQ04PreludePhaseV1::PreparedSource,
            RootSourceObservationPurposeV1::Completion => RootQ04PreludePhaseV1::CompletedSource,
            RootSourceObservationPurposeV1::Refresh => RootQ04PreludePhaseV1::RefreshedSource,
        };
        Ok(())
    }

    fn retain_error(&self, error: CreateQ04ErrorV1) {
        let mut first = self.original.cause.borrow_mut();
        if first.is_none() {
            *first = Some(error);
        } else {
            self.postcheck_debt.borrow_mut().get_or_insert(error);
        }
    }
}

impl Drop for RootCreateQ04SourceObservationLoanV1<'_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            // No abandonment/unwind may release the enclosing borrowed Root
            // writer or original socket while this request is unresolved.
            std::process::exit(1);
        }
    }
}

// This loan keeps actual original startup/peer/stream/state owners, not an
// injected clock/verifier callback or detached observation. Its copied clock
// origin is taken only from the enclosing non-resettable original attempt.
pub(crate) struct RootOriginalInputLoanV1<'cut, 'startup> {
    startup: &'startup ProductionNormalRootStartupV1,
    stream: &'cut RetainedUnixStream,
    peer: &'cut OriginalControllerPolicyPeerV1<'startup>,
    state: &'cut Journal,
    clock: RawPairedClockSample,
    started: Instant,
    cause: &'cut RefCell<Option<CreateQ04ErrorV1>>,
}

// The publication adapter exclusively borrows the actual policy-state writer.
// Its snapshot/CAS/native readback owns that target boundary; this loan holds
// only the independent prerequisites and the same original flight. It is
// created inside the fixed publication action, never from caller field DATA.
struct RootOriginalPublicationLoanV1<'cut, 'startup> {
    startup: &'startup ProductionNormalRootStartupV1,
    stream: &'cut RetainedUnixStream,
    peer: &'cut OriginalControllerPolicyPeerV1<'startup>,
    clock: RawPairedClockSample,
    started: Instant,
    cause: &'cut RefCell<Option<CreateQ04ErrorV1>>,
}

impl RootOriginalPublicationLoanV1<'_, '_> {
    fn recheck(&self) -> Result<RawPairedClockSample, CreateQ04ErrorV1> {
        if self.cause.borrow().is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        recheck_original_flight(
            self.startup, self.stream, self.peer, self.clock, self.started,
        )
    }
}

// Two closed borrow positions share the same input-verification engine. The
// publication position does not pretend to retain an immutable Journal loan
// while the same actual Journal is mutably lent to its canonical adapter.
enum RootCurrentOwnerLoanV1<'cut, 'startup> {
    Input(RootOriginalInputLoanV1<'cut, 'startup>),
    Publication(RootOriginalPublicationLoanV1<'cut, 'startup>),
}

impl RootCurrentOwnerLoanV1<'_, '_> {
    fn clock(&self) -> RawPairedClockSample {
        match self {
            Self::Input(original) => original.clock,
            Self::Publication(original) => original.clock,
        }
    }

    fn recheck(&self) -> Result<RawPairedClockSample, CreateQ04ErrorV1> {
        match self {
            Self::Input(original) => original.recheck(),
            Self::Publication(original) => original.recheck(),
        }
    }

    fn require_model_verification(&self, outcome: Result<bool, CreateQ04ErrorV1>) -> bool {
        let cause = match self {
            Self::Input(original) => original.cause,
            Self::Publication(original) => original.cause,
        };
        retain_model_verification(cause, outcome)
    }
}

impl RootOriginalInputLoanV1<'_, '_> {
    pub(crate) fn recheck(&self) -> Result<RawPairedClockSample, CreateQ04ErrorV1> {
        if self.cause.borrow().is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.recheck_owned()
    }

    // The lower Root append receives this same real flight loan, not a
    // caller-supplied qualification flag. Its last sample observes both
    // original cutoffs after the slow native/name/startup checks.
    pub(crate) fn recheck_cut(
        &self,
        identity: &Q04CutIdentityV1,
    ) -> Result<RawPairedClockSample, CreateQ04ErrorV1> {
        let current = self.recheck()?;
        if identity.bytes()[112..128] != self.clock.host_boot_id()
            || identity.bytes()[144..152] != self.clock.boottime_nanoseconds().to_be_bytes()
            || current.boottime_nanoseconds()
                >= u64::from_be_bytes(super::fixed(identity.bytes(), 136))
        {
            return Err(CreateQ04ErrorV1::Expired);
        }
        Ok(current)
    }

    // Negative postchecks preserve physical debt after a first RPC failure;
    // they cannot revive any positive action or change the original cutoff.
    fn recheck_owned(&self) -> Result<RawPairedClockSample, CreateQ04ErrorV1> {
        self.startup.recheck()?;
        self.peer.recheck_stream(self.stream)?;
        require_open_receive_queue(self.stream.as_fd())?;
        self.state.require_protected_named_location(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_STATE_JOURNAL,
            0,
            policy_state_journal_limits(),
        )?;

        recheck_original_clock(self.clock, self.started)
    }

    // These are independent negative bookends, not retry/admission authority.
    // The caller already parked the RPC and Root post in the same reservoir.
    fn recheck_resource_posts(&self, posts: &mut RootResourceSourcePostsV2) {
        posts.owners[1] = Some(self.startup.recheck().map_err(CreateQ04ErrorV1::from));
        posts.owners[2] = Some(self.peer.recheck_stream(self.stream).map_err(CreateQ04ErrorV1::from));
        posts.owners[3] = Some(require_open_receive_queue(self.stream.as_fd()).map_err(CreateQ04ErrorV1::from));
        posts.owners[4] = Some(self.state.require_protected_named_location(
            Path::new(PROTECTED_POLICY_ROOT),
            POLICY_STATE_JOURNAL,
            0,
            policy_state_journal_limits(),
        ).map_err(CreateQ04ErrorV1::from));
        posts.clock = Some(recheck_original_clock(self.clock, self.started));
    }

    // A boolean model-verifier surface must not erase the real first I/O
    // cause. It is latched in the same original attempt before returning false.
    fn require_model_verification(&self, outcome: Result<bool, CreateQ04ErrorV1>) -> bool {
        retain_model_verification(self.cause, outcome)
    }
}

fn retain_model_verification(
    cause: &RefCell<Option<CreateQ04ErrorV1>>,
    outcome: Result<bool, CreateQ04ErrorV1>,
) -> bool {
    match outcome {
        Ok(true) => true,
        Ok(false) => {
            let mut cause = cause.borrow_mut();
            if cause.is_none() {
                *cause = Some(CreateQ04ErrorV1::ChangedCut);
            }
            false
        }
        Err(error) => {
            let mut cause = cause.borrow_mut();
            if cause.is_none() {
                *cause = Some(error);
            }
            false
        }
    }
}

fn recheck_original_flight(
    startup: &ProductionNormalRootStartupV1,
    stream: &RetainedUnixStream,
    peer: &OriginalControllerPolicyPeerV1<'_>,
    clock: RawPairedClockSample,
    started: Instant,
) -> Result<RawPairedClockSample, CreateQ04ErrorV1> {
    startup.recheck()?;
    peer.recheck_stream(stream)?;
    require_open_receive_queue(stream.as_fd())?;
    recheck_original_clock(clock, started)
}

// Both actual-owner views sample the same original cut through one closed
// engine, after their slow physical/startup checks. No phase resets it.
fn recheck_original_clock(
    original: RawPairedClockSample,
    started: Instant,
) -> Result<RawPairedClockSample, CreateQ04ErrorV1> {
    let current = original_root_kernel_pair_v1()?;
    original.validate_later_sample(current).map_err(|_| CreateQ04ErrorV1::Expired)?;
    let cutoff = original.boottime_nanoseconds().checked_add(65_000_000_000)
        .ok_or(CreateQ04ErrorV1::Expired)?;
    if current.boottime_nanoseconds() >= cutoff || started.elapsed() >= MAXIMUM_ROOT_FLIGHT {
        return Err(CreateQ04ErrorV1::Expired);
    }
    Ok(current)
}

// This closed verifier is constructed only above from the same Root loan,
// independently pinned packets and the actual original parent. Repeated
// checks are authority boundaries, not cached digest substitutions.
struct RootCurrentInputVerifierV1<'cut, 'root, 'packet, 'startup> {
    original: RootCurrentOwnerLoanV1<'cut, 'startup>,
    gen1: &'cut Q04RootGen1CutLoanV1<'root>,
    stage: &'cut super::super::binding_v2::Q04RootStageRecipeV1,
    controller: VerifiedControllerProjectAdmissionV1,
    project: &'cut VerifiedSignedProjectPolicySourceV2,
    deployment_head: PolicyDeploymentHeadV1,
    project_input: &'packet [u8],
    deployment_inputs: PolicyDeploymentInputsV1<'packet>,
    controller_packet: &'packet [u8],
    proposed: &'packet [u8],
    purpose: RootInputCurrentPurposeV1<'cut, 'packet>,
}

// Only Held carries real held/Cache evidence. Prehold is deliberately a
// separate, nonissuing DATA purpose; it cannot be used to authenticate a
// publication or drive a durable action through this shared model verifier.
enum RootInputCurrentPurposeV1<'cut, 'packet> {
    Prehold { request_packet: &'packet [u8] },
    Held {
        identity: &'cut Q04CutIdentityV1,
        held: VerifiedControllerHoldReadbackV1,
        held_packet: &'packet [u8],
        cache_packet: &'packet [u8],
        cache: crate::cache_residency::VerifiedClosedCacheOwnerReadbackV2,
        cache_uid: u32,
    },
    TerminalHeld {
        identity: &'cut Q04CutIdentityV1,
        held: VerifiedControllerHoldReadbackV1,
        held_packet: &'packet [u8],
        cache_packet: &'packet [u8],
        cache: crate::cache_residency::VerifiedClosedCacheOwnerReadbackV2,
        cache_uid: u32,
        kind: super::Q04AcknowledgementKindV1,
        acknowledgement: &'packet [u8],
        original_next: u64,
        original_names: crate::journal::ProtectedJournalNamesV1,
    },
    TerminalReleased {
        identity: &'cut Q04CutIdentityV1,
        held: VerifiedControllerHoldReadbackV1,
        held_packet: &'packet [u8],
        cache_packet: &'packet [u8],
        cache: crate::cache_residency::VerifiedClosedCacheOwnerReadbackV2,
        cache_uid: u32,
        kind: super::Q04AcknowledgementKindV1,
        acknowledgement: &'packet [u8],
        original_next: u64,
        original_names: crate::journal::ProtectedJournalNamesV1,
        observed: &'cut crate::cache_residency::CacheResidencyRootReadOnlyPolicyHoldV1,
    },
}

impl RootCurrentInputVerifierV1<'_, '_, '_, '_> {
    fn recheck(&self) -> Result<(), CreateQ04ErrorV1> {
        let now = self.original.recheck()?.wall_seconds();
        self.gen1.recheck()?;
        let (controller, observed_held) = match &self.purpose {
            RootInputCurrentPurposeV1::Prehold { request_packet } => {
                let (request, controller) = self.gen1.prehold_input(request_packet, self.stage)?;
                if request.fields()[5] != self.controller_packet
                    || request.fields()[4] != self.proposed
                {
                    return Err(CreateQ04ErrorV1::ChangedCut);
                }
                let metadata = request.fields()[0];
                let start = u64::from_be_bytes(super::fixed(metadata, 16));
                let cutoff = u64::from_be_bytes(super::fixed(metadata, 24));
                if metadata[..16] != self.original.clock().host_boot_id()
                    || start > self.original.clock().boottime_nanoseconds()
                    || self.original.recheck()?.boottime_nanoseconds() >= cutoff
                {
                    return Err(CreateQ04ErrorV1::Expired);
                }
                (controller, None)
            }
            RootInputCurrentPurposeV1::Held {
                identity, held_packet, ..
            } => {
                let (controller, observed_held) = self.gen1.controller_cut(
                    self.controller_packet, held_packet, self.proposed, self.stage, identity,
                )?;
                (controller, Some(observed_held))
            }
            RootInputCurrentPurposeV1::TerminalHeld {
                identity, held_packet, kind, acknowledgement, original_next, original_names, ..
            } | RootInputCurrentPurposeV1::TerminalReleased {
                identity, held_packet, kind, acknowledgement, original_next, original_names, ..
            } => {
                self.gen1.acknowledgement(*kind, acknowledgement, identity, *original_names)?;
                let (controller, observed_held) = self.gen1.original_controller_provenance(
                    self.controller_packet, held_packet, self.proposed, self.stage, identity, *original_next,
                )?;
                (controller, Some(observed_held))
            }
        };
        let (project, deployment, _) = self.gen1.signed_project_sources(
            self.project_input, &self.deployment_inputs, now,
        )?;
        if let RootInputCurrentPurposeV1::Held { identity, held, cache_packet, cache, cache_uid, .. }
            | RootInputCurrentPurposeV1::TerminalHeld { identity, held, cache_packet, cache, cache_uid, .. }
            = &self.purpose
        {
            let observed_cache = self.gen1.cache_cut(
                cache_packet, self.proposed, self.stage, identity, *cache_uid,
            )?;
            if observed_held != Some(*held) || observed_cache != *cache
                || identity.bytes()[360..392] != *self.gen1.floor().tree_head().as_bytes()
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        if let RootInputCurrentPurposeV1::TerminalReleased {
            identity, held, cache_packet, cache, cache_uid, observed, ..
        } = &self.purpose {
            let original_cache = self.gen1.original_cache_provenance(
                cache_packet, self.proposed, self.stage, identity, *cache_uid,
            )?;
            if observed_held != Some(*held) || original_cache != *cache
                || observed.hold.is_held()
                || observed.hold.record_digest()? != original_cache.hold().q04_released_record_digest()?
                || observed.replay.quota_digest != identity.cache_quota()
                || identity.bytes()[360..392] != *self.gen1.floor().tree_head().as_bytes()
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        let revocation = crate::publisher_policy::project_revocation_digest(
            controller.project(), controller.revocation_scope(), controller.revocation_generation(),
        );
        if controller != self.controller
            || project.head() != self.project.head()
            || project.cache_domain() != self.project.cache_domain()
            || project.revocation() != self.project.revocation()
            || deployment != self.deployment_head
            || project.head().project() != controller.project()
            || project.head().publisher_generation() != controller.publisher_generation()
            || project.head().publisher_digest() != controller.publisher_digest()
            || project.head().prerequisite_claims() != [
                self.gen1.floor().tree_head(), deployment.packet_digest(),
                controller.cache_domain_head(), controller.revocation_head(),
            ]
            || controller.revocation_head() != revocation
            || project.revocation().mode() != controller.revocation_mode()
            || project.revocation().grace_nanos() != controller.revocation_grace_nanos()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.gen1.recheck()?;
        let current = self.original.recheck()?;
        match &self.purpose {
            RootInputCurrentPurposeV1::Prehold { request_packet } => {
                let request = super::Q04PreholdInputDataV1::decode(request_packet)?;
                let cutoff = u64::from_be_bytes(super::fixed(request.fields()[0], 24));
                if current.boottime_nanoseconds() >= cutoff {
                    return Err(CreateQ04ErrorV1::Expired);
                }
            }
            RootInputCurrentPurposeV1::Held { identity, .. }
                | RootInputCurrentPurposeV1::TerminalHeld { identity, .. }
                | RootInputCurrentPurposeV1::TerminalReleased { identity, .. } => {
                if current.host_boot_id() != super::fixed(identity.bytes(), 112)
                    || current.boottime_nanoseconds() >= u64::from_be_bytes(super::fixed(identity.bytes(), 136))
                {
                    return Err(CreateQ04ErrorV1::Expired);
                }
            }
        }
        Ok(())
    }

    // Both purposes reuse the same authenticated layer/relation and compiler
    // constructors. The repeated purpose-specific checks are intentionally
    // kept around each brand/allocation boundary rather than cached once.
    fn compile_authenticated_input(
        &self,
        deployment: &super::super::PolicyDeploymentSourcesV1,
    ) -> Result<
        (PolicyCompilerInputV1, PolicyPublicationPrerequisitesV1, ObjectDigest, CompiledPolicyCandidateV1),
        CreateQ04ErrorV1,
    > {
        let domain = AuthenticatedCacheDomainV1::authenticate(
            self.project.cache_domain(),
            CacheDomainBindingV1::Project(self.controller.project()), self,
        ).map_err(super::super::CurrentCreateCompilerInputErrorV1::from)?;
        self.recheck()?;
        let layer = self.project.q04_layer_recipe().materialize_with_authenticated_binding(domain)?;
        let relation = AuthenticatedSandboxProjectRelationV1::authenticate(
            self.controller.sandbox(), self.controller.project(), self,
        ).map_err(super::super::CurrentCreateCompilerInputErrorV1::from)?;
        self.recheck()?;
        let input = super::super::public_create_source::parentless_create_input_from_authenticated_layers_v1(
            relation, layer, deployment,
        )?;
        let prerequisites = PolicyPublicationPrerequisitesV1::new(
            self.gen1.floor().tree_head(), self.deployment_head.packet_digest(),
            self.controller.cache_domain_head(), self.controller.revocation_head(),
            self.stage.staged().base().next_generation(),
        )?;
        self.recheck()?;
        let normalized = normalized_policy_input_digest_v1(&input).map_err(|_| super::super::PolicyCompilerJournalErrorV1::NonCanonicalPublication)?;
        let candidate = PolicyCompilerV1::compile_retained(&input)?;
        self.recheck()?;
        Ok((input, prerequisites, normalized, candidate))
    }

    fn verify_descriptor(
        &self,
        descriptor: &ObjectDescriptor,
        canonical_bytes: &[u8],
    ) -> Result<bool, CreateQ04ErrorV1> {
        self.recheck()?;
        let media = MediaType::new(PortableMediaType::Content.as_str())
            .map_err(|_| CreateQ04ErrorV1::ChangedCut)?;
        let matches = !canonical_bytes.is_empty()
            && descriptor_for_bytes(media, canonical_bytes) == *descriptor;
        self.recheck()?;
        Ok(matches)
    }
}

impl CacheDomainVerifierV1 for RootCurrentInputVerifierV1<'_, '_, '_, '_> {
    fn verify(&self, descriptor: &ObjectDescriptor, canonical_bytes: &[u8]) -> bool {
        self.original.require_model_verification(self.verify_descriptor(descriptor, canonical_bytes))
    }
}

impl SandboxProjectRelationVerifierV1 for RootCurrentInputVerifierV1<'_, '_, '_, '_> {
    fn verify(
        &self,
        sandbox: aos_sandbox_core::SandboxId,
        project: aos_sandbox_core::ProjectId,
        descriptor: &ObjectDescriptor,
        canonical_bytes: &[u8],
    ) -> bool {
        self.original.require_model_verification(
            if sandbox == self.controller.sandbox() && project == self.controller.project() {
                self.verify_descriptor(descriptor, canonical_bytes)
            } else {
                Ok(false)
            },
        )
    }
}

// Prehold supplies provenance only. The held publication position separately
// rejoins the real original Root/gen1/Controller/Cache cut; copied prerequisite
// fields cannot select it. Generic effect completion remains unavailable.
impl super::super::protected_journal::PolicyPublicationVerifierV1
    for RootCurrentInputVerifierV1<'_, '_, '_, '_>
{
    fn prerequisite_evidence_is_authentic(
        &self,
        prerequisites: &PolicyPublicationPrerequisitesV1,
    ) -> bool {
        self.original.require_model_verification(self.recheck().map(|()| {
            prerequisites.ancestry_head() == self.gen1.floor().tree_head()
                && prerequisites.compiler_authority_head() == self.deployment_head.packet_digest()
                && prerequisites.cache_domain_head() == self.controller.cache_domain_head()
                && prerequisites.revocation_head() == self.controller.revocation_head()
                && prerequisites.generation() == self.stage.staged().base().next_generation()
        }))
    }

    fn prerequisites_are_current(&self, prerequisites: &PolicyPublicationPrerequisitesV1) -> bool {
        if !matches!(&self.purpose, RootInputCurrentPurposeV1::Held { .. }) {
            return false;
        }
        self.prerequisite_evidence_is_authentic(prerequisites)
    }

    fn while_prerequisites_current<T>(
        &self,
        prerequisites: &PolicyPublicationPrerequisitesV1,
        action: impl FnOnce() -> T,
    ) -> Option<T> {
        if !matches!(&self.original, RootCurrentOwnerLoanV1::Publication(_))
            || !self.prerequisites_are_current(prerequisites)
        {
            return None;
        }
        // The same Root writer/current-floor loan and original external cut
        // remain borrowed through the action. Its actual returned ownership
        // must be parked by the enclosing fixed caller BEFORE postchecks;
        // adding a fallible postcheck here would drop an ambiguous outcome.
        Some(action())
    }

    fn while_effect_observation_current<T>(
        &self,
        _prerequisites: &PolicyPublicationPrerequisitesV1,
        _request: &super::super::protected_journal::PolicyEffectObservationRequestV1,
        _action: impl FnOnce(super::super::protected_journal::VerifiedPolicyEffectObservationV1) -> T,
    ) -> Option<T> {
        None
    }

    fn verify(
        &self,
        project: aos_sandbox_core::ProjectId,
        sandbox: aos_sandbox_core::SandboxId,
        normalized_input: ObjectDigest,
        candidate: ObjectDigest,
        prerequisites: &PolicyPublicationPrerequisitesV1,
    ) -> bool {
        let RootInputCurrentPurposeV1::Held { identity, .. } = &self.purpose else {
            return false;
        };
        self.original.require_model_verification(self.recheck().map(|()| {
            project == self.controller.project()
                && sandbox == self.controller.sandbox()
                && project == identity.project()
                && sandbox == identity.sandbox()
                && normalized_input.as_bytes() == &identity.bytes()[456..488]
                && candidate.as_bytes() == &identity.bytes()[488..520]
                && prerequisites.ancestry_head() == self.gen1.floor().tree_head()
                && prerequisites.compiler_authority_head() == self.deployment_head.packet_digest()
                && prerequisites.cache_domain_head() == self.controller.cache_domain_head()
                && prerequisites.revocation_head() == self.controller.revocation_head()
                && prerequisites.generation() == identity.epoch()
        }))
    }
}

impl Drop for OriginalRootCreateQ04AttemptV1<'_> {
    fn drop(&mut self) {
        if !self.cleared {
            // This negative owner must not release a writer/socket/partial on
            // error or unwind. OS process death disposes it; this is not Drain,
            // a rollback, retry or proof of resource retirement.
            if self.cause.get_mut().is_none()
                && !matches!(self.shutdown_result, Some(Err(_)))
            {
                *self.cause.get_mut() = Some(CreateQ04ErrorV1::Unwind);
            }
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical inert DATA only. No genuine owner, floor, native commit,
    // currentness, capacity reservation or deployment fixture is constructed.
    fn cut() -> Q04CutIdentityV1 {
        let mut body = [0; super::super::IDENTITY_BYTES];
        body[16..80].fill(1);
        body[80..84].copy_from_slice(&1000_u32.to_be_bytes());
        body[84..88].copy_from_slice(&1001_u32.to_be_bytes());
        body[88..104].copy_from_slice(&[1_u64.to_be_bytes(), 1_u64.to_be_bytes()].concat());
        body[112..128].fill(2);
        for (offset, value) in [(128, 100_u64), (136, 60_000_000_100),
            (144, 200), (152, 65_000_000_200), (160, 7)]
        {
            body[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        body[168..184].fill(3);
        body[184..200].fill(4);
        for (index, start) in (200..648).step_by(32).enumerate() {
            body[start..start + 32].fill(5 + index as u8);
        }
        Q04CutIdentityV1::from_body(body).unwrap()
    }

    #[test]
    fn root_record_keys_keep_the_funded_exact_namespace_widths() {
        let nonce = [1; 16];

        for (key, expected) in [
            (RootQ04RecordKeyV1::Cut, 37),
            (RootQ04RecordKeyV1::Phase(1), 40),
            (RootQ04RecordKeyV1::Decision, 42),
            (RootQ04RecordKeyV1::Packet(4), 41),
            (RootQ04RecordKeyV1::ClaimIndex, 45),
            (RootQ04RecordKeyV1::ClaimChunk(341), 41),
        ] {
            assert_eq!(key.encode(nonce).unwrap().len(), expected);
            assert!(key.encode([0; 16]).is_err());
        }
        assert!(RootQ04RecordKeyV1::Phase(8).encode(nonce).is_err());
        assert!(RootQ04RecordKeyV1::Packet(5).encode(nonce).is_err());
    }

    #[test]
    fn root_phase_capacity_recipe_requires_the_actual_prior_release_row_digest() {
        let cut = cut();
        let before = ObjectDigest::from_bytes([1; 32]);
        let zero = ObjectDigest::from_bytes([0; 32]);
        let pairs = [ObjectDigest::from_bytes([2; 32]); 6];
        let r5 = root_phase_record(&cut, 5, [5; 16], before, Some(before),
            [before, before, ObjectDigest::from_bytes([3; 32]), zero, zero],
            pairs, Some(before)).unwrap();
        let wrong = root_phase_record(&cut, 6, [6; 16], before, Some(r5.digest()),
            [before, before, ObjectDigest::from_bytes([4; 32]), zero, zero],
            pairs, Some(before)).unwrap();

        assert!(wrong.require_successor(&r5).is_err());

        let correct = root_phase_record(&cut, 6, [6; 16], before, Some(r5.digest()),
            [before, before, r5.digest(), zero, zero], pairs, Some(before)).unwrap();
        correct.require_successor(&r5).unwrap();
        assert_eq!(&r5.bytes()[320..352], &[0; 32]);
        assert_ne!(&correct.bytes()[320..352], &[0; 32]);
        assert_eq!(&correct.bytes()[192..288], &[0; 96]);
    }

    #[test]
    fn capacity_acknowledgement_is_not_an_authentic_controller_packet() {
        use super::super::{Q04AcknowledgementKindV1, Q04AcknowledgementV1};

        let cut = cut();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let credential = crate::policy_compiler::encode_controller_hold_signer_credential_v1(
            1, &key.verifying_key(),
        ).unwrap();
        let pin = crate::policy_compiler::PinnedControllerHoldSignerV1::decode(&credential).unwrap();
        let kind = Q04AcknowledgementKindV1::Policy;
        let mut packet = Vec::new();

        root_capacity_acknowledgement(&mut packet, kind, &cut, 7,
            ObjectDigest::from_bytes([3; 32]), [ObjectDigest::from_bytes([2; 32]); 6]).unwrap();

        assert_eq!(packet.len(), 408);
        assert_eq!(&packet[76..84], &16_u64.to_be_bytes());
        assert!(matches!(Q04AcknowledgementV1::verify(kind, &packet, &pin, &cut),
            Err(CreateQ04ErrorV1::AcknowledgementSignature(_))));
    }
}
