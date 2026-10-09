//! Subdivides an already-paid Project interval in the first Q04 hold.
//!
//! The native association is replay DATA, not a transferable permission:
//! ```text
//! AOSRSQ01 | original787 | grant531 | use531 | Spec/compile joins184 | SHA32
//! AOSRSQ02 | same body2041 | normalized32 | input-sha32 | input-bytes8 |
//!            Project-continuation176 | Q-intake-id16 | observer-quota8 | SHA32
//! ```
//! All six bank members share the existing Controller hold transaction. Q02
//! adds the full AOSPCO03 input after them, without changing bank indices. The
//! parent remains charged for the original total, and the child remains charged
//! for its operation use even after the owning invocation becomes uncertain.

use std::cell::OnceCell;

use aos_sandbox_core::model::LimitValue;
use aos_sandbox_core::{
    RawPairedClockSample, ResourceAccount, ResourceCeilings,
    ResourceDimension, ResourceVector,
};
use sha2::{Digest as _, Sha256};

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::policy_compiler::create_q04::{
    CreateQ04ErrorV1, OriginalCreateQ04InvocationV1, Q04ControllerPreparationV1,
    Q04CutIdentityV1,
};
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

use super::{
    AccountHead, AccountKind, Claim, ClaimPurpose, ClaimState, NativeCrossing,
    PreparationBinding, ResourceReservationErrorV1, Transition, TransitionOriginal,
    codec, replay,
};

pub(super) const PREFIX: u8 = b'q';
pub(super) const RECORD_BYTES: usize = 2073;
const INPUT_RECORD_BYTES: usize = 2345;
pub(crate) const BANK_MEMBERS: usize = 6;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Binding {
    original: PreparationBinding,
    grant: Claim,
    use_claim: Claim,
    specification: [u8; 32],
    specification_size: u64,
    specification_record: [u8; 32],
    specification_operation: [u8; 16],
    specification_request: [u8; 32],
    candidate: [u8; 32],
    policy_binding: [u8; 32],
    origin: Option<InputAssociation>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct InputAssociation {
    normalized: [u8; 32],
    digest: [u8; 32],
    bytes: u64,
    continuation: ResourceVector,
    intake: [u8; 16],
    observations: u64,
}

/// Owns the exact co-issued native mutation and its sole crossing observation.
pub(crate) struct Q04ResourceTransferV1 {
    before: AccountHead,
    after: AccountHead,
    residual: Claim,
    child: AccountHead,
    pub(super) binding: Binding,
    pub(super) original_clock: RawPairedClockSample,
    crossing: OnceCell<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    last_clock: OnceCell<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    transaction: OnceCell<JournalTransaction>,
    specification: crate::sandbox_spec_state::DurableSandboxSpecV1,
    input_origin: Vec<u8>,
}

impl Q04ResourceTransferV1 {
    pub(crate) fn prepare(
        journal: &Journal,
        root: &OriginalCreateQ04InvocationV1<'_>,
        ledger: &crate::reconciler::OriginalQ04ControllerLedgerV1,
        prepared: &Q04ControllerPreparationV1,
        identity: &Q04CutIdentityV1,
    ) -> Result<Self, CreateQ04ErrorV1> {
        root.recheck_resource_bank(journal)?;
        let original = root.resource_preparation()?;
        let retained = original.original_binding().map_err(resource_error)?;
        let root_loan = root.cache_terminal_loan(identity)?;
        root_loan.cache_signing_challenge(prepared.staged(), prepared.proposed())?;
        ledger.require_identity(identity)?;
        let candidate = prepared.candidate();
        if identity.bytes()[488..520] != *candidate.commitment().digest().as_bytes()
            || retained.claim.operation != identity.operation().into_bytes()
            || retained.claim.project != identity.project().into_bytes()
            || retained.nonce != identity.nonce()
            || retained.floor != *identity.gen1_floor().as_bytes()
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }

        // The immutable Spec comes from the same original Request/Desired
        // descriptor, not a Runtime (which does not yet exist for fresh Create).
        let specification = crate::sandbox_spec_state::get(journal, ledger.specification())
            .map_err(|error| resource_error(ResourceReservationErrorV1::Specification(Box::new(error))))?
            .ok_or(CreateQ04ErrorV1::ChangedCut)?;
        let requested = specification.spec().resource_profile().limits();
        let resolved = candidate.hard_resources().core_profile().limits();
        if requested.len() != 16 || resolved.len() != 16 {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        for (index, (requested, resolved)) in requested.iter().zip(resolved).enumerate() {
            let LimitValue::Bounded(actual) = resolved.value() else {
                return Err(CreateQ04ErrorV1::ChangedCut);
            };
            if requested.dimension() as usize != index
                || requested.dimension() != resolved.dimension()
                || requested.enforcement() != resolved.enforcement()
                || match requested.value() {
                    LimitValue::Inherited => false,
                    LimitValue::Bounded(limit) => actual > limit,
                    LimitValue::Unlimited(_) => true,
                }
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        let amount = crate::policy_compiler::create_q04::candidate_capacity(candidate)?;
        let demand = root.original_input_demand(amount)?;
        let retained_use = demand.retained();
        let (intake, observations) = root.original_intake_association()?;
        prepared.input_origin().require_identity(identity)?;
        let origin = InputAssociation {
            normalized: identity.bytes()[456..488].try_into().map_err(|_| CreateQ04ErrorV1::Bounds)?,
            digest: prepared.input_origin().raw_digest(),
            bytes: u64::try_from(prepared.input_origin().bytes().len()).map_err(|_| CreateQ04ErrorV1::Bounds)?,
            continuation: demand.continuation(), intake, observations,
        };
        let residual = Claim {
            amount: retained.claim.amount.checked_sub(amount).map_err(|error| resource_error(error.into()))?,
            ..retained.claim
        };
        let state = journal.controller_resource_state_v1()?;
        replay::validate(state).map_err(resource_error)?;
        let before = replay::find_head(state, retained.claim.account).map_err(resource_error)?;
        let after = AccountHead {
            generation: before.generation.checked_add(1).ok_or(CreateQ04ErrorV1::Bounds)?,
            // Subdivision changes no total charge in this immediate parent.
            ..before
        };
        let sandbox = identity.sandbox().into_bytes();
        let child = AccountHead {
            enrollment: before.enrollment, id: sandbox, parent: before.id,
            kind: AccountKind::Sandbox, generation: 1, project: before.project,
            sandbox, tree_revision: before.tree_revision, baseline: ResourceVector::ZERO,
            account: ResourceAccount::from_usage(
                ResourceCeilings::bounded(amount), ResourceVector::ZERO, retained_use,
            ).map_err(|error| resource_error(error.into()))?,
        };
        let grant = Claim {
            id: derived_id(b"AOS-Q04-INCLUSIVE-GRANT-V1", identity),
            child: sandbox, sandbox, purpose: ClaimPurpose::InclusiveGrant, amount,
            ..retained.claim
        };
        let use_claim = Claim {
            id: derived_id(b"AOS-Q04-RETAINED-USE-V1", identity),
            account: sandbox, child: [0; 16], sandbox,
            purpose: ClaimPurpose::Q04Preparation, amount: retained_use, ..grant
        };
        let binding = Binding {
            original: retained, grant, use_claim,
            specification: *specification.descriptor().digest().as_bytes(),
            specification_size: specification.descriptor().encoded_size(),
            specification_record: *specification.record_digest().as_bytes(),
            specification_operation: specification.operation_id().into_bytes(),
            specification_request: *specification.request_digest().as_bytes(),
            candidate: *candidate.commitment().digest().as_bytes(),
            policy_binding: *identity.binding().as_bytes(),
            origin: Some(origin),
        };
        let transfer = Self {
            before, after, residual, child, binding,
            original_clock: original.original_clock().map_err(resource_error)?,
            crossing: OnceCell::new(),
            last_clock: OnceCell::new(),
            transaction: OnceCell::new(),
            specification,
            input_origin: prepared.input_origin().bytes().to_vec(),
        };
        transfer.require_predecessor(state).map_err(resource_error)?;
        root_loan.recheck()?;
        Ok(transfer)
    }

    pub(crate) fn append_records(&self, records: &mut Vec<JournalRecord>) -> Result<(), CreateQ04ErrorV1> {
        records.try_reserve_exact(BANK_MEMBERS + 1)?;
        records.extend(self.records().map_err(resource_error)?);
        records.push(self.origin_record());
        Ok(())
    }

    fn origin_record(&self) -> JournalRecord {
        JournalRecord::put(RecordNamespace::ControllerPolicyHold,
            crate::policy_compiler::create_q04::CONTROLLER_INPUT_ORIGIN_KEY.to_vec(),
            self.input_origin.clone())
    }

    fn records(&self) -> Result<[JournalRecord; BANK_MEMBERS], ResourceReservationErrorV1> {
        let row = |prefix, id, bytes: Vec<u8>| JournalRecord::put(
            RecordNamespace::ControllerResourceReservation, replay::key(prefix, id).to_vec(), bytes,
        );
        Ok([
            row(replay::HEAD_PREFIX, self.after.id, codec::encode_head(self.after)?.to_vec()),
            row(replay::CLAIM_PREFIX, self.residual.id, codec::encode_claim(self.residual)?.to_vec()),
            row(replay::CLAIM_PREFIX, self.binding.grant.id, codec::encode_claim(self.binding.grant)?.to_vec()),
            row(replay::HEAD_PREFIX, self.child.id, codec::encode_head(self.child)?.to_vec()),
            row(replay::CLAIM_PREFIX, self.binding.use_claim.id, codec::encode_claim(self.binding.use_claim)?.to_vec()),
            row(PREFIX, self.residual.id, encode(self.binding)?.to_vec()),
        ])
    }

    fn require_predecessor(&self, state: &replay::State) -> Result<(), ResourceReservationErrorV1> {
        let original = self.binding.original;
        if replay::validate(state)? != Some(self.before.enrollment)
            || replay::find_head(state, self.before.id)? != self.before
            || self.before.kind != AccountKind::Project
            || original.claim.enrollment != self.before.enrollment
            || original.claim.account != self.before.id
            || original.claim.project != self.before.project
            || original.claim.tree_revision != self.before.tree_revision
            || self.after != (AccountHead { generation: self.before.generation.checked_add(1)
                .ok_or(ResourceReservationErrorV1::Conflict)?, ..self.before })
            || replay::record_bytes(state, replay::CLAIM_PREFIX, original.claim.id)
                .map(codec::decode_claim).transpose()? != Some(original.claim)
            || replay::record_bytes(state, replay::PREPARATION_PREFIX, original.claim.id)
                .map(codec::decode_preparation).transpose()? != Some(original)
            || replay::has_head(state, self.child.id)
            || [self.binding.grant.id, self.binding.use_claim.id].into_iter().any(|id|
                replay::record_bytes(state, replay::CLAIM_PREFIX, id).is_some())
            || replay::record_bytes(state, PREFIX, original.claim.id).is_some()
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        require_binding(self.binding)?;
        if self.residual != residual_claim(self.binding)? || self.child != child_head(self.binding)? {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn require_current(&self, state: &replay::State, transaction: &JournalTransaction) -> Result<(), ResourceReservationErrorV1> {
        self.require_predecessor(state)?;
        if transaction.records().len() != 4 + BANK_MEMBERS
            || transaction.records()[3..9] != self.records()?
            || !self.matches_retained_origin(&transaction.records()[9])
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        Ok(())
    }

    pub(crate) fn crossing(&self) -> Transition<'_> {
        let deadline = match self.binding.original.claim.cut {
            super::ClaimCut::Operation { deadline_boottime_nanoseconds, .. } => deadline_boottime_nanoseconds,
            super::ClaimCut::BootLifetime => 0,
        };
        Transition {
            original: TransitionOriginal::Q04(self),
            crossing: Some(NativeCrossing {
                original: self.original_clock, deadline, result: &self.crossing,
            }),
        }
    }

    pub(crate) fn crossing_failure(&self) -> Option<&SourceGenesisErrorV1> {
        self.crossing.get().and_then(|result| result.as_ref().err())
    }

    pub(crate) fn capture_last_clock(&self) -> Result<(), ()> {
        if self.last_clock.get().is_some() { return Err(()); }
        let result = self.last_clock.get_or_init(|| {
            crate::policy_compiler::observe_root_first_source_successor_clock_v2(Some(self.original_clock))
                .and_then(|sample| match self.binding.original.claim.cut {
                    super::ClaimCut::Operation { deadline_boottime_nanoseconds, .. }
                        if sample.boottime_nanoseconds() < deadline_boottime_nanoseconds => Ok(sample),
                    _ => Err(SourceGenesisErrorV1::Stale),
                })
        });
        if result.is_ok() { Ok(()) } else { Err(()) }
    }

    pub(crate) fn last_clock_failure(&self) -> Option<&SourceGenesisErrorV1> {
        self.last_clock.get().and_then(|result| result.as_ref().err())
    }

    pub(crate) fn require_last_clock(&self) -> Result<(), ResourceReservationErrorV1> {
        if matches!(self.last_clock.get(), Some(Ok(_))) { Ok(()) }
        else { Err(ResourceReservationErrorV1::Conflict) }
    }

    pub(crate) fn retain_transaction(&self, transaction: &JournalTransaction) -> Result<(), CreateQ04ErrorV1> {
        if self.transaction.get().is_some() || transaction.records().len() != 4 + BANK_MEMBERS
            || transaction.records()[3..9] != self.records().map_err(resource_error)?
            || !self.matches_retained_origin(&transaction.records()[9])
        {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        self.transaction.set(transaction.clone()).map_err(|_| CreateQ04ErrorV1::ChangedCut)
    }

    pub(crate) fn require_readback(&self, journal: &Journal) -> Result<(), ResourceReservationErrorV1> {
        if !matches!(self.crossing.get(), Some(Ok(_))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        if self.specification.descriptor().digest().as_bytes() != &self.binding.specification
            || self.specification.record_digest().as_bytes() != &self.binding.specification_record
            || !matches_origin_bytes(self.binding, &self.input_origin)?
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let state = journal.controller_resource_state_v1()?;
        let transaction = self.transaction.get().ok_or(ResourceReservationErrorV1::Conflict)?;
        if !journal.controller_resource_contains_transaction_v1(transaction.id())? {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        replay::validate(state)?;
        if replay::find_head(state, self.after.id)? != self.after {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        require_replayed(state, self.binding)
    }

    fn matches_retained_origin(&self, record: &JournalRecord) -> bool {
        record.namespace() == RecordNamespace::ControllerPolicyHold
            && record.key() == crate::policy_compiler::create_q04::CONTROLLER_INPUT_ORIGIN_KEY
            && record.value() == Some(self.input_origin.as_slice())
    }
}

fn derived_id(domain: &[u8], identity: &Q04CutIdentityV1) -> [u8; 16] {
    let digest = Sha256::new().chain_update(domain).chain_update(identity.digest().as_bytes()).finalize();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

fn resource_error(error: ResourceReservationErrorV1) -> CreateQ04ErrorV1 {
    CreateQ04ErrorV1::ResourceReservation(Box::new(error))
}

pub(super) fn residual_claim(binding: Binding) -> Result<Claim, ResourceReservationErrorV1> {
    Ok(Claim { amount: binding.original.claim.amount.checked_sub(binding.grant.amount)?, ..binding.original.claim })
}

pub(super) fn child_head(binding: Binding) -> Result<AccountHead, ResourceReservationErrorV1> {
    let grant = binding.grant;
    Ok(AccountHead {
        enrollment: grant.enrollment, id: grant.child, parent: grant.account,
        kind: AccountKind::Sandbox, generation: 1, project: grant.project,
        sandbox: grant.sandbox, tree_revision: grant.tree_revision,
        baseline: ResourceVector::ZERO,
        account: ResourceAccount::from_usage(ResourceCeilings::bounded(grant.amount), ResourceVector::ZERO, binding.use_claim.amount)?,
    })
}

fn require_binding(binding: Binding) -> Result<(), ResourceReservationErrorV1> {
    let original = binding.original.claim;
    let grant = binding.grant;
    let use_claim = binding.use_claim;
    if grant != (Claim {
        id: grant.id, child: grant.child, sandbox: grant.sandbox,
        purpose: ClaimPurpose::InclusiveGrant, amount: grant.amount, ..original
    }) || grant.sandbox == [0; 16] || grant.child != grant.sandbox
        || use_claim != (Claim {
            id: use_claim.id, account: grant.child, child: [0; 16],
            purpose: ClaimPurpose::Q04Preparation, amount: use_claim.amount, ..grant
        }) || [original.id, grant.id, use_claim.id].iter().enumerate().any(|(index, id)|
            *id == [0; 16] || [original.id, grant.id, use_claim.id][..index].contains(id))
        || binding.specification_size == 0 || binding.specification_operation == [0; 16]
        || [binding.specification, binding.specification_record, binding.specification_request,
            binding.candidate, binding.policy_binding].contains(&[0; 32])
        || original.state != ClaimState::Reserved
    {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    match binding.origin {
        None if use_claim.amount != grant.amount => return Err(ResourceReservationErrorV1::CorruptLedger),
        Some(origin) => {
            if origin.normalized == [0; 32] || origin.digest == [0; 32]
                || origin.bytes == 0 || origin.bytes > 4 * 1024 * 1024
                || origin.intake == [0; 16] || origin.observations < 27
            {
                return Err(ResourceReservationErrorV1::CorruptLedger);
            }
            grant.amount.checked_sub(use_claim.amount)?;
            residual_claim(binding)?.amount.checked_sub(origin.continuation)?;
            original.amount.checked_sub(use_claim.amount.checked_add(origin.continuation)?)?;
        }
        None => {}
    }
    residual_claim(binding)?;
    codec::encode_claim(grant)?;
    codec::encode_claim(use_claim)?;
    Ok(())
}

pub(super) fn require_replayed(state: &replay::State, binding: Binding) -> Result<(), ResourceReservationErrorV1> {
    require_binding(binding)?;
    if let Some(origin) = binding.origin {
        let intake = codec::decode_claim(replay::record_bytes(state, replay::CLAIM_PREFIX, origin.intake)
            .ok_or(ResourceReservationErrorV1::CorruptLedger)?)?;
        if intake.purpose != ClaimPurpose::Q04OriginalIntake
            || intake.state != ClaimState::Committed
            || intake.enrollment != binding.original.claim.enrollment
        {
            return Err(ResourceReservationErrorV1::CorruptLedger);
        }
        let bytes = state.get(&(RecordNamespace::ControllerPolicyHold,
            crate::policy_compiler::create_q04::CONTROLLER_INPUT_ORIGIN_KEY.to_vec()))
            .ok_or(ResourceReservationErrorV1::CorruptLedger)?;
        if !matches_origin_bytes(binding, bytes)? {
            return Err(ResourceReservationErrorV1::CorruptLedger);
        }
    }
    // Original co-issuance remains immutable. Only an exact typed terminal
    // successor may change its current use/head; a newer generation alone
    // cannot waive the original association or create spare capacity.
    let (use_claim, child) = super::settlement::current_use(state, binding)?;
    for claim in [residual_claim(binding)?, binding.grant, use_claim] {
        if replay::record_bytes(state, replay::CLAIM_PREFIX, claim.id).map(codec::decode_claim).transpose()? != Some(claim) {
            return Err(ResourceReservationErrorV1::CorruptLedger);
        }
    }
    if replay::find_head(state, binding.grant.child)? != child
        || replay::record_bytes(state, replay::PREPARATION_PREFIX, binding.original.claim.id)
            .map(codec::decode_preparation).transpose()? != Some(binding.original)
        || replay::record_bytes(state, PREFIX, binding.original.claim.id).map(decode).transpose()? != Some(binding)
    {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    Ok(())
}

pub(super) fn original_claim(binding: Binding) -> Claim { binding.original.claim }

pub(super) fn contains_use(binding: Binding, claim: Claim) -> bool {
    claim == binding.use_claim
        || claim == (Claim { state: ClaimState::Committed, ..binding.use_claim })
}

pub(super) fn use_claim(binding: Binding) -> Claim { binding.use_claim }

pub(super) fn has_input_origin(binding: Binding) -> bool { binding.origin.is_some() }

pub(super) fn require_input_history(
    state: &replay::State,
    identity: &Q04CutIdentityV1,
    bytes: Option<&[u8]>,
) -> Result<(), ResourceReservationErrorV1> {
    let mut selected = None;
    for ((namespace, key), value) in state {
        if *namespace != RecordNamespace::ControllerResourceReservation
            || key.first() != Some(&PREFIX)
        {
            continue;
        }
        let binding = decode(value)?;
        if binding.original.claim.operation != identity.operation().into_bytes() {
            continue;
        }
        if selected.replace(binding).is_some() {
            return Err(ResourceReservationErrorV1::CorruptLedger);
        }
    }
    match (selected, bytes) {
        (Some(binding), Some(bytes)) if has_input_origin(binding) => {
            crate::policy_compiler::create_q04::require_origin_identity(bytes, identity)
                .map_err(|_| ResourceReservationErrorV1::CorruptLedger)?;
            if !matches_origin_bytes(binding, bytes)? {
                return Err(ResourceReservationErrorV1::CorruptLedger);
            }
            require_replayed(state, binding)
        }
        (Some(binding), None) if !has_input_origin(binding) => Ok(()),
        (None, None) => Ok(()),
        _ => Err(ResourceReservationErrorV1::CorruptLedger),
    }
}

pub(super) fn matches_origin_record(binding: Binding, record: &JournalRecord) -> Result<bool, ResourceReservationErrorV1> {
    if record.namespace() != RecordNamespace::ControllerPolicyHold
        || record.key() != crate::policy_compiler::create_q04::CONTROLLER_INPUT_ORIGIN_KEY
    {
        return Ok(false);
    }
    match record.value() {
        Some(bytes) => matches_origin_bytes(binding, bytes),
        None => Ok(false),
    }
}

fn matches_origin_bytes(binding: Binding, bytes: &[u8]) -> Result<bool, ResourceReservationErrorV1> {
    let Some(origin) = binding.origin else { return Ok(false); };
    if bytes.len() as u64 != origin.bytes || <[u8; 32]>::from(Sha256::digest(bytes)) != origin.digest {
        return Ok(false);
    }
    let input = crate::policy_compiler::RetainedPublisherCompilerOriginV3::from_record_bytes(bytes)
        .map_err(|_| ResourceReservationErrorV1::CorruptLedger)?;
    Ok(input.project().into_bytes() == binding.grant.project
        && input.original_target().into_bytes() == binding.grant.sandbox
        && input.normalized_input().as_bytes() == &origin.normalized
        && input.candidate().as_bytes() == &binding.candidate)
}

pub(super) enum EncodedBinding {
    Legacy([u8; RECORD_BYTES]),
    Input([u8; INPUT_RECORD_BYTES]),
}

impl EncodedBinding {
    pub(super) fn as_slice(&self) -> &[u8] {
        match self {
            Self::Legacy(bytes) => bytes,
            Self::Input(bytes) => bytes,
        }
    }

    pub(super) fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

impl AsRef<[u8]> for EncodedBinding {
    fn as_ref(&self) -> &[u8] { self.as_slice() }
}

pub(super) fn encode(binding: Binding) -> Result<EncodedBinding, ResourceReservationErrorV1> {
    require_binding(binding)?;
    let mut encoded = if binding.origin.is_some() {
        EncodedBinding::Input([0; INPUT_RECORD_BYTES])
    } else {
        EncodedBinding::Legacy([0; RECORD_BYTES])
    };
    let bytes: &mut [u8] = match &mut encoded {
        EncodedBinding::Legacy(bytes) => bytes,
        EncodedBinding::Input(bytes) => bytes,
    };
    bytes[..8].copy_from_slice(if binding.origin.is_some() { b"AOSRSQ02" } else { b"AOSRSQ01" });
    bytes[8..795].copy_from_slice(&codec::encode_preparation(binding.original)?);
    bytes[795..1326].copy_from_slice(&codec::encode_claim(binding.grant)?);
    bytes[1326..1857].copy_from_slice(&codec::encode_claim(binding.use_claim)?);
    bytes[1857..1889].copy_from_slice(&binding.specification);
    bytes[1889..1897].copy_from_slice(&binding.specification_size.to_be_bytes());
    bytes[1897..1929].copy_from_slice(&binding.specification_record);
    bytes[1929..1945].copy_from_slice(&binding.specification_operation);
    bytes[1945..1977].copy_from_slice(&binding.specification_request);
    bytes[1977..2009].copy_from_slice(&binding.candidate);
    bytes[2009..2041].copy_from_slice(&binding.policy_binding);
    if let Some(origin) = binding.origin {
        bytes[2041..2073].copy_from_slice(&origin.normalized);
        bytes[2073..2105].copy_from_slice(&origin.digest);
        bytes[2105..2113].copy_from_slice(&origin.bytes.to_be_bytes());
        for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
            let start = 2113 + index * 8;
            bytes[start..start + 8].copy_from_slice(&origin.continuation.get(dimension).to_be_bytes());
        }
        bytes[2289..2305].copy_from_slice(&origin.intake);
        bytes[2305..2313].copy_from_slice(&origin.observations.to_be_bytes());
    }
    let end = bytes.len() - 32;
    let checksum = Sha256::digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&checksum);
    Ok(encoded)
}

pub(super) fn decode(bytes: &[u8]) -> Result<Binding, ResourceReservationErrorV1> {
    let input = bytes.len() == INPUT_RECORD_BYTES && bytes.get(..8) == Some(b"AOSRSQ02");
    if !input && (bytes.len() != RECORD_BYTES || bytes.get(..8) != Some(b"AOSRSQ01")) {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    let fixed = |range: std::ops::Range<usize>| -> Result<[u8; 32], ResourceReservationErrorV1> {
        bytes[range].try_into().map_err(|_| ResourceReservationErrorV1::CorruptLedger)
    };
    let binding = Binding {
        original: codec::decode_preparation(&bytes[8..795])?,
        grant: codec::decode_claim(&bytes[795..1326])?,
        use_claim: codec::decode_claim(&bytes[1326..1857])?,
        specification: fixed(1857..1889)?,
        specification_size: u64::from_be_bytes(bytes[1889..1897].try_into().map_err(|_| ResourceReservationErrorV1::CorruptLedger)?),
        specification_record: fixed(1897..1929)?,
        specification_operation: bytes[1929..1945].try_into().map_err(|_| ResourceReservationErrorV1::CorruptLedger)?,
        specification_request: fixed(1945..1977)?,
        candidate: fixed(1977..2009)?, policy_binding: fixed(2009..2041)?,
        origin: if input {
            let mut values = [0; ResourceDimension::COUNT];
            for (index, value) in values.iter_mut().enumerate() {
                let start = 2113 + index * 8;
                *value = u64::from_be_bytes(bytes[start..start + 8].try_into()
                    .map_err(|_| ResourceReservationErrorV1::CorruptLedger)?);
            }
            Some(InputAssociation {
                normalized: fixed(2041..2073)?, digest: fixed(2073..2105)?,
                bytes: u64::from_be_bytes(bytes[2105..2113].try_into().map_err(|_| ResourceReservationErrorV1::CorruptLedger)?),
                continuation: ResourceVector::new(values),
                intake: bytes[2289..2305].try_into().map_err(|_| ResourceReservationErrorV1::CorruptLedger)?,
                observations: u64::from_be_bytes(bytes[2305..2313].try_into().map_err(|_| ResourceReservationErrorV1::CorruptLedger)?),
            })
        } else { None },
    };
    if encode(binding)?.as_slice() != bytes {
        return Err(ResourceReservationErrorV1::CorruptLedger);
    }
    Ok(binding)
}
