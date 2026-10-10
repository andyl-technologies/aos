//! Owns complete passive account mutation assembly and exact comparison.
//!
//! Ordered members reuse the sole head, claim, preparation and terminal codecs.
//! The prefix-size recipe uses existing Journal framing and runs only when called.
//!
//! ```text
//! mutation = after-head || claim || optional-child || preparation-or-terminal
//! bank-key = record-prefix:u8 || identity[16]
//! ```

use aos_sandbox_core::{RawPairedClockSample, ResourceAccount, ResourceCeilings, ResourceVector};
use aos_sandbox_journal::framing::{COMMIT_PAYLOAD_BYTES, EncodedFrameLayout, FrameError};
use aos_sandbox_journal::geometry::EncodedRecordLayout;
use sha2::{Digest as _, Sha256};

use super::{AccountHead, AccountKind, AccountMutation, Claim, ClaimCut, ClaimPurpose, ClaimState, EnrollmentIdentity, JournalRecord, JournalTransaction, RecordNamespace, ResourceBankDataError, codec, matches_record, replay, settlement};
use super::super::transaction::encoded_transaction_append_bytes;

/// Performs the complete original checked reserve_head DATA operation.
///
/// # Errors
/// Preserves the original identity, predecessor and arithmetic refusal order.
pub fn reserve_head(before: AccountHead, claim: Claim) -> Result<AccountHead, ResourceBankDataError> {
if claim.enrollment != before.enrollment || claim.account != before.id
    || claim.child != [0; 16] || claim.state != ClaimState::Reserved
    || claim.project != before.project || claim.sandbox != before.sandbox
    || claim.tree_revision != before.tree_revision
    || !matches!((before.kind, claim.purpose),
        (AccountKind::Sandbox, ClaimPurpose::Snapshot)
        | (AccountKind::Project, ClaimPurpose::ProjectPreparation))
{
    return Err(ResourceBankDataError::Conflict);
}
let generation = before.generation.checked_add(1)
    .ok_or(ResourceBankDataError::Conflict)?;
let after = AccountHead {
    generation,
    account: before.account.reserve(claim.amount)?,
    ..before
};
    Ok(after)
}

/// Performs the complete original checked settled_pair DATA operation.
///
/// # Errors
/// Preserves the original identity, predecessor and arithmetic refusal order.
pub fn settled_pair(before: AccountHead, previous_claim: Claim, committed: bool) -> Result<(AccountHead, Claim), ResourceBankDataError> {
if previous_claim.enrollment != before.enrollment || previous_claim.account != before.id
    || previous_claim.child != [0; 16] || previous_claim.state != ClaimState::Reserved
{
    return Err(ResourceBankDataError::Conflict);
}
if matches!(previous_claim.purpose,
    ClaimPurpose::ControllerFirstGlobalPrefix | ClaimPurpose::NixOriginalStartIntake
        | ClaimPurpose::Q04OriginalIntake)
    && !committed
{
    return Err(ResourceBankDataError::Conflict);
}
let generation = before.generation.checked_add(1)
    .ok_or(ResourceBankDataError::Conflict)?;
let account = if committed {
    before.account.commit(previous_claim.amount)?
} else {
    before.account.release_reservation(previous_claim.amount)?
};
let claim = Claim {
    state: if committed { ClaimState::Committed } else { ClaimState::Released },
    ..previous_claim
};
    Ok((AccountHead { generation, account, ..before }, claim))
}

/// Checks original grant inputs and sampled clock before Native ID generation.
///
/// # Errors
/// Retains the exact input, clock and generation-overflow refusal order.
pub fn require_grant_generation(before: AccountHead, child: AccountHead, claim: Claim, original_clock: RawPairedClockSample) -> Result<u64, ResourceBankDataError> {
        require_grant_inputs(before, child, claim)?;
        let ClaimCut::Operation {
            original_wall_seconds, original_boottime_nanoseconds,
            deadline_boottime_nanoseconds,
        } = claim.cut else { return Err(ResourceBankDataError::Conflict); };
        if original_clock.host_boot_id() != before.enrollment.boot
            || original_clock.wall_seconds() != original_wall_seconds
            || original_clock.boottime_nanoseconds() != original_boottime_nanoseconds
            || original_boottime_nanoseconds >= deadline_boottime_nanoseconds
        {
            return Err(ResourceBankDataError::Conflict);
        }
        let generation = before.generation.checked_add(1)
            .ok_or(ResourceBankDataError::Conflict)?;
    Ok(generation)
}

fn require_grant_inputs(
    before: AccountHead,
    child: AccountHead,
    claim: Claim,
) -> Result<(), ResourceBankDataError> {
    if child.enrollment != before.enrollment
        || child.parent != before.id
        || child.generation != 1
        || child.baseline != ResourceVector::ZERO
        || child.account.committed() != ResourceVector::ZERO
        || child.account.reserved() != ResourceVector::ZERO
        || claim.enrollment != before.enrollment
        || claim.account != before.id
        || claim.child != child.id
        || claim.state != ClaimState::Reserved
        || claim.purpose != ClaimPurpose::InclusiveGrant
        || claim.amount != replay::finite_ceilings(child)?
        || claim.project != child.project
        || claim.sandbox != child.sandbox
        || claim.tree_revision != child.tree_revision
        || !replay::allowed_edge(before.kind, child.kind)
        || !matches!(child.kind, AccountKind::Project | AccountKind::Sandbox)
        || (before.kind != AccountKind::Node
            && (before.project != child.project
                || before.tree_revision != child.tree_revision))
    {
        return Err(ResourceBankDataError::Conflict);
    }

    Ok(())
}

/// Builds the complete historical Project head with the existing hash recipe.
///
/// # Errors
/// Retains the original account construction failure.
pub fn project_child(enrollment: EnrollmentIdentity, before: AccountHead, project: [u8; 16], tree: [u8; 32], amount: ResourceVector) -> Result<AccountHead, ResourceBankDataError> {
        let mut hash = Sha256::new();
        hash.update(b"AOS-resource-project-v1\0");
        hash.update(enrollment.node);
        hash.update(enrollment.epoch);
        hash.update(project);
        let hash = hash.finalize();
        let mut child_id = [0; 16];
        child_id.copy_from_slice(&hash[..16]);
        Ok(AccountHead {
            enrollment,
            id: child_id,
            parent: before.id,
            kind: AccountKind::Project,
            generation: 1,
            project: project,
            sandbox: [0; 16],
            tree_revision: tree,
            baseline: ResourceVector::ZERO,
            account: ResourceAccount::from_usage(
                ResourceCeilings::bounded(amount),
                ResourceVector::ZERO,
                ResourceVector::ZERO,
            )?,
        })
    }


/// Assembles the original closed inclusive Project grant claim.
pub fn project_grant_claim(enrollment: EnrollmentIdentity, operation: [u8; 16], parent: [u8; 16], child: [u8; 16], acceptance: [u8; 32], project: [u8; 16], tree: [u8; 32], cut: ClaimCut, instance: [u8; 32], amount: ResourceVector) -> Claim {
    Claim { enrollment, id: operation, account: parent, child, owner: acceptance,
        purpose: ClaimPurpose::InclusiveGrant, operation, project, sandbox: [0; 16],
        tree_revision: tree, cut, genesis_instance: instance, amount, state: ClaimState::Reserved }
}

/// Assembles the original closed Project preparation claim.
pub fn project_preparation_claim(enrollment: EnrollmentIdentity, operation: [u8; 16], account: [u8; 16], authorization: [u8; 32], project: [u8; 16], tree: [u8; 32], cut: ClaimCut, instance: [u8; 32], amount: ResourceVector) -> Claim {
    Claim { enrollment, id: operation, account, child: [0; 16], owner: authorization,
        purpose: ClaimPurpose::ProjectPreparation, operation, project, sandbox: [0; 16],
        tree_revision: tree, genesis_instance: instance, cut, amount, state: ClaimState::Reserved }
}

impl AccountMutation<'_> {
    /// Encodes every original ordered account mutation member once.
    ///
    /// # Errors
    /// Retains canonical record and transaction construction failures.
    pub fn transaction(&self) -> Result<JournalTransaction, ResourceBankDataError> {
        let mut records = vec![
            JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::HEAD_PREFIX, self.after.id).to_vec(),
                codec::encode_head((*self.after))?.to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::CLAIM_PREFIX, self.claim.id).to_vec(),
                codec::encode_claim((*self.claim))?.to_vec(),
            ),
        ];
        if let Some(child) = (*self.child) {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::HEAD_PREFIX, child.id).to_vec(),
                codec::encode_head(child)?.to_vec(),
            ));
        }
        if let Some(binding) = (*self.preparation) {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(replay::PREPARATION_PREFIX, binding.claim.id).to_vec(),
                codec::encode_preparation(binding)?.to_vec(),
            ));
        }
        if let Some(binding) = (*self.terminal) {
            records.push(JournalRecord::put(
                RecordNamespace::ControllerResourceReservation,
                replay::key(settlement::PREFIX, binding.original_id()).to_vec(),
                settlement::encode(binding)?.to_vec(),
            ));
        }
        Ok(JournalTransaction::new((*self.transaction_id), records)
            .map_err(ResourceBankDataError::Transaction)?)
    }

    /// Compares the full ordered mutation with its exact historical predecessor.
    ///
    /// # Errors
    /// Preserves replay, accounting, record, preparation and terminal refusal order.
    pub fn require_exact(&self, state: &replay::State, transaction: &JournalTransaction) -> Result<(), ResourceBankDataError> {
        if replay::validate(state)? != Some(self.before.enrollment)
            || replay::find_head(state, self.before.id)? != (*self.before)
            || transaction.id() != self.transaction_id
            || transaction.records().len() != 2 + usize::from(self.child.is_some())
                + usize::from(self.preparation.is_some())
                + usize::from(self.terminal.is_some())
        {
            return Err(ResourceBankDataError::Conflict);
        }
        let next_generation = self.before.generation.checked_add(1)
            .ok_or(ResourceBankDataError::Conflict)?;
        let account = match (*self.previous_claim) {
            None if self.claim.state == ClaimState::Reserved => self.before.account.reserve(self.claim.amount)?,
            Some(previous) if previous.state == ClaimState::Reserved
                && (*self.claim) == (Claim { state: ClaimState::Committed, ..previous }) =>
                    self.before.account.commit(previous.amount)?,
            Some(previous) if previous.state == ClaimState::Reserved
                && (*self.claim) == (Claim { state: ClaimState::Released, ..previous }) =>
                    self.before.account.release_reservation(previous.amount)?,
            _ => return Err(ResourceBankDataError::Conflict),
        };
        if (*self.after) != (AccountHead { generation: next_generation, account, ..(*self.before) }) {
            return Err(ResourceBankDataError::Conflict);
        }
        let old = replay::record_bytes(state, replay::CLAIM_PREFIX, self.claim.id);
        match (old, (*self.previous_claim)) {
            (None, None) => {}
            (Some(bytes), Some(previous)) if codec::decode_claim(bytes)? == previous => {}
            _ => return Err(ResourceBankDataError::Conflict),
        }
        let head_bytes = codec::encode_head((*self.after))?;
        let claim_bytes = codec::encode_claim((*self.claim))?;
        if matches!(self.claim.purpose,
            ClaimPurpose::ControllerFirstGlobalPrefix | ClaimPurpose::NixOriginalStartIntake
                | ClaimPurpose::Q04OriginalIntake)
            && encoded_transaction_append_bytes(transaction)?
                != first_global_prefix_append_bytes()?
        {
            return Err(ResourceBankDataError::Conflict);
        }
        let records = transaction.records();
        if !matches_record(&records[0], replay::HEAD_PREFIX, self.after.id, &head_bytes)
            || !matches_record(&records[1], replay::CLAIM_PREFIX, self.claim.id, &claim_bytes)
        {
            return Err(ResourceBankDataError::Conflict);
        }
        if let Some(child) = (*self.child) {
            require_grant_inputs((*self.before), child, (*self.claim))?;
            if self.previous_claim.is_some()
                || replay::has_head(state, child.id)
                || !matches_record(&records[2], replay::HEAD_PREFIX, child.id, &codec::encode_head(child)?)
            {
                return Err(ResourceBankDataError::Conflict);
            }
        } else if self.claim.child != [0; 16] {
            return Err(ResourceBankDataError::Conflict);
        }
        match (self.claim.purpose, (*self.preparation)) {
            (ClaimPurpose::ProjectPreparation, Some(binding))
                if binding.claim == (*self.claim) && self.child.is_none()
                    && self.previous_claim.is_none()
                    && replay::record_bytes(state, replay::PREPARATION_PREFIX, self.claim.id).is_none()
                    && matches_record(&records[2], replay::PREPARATION_PREFIX,
                        self.claim.id, &codec::encode_preparation(binding)?) => {}
            (ClaimPurpose::ProjectPreparation, _) | (_, Some(_)) =>
                return Err(ResourceBankDataError::Conflict),
            (_, None) => {}
        }
        match (self.claim.purpose, (*self.terminal)) {
            (ClaimPurpose::Q04Preparation, Some(binding))
                if self.previous_claim.is_some()
                    && self.child.is_none()
                    && self.preparation.is_none()
                    && replay::record_bytes(state, settlement::PREFIX, binding.original_id()).is_none()
                    && matches_record(&records[2], settlement::PREFIX,
                        binding.original_id(), &settlement::encode(binding)?) => {
                settlement::require_predecessor(state, binding, self)?;
            }
            (ClaimPurpose::Q04Preparation, _) | (_, Some(_)) =>
                return Err(ResourceBankDataError::Conflict),
            (_, None) => {}
        }
        Ok(())
    }
}

/// Measures the complete existing two-member prefix framing geometry lazily.
///
/// # Errors
/// Retains checked frame/record width and aggregate overflow failures.
    // Uses the same framing layouts before the prefix's two record Vecs exist.
pub fn first_global_prefix_append_bytes() -> Result<u64, FrameError> {
        let begin = EncodedFrameLayout::new(std::mem::size_of::<u32>())?;
        let head = EncodedFrameLayout::new(EncodedRecordLayout::new(17, Some(945))?.payload_bytes)?;
        let claim = EncodedFrameLayout::new(EncodedRecordLayout::new(17, Some(531))?.payload_bytes)?;
        let commit = EncodedFrameLayout::new(COMMIT_PAYLOAD_BYTES)?;
        [begin.frame_bytes, head.frame_bytes, claim.frame_bytes, commit.frame_bytes]
            .into_iter().try_fold(0_u64, |bytes, frame| {
                bytes.checked_add(frame as u64).ok_or(FrameError::JournalTooLarge)
            })
    }
