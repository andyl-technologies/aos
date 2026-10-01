//! Complete signed A-only preparation schema for the separate deployment journal.
//!
//! No phase proves live pidfd custody or production guest readiness. Historical
//! records cannot be adopted after restart; the physical owner reacquires or
//! quarantines the exact original population. Quiescence requires its real
//! producer, never elapsed time or a copied PID. The shared floor engine must
//! validate this entire schema and exact append before cold NV extend/commit.
//!
//! ```text
//! key = "deployment-genesis-v1" | "d" || generation:u64be || phase:1..5
//! AOSRDS01:552 || strict publisher signature:64                  (616 bytes)
//! phase1 Prepared -> phase2 Started -> phase3 Measured -> phase5 Quiescent
//! phase1/2/3 -> phase4 Quarantined -> phase5 Quiescent
//! next Prepared requires the previous generation's exact Quiescent record
//! ```
//!
//! Every append is one immutable row, no deletion, overwrite, batch or current
//! head row. Its signed predecessor is the complete old map, not its own future
//! map. The existing common head codec includes every genesis and phase byte.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use aos_sandbox_protocol::runtime_deployment::DeploymentGenesisV1;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::journal::{
    Journal, JournalLimits, JournalTransaction, RuntimeDeploymentNativeTransactionDataV1,
};
use crate::tpm_nv_custody::{
    NvCustodyEndpointV1, NvCustodyErrorV1, canonical_purpose_main_head_v1,
};

use super::genesis::{
    DIRECTORY, GENESIS_KEY, MAIN_NAME, NAMESPACE, SIGNED_GENESIS_BYTES,
    VerifiedDeploymentGenesisV1, genesis_native_transaction_v1,
};

const BODY_BYTES: usize = 552;
const STEP_BYTES: usize = BODY_BYTES + 64;
const STEP_KEY_BYTES: usize = 10;
const MAXIMUM_GENERATIONS: u64 = 64;
const MAXIMUM_ROWS: usize = 1 + MAXIMUM_GENERATIONS as usize * 5;
const INITIAL_SEQUENCE: u64 = 4;
const STEP_DOMAIN: &[u8] = b"aos.runtime-deployment.preparation-step.v1\0";

/// Fixes all eight main replay/admission limits for this separate purpose.
///
/// Sidecar framing and suffix reservation remain solely in the shared engine.
pub(crate) const MAIN_LIMITS: JournalLimits = JournalLimits {
    maximum_journal_bytes: 1024 * 1024,
    maximum_record_bytes: 1024,
    maximum_key_bytes: 32,
    maximum_records_per_transaction: 1,
    maximum_transaction_bytes: 1024,
    maximum_transactions: MAXIMUM_ROWS,
    maximum_materialized_bytes: 256 * 1024,
    maximum_materialized_records: MAXIMUM_ROWS,
};

/// Requires the actual held original main path, root ownership and all eight limits.
///
/// The namespace number is not permission to open another Host catalog. This
/// fixed-name comparison precedes any retained row-map allocation and is
/// repeated by the common owner around its actual snapshot/effect boundary.
///
/// # Errors
///
/// Rejects original credential/startup drift, a substituted path or writer,
/// nonroot ownership, changed limits, foreign namespaces or an empty/large map.
/// Also rejects a signed/materialized map whose original native UUIDs, order,
/// one-PUT associations or complete physical cut differ. This mandatory cold
/// audit cannot be replaced by either map-only schema helper below.
pub(crate) fn require_deployment_main_v1(
    owner: &VerifiedDeploymentGenesisV1<'_>,
    journal: &Journal,
) -> Result<(), NvCustodyErrorV1> {
    owner.recheck()?;
    journal.require_protected_named_location(Path::new(DIRECTORY), MAIN_NAME, 0, MAIN_LIMITS)
        .map_err(|_| NvCustodyErrorV1::Provisioning)?;
    let mut rows = 0_usize;
    for (namespace, _, _) in journal.all_records() {
        if namespace != NAMESPACE {
            return Err(NvCustodyErrorV1::Provisioning);
        }
        rows = rows.checked_add(1).ok_or(NvCustodyErrorV1::Encoding)?;
        require_deployment_row_bound_v1(rows)?;
    }
    require_deployment_row_bound_v1(rows)?;
    journal.require_runtime_deployment_native_history_v1(owner)
        .map_err(|_| NvCustodyErrorV1::Provisioning)?;
    owner.recheck()
}

/// Refuses an oversized row set before the shared engine retains a map.
///
/// # Errors
///
/// Rejects a missing genesis map or more than 321 materialized rows.
pub(crate) fn require_deployment_row_bound_v1(rows: usize) -> Result<(), NvCustodyErrorV1> {
    if rows == 0 || rows > MAXIMUM_ROWS {
        return Err(NvCustodyErrorV1::Encoding);
    }
    Ok(())
}

/// Validates the complete current map under genuine independently rechecked origins.
///
/// # Errors
///
/// Rejects current origin drift, any unknown/malformed/unsigned row, missing
/// genesis, inconsistent original history or a sequence/predecessor mismatch.
pub(crate) fn require_current_deployment_rows_v1(
    owner: &VerifiedDeploymentGenesisV1<'_>,
    sequence: u64,
    records: &BTreeMap<&[u8], &[u8]>,
) -> Result<(), NvCustodyErrorV1> {
    owner.recheck()?;
    require_rows(
        sequence,
        records,
        owner.exact_bytes(),
        owner.claims(),
        owner.publisher_verifier(),
        owner.scope(),
    )?;
    owner.recheck()
}

/// Validates one exact signed append, including every current and resulting row.
///
/// This is a schema check, not a public authorizer or effect producer. The common
/// owner separately retains/preflights both writers and verifies fresh NV; the
/// actual publisher must still derive each signed record from physical custody.
///
/// # Errors
///
/// Rejects any invalid current/resulting map, origin drift, foreign or repeated
/// keys, deletion/overwrite/batching, or a substituted original transaction ID.
pub(crate) fn require_prospective_deployment_append_v1<'data>(
    owner: &VerifiedDeploymentGenesisV1<'_>,
    sequence: u64,
    records: &BTreeMap<&'data [u8], &'data [u8]>,
    transaction: &'data JournalTransaction,
) -> Result<(), NvCustodyErrorV1> {
    owner.recheck()?;
    require_append(
        sequence,
        records,
        transaction,
        owner.exact_bytes(),
        owner.claims(),
        owner.publisher_verifier(),
        owner.scope(),
    )?;
    owner.recheck()
}

/// Compares one signed phase with its genuinely parsed native transaction.
///
/// This DATA check reuses the sole phase decoder and does not repeat the phase
/// reducer or replace original Journal custody. The closed native observer
/// supplies an actual validated BEGIN and UUID, not a caller phase label.
///
/// # Errors
///
/// Rejects a malformed or unsigned phase, reserved compaction UUID, or a
/// difference between signed predecessor/transaction and the native frame.
pub(crate) fn require_native_step_binding_v1(
    key: &[u8],
    bytes: &[u8],
    genesis: &DeploymentGenesisV1,
    signer: VerifyingKey,
    native_transaction: [u8; 16],
    native_begin_sequence: u64,
) -> Result<(), NvCustodyErrorV1> {
    let step = StepV1::decode(key, bytes, genesis, signer)?;
    if step.transaction != native_transaction
        || step.predecessor_sequence != native_begin_sequence
    {
        return Err(NvCustodyErrorV1::Provisioning);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PhaseV1 {
    Prepared = 1,
    Started = 2,
    Measured = 3,
    Quarantined = 4,
    Quiescent = 5,
}

impl PhaseV1 {
    fn decode(value: u8) -> Result<Self, NvCustodyErrorV1> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Started),
            3 => Ok(Self::Measured),
            4 => Ok(Self::Quarantined),
            5 => Ok(Self::Quiescent),
            _ => Err(NvCustodyErrorV1::Encoding),
        }
    }

    fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Prepared, Self::Started | Self::Quarantined)
                | (Self::Started, Self::Measured | Self::Quarantined)
                | (Self::Measured, Self::Quarantined | Self::Quiescent)
                | (Self::Quarantined, Self::Quiescent)
        )
    }
}

/// Borrows canonical signed bytes; it never reconstructs a physical owner.
struct StepV1<'record> {
    exact: &'record [u8],
    phase: PhaseV1,
    generation: u64,
    attempt: [u8; 16],
    previous: [u8; 32],
    predecessor_sequence: u64,
    predecessor_head: [u8; 32],
    transaction: [u8; 16],
}

impl<'record> StepV1<'record> {
    fn decode(
        key: &[u8],
        bytes: &'record [u8],
        genesis: &DeploymentGenesisV1,
        signer: VerifyingKey,
    ) -> Result<Self, NvCustodyErrorV1> {
        if key.len() != STEP_KEY_BYTES
            || key[0] != b'd'
            || bytes.len() != STEP_BYTES
            || &bytes[..8] != b"AOSRDS01"
            || bytes[8..12] != [0, 1, 0, 0]
            || bytes[13..16] != [0; 3]
        {
            return Err(NvCustodyErrorV1::Encoding);
        }
        let phase = PhaseV1::decode(bytes[12])?;
        let generation = u64::from_be_bytes(array(bytes, 48)?);
        if key[1..9] != generation.to_be_bytes()
            || key[9] != phase as u8
            || generation == 0
            || generation > MAXIMUM_GENERATIONS
            || bytes[16..48] != genesis.digest().map_err(|_| NvCustodyErrorV1::Encoding)?
            || signer.to_bytes() != genesis.signer
            || signer.is_weak()
        {
            return Err(NvCustodyErrorV1::Provisioning);
        }

        let message = [STEP_DOMAIN, &bytes[..BODY_BYTES]].concat();
        let signature = Signature::from_bytes(&array(bytes, BODY_BYTES)?);
        signer.verify_strict(&message, &signature)
            .map_err(|_| NvCustodyErrorV1::Provisioning)?;

        let step = Self {
            exact: bytes,
            phase,
            generation,
            attempt: array(bytes, 56)?,
            previous: array(bytes, 88)?,
            predecessor_sequence: u64::from_be_bytes(array(bytes, 120)?),
            predecessor_head: array(bytes, 128)?,
            transaction: array(bytes, 160)?,
        };
        if step.attempt == [0; 16]
            || bytes[72..88] == [0; 16]
            || step.transaction == [0; 16]
            || &step.transaction[8..] == b"compact1"
            || bytes[176..192] == [0; 16]
            || bytes[192..224] == [0; 32]
            || bytes[224..256] == [0; 32]
            || step.predecessor_sequence == 0
            || step.predecessor_head == [0; 32]
        {
            return Err(NvCustodyErrorV1::Encoding);
        }
        step.require_physical_shape(genesis)?;
        Ok(step)
    }

    fn digest(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(STEP_DOMAIN)
            .chain_update(self.exact)
            .finalize()
            .into()
    }

    fn require_physical_shape(&self, genesis: &DeploymentGenesisV1) -> Result<(), NvCustodyErrorV1> {
        let bytes = self.exact;
        if self.phase == PhaseV1::Prepared {
            if bytes[256..BODY_BYTES].iter().any(|byte| *byte != 0) {
                return Err(NvCustodyErrorV1::Encoding);
            }
            return Ok(());
        }
        if matches!(self.phase, PhaseV1::Quarantined | PhaseV1::Quiescent) {
            // Exact preservation against the predecessor is checked separately.
            // A zero observation is not reinterpreted as an empty live target.
            return Ok(());
        }

        let supervisor_pid = u32::from_be_bytes(array(bytes, 272)?);
        let payload_pid = u32::from_be_bytes(array(bytes, 276)?);
        if bytes[256..272] == [0; 16]
            || supervisor_pid <= 1
            || payload_pid <= 1
            || supervisor_pid == payload_pid
            || bytes[480] != 1
            || bytes[481] != 2
            || bytes[484] != 1
            || bytes[485] != 2
            || u16::from_be_bytes(array(bytes, 482)?) == 0
            || u16::from_be_bytes(array(bytes, 486)?) == 0
            || u16::from_be_bytes(array(bytes, 482)?) > 32
            || u16::from_be_bytes(array(bytes, 486)?) > 32
        {
            return Err(NvCustodyErrorV1::Encoding);
        }
        for offset in (280..400).step_by(8) {
            if u64::from_be_bytes(array(bytes, offset)?) == 0 {
                return Err(NvCustodyErrorV1::Encoding);
            }
        }
        let ceiling = aos_systemd::PayloadRootContinuityPolicyV1::fixed()
            .supervisor_capability_bounding_set();
        for offset in [400, 440] {
            let caps = (0..5)
                .map(|index| array(bytes, offset + index * 8).map(u64::from_be_bytes))
                .collect::<Result<Vec<_>, _>>()?;
            if caps[0] != 0
                || caps[4] != 0
                || caps.iter().any(|value| value & !ceiling != 0)
                || caps[2] & !caps[1] != 0
                || caps[1] & !caps[3] != 0
            {
                return Err(NvCustodyErrorV1::Encoding);
            }
        }
        match self.phase {
            PhaseV1::Started if bytes[488..552].iter().any(|byte| *byte != 0) => {
                Err(NvCustodyErrorV1::Encoding)
            }
            PhaseV1::Measured if bytes[488..520] != genesis.supervisor_filter
                || bytes[520..552] != genesis.payload_filter => {
                Err(NvCustodyErrorV1::Provisioning)
            }
            _ => Ok(()),
        }
    }

    fn require_continuation(&self, previous: &Self) -> Result<(), NvCustodyErrorV1> {
        if self.generation == previous.generation {
            if !previous.phase.permits(self.phase)
                || self.attempt != previous.attempt
                || self.previous != previous.digest()
                || self.exact[72..88] != previous.exact[72..88]
                || self.exact[176..256] != previous.exact[176..256]
            {
                return Err(NvCustodyErrorV1::Provisioning);
            }
            let preserved = match self.phase {
                PhaseV1::Measured => 256..488,
                PhaseV1::Quarantined | PhaseV1::Quiescent => 256..BODY_BYTES,
                _ => 0..0,
            };
            if self.exact[preserved.clone()] != previous.exact[preserved] {
                return Err(NvCustodyErrorV1::Provisioning);
            }
        } else if previous.phase != PhaseV1::Quiescent
            || self.phase != PhaseV1::Prepared
            || previous.generation.checked_add(1) != Some(self.generation)
            || self.attempt == previous.attempt
            || self.previous != previous.digest()
        {
            return Err(NvCustodyErrorV1::Provisioning);
        }
        Ok(())
    }
}

fn require_rows(
    sequence: u64,
    records: &BTreeMap<&[u8], &[u8]>,
    exact_genesis: &[u8],
    genesis: &DeploymentGenesisV1,
    signer: VerifyingKey,
    scope: [u8; 32],
) -> Result<(), NvCustodyErrorV1> {
    require_deployment_row_bound_v1(records.len())?;
    if exact_genesis.len() != SIGNED_GENESIS_BYTES
        || records.get(GENESIS_KEY).copied() != Some(exact_genesis)
    {
        return Err(NvCustodyErrorV1::Provisioning);
    }

    let mut prefix = BTreeMap::from([(GENESIS_KEY, exact_genesis)]);
    let mut predecessor_sequence = INITIAL_SEQUENCE;
    let mut previous = None;
    let mut transactions = BTreeSet::from([genesis_native_transaction_v1(exact_genesis)?]);
    let mut attempts = BTreeSet::new();
    for (&key, &value) in records {
        if key == GENESIS_KEY {
            continue;
        }
        let step = StepV1::decode(key, value, genesis, signer)?;
        let predecessor_head = canonical_purpose_main_head_v1(
            NvCustodyEndpointV1::RuntimeDeployment, scope, predecessor_sequence, &prefix,
        )?;
        if step.predecessor_sequence != predecessor_sequence
            || step.predecessor_head != predecessor_head
            || !transactions.insert(step.transaction)
        {
            return Err(NvCustodyErrorV1::Provisioning);
        }
        if let Some(previous) = &previous {
            step.require_continuation(previous)?;
        } else if step.phase != PhaseV1::Prepared
            || step.generation != 1
            || step.previous != [0; 32]
        {
            return Err(NvCustodyErrorV1::Provisioning);
        }
        if step.phase == PhaseV1::Prepared && !attempts.insert(step.attempt) {
            return Err(NvCustodyErrorV1::Provisioning);
        }
        prefix.insert(key, value);
        predecessor_sequence = predecessor_sequence.checked_add(3)
            .ok_or(NvCustodyErrorV1::Encoding)?;
        previous = Some(step);
    }
    if sequence != predecessor_sequence {
        return Err(NvCustodyErrorV1::Provisioning);
    }
    Ok(())
}

fn require_append<'data>(
    sequence: u64,
    records: &BTreeMap<&'data [u8], &'data [u8]>,
    transaction: &'data JournalTransaction,
    exact_genesis: &[u8],
    genesis: &DeploymentGenesisV1,
    signer: VerifyingKey,
    scope: [u8; 32],
) -> Result<(), NvCustodyErrorV1> {
    validated_append_rows_v1(
        sequence, records, transaction, exact_genesis, genesis, signer, scope,
    )
    .map(|_| ())
}

/// Retains only borrowed rows after the existing complete append checks.
///
/// The private comparison bridge uses this same successful map for its target
/// head. Existing schema callers still discard it through `require_append`.
pub(super) fn validated_append_rows_v1<'data>(
    sequence: u64,
    records: &BTreeMap<&'data [u8], &'data [u8]>,
    transaction: &'data JournalTransaction,
    exact_genesis: &[u8],
    genesis: &DeploymentGenesisV1,
    signer: VerifyingKey,
    scope: [u8; 32],
) -> Result<(u64, BTreeMap<&'data [u8], &'data [u8]>), NvCustodyErrorV1> {
    require_rows(sequence, records, exact_genesis, genesis, signer, scope)?;
    let next_rows = records.len().checked_add(1).ok_or(NvCustodyErrorV1::Encoding)?;
    require_deployment_row_bound_v1(next_rows)?;
    if transaction.records().len() != 1 {
        return Err(NvCustodyErrorV1::Encoding);
    }
    let record = &transaction.records()[0];
    if record.namespace() != NAMESPACE
        || record.key() == GENESIS_KEY
        || records.contains_key(record.key())
    {
        return Err(NvCustodyErrorV1::Provisioning);
    }
    let value = record.value().ok_or(NvCustodyErrorV1::Encoding)?;
    let step = StepV1::decode(record.key(), value, genesis, signer)?;
    if step.transaction != *transaction.id() {
        return Err(NvCustodyErrorV1::Provisioning);
    }

    let mut after = records.clone();
    after.insert(record.key(), value);
    let next_sequence = sequence.checked_add(3).ok_or(NvCustodyErrorV1::Encoding)?;
    require_rows(next_sequence, &after, exact_genesis, genesis, signer, scope)?;
    Ok((next_sequence, after))
}

/// Compares the target head through the sole validated append and head engines.
pub(super) fn compared_prospective_deployment_head_v1<'data>(
    owner: &VerifiedDeploymentGenesisV1<'_>,
    sequence: u64,
    records: &BTreeMap<&'data [u8], &'data [u8]>,
    transaction: &'data JournalTransaction,
) -> Result<(u64, [u8; 32]), NvCustodyErrorV1> {
    owner.recheck()?;
    let (next_sequence, after) = validated_append_rows_v1(
        sequence,
        records,
        transaction,
        owner.exact_bytes(),
        owner.claims(),
        owner.publisher_verifier(),
        owner.scope(),
    )?;
    let head = canonical_purpose_main_head_v1(
        NvCustodyEndpointV1::RuntimeDeployment, owner.scope(), next_sequence, &after,
    )?;
    owner.recheck()?;
    Ok((next_sequence, head))
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], NvCustodyErrorV1> {
    bytes.get(offset..offset.checked_add(N).ok_or(NvCustodyErrorV1::Encoding)?)
        .and_then(|bytes| bytes.try_into().ok()).ok_or(NvCustodyErrorV1::Encoding)
}

/// Reconstructs one actual native prefix, never all full-map prefixes.
pub(super) fn deployment_native_prefix_rows_v1(
    history: &[RuntimeDeploymentNativeTransactionDataV1],
    sequence: u64,
) -> Result<BTreeMap<&[u8], &[u8]>, NvCustodyErrorV1> {
    require_deployment_row_bound_v1(history.len())?;
    if sequence < INITIAL_SEQUENCE {
        return Err(NvCustodyErrorV1::Provisioning);
    }
    let mut records = BTreeMap::new();
    let mut next_sequence = 1;
    for native in history {
        if native.begin_sequence() >= sequence {
            break;
        }
        if native.begin_sequence() != next_sequence
            || native.next_sequence() > sequence
            || native.transaction().records().len() != 1
        {
            return Err(NvCustodyErrorV1::Provisioning);
        }
        let record = &native.transaction().records()[0];
        let value = record.value().ok_or(NvCustodyErrorV1::Encoding)?;
        if record.namespace() != NAMESPACE
            || records.insert(record.key(), value).is_some()
        {
            return Err(NvCustodyErrorV1::Provisioning);
        }
        next_sequence = native.next_sequence();
    }
    if next_sequence != sequence {
        return Err(NvCustodyErrorV1::Provisioning);
    }
    Ok(records)
}

/// Compares one actual original prefix through the sole schema and HEAD engines.
pub(super) fn compared_deployment_native_prefix_v1(
    owner: &VerifiedDeploymentGenesisV1<'_>,
    history: &[RuntimeDeploymentNativeTransactionDataV1],
    sequence: u64,
) -> Result<(u64, [u8; 32]), NvCustodyErrorV1> {
    owner.recheck()?;
    let records = deployment_native_prefix_rows_v1(history, sequence)?;
    require_current_deployment_rows_v1(owner, sequence, &records)?;
    let head = canonical_purpose_main_head_v1(
        NvCustodyEndpointV1::RuntimeDeployment, owner.scope(), sequence, &records,
    )?;
    owner.recheck()?;
    Ok((sequence, head))
}

/// Compares a past exact phase at its actual original preimage, never reappends.
pub(super) fn compared_retained_deployment_transition_v1(
    owner: &VerifiedDeploymentGenesisV1<'_>,
    history: &[RuntimeDeploymentNativeTransactionDataV1],
    transaction: &JournalTransaction,
) -> Result<((u64, [u8; 32]), (u64, [u8; 32])), NvCustodyErrorV1> {
    owner.recheck()?;
    let native = history.iter()
        .find(|native| native.transaction() == transaction)
        .ok_or(NvCustodyErrorV1::Provisioning)?;
    let before = compared_deployment_native_prefix_v1(
        owner, history, native.begin_sequence(),
    )?;
    let records = deployment_native_prefix_rows_v1(history, before.0)?;
    // This is the actual historical preimage, not the current writer map.
    // Reuse the original pure append checks, without acquiring an append token.
    let expected = compared_prospective_deployment_head_v1(owner, before.0, &records, transaction)?;
    drop(records);
    let after = compared_deployment_native_prefix_v1(owner, history, native.next_sequence())?;
    if after != expected {
        return Err(NvCustodyErrorV1::Provisioning);
    }
    owner.recheck()?;
    Ok((before, after))
}

#[cfg(test)]
pub(crate) mod tests;
