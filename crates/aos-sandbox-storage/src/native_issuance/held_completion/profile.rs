//! All-row conservative continuation geometry, separate from live admission.

use std::collections::BTreeMap;

use aos_sandbox::journal::encoded_transaction_append_bytes;
use aos_sandbox_source_provider_protocol::native_held_completion::MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1;

use super::*;

/// Reports ungranted future geometry including every active row's retirement.
///
/// Unknown future controls use their actual canonical bound, not invented signed
/// proofs. Alternative paths take a maximum, never add mutually exclusive writes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StorageHeldCapacityProfileV1 {
    /// Sum of maximal remaining append counts for all actual issuance rows.
    pub(crate) remaining_transactions: usize,
    /// Sum of maximal complete append bytes, including BEGIN/record/COMMIT frames.
    pub(crate) remaining_append_bytes: u64,
    /// Sum of each original row's peak key+value size along its remaining paths.
    pub(crate) peak_materialized_bytes: usize,
    /// Largest future canonical record payload, including key and record header.
    pub(crate) maximum_record_bytes: usize,
}

/// Measures all actual rows' complete remaining prefix and retirement union.
///
/// This DATA function does not compare or grant live journal limits. The existing
/// 1024*2 limit remains unchanged and cannot admit the eight-write held grammar.
///
/// # Errors
///
/// Rejects invalid rows/identity, oversized canonical templates and arithmetic.
pub(crate) fn remaining_capacity_profile(
    values: &BTreeMap<[u8; 48], Vec<u8>>,
) -> Result<StorageHeldCapacityProfileV1> {
    let rows = reducer::decode_state(values)?;
    let mut total = StorageHeldCapacityProfileV1::default();
    for row in rows.values() {
        let current = row.to_canonical_bytes()?.len();
        let mut peak = current;
        let mut count = 0;
        let mut append = 0;
        match row {
            StorageIssuanceValueV1::Legacy(original) => {
                if original.retirement.is_none() {
                    // The unchanged legacy path owes exactly its own retirement;
                    // it is not eligible for an implicit held-format upgrade.
                    let transaction = original
                        .retired(
                            ObjectDigest::from_bytes([1; 32]),
                            ObjectDigest::from_bytes([2; 32]),
                        )
                        .transaction()?;
                    append = encoded_transaction_append_bytes(&transaction)
                        .map_err(|_| invalid("legacy append geometry"))?;
                    count = 1;
                }
            }
            StorageIssuanceValueV1::Held(held) => {
                for path in paths(held) {
                    let mut path_append = 0_u64;
                    for stage in &path {
                        let size = stage_size(held, stage)?;
                        peak = peak.max(size);
                        // Capacity-only zero bytes cannot decode as a row/control.
                        // The real Journal encoder supplies the complete framing.
                        let transaction = JournalTransaction::new(
                            [1; 16],
                            vec![JournalRecord::put(
                                RecordNamespace::AuthorityPublication,
                                held.key().to_vec(),
                                vec![0; size],
                            )],
                        )
                        .map_err(|_| invalid("capacity template"))?;
                        path_append = path_append
                            .checked_add(
                                encoded_transaction_append_bytes(&transaction)
                                    .map_err(|_| invalid("held append geometry"))?,
                            )
                            .ok_or_else(|| invalid("append sum overflow"))?;
                    }
                    count = count.max(path.len());
                    append = append.max(path_append);
                }
            }
        }
        total.remaining_transactions = total
            .remaining_transactions
            .checked_add(count)
            .ok_or_else(|| invalid("remaining count overflow"))?;
        total.remaining_append_bytes = total
            .remaining_append_bytes
            .checked_add(append)
            .ok_or_else(|| invalid("all-row append overflow"))?;
        total.peak_materialized_bytes = total
            .peak_materialized_bytes
            .checked_add(48)
            .and_then(|size| size.checked_add(peak))
            .ok_or_else(|| invalid("all-row materialization overflow"))?;
        total.maximum_record_bytes = total.maximum_record_bytes.max(
            peak.checked_add(48 + 7)
                .ok_or_else(|| invalid("record size overflow"))?,
        );
    }
    Ok(total)
}

struct Stage {
    controls: Vec<Kind>,
    prepared: Option<Kind>,
}

fn stage(controls: &[Kind], prepared: Option<Kind>) -> Stage {
    Stage {
        controls: controls.to_vec(),
        prepared,
    }
}

fn paths(row: &StorageHeldIssuanceRowV2) -> Vec<Vec<Stage>> {
    use Kind::*;
    let normal = [RootPrepared, StorageHeld, ProviderRelay, StorageSettled];
    let recovered = [
        RootPrepared,
        StorageHeld,
        ProviderRelay,
        StorageSettled,
        ProviderStorageRecoveryQuery,
        StorageRecoveryState,
    ];
    let mut normal_path = vec![
        stage(&normal[..1], Some(StorageHeld)),
        stage(&normal[..2], None),
        stage(&normal[..3], None),
        stage(&normal[..3], Some(StorageSettled)),
        stage(&normal, None),
        stage(&recovered, None),
        stage(&recovered, None),
    ];
    let phase = row.suffix.phase();
    let controls = row
        .suffix
        .controls()
        .iter()
        .map(SignedNativeHeldControlV1::kind)
        .collect::<Vec<_>>();
    let prepared = row.suffix.prepared().map(|value| value.kind());
    let mut cold = controls.clone();
    if !cold.contains(&ProviderStorageRecoveryQuery) {
        cold.push(ProviderStorageRecoveryQuery);
    }
    let mut terminal = cold.clone();
    terminal.push(StorageRecoveryState);
    let cold_path = vec![
        stage(&cold, None),
        stage(&cold, Some(StorageRecoveryState)),
        stage(&terminal, None),
        stage(&terminal, None),
    ];
    match phase {
        0..=2 => {
            normal_path.drain(..phase as usize);
            vec![normal_path, cold_path]
        }
        3 if prepared == Some(StorageSettled) => vec![
            normal_path.drain(4..).collect(),
            vec![
                stage(&cold, Some(StorageRecoveryState)),
                stage(&terminal, None),
                stage(&terminal, None),
            ],
        ],
        3 if controls.contains(&ProviderStorageRecoveryQuery) => {
            let offset = if prepared.is_some() { 2 } else { 1 };
            vec![cold_path.into_iter().skip(offset).collect()]
        }
        3 => vec![normal_path.drain(3..).collect(), cold_path],
        4 if row.suffix.control(StorageSettled).is_some()
            && row.suffix.control(StorageRecoveryState).is_none() =>
        {
            vec![vec![stage(&recovered, None), stage(&recovered, None)]]
        }
        4 => vec![vec![stage(&controls, None)]],
        _ => vec![Vec::new()],
    }
}

fn stage_size(row: &StorageHeldIssuanceRowV2, stage: &Stage) -> Result<usize> {
    // A cold Closed branch may skip a hot slot; do not add missing old controls
    // to a path template. Extra conservative normal-path slots are bounded DATA.
    let mut size = row
        .original
        .encode()?
        .len()
        .checked_add(56)
        .ok_or_else(|| invalid("suffix header overflow"))?;
    for kind in &stage.controls {
        let bytes = row
            .suffix
            .control(*kind)
            .map_or(MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1, |control| {
                control.to_canonical_bytes().len()
            });
        size = size
            .checked_add(8)
            .and_then(|size| size.checked_add(bytes))
            .ok_or_else(|| invalid("archive capacity overflow"))?;
    }
    if let Some(kind) = stage.prepared {
        let bytes = row
            .suffix
            .prepared()
            .filter(|control| control.kind() == kind)
            .map_or(MAXIMUM_NATIVE_HELD_CONTROL_BYTES_V1 - 64, |control| {
                control.to_canonical_bytes().len()
            });
        size = size
            .checked_add(bytes)
            .ok_or_else(|| invalid("prepared capacity overflow"))?;
    }
    if size > MAXIMUM_STORAGE_HELD_ISSUANCE_VALUE_BYTES_V2 {
        return Err(invalid("complete capacity value bound"));
    }
    Ok(size)
}
