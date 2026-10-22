//! Divergence localization helpers for harness diagnostics.
//!
//! The module provides the deterministic comparison core shared by
//! `gate:divergence-bisect` without owning VM resume itself. Higher layers supply
//! the probe that answers whether two resumed states still match at an icount.

use std::collections::{BTreeMap, BTreeSet};

use crate::fingerprint::{FingerprintMismatchKind, FingerprintStream, compare_fingerprint_streams};

mod segment;
mod types;

pub use segment::{
    SegmentedDivergenceBisectionError, SegmentedDivergenceBisectionReport,
    bisect_diverging_runs_with_segment_replay,
};
pub use types::{
    BisectionWindowError, BisectionWindowErrorKind, DecisionTraceEntry, DecisionTraceMismatch,
    DivergenceBisectionError, DivergenceBisectionReport, DivergenceMemoryRegion,
    DivergenceRegister, DivergenceReport, DivergenceSide, DivergenceStateDiff, DivergenceStateDump,
    DivergenceStatePair, IcountBisection,
};

/// Locates the first differing fingerprint sample, if the streams differ.
#[must_use]
pub fn locate_first_divergence(
    left: &FingerprintStream,
    right: &FingerprintStream,
) -> Option<DivergenceReport> {
    let mismatch = compare_fingerprint_streams(left, right).err()?;
    if matches!(
        mismatch.kind,
        FingerprintMismatchKind::Definition { .. } | FingerprintMismatchKind::Final { .. }
    ) {
        return None;
    }

    Some(divergence_report_for_sample_index(
        left,
        right,
        mismatch.sample_index,
    ))
}

/// Locates the first differing schedule decision in canonical order.
#[must_use]
pub fn locate_first_decision_mismatch(
    left: &[DecisionTraceEntry],
    right: &[DecisionTraceEntry],
) -> Option<DecisionTraceMismatch> {
    for (index, (left_entry, right_entry)) in left.iter().zip(right.iter()).enumerate() {
        if left_entry.canonical_bytes != right_entry.canonical_bytes {
            return Some(DecisionTraceMismatch {
                index,
                left: Some(left_entry.clone()),
                right: Some(right_entry.clone()),
            });
        }
    }

    if left.len() != right.len() {
        let index = left.len().min(right.len());
        return Some(DecisionTraceMismatch {
            index,
            left: left.get(index).cloned(),
            right: right.get(index).cloned(),
        });
    }

    None
}

/// Runs coarse fingerprint localization, fine icount bisection, and state dump.
///
/// The `matches_at` probe returns whether both runs still match at the requested
/// icount. The `dump_at` probe returns the canonical diagnostic state for one
/// side at the requested icount.
///
/// # Errors
///
/// Returns [`DivergenceBisectionError::MatchingStreams`] when the streams do not
/// diverge, [`DivergenceBisectionError::DefinitionMismatch`] or
/// [`DivergenceBisectionError::FinalFingerprintMismatch`] for non-bisectable
/// fingerprint differences, [`DivergenceBisectionError::MissingDifferentSampleIcount`]
/// when the coarse mismatch has no icount,
/// [`DivergenceBisectionError::InvalidWindow`] when the coarse sample window is
/// invalid for bisection, or [`DivergenceBisectionError::MalformedStateDump`]
/// when either diagnostic dump contains duplicate stable keys.
pub fn bisect_diverging_runs<M, D>(
    left: &FingerprintStream,
    right: &FingerprintStream,
    left_decisions: &[DecisionTraceEntry],
    right_decisions: &[DecisionTraceEntry],
    matches_at: M,
    mut dump_at: D,
) -> Result<DivergenceBisectionReport, DivergenceBisectionError>
where
    M: FnMut(u64) -> bool,
    D: FnMut(DivergenceSide, u64) -> DivergenceStateDump,
{
    let coarse = locate_bisectable_divergence(left, right)?;
    let Some(first_different_sample_icount) = coarse.first_different_sample_icount else {
        return Err(DivergenceBisectionError::MissingDifferentSampleIcount);
    };

    let bisection = refine_from_coarse_window(
        coarse.previous_matching_icount,
        first_different_sample_icount,
        matches_at,
    )?;
    let last_matching_state = if bisection.first_different_icount == 0 {
        None
    } else {
        let state = dump_pair(bisection.last_matching_icount, &mut dump_at);
        validate_state_pair(&state)?;
        Some(state)
    };
    let first_different_state = dump_pair(bisection.first_different_icount, &mut dump_at);
    validate_state_pair(&first_different_state)?;
    let first_different_state_diff =
        diff_state_dumps(&first_different_state.left, &first_different_state.right);

    Ok(DivergenceBisectionReport {
        sample_index: coarse.sample_index,
        node: coarse.node,
        previous_matching_icount: coarse.previous_matching_icount,
        first_different_sample_icount,
        first_different_icount: bisection.first_different_icount,
        first_different_decision: locate_first_decision_mismatch(left_decisions, right_decisions),
        last_matching_state,
        first_different_state,
        first_different_state_diff,
    })
}

/// Refines a known `(last matching, first differing]` icount window.
///
/// The `matches_at` probe must return `true` for the low endpoint and `false`
/// for the high endpoint.
///
/// # Errors
///
/// Returns [`BisectionWindowError`] when the endpoints are reversed, the low
/// endpoint already differs, or the high endpoint still matches.
pub fn bisect_first_different_icount<F>(
    low_matching_icount: u64,
    high_different_icount: u64,
    matches_at: F,
) -> Result<u64, BisectionWindowError>
where
    F: FnMut(u64) -> bool,
{
    bisect_icount_window(low_matching_icount, high_different_icount, matches_at)
        .map(|bisection| bisection.first_different_icount)
}

/// Refines a known `(last matching, first differing]` icount window.
///
/// The `matches_at` probe must return `true` for the low endpoint and `false`
/// for the high endpoint.
///
/// # Errors
///
/// Returns [`BisectionWindowError`] when the endpoints are reversed, the low
/// endpoint already differs, or the high endpoint still matches.
pub fn bisect_icount_window<F>(
    mut low_matching_icount: u64,
    mut high_different_icount: u64,
    mut matches_at: F,
) -> Result<IcountBisection, BisectionWindowError>
where
    F: FnMut(u64) -> bool,
{
    if low_matching_icount >= high_different_icount {
        return Err(BisectionWindowError {
            low_matching_icount,
            high_different_icount,
            kind: BisectionWindowErrorKind::EmptyOrReversed,
        });
    }
    if !matches_at(low_matching_icount) {
        return Err(BisectionWindowError {
            low_matching_icount,
            high_different_icount,
            kind: BisectionWindowErrorKind::LowAlreadyDifferent,
        });
    }
    if matches_at(high_different_icount) {
        return Err(BisectionWindowError {
            low_matching_icount,
            high_different_icount,
            kind: BisectionWindowErrorKind::HighStillMatching,
        });
    }

    while high_different_icount - low_matching_icount > 1 {
        let midpoint = low_matching_icount + ((high_different_icount - low_matching_icount) / 2);
        if matches_at(midpoint) {
            low_matching_icount = midpoint;
        } else {
            high_different_icount = midpoint;
        }
    }

    Ok(IcountBisection {
        last_matching_icount: low_matching_icount,
        first_different_icount: high_different_icount,
    })
}

fn locate_bisectable_divergence(
    left: &FingerprintStream,
    right: &FingerprintStream,
) -> Result<DivergenceReport, DivergenceBisectionError> {
    match compare_fingerprint_streams(left, right) {
        Ok(()) => Err(DivergenceBisectionError::MatchingStreams),
        Err(mismatch) => match mismatch.kind {
            FingerprintMismatchKind::Definition { .. } => {
                Err(DivergenceBisectionError::DefinitionMismatch)
            }
            FingerprintMismatchKind::Final { .. } => {
                Err(DivergenceBisectionError::FinalFingerprintMismatch)
            }
            FingerprintMismatchKind::Sample { .. } | FingerprintMismatchKind::Length { .. } => Ok(
                divergence_report_for_sample_index(left, right, mismatch.sample_index),
            ),
        },
    }
}

fn divergence_report_for_sample_index(
    left: &FingerprintStream,
    right: &FingerprintStream,
    sample_index: usize,
) -> DivergenceReport {
    let previous_matching_icount = sample_index
        .checked_sub(1)
        .and_then(|index| left.samples.get(index).or_else(|| right.samples.get(index)))
        .map(|sample| sample.icount);
    let left_sample = left.samples.get(sample_index);
    let right_sample = right.samples.get(sample_index);
    let node = left_sample
        .or(right_sample)
        .map(|sample| sample.node.clone());
    let first_different_sample_icount = match (left_sample, right_sample) {
        (Some(left), Some(right)) => Some(left.icount.min(right.icount)),
        (Some(sample), None) | (None, Some(sample)) => Some(sample.icount),
        (None, None) => None,
    };

    DivergenceReport {
        sample_index,
        node,
        previous_matching_icount,
        first_different_sample_icount,
    }
}

fn refine_from_coarse_window<F>(
    previous_matching_icount: Option<u64>,
    first_different_sample_icount: u64,
    matches_at: F,
) -> Result<IcountBisection, DivergenceBisectionError>
where
    F: FnMut(u64) -> bool,
{
    match previous_matching_icount {
        Some(low) => bisect_icount_window(low, first_different_sample_icount, matches_at)
            .map_err(DivergenceBisectionError::InvalidWindow),
        None if first_different_sample_icount == 0 => Ok(IcountBisection {
            last_matching_icount: 0,
            first_different_icount: 0,
        }),
        None => {
            let mut matches_at = matches_at;
            if !matches_at(0) {
                Ok(IcountBisection {
                    last_matching_icount: 0,
                    first_different_icount: 0,
                })
            } else {
                bisect_icount_window(0, first_different_sample_icount, matches_at)
                    .map_err(DivergenceBisectionError::InvalidWindow)
            }
        }
    }
}

fn dump_pair<D>(icount: u64, dump_at: &mut D) -> DivergenceStatePair
where
    D: FnMut(DivergenceSide, u64) -> DivergenceStateDump,
{
    DivergenceStatePair {
        left: dump_at(DivergenceSide::Left, icount),
        right: dump_at(DivergenceSide::Right, icount),
    }
}

fn validate_state_pair(pair: &DivergenceStatePair) -> Result<(), DivergenceBisectionError> {
    validate_state_dump(DivergenceSide::Left, &pair.left)?;
    validate_state_dump(DivergenceSide::Right, &pair.right)
}

fn validate_state_dump(
    side: DivergenceSide,
    dump: &DivergenceStateDump,
) -> Result<(), DivergenceBisectionError> {
    let mut registers = BTreeSet::new();
    for register in &dump.registers {
        if !registers.insert(register.name.clone()) {
            return Err(DivergenceBisectionError::MalformedStateDump {
                side,
                icount: dump.icount,
                field: "register",
                key: register.name.clone(),
            });
        }
    }

    let mut regions = BTreeSet::new();
    for region in &dump.memory_regions {
        let key = memory_region_key(region);
        if !regions.insert(key.clone()) {
            return Err(DivergenceBisectionError::MalformedStateDump {
                side,
                icount: dump.icount,
                field: "memory region",
                key,
            });
        }
    }

    Ok(())
}

fn diff_state_dumps(
    left: &DivergenceStateDump,
    right: &DivergenceStateDump,
) -> DivergenceStateDiff {
    DivergenceStateDiff {
        registers: differing_registers(left, right),
        memory_regions: differing_memory_regions(left, right),
        canonical_events_differ: left.last_canonical_events != right.last_canonical_events,
    }
}

fn differing_registers(left: &DivergenceStateDump, right: &DivergenceStateDump) -> Vec<String> {
    let left_registers = register_map(&left.registers);
    let right_registers = register_map(&right.registers);
    let keys: BTreeSet<String> = left_registers
        .keys()
        .chain(right_registers.keys())
        .cloned()
        .collect();

    keys.into_iter()
        .filter(|name| left_registers.get(name) != right_registers.get(name))
        .collect()
}

fn register_map(registers: &[DivergenceRegister]) -> BTreeMap<String, Vec<u8>> {
    registers
        .iter()
        .map(|register| (register.name.clone(), register.bytes.clone()))
        .collect()
}

fn differing_memory_regions(
    left: &DivergenceStateDump,
    right: &DivergenceStateDump,
) -> Vec<String> {
    let left_regions = memory_region_map(&left.memory_regions);
    let right_regions = memory_region_map(&right.memory_regions);
    let keys: BTreeSet<String> = left_regions
        .keys()
        .chain(right_regions.keys())
        .cloned()
        .collect();

    keys.into_iter()
        .filter(|key| left_regions.get(key) != right_regions.get(key))
        .collect()
}

fn memory_region_map(regions: &[DivergenceMemoryRegion]) -> BTreeMap<String, Vec<u8>> {
    regions
        .iter()
        .map(|region| (memory_region_key(region), region.bytes.clone()))
        .collect()
}

fn memory_region_key(region: &DivergenceMemoryRegion) -> String {
    format!("{}@{:#018x}", region.name, region.start)
}
