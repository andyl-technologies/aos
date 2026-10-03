//! Bounded measurements and checked test-only profile declarations.
//!
//! JSON reports use `aos.filesystem.metadata-scale/v1`. Raw samples are fixed
//! arrays of batch-total nanoseconds; their quantiles are not individual FUSE
//! request quantiles. RSS includes allocator retention and mapped residency.

use std::fs::File;
use std::io::Read;

use aos_filesystem_view::TreeCompileLimits;
use serde::{Deserialize, Serialize};

use crate::Result;
use crate::allocation::AllocationPhase;

pub(super) const BATCHES: usize = 16;
pub(super) const MAX_REPORT_BYTES: u64 = 65_536;
pub(super) const TOUCHED: usize = 128;
pub(super) const OPENS: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Profile {
    Small,
    Million,
}

impl Profile {
    pub(super) const fn name(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Million => "million",
        }
    }

    pub(super) const fn children(self) -> u64 {
        match self {
            Self::Small => 256,
            Self::Million => 1_000_000,
        }
    }

    pub(super) const fn batch_operations(self) -> u64 {
        match self {
            Self::Small => 256,
            Self::Million => 62_500,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Config {
    pub profile: Profile,
    pub validation_envelope_bytes: u64,
}

impl Config {
    pub(super) fn child(profile: &str, envelope: u64) -> Result<Self> {
        let profile = match profile {
            "small" => Profile::Small,
            "million" => Profile::Million,
            _ => return Err("unknown metadata profile".into()),
        };
        if envelope == 0
            || (profile == Profile::Small && envelope != TreeCompileLimits::default().working_bytes)
        {
            return Err("small profile must retain the normal working-byte ceiling".into());
        }
        Ok(Self {
            profile,
            validation_envelope_bytes: envelope,
        })
    }

    pub(super) fn parse(args: &[String]) -> Result<Self> {
        let mut profile = Profile::Small;
        let mut envelope = TreeCompileLimits::default().working_bytes;
        let mut position = 0;
        while position < args.len() {
            match args[position].as_str() {
                "--million" if profile == Profile::Small => profile = Profile::Million,
                "--validation-envelope-bytes" => {
                    position += 1;
                    envelope = args
                        .get(position)
                        .ok_or("missing validation envelope")?
                        .parse()?;
                }
                _ => {
                    return Err(
                        "use --million [--validation-envelope-bytes N] or no arguments".into(),
                    );
                }
            }
            position += 1;
        }
        Self::child(profile.name(), envelope)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct ResourceSnapshot {
    pub virtual_bytes: u64,
    pub rss_bytes: u64,
    pub rss_high_water_bytes: u64,
    pub minor_faults: u64,
    pub major_faults: u64,
}

fn read_proc(path: &str, scratch: &mut [u8; 8192]) -> Result<usize> {
    let mut file = File::open(path)?;
    let mut length = 0;
    while length < scratch.len() {
        let read = file.read(&mut scratch[length..])?;
        if read == 0 {
            return Ok(length);
        }
        length += read;
    }
    Err("proc snapshot exceeds bounded scratch".into())
}

impl ResourceSnapshot {
    pub(super) fn take() -> Result<Self> {
        let mut scratch = [0; 8192];
        let length = read_proc("/proc/self/status", &mut scratch)?;
        let status = std::str::from_utf8(&scratch[..length])?;
        let bytes = |key: &str| -> Result<u64> {
            let line = status
                .lines()
                .find(|line| line.starts_with(key))
                .ok_or("missing proc memory field")?;
            let mut fields = line.split_ascii_whitespace();
            fields.next();
            let amount: u64 = fields.next().ok_or("missing proc memory amount")?.parse()?;
            if fields.next() != Some("kB") || fields.next().is_some() {
                return Err("unexpected proc memory unit".into());
            }
            amount
                .checked_mul(1024)
                .ok_or_else(|| "proc memory amount overflow".into())
        };
        let virtual_bytes = bytes("VmSize:")?;
        let rss_bytes = bytes("VmRSS:")?;
        let rss_high_water_bytes = bytes("VmHWM:")?;
        let length = read_proc("/proc/self/stat", &mut scratch)?;
        let stat = std::str::from_utf8(&scratch[..length])?;
        // The parenthesized comm may contain whitespace or ')' characters.
        let tail = &stat[stat.rfind(')').ok_or("missing proc comm delimiter")? + 1..];
        let field = |offset: usize| -> Result<u64> {
            Ok(tail
                .split_ascii_whitespace()
                .nth(offset)
                .ok_or("missing proc fault field")?
                .parse()?)
        };
        Ok(Self {
            virtual_bytes,
            rss_bytes,
            rss_high_water_bytes,
            minor_faults: field(7)?,
            major_faults: field(9)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub(super) struct Latency {
    pub raw_batch_ns: [u64; BATCHES],
    pub operations_per_batch: u64,
    pub p50_batch_ns: u64,
    pub p95_batch_ns: u64,
    pub p99_batch_ns: u64,
    pub mean_batch_ns: f64,
    pub variance_batch_ns_squared: f64,
}

impl Latency {
    pub(super) fn new(raw: [u64; BATCHES], operations_per_batch: u64) -> Self {
        assert!(operations_per_batch > 0);
        let mut ordered = raw;
        ordered.sort_unstable();
        let quantile = |percent: usize| ordered[(percent * BATCHES).div_ceil(100) - 1];
        let mean = raw.iter().map(|value| *value as f64).sum::<f64>() / BATCHES as f64;
        let variance = raw
            .iter()
            .map(|value| (*value as f64 - mean).powi(2))
            .sum::<f64>()
            / BATCHES as f64;
        Self {
            raw_batch_ns: raw,
            operations_per_batch,
            p50_batch_ns: quantile(50),
            p95_batch_ns: quantile(95),
            p99_batch_ns: quantile(99),
            mean_batch_ns: mean,
            variance_batch_ns_squared: variance,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct BuildReport {
    pub records: u64,
    pub index_bytes: u64,
    pub builder_index_and_working_cap_bytes: u64,
    pub normal_portable_compiler_working_cap_bytes: u64,
    pub elapsed_ns: u64,
    pub allocation: AllocationPhase,
    pub before: ResourceSnapshot,
    pub after: ResourceSnapshot,
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct WorkloadReport {
    pub negative: Latency,
    pub borrowed_positive: Latency,
    pub negative_allocation: AllocationPhase,
    pub modeled_inode_heap_bytes: u64,
    pub modeled_heap_at_open_ceiling_bytes: u64,
    pub open_allocation: AllocationPhase,
    pub touched_nodes_including_root: u64,
    pub peak_open_handles: u64,
    pub retained_working_sets: [WorkingSet; 3],
    pub before: ResourceSnapshot,
    pub after: ResourceSnapshot,
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct WorkingSet {
    pub touched_children: u64,
    pub live_nodes_including_root: u64,
    pub modeled_table_heap_bytes: u64,
    pub allocation: AllocationPhase,
    pub resident_observation: ResourceSnapshot,
    pub after_table_drop_requested_bytes: usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct MeasurementReport {
    pub index_bytes: u64,
    pub mapping_kind: String,
    pub mapped_bytes: u64,
    pub normal_validation_ceiling_bytes: u64,
    pub normal_validation_refused: bool,
    /// Actual cap-minus-one validator refusal, not an inferred estimate comparison.
    pub underbudget_validation_refused: bool,
    pub underbudget_validation_allocation: AllocationPhase,
    pub computed_validation_reservation_bytes: u64,
    pub selected_validation_cap_bytes: u64,
    pub validated: bool,
    pub refusal: Option<String>,
    pub validation_elapsed_ns: u64,
    pub validation_allocation: AllocationPhase,
    pub validation_before: ResourceSnapshot,
    pub validation_after: ResourceSnapshot,
    pub workload: Option<WorkloadReport>,
    pub drop_baseline_requested_bytes: usize,
    pub after_drop_requested_bytes: usize,
    pub after_unmap: ResourceSnapshot,
}

#[derive(Serialize)]
pub(super) struct Report {
    pub schema: &'static str,
    pub scope: &'static str,
    pub architecture: &'static str,
    pub kernel: String,
    pub hardware_class: String,
    pub source_commit_label: String,
    pub concurrency: u32,
    pub cache_state: &'static str,
    pub security_profile: &'static str,
    pub profile: Profile,
    pub validation_envelope_bytes: u64,
    pub construction: BuildReport,
    pub measurement: MeasurementReport,
    pub temporary_files_removed: bool,
}

pub(super) fn check_helpers() {
    let report = Latency::new(std::array::from_fn(|index| index as u64 + 1), 1);
    assert_eq!(
        (
            report.p50_batch_ns,
            report.p95_batch_ns,
            report.p99_batch_ns
        ),
        (8, 16, 16)
    );
    assert_eq!(report.mean_batch_ns, 8.5);
    assert_eq!(report.variance_batch_ns_squared, 21.25);
    assert!(Config::child("small", 1).is_err());
    assert!(Config::child("million", 0).is_err());
    assert_eq!(Profile::Million.children() + 1, 1_000_001);

    // Accounting must handle freeing a pre-phase allocation, not just new ones.
    let old = std::hint::black_box(vec![0_u8; 64]);
    let (_, phase) = crate::allocation::measure(|| drop(old));
    assert_eq!(
        phase.live_requested_bytes + 64,
        phase.baseline_requested_bytes
    );
    assert_eq!(phase.allocation_calls, 0);
    let mut grow = Vec::<u8>::with_capacity(8);
    let (_, phase) = crate::allocation::measure(|| grow.reserve_exact(256));
    std::hint::black_box(&grow);
    assert!(phase.live_requested_bytes > phase.baseline_requested_bytes);
    assert_eq!(phase.allocation_calls, 1);
}
