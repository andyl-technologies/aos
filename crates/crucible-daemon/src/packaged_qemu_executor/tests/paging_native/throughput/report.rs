//! Bounded, versioned throughput receipts from durable completion and live RAM.
//!
//! Rates retain integer count/time pairs. Repeated rows retain raw samples;
//! unavailable phase metrics are explicitly null, never synthetic zero values.

use super::*;
use serde::{Serialize, Serializer};
use std::io::{Read, Write};

#[derive(Serialize)]
pub(super) struct PinnedInputs {
    host: String,
    storage: String,
    cpu_affinity: String,
    artifact_digests: Vec<ArtifactDigest>,
}

#[derive(Serialize)]
struct ArtifactDigest {
    role: &'static str,
    path: String,
    bytes: u64,
    blake3: [u8; 32],
}

fn corpus_identities(
    scenarios: &blake3::Hasher,
    artifacts: &[ArtifactDigest],
) -> ([u8; 32], [u8; 32]) {
    let scenario_identity = *scenarios.clone().finalize().as_bytes();
    let mut deployment = scenarios.clone();
    for artifact in artifacts {
        deployment.update(&artifact.blake3);
        deployment.update(&artifact.bytes.to_le_bytes());
    }

    (scenario_identity, *deployment.finalize().as_bytes())
}

impl PinnedInputs {
    pub(super) fn read(
        controller: &workers::WorkerService,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let label = |name| -> Result<String, Box<dyn std::error::Error>> {
            let value = std::env::var(name)?;
            if value.is_empty() || value.len() > 1024 {
                return Err("pinned deployment label is missing or exceeds 1024 bytes".into());
            }
            Ok(value)
        };
        let cpu_affinity = label("CRUCIBLE_THROUGHPUT_CPU_AFFINITY")?;
        let status = std::fs::read_to_string("/proc/self/status")?;
        let actual = status
            .lines()
            .find_map(|line| line.strip_prefix("Cpus_allowed_list:\t"))
            .ok_or("kernel process affinity witness is absent")?;
        if actual != cpu_affinity {
            return Err("actual kernel CPU affinity differs from the declared pinned host".into());
        }
        let original = controller.supervisor();
        let authentication = original.begin(HostOperationClass::Preparation)?;
        let mut artifact_digests = Vec::with_capacity(5);
        for role in [
            "CRUCIBLE_PAGING_QEMU",
            "CRUCIBLE_PAGING_PLUGIN",
            "CRUCIBLE_PAGING_KERNEL",
            "CRUCIBLE_PAGING_INITRD",
            "CRUCIBLE_PAGING_ROOT",
        ] {
            authentication.wait_slice()?;
            let path = environment_path(role);
            if role != "CRUCIBLE_PAGING_ROOT" && !path.starts_with("/nix/store") {
                return Err(
                    "benchmark kernel, initrd and native artifacts must be immutable AOS store inputs"
                        .into(),
                );
            }
            let mut file = std::fs::File::open(&path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.len() > 8 << 30 {
                return Err("benchmark artifact is not a bounded regular immutable file".into());
            }
            let mut hasher = blake3::Hasher::new();
            let mut bytes = 0_u64;
            let mut scratch = [0_u8; 4096];
            loop {
                authentication.wait_slice()?;
                let count = file.read(&mut scratch)?;
                if count == 0 {
                    break;
                }
                bytes = bytes
                    .checked_add(u64::try_from(count)?)
                    .filter(|bytes| *bytes <= metadata.len())
                    .ok_or("immutable artifact length changed during authentication")?;
                hasher.update(&scratch[..count]);
            }
            if bytes != metadata.len() {
                return Err("immutable artifact ended before its authenticated length".into());
            }
            artifact_digests.push(ArtifactDigest {
                role,
                path: path.display().to_string(),
                bytes,
                blake3: *hasher.finalize().as_bytes(),
            });
        }
        authentication.complete()?;
        Ok(Self {
            host: label("CRUCIBLE_THROUGHPUT_HOST")?,
            storage: label("CRUCIBLE_THROUGHPUT_STORAGE")?,
            cpu_affinity,
            artifact_digests,
        })
    }
}

#[derive(Serialize)]
pub(super) struct Row {
    pub(super) target_divisor: u64,
    pub(super) parallel: usize,
    pub(super) repeat: usize,
    pub(super) elapsed_ns: u64,
    pub(super) completed_work_cpu_ns: Option<u64>,
    pub(super) completed: u64,
    pub(super) completed_attempts_per_host_hour: f64,
    pub(super) failures: Vec<String>,
    pub(super) samples: Vec<Sample>,
    #[serde(serialize_with = "vector")]
    pub(super) reservation_peak: HostResourceVector,
    pub(super) paused_census: resource_census::Census,
    pub(super) cleanup_census: resource_census::Census,
}

#[derive(Serialize)]
pub(super) struct Sample {
    pub(super) seed: u64,
    pub(super) scenario: [u8; 32],
    pub(super) fingerprint: [u8; 32],
    pub(super) fingerprint_ns: u64,
    pub(super) guest_drive_ns: u64,
    pub(super) charged_physical_quanta: u64,
    pub(super) emitted_signal_events: u64,
    pub(super) fault_work_items: Option<usize>,
    pub(super) requested_target_bytes: u64,
    pub(super) effective_target_bytes: u64,
    #[serde(serialize_with = "activity")]
    pub(super) activity: Option<HostRamActivity>,
    #[serde(serialize_with = "vector")]
    pub(super) resources: HostResourceVector,
}

#[derive(Serialize)]
struct RepeatedRates {
    target_divisor: u64,
    parallel: usize,
    trials: usize,
    failed_trials: usize,
    minimum: f64,
    median: f64,
    maximum: f64,
}

fn repeated_rates(rows: &[Row]) -> Vec<RepeatedRates> {
    let mut summaries = Vec::with_capacity(TARGET_DIVISORS.len() * PARALLEL.len());
    for target_divisor in TARGET_DIVISORS {
        for parallel in PARALLEL {
            let mut rates = [0.0; REPEATS];
            let mut trials = 0;
            let mut failed_trials = 0;
            for row in rows
                .iter()
                .filter(|row| row.target_divisor == target_divisor && row.parallel == parallel)
            {
                assert!(trials < REPEATS, "fixed repeated-trial inventory");
                rates[trials] = row.completed_attempts_per_host_hour;
                trials += 1;
                failed_trials += usize::from(!row.failures.is_empty());
            }
            assert_eq!(trials, REPEATS, "every repeated row remains in the receipt");
            rates.sort_by(f64::total_cmp);
            summaries.push(RepeatedRates {
                target_divisor,
                parallel,
                trials,
                failed_trials,
                minimum: rates[0],
                median: rates[REPEATS / 2],
                maximum: rates[REPEATS - 1],
            });
        }
    }
    summaries
}

pub(super) fn now() -> u64 {
    // Host elapsed measurements never enter scheduler decisions or identities.
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    clock_ns(value.tv_sec, value.tv_nsec).expect("valid bounded kernel monotonic time")
}

fn clock_ns(seconds: i64, nanoseconds: i64) -> Option<u64> {
    if !(0..1_000_000_000).contains(&nanoseconds) {
        return None;
    }

    u64::try_from(seconds)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(nanoseconds).ok()?)
}

#[expect(
    clippy::float_arithmetic,
    reason = "host throughput reporting preserves the integer count and elapsed time; the derived rate never enters scheduler decisions or identities"
)]
pub(super) fn rate(completed: u64, elapsed_ns: u64) -> f64 {
    assert_ne!(
        elapsed_ns, 0,
        "a throughput rate requires a positive measured interval"
    );
    completed as f64 * 3_600_000_000_000.0 / elapsed_ns as f64
}

pub(super) fn publish_row(row: &Row) {
    let mut output = std::io::stdout().lock();
    output
        .write_all(b"COMPLETED_CAMPAIGN_THROUGHPUT_ROW=")
        .expect("row sink");
    serde_json::to_writer(&mut output, row).expect("bounded streaming row");
    output.write_all(b"\n").expect("complete measured row");
}

pub(super) fn availability(owner: &GuardedCampaignOwner) -> HostResourceVector {
    owner
        .inner
        .actor
        .with_supervisor(|actor| {
            actor
                .host_resource_availability()
                .ok_or(HostOperationalError::Unavailable)
        })
        .expect("actual eight-dimensional actor")
}

pub(super) fn completed_count(owner: &GuardedCampaignOwner) -> u64 {
    owner
        .inner
        .actor
        .with_supervisor(|actor| Ok(actor.native_completed_transitions()))
        .expect("same original actor's committed completion counter")
}

pub(super) fn target(
    context: &AttemptExecutionContext,
) -> Result<HostRamTarget, HostOperationalError> {
    let registry = context
        .host_operational_registry()
        .ok_or(HostOperationalError::Unavailable)?;
    let target = HostRamOwnerTarget {
        daemon_epoch: context.host_daemon_epoch(),
        owner_id: context
            .host_ram_owner_id()
            .ok_or(HostOperationalError::Unavailable)?,
    };
    let response = registry.execute(
        OPERATOR,
        HostOperationalRequest::ListTargets {
            target,
            after: None,
            limit: 2,
        },
    )?;
    match response.value() {
        HostOperationalResponse::Targets { targets, next, .. }
            if targets.len() == 1 && next.is_none() =>
        {
            Ok(targets[0])
        }
        _ => Err(HostOperationalError::Unavailable),
    }
}

pub(super) fn status(
    registry: &crate::HostOperationalRegistry,
    target: HostRamTarget,
) -> Result<crucible_api::AdmittedOutput<HostOperationalResponse>, HostOperationalError> {
    registry.execute(OPERATOR, HostOperationalRequest::Status { target })
}

pub(super) fn observe_peak(
    owner: &GuardedCampaignOwner,
    baseline: HostResourceVector,
    peak: &mut HostResourceVector,
) {
    let current = availability(owner);
    macro_rules! update {
        ($($field:ident),+ $(,)?) => { $(peak.$field = peak.$field.max(
            baseline.$field.checked_sub(current.$field).expect("no unowned capacity appears during cohort"));)+ };
    }
    update!(
        resident_peak_bytes,
        backing_peak_bytes,
        metadata_bytes,
        staging_bytes,
        paging_io_slots,
        cpu_slots,
        task_slots,
        file_descriptors
    );
}

fn vector<S: Serializer>(value: &HostResourceVector, serializer: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Fields {
        resident_peak_bytes: u64,
        backing_peak_bytes: u64,
        metadata_bytes: u64,
        staging_bytes: u64,
        paging_io_slots: u64,
        cpu_slots: u64,
        task_slots: u64,
        file_descriptors: u64,
    }
    Fields {
        resident_peak_bytes: value.resident_peak_bytes,
        backing_peak_bytes: value.backing_peak_bytes,
        metadata_bytes: value.metadata_bytes,
        staging_bytes: value.staging_bytes,
        paging_io_slots: value.paging_io_slots,
        cpu_slots: value.cpu_slots,
        task_slots: value.task_slots,
        file_descriptors: value.file_descriptors,
    }
    .serialize(serializer)
}

fn activity<S: Serializer>(
    value: &Option<HostRamActivity>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Fields {
        missing: u64,
        missing_read: u64,
        missing_write: u64,
        write_protect: u64,
        preservation_reads: u64,
        preservation_writes: u64,
        physical_discards: u64,
        prefetched_pages: u64,
    }
    value
        .map(|value| Fields {
            missing: value.successful_missing_installs,
            missing_read: value.successful_missing_read_installs,
            missing_write: value.successful_missing_write_installs,
            write_protect: value.write_protect_transitions,
            preservation_reads: value.preservation_reads,
            preservation_writes: value.preservation_writes,
            physical_discards: value.physical_discards,
            prefetched_pages: value.prefetched_pages,
        })
        .serialize(serializer)
}

pub(super) fn publish(
    pin: &PinnedInputs,
    source: &ScenarioDefForm,
    config: &PackagedQemuExecutorConfig,
    rows: &[Row],
) {
    #[derive(Serialize)]
    struct Receipt<'a> {
        schema: &'static str,
        scope: &'static str,
        pinned: &'a PinnedInputs,
        corpus: [u8; 32],
        scenario_corpus: [u8; 32],
        scenario_corpus_scope: &'static str,
        completed_work_cpu_scope: &'static str,
        scenario_seeds: &'a [u64],
        fingerprint_comparison: &'static str,
        quanta_per_attempt: u64,
        preparation_total_seconds: Option<u64>,
        native_qemu: String,
        native_plugin: String,
        guest_kernel: String,
        guest_initrd: String,
        rows: &'a [Row],
        repeated_rates: Vec<RepeatedRates>,
        rate: &'static str,
        cache_scope: &'static str,
        resource_census_schema: &'static str,
        resource_census_scope: &'static str,
        unavailable_metrics: [&'static str; 7],
    }
    let mut corpus = blake3::Hasher::new();
    corpus.update(b"crucible.completed-campaign-throughput-corpus.v1\0");
    for seed in corpus::SEEDS {
        let source = corpus::seeded_source(source, seed).expect("original corpus reconstruction");
        let scenario =
            crate::encode_crucible_scenario_artifact(&source).expect("actual corpus bytes");
        corpus.update(&seed.to_le_bytes());
        corpus.update(&(scenario.payload().len() as u64).to_le_bytes());
        corpus.update(scenario.payload());
    }
    corpus.update(&QUANTA_PER_ATTEMPT.to_le_bytes());
    // Separate the authored scenarios from the native build under comparison.
    // This identifier alone does not bind implicit firmware or host policy.
    let (scenario_corpus, corpus) = corpus_identities(&corpus, &pin.artifact_digests);
    let receipt = Receipt {
        schema: "crucible.completed-campaign-throughput.v2",
        scope: "real accepted campaigns; managed native qualification only; full original peaks",
        pinned: pin,
        corpus,
        scenario_corpus,
        scenario_corpus_scope: "canonical seeded scenarios and quanta only; guest artifact, firmware, host/storage and native build identities remain separate comparison obligations",
        completed_work_cpu_scope: "unavailable; controller process CPU excludes native descendants and cannot substitute for equal completed-work CPU",
        scenario_seeds: &corpus::SEEDS,
        fingerprint_comparison: "raw per-seed boundaries; compare only matching seed/corpus against baseline; no cross-seed equality claim",
        quanta_per_attempt: QUANTA_PER_ATTEMPT,
        preparation_total_seconds: config
            .host_operation_budgets()
            .expect("actual accepted roster")
            .get(HostOperationClass::Preparation)
            .total_timeout
            .map(|duration| duration.as_secs()),
        native_qemu: environment_path("CRUCIBLE_PAGING_QEMU")
            .display()
            .to_string(),
        native_plugin: environment_path("CRUCIBLE_PAGING_PLUGIN")
            .display()
            .to_string(),
        guest_kernel: environment_path("CRUCIBLE_PAGING_KERNEL")
            .display()
            .to_string(),
        guest_initrd: environment_path("CRUCIBLE_PAGING_INITRD")
            .display()
            .to_string(),
        rows,
        repeated_rates: repeated_rates(rows),
        rate: "completed * 3600000000000 / elapsed_ns attempts per host hour; raw repeats retained",
        cache_scope: "fresh native processes; shared immutable catalog; host storage cache not controlled",
        resource_census_schema: "crucible.host-resource-census.v1",
        resource_census_scope: concat!(
            "controller-thread stopped prepared worlds and post-join cleanup; ",
            "cgroup hierarchy and combined admitted host-run/lifecycle run-state storage, ",
            "catalog excluded; shared RSS counts mappings, PSS is proportional; ",
            "best-effort observations with process birth/inode and membership revalidation; ",
            "null means unavailable, observed identity instability or finite census bound exceeded; ",
            "stopped census overhead is included in row elapsed but excluded from guest ",
            "drive/fingerprint intervals; no atomic snapshot, cleanup authority or peak usage claim"
        ),
        unavailable_metrics: [
            "completed-work CPU including native descendants",
            "cold host-cache throughput",
            "fork duration",
            "capture-restore duration",
            "transfer duration",
            "index failure attribution",
            "RSS peak",
        ],
    };
    let mut output = std::io::stdout().lock();
    output
        .write_all(b"COMPLETED_CAMPAIGN_THROUGHPUT_RECEIPT=")
        .expect("report sink");
    serde_json::to_writer(&mut output, &receipt).expect("bounded streaming report");
    output.write_all(b"\n").expect("complete receipt line");
}

#[test]
fn rate_uses_completed_terminal_count_and_entire_host_interval() {
    assert_eq!(rate(4, 3_600_000_000_000), 4.0);
    assert_eq!(rate(0, 1_000_000_000), 0.0);
    assert_eq!(rate(1, 1_000_000_000), 3600.0);
}

#[test]
fn repeated_receipt_keeps_failed_rows_in_uncertainty() {
    // Pure report arithmetic has no actor or native admission authority.
    let mut rows = Vec::new();
    for target_divisor in TARGET_DIVISORS {
        for parallel in PARALLEL {
            for repeat in 0..REPEATS {
                let failed = repeat == 1;
                rows.push(Row {
                    target_divisor,
                    parallel,
                    repeat,
                    elapsed_ns: 3_600_000_000_000,
                    completed_work_cpu_ns: None,
                    completed: u64::from(!failed),
                    completed_attempts_per_host_hour: f64::from(u32::from(!failed)),
                    failures: if failed {
                        vec!["fixture storage failure".into()]
                    } else {
                        Vec::new()
                    },
                    samples: Vec::new(),
                    reservation_peak: HostResourceVector::default(),
                    paused_census: resource_census::Census::default(),
                    cleanup_census: resource_census::Census::default(),
                });
            }
        }
    }
    let summaries = repeated_rates(&rows);
    assert_eq!(summaries.len(), TARGET_DIVISORS.len() * PARALLEL.len());
    assert!(summaries.iter().all(|summary| summary.trials == 3
        && summary.failed_trials == 1
        && summary.minimum == 0.0
        && summary.median == 1.0
        && summary.maximum == 1.0));
}

#[test]
fn clock_conversion_rejects_invalid_fields_and_overflow() {
    assert_eq!(clock_ns(1, 999_999_999), Some(1_999_999_999));
    assert_eq!(clock_ns(-1, 0), None);
    assert_eq!(clock_ns(1, -1), None);
    assert_eq!(clock_ns(1, 1_000_000_000), None);
    assert_eq!(clock_ns(i64::MAX, 0), None);
}

#[test]
fn scenario_identity_is_retained_before_native_build_binding() {
    let mut scenarios = blake3::Hasher::new();
    scenarios.update(b"synthetic canonical scenarios and quanta");
    let artifact = |byte| ArtifactDigest {
        role: "CRUCIBLE_PAGING_QEMU",
        path: "synthetic native artifact".into(),
        bytes: 1,
        blake3: [byte; 32],
    };
    let reference = corpus_identities(&scenarios, &[artifact(1)]);
    let candidate = corpus_identities(&scenarios, &[artifact(2)]);

    assert_eq!(reference.0, candidate.0);
    assert_ne!(reference.1, candidate.1);
    scenarios.update(b"different synthetic authored work");
    assert_ne!(reference.0, corpus_identities(&scenarios, &[artifact(1)]).0);
}

#[test]
fn absent_paging_observation_serializes_as_unavailable() {
    let sample = Sample {
        seed: 1000,
        scenario: [0; 32],
        fingerprint: [0; 32],
        fingerprint_ns: 1,
        guest_drive_ns: 1,
        charged_physical_quanta: 0,
        emitted_signal_events: 0,
        fault_work_items: None,
        requested_target_bytes: 0,
        effective_target_bytes: 0,
        activity: None,
        resources: HostResourceVector::default(),
    };
    let encoded = serde_json::to_value(&sample).expect("pure report encoding");
    assert!(encoded["activity"].is_null());
    assert!(encoded["fault_work_items"].is_null());
}
