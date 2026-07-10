//! Real QEMU trace-plugin import for execution fingerprints.
//!
//! The diagnostic QEMU plugin writes one JSON object per periodic sample. This
//! module validates that host-observed wire form and converts it into the same
//! canonical [`SingleVmFingerprintStream`] used by the run-twice gate. It
//! rejects missing vCPUs, incomplete register reads, a mismatched QMP topology,
//! RR-cursor drift, missing full-RAM observation, and disabled device-event
//! observation instead of silently manufacturing fingerprint components.

use std::io::{self, BufRead};

use crucible::ContentHash;
use serde_json::Value;
use thiserror::Error;

use super::{
    SingleVmFingerprintGateError, SingleVmFingerprintSample, SingleVmFingerprintSampleMaterial,
    SingleVmFingerprintStream, SingleVmFingerprintTrigger, SingleVmNvcpuFingerprintContract,
    SingleVmNvcpuFingerprintMaterial, SingleVmQmpVcpuTopology, SingleVmRoundRobinCursor,
    SingleVmVcpuRegisterDigest, initial_single_vm_rolling_fingerprint,
};

const REGISTER_COMPONENT_DOMAIN: &str = "crucible.qemu.trace-register-component.v1";
const MEMORY_COMPONENT_DOMAIN: &str = "crucible.qemu.trace-memory-component.v1";
const DEVICE_EVENT_COMPONENT_DOMAIN: &str = "crucible.qemu.trace-device-event-component.v1";
const PROVISIONAL_DEFINITION_DOMAIN: &str =
    "crucible.qemu.provisional-trace-fingerprint-definition.v1";

/// Wire-schema identifier emitted by the provisional QEMU trace plugin.
pub const QEMU_TRACE_FINGERPRINT_SCHEMA: &str = "crucible.qemu.trace-fingerprint.v2";

/// Provisional fingerprint definition implemented by the diagnostic trace path.
///
/// Unlike [`crate::QemuExecutionFingerprintDefinition`], this definition does
/// not claim event-boundary sampling or complete current device state. Its
/// device component is explicitly the cumulative history of CPU-observed MMIO
/// events, and its only trigger is the periodic aggregate-icount cadence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuTraceFingerprintDefinition {
    canonical_material: String,
}

impl QemuTraceFingerprintDefinition {
    /// Builds the provisional trace definition for one periodic cadence.
    ///
    /// # Errors
    ///
    /// Returns [`QemuTraceFingerprintImportError::InvalidContract`] when the
    /// cadence is zero.
    pub fn new(
        cadence_icount: u64,
        observation: &QemuTraceObservationContract,
    ) -> Result<Self, QemuTraceFingerprintImportError> {
        if cadence_icount == 0 {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace fingerprint cadence must be non-zero",
            });
        }
        Ok(Self {
            canonical_material: provisional_definition_material(cadence_icount, observation),
        })
    }

    /// Returns the canonical material describing the provisional observation.
    #[must_use]
    pub fn canonical_material(&self) -> &str {
        &self.canonical_material
    }

    /// Returns the content-addressed provisional definition digest.
    #[must_use]
    pub fn definition_digest(&self) -> [u8; 32] {
        ContentHash::from_canonical_material(
            PROVISIONAL_DEFINITION_DOMAIN,
            self.canonical_material(),
        )
        .bytes
    }
}

fn provisional_definition_material(
    cadence_icount: u64,
    observation: &QemuTraceObservationContract,
) -> String {
    let mut lines = vec![
        QEMU_TRACE_FINGERPRINT_SCHEMA.to_owned(),
        "status=provisional".to_owned(),
        format!("cadence_icount={cadence_icount}"),
        "trigger=periodic-aggregate-icount-only".to_owned(),
        "component[0]=aggregate-icount".to_owned(),
        "component[1]=all-vcpu-register-files-fnv1a64-standard-v2".to_owned(),
        "component[2]=full-guest-ram-aos-legacy-fnv-offset-v1".to_owned(),
        "component[3]=ordered-cpu-mmio-read-write-history-fnv1a64-standard-v2".to_owned(),
        "complete_current_device_state=false".to_owned(),
        "event_boundary_sampling=false".to_owned(),
        format!("rr_switch_quantum={}", observation.rr_switch_quantum),
        format!("baseline_ram_bytes={}", observation.baseline_ram_bytes),
        format!(
            "launch_definition_digest={}",
            observation.identity.launch_definition_digest
        ),
        format!(
            "qemu_build_digest={}",
            observation.identity.qemu_build_digest
        ),
        format!(
            "trace_plugin_build_digest={}",
            observation.identity.trace_plugin_build_digest
        ),
    ];
    for (index, cpu_id) in observation.qmp_cpu_ids.iter().enumerate() {
        let contract = observation.vcpu_contracts[index];
        lines.push(format!("vcpu[{index}].cpu_id={cpu_id}"));
        lines.push(format!(
            "vcpu[{index}].baseline_register_count={}",
            contract.register_count
        ));
        lines.push(format!(
            "vcpu[{index}].baseline_register_file_bytes={}",
            contract.register_file_bytes
        ));
        lines.push(format!(
            "vcpu[{index}].baseline_register_schema_hash={:016x}",
            contract.register_schema_hash
        ));
    }
    lines.join("\n")
}

/// Digests that bind a trace to launch, QEMU, and trace-plugin identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuTraceIdentityContract {
    launch_definition_digest: String,
    qemu_build_digest: String,
    trace_plugin_build_digest: String,
}

impl QemuTraceIdentityContract {
    /// Builds an exact trace identity contract from SHA-256 hex digests.
    ///
    /// # Errors
    ///
    /// Returns [`QemuTraceFingerprintImportError::InvalidContract`] when any
    /// digest is not exactly 64 hexadecimal digits.
    pub fn new(
        launch_definition_digest: impl Into<String>,
        qemu_build_digest: impl Into<String>,
        trace_plugin_build_digest: impl Into<String>,
    ) -> Result<Self, QemuTraceFingerprintImportError> {
        let identity = Self {
            launch_definition_digest: launch_definition_digest.into(),
            qemu_build_digest: qemu_build_digest.into(),
            trace_plugin_build_digest: trace_plugin_build_digest.into(),
        };
        if !is_sha256_hex(&identity.launch_definition_digest)
            || !is_sha256_hex(&identity.qemu_build_digest)
            || !is_sha256_hex(&identity.trace_plugin_build_digest)
        {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace identity digests must contain exactly 64 hexadecimal digits",
            });
        }
        Ok(identity)
    }
}

/// Caller-supplied baseline register observation for one QMP vCPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuTraceVcpuContract {
    cpu_id: u64,
    register_count: u64,
    register_file_bytes: u64,
    register_schema_hash: u64,
}

impl QemuTraceVcpuContract {
    /// Builds one exact register-observation contract.
    ///
    /// # Errors
    ///
    /// Returns [`QemuTraceFingerprintImportError::InvalidContract`] when the
    /// descriptor count or canonical register byte count is zero.
    pub fn new(
        cpu_id: u64,
        register_count: u64,
        register_file_bytes: u64,
        register_schema_hash: u64,
    ) -> Result<Self, QemuTraceFingerprintImportError> {
        if register_count == 0 {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace register descriptor count must be non-zero",
            });
        }
        if register_file_bytes == 0 {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace canonical register byte count must be non-zero",
            });
        }
        Ok(Self {
            cpu_id,
            register_count,
            register_file_bytes,
            register_schema_hash,
        })
    }

    /// Returns the QMP CPU index covered by this contract.
    #[must_use]
    pub const fn cpu_id(self) -> u64 {
        self.cpu_id
    }
}

/// Exact comparison-baseline and QMP-bound shape for one trace import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuTraceObservationContract {
    qmp_cpu_ids: Vec<u64>,
    rr_switch_quantum: u64,
    baseline_ram_bytes: u64,
    vcpu_contracts: Vec<QemuTraceVcpuContract>,
    identity: QemuTraceIdentityContract,
}

impl QemuTraceObservationContract {
    /// Builds an exact observation-shape contract.
    ///
    /// # Errors
    ///
    /// Returns [`QemuTraceFingerprintImportError::InvalidContract`] when CPU
    /// indexes are not exactly `0..N`, RAM coverage is zero, or register
    /// contracts do not match the QMP CPU set.
    pub fn new(
        qmp_cpu_ids: Vec<u64>,
        rr_switch_quantum: u64,
        baseline_ram_bytes: u64,
        vcpu_contracts: Vec<QemuTraceVcpuContract>,
        identity: QemuTraceIdentityContract,
    ) -> Result<Self, QemuTraceFingerprintImportError> {
        validate_cpu_ids(&qmp_cpu_ids)?;
        if rr_switch_quantum == 0 {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace observation contract requires a non-zero RR quantum",
            });
        }
        if baseline_ram_bytes == 0 {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace fingerprint contract requires exact non-zero RAM bytes",
            });
        }
        if vcpu_contracts.len() != qmp_cpu_ids.len()
            || vcpu_contracts
                .iter()
                .zip(&qmp_cpu_ids)
                .any(|(contract, cpu_id)| contract.cpu_id() != *cpu_id)
        {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace vCPU contracts must cover the exact sorted QMP CPU index set",
            });
        }
        Ok(Self {
            qmp_cpu_ids,
            rr_switch_quantum,
            baseline_ram_bytes,
            vcpu_contracts,
            identity,
        })
    }
}

/// Fixed import contract for one real-QEMU trace-plugin run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuTraceFingerprintImport {
    node: String,
    definition_digest: Vec<u8>,
    cadence_icount: u64,
    run_horizon_icount: u64,
    qmp_cpu_ids: Vec<u64>,
    nvcpu_contract: SingleVmNvcpuFingerprintContract,
    baseline_ram_bytes: u64,
    vcpu_contracts: Vec<QemuTraceVcpuContract>,
    identity: QemuTraceIdentityContract,
}

impl QemuTraceFingerprintImport {
    /// Builds a real-QEMU trace import contract.
    ///
    /// The QMP-observed topology is retained separately from the launch-derived
    /// contract so every imported sample is checked against both boundaries.
    ///
    /// # Errors
    ///
    /// Returns [`QemuTraceFingerprintImportError::InvalidContract`] when the
    /// node name or cadence is empty, the horizon is not on the cadence, the
    /// digest is malformed, or the N-vCPU contract is invalid.
    pub fn new(
        node: impl Into<String>,
        definition_digest: impl Into<Vec<u8>>,
        cadence_icount: u64,
        run_horizon_icount: u64,
        observation: QemuTraceObservationContract,
    ) -> Result<Self, QemuTraceFingerprintImportError> {
        let node = node.into();
        if node.is_empty() {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace fingerprint node id must be non-empty",
            });
        }
        if cadence_icount == 0 {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace fingerprint cadence must be non-zero",
            });
        }
        if run_horizon_icount == 0 || !run_horizon_icount.is_multiple_of(cadence_icount) {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace fingerprint horizon must be a non-zero cadence multiple",
            });
        }
        let definition_digest = definition_digest.into();
        initial_single_vm_rolling_fingerprint(&definition_digest).map_err(|source| {
            QemuTraceFingerprintImportError::CanonicalStream { line: 0, source }
        })?;
        let qmp_topology =
            SingleVmQmpVcpuTopology::new(observation.qmp_cpu_ids.len()).map_err(|source| {
                QemuTraceFingerprintImportError::CanonicalStream { line: 0, source }
            })?;
        let nvcpu_contract = SingleVmNvcpuFingerprintContract::new(
            qmp_topology.vcpu_count(),
            observation.rr_switch_quantum,
        )
        .map_err(|source| QemuTraceFingerprintImportError::CanonicalStream { line: 0, source })?;
        Ok(Self {
            node,
            definition_digest,
            cadence_icount,
            run_horizon_icount,
            qmp_cpu_ids: observation.qmp_cpu_ids,
            nvcpu_contract,
            baseline_ram_bytes: observation.baseline_ram_bytes,
            vcpu_contracts: observation.vcpu_contracts,
            identity: observation.identity,
        })
    }

    /// Imports one completed real-QEMU JSON-lines trace.
    ///
    /// Non-sample diagnostic records, such as RR-switch and deterministic-IPI
    /// records, are ignored. Periodic sample records must cover every cadence
    /// point through the configured horizon exactly once. The terminal plugin
    /// exit record is required as evidence that QEMU reached its requested
    /// stop, but is not fingerprinted because teardown no longer exposes a
    /// valid live RR cursor.
    ///
    /// # Errors
    ///
    /// Returns [`QemuTraceFingerprintImportError`] when input cannot be read or
    /// decoded, any required sample field is absent or malformed, host-observed
    /// state is incomplete, cadence coverage is not exact, or canonical stream
    /// validation fails.
    pub fn import<R: BufRead>(
        &self,
        reader: R,
    ) -> Result<SingleVmFingerprintStream, QemuTraceFingerprintImportError> {
        let mut samples: Vec<SingleVmFingerprintSample> = Vec::new();
        let mut previous =
            initial_single_vm_rolling_fingerprint(&self.definition_digest).map_err(|source| {
                QemuTraceFingerprintImportError::CanonicalStream { line: 0, source }
            })?;
        let mut terminal_stop_seen = false;
        let mut previous_retired: Option<Vec<u64>> = None;

        for (line_index, line) in reader.lines().enumerate() {
            let line_number = line_index.saturating_add(1);
            let line = line.map_err(|source| QemuTraceFingerprintImportError::Io {
                line: line_number,
                source,
            })?;
            if line.trim().is_empty() {
                return Err(QemuTraceFingerprintImportError::MalformedTrace {
                    line: line_number,
                    reason: "blank JSON-lines record".to_owned(),
                });
            }
            let value: Value = serde_json::from_str(&line).map_err(|source| {
                QemuTraceFingerprintImportError::Json {
                    line: line_number,
                    source,
                }
            })?;
            if let Some(kind) = value.get("kind").and_then(Value::as_str) {
                match kind {
                    "rr_switch" | "det_ipi" => continue,
                    _ => {
                        return Err(QemuTraceFingerprintImportError::MalformedTrace {
                            line: line_number,
                            reason: format!("unknown QEMU trace diagnostic kind `{kind}`"),
                        });
                    }
                }
            }
            require_str(&value, "schema", QEMU_TRACE_FINGERPRINT_SCHEMA, line_number)?;
            self.require_identity(&value, line_number)?;
            if bool_field(&value, "final", line_number)? {
                if terminal_stop_seen {
                    return Err(QemuTraceFingerprintImportError::MalformedTrace {
                        line: line_number,
                        reason: "duplicate terminal plugin stop record".to_owned(),
                    });
                }
                require_true(&value, "stop_requested", line_number)?;
                require_u64(&value, "stop_at", self.run_horizon_icount, line_number)?;
                if u64_field(&value, "retired", line_number)? != self.run_horizon_icount {
                    return Err(QemuTraceFingerprintImportError::MalformedTrace {
                        line: line_number,
                        reason:
                            "terminal plugin record must retire at the exact configured horizon"
                                .to_owned(),
                    });
                }
                if samples.last().map(|sample| sample.icount) != Some(self.run_horizon_icount) {
                    return Err(QemuTraceFingerprintImportError::MalformedTrace {
                        line: line_number,
                        reason: "terminal plugin record preceded the horizon sample".to_owned(),
                    });
                }
                require_true(&value, "rr_cursor_valid", line_number)?;
                require_str(
                    &value,
                    "rr_cursor_source",
                    "last_executed_instruction",
                    line_number,
                )?;
                let terminal_quantum = u64_field(&value, "rr_switch_quantum", line_number)?;
                if terminal_quantum != self.nvcpu_contract.rr_switch_quantum() {
                    return Err(QemuTraceFingerprintImportError::MalformedTrace {
                        line: line_number,
                        reason: "terminal RR cursor quantum differs from the launch contract"
                            .to_owned(),
                    });
                }
                let terminal_cursor = SingleVmRoundRobinCursor::new(
                    u64_field(&value, "rr_current_vcpu", line_number)?,
                    u64_field(&value, "rr_cursor_position", line_number)?,
                    terminal_quantum,
                    self.qmp_cpu_ids.len(),
                )
                .map_err(|source| {
                    QemuTraceFingerprintImportError::CanonicalStream {
                        line: line_number,
                        source,
                    }
                })?;
                if samples
                    .last()
                    .map(|sample| sample.nvcpu_fingerprint.rr_cursor())
                    != Some(terminal_cursor)
                {
                    return Err(QemuTraceFingerprintImportError::MalformedTrace {
                        line: line_number,
                        reason: "terminal RR cursor must equal the last horizon sample cursor"
                            .to_owned(),
                    });
                }
                terminal_stop_seen = true;
                continue;
            }
            if terminal_stop_seen {
                return Err(QemuTraceFingerprintImportError::MalformedTrace {
                    line: line_number,
                    reason: "periodic sample appeared after the terminal plugin record".to_owned(),
                });
            }
            require_u64(&value, "stop_at", self.run_horizon_icount, line_number)?;
            let expected_icount = self
                .cadence_icount
                .checked_mul((samples.len() as u64).saturating_add(1))
                .ok_or(QemuTraceFingerprintImportError::MalformedTrace {
                    line: line_number,
                    reason: "periodic sample icount overflow".to_owned(),
                })?;
            let observed_icount = u64_field(&value, "retired", line_number)?;
            if observed_icount != expected_icount || observed_icount > self.run_horizon_icount {
                return Err(QemuTraceFingerprintImportError::MalformedTrace {
                    line: line_number,
                    reason: format!(
                        "periodic sample icount {observed_icount} does not match expected {expected_icount}"
                    ),
                });
            }
            let (material, retired_counts) = self.sample_material(
                &value,
                line_number,
                samples.len() as u64,
                previous_retired.as_deref(),
            )?;
            let sample = SingleVmFingerprintSample::from_material(
                &self.definition_digest,
                &previous,
                material,
            )
            .map_err(|source| QemuTraceFingerprintImportError::CanonicalStream {
                line: line_number,
                source,
            })?;
            previous = sample.rolling_fingerprint.clone();
            previous_retired = Some(retired_counts);
            samples.push(sample);
        }

        if samples.last().map(|sample| sample.icount) != Some(self.run_horizon_icount) {
            return Err(QemuTraceFingerprintImportError::IncompleteTrace {
                reason: "periodic samples do not reach the configured horizon",
            });
        }
        if !terminal_stop_seen {
            return Err(QemuTraceFingerprintImportError::IncompleteTrace {
                reason: "terminal plugin stop record is absent",
            });
        }

        SingleVmFingerprintStream::new(
            self.definition_digest.clone(),
            samples,
            self.run_horizon_icount,
            previous,
            self.run_horizon_icount,
        )
        .map_err(|source| QemuTraceFingerprintImportError::CanonicalStream { line: 0, source })
    }

    fn require_identity(
        &self,
        value: &Value,
        line: usize,
    ) -> Result<(), QemuTraceFingerprintImportError> {
        require_str(
            value,
            "launch_definition_digest",
            &self.identity.launch_definition_digest,
            line,
        )?;
        require_str(
            value,
            "qemu_build_digest",
            &self.identity.qemu_build_digest,
            line,
        )?;
        require_str(
            value,
            "trace_plugin_build_digest",
            &self.identity.trace_plugin_build_digest,
            line,
        )
    }

    fn sample_material(
        &self,
        value: &Value,
        line: usize,
        seq: u64,
        previous_retired: Option<&[u64]>,
    ) -> Result<(SingleVmFingerprintSampleMaterial, Vec<u64>), QemuTraceFingerprintImportError>
    {
        require_true(value, "rr_cursor_valid", line)?;
        require_str(value, "rr_cursor_source", "live_instruction", line)?;
        require_true(value, "memory_events_enabled", line)?;
        require_true(value, "device_event_capture", line)?;
        require_zero(value, "sample_register_failures", line)?;
        require_zero(value, "register_read_failures", line)?;

        let tracked_vcpus = usize_field(value, "tracked_vcpus", line)?;
        if tracked_vcpus != self.qmp_cpu_ids.len()
            || tracked_vcpus != self.nvcpu_contract.vcpu_count()
        {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line,
                reason: format!(
                    "plugin tracked {tracked_vcpus} vCPUs but QMP and launch require {}",
                    self.qmp_cpu_ids.len()
                ),
            });
        }

        let register_hashes = array_field(value, "register_hashes", line)?;
        let register_counts = array_field(value, "register_counts", line)?;
        let register_file_bytes = array_field(value, "register_file_bytes", line)?;
        let register_schema_hashes = array_field(value, "register_schema_hashes", line)?;
        let register_retired = array_field(value, "register_retired", line)?;
        if register_hashes.len() != tracked_vcpus
            || register_counts.len() != tracked_vcpus
            || register_file_bytes.len() != tracked_vcpus
            || register_schema_hashes.len() != tracked_vcpus
            || register_retired.len() != tracked_vcpus
        {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line,
                reason: "register arrays must cover exactly the QMP-observed vCPU set".to_owned(),
            });
        }

        let mut registers = Vec::with_capacity(tracked_vcpus);
        let mut retired_counts = Vec::with_capacity(tracked_vcpus);
        let mut retired_sum = 0_u64;
        for vcpu_id in 0..tracked_vcpus {
            let expected = self.vcpu_contracts[vcpu_id];
            let register_count = u64_array_item(register_counts, vcpu_id, "register_counts", line)?;
            if register_count != expected.register_count {
                return Err(QemuTraceFingerprintImportError::MalformedTrace {
                    line,
                    reason: format!(
                        "register_counts[{vcpu_id}] must be {}, got {register_count}",
                        expected.register_count
                    ),
                });
            }
            let raw_hash = hex_u64_array_item(register_hashes, vcpu_id, "register_hashes", line)?;
            let bytes = u64_array_item(register_file_bytes, vcpu_id, "register_file_bytes", line)?;
            if bytes != expected.register_file_bytes {
                return Err(QemuTraceFingerprintImportError::MalformedTrace {
                    line,
                    reason: format!(
                        "register_file_bytes[{vcpu_id}] must be {}, got {bytes}",
                        expected.register_file_bytes
                    ),
                });
            }
            let schema_hash = hex_u64_array_item(
                register_schema_hashes,
                vcpu_id,
                "register_schema_hashes",
                line,
            )?;
            if schema_hash != expected.register_schema_hash {
                return Err(QemuTraceFingerprintImportError::MalformedTrace {
                    line,
                    reason: format!(
                        "register_schema_hashes[{vcpu_id}] differs from the run-A baseline schema"
                    ),
                });
            }
            let bytes = usize::try_from(bytes).map_err(|_| {
                QemuTraceFingerprintImportError::MalformedTrace {
                    line,
                    reason: format!("register_file_bytes[{vcpu_id}] does not fit usize"),
                }
            })?;
            let retired = u64_array_item(register_retired, vcpu_id, "register_retired", line)?;
            if previous_retired.is_some_and(|previous| retired < previous[vcpu_id]) {
                return Err(QemuTraceFingerprintImportError::MalformedTrace {
                    line,
                    reason: format!("register_retired[{vcpu_id}] must be monotonic"),
                });
            }
            retired_sum = retired_sum.checked_add(retired).ok_or_else(|| {
                QemuTraceFingerprintImportError::MalformedTrace {
                    line,
                    reason: "per-vCPU retired instruction sum overflow".to_owned(),
                }
            })?;
            retired_counts.push(retired);
            let digest = component_digest(
                REGISTER_COMPONENT_DOMAIN,
                &format!("vcpu={vcpu_id}\nfnv1a64={raw_hash:016x}"),
            );
            registers.push(
                SingleVmVcpuRegisterDigest::new(vcpu_id as u64, digest, bytes, retired).map_err(
                    |source| QemuTraceFingerprintImportError::CanonicalStream { line, source },
                )?,
            );
        }
        let aggregate_retired = u64_field(value, "retired", line)?;
        if retired_sum != aggregate_retired {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line,
                reason: format!(
                    "per-vCPU retired instruction sum {retired_sum} differs from aggregate {aggregate_retired}"
                ),
            });
        }

        let rr_switch_quantum = u64_field(value, "rr_switch_quantum", line)?;
        if rr_switch_quantum != self.nvcpu_contract.rr_switch_quantum() {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line,
                reason: format!(
                    "trace RR quantum {rr_switch_quantum} differs from launch quantum {}",
                    self.nvcpu_contract.rr_switch_quantum()
                ),
            });
        }
        let rr_cursor = SingleVmRoundRobinCursor::new(
            u64_field(value, "rr_current_vcpu", line)?,
            u64_field(value, "rr_cursor_position", line)?,
            rr_switch_quantum,
            tracked_vcpus,
        )
        .map_err(|source| QemuTraceFingerprintImportError::CanonicalStream { line, source })?;
        let sample_vcpu = u64_field(value, "vcpu", line)?;
        if sample_vcpu != rr_cursor.current_vcpu() {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line,
                reason: format!(
                    "sample callback vCPU {sample_vcpu} differs from RR current vCPU {}",
                    rr_cursor.current_vcpu()
                ),
            });
        }
        let current_retired = retired_counts[rr_cursor.current_vcpu() as usize];
        if current_retired < rr_cursor.position_in_quantum() {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line,
                reason: "RR cursor position exceeds the current vCPU retired count".to_owned(),
            });
        }

        let ram_bytes = u64_field(value, "ram_bytes", line)?;
        if ram_bytes != self.baseline_ram_bytes {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line,
                reason: format!(
                    "guest RAM observation differs from the run-A baseline of {} bytes, got {ram_bytes}",
                    self.baseline_ram_bytes
                ),
            });
        }
        let ram_hash = hex_u64_field(value, "ram_hash", line)?;
        let device_event_hash = hex_u64_field(value, "device_event_hash", line)?;
        let memory_digest = component_digest(
            MEMORY_COMPONENT_DOMAIN,
            &format!("ram_bytes={ram_bytes}\nfnv1a64={ram_hash:016x}"),
        );
        let device_digest = component_digest(
            DEVICE_EVENT_COMPONENT_DOMAIN,
            &format!("fnv1a64={device_event_hash:016x}"),
        );
        let nvcpu_fingerprint = SingleVmNvcpuFingerprintMaterial::new(
            registers,
            rr_cursor,
            memory_digest,
            device_digest,
        )
        .and_then(|material| {
            material.validate_against_contract(self.nvcpu_contract)?;
            Ok(material)
        })
        .map_err(|source| QemuTraceFingerprintImportError::CanonicalStream { line, source })?;

        let material = SingleVmFingerprintSampleMaterial::new(
            seq,
            self.node.clone(),
            aggregate_retired,
            SingleVmFingerprintTrigger::Periodic,
            nvcpu_fingerprint,
        )
        .map_err(|source| QemuTraceFingerprintImportError::CanonicalStream { line, source })?;
        Ok((material, retired_counts))
    }
}

/// Failure while importing the real QEMU trace-plugin fingerprint stream.
#[derive(Debug, Error)]
pub enum QemuTraceFingerprintImportError {
    /// The fixed import contract is internally invalid.
    #[error("invalid QEMU trace fingerprint import contract: {reason}")]
    InvalidContract {
        /// Stable contract rejection reason.
        reason: &'static str,
    },
    /// Reading one JSON-lines record failed.
    #[error("failed to read QEMU trace line {line}: {source}")]
    Io {
        /// One-based trace line number.
        line: usize,
        /// Underlying stream error.
        source: io::Error,
    },
    /// One trace record is not valid JSON.
    #[error("invalid JSON on QEMU trace line {line}: {source}")]
    Json {
        /// One-based trace line number.
        line: usize,
        /// Underlying JSON decoder error.
        source: serde_json::Error,
    },
    /// One trace record violates the required wire contract.
    #[error("malformed QEMU fingerprint trace line {line}: {reason}")]
    MalformedTrace {
        /// One-based trace line number.
        line: usize,
        /// Deterministic validation failure.
        reason: String,
    },
    /// The stream ended without complete horizon or stop evidence.
    #[error("incomplete QEMU fingerprint trace: {reason}")]
    IncompleteTrace {
        /// Stable incompleteness reason.
        reason: &'static str,
    },
    /// Imported state failed the canonical fingerprint-stream contract.
    #[error("QEMU trace line {line} failed canonical fingerprint validation: {source}")]
    CanonicalStream {
        /// One-based trace line number, or zero for stream-level validation.
        line: usize,
        /// Underlying canonical stream error.
        source: SingleVmFingerprintGateError,
    },
}

fn component_digest(domain: &str, material: &str) -> Vec<u8> {
    ContentHash::from_canonical_material(domain, material)
        .bytes
        .to_vec()
}

fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_cpu_ids(cpu_ids: &[u64]) -> Result<(), QemuTraceFingerprintImportError> {
    if cpu_ids.is_empty() {
        return Err(QemuTraceFingerprintImportError::InvalidContract {
            reason: "QMP CPU index set must be non-empty",
        });
    }
    if cpu_ids
        .iter()
        .enumerate()
        .any(|(expected, actual)| *actual != expected as u64)
    {
        return Err(QemuTraceFingerprintImportError::InvalidContract {
            reason: "QMP CPU indexes must be the exact sorted set 0..N",
        });
    }
    Ok(())
}

fn array_field<'a>(
    value: &'a Value,
    field: &str,
    line: usize,
) -> Result<&'a [Value], QemuTraceFingerprintImportError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must be an array"),
        })
}

fn bool_field(
    value: &Value,
    field: &str,
    line: usize,
) -> Result<bool, QemuTraceFingerprintImportError> {
    value.get(field).and_then(Value::as_bool).ok_or_else(|| {
        QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must be a boolean"),
        }
    })
}

fn require_str(
    value: &Value,
    field: &str,
    expected: &str,
    line: usize,
) -> Result<(), QemuTraceFingerprintImportError> {
    let actual = value.get(field).and_then(Value::as_str).ok_or_else(|| {
        QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must be text"),
        }
    })?;
    if actual == expected {
        Ok(())
    } else {
        Err(QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must be `{expected}`, got `{actual}`"),
        })
    }
}

fn u64_field(
    value: &Value,
    field: &str,
    line: usize,
) -> Result<u64, QemuTraceFingerprintImportError> {
    value.get(field).and_then(Value::as_u64).ok_or_else(|| {
        QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must be an unsigned integer"),
        }
    })
}

fn usize_field(
    value: &Value,
    field: &str,
    line: usize,
) -> Result<usize, QemuTraceFingerprintImportError> {
    let raw = u64_field(value, field, line)?;
    usize::try_from(raw).map_err(|_| QemuTraceFingerprintImportError::MalformedTrace {
        line,
        reason: format!("field `{field}` does not fit usize"),
    })
}

fn hex_u64_field(
    value: &Value,
    field: &str,
    line: usize,
) -> Result<u64, QemuTraceFingerprintImportError> {
    let text = value.get(field).and_then(Value::as_str).ok_or_else(|| {
        QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must be a 16-digit hexadecimal string"),
        }
    })?;
    parse_hex_u64(text, field, line)
}

fn hex_u64_array_item(
    values: &[Value],
    index: usize,
    field: &str,
    line: usize,
) -> Result<u64, QemuTraceFingerprintImportError> {
    let text = values.get(index).and_then(Value::as_str).ok_or_else(|| {
        QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}[{index}]` must be hexadecimal text"),
        }
    })?;
    parse_hex_u64(text, field, line)
}

fn u64_array_item(
    values: &[Value],
    index: usize,
    field: &str,
    line: usize,
) -> Result<u64, QemuTraceFingerprintImportError> {
    values.get(index).and_then(Value::as_u64).ok_or_else(|| {
        QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}[{index}]` must be an unsigned integer"),
        }
    })
}

fn parse_hex_u64(
    text: &str,
    field: &str,
    line: usize,
) -> Result<u64, QemuTraceFingerprintImportError> {
    if text.len() != 16 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must contain exactly 16 hexadecimal digits"),
        });
    }
    u64::from_str_radix(text, 16).map_err(|_| QemuTraceFingerprintImportError::MalformedTrace {
        line,
        reason: format!("field `{field}` is outside the u64 hexadecimal range"),
    })
}

fn require_true(
    value: &Value,
    field: &str,
    line: usize,
) -> Result<(), QemuTraceFingerprintImportError> {
    if bool_field(value, field, line)? {
        Ok(())
    } else {
        Err(QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must be true"),
        })
    }
}

fn require_zero(
    value: &Value,
    field: &str,
    line: usize,
) -> Result<(), QemuTraceFingerprintImportError> {
    let count = u64_field(value, field, line)?;
    if count == 0 {
        Ok(())
    } else {
        Err(QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must be zero, got {count}"),
        })
    }
}

fn require_u64(
    value: &Value,
    field: &str,
    expected: u64,
    line: usize,
) -> Result<(), QemuTraceFingerprintImportError> {
    let actual = u64_field(value, field, line)?;
    if actual == expected {
        Ok(())
    } else {
        Err(QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must be {expected}, got {actual}"),
        })
    }
}
