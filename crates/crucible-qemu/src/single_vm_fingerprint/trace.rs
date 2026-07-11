//! Real QEMU trace-plugin import for execution fingerprints.
//!
//! The QEMU observation plugin writes one JSON object per icount-driven sample.
//! An independent preflight pins the exact register, RAM, device-state, and
//! build shape before either comparison run starts. This module validates that
//! host-observed wire form and converts it into the same canonical
//! [`SingleVmFingerprintStream`] used by the run-twice gate. It rejects missing
//! vCPUs, incomplete register reads, a mismatched QMP topology, RR-cursor drift,
//! missing guest RAM or current VMState, and definition drift instead of
//! silently manufacturing fingerprint components.

use std::io::{self, BufRead};

use crucible::ContentHash;
use serde_json::Value;
use thiserror::Error;

use super::{
    SingleVmFingerprintEventBoundary, SingleVmFingerprintGateError, SingleVmFingerprintSample,
    SingleVmFingerprintSampleMaterial, SingleVmFingerprintStream, SingleVmFingerprintTrigger,
    SingleVmNvcpuFingerprintContract, SingleVmNvcpuFingerprintMaterial, SingleVmQmpVcpuTopology,
    SingleVmRoundRobinCursor, SingleVmVcpuRegisterDigest, initial_single_vm_rolling_fingerprint,
};

const REGISTER_COMPONENT_DOMAIN: &str = "crucible.qemu.trace-register-component.v2";
const MEMORY_COMPONENT_DOMAIN: &str = "crucible.qemu.trace-memory-component.v2";
const DEVICE_STATE_COMPONENT_DOMAIN: &str = "crucible.qemu.trace-device-state-component.v2";
const DEFINITION_DOMAIN: &str = "crucible.qemu.trace-fingerprint-definition.v2";

/// Wire-schema identifier emitted by the canonical QEMU observation plugin.
pub const QEMU_TRACE_FINGERPRINT_SCHEMA: &str = "crucible.qemu.trace-fingerprint.v4";

/// Canonical fingerprint definition pinned by an independent QEMU preflight.
///
/// The preflight is distinct from both comparison runs. It fixes the exact
/// register descriptor schemas and byte widths, guest-RAM coverage, serialized
/// non-RAM VMState coverage, QMP topology, RR quantum, launch identity, and
/// observation-plugin build identity before either run is admitted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuTraceFingerprintDefinition {
    canonical_material: String,
}

impl QemuTraceFingerprintDefinition {
    /// Builds the canonical trace definition for one periodic cadence.
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
            canonical_material: definition_material(cadence_icount, observation),
        })
    }

    /// Returns the canonical material describing the pinned observation set.
    #[must_use]
    pub fn canonical_material(&self) -> &str {
        &self.canonical_material
    }

    /// Returns the content-addressed production definition digest.
    #[must_use]
    pub fn definition_digest(&self) -> [u8; 32] {
        ContentHash::from_canonical_material(DEFINITION_DOMAIN, self.canonical_material()).bytes
    }
}

fn definition_material(cadence_icount: u64, observation: &QemuTraceObservationContract) -> String {
    let mut lines = vec![
        QEMU_TRACE_FINGERPRINT_SCHEMA.to_owned(),
        "status=canonical".to_owned(),
        format!("cadence_icount={cadence_icount}"),
        "trigger[0]=periodic-aggregate-icount".to_owned(),
        "trigger[1]=horizon-advance".to_owned(),
        "trigger[2]=frame-delivery".to_owned(),
        "trigger[3]=fault-activation".to_owned(),
        "component[0]=aggregate-icount".to_owned(),
        "component[1]=all-vcpu-register-files-sha256-v1".to_owned(),
        "component[2]=full-guest-ram-sha256-v1".to_owned(),
        "component[3]=qemu-non-ram-vmstate-sha256-v1".to_owned(),
        "complete_current_device_state=true".to_owned(),
        "event_boundary_sampling=true".to_owned(),
        format!("rr_switch_quantum={}", observation.rr_switch_quantum),
        format!("guest_ram_bytes={}", observation.guest_ram_bytes),
        format!(
            "device_state_sections={}",
            observation.device_state_sections
        ),
        format!(
            "device_state_schema_digest={}",
            lower_hex(&observation.device_state_schema_digest)
        ),
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
            "vcpu[{index}].register_count={}",
            contract.register_count
        ));
        lines.push(format!(
            "vcpu[{index}].register_file_bytes={}",
            contract.register_file_bytes
        ));
        lines.push(format!(
            "vcpu[{index}].register_schema_digest={}",
            lower_hex(&contract.register_schema_digest)
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

    /// Returns the content digest of the complete launch definition.
    #[must_use]
    pub fn launch_definition_digest(&self) -> &str {
        &self.launch_definition_digest
    }

    /// Returns the digest of the exact QEMU executable build.
    #[must_use]
    pub fn qemu_build_digest(&self) -> &str {
        &self.qemu_build_digest
    }

    /// Returns the digest of the exact observation-plugin build.
    #[must_use]
    pub fn trace_plugin_build_digest(&self) -> &str {
        &self.trace_plugin_build_digest
    }
}

/// Preflight-pinned register observation for one QMP vCPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuTraceVcpuContract {
    cpu_id: u64,
    register_count: u64,
    register_file_bytes: u64,
    register_schema_digest: [u8; 32],
}

impl QemuTraceVcpuContract {
    /// Builds one exact register-observation contract.
    ///
    /// # Errors
    ///
    /// Returns [`QemuTraceFingerprintImportError::InvalidContract`] when the
    /// descriptor count, canonical register byte count, or register-schema
    /// digest is zero.
    pub fn new(
        cpu_id: u64,
        register_count: u64,
        register_file_bytes: u64,
        register_schema_digest: [u8; 32],
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
        if digest_is_zero(&register_schema_digest) {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace register-schema digest must be non-zero",
            });
        }
        Ok(Self {
            cpu_id,
            register_count,
            register_file_bytes,
            register_schema_digest,
        })
    }

    /// Returns the QMP CPU index covered by this contract.
    #[must_use]
    pub const fn cpu_id(self) -> u64 {
        self.cpu_id
    }

    /// Returns the exact register descriptor count pinned by preflight.
    #[must_use]
    pub const fn register_count(self) -> u64 {
        self.register_count
    }

    /// Returns the exact canonical register-file byte width pinned by preflight.
    #[must_use]
    pub const fn register_file_bytes(self) -> u64 {
        self.register_file_bytes
    }

    /// Returns the exact register descriptor-schema digest pinned by preflight.
    #[must_use]
    pub const fn register_schema_digest(self) -> [u8; 32] {
        self.register_schema_digest
    }
}

/// Exact preflight and QMP-bound shape for one trace import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuTraceObservationContract {
    qmp_cpu_ids: Vec<u64>,
    rr_switch_quantum: u64,
    guest_ram_bytes: u64,
    device_state_sections: u64,
    device_state_schema_digest: [u8; 32],
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
        guest_ram_bytes: u64,
        device_state_sections: u64,
        device_state_schema_digest: [u8; 32],
        vcpu_contracts: Vec<QemuTraceVcpuContract>,
        identity: QemuTraceIdentityContract,
    ) -> Result<Self, QemuTraceFingerprintImportError> {
        validate_cpu_ids(&qmp_cpu_ids)?;
        if rr_switch_quantum == 0 {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace observation contract requires a non-zero RR quantum",
            });
        }
        if guest_ram_bytes == 0 {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace fingerprint contract requires exact non-zero RAM bytes",
            });
        }
        if device_state_sections == 0 || digest_is_zero(&device_state_schema_digest) {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace fingerprint contract requires non-zero device-state schema coverage",
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
            guest_ram_bytes,
            device_state_sections,
            device_state_schema_digest,
            vcpu_contracts,
            identity,
        })
    }

    /// Returns the exact sorted QMP CPU-index set pinned by preflight.
    #[must_use]
    pub fn qmp_cpu_ids(&self) -> &[u64] {
        &self.qmp_cpu_ids
    }

    /// Returns the launch-pinned round-robin switch quantum.
    #[must_use]
    pub const fn rr_switch_quantum(&self) -> u64 {
        self.rr_switch_quantum
    }

    /// Returns the exact writable guest-RAM byte coverage.
    #[must_use]
    pub const fn guest_ram_bytes(&self) -> u64 {
        self.guest_ram_bytes
    }

    /// Returns the exact non-RAM VMState section count.
    #[must_use]
    pub const fn device_state_sections(&self) -> u64 {
        self.device_state_sections
    }

    /// Returns the preflight-pinned non-RAM VMState schema digest.
    #[must_use]
    pub const fn device_state_schema_digest(&self) -> [u8; 32] {
        self.device_state_schema_digest
    }

    /// Returns the per-vCPU register shape pinned by preflight.
    #[must_use]
    pub fn vcpu_contracts(&self) -> &[QemuTraceVcpuContract] {
        &self.vcpu_contracts
    }

    /// Returns the launch and build identity pinned by preflight.
    #[must_use]
    pub const fn identity(&self) -> &QemuTraceIdentityContract {
        &self.identity
    }
}

/// Independently captured fingerprint-definition preflight.
///
/// A preflight is produced by a dedicated QEMU launch that pauses before guest
/// execution. Comparison run A and run B must both conform to this exact shape;
/// neither comparison run is allowed to define the observation set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuTraceDefinitionPreflight {
    observation: QemuTraceObservationContract,
}

impl QemuTraceDefinitionPreflight {
    /// Imports one definition-only trace record.
    ///
    /// # Errors
    ///
    /// Returns [`QemuTraceFingerprintImportError`] when the input is not
    /// exactly one definition record, any identity or observation field is
    /// malformed, VMState coverage is incomplete, or the preflight retired a
    /// guest instruction.
    pub fn import<R: BufRead>(reader: R) -> Result<Self, QemuTraceFingerprintImportError> {
        let mut records = reader.lines();
        let line = records
            .next()
            .ok_or(QemuTraceFingerprintImportError::IncompleteTrace {
                reason: "definition preflight record is absent",
            })?
            .map_err(|source| QemuTraceFingerprintImportError::Io { line: 1, source })?;
        if line.trim().is_empty() {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line: 1,
                reason: "blank definition preflight record".to_owned(),
            });
        }
        if records.next().is_some() {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line: 2,
                reason: "definition preflight must contain exactly one record".to_owned(),
            });
        }
        let value: Value = serde_json::from_str(&line)
            .map_err(|source| QemuTraceFingerprintImportError::Json { line: 1, source })?;
        require_str(&value, "kind", "definition", 1)?;
        require_str(&value, "schema", QEMU_TRACE_FINGERPRINT_SCHEMA, 1)?;
        require_true(&value, "definition_only", 1)?;
        require_true(&value, "observed_non_running", 1)?;
        require_true(&value, "device_state_complete", 1)?;
        require_zero(&value, "retired", 1)?;
        require_zero(&value, "observed_icount", 1)?;
        require_zero(&value, "ram_status", 1)?;
        require_zero(&value, "device_state_status", 1)?;
        require_zero(&value, "device_state_schema_status", 1)?;
        require_zero(&value, "sample_register_failures", 1)?;
        require_zero(&value, "register_read_failures", 1)?;
        require_zero(&value, "device_state_failures", 1)?;

        let tracked_vcpus = usize_field(&value, "tracked_vcpus", 1)?;
        if tracked_vcpus == 0 {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line: 1,
                reason: "definition preflight must cover at least one vCPU".to_owned(),
            });
        }
        let qmp_cpu_ids = (0..tracked_vcpus as u64).collect::<Vec<_>>();
        let register_counts = array_field(&value, "register_counts", 1)?;
        let register_file_bytes = array_field(&value, "register_file_bytes", 1)?;
        let register_digests = array_field(&value, "register_digests", 1)?;
        let register_schema_digests = array_field(&value, "register_schema_digests", 1)?;
        if register_counts.len() != tracked_vcpus
            || register_file_bytes.len() != tracked_vcpus
            || register_digests.len() != tracked_vcpus
            || register_schema_digests.len() != tracked_vcpus
        {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line: 1,
                reason: "definition register arrays must cover exactly the configured vCPUs"
                    .to_owned(),
            });
        }
        let vcpu_contracts = (0..tracked_vcpus)
            .map(|vcpu| {
                sha256_array_item(register_digests, vcpu, "register_digests", 1)?;
                QemuTraceVcpuContract::new(
                    vcpu as u64,
                    u64_array_item(register_counts, vcpu, "register_counts", 1)?,
                    u64_array_item(register_file_bytes, vcpu, "register_file_bytes", 1)?,
                    sha256_array_item(register_schema_digests, vcpu, "register_schema_digests", 1)?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        sha256_field(&value, "ram_digest", 1)?;
        sha256_field(&value, "device_state_digest", 1)?;
        if u64_field(&value, "device_state_bytes", 1)? == 0 {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line: 1,
                reason: "definition device-state serialized byte count must be non-zero".to_owned(),
            });
        }
        let identity = QemuTraceIdentityContract::new(
            text_field(&value, "launch_definition_digest", 1)?,
            text_field(&value, "qemu_build_digest", 1)?,
            text_field(&value, "trace_plugin_build_digest", 1)?,
        )?;
        let observation = QemuTraceObservationContract::new(
            qmp_cpu_ids,
            u64_field(&value, "rr_switch_quantum", 1)?,
            u64_field(&value, "ram_bytes", 1)?,
            u64_field(&value, "device_state_sections", 1)?,
            sha256_field(&value, "device_state_schema_digest", 1)?,
            vcpu_contracts,
            identity,
        )?;
        Ok(Self { observation })
    }

    /// Returns the exact observation contract pinned before the two gate runs.
    #[must_use]
    pub const fn observation(&self) -> &QemuTraceObservationContract {
        &self.observation
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
    guest_ram_bytes: u64,
    device_state_sections: u64,
    device_state_schema_digest: [u8; 32],
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
    /// node name is empty, the cadence or horizon is zero, the digest is
    /// malformed, or the N-vCPU contract is invalid.
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
        if run_horizon_icount == 0 {
            return Err(QemuTraceFingerprintImportError::InvalidContract {
                reason: "trace fingerprint horizon must be non-zero",
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
            guest_ram_bytes: observation.guest_ram_bytes,
            device_state_sections: observation.device_state_sections,
            device_state_schema_digest: observation.device_state_schema_digest,
            vcpu_contracts: observation.vcpu_contracts,
            identity: observation.identity,
        })
    }

    /// Imports one completed real-QEMU JSON-lines trace.
    ///
    /// Non-sample diagnostic records, such as RR-switch and deterministic-IPI
    /// records, are ignored. Periodic sample records must cover every cadence
    /// point before the configured horizon exactly once, and the exact horizon
    /// is always represented by its event-boundary sample. When the horizon
    /// lands on a cadence, that one event sample satisfies both observations.
    /// The terminal plugin exit record is required as evidence that QEMU
    /// reached its requested stop, but is not fingerprinted because the event
    /// sample is the authoritative horizon state. The terminal record must be
    /// final, report the exact horizon on QEMU's logical icount axis, and repeat
    /// the horizon sample's aggregate plugin-retired instruction count.
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
        let mut last_aggregate_retired = None;
        let mut periodic_sample_count = 0_u64;
        let mut horizon_boundary_seen = false;

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
            if terminal_stop_seen {
                return Err(QemuTraceFingerprintImportError::MalformedTrace {
                    line: line_number,
                    reason: "record appeared after the terminal plugin stop record".to_owned(),
                });
            }
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
                let terminal_retired = u64_field(&value, "retired", line_number)?;
                let terminal_observed = u64_field(&value, "observed_icount", line_number)?;
                if terminal_observed != self.run_horizon_icount {
                    return Err(QemuTraceFingerprintImportError::MalformedTrace {
                        line: line_number,
                        reason: format!(
                            "terminal observed icount {terminal_observed} differs from exact horizon {}",
                            self.run_horizon_icount
                        ),
                    });
                }
                if terminal_retired > terminal_observed {
                    return Err(QemuTraceFingerprintImportError::MalformedTrace {
                        line: line_number,
                        reason:
                            "terminal retired instruction count exceeds the observed QEMU icount"
                                .to_owned(),
                    });
                }
                if samples.last().map(|sample| sample.icount) != Some(self.run_horizon_icount) {
                    return Err(QemuTraceFingerprintImportError::MalformedTrace {
                        line: line_number,
                        reason: "terminal plugin record preceded the horizon sample".to_owned(),
                    });
                }
                if last_aggregate_retired != Some(terminal_retired) {
                    return Err(QemuTraceFingerprintImportError::MalformedTrace {
                        line: line_number,
                        reason:
                            "terminal retired instruction count differs from the horizon sample"
                                .to_owned(),
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
                SingleVmRoundRobinCursor::new(
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
                terminal_stop_seen = true;
                continue;
            }
            require_u64(&value, "stop_at", self.run_horizon_icount, line_number)?;
            let observed_icount = u64_field(&value, "observed_icount", line_number)?;
            let trigger = sample_trigger(&value, line_number)?;
            if observed_icount > self.run_horizon_icount {
                return Err(QemuTraceFingerprintImportError::MalformedTrace {
                    line: line_number,
                    reason: format!("sample icount {observed_icount} exceeds the run horizon"),
                });
            }
            let next_periodic_count = periodic_sample_count.checked_add(1).ok_or(
                QemuTraceFingerprintImportError::MalformedTrace {
                    line: line_number,
                    reason: "periodic sample count overflow".to_owned(),
                },
            )?;
            let next_periodic_icount = self.cadence_icount.checked_mul(next_periodic_count).ok_or(
                QemuTraceFingerprintImportError::MalformedTrace {
                    line: line_number,
                    reason: "periodic sample icount overflow".to_owned(),
                },
            )?;
            if trigger == SingleVmFingerprintTrigger::Periodic {
                if observed_icount != next_periodic_icount {
                    return Err(QemuTraceFingerprintImportError::MalformedTrace {
                        line: line_number,
                        reason: format!(
                            "periodic sample icount {observed_icount} does not match expected {next_periodic_icount}"
                        ),
                    });
                }
                periodic_sample_count = next_periodic_count;
            } else if observed_icount == next_periodic_icount {
                // A deterministic boundary that lands exactly on the periodic
                // cadence satisfies both required observations with one state
                // read; the event trigger remains explicit in the digest.
                periodic_sample_count = next_periodic_count;
            }
            if trigger
                == SingleVmFingerprintTrigger::Event(
                    SingleVmFingerprintEventBoundary::HorizonAdvance,
                )
                && observed_icount == self.run_horizon_icount
            {
                horizon_boundary_seen = true;
            }
            let (material, retired_counts) = self.sample_material(
                &value,
                line_number,
                samples.len() as u64,
                trigger,
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
            last_aggregate_retired = Some(u64_field(&value, "retired", line_number)?);
            samples.push(sample);
        }

        let expected_periodic_sample_count = self.run_horizon_icount / self.cadence_icount;
        if periodic_sample_count != expected_periodic_sample_count {
            return Err(QemuTraceFingerprintImportError::IncompleteTrace {
                reason: "periodic samples do not cover every cadence before the configured horizon",
            });
        }
        if !horizon_boundary_seen {
            return Err(QemuTraceFingerprintImportError::IncompleteTrace {
                reason: "the configured horizon-advance boundary sample is absent",
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
        trigger: SingleVmFingerprintTrigger,
        previous_retired: Option<&[u64]>,
    ) -> Result<(SingleVmFingerprintSampleMaterial, Vec<u64>), QemuTraceFingerprintImportError>
    {
        require_true(value, "rr_cursor_valid", line)?;
        require_str(value, "rr_cursor_source", "live_instruction", line)?;
        require_true(value, "device_state_complete", line)?;
        require_zero(value, "ram_status", line)?;
        require_zero(value, "device_state_status", line)?;
        require_zero(value, "device_state_schema_status", line)?;
        require_zero(value, "sample_register_failures", line)?;
        require_zero(value, "register_read_failures", line)?;
        require_zero(value, "device_state_failures", line)?;

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

        let register_digests = array_field(value, "register_digests", line)?;
        let register_counts = array_field(value, "register_counts", line)?;
        let register_file_bytes = array_field(value, "register_file_bytes", line)?;
        let register_schema_digests = array_field(value, "register_schema_digests", line)?;
        let register_retired = array_field(value, "register_retired", line)?;
        if register_digests.len() != tracked_vcpus
            || register_counts.len() != tracked_vcpus
            || register_file_bytes.len() != tracked_vcpus
            || register_schema_digests.len() != tracked_vcpus
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
            let raw_digest =
                sha256_array_item(register_digests, vcpu_id, "register_digests", line)?;
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
            let schema_digest = sha256_array_item(
                register_schema_digests,
                vcpu_id,
                "register_schema_digests",
                line,
            )?;
            if schema_digest != expected.register_schema_digest {
                return Err(QemuTraceFingerprintImportError::MalformedTrace {
                    line,
                    reason: format!(
                        "register_schema_digests[{vcpu_id}] differs from the independent preflight schema"
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
                &format!("vcpu={vcpu_id}\nsha256={}", lower_hex(&raw_digest)),
            );
            registers.push(
                SingleVmVcpuRegisterDigest::new(vcpu_id as u64, digest, bytes, retired).map_err(
                    |source| QemuTraceFingerprintImportError::CanonicalStream { line, source },
                )?,
            );
        }
        let aggregate_retired = u64_field(value, "retired", line)?;
        let observed_icount = u64_field(value, "observed_icount", line)?;
        if aggregate_retired > observed_icount {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line,
                reason: "aggregate retired instruction count exceeds the observed QEMU icount"
                    .to_owned(),
            });
        }
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
        if ram_bytes != self.guest_ram_bytes {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line,
                reason: format!(
                    "guest RAM observation differs from the independent preflight of {} bytes, got {ram_bytes}",
                    self.guest_ram_bytes
                ),
            });
        }
        let ram_digest = sha256_field(value, "ram_digest", line)?;
        let device_state_bytes = u64_field(value, "device_state_bytes", line)?;
        if device_state_bytes == 0 {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line,
                reason: "device-state serialized byte count must be non-zero".to_owned(),
            });
        }
        let device_state_digest = sha256_field(value, "device_state_digest", line)?;
        let device_state_sections = u64_field(value, "device_state_sections", line)?;
        let device_state_schema_digest = sha256_field(value, "device_state_schema_digest", line)?;
        if device_state_sections != self.device_state_sections
            || device_state_schema_digest != self.device_state_schema_digest
        {
            return Err(QemuTraceFingerprintImportError::MalformedTrace {
                line,
                reason:
                    "device-state section/schema coverage differs from the independent preflight"
                        .to_owned(),
            });
        }
        let memory_digest = component_digest(
            MEMORY_COMPONENT_DOMAIN,
            &format!("ram_bytes={ram_bytes}\nsha256={}", lower_hex(&ram_digest)),
        );
        let device_digest = component_digest(
            DEVICE_STATE_COMPONENT_DOMAIN,
            &format!(
                "device_state_bytes={device_state_bytes}\ndevice_state_sections={device_state_sections}\nschema_sha256={}\nstate_sha256={}",
                lower_hex(&device_state_schema_digest),
                lower_hex(&device_state_digest)
            ),
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
            observed_icount,
            trigger,
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

fn sample_trigger(
    value: &Value,
    line: usize,
) -> Result<SingleVmFingerprintTrigger, QemuTraceFingerprintImportError> {
    let trigger = value
        .get("trigger")
        .and_then(Value::as_str)
        .ok_or_else(|| QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: "field `trigger` must be text".to_owned(),
        })?;
    match trigger {
        "periodic" => {
            if value
                .get("event_boundary")
                .is_some_and(|boundary| !boundary.is_null())
            {
                return Err(QemuTraceFingerprintImportError::MalformedTrace {
                    line,
                    reason: "periodic samples must not name an event boundary".to_owned(),
                });
            }
            Ok(SingleVmFingerprintTrigger::Periodic)
        }
        "event" => {
            let boundary = value
                .get("event_boundary")
                .and_then(Value::as_str)
                .ok_or_else(|| QemuTraceFingerprintImportError::MalformedTrace {
                    line,
                    reason: "event samples must name `event_boundary`".to_owned(),
                })?;
            let boundary = match boundary {
                "horizon-advance" => SingleVmFingerprintEventBoundary::HorizonAdvance,
                "frame-delivery" => SingleVmFingerprintEventBoundary::FrameDelivery,
                "fault-activation" => SingleVmFingerprintEventBoundary::FaultActivation,
                other => {
                    return Err(QemuTraceFingerprintImportError::MalformedTrace {
                        line,
                        reason: format!("unknown fingerprint event boundary `{other}`"),
                    });
                }
            };
            Ok(SingleVmFingerprintTrigger::Event(boundary))
        }
        other => Err(QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("unknown fingerprint sample trigger `{other}`"),
        }),
    }
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

fn text_field(
    value: &Value,
    field: &str,
    line: usize,
) -> Result<String, QemuTraceFingerprintImportError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must be text"),
        })
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

fn sha256_field(
    value: &Value,
    field: &str,
    line: usize,
) -> Result<[u8; 32], QemuTraceFingerprintImportError> {
    let text = value.get(field).and_then(Value::as_str).ok_or_else(|| {
        QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must be a SHA-256 hexadecimal string"),
        }
    })?;
    parse_sha256(text, field, line)
}

fn sha256_array_item(
    values: &[Value],
    index: usize,
    field: &str,
    line: usize,
) -> Result<[u8; 32], QemuTraceFingerprintImportError> {
    let text = values.get(index).and_then(Value::as_str).ok_or_else(|| {
        QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}[{index}]` must be SHA-256 hexadecimal text"),
        }
    })?;
    parse_sha256(text, &format!("{field}[{index}]"), line)
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

fn parse_sha256(
    text: &str,
    field: &str,
    line: usize,
) -> Result<[u8; 32], QemuTraceFingerprintImportError> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must contain exactly 64 lowercase hexadecimal digits"),
        });
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    if digest_is_zero(&digest) {
        return Err(QemuTraceFingerprintImportError::MalformedTrace {
            line,
            reason: format!("field `{field}` must be non-zero"),
        });
    }
    Ok(digest)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn digest_is_zero(digest: &[u8; 32]) -> bool {
    digest.iter().all(|byte| *byte == 0)
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
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
