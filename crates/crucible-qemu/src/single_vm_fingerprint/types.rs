//! Public data types for the single-VM fingerprint gate.

use crucible::ContentHash;
use crucible_protocol::PluginNvcpuFingerprintSnapshot;
use thiserror::Error;

use super::{
    compare::SingleVmFingerprintMismatch, state_dump::SingleVmFingerprintDivergenceStateDump,
};

/// The byte length of canonical execution-fingerprint digests.
pub const SINGLE_VM_FINGERPRINT_DIGEST_BYTES: usize = 32;

const SINGLE_VM_FINGERPRINT_STREAM_SEED_DOMAIN: &str =
    "crucible.qemu.single-vm-fingerprint-stream-seed.v1";
const SINGLE_VM_FINGERPRINT_SAMPLE_DOMAIN: &str = "crucible.qemu.single-vm-fingerprint-sample.v1";
const SINGLE_VM_RUN_INPUTS_DOMAIN: &str = "crucible.qemu.single-vm-run-inputs.v1";

/// The deterministic reason a single-VM fingerprint sample exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SingleVmFingerprintTrigger {
    /// The sample was taken at the fixed periodic aggregate-icount cadence.
    Periodic,
    /// The sample was taken at a deterministic host-visible event boundary.
    Event(SingleVmFingerprintEventBoundary),
}

/// A deterministic event boundary that may force a fingerprint sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SingleVmFingerprintEventBoundary {
    /// A scheduler horizon advanced.
    HorizonAdvance,
    /// An icount-stamped frame became visible.
    FrameDelivery,
    /// A scheduled signal effect boundary became visible.
    SignalEffectBoundary,
}

/// Digest of one vCPU architectural register file sampled by the host hook.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmVcpuRegisterDigest {
    vcpu_id: u64,
    register_digest: Vec<u8>,
    register_file_bytes: usize,
    retired_instruction_count: u64,
}

impl SingleVmVcpuRegisterDigest {
    /// Builds one vCPU register-file digest record.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when `register_digest` is not a
    /// canonical fingerprint digest or `register_file_bytes` is zero.
    pub fn new(
        vcpu_id: u64,
        register_digest: impl Into<Vec<u8>>,
        register_file_bytes: usize,
        retired_instruction_count: u64,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        if register_file_bytes == 0 {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "vCPU register file byte count must be non-zero",
                },
            );
        }
        let register_digest = register_digest.into();
        validate_digest_len("register_digest", &register_digest)?;
        Ok(Self {
            vcpu_id,
            register_digest,
            register_file_bytes,
            retired_instruction_count,
        })
    }

    /// Returns the vCPU identifier.
    #[must_use]
    pub const fn vcpu_id(&self) -> u64 {
        self.vcpu_id
    }

    /// Returns the digest of this vCPU's architectural register file.
    #[must_use]
    pub fn register_digest(&self) -> &[u8] {
        &self.register_digest
    }

    /// Returns the number of canonical register-file bytes read.
    #[must_use]
    pub const fn register_file_bytes(&self) -> usize {
        self.register_file_bytes
    }

    /// Returns the adapter-provided retired-instruction stamp for the registers.
    #[must_use]
    pub const fn retired_instruction_count(&self) -> u64 {
        self.retired_instruction_count
    }
}

/// Round-robin cursor state included in an N-vCPU fingerprint sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SingleVmRoundRobinCursor {
    current_vcpu: u64,
    position_in_quantum: u64,
    rr_switch_quantum: u64,
}

impl SingleVmRoundRobinCursor {
    /// Builds a validated round-robin cursor snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when the sampled vCPU count is
    /// zero, the current vCPU is outside the sampled set, the switch quantum is
    /// zero, or the cursor position is outside the current quantum.
    pub const fn new(
        current_vcpu: u64,
        position_in_quantum: u64,
        rr_switch_quantum: u64,
        vcpu_count: usize,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        if vcpu_count == 0 {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "N-vCPU fingerprint material must include at least one vCPU",
                },
            );
        }
        if current_vcpu >= vcpu_count as u64 {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "round-robin current vCPU must be inside the sampled vCPU set",
                },
            );
        }
        if rr_switch_quantum == 0 {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "round-robin switch quantum must be non-zero",
                },
            );
        }
        if position_in_quantum >= rr_switch_quantum {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "round-robin cursor position must be inside rr_switch_quantum",
                },
            );
        }
        Ok(Self {
            current_vcpu,
            position_in_quantum,
            rr_switch_quantum,
        })
    }

    /// Returns the currently running vCPU in the fixed RR cursor.
    #[must_use]
    pub const fn current_vcpu(self) -> u64 {
        self.current_vcpu
    }

    /// Returns the node-icount position within the pinned RR quantum.
    #[must_use]
    pub const fn position_in_quantum(self) -> u64 {
        self.position_in_quantum
    }

    /// Returns the pinned RR switch quantum in node-icount units.
    #[must_use]
    pub const fn rr_switch_quantum(self) -> u64 {
        self.rr_switch_quantum
    }
}

/// Black-box state material folded into one N-vCPU fingerprint sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmNvcpuFingerprintMaterial {
    vcpu_registers: Vec<SingleVmVcpuRegisterDigest>,
    rr_cursor: SingleVmRoundRobinCursor,
    guest_memory_digest: Vec<u8>,
    device_state_digest: Vec<u8>,
}

impl SingleVmNvcpuFingerprintMaterial {
    /// Builds sample material from plugin introspection and QMP topology.
    ///
    /// `qmp_topology` is the host-observed `-smp N` topology from the typed QMP
    /// control boundary, while `plugin_inputs` is the validated snapshot emitted
    /// from the real plugin introspection reader. `expected_rr_switch_quantum`
    /// is the launch-pinned node-icount quantum.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when QMP topology is invalid,
    /// the plugin material is malformed, the plugin omitted a vCPU reported by
    /// QMP, or the cursor quantum differs from the launch-pinned quantum.
    pub fn from_plugin_introspection_and_qmp(
        qmp_topology: SingleVmQmpVcpuTopology,
        plugin_inputs: &PluginNvcpuFingerprintSnapshot,
        expected_rr_switch_quantum: u64,
        guest_memory_digest: impl Into<Vec<u8>>,
        device_state_digest: impl Into<Vec<u8>>,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        let contract = SingleVmNvcpuFingerprintContract::new(
            qmp_topology.vcpu_count(),
            expected_rr_switch_quantum,
        )?;
        let vcpu_registers = plugin_inputs
            .vcpu_registers()
            .iter()
            .map(|register| {
                SingleVmVcpuRegisterDigest::new(
                    u64::from(register.vcpu_id()),
                    register.register_digest().to_vec(),
                    register.register_file_bytes(),
                    register.retired_instruction_count(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let plugin_cursor = plugin_inputs.rr_cursor();
        let rr_cursor = SingleVmRoundRobinCursor::new(
            plugin_cursor.current_vcpu(),
            plugin_cursor.position_in_quantum(),
            plugin_cursor.rr_switch_quantum(),
            plugin_inputs.vcpu_registers().len(),
        )?;
        let material = Self::new(
            vcpu_registers,
            rr_cursor,
            guest_memory_digest,
            device_state_digest,
        )?;
        material.validate_against_contract(contract)?;
        Ok(material)
    }

    /// Builds canonical sample material for all vCPUs and the RR cursor.
    ///
    /// Register records are sorted by vCPU id and must cover exactly `0..N`.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when the vCPU set is empty,
    /// duplicate, non-contiguous, inconsistent with the RR cursor, or any digest
    /// has a non-canonical length.
    pub fn new(
        mut vcpu_registers: Vec<SingleVmVcpuRegisterDigest>,
        rr_cursor: SingleVmRoundRobinCursor,
        guest_memory_digest: impl Into<Vec<u8>>,
        device_state_digest: impl Into<Vec<u8>>,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        if vcpu_registers.is_empty() {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "N-vCPU fingerprint material must include at least one vCPU",
                },
            );
        }
        vcpu_registers.sort_by_key(SingleVmVcpuRegisterDigest::vcpu_id);
        for (expected, register) in vcpu_registers.iter().enumerate() {
            let expected = expected as u64;
            if register.vcpu_id() != expected {
                return Err(
                    SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                        reason: "N-vCPU fingerprint material must cover exactly vCPUs 0..N",
                    },
                );
            }
        }
        if rr_cursor.current_vcpu() >= vcpu_registers.len() as u64 {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "round-robin current vCPU must be inside the sampled vCPU set",
                },
            );
        }
        let guest_memory_digest = guest_memory_digest.into();
        validate_digest_len("guest_memory_digest", &guest_memory_digest)?;
        let device_state_digest = device_state_digest.into();
        validate_digest_len("device_state_digest", &device_state_digest)?;

        Ok(Self {
            vcpu_registers,
            rr_cursor,
            guest_memory_digest,
            device_state_digest,
        })
    }

    /// Returns sorted register digests for every vCPU in the sampled node.
    #[must_use]
    pub fn vcpu_registers(&self) -> &[SingleVmVcpuRegisterDigest] {
        &self.vcpu_registers
    }

    /// Returns the sampled round-robin cursor.
    #[must_use]
    pub const fn rr_cursor(&self) -> SingleVmRoundRobinCursor {
        self.rr_cursor
    }

    /// Returns the guest-memory digest sampled with the registers.
    #[must_use]
    pub fn guest_memory_digest(&self) -> &[u8] {
        &self.guest_memory_digest
    }

    /// Returns the device-state digest sampled with the registers.
    #[must_use]
    pub fn device_state_digest(&self) -> &[u8] {
        &self.device_state_digest
    }

    /// Validates this material against the scenario launch contract.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when the material omits a vCPU
    /// from the launched `-smp N` topology or reports an RR quantum different
    /// from the scenario's pinned `rr_switch_quantum`.
    pub fn validate_against_contract(
        &self,
        contract: SingleVmNvcpuFingerprintContract,
    ) -> Result<(), SingleVmFingerprintGateError> {
        validate_nvcpu_fingerprint_material(self)?;
        if self.vcpu_registers.len() != contract.vcpu_count {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "N-vCPU fingerprint material vCPU count must match scenario -smp N",
                },
            );
        }
        if self.rr_cursor.rr_switch_quantum() != contract.rr_switch_quantum {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "round-robin switch quantum must match the scenario launch profile",
                },
            );
        }
        Ok(())
    }
}

/// QMP-observed vCPU topology for one sampled VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SingleVmQmpVcpuTopology {
    vcpu_count: usize,
}

impl SingleVmQmpVcpuTopology {
    /// Builds a QMP topology snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when QMP reports no vCPUs.
    pub const fn new(vcpu_count: usize) -> Result<Self, SingleVmFingerprintGateError> {
        if vcpu_count == 0 {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "QMP vCPU topology must report at least one vCPU",
                },
            );
        }
        Ok(Self { vcpu_count })
    }

    /// Returns the `-smp N` vCPU count observed through QMP.
    #[must_use]
    pub const fn vcpu_count(self) -> usize {
        self.vcpu_count
    }
}

/// Scenario contract for N-vCPU fingerprint samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SingleVmNvcpuFingerprintContract {
    vcpu_count: usize,
    rr_switch_quantum: u64,
}

impl SingleVmNvcpuFingerprintContract {
    /// Builds the launch-derived N-vCPU fingerprint contract.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when `vcpu_count` or
    /// `rr_switch_quantum` is zero.
    pub const fn new(
        vcpu_count: usize,
        rr_switch_quantum: u64,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        if vcpu_count == 0 {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "N-vCPU fingerprint contract must include at least one vCPU",
                },
            );
        }
        if rr_switch_quantum == 0 {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "N-vCPU fingerprint contract requires non-zero rr_switch_quantum",
                },
            );
        }
        Ok(Self {
            vcpu_count,
            rr_switch_quantum,
        })
    }

    /// Returns the launch-pinned `-smp N` vCPU count.
    #[must_use]
    pub const fn vcpu_count(self) -> usize {
        self.vcpu_count
    }

    /// Returns the launch-pinned RR switch quantum in node-icount units.
    #[must_use]
    pub const fn rr_switch_quantum(self) -> u64 {
        self.rr_switch_quantum
    }
}

/// Full material used to compute one rolling fingerprint sample.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintSampleMaterial {
    seq: u64,
    node: String,
    icount: u64,
    trigger: SingleVmFingerprintTrigger,
    nvcpu_fingerprint: SingleVmNvcpuFingerprintMaterial,
}

impl SingleVmFingerprintSampleMaterial {
    /// Builds validated material for one sample position.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when `node` is empty or
    /// `icount` is zero.
    pub fn new(
        seq: u64,
        node: impl Into<String>,
        icount: u64,
        trigger: SingleVmFingerprintTrigger,
        nvcpu_fingerprint: SingleVmNvcpuFingerprintMaterial,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        let node = node.into();
        if node.is_empty() {
            return Err(SingleVmFingerprintGateError::InvalidStream {
                reason: "sample node id must be non-empty",
            });
        }
        if icount == 0 {
            return Err(SingleVmFingerprintGateError::InvalidStream {
                reason: "sample icount must be non-zero",
            });
        }
        Ok(Self {
            seq,
            node,
            icount,
            trigger,
            nvcpu_fingerprint,
        })
    }

    /// Returns the monotonic sample number.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// Returns the stable node identifier.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Returns the aggregate node icount at the sample point.
    #[must_use]
    pub const fn icount(&self) -> u64 {
        self.icount
    }

    /// Returns the deterministic reason this sample was taken.
    #[must_use]
    pub const fn trigger(&self) -> SingleVmFingerprintTrigger {
        self.trigger
    }

    /// Returns the N-vCPU material folded into the sample digest.
    #[must_use]
    pub const fn nvcpu_fingerprint(&self) -> &SingleVmNvcpuFingerprintMaterial {
        &self.nvcpu_fingerprint
    }
}

/// Deterministic host-condition labels applied around both gate runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmHostProfile {
    name: String,
    stressors: Vec<String>,
}

impl SingleVmHostProfile {
    /// Builds a deterministic host profile.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError::InvalidHostProfile`] when the
    /// profile name is empty, a stressor label is empty, or the same stressor is
    /// named more than once.
    pub fn new(
        name: impl Into<String>,
        stressors: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        let name = name.into();
        if name.is_empty() {
            return Err(SingleVmFingerprintGateError::InvalidHostProfile {
                reason: "host profile name must be non-empty",
            });
        }

        let mut stressors = stressors.into_iter().map(Into::into).collect::<Vec<_>>();
        stressors.sort();
        for (index, stressor) in stressors.iter().enumerate() {
            if stressor.is_empty() {
                return Err(SingleVmFingerprintGateError::InvalidHostProfile {
                    reason: "host profile stressor labels must be non-empty",
                });
            }
            if index > 0 && stressors[index - 1] == *stressor {
                return Err(SingleVmFingerprintGateError::InvalidHostProfile {
                    reason: "host profile stressor labels must be unique",
                });
            }
        }

        Ok(Self { name, stressors })
    }

    /// Builds the conservative deterministic host-condition profile for Phase 1.
    #[must_use]
    pub fn phase1_adversarial() -> Self {
        Self {
            name: "phase1-single-vm-host-adversarial".to_owned(),
            stressors: vec![
                "host-scheduler-yield-points".to_owned(),
                "poll-order-rotation".to_owned(),
                "stdio-drain-order-variation".to_owned(),
            ],
        }
    }

    /// Returns the stable profile name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the sorted deterministic host-stressor labels.
    #[must_use]
    pub fn stressors(&self) -> &[String] {
        &self.stressors
    }
}

/// Exact content identities for one fixed single-VM gate configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintRunInputs {
    guest_image_digest: Vec<u8>,
    kernel_cmdline: String,
    seed_digest: Vec<u8>,
    injected_input_sequence_digest: Vec<u8>,
    launch_definition_digest: Vec<u8>,
}

impl SingleVmFingerprintRunInputs {
    /// Builds the exact guest-visible inputs shared by both gate runs.
    ///
    /// `guest_image_digest` covers the immutable kernel, initramfs, firmware,
    /// and disk backing manifest. `injected_input_sequence_digest` covers the
    /// complete ordered input sequence, including an explicitly empty one.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when any digest is not the
    /// canonical fingerprint width.
    pub fn new(
        guest_image_digest: impl Into<Vec<u8>>,
        kernel_cmdline: impl Into<String>,
        seed_digest: impl Into<Vec<u8>>,
        injected_input_sequence_digest: impl Into<Vec<u8>>,
        launch_definition_digest: impl Into<Vec<u8>>,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        let inputs = Self {
            guest_image_digest: guest_image_digest.into(),
            kernel_cmdline: kernel_cmdline.into(),
            seed_digest: seed_digest.into(),
            injected_input_sequence_digest: injected_input_sequence_digest.into(),
            launch_definition_digest: launch_definition_digest.into(),
        };
        validate_digest_len("guest_image_digest", &inputs.guest_image_digest)?;
        validate_digest_len("seed_digest", &inputs.seed_digest)?;
        validate_digest_len(
            "injected_input_sequence_digest",
            &inputs.injected_input_sequence_digest,
        )?;
        validate_digest_len("launch_definition_digest", &inputs.launch_definition_digest)?;
        Ok(inputs)
    }

    /// Returns the immutable guest image-manifest digest.
    #[must_use]
    pub fn guest_image_digest(&self) -> &[u8] {
        &self.guest_image_digest
    }

    /// Returns the exact kernel command line.
    #[must_use]
    pub fn kernel_cmdline(&self) -> &str {
        &self.kernel_cmdline
    }

    /// Returns the deterministic run-seed digest.
    #[must_use]
    pub fn seed_digest(&self) -> &[u8] {
        &self.seed_digest
    }

    /// Returns the content digest of the exact ordered injected-input sequence.
    #[must_use]
    pub fn injected_input_sequence_digest(&self) -> &[u8] {
        &self.injected_input_sequence_digest
    }

    /// Returns the digest of the complete concrete launch definition.
    #[must_use]
    pub fn launch_definition_digest(&self) -> &[u8] {
        &self.launch_definition_digest
    }

    /// Returns canonical material for the run-input identity.
    #[must_use]
    pub fn canonical_material(&self) -> String {
        [
            "crucible.qemu.single-vm-run-inputs.v1".to_owned(),
            format!("guest_image_digest={}", lower_hex(&self.guest_image_digest)),
            format!("kernel_cmdline={}", self.kernel_cmdline),
            format!("seed_digest={}", lower_hex(&self.seed_digest)),
            format!(
                "injected_input_sequence_digest={}",
                lower_hex(&self.injected_input_sequence_digest)
            ),
            format!(
                "launch_definition_digest={}",
                lower_hex(&self.launch_definition_digest)
            ),
        ]
        .join("\n")
    }

    /// Returns the content address of the complete fixed run-input tuple.
    #[must_use]
    pub fn content_digest(&self) -> [u8; 32] {
        ContentHash::from_canonical_material(
            SINGLE_VM_RUN_INPUTS_DOMAIN,
            &self.canonical_material(),
        )
        .bytes
    }
}

/// A fixed single-VM scenario for `gate:single-vm-fingerprint`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintScenario {
    pub(super) id: String,
    pub(super) fingerprint_definition_digest: Vec<u8>,
    pub(super) run_horizon_icount: u64,
    run_inputs: SingleVmFingerprintRunInputs,
    nvcpu_contract: SingleVmNvcpuFingerprintContract,
    host_profile: SingleVmHostProfile,
}

impl SingleVmFingerprintScenario {
    /// Builds a fixed single-VM fingerprint-gate scenario.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when the scenario id is empty,
    /// the run horizon is zero, or the fingerprint-definition digest is not the
    /// canonical digest width.
    pub fn new(
        id: impl Into<String>,
        fingerprint_definition_digest: impl Into<Vec<u8>>,
        run_horizon_icount: u64,
        run_inputs: SingleVmFingerprintRunInputs,
        host_profile: SingleVmHostProfile,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        Self::new_with_nvcpu_contract(
            id,
            fingerprint_definition_digest,
            run_horizon_icount,
            SingleVmNvcpuFingerprintContract::new(1, 1)?,
            run_inputs,
            host_profile,
        )
    }

    /// Builds a fixed scenario with an explicit N-vCPU launch contract.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when the scenario id is empty,
    /// the run horizon is zero, or the fingerprint-definition digest is not the
    /// canonical digest width.
    pub fn new_with_nvcpu_contract(
        id: impl Into<String>,
        fingerprint_definition_digest: impl Into<Vec<u8>>,
        run_horizon_icount: u64,
        nvcpu_contract: SingleVmNvcpuFingerprintContract,
        run_inputs: SingleVmFingerprintRunInputs,
        host_profile: SingleVmHostProfile,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        let id = id.into();
        if id.is_empty() {
            return Err(SingleVmFingerprintGateError::InvalidScenario {
                reason: "scenario id must be non-empty",
            });
        }
        if run_horizon_icount == 0 {
            return Err(SingleVmFingerprintGateError::InvalidScenario {
                reason: "run horizon icount must be non-zero",
            });
        }
        let fingerprint_definition_digest = fingerprint_definition_digest.into();
        validate_digest_len(
            "fingerprint_definition_digest",
            &fingerprint_definition_digest,
        )?;

        Ok(Self {
            id,
            fingerprint_definition_digest,
            run_horizon_icount,
            run_inputs,
            nvcpu_contract,
            host_profile,
        })
    }

    /// Returns the content-addressed scenario id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the content-addressed fingerprint definition digest.
    #[must_use]
    pub fn fingerprint_definition_digest(&self) -> &[u8] {
        &self.fingerprint_definition_digest
    }

    /// Returns the aggregate icount each run must reach.
    #[must_use]
    pub fn run_horizon_icount(&self) -> u64 {
        self.run_horizon_icount
    }

    /// Returns the exact image, command line, seed, input, and launch tuple.
    #[must_use]
    pub const fn run_inputs(&self) -> &SingleVmFingerprintRunInputs {
        &self.run_inputs
    }

    /// Returns the scenario's launch-derived N-vCPU fingerprint contract.
    #[must_use]
    pub const fn nvcpu_contract(&self) -> SingleVmNvcpuFingerprintContract {
        self.nvcpu_contract
    }

    /// Returns the launch-pinned expected vCPU count.
    #[must_use]
    pub const fn expected_vcpu_count(&self) -> usize {
        self.nvcpu_contract.vcpu_count()
    }

    /// Returns the launch-pinned RR switch quantum.
    #[must_use]
    pub const fn expected_rr_switch_quantum(&self) -> u64 {
        self.nvcpu_contract.rr_switch_quantum()
    }

    /// Returns the deterministic host-condition profile for both runs.
    #[must_use]
    pub fn host_profile(&self) -> &SingleVmHostProfile {
        &self.host_profile
    }
}

/// Which of the two required gate runs a backend should execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SingleVmFingerprintRunOrdinal {
    /// The first run of the fixed scenario.
    First,
    /// The second run of the fixed scenario.
    Second,
}

/// A request sent from the gate driver to a backend runner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintRunRequest {
    scenario: SingleVmFingerprintScenario,
    ordinal: SingleVmFingerprintRunOrdinal,
}

impl SingleVmFingerprintRunRequest {
    /// Builds a single run request for a fixed scenario.
    #[must_use]
    pub fn new(
        scenario: SingleVmFingerprintScenario,
        ordinal: SingleVmFingerprintRunOrdinal,
    ) -> Self {
        Self { scenario, ordinal }
    }

    /// Returns the fixed scenario to execute.
    #[must_use]
    pub fn scenario(&self) -> &SingleVmFingerprintScenario {
        &self.scenario
    }

    /// Returns whether this is the first or second run.
    #[must_use]
    pub fn ordinal(&self) -> SingleVmFingerprintRunOrdinal {
        self.ordinal
    }
}

/// A request to refine a mismatching pair of fingerprint streams.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintBisectionRequest {
    scenario: SingleVmFingerprintScenario,
    mismatch: SingleVmFingerprintMismatch,
    first_stream: SingleVmFingerprintStream,
    second_stream: SingleVmFingerprintStream,
}

impl SingleVmFingerprintBisectionRequest {
    /// Builds a mismatch bisection request.
    #[must_use]
    pub fn new(
        scenario: SingleVmFingerprintScenario,
        mismatch: SingleVmFingerprintMismatch,
        first_stream: SingleVmFingerprintStream,
        second_stream: SingleVmFingerprintStream,
    ) -> Self {
        Self {
            scenario,
            mismatch,
            first_stream,
            second_stream,
        }
    }

    /// Returns the fixed scenario whose runs diverged.
    #[must_use]
    pub fn scenario(&self) -> &SingleVmFingerprintScenario {
        &self.scenario
    }

    /// Returns the first localized stream mismatch.
    #[must_use]
    pub fn mismatch(&self) -> &SingleVmFingerprintMismatch {
        &self.mismatch
    }

    /// Returns the first run stream to include in diagnostics.
    #[must_use]
    pub fn first_stream(&self) -> &SingleVmFingerprintStream {
        &self.first_stream
    }

    /// Returns the second run stream to include in diagnostics.
    #[must_use]
    pub fn second_stream(&self) -> &SingleVmFingerprintStream {
        &self.second_stream
    }
}

/// The refined bisection result attached to a single-VM fingerprint mismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintBisectionReport {
    sample_index: usize,
    previous_matching_icount: Option<u64>,
    first_different_sample_icount: u64,
    last_matching_icount: u64,
    first_different_icount: u64,
    responsible_node: String,
    definition_digest: [u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES],
    run_inputs_digest: [u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES],
    state_dump: SingleVmFingerprintDivergenceStateDump,
    state_dump_content_address: String,
}

impl SingleVmFingerprintBisectionReport {
    /// Builds a validated bisection report.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError::InvalidBisectionReport`] when
    /// the report has an impossible icount window or the state dump does not
    /// describe the exact first differing instruction.
    pub fn new(
        sample_index: usize,
        previous_matching_icount: Option<u64>,
        first_different_sample_icount: u64,
        last_matching_icount: u64,
        first_different_icount: u64,
        scenario: &SingleVmFingerprintScenario,
        state_dump: SingleVmFingerprintDivergenceStateDump,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        if first_different_icount > first_different_sample_icount {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "exact first differing icount must be within the coarse sample window",
            });
        }
        if first_different_icount == 0 {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "instruction divergence must follow at least one retired instruction",
            });
        }
        if last_matching_icount >= first_different_icount {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "last matching icount must be before the first differing icount",
            });
        }
        if first_different_icount != 0
            && last_matching_icount.checked_add(1) != Some(first_different_icount)
        {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "instruction-exact bisection must leave a one-instruction interval",
            });
        }
        if previous_matching_icount.is_some_and(|previous| {
            previous > last_matching_icount || previous >= first_different_sample_icount
        }) {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "previous matching icount is outside the bisection window",
            });
        }

        if state_dump.first().icount() != first_different_icount
            || state_dump.second().icount() != first_different_icount
        {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump icount must equal the first differing instruction",
            });
        }
        if state_dump.first().vcpu_registers().len() != scenario.expected_vcpu_count()
            || state_dump.second().vcpu_registers().len() != scenario.expected_vcpu_count()
        {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump vCPU topology must match the report scenario",
            });
        }
        let responsible_node = state_dump.first().node().to_owned();
        let definition_digest = scenario
            .fingerprint_definition_digest()
            .try_into()
            .map_err(
                |_error| SingleVmFingerprintGateError::InvalidBisectionReport {
                    reason: "scenario definition digest lost its fixed width",
                },
            )?;
        let run_inputs_digest = scenario.run_inputs().content_digest();
        let state_dump_content_address =
            format!("blake3:{}", lower_hex(&state_dump.content_digest()));

        Ok(Self {
            sample_index,
            previous_matching_icount,
            first_different_sample_icount,
            last_matching_icount,
            first_different_icount,
            responsible_node,
            definition_digest,
            run_inputs_digest,
            state_dump,
            state_dump_content_address,
        })
    }

    /// Returns the index of the first differing fingerprint sample.
    #[must_use]
    pub fn sample_index(&self) -> usize {
        self.sample_index
    }

    /// Returns the last icount known to match before bisection.
    #[must_use]
    pub fn previous_matching_icount(&self) -> Option<u64> {
        self.previous_matching_icount
    }

    /// Returns the first differing sample icount before fine bisection.
    #[must_use]
    pub fn first_different_sample_icount(&self) -> u64 {
        self.first_different_sample_icount
    }

    /// Returns the last exact icount where the two runs still matched.
    #[must_use]
    pub fn last_matching_icount(&self) -> u64 {
        self.last_matching_icount
    }

    /// Returns the exact first icount where the two runs differed.
    #[must_use]
    pub fn first_different_icount(&self) -> u64 {
        self.first_different_icount
    }

    /// Returns the node whose architectural state first diverged.
    #[must_use]
    pub fn responsible_node(&self) -> &str {
        &self.responsible_node
    }

    /// Returns the observation-definition digest used by both dump runs.
    #[must_use]
    pub const fn definition_digest(&self) -> &[u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES] {
        &self.definition_digest
    }

    /// Returns the exact run-input tuple digest used by both dump runs.
    #[must_use]
    pub const fn run_inputs_digest(&self) -> &[u8; SINGLE_VM_FINGERPRINT_DIGEST_BYTES] {
        &self.run_inputs_digest
    }

    /// Returns the validated both-sides architectural state dump.
    #[must_use]
    pub const fn state_dump(&self) -> &SingleVmFingerprintDivergenceStateDump {
        &self.state_dump
    }

    /// Returns the BLAKE3 content address of the in-memory both-side state dump.
    #[must_use]
    pub fn state_dump_content_address(&self) -> &str {
        &self.state_dump_content_address
    }
}

/// One canonical fingerprint sample from a single-VM run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintSample {
    /// Monotonic sample number within the stream.
    pub seq: u64,
    /// Stable node identifier associated with the sampled VM.
    pub node: String,
    /// Aggregate node icount at the sample point.
    pub icount: u64,
    /// The deterministic reason the sample was taken.
    pub trigger: SingleVmFingerprintTrigger,
    /// Host-observed N-vCPU register, RR cursor, memory, and device material.
    pub nvcpu_fingerprint: SingleVmNvcpuFingerprintMaterial,
    /// Rolling fingerprint bytes after incorporating this sample.
    pub rolling_fingerprint: Vec<u8>,
}

impl SingleVmFingerprintSample {
    /// Builds a sample by folding canonical material into the rolling digest.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when the definition digest,
    /// previous rolling fingerprint, or sample material is invalid.
    pub fn from_material(
        definition_digest: &[u8],
        previous_rolling_fingerprint: &[u8],
        material: SingleVmFingerprintSampleMaterial,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        let rolling_fingerprint = compute_single_vm_sample_rolling_fingerprint_from_material(
            definition_digest,
            previous_rolling_fingerprint,
            &material,
        )?;
        Ok(Self {
            seq: material.seq,
            node: material.node,
            icount: material.icount,
            trigger: material.trigger,
            nvcpu_fingerprint: material.nvcpu_fingerprint,
            rolling_fingerprint,
        })
    }

    /// Returns the canonical sample material without the rolling digest.
    #[must_use]
    pub fn material(&self) -> SingleVmFingerprintSampleMaterial {
        SingleVmFingerprintSampleMaterial {
            seq: self.seq,
            node: self.node.clone(),
            icount: self.icount,
            trigger: self.trigger,
            nvcpu_fingerprint: self.nvcpu_fingerprint.clone(),
        }
    }
}

/// The ordered fingerprint stream for one single-VM run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintStream {
    /// The fixed content-addressed fingerprint definition digest.
    pub definition_digest: Vec<u8>,
    /// Samples in canonical comparison order.
    pub samples: Vec<SingleVmFingerprintSample>,
    /// Aggregate node icount associated with the final fingerprint.
    pub final_icount: u64,
    /// Final run fingerprint bytes.
    pub final_fingerprint: Vec<u8>,
}

impl SingleVmFingerprintStream {
    /// Builds a validated single-VM fingerprint stream.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when a digest has the wrong
    /// length, the stream is empty, samples are not canonical, or a sample
    /// appears beyond the scenario horizon.
    pub fn new(
        definition_digest: impl Into<Vec<u8>>,
        samples: Vec<SingleVmFingerprintSample>,
        final_icount: u64,
        final_fingerprint: impl Into<Vec<u8>>,
        run_horizon_icount: u64,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        let definition_digest = definition_digest.into();
        validate_digest_len("definition_digest", &definition_digest)?;
        validate_samples(&definition_digest, &samples, run_horizon_icount, None)?;
        validate_final_icount(final_icount, run_horizon_icount)?;
        let final_fingerprint = final_fingerprint.into();
        validate_digest_len("final_fingerprint", &final_fingerprint)?;

        Ok(Self {
            definition_digest,
            samples,
            final_icount,
            final_fingerprint,
        })
    }
}

/// A backend capable of executing one fixed single-VM fingerprint run.
pub trait SingleVmFingerprintRunner {
    /// Runs the requested VM and returns its canonical fingerprint stream.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintRunError`] when the backend cannot complete
    /// the requested run or cannot obtain a canonical fingerprint stream.
    fn run_single_vm_fingerprint(
        &mut self,
        request: &SingleVmFingerprintRunRequest,
    ) -> Result<SingleVmFingerprintStream, SingleVmFingerprintRunError>;

    /// Refines a stream mismatch to an exact divergence report.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintBisectionError`] when the backend cannot
    /// resume/probe the two runs or cannot emit the required both-sides state
    /// dump for the first differing icount.
    fn bisect_single_vm_fingerprint_mismatch(
        &mut self,
        request: &SingleVmFingerprintBisectionRequest,
    ) -> Result<SingleVmFingerprintBisectionReport, SingleVmFingerprintBisectionError>;
}

/// A backend execution failure before stream comparison.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("single-VM fingerprint backend failed: {message}")]
pub struct SingleVmFingerprintRunError {
    message: String,
}

impl SingleVmFingerprintRunError {
    /// Builds a backend execution failure.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the backend-provided message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// A backend failure while refining a mismatch with bisection.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("single-VM fingerprint bisection failed: {message}")]
pub struct SingleVmFingerprintBisectionError {
    message: String,
}

impl SingleVmFingerprintBisectionError {
    /// Builds a backend bisection failure.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the backend-provided message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// The successful result of `gate:single-vm-fingerprint`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintGateReport {
    /// The content-addressed scenario id that was executed twice.
    pub scenario_id: String,
    /// The first run stream.
    pub first_stream: SingleVmFingerprintStream,
    /// The second run stream.
    pub second_stream: SingleVmFingerprintStream,
    /// The shared final fingerprint proven equal by the gate.
    pub matching_final_fingerprint: Vec<u8>,
    /// Number of compared samples.
    pub sample_count: usize,
}

/// A validation, execution, or comparison failure from the single-VM gate.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum SingleVmFingerprintGateError {
    /// The requested scenario is not fixed enough to compare.
    #[error("invalid single-VM fingerprint scenario: {reason}")]
    InvalidScenario {
        /// Human-readable validation failure.
        reason: &'static str,
    },
    /// The host-condition profile is ambiguous.
    #[error("invalid single-VM fingerprint host profile: {reason}")]
    InvalidHostProfile {
        /// Human-readable validation failure.
        reason: &'static str,
    },
    /// N-vCPU sample material is ambiguous or incomplete.
    #[error("invalid single-VM N-vCPU fingerprint material: {reason}")]
    InvalidNvcpuFingerprintMaterial {
        /// Human-readable validation failure.
        reason: &'static str,
    },
    /// A digest does not use the canonical fixed length.
    #[error("{field} digest length {len} is not {SINGLE_VM_FINGERPRINT_DIGEST_BYTES} bytes")]
    InvalidDigestLength {
        /// Digest field with the wrong length.
        field: &'static str,
        /// Provided byte length.
        len: usize,
    },
    /// A backend failed one of the two required runs.
    #[error("{ordinal:?} single-VM fingerprint run failed: {source}")]
    RunFailed {
        /// Which of the two runs failed.
        ordinal: SingleVmFingerprintRunOrdinal,
        /// Backend failure.
        source: SingleVmFingerprintRunError,
    },
    /// A backend returned a non-canonical stream.
    #[error("invalid {ordinal:?} single-VM fingerprint stream: {reason}")]
    InvalidStreamForRun {
        /// Which run returned the invalid stream.
        ordinal: SingleVmFingerprintRunOrdinal,
        /// Human-readable validation failure.
        reason: &'static str,
    },
    /// A backend returned a malformed mismatch bisection report.
    #[error("invalid single-VM fingerprint bisection report: {reason}")]
    InvalidBisectionReport {
        /// Human-readable validation failure.
        reason: &'static str,
    },
    /// A stream is not internally canonical.
    #[error("invalid single-VM fingerprint stream: {reason}")]
    InvalidStream {
        /// Human-readable validation failure.
        reason: &'static str,
    },
    /// A backend could not refine a stream mismatch by bisection.
    #[error("single-VM fingerprint mismatch bisection failed: {source}")]
    BisectionFailed {
        /// The first deterministic mismatch.
        mismatch: Box<SingleVmFingerprintMismatch>,
        /// First run stream to include in diagnostics.
        first_stream: Box<SingleVmFingerprintStream>,
        /// Second run stream to include in diagnostics.
        second_stream: Box<SingleVmFingerprintStream>,
        /// Backend bisection failure.
        source: SingleVmFingerprintBisectionError,
    },
    /// The two canonical streams differed.
    #[error("single-VM fingerprint streams differ: {mismatch}; bisection report attached")]
    Mismatch {
        /// The first deterministic mismatch.
        mismatch: Box<SingleVmFingerprintMismatch>,
        /// First run stream to include in diagnostics.
        first_stream: Box<SingleVmFingerprintStream>,
        /// Second run stream to include in diagnostics.
        second_stream: Box<SingleVmFingerprintStream>,
        /// Exact bisection result for the mismatch.
        bisection: Box<SingleVmFingerprintBisectionReport>,
    },
}

/// Computes the definition-specific initial rolling fingerprint.
///
/// # Errors
///
/// Returns [`SingleVmFingerprintGateError::InvalidDigestLength`] when
/// `definition_digest` is not the canonical digest width.
pub fn initial_single_vm_rolling_fingerprint(
    definition_digest: &[u8],
) -> Result<Vec<u8>, SingleVmFingerprintGateError> {
    validate_digest_len("definition_digest", definition_digest)?;
    let material = format!("definition_digest={}", lower_hex(definition_digest));
    Ok(
        ContentHash::from_canonical_material(SINGLE_VM_FINGERPRINT_STREAM_SEED_DOMAIN, &material)
            .bytes
            .to_vec(),
    )
}

/// Computes the rolling digest for a sample's canonical N-vCPU material.
///
/// # Errors
///
/// Returns [`SingleVmFingerprintGateError`] when either input digest is not the
/// canonical width or the sample material is invalid.
pub fn compute_single_vm_sample_rolling_fingerprint(
    definition_digest: &[u8],
    previous_rolling_fingerprint: &[u8],
    sample: &SingleVmFingerprintSample,
) -> Result<Vec<u8>, SingleVmFingerprintGateError> {
    compute_single_vm_sample_rolling_fingerprint_from_material(
        definition_digest,
        previous_rolling_fingerprint,
        &sample.material(),
    )
}

fn compute_single_vm_sample_rolling_fingerprint_from_material(
    definition_digest: &[u8],
    previous_rolling_fingerprint: &[u8],
    material: &SingleVmFingerprintSampleMaterial,
) -> Result<Vec<u8>, SingleVmFingerprintGateError> {
    validate_digest_len("definition_digest", definition_digest)?;
    validate_digest_len("previous_rolling_fingerprint", previous_rolling_fingerprint)?;
    validate_nvcpu_fingerprint_material(&material.nvcpu_fingerprint)?;

    let canonical_material =
        sample_canonical_material(definition_digest, previous_rolling_fingerprint, material);
    Ok(ContentHash::from_canonical_material(
        SINGLE_VM_FINGERPRINT_SAMPLE_DOMAIN,
        &canonical_material,
    )
    .bytes
    .to_vec())
}

fn sample_canonical_material(
    definition_digest: &[u8],
    previous_rolling_fingerprint: &[u8],
    material: &SingleVmFingerprintSampleMaterial,
) -> String {
    let mut lines = vec![
        "crucible.qemu.single-vm-fingerprint-sample.v1".to_owned(),
        format!("definition_digest={}", lower_hex(definition_digest)),
        format!(
            "previous_rolling_fingerprint={}",
            lower_hex(previous_rolling_fingerprint)
        ),
        format!("seq={}", material.seq),
        format!("node={}", material.node),
        format!("icount={}", material.icount),
        format!("trigger={}", trigger_token(material.trigger)),
        format!(
            "vcpu_count={}",
            material.nvcpu_fingerprint.vcpu_registers.len()
        ),
    ];
    for (index, register) in material.nvcpu_fingerprint.vcpu_registers.iter().enumerate() {
        lines.push(format!("vcpu[{index}].id={}", register.vcpu_id));
        lines.push(format!(
            "vcpu[{index}].register_digest={}",
            lower_hex(&register.register_digest)
        ));
        lines.push(format!(
            "vcpu[{index}].register_file_bytes={}",
            register.register_file_bytes
        ));
        lines.push(format!(
            "vcpu[{index}].retired_instruction_count={}",
            register.retired_instruction_count
        ));
    }

    let cursor = material.nvcpu_fingerprint.rr_cursor;
    lines.push(format!("rr_current_vcpu={}", cursor.current_vcpu));
    lines.push(format!(
        "rr_position_in_quantum={}",
        cursor.position_in_quantum
    ));
    lines.push(format!("rr_switch_quantum={}", cursor.rr_switch_quantum));
    lines.push(format!(
        "guest_memory_digest={}",
        lower_hex(&material.nvcpu_fingerprint.guest_memory_digest)
    ));
    lines.push(format!(
        "device_state_digest={}",
        lower_hex(&material.nvcpu_fingerprint.device_state_digest)
    ));
    lines.join("\n")
}

fn validate_nvcpu_fingerprint_material(
    material: &SingleVmNvcpuFingerprintMaterial,
) -> Result<(), SingleVmFingerprintGateError> {
    if material.vcpu_registers.is_empty() {
        return Err(
            SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                reason: "N-vCPU fingerprint material must include at least one vCPU",
            },
        );
    }
    for (expected, register) in material.vcpu_registers.iter().enumerate() {
        if register.vcpu_id != expected as u64 {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "N-vCPU fingerprint material must cover exactly vCPUs 0..N",
                },
            );
        }
        if register.register_file_bytes == 0 {
            return Err(
                SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                    reason: "vCPU register file byte count must be non-zero",
                },
            );
        }
        validate_digest_len("register_digest", &register.register_digest)?;
    }
    if material.rr_cursor.current_vcpu >= material.vcpu_registers.len() as u64 {
        return Err(
            SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                reason: "round-robin current vCPU must be inside the sampled vCPU set",
            },
        );
    }
    if material.rr_cursor.rr_switch_quantum == 0 {
        return Err(
            SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                reason: "round-robin switch quantum must be non-zero",
            },
        );
    }
    if material.rr_cursor.position_in_quantum >= material.rr_cursor.rr_switch_quantum {
        return Err(
            SingleVmFingerprintGateError::InvalidNvcpuFingerprintMaterial {
                reason: "round-robin cursor position must be inside rr_switch_quantum",
            },
        );
    }
    validate_digest_len("guest_memory_digest", &material.guest_memory_digest)?;
    validate_digest_len("device_state_digest", &material.device_state_digest)?;
    Ok(())
}

fn trigger_token(trigger: SingleVmFingerprintTrigger) -> &'static str {
    match trigger {
        SingleVmFingerprintTrigger::Periodic => "periodic",
        SingleVmFingerprintTrigger::Event(event) => match event {
            SingleVmFingerprintEventBoundary::HorizonAdvance => "horizon-advance",
            SingleVmFingerprintEventBoundary::FrameDelivery => "frame-delivery",
            SingleVmFingerprintEventBoundary::SignalEffectBoundary => "signal-effect-boundary",
        },
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub(super) fn validate_samples(
    definition_digest: &[u8],
    samples: &[SingleVmFingerprintSample],
    run_horizon_icount: u64,
    nvcpu_contract: Option<SingleVmNvcpuFingerprintContract>,
) -> Result<(), SingleVmFingerprintGateError> {
    if samples.is_empty() {
        return Err(SingleVmFingerprintGateError::InvalidStream {
            reason: "fingerprint stream must include at least one sample",
        });
    }
    let mut previous_icount = None;
    let mut previous_rolling_fingerprint =
        initial_single_vm_rolling_fingerprint(definition_digest)?;
    for (index, sample) in samples.iter().enumerate() {
        if sample.seq != index as u64 {
            return Err(SingleVmFingerprintGateError::InvalidStream {
                reason: "sample sequence numbers must match canonical stream order",
            });
        }
        if sample.node.is_empty() {
            return Err(SingleVmFingerprintGateError::InvalidStream {
                reason: "sample node id must be non-empty",
            });
        }
        if sample.icount == 0 || sample.icount > run_horizon_icount {
            return Err(SingleVmFingerprintGateError::InvalidStream {
                reason: "sample icount must be within the scenario horizon",
            });
        }
        if previous_icount.is_some_and(|previous| previous > sample.icount) {
            return Err(SingleVmFingerprintGateError::InvalidStream {
                reason: "sample icounts must be monotonically ordered",
            });
        }
        validate_digest_len("rolling_fingerprint", &sample.rolling_fingerprint)?;
        validate_nvcpu_fingerprint_material(&sample.nvcpu_fingerprint)?;
        if let Some(contract) = nvcpu_contract {
            sample
                .nvcpu_fingerprint
                .validate_against_contract(contract)?;
        }
        let expected_rolling_fingerprint = compute_single_vm_sample_rolling_fingerprint(
            definition_digest,
            &previous_rolling_fingerprint,
            sample,
        )?;
        if sample.rolling_fingerprint != expected_rolling_fingerprint {
            return Err(SingleVmFingerprintGateError::InvalidStream {
                reason: "sample rolling fingerprint must include canonical N-vCPU material",
            });
        }
        previous_icount = Some(sample.icount);
        previous_rolling_fingerprint = sample.rolling_fingerprint.clone();
    }
    if previous_icount != Some(run_horizon_icount) {
        return Err(SingleVmFingerprintGateError::InvalidStream {
            reason: "fingerprint stream must include a sample at the scenario horizon",
        });
    }
    Ok(())
}

pub(super) fn validate_final_icount(
    final_icount: u64,
    run_horizon_icount: u64,
) -> Result<(), SingleVmFingerprintGateError> {
    if final_icount < run_horizon_icount {
        Err(SingleVmFingerprintGateError::InvalidStream {
            reason: "final fingerprint icount must be at or beyond the scenario horizon",
        })
    } else {
        Ok(())
    }
}

pub(super) fn validate_digest_len(
    field: &'static str,
    digest: &[u8],
) -> Result<(), SingleVmFingerprintGateError> {
    if digest.len() == SINGLE_VM_FINGERPRINT_DIGEST_BYTES {
        Ok(())
    } else {
        Err(SingleVmFingerprintGateError::InvalidDigestLength {
            field,
            len: digest.len(),
        })
    }
}
