//! Structured both-sides state dumps for instruction-exact divergence reports.
//!
//! A dump contains the complete architectural register bytes for every vCPU,
//! the memory regions that differ, the complete serialized non-RAM QEMU
//! VMState, and the retained canonical events leading to the first differing
//! instruction. The content digest makes the diagnostic artifact independently
//! verifiable instead of trusting an arbitrary path label.

use crucible::ContentHash;

use super::SingleVmFingerprintGateError;

const STATE_DUMP_DOMAIN: &str = "crucible.qemu.single-vm-divergence-state-dump.v1";

/// One vCPU's complete architectural register-file bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintVcpuState {
    vcpu_id: u64,
    register_file: Vec<u8>,
}

impl SingleVmFingerprintVcpuState {
    /// Builds one full vCPU register state.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when the register file is empty.
    pub fn new(
        vcpu_id: u64,
        register_file: impl Into<Vec<u8>>,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        let register_file = register_file.into();
        if register_file.is_empty() {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump vCPU register files must be non-empty",
            });
        }
        Ok(Self {
            vcpu_id,
            register_file,
        })
    }

    /// Returns the zero-based vCPU identifier.
    #[must_use]
    pub const fn vcpu_id(&self) -> u64 {
        self.vcpu_id
    }

    /// Returns the complete canonical architectural register bytes.
    #[must_use]
    pub fn register_file(&self) -> &[u8] {
        &self.register_file
    }
}

/// One contiguous guest-memory region retained because the two sides differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintMemoryRegionState {
    guest_physical_start: u64,
    bytes: Vec<u8>,
}

impl SingleVmFingerprintMemoryRegionState {
    /// Builds one non-empty differing guest-memory region.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when `bytes` is empty or the
    /// region end overflows the guest-physical address space.
    pub fn new(
        guest_physical_start: u64,
        bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump memory regions must be non-empty",
            });
        }
        let length = u64::try_from(bytes.len()).map_err(|_error| {
            SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump memory region length does not fit u64",
            }
        })?;
        guest_physical_start.checked_add(length).ok_or(
            SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump memory region end overflowed",
            },
        )?;
        Ok(Self {
            guest_physical_start,
            bytes,
        })
    }

    /// Returns the first guest-physical byte address.
    #[must_use]
    pub const fn guest_physical_start(&self) -> u64 {
        self.guest_physical_start
    }

    /// Returns the retained bytes for this side of the divergence.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn end_exclusive(&self) -> u64 {
        self.guest_physical_start + self.bytes.len() as u64
    }
}

/// Complete diagnostic state for one side at the first differing instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintRunStateDump {
    node: String,
    icount: u64,
    vcpu_registers: Vec<SingleVmFingerprintVcpuState>,
    differing_memory_regions: Vec<SingleVmFingerprintMemoryRegionState>,
    device_state: Vec<u8>,
    canonical_events: Vec<String>,
}

impl SingleVmFingerprintRunStateDump {
    /// Builds one validated side of a divergence dump.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when the node is empty, icount
    /// is zero, vCPU states are not exactly `0..N`, memory regions overlap or
    /// are out of order, the device VMState is empty, or no canonical event is
    /// retained.
    pub fn new(
        node: impl Into<String>,
        icount: u64,
        vcpu_registers: Vec<SingleVmFingerprintVcpuState>,
        differing_memory_regions: Vec<SingleVmFingerprintMemoryRegionState>,
        device_state: impl Into<Vec<u8>>,
        canonical_events: Vec<String>,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        let node = node.into();
        if node.is_empty() {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump node must be non-empty",
            });
        }
        if icount == 0 {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump icount must be non-zero",
            });
        }
        if vcpu_registers.is_empty()
            || vcpu_registers
                .iter()
                .enumerate()
                .any(|(expected, state)| state.vcpu_id() != expected as u64)
        {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump vCPU registers must cover exactly vCPUs 0..N",
            });
        }
        if differing_memory_regions.windows(2).any(|pair| {
            pair[0].guest_physical_start() >= pair[1].guest_physical_start()
                || pair[0].end_exclusive() > pair[1].guest_physical_start()
        }) {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump memory regions must be sorted and non-overlapping",
            });
        }
        let device_state = device_state.into();
        if device_state.is_empty() {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump device VMState must be non-empty",
            });
        }
        if canonical_events.is_empty() || canonical_events.iter().any(String::is_empty) {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump must retain non-empty canonical events",
            });
        }
        Ok(Self {
            node,
            icount,
            vcpu_registers,
            differing_memory_regions,
            device_state,
            canonical_events,
        })
    }

    /// Returns the responsible node.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// Returns the exact first differing aggregate icount.
    #[must_use]
    pub const fn icount(&self) -> u64 {
        self.icount
    }

    /// Returns every vCPU's complete architectural register bytes.
    #[must_use]
    pub fn vcpu_registers(&self) -> &[SingleVmFingerprintVcpuState] {
        &self.vcpu_registers
    }

    /// Returns the sorted guest-memory regions that differ.
    #[must_use]
    pub fn differing_memory_regions(&self) -> &[SingleVmFingerprintMemoryRegionState] {
        &self.differing_memory_regions
    }

    /// Returns the complete serialized non-RAM QEMU VMState bytes.
    #[must_use]
    pub fn device_state(&self) -> &[u8] {
        &self.device_state
    }

    /// Returns the retained canonical events leading to the divergence.
    #[must_use]
    pub fn canonical_events(&self) -> &[String] {
        &self.canonical_events
    }
}

/// Validated both-sides state at the first differing instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintDivergenceStateDump {
    first: SingleVmFingerprintRunStateDump,
    second: SingleVmFingerprintRunStateDump,
}

impl SingleVmFingerprintDivergenceStateDump {
    /// Builds a both-sides state dump and proves that it contains a difference.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when the two sides name
    /// different nodes or icounts, cover different vCPU sets, or contain no
    /// register, memory, or device-state difference.
    pub fn new(
        first: SingleVmFingerprintRunStateDump,
        second: SingleVmFingerprintRunStateDump,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        if first.node() != second.node() || first.icount() != second.icount() {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "both state-dump sides must name the same node and icount",
            });
        }
        if first.vcpu_registers().len() != second.vcpu_registers().len() {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "both state-dump sides must cover the same vCPU set",
            });
        }
        let registers_differ = first.vcpu_registers() != second.vcpu_registers();
        let memory_differs = first.differing_memory_regions() != second.differing_memory_regions();
        let device_differs = first.device_state() != second.device_state();
        if !registers_differ && !memory_differs && !device_differs {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "both-sides state dump must contain an architectural difference",
            });
        }
        Ok(Self { first, second })
    }

    /// Returns the first run's state.
    #[must_use]
    pub const fn first(&self) -> &SingleVmFingerprintRunStateDump {
        &self.first
    }

    /// Returns the second run's state.
    #[must_use]
    pub const fn second(&self) -> &SingleVmFingerprintRunStateDump {
        &self.second
    }

    /// Returns the content address of the complete structured dump.
    #[must_use]
    pub fn content_digest(&self) -> [u8; 32] {
        ContentHash::from_canonical_material(STATE_DUMP_DOMAIN, &self.canonical_material()).bytes
    }

    fn canonical_material(&self) -> String {
        let mut material = String::from("crucible.qemu.single-vm-divergence-state-dump.v1\n");
        append_run_material(&mut material, "first", &self.first);
        append_run_material(&mut material, "second", &self.second);
        material
    }
}

fn append_run_material(output: &mut String, side: &str, state: &SingleVmFingerprintRunStateDump) {
    output.push_str(&format!("{side}.node={}\n", state.node()));
    output.push_str(&format!("{side}.icount={}\n", state.icount()));
    for register in state.vcpu_registers() {
        output.push_str(&format!(
            "{side}.vcpu[{}]={}\n",
            register.vcpu_id(),
            lower_hex(register.register_file())
        ));
    }
    for (index, region) in state.differing_memory_regions().iter().enumerate() {
        output.push_str(&format!(
            "{side}.memory[{index}].start={}\n{side}.memory[{index}].bytes={}\n",
            region.guest_physical_start(),
            lower_hex(region.bytes())
        ));
    }
    output.push_str(&format!(
        "{side}.device_state={}\n",
        lower_hex(state.device_state())
    ));
    for (index, event) in state.canonical_events().iter().enumerate() {
        output.push_str(&format!("{side}.event[{index}]={event}\n"));
    }
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
