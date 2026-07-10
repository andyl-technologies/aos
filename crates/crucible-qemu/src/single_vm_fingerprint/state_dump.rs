//! Structured both-sides state dumps for instruction-exact divergence reports.
//!
//! A dump contains the complete architectural register bytes for every vCPU,
//! the memory regions that differ, the complete serialized non-RAM QEMU
//! VMState, and the retained canonical events leading to the first differing
//! instruction. The content digest makes the diagnostic artifact independently
//! verifiable instead of trusting an arbitrary path label.

use crucible::{
    ContentHash, EventLogCausalProjectionEntry, SchedulerEventLogClass, SchedulerEventLogEntry,
};

use super::SingleVmFingerprintGateError;

const STATE_DUMP_DOMAIN: &str = "crucible.qemu.single-vm-divergence-state-dump.v1";
/// Number of final scheduler-causal events retained on each dump side.
pub const SINGLE_VM_FINGERPRINT_STATE_DUMP_EVENT_LIMIT: u64 = 64;

/// One typed canonical event retained before the divergence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SingleVmFingerprintCanonicalEvent {
    scheduler_entry: SchedulerEventLogEntry,
}

impl SingleVmFingerprintCanonicalEvent {
    /// Retains one verified scheduler causal-projection entry.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when the supplied entry is not
    /// causal or its canonical scheduler content hash is invalid.
    pub fn from_causal_projection_entry(
        entry: &EventLogCausalProjectionEntry,
    ) -> Result<Self, SingleVmFingerprintGateError> {
        if entry.entry.class() != SchedulerEventLogClass::Causal
            || !entry.entry.has_valid_content_hash()
        {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump event must be a valid scheduler causal-projection entry",
            });
        }
        Ok(Self {
            scheduler_entry: entry.entry.clone(),
        })
    }

    /// Returns the zero-based sequence in the complete canonical event log.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.scheduler_entry.sequence()
    }

    /// Returns the event's retired-instruction coordinate.
    #[must_use]
    pub fn icount(&self) -> u64 {
        self.scheduler_entry.time().icount.icount.retired
    }

    /// Returns the canonical scheduler-entry content hash.
    #[must_use]
    pub fn scheduler_entry_content_hash(&self) -> [u8; 32] {
        self.scheduler_entry.content_hash().bytes
    }

    /// Returns the complete verified canonical scheduler entry.
    #[must_use]
    pub const fn scheduler_entry(&self) -> &SchedulerEventLogEntry {
        &self.scheduler_entry
    }
}

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
    canonical_event_total_count: u64,
    canonical_events: Vec<SingleVmFingerprintCanonicalEvent>,
}

impl SingleVmFingerprintRunStateDump {
    /// Builds one validated side of a divergence dump.
    ///
    /// # Errors
    ///
    /// Returns [`SingleVmFingerprintGateError`] when the node is empty, icount
    /// is zero, vCPU states are not exactly `0..N`, memory regions overlap or
    /// are out of order, the device VMState is empty, or `canonical_events` is
    /// not the exact final `min(canonical_event_total_count, 64)` suffix of
    /// verified scheduler-causal entries at or before `icount`.
    pub fn new(
        node: impl Into<String>,
        icount: u64,
        vcpu_registers: Vec<SingleVmFingerprintVcpuState>,
        differing_memory_regions: Vec<SingleVmFingerprintMemoryRegionState>,
        device_state: impl Into<Vec<u8>>,
        canonical_event_total_count: u64,
        canonical_events: Vec<SingleVmFingerprintCanonicalEvent>,
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
        let retained_count = u64::try_from(canonical_events.len()).map_err(|_error| {
            SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump retained event count does not fit u64",
            }
        })?;
        if retained_count
            != canonical_event_total_count.min(SINGLE_VM_FINGERPRINT_STATE_DUMP_EVENT_LIMIT)
        {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump must retain the configured last-N canonical event suffix",
            });
        }
        let expected_first = canonical_event_total_count
            .checked_sub(retained_count)
            .ok_or(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump cannot retain more events than the complete event log",
            })?;
        if canonical_events
            .iter()
            .enumerate()
            .any(|(index, event)| event.sequence() != expected_first + index as u64)
        {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump events must be the contiguous last-N canonical event suffix",
            });
        }
        if canonical_events.iter().any(|event| event.icount() > icount) {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "state dump canonical events must not follow the dump icount",
            });
        }
        Ok(Self {
            node,
            icount,
            vcpu_registers,
            differing_memory_regions,
            device_state,
            canonical_event_total_count,
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

    /// Returns the complete canonical event-log length before suffix retention.
    #[must_use]
    pub const fn canonical_event_total_count(&self) -> u64 {
        self.canonical_event_total_count
    }

    /// Returns the retained canonical events leading to the divergence.
    #[must_use]
    pub fn canonical_events(&self) -> &[SingleVmFingerprintCanonicalEvent] {
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
        if first.differing_memory_regions().len() != second.differing_memory_regions().len()
            || first
                .differing_memory_regions()
                .iter()
                .zip(second.differing_memory_regions())
                .any(|(first_region, second_region)| {
                    first_region.guest_physical_start() != second_region.guest_physical_start()
                        || first_region.bytes().len() != second_region.bytes().len()
                        || first_region.bytes() == second_region.bytes()
                })
        {
            return Err(SingleVmFingerprintGateError::InvalidBisectionReport {
                reason: "both state-dump sides must pair identical differing memory ranges",
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
    output.push_str(&format!(
        "{side}.node.len={}\n{side}.node.hex={}\n",
        state.node().len(),
        lower_hex(state.node().as_bytes())
    ));
    output.push_str(&format!("{side}.icount={}\n", state.icount()));
    output.push_str(&format!(
        "{side}.vcpu_register_count={}\n",
        state.vcpu_registers().len()
    ));
    for register in state.vcpu_registers() {
        output.push_str(&format!(
            "{side}.vcpu[{}].len={}\n{side}.vcpu[{}].hex={}\n",
            register.vcpu_id(),
            register.register_file().len(),
            register.vcpu_id(),
            lower_hex(register.register_file())
        ));
    }
    output.push_str(&format!(
        "{side}.memory_region_count={}\n",
        state.differing_memory_regions().len()
    ));
    for (index, region) in state.differing_memory_regions().iter().enumerate() {
        output.push_str(&format!(
            "{side}.memory[{index}].start={}\n{side}.memory[{index}].len={}\n{side}.memory[{index}].hex={}\n",
            region.guest_physical_start(),
            region.bytes().len(),
            lower_hex(region.bytes())
        ));
    }
    output.push_str(&format!(
        "{side}.device_state.len={}\n{side}.device_state.hex={}\n",
        state.device_state().len(),
        lower_hex(state.device_state())
    ));
    output.push_str(&format!(
        "{side}.canonical_event_total_count={}\n{side}.canonical_event_retained_count={}\n",
        state.canonical_event_total_count(),
        state.canonical_events().len()
    ));
    for (index, event) in state.canonical_events().iter().enumerate() {
        output.push_str(&format!(
            "{side}.event[{index}].sequence={}\n{side}.event[{index}].icount={}\n{side}.event[{index}].scheduler_entry_content_hash={}\n",
            event.sequence(),
            event.icount(),
            lower_hex(&event.scheduler_entry_content_hash())
        ));
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
