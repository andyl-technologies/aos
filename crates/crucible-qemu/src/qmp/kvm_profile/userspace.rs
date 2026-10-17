//! Bounded original KVM userspace exit observations without execution authority.
//!
//! Callback return and kernel response consumption are distinct. This independent
//! inventory preserves that distinction; neither a clear ledger nor paused CPUs
//! close device workers, DMA, external input or publication custody.

use serde::{Deserialize, Serialize};

use super::{QmpClient, QmpCommand, QmpCommandKind, QmpError, QmpTimeoutStream};

const MAXIMUM_VCPUS: u32 = 4096;

/// Identifies one original userspace callback or kernel response phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QmpKvmUserspaceExitPhase {
    /// Retains no outstanding kernel response obligation.
    Ready,
    /// Retains an original vCPU inside KVM_RUN.
    Running,
    /// Retains an original synchronous IO or MMIO callback that has not returned.
    Handling,
    /// Retains a returned callback whose kernel response has not been consumed.
    Pending,
    /// Retains uncertain completion after interrupted or failed kernel re-entry.
    Unknown,
    /// Retains an unsupported kernel response family with opaque handler effects.
    Unsupported,
}

/// Describes the original response inventory of one native vCPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmUserspaceExitRecord {
    /// Identifies the original QEMU CPU index in the fixed allocation.
    pub vcpu_index: u32,
    /// Identifies the original kernel vCPU assigned once before native creation.
    pub kernel_vcpu_id: u64,
    /// Identifies the last observed original kernel response obligation.
    pub exit_sequence: u64,
    /// Identifies the last response consumed by a successful later KVM_RUN.
    pub consumed_sequence: u64,
    /// Reports the exit reason of the last successful KVM_RUN.
    pub exit_reason: u32,
    /// Reports the current actual callback and response phase.
    pub phase: QmpKvmUserspaceExitPhase,
    /// Retains evidence that an unsupported exit handler has been encountered.
    pub opaque_effects: bool,
    /// Retains uncertain-effect history after any failed or interrupted re-entry.
    pub uncertain_effects: bool,
}

/// Reports a partial native process inventory that grants no node capability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct QmpKvmUserspaceInventory {
    /// Identifies this independent inventory schema, always one.
    pub schema_version: u32,
    /// Bounds the preallocated CPU roster to at most 4096 entries.
    pub capacity: u32,
    /// Reports the monotonic original native transition sequence.
    pub revision: u64,
    /// Reports original counter exhaustion or a refused native transition.
    pub faulted: bool,
    /// Lists actual seen vCPU records in strictly increasing CPU index order.
    pub exits: Vec<QmpKvmUserspaceExitRecord>,
    /// Remains false because asynchronous devices and DMA are not covered.
    pub device_closure: bool,
    /// Remains false because the original input cut is not authenticated here.
    pub input_custody: bool,
    /// Remains false because publication bytes are not retained by this component.
    pub output_custody: bool,
    /// Remains false because partial native inventory cannot qualify execution.
    pub profile_qualified: bool,
}

/// Retains a checked partial observation without native execution or stop authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QmpKvmUserspaceComponentState {
    observed: QmpKvmUserspaceInventory,
}

impl QmpKvmUserspaceComponentState {
    /// Borrows the bounded observation, including its explicit missing custody.
    pub fn observed(&self) -> &QmpKvmUserspaceInventory {
        &self.observed
    }

    /// Reports unresolved local callbacks, response obligations or opaque effects.
    ///
    /// A false result says only that this partial response ledger is clear. It
    /// does not establish whole-device closure, physical stop or publication
    /// authority; all corresponding inventory claims remain false.
    pub fn requires_retained_exit_custody(&self) -> bool {
        self.observed.faulted
            || self.observed.exits.iter().any(|record| {
                record.phase != QmpKvmUserspaceExitPhase::Ready
                    || record.opaque_effects
                    || record.uncertain_effects
            })
    }
}

impl<S: QmpTimeoutStream> QmpClient<S> {
    /// Queries original userspace response custody without clearing or running it.
    ///
    /// The caller independently authenticates the source-patched child and peer.
    /// The native component requires immutable pre-vCPU opt-in, a configured
    /// controller clock and actual acknowledged paused CPU threads. Existing
    /// clock component commands cannot substitute for this inventory.
    ///
    /// # Errors
    /// Reports bounded transport failures, actual native refusal, an unknown
    /// schema, unbounded or inconsistent response records, or any whole-device,
    /// input, output or profile qualification claim.
    pub fn query_native_kvm_userspace_exits(
        &mut self,
    ) -> Result<QmpKvmUserspaceComponentState, QmpError> {
        let response = self.send_command_return(QmpCommand::KvmUserspaceExits)?;
        parse_userspace_inventory(&response.value)
    }
}

fn parse_userspace_inventory(
    value: &serde_json::Value,
) -> Result<QmpKvmUserspaceComponentState, QmpError> {
    let malformed = || QmpError::MalformedTypedResponse {
        command: QmpCommandKind::KvmUserspaceExits,
        response: "native userspace exit inventory must be bounded, coherent and unqualified"
            .to_owned(),
    };
    let entries = value
        .get("exits")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(malformed)?;
    if entries.len() > MAXIMUM_VCPUS as usize {
        return Err(malformed());
    }

    let inventory: QmpKvmUserspaceInventory =
        serde_json::from_value(value.clone()).map_err(|_| malformed())?;
    if inventory.schema_version != 1
        || inventory.capacity == 0
        || inventory.capacity > MAXIMUM_VCPUS
        || inventory.exits.len() > inventory.capacity as usize
        || inventory.device_closure
        || inventory.input_custody
        || inventory.output_custody
        || inventory.profile_qualified
    {
        return Err(malformed());
    }

    let mut previous_index = None;
    let mut original_exit_count = 0_u64;
    let mut native_ids = std::collections::BTreeSet::new();
    for record in &inventory.exits {
        if record.vcpu_index >= inventory.capacity
            || previous_index.is_some_and(|index| index >= record.vcpu_index)
            || record.consumed_sequence > record.exit_sequence
            || !native_ids.insert(record.kernel_vcpu_id)
        {
            return Err(malformed());
        }
        let retained_count = record.exit_sequence - record.consumed_sequence;
        original_exit_count = original_exit_count
            .checked_add(record.exit_sequence)
            .ok_or_else(malformed)?;
        if retained_count > 1 || original_exit_count > inventory.revision {
            return Err(malformed());
        }
        let outstanding = record.consumed_sequence < record.exit_sequence;
        let coherent_phase = match record.phase {
            QmpKvmUserspaceExitPhase::Ready => !outstanding,
            QmpKvmUserspaceExitPhase::Running => true,
            QmpKvmUserspaceExitPhase::Unknown => record.uncertain_effects,
            QmpKvmUserspaceExitPhase::Handling | QmpKvmUserspaceExitPhase::Pending => {
                outstanding && matches!(record.exit_reason, 2 | 6)
            }
            QmpKvmUserspaceExitPhase::Unsupported => {
                outstanding
                    && record.opaque_effects
                    && matches!(record.exit_reason, 3 | 18 | 19 | 23 | 29 | 30 | 34 | 40)
            }
        };
        if !coherent_phase {
            return Err(malformed());
        }
        previous_index = Some(record.vcpu_index);
    }
    if inventory.revision == 0 && !inventory.exits.is_empty() {
        return Err(malformed());
    }
    Ok(QmpKvmUserspaceComponentState {
        observed: inventory,
    })
}

#[cfg(test)]
#[path = "userspace_tests.rs"]
mod tests;
