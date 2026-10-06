//! Immutable deployment evidence for the supported paused paging profile.
//!
//! The build embeds canonical JSON through `CRUCIBLE_PAGING_QUALIFICATION_JSON`.
//! Bootstrap builds embed no evidence. A receipt never authorizes a different
//! kernel, emulator, plugin, realized topology, launch profile, or child identity.
//! Guest kernel and application contents are deliberately absent from the match.

use std::io;
use std::sync::{Arc, Mutex};

use crucible_api::host_operational::{HostRamBackend, HostRamQualification};
use crucible_api::vm_lifecycle::ProductionVmLifecycleConfig;
use crucible_linux_resource::host_supervision::HostOperationSupervisor;
use crucible_linux_resource::ram_policy::{HostRamPolicy, HostRamTarget, HostResourceVector};
use crucible_protocol::ram_control::RamControlError;
use crucible_qemu::ram_control::{RamControlClient, RamControlRegistrar, RamInventoryAdmission};
use serde::Deserialize;

use crate::HostOperationalRegistry;

pub(crate) mod artifacts;

const MAX_RECEIPT_BYTES: usize = 16_384;
const REQUIRED_KERNEL_FEATURES: u64 = (1 << 0) | (1 << 8);

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    edition: u32,
    host_kernel_build_id: String,
    host_kernel_blake3: String,
    qemu_blake3: String,
    plugin_blake3: String,
    topology_blake3: String,
    build_graph_sha256: String,
    profile: Profile,
    operations: Operations,
    activity: Activity,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    machine: String,
    accelerator: String,
    thread_mode: String,
    architecture: String,
    guest_ram_bytes: u64,
    vcpu_count: u32,
    page_bytes: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operations {
    full_peak_paused_reclamation: bool,
    read_first_faults: bool,
    write_first_faults: bool,
    authenticated_spill: bool,
    logical_state_unchanged: bool,
    strict_low_peak: bool,
    hot_fork: bool,
    lazy_restore: bool,
    transfer: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Activity {
    successful_missing_installs: u64,
    successful_missing_read_installs: u64,
    successful_missing_write_installs: u64,
    write_protect_transitions: u64,
    preservation_reads: u64,
    preservation_writes: u64,
    physical_discards: u64,
}

struct ValidatedReceipt {
    receipt: Receipt,
    evidence: [u8; 32],
}

impl ValidatedReceipt {
    fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
            return Err(invalid("paging receipt exceeds its canonical bound"));
        }
        // Decode the fixed schema before constructing a generic JSON tree.
        // Unsupported arrays, keys and arbitrary nested values cannot allocate
        // a large intermediate tree from the bounded input envelope.
        let receipt: Receipt = serde_json::from_slice(bytes).map_err(invalid_source)?;
        receipt.validate()?;
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(invalid_source)?;
        if serde_json::to_vec(&value).map_err(invalid_source)? != bytes {
            return Err(invalid("paging receipt JSON is not canonical"));
        }
        Ok(Self {
            receipt,
            evidence: *blake3::hash(bytes).as_bytes(),
        })
    }

    fn matches_launch(
        &self,
        config: &ProductionVmLifecycleConfig,
        node: &crucible::WorldNode,
        boundary: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<bool> {
        let profile = &self.receipt.profile;
        if node.arch != crucible::VmArchitecture::X86_64
            || u64::from(node.memory_mib) * 1024 * 1024 != profile.guest_ram_bytes
            || u32::from(node.smp_vcpus) != profile.vcpu_count
        {
            return Ok(false);
        }
        boundary()?;
        if !artifacts::immutable_store_artifact(config.executable())?
            || !artifacts::immutable_store_artifact(config.plugin())?
        {
            return Ok(false);
        }
        // The production step gate fixes q35 and single-threaded sim; the
        // validated profile cannot select another accelerator or machine.
        let kernel = artifacts::kernel_build_id()?;
        if hex(&kernel) != self.receipt.host_kernel_build_id {
            return Ok(false);
        }
        Ok(
            artifacts::artifact_hash_with_boundary(config.executable(), boundary)?
                .to_hex()
                .as_str()
                == self.receipt.qemu_blake3
                && artifacts::artifact_hash_with_boundary(config.plugin(), boundary)?
                    .to_hex()
                    .as_str()
                    == self.receipt.plugin_blake3,
        )
    }

    fn qualification(&self) -> HostRamQualification {
        HostRamQualification {
            backend: HostRamBackend::PausedPager,
            authenticated_pages: true,
            // Execution retains the full RAM peak. This receipt does not prove
            // reclamation under a smaller peak or any successor operation.
            fault_safe_progress: false,
            bounded_execution_peak: false,
            hot_fork: false,
            lazy_restore: false,
            authenticated_transfer: false,
            evidence: Some(self.evidence),
        }
    }
}

impl Receipt {
    fn validate(&self) -> io::Result<()> {
        for digest in [
            &self.host_kernel_blake3,
            &self.qemu_blake3,
            &self.plugin_blake3,
            &self.topology_blake3,
            &self.build_graph_sha256,
        ] {
            if !canonical_hex(digest, 64) {
                return Err(invalid("paging receipt contains a noncanonical digest"));
            }
        }
        let build_id = &self.host_kernel_build_id;
        if self.edition != 1
            || !(32..=128).contains(&build_id.len())
            || !build_id.len().is_multiple_of(2)
            || !canonical_hex(build_id, build_id.len())
        {
            return Err(invalid(
                "paging receipt has an unsupported edition or kernel identity",
            ));
        }
        let profile = &self.profile;
        if profile.machine != "pc-q35-9.2"
            || profile.accelerator != "sim"
            || profile.thread_mode != "single"
            || profile.architecture != "x86_64"
            || profile.guest_ram_bytes != 64 * 1024 * 1024
            || profile.vcpu_count != 1
            || profile.page_bytes != 4096
        {
            return Err(invalid(
                "paging receipt describes an unsupported launch profile",
            ));
        }
        let operations = &self.operations;
        if !operations.full_peak_paused_reclamation
            || !operations.read_first_faults
            || !operations.write_first_faults
            || !operations.authenticated_spill
            || !operations.logical_state_unchanged
            || operations.strict_low_peak
            || operations.hot_fork
            || operations.lazy_restore
            || operations.transfer
        {
            return Err(invalid(
                "paging receipt exceeds the supported evidence scope",
            ));
        }
        let activity = &self.activity;
        if [
            activity.successful_missing_read_installs,
            activity.successful_missing_write_installs,
            activity.write_protect_transitions,
            activity.preservation_reads,
            activity.preservation_writes,
            activity.physical_discards,
        ]
        .contains(&0)
            || activity
                .successful_missing_read_installs
                .checked_add(activity.successful_missing_write_installs)
                .is_none_or(|classified| classified != activity.successful_missing_installs)
        {
            return Err(invalid(
                "paging receipt lacks consistent successful kernel activity",
            ));
        }
        Ok(())
    }
}

struct ScopedRegistrar {
    registry: HostOperationalRegistry,
    receipt: Option<ValidatedReceipt>,
    expected_credentials: (u32, u32),
    admitted: Mutex<Option<(HostRamTarget, bool)>>,
}

/// Binds immutable deployment evidence to one actual launch and inventory.
///
/// # Errors
/// Refuses malformed embedded evidence, artifact or kernel identity read
/// failures, and cancellation under the original launch supervision boundary.
pub(crate) fn scoped_registrar(
    registry: HostOperationalRegistry,
    lifecycle: &ProductionVmLifecycleConfig,
    node: &crucible::WorldNode,
    expected_credentials: Option<(u32, u32)>,
    boundary: &mut dyn FnMut() -> io::Result<()>,
) -> io::Result<Option<Arc<dyn RamControlRegistrar>>> {
    let Some(bytes) = option_env!("CRUCIBLE_PAGING_QUALIFICATION_JSON") else {
        return Ok(None);
    };
    let Some(expected_credentials) = expected_credentials else {
        return Ok(None);
    };
    let receipt = registry.with_paging_qualification_match(boundary, |boundary| {
        let receipt = ValidatedReceipt::decode(bytes.as_bytes())?;
        if receipt.matches_launch(lifecycle, node, boundary)? {
            Ok(Some(receipt))
        } else {
            Ok(None)
        }
    })?;
    if receipt.is_none() {
        return Ok(None);
    }
    Ok(Some(Arc::new(ScopedRegistrar {
        registry,
        receipt,
        expected_credentials,
        admitted: Mutex::new(None),
    })))
}

impl ScopedRegistrar {
    fn clear_unpublished_admission(&self, target: HostRamTarget) -> Result<(), RamControlError> {
        let mut admitted = self
            .admitted
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        if admitted.as_ref().is_some_and(|(owner, _)| *owner == target) {
            *admitted = None;
        }
        Ok(())
    }
}

impl RamControlRegistrar for ScopedRegistrar {
    fn retirement_authority(
        &self,
        target: HostRamTarget,
    ) -> Result<Arc<dyn crucible_qemu::ram_control::RamControlRetirementAuthority>, RamControlError>
    {
        self.registry.retirement_authority(target)
    }

    fn admit_inventory(
        &self,
        admission: RamInventoryAdmission<'_>,
    ) -> Result<HostResourceVector, RamControlError> {
        let resources = self.registry.admit_inventory(admission)?;
        let matches = self.receipt.as_ref().is_some_and(|receipt| {
            admission.topology.digest().to_string() == receipt.receipt.topology_blake3
        });
        let mut admitted = self
            .admitted
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?;
        if admitted.is_some() {
            return Err(RamControlError::AuthorityMismatch);
        }
        *admitted = Some((admission.target, matches));
        Ok(resources)
    }

    fn register(
        &self,
        target: HostRamTarget,
        policy: HostRamPolicy,
        resources: HostResourceVector,
        supervisor: HostOperationSupervisor,
        mut client: Option<RamControlClient>,
    ) -> Result<(), RamControlError> {
        let (admitted_target, matches) = self
            .admitted
            .lock()
            .map_err(|_| RamControlError::AuthorityMismatch)?
            .take()
            .ok_or(RamControlError::AuthorityMismatch)?;
        if admitted_target != target {
            return Err(RamControlError::AuthorityMismatch);
        }
        let qualification = if matches {
            let observation = client
                .as_mut()
                .ok_or(RamControlError::AuthorityMismatch)?
                .status()?;
            let probe = observation
                .kernel_probe
                .ok_or(RamControlError::AuthorityMismatch)?;
            if probe.effective_uid != self.expected_credentials.0
                || probe.effective_gid != self.expected_credentials.1
                || probe.mode
                    != crucible_protocol::ram_control::RamControlKernelProbeMode::FullKernel
                || probe.features & REQUIRED_KERNEL_FEATURES != REQUIRED_KERNEL_FEATURES
            {
                return Err(RamControlError::AuthorityMismatch);
            }
            self.receipt
                .as_ref()
                .ok_or(RamControlError::AuthorityMismatch)?
                .qualification()
        } else {
            HostRamQualification::default()
        };
        self.registry.register_with_qualification(
            target,
            policy,
            resources,
            supervisor,
            client,
            qualification,
        )
    }

    fn retire_after_cleanup(&self, target: HostRamTarget) -> Result<(), RamControlError> {
        self.registry.retire_after_cleanup(target)
    }

    fn prepare_retirement_after_cleanup(
        &self,
        target: HostRamTarget,
    ) -> Result<(), RamControlError> {
        self.registry.prepare_retirement_after_cleanup(target)
    }

    fn retire_unpublished_after_cleanup(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), RamControlError> {
        self.registry
            .retire_unpublished_after_cleanup(target, resources)?;
        self.clear_unpublished_admission(target)
    }

    fn quarantine_unpublished(
        &self,
        target: HostRamTarget,
        resources: HostResourceVector,
    ) -> Result<(), RamControlError> {
        self.registry.quarantine_unpublished(target, resources)?;
        self.clear_unpublished_admission(target)
    }
}

fn canonical_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_source(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests;
