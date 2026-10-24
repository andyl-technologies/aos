//! Encodes one issued incarnation subdivision for its once-owned native carrier.
//!
//! ```text
//! CRUCPUR8 | BE schema 8 | BE length 2520
//! 16..144: original/family/outside/lineage/effective-limit u64 fields
//! 144..184: final plugin SHA-256, ELF machine, seven allocation roles
//! 184..248: containing Preparation cap, operation, start, end, poll
//! 248..472: seven fixed role/reserved/size/alignment/count records
//! 472..496: local share, fixed maximum incarnations, subdivision index
//! 496..512: actual retained child cgroup device and inode
//! 512..552: actual retained parent device/inode, CPU quota/period, task limit
//! 552..568: child UID/GID assigned by this same configured contract
//! 568..744: actual paid RAM endpoint identity, session and complete target
//! 744..1000: fixed reservations retained by the same actual Main issuer
//! 1000..2520: retained standing publication file and initial observation
//!
//! The private prebirth allocation prefix occupies 568 bytes. Only sealing
//! after actual socketpair birth can emit the complete 2520-byte carrier.
//! ```
//!
//! Only a checked borrow from the retained slot can invoke the encoder. The
//! record describes that assignment; acceptance also requires the real single
//! inherited carrier and its retained issuer, not equality of these bytes.
// SPDX-License-Identifier: Apache-2.0

use super::{InstalledProcessPurposeError, IssuedInstalledProcessMaterial};

pub(crate) const ISSUED_PROCESS_RECORD_BYTES: usize =
    crucible_qemu_protocol::plugin_setup_plan::PROCESS_PURPOSE_BYTES;
const ISSUED_PROCESS_ALLOCATION_PREFIX_BYTES: usize = 568;

/// Keeps encoded issued material outside its transport aliases.
pub(crate) struct IssuedInstalledProcessRecord {
    bytes: [u8; ISSUED_PROCESS_ALLOCATION_PREFIX_BYTES],
    family: [u8; 256],
}

impl IssuedInstalledProcessMaterial<'_> {
    /// Encodes private prebirth allocation material without endpoint authority.
    ///
    /// # Errors
    /// Refuses overflow, overdrawn family/local shares or changed containment,
    /// credentials and original preparation geometry.
    pub(in crate::linux_attempt_host) fn encode_record(
        self,
    ) -> Result<IssuedInstalledProcessRecord, InstalledProcessPurposeError> {
        self.family.verify_incarnation(
            self.account_generation,
            &self.containing_original_basis,
            self.subdivision_index,
            self.effective_process_bytes,
            self.envelope,
        )?;

        let outside = self
            .assigned_host_metadata_bytes
            .checked_add(self.pending_cleanup_bytes)
            .and_then(|bytes| bytes.checked_add(self.pending_workspace_bytes))
            .and_then(|bytes| bytes.checked_add(self.pending_startup_bytes))
            .and_then(|bytes| bytes.checked_add(self.assigned_startup_bytes))
            .ok_or(InstalledProcessPurposeError::Capacity)?;
        let accepted = outside
            .checked_add(self.effective_process_bytes)
            .filter(|bytes| *bytes <= self.original_total_metadata_bytes);
        let (child_user, child_group) = self.envelope.child_credential_ids();
        let [parent_device, parent_inode, cpu_quota, cpu_period, tasks] = self.native_parent_fields;
        let local_sum = self
            .native_incarnation_bytes
            .checked_mul(u64::from(self.maximum_incarnations));
        if accepted.is_none()
            || local_sum.is_none_or(|bytes| bytes > self.effective_process_bytes)
            || self.current_guest_ram_bytes > self.native_incarnation_bytes
            || self.current_guest_ram_bytes > self.live_guest_ram_bytes
            || self.maximum_incarnations != super::super::MAX_ORIGINAL_NATIVE_NODE_GENERATIONS
            || self.subdivision_index >= self.maximum_incarnations
            || self.envelope.maximum_resident_bytes() == 0
            || self.envelope.maximum_resident_bytes() > self.native_incarnation_bytes
            || child_user == 0
            || child_group == 0
            || parent_inode == 0
            || cpu_quota == 0
            || cpu_period != 100_000
            || tasks == 0
            || u64::from(self.envelope.maximum_tasks()) > tasks
            || u64::from(self.envelope.maximum_vcpus()) * 100_000 > cpu_quota
            || (parent_device, parent_inode)
                == (
                    self.envelope.child_cgroup_device(),
                    self.envelope.child_cgroup_inode(),
                )
            || self.containing_original_basis[..16] != *b"CRUCPRP1\0\0\0\x01\0\0\0\x50"
        {
            return Err(InstalledProcessPurposeError::Identity);
        }

        let mut bytes = [0; ISSUED_PROCESS_ALLOCATION_PREFIX_BYTES];
        bytes[..8].copy_from_slice(b"CRUCPUR8");
        bytes[8..12].copy_from_slice(&8_u32.to_be_bytes());
        bytes[12..16].copy_from_slice(&2520_u32.to_be_bytes());
        for (offset, value) in [
            (16, self.original_total_metadata_bytes),
            (24, self.effective_process_bytes),
            (32, self.assigned_host_metadata_bytes),
            (40, self.pending_cleanup_bytes),
            (48, self.pending_workspace_bytes),
            (56, self.pending_startup_bytes),
            (64, self.assigned_startup_bytes),
            (72, self.current_guest_ram_bytes),
            (80, u64::from(self.live_incarnations)),
            (88, self.account_generation),
            (96, self.process_generation),
            (104, self.envelope.maximum_resident_bytes()),
            // This is the enforced per-file FSIZE ceiling, not project quota.
            (112, self.envelope.maximum_writable_bytes()),
            (120, u64::from(self.envelope.maximum_tasks())),
            (128, self.envelope.maximum_file_descriptors()),
            (136, u64::from(self.envelope.maximum_vcpus())),
            (472, self.native_incarnation_bytes),
            (480, u64::from(self.maximum_incarnations)),
            (488, u64::from(self.subdivision_index)),
            (496, self.envelope.child_cgroup_device()),
            (504, self.envelope.child_cgroup_inode()),
            (512, parent_device),
            (520, parent_inode),
            (528, cpu_quota),
            (536, cpu_period),
            (544, tasks),
            (552, u64::from(child_user)),
            (560, u64::from(child_group)),
        ] {
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        bytes[144..176].copy_from_slice(self.controls.plugin_sha256());
        bytes[176..180].copy_from_slice(&u32::from(self.controls.machine()).to_be_bytes());
        bytes[180..184].copy_from_slice(&8_u32.to_be_bytes());
        // Serialize the actual containing original without changing its class
        // or substituting the later, separately entered Setup operation.
        bytes[184..248].copy_from_slice(&self.containing_original_basis[16..80]);
        for (index, allocation) in self.controls.allocations().iter().enumerate() {
            let offset = 248 + index * 32;
            bytes[offset..offset + 4].copy_from_slice(&u32::from(allocation.role()).to_be_bytes());
            for (relative, value) in [
                (8, allocation.size()),
                (16, allocation.alignment()),
                (24, allocation.count()),
            ] {
                bytes[offset + relative..offset + relative + 8]
                    .copy_from_slice(&value.to_be_bytes());
            }
        }
        Ok(IssuedInstalledProcessRecord {
            bytes,
            family: self.family.encode_corroboration(),
        })
    }
}

impl IssuedInstalledProcessRecord {
    /// Emits the complete carrier only at the actual postbirth sealing boundary.
    pub(crate) fn with_ram_endpoint(
        &self,
        endpoint: Option<&crate::spawn::ram_endpoint_binding::IssuedRamControlEndpoint<'_>>,
        standing: &[u8; crate::spawn::source_supervision::SOURCE_CORROBORATION_BYTES],
    ) -> [u8; ISSUED_PROCESS_RECORD_BYTES] {
        let mut bytes = [0; ISSUED_PROCESS_RECORD_BYTES];
        bytes[..ISSUED_PROCESS_ALLOCATION_PREFIX_BYTES].copy_from_slice(&self.bytes);
        if let Some(endpoint) = endpoint {
            bytes[ISSUED_PROCESS_ALLOCATION_PREFIX_BYTES..744]
                .copy_from_slice(&endpoint.corroboration_bytes());
        }
        bytes[744..1000].copy_from_slice(&self.family);
        bytes[1000..].copy_from_slice(standing);
        bytes
    }
}
