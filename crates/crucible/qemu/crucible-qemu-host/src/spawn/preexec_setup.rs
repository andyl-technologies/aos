//! Retains one original-funded sealed plan and its pre-exec descriptor handover.
//!
//! The same slot reserves this complete outside-process peak before refining W.
//! The actual registered host account then pays the physical allocations before
//! encoding, sealing, or duplicating descriptors. Queued aliases retain the
//! launch cleanup owner until actual child and transport retirement.
//!
//! ```text
//! sealed plan: CRUCSUP9, schema 9, header 40, unchanged aggregate byte cap
//! nested purpose: CRUCPUR8, schema 8, 2520 bytes
//! frame: BEu32(121), tag 0x16, selected Setup6 and publisher binding
//! SCM roles: shared memory, wake event, sealed plan, standing publication,
//! standing cancellation, optional workspace, publisher region and two events
//! ```
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::{AsRawFd, BorrowedFd, IntoRawFd, OwnedFd};

use crucible_host_resources::host_services::process_birth::SourceHostControlLease;
use crucible_host_resources::host_supervision::{HostOperationSupervisor, HostSupervisionError};
use crucible_qemu_protocol::plugin_setup_plan::{
    PLUGIN_SETUP_PLAN_MAX_BYTES, PROCESS_PURPOSE_BYTES, PluginSetupPlan,
};

use super::{OriginalPluginStartup, QemuChildProcessContract};
use crate::linux_attempt_host::OriginalNativeNodeBinding;
use crate::ram_control::RamControlRegistration;

const FRAME_BYTES: usize = 125;
const PURPOSE_BYTES: usize = PROCESS_PURPOSE_BYTES;
const READBACK_BYTES: usize = 4096;

/// Lends the real issuer and registered Setup at their used spawn boundary.
pub(crate) struct BorrowedPreexecSetup<'a> {
    pub(crate) startup: &'a OriginalPluginStartup,
    pub(crate) binding: &'a OriginalNativeNodeBinding,
    pub(crate) supervisor: &'a HostOperationSupervisor,
    pub(crate) registration: Option<&'a RamControlRegistration>,
    pub(crate) region_config: crucible_qemu_shmem::RegionConfig,
}

/// Owns the actual local and queued descriptor history before its credit.
#[derive(Debug)]
pub(crate) struct PreparedPreexecSetup {
    aliases: [Option<OwnedFd>; 9],
    frame: [u8; FRAME_BYTES],
    queued: bool,
    receipt: Option<crucible_qemu_protocol::PreexecSetupHandover>,
    control: Option<SourceHostControlLease>,
    cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
}

/// Retains prepared physical owners with the first cause and independent postcut.
#[derive(Debug, thiserror::Error)]
#[error("pre-exec handover refused: {cause}; original: {original_after:?}")]
pub struct PreexecSetupError {
    #[source]
    cause: PreexecSetupCause,
    original_after: Option<HostSupervisionError>,
    _owner: PreparedPreexecSetup,
}

#[derive(Debug, thiserror::Error)]
enum PreexecSetupCause {
    #[error("original Setup refused: {0}")]
    Original(#[source] HostSupervisionError),
    #[error("retained startup refused: {0}")]
    Startup(#[source] super::PluginStartupError),
    #[error("issued process material refused: {0}")]
    Purpose(#[source] super::source_supervision::SourceEmissionError),
    #[error("canonical shared region layout refused: {0}")]
    RegionLayout(#[source] crucible_qemu_shmem::RegionLayoutError),
    #[error("canonical shared region serialization refused: {0}")]
    RegionSerialization(#[source] crucible_qemu_shmem::RegionSerializationError),
    #[error("canonical setup plan refused: {0}")]
    Plan(#[source] crucible_qemu_protocol::plugin_setup_plan::PluginSetupPlanError),
    #[error("pre-exec descriptor operation failed: {0}")]
    Kernel(#[source] rustix::io::Errno),
    #[error("pre-exec descriptor handover failed: {0}")]
    Handover(#[source] crucible_qemu_protocol::DescriptorHandoverError),
    #[error("pre-exec plan or descriptor geometry differs")]
    Geometry,
    #[error("the allocation-purpose workspace handover is unavailable")]
    WorkspaceUnavailable,
    #[error("the actual publisher session refused: {0}")]
    Publisher(#[source] super::source_supervision::PublisherSessionError),
}

impl PreparedPreexecSetup {
    /// Reports the complete encoder, sealed backing, fixed body and scratch peak.
    ///
    /// The bounded typed region model and its byte image coexist with the
    /// nested plans and canonical issued encoding. The nested encodings and
    /// model then retire before output overlaps sealed backing. Four existing
    /// aggregate-cap terms conservatively cover these overlapping bodies; the
    /// nominal endpoint borrower and fixed suffix coexist with the issued
    /// record and stay inside this same original's prepaid extent. Directed-ring
    /// storage and fixed owner/scratch layouts are included separately.
    pub(crate) fn host_allocation_extent() -> Option<u64> {
        let dynamic = PLUGIN_SETUP_PLAN_MAX_BYTES.checked_mul(4)?;
        let fixed = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<PreexecSetupError>())?
            .checked_add(PURPOSE_BYTES)?
            .checked_add(std::mem::size_of::<
                super::ram_endpoint_binding::IssuedRamControlEndpoint<'_>,
            >())?
            .checked_add(super::ram_endpoint_binding::RAM_ENDPOINT_CORROBORATION_BYTES)?
            .checked_add(READBACK_BYTES)?
            .checked_add(std::mem::size_of::<crucible_qemu_shmem::RegionAllocation>())?
            .checked_add(
                std::mem::size_of::<crucible_qemu_shmem::DirectedRing>().checked_mul(
                    crucible_qemu_shmem::ReservedExecutorSlot::all()
                        .len()
                        .checked_mul(2)?,
                )?,
            )?;
        u64::try_from(dynamic.checked_add(fixed)?)
            .ok()?
            .checked_add(std::mem::size_of::<SourceHostControlLease>() as u64)
    }

    /// Counts nine local aliases and their independently retained queue copies.
    pub(crate) const fn descriptor_peak() -> u64 {
        18
    }

    /// Admits one physical owner before socket, endpoint borrower, or plan birth.
    ///
    /// The same reservation survives preparation and queue refusals. Its cleanup
    /// owner cannot discharge a queued or ambiguous child by dropping this value.
    ///
    /// # Errors
    /// Refuses the same original's live cut, unrepresentable fixed extent, or
    /// reservation admission while preserving the independently observed postcut.
    pub(super) fn reserve(
        startup: &OriginalPluginStartup,
        cleanup: crate::launch_cleanup::LaunchCleanup,
    ) -> Result<Self, PreexecSetupError> {
        let mut owner = Self {
            aliases: std::array::from_fn(|_| None),
            frame: [0; FRAME_BYTES],
            queued: false,
            receipt: None,
            control: None,
            cleanup: Some(cleanup),
        };
        let reserved = (|| {
            startup.check().map_err(PreexecSetupCause::Original)?;
            let extent = Self::host_allocation_extent().ok_or(PreexecSetupCause::Geometry)?;
            owner.control = Some(
                startup
                    .reserve_preexec(Self::descriptor_peak(), extent)
                    .map_err(PreexecSetupCause::Startup)?,
            );
            Ok(())
        })();
        owner.finish(startup, reserved)
    }

    /// Completes the already reserved owner's sealed plan after socket birth.
    ///
    /// The endpoint borrower and queued aliases stay under the original debit
    /// acquired by `reserve`; completing the carrier creates no second account.
    ///
    /// # Errors
    /// Refuses reused custody, changed original or issued binding, unsupported
    /// layout, encoding, or kernel operations. The same paid owner survives every
    /// failure with its initiating cause and independent original postcut.
    pub(super) fn prepare(
        mut self,
        startup: &OriginalPluginStartup,
        binding: &OriginalNativeNodeBinding,
        contract: &QemuChildProcessContract,
        supervisor: &HostOperationSupervisor,
        registration: Option<&RamControlRegistration>,
        ram_endpoint: Option<&super::ram_endpoint_binding::IssuedRamControlEndpoint<'_>>,
        plan: &PluginSetupPlan,
        region_len: u64,
        region_config: crucible_qemu_shmem::RegionConfig,
        shmem: &OwnedFd,
        wake: &OwnedFd,
    ) -> Result<Self, PreexecSetupError> {
        let prepared = (|| {
            startup.check().map_err(PreexecSetupCause::Original)?;
            if self.control.is_none() || self.queued || self.aliases.iter().any(Option::is_some) {
                return Err(PreexecSetupCause::Geometry);
            }
            let startup_record = startup.record().map_err(PreexecSetupCause::Startup)?;
            if plan.startup_operation() != Some(&startup_record)
                || region_len == 0
                || region_len > PLUGIN_SETUP_PLAN_MAX_BYTES as u64
                || region_config.vm_node_count != 1
            {
                return Err(PreexecSetupCause::Geometry);
            }
            let workspace = startup
                .workspace_view()
                .map_err(PreexecSetupCause::Startup)?;
            let workspace_record = workspace
                .as_ref()
                .map(|body| {
                    body.record()
                        .map(|record| record.encode())
                        .map_err(|_| PreexecSetupCause::WorkspaceUnavailable)
                })
                .transpose()?;
            let backing = rustix::fs::fstat(shmem).map_err(PreexecSetupCause::Kernel)?;
            if backing.st_size < 0
                || u64::try_from(backing.st_size).ok() != Some(region_len)
                || rustix::fs::FileType::from_raw_mode(backing.st_mode)
                    != rustix::fs::FileType::RegularFile
            {
                return Err(PreexecSetupCause::Geometry);
            }
            let allocation = crucible_qemu_shmem::RegionAllocation::new(region_config)
                .map_err(PreexecSetupCause::RegionLayout)?;
            if allocation.layout().region_size != region_len {
                return Err(PreexecSetupCause::Geometry);
            }
            let region_image = allocation
                .setup_region_bytes()
                .map_err(PreexecSetupCause::RegionSerialization)?;
            // The region is initialized under this same owner's first-cause and
            // final original cut before the receiver can acquire any alias.
            let mut written = 0;
            while written < region_image.len() {
                startup.check().map_err(PreexecSetupCause::Original)?;
                let count = rustix::io::pwrite(shmem, &region_image[written..], written as u64)
                    .map_err(PreexecSetupCause::Kernel)?;
                if count == 0 {
                    return Err(PreexecSetupCause::Geometry);
                }
                written += count;
            }
            startup.check().map_err(PreexecSetupCause::Original)?;

            let record = binding
                .with_issued_process_record(
                    contract,
                    supervisor,
                    registration,
                    startup.admission().map_err(PreexecSetupCause::Startup)?,
                    startup.standing().map_err(PreexecSetupCause::Startup)?,
                    startup_record.fields().process_generation,
                    region_len,
                    ram_endpoint,
                    |record| *record,
                )
                .map_err(PreexecSetupCause::Purpose)?;
            let standing = startup.standing().map_err(PreexecSetupCause::Startup)?;
            let publisher = standing
                .prepare_publisher_session(
                    startup,
                    self.cleanup
                        .as_ref()
                        .ok_or(PreexecSetupCause::Geometry)?
                        .clone(),
                    0,
                    region_config.vm_node_count,
                    &mut self.aliases[6..],
                )
                .map_err(PreexecSetupCause::Publisher)?;
            let encoded = plan
                .encode_preexec_publisher(&record, workspace_record.as_ref(), &publisher)
                .map_err(PreexecSetupCause::Plan)?;
            startup.check().map_err(PreexecSetupCause::Original)?;
            self.aliases[2] = Some(
                rustix::fs::memfd_create(
                    c"crucible-issued-preexec-plan",
                    rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
                )
                .map_err(PreexecSetupCause::Kernel)?,
            );
            let descriptor = self.aliases[2]
                .as_ref()
                .ok_or(PreexecSetupCause::Geometry)?;
            startup.check().map_err(PreexecSetupCause::Original)?;
            rustix::fs::ftruncate(descriptor, encoded.len() as u64)
                .map_err(PreexecSetupCause::Kernel)?;
            let mut offset = 0;
            while offset < encoded.len() {
                startup.check().map_err(PreexecSetupCause::Original)?;
                let written = rustix::io::pwrite(descriptor, &encoded[offset..], offset as u64)
                    .map_err(PreexecSetupCause::Kernel)?;
                if written == 0 {
                    return Err(PreexecSetupCause::Geometry);
                }
                offset += written;
            }
            startup.check().map_err(PreexecSetupCause::Original)?;
            let seals = rustix::fs::SealFlags::SHRINK
                | rustix::fs::SealFlags::GROW
                | rustix::fs::SealFlags::WRITE
                | rustix::fs::SealFlags::SEAL;
            rustix::fs::fcntl_add_seals(descriptor, seals).map_err(PreexecSetupCause::Kernel)?;
            if !rustix::fs::fcntl_get_seals(descriptor)
                .map_err(PreexecSetupCause::Kernel)?
                .contains(seals)
            {
                return Err(PreexecSetupCause::Geometry);
            }
            let mut readback = [0; READBACK_BYTES];
            let mut offset = 0;
            while offset < encoded.len() {
                startup.check().map_err(PreexecSetupCause::Original)?;
                let length = readback.len().min(encoded.len() - offset);
                let read = rustix::io::pread(descriptor, &mut readback[..length], offset as u64)
                    .map_err(PreexecSetupCause::Kernel)?;
                if read == 0 || readback[..read] != encoded[offset..offset + read] {
                    return Err(PreexecSetupCause::Geometry);
                }
                offset += read;
            }
            startup.check().map_err(PreexecSetupCause::Original)?;
            if rustix::io::pread(descriptor, &mut readback[..1], encoded.len() as u64)
                .map_err(PreexecSetupCause::Kernel)?
                != 0
            {
                return Err(PreexecSetupCause::Geometry);
            }
            for (index, descriptor) in [(0, shmem), (1, wake)] {
                startup.check().map_err(PreexecSetupCause::Original)?;
                self.aliases[index] = Some(
                    rustix::io::fcntl_dupfd_cloexec(descriptor, super::CHILD_SOURCE_FD_MIN)
                        .map_err(PreexecSetupCause::Kernel)?,
                );
            }
            let standing = startup.standing().map_err(PreexecSetupCause::Startup)?;
            retain_standing_aliases(
                &mut self.aliases,
                [standing.publication_role(), standing.cancellation_role()],
                |role| {
                    startup.check().map_err(PreexecSetupCause::Original)?;
                    rustix::io::fcntl_dupfd_cloexec(role, super::CHILD_SOURCE_FD_MIN)
                        .map_err(PreexecSetupCause::Kernel)
                },
            )?;
            if let Some(workspace) = workspace.as_ref() {
                startup.check().map_err(PreexecSetupCause::Original)?;
                self.aliases[5] = Some(
                    workspace
                        .duplicate_for_preexec()
                        .map_err(|_| PreexecSetupCause::WorkspaceUnavailable)?,
                );
            }
            self.frame = crucible_qemu_protocol::publisher_subscription::PublisherSetup {
                region_len,
                process_generation: startup_record.fields().process_generation,
                device_digest_workspace: workspace
                    .as_ref()
                    .map(|workspace| workspace.descriptor())
                    .transpose()
                    .map_err(|_| PreexecSetupCause::WorkspaceUnavailable)?
                    .map(|descriptor| descriptor.binding),
                lender_generation: publisher.lender_generation,
                device: publisher.device,
                inode: publisher.inode,
                producer_event: publisher.producer_event,
                receiver_event: publisher.receiver_event,
            }
            .encode()
            .map_err(|_| PreexecSetupCause::Geometry)?;
            Ok(())
        })();
        self.finish(startup, prepared)
    }

    /// Queues this owner's one frame before exec; a short send never retries it.
    pub(super) fn queue(
        mut self,
        socket: &OwnedFd,
        startup: &OriginalPluginStartup,
    ) -> Result<Self, PreexecSetupError> {
        let result = (|| {
            startup.check().map_err(PreexecSetupCause::Original)?;
            if self.queued {
                return Err(PreexecSetupCause::Geometry);
            }
            // A failing or partial syscall may still retain queue aliases.
            self.queued = true;
            let mut descriptors = [-1; 9];
            let mut count = 0;
            for alias in self.aliases.iter().flatten() {
                descriptors[count] = alias.as_raw_fd();
                count += 1;
            }
            let receipt = crucible_qemu_protocol::publisher_subscription::send_publisher_setup_frame_with_descriptors(
                socket.as_raw_fd(),
                &self.frame,
                &descriptors[..count],
            )
            .map_err(PreexecSetupCause::Handover)?;
            self.receipt = Some(receipt);
            Ok(())
        })();
        self.finish(startup, result)
    }

    /// Moves the actual completed-write fact to the ACK-only host continuation.
    pub(super) fn take_receipt(&mut self) -> Option<crucible_qemu_protocol::PreexecSetupHandover> {
        self.receipt.take()
    }

    fn finish(
        self,
        startup: &OriginalPluginStartup,
        result: Result<(), PreexecSetupCause>,
    ) -> Result<Self, PreexecSetupError> {
        let after = startup.check().err();
        match (result, after) {
            (Ok(()), None) => Ok(self),
            (Err(cause), original_after) => Err(PreexecSetupError {
                cause,
                original_after,
                _owner: self,
            }),
            (Ok(()), Some(source)) => Err(PreexecSetupError {
                cause: PreexecSetupCause::Original(source),
                original_after: None,
                _owner: self,
            }),
        }
    }
}

/// Records each physical alias before checking or duplicating the next role.
fn retain_standing_aliases(
    aliases: &mut [Option<OwnedFd>; 9],
    roles: [BorrowedFd<'_>; 2],
    mut duplicate: impl FnMut(BorrowedFd<'_>) -> Result<OwnedFd, PreexecSetupCause>,
) -> Result<(), PreexecSetupCause> {
    if aliases[3].is_some() || aliases[4].is_some() {
        return Err(PreexecSetupCause::Geometry);
    }

    // A later refusal leaves every earlier alias in the paid cleanup journal.
    for (index, role) in [(3, roles[0]), (4, roles[1])] {
        aliases[index] = Some(duplicate(role)?);
    }
    Ok(())
}

impl Drop for PreparedPreexecSetup {
    fn drop(&mut self) {
        let mut uncertain = false;
        for alias in &mut self.aliases {
            if let Some(alias) = alias.take() {
                uncertain |= super::close_child_source_fd(alias.into_raw_fd()).is_err();
            }
        }
        // Closing a local alias cannot certify that a queued receiver or live
        // child stopped using it. Keep the actual loan on unknown retirement.
        uncertain |= self.queued
            && self
                .cleanup
                .as_ref()
                .is_none_or(|cleanup| !cleanup.cleanup_proven());
        if uncertain {
            if let Some(control) = self.control.take() {
                std::mem::forget(control);
            }
            if let Some(cleanup) = self.cleanup.take() {
                std::mem::forget(cleanup);
            }
        }
        // A successful queue remains charged through the actual cleanup clone,
        // whose final drop is later than receiver closure and verified reap.
    }
}

#[cfg(test)]
mod tests;
