//! Retains the exact Transfer names beside the active local Ownership journal.
//!
//! A namespace observation is not a default-off or Ownership-service proof.
//! The genuine Runtime original and independent active Ownership profile must
//! still join it before any six-owner acceptance or Root terminal disposition.
//! Every actual directory, original error and owed post remains on this flight.

mod ownership;
mod bootstrap_trust;
pub(super) use ownership::{RootOwnershipProfileOriginalV1, OwnershipProfileClosedV1};

use std::error::Error;
use std::fs::File;
use std::os::fd::AsFd as _;
use std::path::Path;

use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_journal::protected_storage::resolve_protected_directory_from_root_original;
use aos_sandbox_linux::inventory::MountId;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, ResolveFlags, Stat, fstat, openat2, statat};

use super::{
    RootDeleteChallengeOriginalsV1, RootDeleteControllerCurrentOriginalV1, RootDeleteErrorV1,
    RootDeleteFloorOriginalV1, RootDeleteSourceCurrentOriginalV1,
};
use crate::controller_resource_reservation::{ResourceReservationErrorV1, RootDeleteChunkPostsV1};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::journal::JournalError;
use crate::normal_root::{NormalRootStartupErrorV1, RootPolicyAcceptedFlightV1};
use crate::policy_compiler::RetainedKernelPairedClockAttemptV1;

const DIRECTORY: &str = "/var/lib/aos/sandbox/multi-node";
const LOCAL_NAMES: [&str; 3] = [
    "coordinator-ownership-bootstrap-v1.bin",
    "coordinator-ownership-v1.journal",
    "coordinator-ownership-v1.journal.lock",
];
// These are the sole fixed Source/Bootstrap/Artifact Journal recipes and their
// canonical lock and replacement names. Local Ownership uses different names.
const TRANSFER_NAMES: [&str; 9] = [
    "multi-node-authority-bootstrap-v1.journal",
    "multi-node-authority-bootstrap-v1.journal.lock",
    "multi-node-authority-bootstrap-v1.journal.compact.tmp",
    "multi-node-authority-v1.journal",
    "multi-node-authority-v1.journal.lock",
    "multi-node-authority-v1.journal.compact.tmp",
    "multi-node-artifacts-v1.journal",
    "multi-node-artifacts-v1.journal.lock",
    "multi-node-artifacts-v1.journal.compact.tmp",
];
const DIRECTORY_DESCRIPTORS: usize = 6; // /, var, lib, aos, sandbox, multi-node.

#[derive(Default)]
struct DirectoryOriginalV1 {
    ancestors: Vec<File>,
    directory: Option<Result<File, JournalError>>,
    native_error: Option<rustix::io::Errno>,
}

impl DirectoryOriginalV1 {
    fn acquire_once(&mut self) {
        if self.directory.is_some() {
            return;
        }
        self.directory = Some(
            resolve_protected_directory_from_root_original::<JournalError>(
                Path::new(DIRECTORY),
                0,
                Some(&mut self.ancestors),
                Some(&mut self.native_error),
            ),
        );
    }

    fn file(&self) -> Option<&File> {
        self.directory.as_ref()?.as_ref().ok()
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native_error
            .as_ref()
            .map(|cause| cause as _)
            .or_else(|| cause(&self.directory))
    }
}

#[derive(Default)]
struct NamespaceSampleV1 {
    directory: Option<rustix::io::Result<Stat>>,
    mount: Option<Result<MountId, aos_sandbox_linux::Error>>,
    local: [Option<rustix::io::Result<Stat>>; LOCAL_NAMES.len()],
    transfer: [Option<rustix::io::Result<Stat>>; TRANSFER_NAMES.len()],
    comparison: Option<Result<(), JournalError>>,
}

impl NamespaceSampleV1 {
    fn observe_once(&mut self, directory: &File) {
        if self.directory.is_some() {
            return;
        }
        self.directory = Some(fstat(directory));
        self.mount = Some(MountId::from_fd(directory.as_fd()));
        // These independent exact names are sampled even if an earlier native
        // result failed. A symlink or any present object is not absence.
        for (slot, name) in self.local.iter_mut().zip(LOCAL_NAMES) {
            *slot = Some(statat(directory, name, AtFlags::SYMLINK_NOFOLLOW));
        }
        for (slot, name) in self.transfer.iter_mut().zip(TRANSFER_NAMES) {
            *slot = Some(statat(directory, name, AtFlags::SYMLINK_NOFOLLOW));
        }
        self.comparison = Some((|| {
            let stat = positive(&self.directory)?;
            if stat.st_uid != 0
                || FileType::from_raw_mode(stat.st_mode) != FileType::Directory
                || Mode::from_raw_mode(stat.st_mode) != Mode::RWXU
                || stat.st_dev == 0
                || stat.st_ino == 0
            {
                return Err(JournalError::ProtectedBoundary);
            }
            positive(&self.mount)?;
            for stat in &self.local {
                require_local(positive(stat)?, 0)?;
            }
            for stat in &self.transfer {
                require_absent(stat)?;
            }
            Ok(())
        })());
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.directory)
            .or_else(|| cause(&self.mount))
            .or_else(|| self.local.iter().find_map(cause))
            .or_else(|| {
                self.transfer.iter().find_map(|slot| match slot {
                    Some(Err(error)) if *error != rustix::io::Errno::NOENT => Some(error as _),
                    _ => None,
                })
            })
            .or_else(|| cause(&self.comparison))
    }
}

#[derive(Default)]
pub(super) struct TransferNamespaceNativeOriginalV1 {
    before_directory: DirectoryOriginalV1,
    after_directory: DirectoryOriginalV1,
    before: NamespaceSampleV1,
    after: NamespaceSampleV1,
    local_files: [Option<Result<File, rustix::io::Errno>>; LOCAL_NAMES.len()],
    local_metadata: [Option<rustix::io::Result<Stat>>; LOCAL_NAMES.len()],
    local_binding: Option<Result<(), JournalError>>,
    final_binding: Option<Result<(), JournalError>>,
    after_entered: bool,
    bootstrap_trust: bootstrap_trust::BootstrapTrustOriginalV2,
    bootstrap_name_binding: Option<Result<(), JournalError>>,
}

impl TransferNamespaceNativeOriginalV1 {
    pub(super) fn fixed_demand_v1() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let path_peak = aos_sandbox_linux::credential::FixedRoleCredentialReadV1::
            joined_path_receiving_bytes_for_lengths_v1(DIRECTORY.len(),
                TRANSFER_NAMES.iter().chain(LOCAL_NAMES.iter()).map(|name| name.len()).max().ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        let memory = std::mem::size_of::<Self>().checked_mul(3)
            .and_then(|bytes| bytes.checked_add(2 * (DIRECTORY_DESCRIPTORS + 1) * std::mem::size_of::<File>()))
            .and_then(|bytes| bytes.checked_add(path_peak))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
        Ok(ResourceVector::ZERO.with(D::MemoryBytes, memory)
            .with(D::OpenFiles, u64::try_from(2 * DIRECTORY_DESCRIPTORS + LOCAL_NAMES.len()).map_err(|_| invalid())?)
            .with(D::MetadataEntries, u64::try_from(2 * DIRECTORY_DESCRIPTORS + LOCAL_NAMES.len() + TRANSFER_NAMES.len()).map_err(|_| invalid())?))
    }

    pub(super) fn bootstrap_trust_demand_v2(&self) -> Result<ResourceVector, JournalError> {
        positive(&self.local_binding)?;
        bootstrap_trust::BootstrapTrustOriginalV2::demand_v2(positive(&self.local_metadata[0])?)
    }

    pub(super) fn read_bootstrap_trust_once_v2(&mut self) -> Result<(), JournalError> {
        positive(&self.local_binding)?;
        let file = positive(&self.local_files[0])?;
        let metadata = positive(&self.local_metadata[0])?;
        self.bootstrap_trust.read_once_v2(file, metadata)
    }

    pub(super) fn finish_bootstrap_trust_if_owed_v2(&mut self) -> Result<(), JournalError> {
        let Some(Ok(file)) = &self.local_files[0] else { return Ok(()); };
        let Some(Ok(metadata)) = &self.local_metadata[0] else { return Ok(()); };
        self.bootstrap_trust.finish_if_owed_v2(file, metadata)
    }

    pub(super) fn bootstrap_trust_data_v2(&self) -> Result<
        aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningTrustDataV2,
        JournalError,
    > {
        positive(&self.final_binding)?;
        positive(&self.bootstrap_name_binding)?;
        self.bootstrap_trust.public_v2()
    }

    pub(super) fn bootstrap_trust_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.bootstrap_trust.failure()
    }

    pub(super) fn begin_once(&mut self) -> Result<(), JournalError> {
        self.before_directory.acquire_once();
        let directory = self
            .before_directory
            .file()
            .ok_or(JournalError::ProtectedBoundary)?;
        self.before.observe_once(directory);
        positive(&self.before.comparison)?;
        for (index, name) in LOCAL_NAMES.into_iter().enumerate() {
            self.local_files[index] = Some(
                openat2(
                    directory,
                    name,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
                )
                .map(File::from),
            );
            if let Some(Ok(file)) = &self.local_files[index] {
                self.local_metadata[index] = Some(fstat(file));
            }
        }
        self.local_binding = Some((|| {
            for index in 0..LOCAL_NAMES.len() {
                let metadata = positive(&self.local_metadata[index])?;
                require_local(metadata, 0)?;
                let named = positive(&self.before.local[index])?;
                if physical(metadata) != physical(named) {
                    return Err(JournalError::ProtectedBoundary);
                }
            }
            Ok(())
        })());
        positive(&self.local_binding).map(|_| ())
    }

    pub(super) fn finish_once(&mut self) -> Result<(), JournalError> {
        if self.after_entered {
            return Err(JournalError::ProtectedBoundary);
        }
        self.after_entered = true;
        // A fresh rooted traversal catches namespace replacement. The original
        // traversal and local file descriptors remain resident throughout.
        self.after_directory.acquire_once();
        if let Some(directory) = self.after_directory.file() {
            self.after.observe_once(directory);
        }
        self.final_binding = Some((|| {
            positive(&self.before.comparison)?;
            positive(&self.local_binding)?;
            positive(&self.after.comparison)?;
            if physical(positive(&self.before.directory)?)
                != physical(positive(&self.after.directory)?)
                || positive(&self.before.mount)? != positive(&self.after.mount)?
            {
                return Err(JournalError::ProtectedBoundary);
            }
            for index in 0..LOCAL_NAMES.len() {
                // The active local journal may append. Only its same original
                // inode/owner/mode/link identity is compared here, never a false
                // claim that Ownership's contents or service are inactive.
                if physical(positive(&self.local_metadata[index])?)
                    != physical(positive(&self.after.local[index])?)
                {
                    return Err(JournalError::ProtectedBoundary);
                }
            }
            Ok(())
        })());
        if self.bootstrap_trust.entered_v2() {
            self.bootstrap_name_binding = Some((|| {
                let held = positive(&self.local_metadata[0])?;
                if !bootstrap_trust::same_bootstrap_stat(held, positive(&self.before.local[0])?)
                    || !bootstrap_trust::same_bootstrap_stat(held, positive(&self.after.local[0])?) {
                    return Err(JournalError::ProtectedBoundary);
                }
                Ok(())
            })());
            positive(&self.bootstrap_name_binding)?;
        }
        positive(&self.final_binding).map(|_| ())
    }

    // This borrows only completed native originals; no fields or caller DATA
    // can install a completed namespace or create an authorized Root purpose.
    pub(super) fn planning_data_v1(&self) -> Result<
        aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningNamespaceDataV1,
        JournalError,
    > {
        use aos_sandbox_protocol::domain_ledger::delete_root::planning::{
            DeleteRootPlanningDirectoryDataV1, DeleteRootPlanningNamespaceDataV1,
        };
        positive(&self.final_binding)?;
        if !self.after_entered { return Err(JournalError::ProtectedBoundary); }
        let directories = [
            DeleteRootPlanningDirectoryDataV1 {
                file: planning_file_data(positive(&self.before.directory)?)?,
                mount: positive(&self.before.mount)?.get(),
            },
            DeleteRootPlanningDirectoryDataV1 {
                file: planning_file_data(positive(&self.after.directory)?)?,
                mount: positive(&self.after.mount)?.get(),
            },
        ];
        let named = |slots: &[Option<rustix::io::Result<Stat>>; 3]| -> Result<_, JournalError> {
            Ok([planning_file_data(positive(&slots[0])?)?,
                planning_file_data(positive(&slots[1])?)?,
                planning_file_data(positive(&slots[2])?)?])
        };
        let data = DeleteRootPlanningNamespaceDataV1 { directories,
            local: [named(&self.before.local)?, named(&self.local_metadata)?, named(&self.after.local)?] };
        data.commitment_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        Ok(data)
    }

    pub(super) fn before_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.before_directory
            .failure()
            .or_else(|| self.before.failure())
            .or_else(|| self.local_files.iter().find_map(cause))
            .or_else(|| self.local_metadata.iter().find_map(cause))
            .or_else(|| cause(&self.local_binding))
    }

    pub(super) fn after_failure(&self) -> Option<&(dyn Error + 'static)> {
        self.after_directory
            .failure()
            .or_else(|| self.after.failure())
            .or_else(|| cause(&self.final_binding))
            .or_else(|| cause(&self.bootstrap_name_binding))
    }
}

#[derive(Clone, Copy)]
enum First {
    Permit,
    BootstrapDemand,
    BootstrapPermit,
    BootstrapRead,
    BootstrapPost,
    Arm,
    ClockBefore,
    Before,
    OwnershipInputs,
    OwnershipBefore,
    OwnershipAfter,
    NamespaceBefore,
    NamespaceAfter,
    After,
    ClockAfter,
    Reentry,
}

/// Holds native namespace evidence only, without a six-owner or default-off grant.
#[derive(Default)]
pub(crate) struct RootDeleteTransferNamespaceOriginalV1 {
    final_read: bool,
    permit: Option<Result<(), ResourceReservationErrorV1>>,
    bootstrap_demand: Option<Result<ResourceVector, JournalError>>,
    bootstrap_permit: Option<Result<(), ResourceReservationErrorV1>>,
    bootstrap_read: Option<Result<(), JournalError>>,
    bootstrap_post: Option<Result<(), JournalError>>,
    posts: RootDeleteChunkPostsV1,
    arm: Option<Result<(), NormalRootStartupErrorV1>>,
    before: Option<Result<(), NormalRootStartupErrorV1>>,
    after: Option<Result<(), NormalRootStartupErrorV1>>,
    before_original: RetainedKernelPairedClockAttemptV1,
    before_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    before_binding: Option<Result<(), JournalError>>,
    after_original: RetainedKernelPairedClockAttemptV1,
    after_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    after_binding: Option<Result<(), JournalError>>,
    ownership: Option<RootOwnershipProfileOriginalV1>,
    ownership_inputs: Option<Result<(), NormalRootStartupErrorV1>>,
    ownership_before: Option<Result<(), OwnershipProfileClosedV1>>,
    ownership_after: Option<Result<(), OwnershipProfileClosedV1>>,
    native: Option<TransferNamespaceNativeOriginalV1>,
    native_before: Option<Result<(), JournalError>>,
    native_after: Option<Result<(), JournalError>>,
    entered: bool,
    native_entered: bool,
    finished: bool,
    first: Option<First>,
    closed: Option<RootDeleteErrorV1>,
}

impl RootDeleteTransferNamespaceOriginalV1 {
    pub(super) fn begin_final_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &RootDeleteControllerCurrentOriginalV1,
        source: &RootDeleteSourceCurrentOriginalV1,
        floor: &RootDeleteFloorOriginalV1,
        initial: &super::initial_inventory::RootDeleteInitialInventoryOriginalV2,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered || self.first.is_some() || self.final_read
            || initial.completed_ack_bytes_v2().is_err()
        {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.final_read = true;
        self.begin_once_v1(flight, challenge, controller, source, floor)
    }

    pub(crate) fn final_admission_is_bootstrap_v2(&self) -> Result<bool, ResourceReservationErrorV1> {
        if !self.final_read || !self.entered || self.first.is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.receiving_demand_v1()?;
        Ok(self.bootstrap_demand.is_some())
    }

    pub(crate) fn is_final_read_v2(&self) -> bool {
        self.final_read
    }

    pub(super) fn completed_clock_v2(&self) -> Result<RawPairedClockSample, JournalError> {
        self.completed_namespace_comparison_v2()?;
        positive(&self.after_clock).copied()
    }

    pub(super) fn begin_once_v1(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
        controller: &RootDeleteControllerCurrentOriginalV1,
        source: &RootDeleteSourceCurrentOriginalV1,
        floor: &RootDeleteFloorOriginalV1,
    ) -> Result<(), RootDeleteErrorV1> {
        if self.entered {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootDeleteErrorV1::Original);
            return Err(RootDeleteErrorV1::Original);
        }
        self.entered = true;
        self.permit = Some(
            flight.admit_delete_transfer_namespace_v1(challenge, controller, source, floor, self),
        );
        if !matches!(self.permit, Some(Ok(()))) {
            self.first = Some(First::Permit);
            return Err(RootDeleteErrorV1::Opening);
        }
        self.native_entered = true;
        let primary = self.begin_inner(flight, challenge).and_then(|()|
            self.read_bootstrap_inner(flight, challenge, controller, source, floor));
        if primary.is_err() {
            let _ = self.finish_once_v1(flight, challenge);
        }
        primary
    }

    fn read_bootstrap_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1, controller: &RootDeleteControllerCurrentOriginalV1,
        source: &RootDeleteSourceCurrentOriginalV1, floor: &RootDeleteFloorOriginalV1,
    ) -> Result<(), RootDeleteErrorV1> {
        self.bootstrap_demand = Some(self.native.as_ref().ok_or(JournalError::ProtectedBoundary)
            .and_then(TransferNamespaceNativeOriginalV1::bootstrap_trust_demand_v2));
        self.require(matches!(self.bootstrap_demand, Some(Ok(_))), First::BootstrapDemand)?;
        self.bootstrap_permit = Some(flight.admit_delete_transfer_namespace_v1(challenge, controller, source, floor, self));
        self.require(matches!(self.bootstrap_permit, Some(Ok(()))), First::BootstrapPermit)?;
        self.bootstrap_read = Some(self.native.as_mut().ok_or(JournalError::ProtectedBoundary)
            .and_then(TransferNamespaceNativeOriginalV1::read_bootstrap_trust_once_v2));
        self.require(matches!(self.bootstrap_read, Some(Ok(()))), First::BootstrapRead)
    }

    fn begin_inner(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
    ) -> Result<(), RootDeleteErrorV1> {
        self.arm = Some(flight.arm_delete_chunk_posts_once_v1(challenge, &mut self.posts));
        self.require(matches!(self.arm, Some(Ok(()))), First::Arm)?;
        self.before_clock = Some(self.before_original.observe_once(None));
        self.before_binding = Some(
            positive(&self.before_clock)
                .and_then(|clock| challenge.require_current_clock_v1(*clock)),
        );
        self.before = Some(self.posts.observe_before_once_v1(flight, challenge));
        self.require(
            matches!(self.before_binding, Some(Ok(()))),
            First::ClockBefore,
        )?;
        self.require(matches!(self.before, Some(Ok(()))), First::Before)?;
        let inputs = (|| {
            let startup = flight.delete_cut_startup_v1()?;
            let ids = startup.native_startup_original_v1().fields().profile.identities;
            Ok(([ids[0], ids[1]], challenge.current_cutoff_v1()?))
        })();
        let (expected, cutoff) = match inputs {
            Ok(inputs) => { self.ownership_inputs = Some(Ok(())); inputs },
            Err(cause) => { self.ownership_inputs = Some(Err(cause)); self.first = Some(First::OwnershipInputs); return Err(RootDeleteErrorV1::Opening); }
        };
        self.ownership = Some(RootOwnershipProfileOriginalV1::new(expected, cutoff));
        self.ownership_before = self.ownership.as_mut().map(RootOwnershipProfileOriginalV1::begin_once_v1);
        self.require(matches!(self.ownership_before, Some(Ok(()))), First::OwnershipBefore)?;
        self.native = Some(TransferNamespaceNativeOriginalV1::default());
        self.native_before = self
            .native
            .as_mut()
            .map(TransferNamespaceNativeOriginalV1::begin_once);
        self.require(
            matches!(self.native_before, Some(Ok(()))),
            First::NamespaceBefore,
        )
    }

    pub(super) fn finish_if_owed_v1(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
    ) -> Result<(), RootDeleteErrorV1> {
        if !self.native_entered || self.finished {
            return Ok(());
        }
        self.finish_once_v1(flight, challenge)
    }

    // Only the enclosing real D continuation can reach this final frontier.
    // It still needs an independent active Ownership profile and genuine
    // Runtime default-off original before claiming a complete Transfer cut.
    pub(super) fn finish_once_v1(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        challenge: &RootDeleteChallengeOriginalsV1,
    ) -> Result<(), RootDeleteErrorV1> {
        if !self.native_entered || self.finished {
            return Err(RootDeleteErrorV1::Original);
        }
        self.finished = true;
        if let Some(native) = self.native.as_mut() {
            // The exact held bootstrap read owes its own fstat even when its
            // decoder refused. Fresh rooted/name comparison remains separately
            // owed afterwards, so neither native post can suppress the other.
            self.bootstrap_post = Some(native.finish_bootstrap_trust_if_owed_v2());
            if !matches!(self.bootstrap_post, Some(Ok(()))) {
                self.first.get_or_insert(First::BootstrapPost);
            }
            self.native_after = Some(native.finish_once());
            if !matches!(self.native_after, Some(Ok(()))) {
                self.first.get_or_insert(First::NamespaceAfter);
            }
        }
        if let Some(ownership) = self.ownership.as_mut() {
            self.ownership_after = Some(ownership.finish_if_owed_v1());
            if !matches!(self.ownership_after, Some(Ok(()))) { self.first.get_or_insert(First::OwnershipAfter); }
        }
        self.after = Some(self.posts.observe_after_once_v1(flight, challenge));
        if !matches!(self.after, Some(Ok(()))) {
            self.first.get_or_insert(First::After);
        }
        self.after_clock = Some(self.after_original.observe_once(None));
        self.after_binding = Some((|| {
            positive(&self.before_clock)?
                .validate_later_sample(*positive(&self.after_clock)?)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            challenge.require_current_clock_v1(*positive(&self.after_clock)?)
        })());
        if !matches!(self.after_binding, Some(Ok(()))) {
            self.first.get_or_insert(First::ClockAfter);
        }
        if self.first.is_some() {
            return Err(RootDeleteErrorV1::Opening);
        }
        Ok(())
    }

    pub(crate) fn receiving_demand_v1(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let offered = if self.bootstrap_demand.is_some() { self.bootstrap_permit.is_some() }
            else { self.permit.is_some() };
        if !self.entered || offered { return Err(ResourceReservationErrorV1::Conflict); }
        self.receiving_recipe_v2()
    }

    pub(crate) fn held_receiving_demand_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        if self.first.is_some() || !matches!(self.permit, Some(Ok(())))
            || !matches!(self.bootstrap_permit, Some(Ok(())))
            || !matches!(self.bootstrap_read, Some(Ok(()))) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.receiving_recipe_v2()
    }

    fn receiving_recipe_v2(&self) -> Result<ResourceVector, ResourceReservationErrorV1> {
        let invalid = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let pair = RetainedKernelPairedClockAttemptV1::dominant_requested_bytes_v1()
            .ok_or_else(invalid)?;
        let memory = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(pair.checked_mul(2)?))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        let clock_names = RetainedKernelPairedClockAttemptV1::receiving_metadata_cells_v1()
            .and_then(|names| names.checked_mul(2))
            .and_then(|names| u64::try_from(names).ok())
            .ok_or_else(invalid)?;
        let files = u64::try_from(
            2 * RetainedKernelPairedClockAttemptV1::MAXIMUM_RETAINED_FILES_V1,
        )
        .map_err(|_| invalid())?;
        let base = RootDeleteChunkPostsV1::fixed_demand_v1()?
            .checked_add(TransferNamespaceNativeOriginalV1::fixed_demand_v1()?)?
            .checked_add(RootOwnershipProfileOriginalV1::demand_v1()?)?
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, memory)
                    .with(D::OpenFiles, files)
                    .with(D::MetadataEntries, clock_names),
            )
            .map_err(ResourceReservationErrorV1::from)?;
        match &self.bootstrap_demand {
            Some(Ok(additional)) => base.checked_add(*additional).map_err(Into::into),
            Some(Err(_)) => Err(ResourceReservationErrorV1::EnrollmentUnavailable),
            None => Ok(base),
        }
    }

    pub(in crate::policy_compiler::delete_root) fn completed_namespace_comparison_v2(&self) -> Result<
        (aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningNamespaceDataV1,
         aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningOwnershipDataV1,
         aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningTrustDataV2), JournalError> {
        if !self.finished || self.first.is_some() || self.failure().is_some()
            || !matches!(self.bootstrap_post, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok((self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?.planning_data_v1()?,
            self.ownership.as_ref().ok_or(JournalError::ProtectedBoundary)?.planning_data_v1().map_err(|_| JournalError::ProtectedBoundary)?,
            self.native.as_ref().ok_or(JournalError::ProtectedBoundary)?.bootstrap_trust_data_v2()?))
    }

    fn require(&mut self, positive: bool, first: First) -> Result<(), RootDeleteErrorV1> {
        if positive {
            Ok(())
        } else {
            self.first.get_or_insert(first);
            Err(RootDeleteErrorV1::Opening)
        }
    }

    pub(super) fn financial_failure_is_selected_v1(&self) -> bool {
        matches!(self.first, Some(First::Permit | First::BootstrapPermit))
            || matches!(self.first, Some(First::Arm)) && self.posts.funding_failed_v1()
    }

    pub(super) fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            First::OwnershipBefore | First::OwnershipAfter => self.ownership.as_ref()?.property_failure_view_v1(),
            First::Before | First::After => self.posts.property_failure_view_v1(self.failure()?),
            _ => None,
        }
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            First::Permit => cause(&self.permit),
            First::BootstrapDemand => cause(&self.bootstrap_demand),
            First::BootstrapPermit => cause(&self.bootstrap_permit),
            First::BootstrapRead | First::BootstrapPost => self.native.as_ref()
                .and_then(TransferNamespaceNativeOriginalV1::bootstrap_trust_failure_v2)
                .or_else(|| cause(&self.bootstrap_read)).or_else(|| cause(&self.bootstrap_post)),
            First::Arm => self.posts.before_failure_v1().or_else(|| cause(&self.arm)),
            First::Before => self
                .posts
                .before_failure_v1()
                .or_else(|| cause(&self.before)),
            First::After => self.posts.after_failure_v1().or_else(|| cause(&self.after)),
            First::ClockBefore => self
                .before_original
                .failure()
                .or_else(|| cause(&self.before_clock))
                .or_else(|| cause(&self.before_binding)),
            First::ClockAfter => self
                .after_original
                .failure()
                .or_else(|| cause(&self.after_clock))
                .or_else(|| cause(&self.after_binding)),
            First::OwnershipInputs => cause(&self.ownership_inputs),
            First::OwnershipBefore | First::OwnershipAfter => self.ownership.as_ref().and_then(RootOwnershipProfileOriginalV1::failure)
                .or_else(|| cause(&self.ownership_before)).or_else(|| cause(&self.ownership_after)),
            First::NamespaceBefore => self
                .native
                .as_ref()
                .and_then(TransferNamespaceNativeOriginalV1::before_failure)
                .or_else(|| cause(&self.native_before)),
            First::NamespaceAfter => self
                .native
                .as_ref()
                .and_then(TransferNamespaceNativeOriginalV1::after_failure)
                .or_else(|| cause(&self.native_after)),
            First::Reentry => self.closed.as_ref().map(|cause| cause as _),
        }
    }
}

fn planning_file_data(stat: &Stat) -> Result<
    aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningFileDataV1,
    JournalError,
> {
    use aos_sandbox_protocol::domain_ledger::delete_root::planning::DeleteRootPlanningFileDataV1;
    Ok(DeleteRootPlanningFileDataV1 {
        device: stat.st_dev, inode: stat.st_ino, uid: stat.st_uid,
        gid: stat.st_gid, mode: stat.st_mode, links: stat.st_nlink,
        bytes: u64::try_from(stat.st_size).map_err(|_| JournalError::ProtectedBoundary)?,
    })
}

fn physical(stat: &Stat) -> (u64, u64, u32, u32, u32, u64) {
    (
        stat.st_dev,
        stat.st_ino,
        stat.st_uid,
        stat.st_gid,
        stat.st_mode,
        stat.st_nlink,
    )
}

fn require_local(stat: &Stat, uid: u32) -> Result<(), JournalError> {
    if stat.st_uid != uid
        || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || Mode::from_raw_mode(stat.st_mode) != (Mode::RUSR | Mode::WUSR)
        || stat.st_nlink != 1
    {
        Err(JournalError::ProtectedBoundary)
    } else {
        Ok(())
    }
}

fn require_absent(result: &Option<rustix::io::Result<Stat>>) -> Result<(), JournalError> {
    match result {
        Some(Err(error)) if *error == rustix::io::Errno::NOENT => Ok(()),
        _ => Err(JournalError::ProtectedBoundary),
    }
}

fn positive<T, E>(result: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    result
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn only_the_original_noent_result_proves_one_fixed_name_absent() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = File::open(temporary.path()).unwrap();
        let missing = Some(statat(
            &directory,
            TRANSFER_NAMES[0],
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        assert_eq!(
            missing.as_ref().unwrap().as_ref().unwrap_err(),
            &rustix::io::Errno::NOENT
        );
        assert!(require_absent(&missing).is_ok());
        assert!(require_absent(&Some(Err(rustix::io::Errno::ACCESS))).is_err());
        assert!(require_absent(&None).is_err());

        std::os::unix::fs::symlink("missing-target", temporary.path().join(TRANSFER_NAMES[0]))
            .unwrap();
        let symlink = Some(statat(
            &directory,
            TRANSFER_NAMES[0],
            AtFlags::SYMLINK_NOFOLLOW,
        ));
        assert!(symlink.as_ref().unwrap().is_ok());
        assert!(require_absent(&symlink).is_err());
    }

    #[test]
    fn a_reached_namespace_sample_keeps_actual_noent_originals_on_reentry() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = File::open(temporary.path()).unwrap();
        let mut sample = NamespaceSampleV1::default();
        sample.observe_once(&directory);
        let original = sample.transfer[0].as_ref().unwrap().as_ref().unwrap_err() as *const _;
        File::create(temporary.path().join(TRANSFER_NAMES[0])).unwrap();

        sample.observe_once(&directory);

        let retained = sample.transfer[0].as_ref().unwrap().as_ref().unwrap_err();
        assert_eq!(retained as *const _, original);
        assert_eq!(*retained, rustix::io::Errno::NOENT);
        let mut after = NamespaceSampleV1::default();
        after.observe_once(&directory);
        assert!(after.transfer[0].as_ref().unwrap().is_ok());
        assert!(require_absent(&after.transfer[0]).is_err());
    }

    #[test]
    fn local_ownership_can_append_without_becoming_an_inactive_transfer_owner() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join(LOCAL_NAMES[1]);
        let file = File::create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let before = fstat(&file).unwrap();

        file.set_len(128).unwrap();

        let after = fstat(&file).unwrap();
        assert_ne!(before.st_size, after.st_size);
        assert_eq!(physical(&before), physical(&after));
        assert!(require_local(&after, after.st_uid).is_ok());
        assert!(!TRANSFER_NAMES.contains(&LOCAL_NAMES[1]));
    }
}
