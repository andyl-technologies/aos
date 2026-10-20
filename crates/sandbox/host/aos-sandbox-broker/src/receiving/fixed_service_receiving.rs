//! Retains one fixed service's original one-way PID1 receiving sequence.
//!
//! Each closed role selects its distinct subdivision of the committed F envelope.
//! Only the real inherited channel and its same-PID1 record sequence enter here;
//! a decoded vector or capsule cannot reconstruct this original. This module
//! owns bootstrap receiving only. It issues no held Source proof or plan permit.

use std::error::Error;
use std::fs::File;
use std::os::fd::{AsFd as _, OwnedFd};
use std::os::unix::fs::{FileExt as _, MetadataExt as _};

use aos_sandbox_model::{AccountingError, ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::domain_ledger::resource_bank::{
    FIXED_SERVICE_FINAL_TRANSFER_BYTES, FIXED_SERVICE_ORIGIN_HEADER_BYTES,
};
use aos_sandbox_linux::cgroup::{
    CgroupV2Root, ExactCgroupMembershipReadbackV1, ExactCgroupMembershipRefusalV1,
    RetainedCgroupAnchor,
};
use aos_sandbox_linux::pidfd::{CurrentSelfPidFdCustodyV1, PidFdProcessIdentity};
use aos_sandbox_linux::seqpacket::{KernelAuthorizedRecordSubject, RetainedSeqpacketAdmissionErrorV1,
    RetainedSeqpacketReceiveErrorV1, SeqpacketSocket};
use aos_sandbox_linux::seqpacket::descriptor_subject::ReceivedDescriptorRecord;
use rustix::event::{PollFd, PollFlags, Timespec};
use sha2::{Digest as _, Sha256};

use super::pair::{OriginalEnrollment, OriginalEnrollmentPairAttemptV1};
use super::representation::{FixedServiceRepresentationSlotV1, RepresentationDemandDebitV1};
use super::receiving_limits::ReceivingContainmentReadbackV1;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum FixedServiceRoleV1 {
    Source = 1,
    Ownership = 2,
    Cache = 3,
    Mount = 4,
    Network = 5,
    BootPreparation = 6,
}

impl FixedServiceRoleV1 {
    fn unit(self) -> &'static [u8] {
        match self {
            Self::Source => b"aos-sandbox-source-signerd.service",
            Self::Ownership => b"aos-sandbox-ownershipd.service",
            Self::Cache => b"aos-sandbox-cache-signerd.service",
            Self::Mount => b"aos-sandbox-mountd.service",
            Self::Network => b"aos-netd.service",
            Self::BootPreparation => b"aos-sandbox-runtime-publisher.service",
        }
    }

    fn auxiliary_name(self) -> &'static str {
        match self {
            Self::Source => "aos-source-root-profile",
            Self::Ownership => "aos-sandbox-ownership",
            Self::Cache => "aos-cache-root-profile",
            Self::Mount => "aos-mount-root-profile",
            Self::Network => "aos-network-root-profile",
            Self::BootPreparation => "aos-runtime-deployment-startup-profile",
        }
    }

    fn profile(self) -> super::fixed_service_profile::FixedServiceProfileRoleV1 {
        use super::fixed_service_profile::FixedServiceProfileRoleV1;
        match self {
            Self::Source => FixedServiceProfileRoleV1::Source,
            Self::Ownership => FixedServiceProfileRoleV1::Ownership,
            Self::Cache => FixedServiceProfileRoleV1::Cache,
            Self::Mount => FixedServiceProfileRoleV1::Mount,
            Self::Network => FixedServiceProfileRoleV1::Network,
            Self::BootPreparation => FixedServiceProfileRoleV1::BootPreparation,
        }
    }

    fn context(self) -> Option<&'static [u8]> {
        match self {
            Self::Source => Some(b"system_u:system_r:aos_sandbox_source_signer_t"),
            Self::Cache => Some(crate::cache_signer_context::CACHE_SIGNER_TASK_CONTEXT_V1),
            Self::BootPreparation => Some(b"system_u:system_r:aos_runtime_deployment_publisher_t"),
            // Ownership has no declared MAC-domain supplier. Its initial
            // actual context is retained, then compared exactly on every post.
            Self::Ownership | Self::Mount | Self::Network => None,
        }
    }

    fn identity_matches(self) -> bool {
        let root = rustix::process::getuid().as_raw() == 0 && rustix::process::geteuid().as_raw() == 0
            && rustix::process::getgid().as_raw() == 0 && rustix::process::getegid().as_raw() == 0;
        match self {
            Self::Source | Self::Cache => rustix::process::getuid().as_raw() != 0 && rustix::process::geteuid().as_raw() != 0
                && rustix::process::getgid().as_raw() != 0 && rustix::process::getegid().as_raw() != 0,
            Self::Ownership | Self::Mount | Self::Network | Self::BootPreparation => root,
        }
    }
}

enum FixedServiceInitialTableV1 {
    Source(aos_sandbox_linux::inherited_fd::SourceSignerInitialActivationTableV1),
    Ownership(aos_sandbox_linux::inherited_fd::OwnershipInitialActivationTableV1),
    Cache(aos_sandbox_linux::inherited_fd::CacheSignerInitialActivationTableV1),
    Mount(aos_sandbox_linux::inherited_fd::MountInitialActivationTableV4),
    Network(aos_sandbox_linux::inherited_fd::NetworkInitialActivationTableV4),
    BootPreparation(aos_sandbox_linux::inherited_fd::RuntimeBootPreparationInitialActivationTableV1),
}

impl FixedServiceInitialTableV1 {
    fn new(role: FixedServiceRoleV1) -> Self {
        match role {
            FixedServiceRoleV1::Source => Self::Source(aos_sandbox_linux::inherited_fd::SourceSignerInitialActivationTableV1::new()),
            FixedServiceRoleV1::Ownership => Self::Ownership(aos_sandbox_linux::inherited_fd::OwnershipInitialActivationTableV1::new()),
            FixedServiceRoleV1::Cache => Self::Cache(aos_sandbox_linux::inherited_fd::CacheSignerInitialActivationTableV1::new()),
            FixedServiceRoleV1::Mount => Self::Mount(aos_sandbox_linux::inherited_fd::MountInitialActivationTableV4::new()),
            FixedServiceRoleV1::Network => Self::Network(aos_sandbox_linux::inherited_fd::NetworkInitialActivationTableV4::new()),
            FixedServiceRoleV1::BootPreparation => Self::BootPreparation(aos_sandbox_linux::inherited_fd::RuntimeBootPreparationInitialActivationTableV1::new()),
        }
    }

    fn observe_once(&mut self) -> Result<(), &aos_sandbox_linux::Error> {
        match self { Self::Source(value) => value.observe_once(), Self::Ownership(value) => value.observe_once(), Self::Cache(value) => value.observe_once(), Self::Mount(value) => value.observe_once(), Self::Network(value) => value.observe_once(), Self::BootPreparation(value) => value.observe_once() }
    }

    fn take_completed_entries(&mut self) -> Option<[Option<OwnedFd>; 4]> {
        let ordinary = match self {
            Self::Source(value) => value.take_completed_entries(),
            Self::Ownership(value) => value.take_completed_entries(),
            Self::Cache(value) => value.take_completed_entries(),
            Self::Mount(value) => value.take_completed_entries(),
            Self::Network(value) => value.take_completed_entries(),
            Self::BootPreparation(value) => return value.take_completed_entries(),
        };
        ordinary.map(|[first, second]| [first, second, None, None])
    }

    fn failure(&self) -> Option<&aos_sandbox_linux::Error> {
        match self { Self::Source(value) => value.failure(), Self::Ownership(value) => value.failure(), Self::Cache(value) => value.failure(), Self::Mount(value) => value.failure(), Self::Network(value) => value.failure(), Self::BootPreparation(value) => value.failure() }
    }
}

enum FixedServiceInitialCgroupV1 {
    Source(aos_sandbox_linux::cgroup::SourceSignerInitialCgroupReadbackV1),
    Ownership(aos_sandbox_linux::cgroup::OwnershipInitialCgroupReadbackV1),
    Cache(aos_sandbox_linux::cgroup::CacheSignerInitialCgroupReadbackV1),
    Mount(aos_sandbox_linux::cgroup::MountInitialCgroupReadbackV4),
    Network(aos_sandbox_linux::cgroup::NetworkInitialCgroupReadbackV4),
    BootPreparation(aos_sandbox_linux::cgroup::RuntimeBootPreparationInitialCgroupReadbackV1),
}

impl FixedServiceInitialCgroupV1 {
    fn new(role: FixedServiceRoleV1) -> Self {
        match role {
            FixedServiceRoleV1::Source => Self::Source(Default::default()),
            FixedServiceRoleV1::Ownership => Self::Ownership(Default::default()),
            FixedServiceRoleV1::Cache => Self::Cache(Default::default()),
            FixedServiceRoleV1::Mount => Self::Mount(Default::default()),
            FixedServiceRoleV1::Network => Self::Network(Default::default()),
            FixedServiceRoleV1::BootPreparation => Self::BootPreparation(Default::default()),
        }
    }

    fn capture_once(&mut self) -> Result<(), aos_sandbox_linux::Error> {
        match self { Self::Source(value) => value.capture_once(), Self::Ownership(value) => value.capture_once(), Self::Cache(value) => value.capture_once(), Self::Mount(value) => value.capture_once(), Self::Network(value) => value.capture_once(), Self::BootPreparation(value) => value.capture_once() }
    }

    fn take_validated_pair(&mut self) -> Option<(CgroupV2Root, RetainedCgroupAnchor)> {
        match self { Self::Source(value) => value.take_validated_pair(), Self::Ownership(value) => value.take_validated_pair(), Self::Cache(value) => value.take_validated_pair(), Self::Mount(value) => value.take_validated_pair(), Self::Network(value) => value.take_validated_pair(), Self::BootPreparation(value) => value.take_validated_pair() }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self { Self::Source(value) => value.failure(), Self::Ownership(value) => value.failure(), Self::Cache(value) => value.failure(), Self::Mount(value) => value.failure(), Self::Network(value) => value.failure(), Self::BootPreparation(value) => value.failure() }
    }
}

const ROLE_NAME: &str = "aos-resource-service-origin-v1";
const MAXIMUM_PARTS: usize = 9;
const PARENT_HEADER: usize = 2742;
const PARENT_ROW: usize = 1506;
const PARENT_MAXIMUM: usize = PARENT_HEADER + 16 * PARENT_ROW + 32;

type NativeResult = Result<(), aos_sandbox_linux::Error>;

pub(crate) struct FixedServiceOriginalPart<E> {
    pub(crate) marker: std::marker::PhantomData<E>,
    pub(crate) payload: Vec<u8>,
    pub(crate) subject: KernelAuthorizedRecordSubject,
    pub(crate) descriptor_slots: Vec<OwnedFd>,
    pub(crate) file: Option<File>,
}

impl<E: Copy + Default> FixedServiceOriginalPart<E> {
    fn retain(record: ReceivedDescriptorRecord) -> Self {
        let (payload, subject, mut descriptor_slots) = record.into_parts();
        let file = descriptor_slots.pop().map(File::from);
        Self { marker: std::marker::PhantomData, payload, subject, descriptor_slots, file }
    }

    fn file(&self) -> Result<&File, E> {
        if !self.descriptor_slots.is_empty() { return Err(E::default()); }
        self.file.as_ref().ok_or(E::default())
    }
}

#[derive(Clone, Copy)]
enum Failure {
    Table, Names, Channel, Peer, Poll(usize), Receive(usize), Part(usize),
    Pair, ParentMetadata, ParentFilesystem, ParentFlags, ParentSize, ParentRead, Parent,
    Demand, Accounting, Process, Cgroup, NetworkAggregate, Membership, Limits, ProcessPost,
    FinalBinding, Transfer, Profile, StartupCurrentness, Closed,
}

/// Retains one selected service's original PID1 delivery and native observations.
///
/// Construction observes nothing and accepts no files, paths, callbacks or
/// resource vector. The first capture selects only this process's fixed table.
/// Every failed or successful capture stays resident until process termination;
/// dropping an entered owner aborts before releasing its originals.
#[must_use]
pub struct FixedServiceReceivingCaptureV1<E> {
    pub(crate) role: FixedServiceRoleV1,
    pub(crate) upper_inline_bytes: usize,
    /// Reports actual one-shot native entry; it supplies no role grant.
    pub entered: bool,
    first: Option<Failure>,
    pub(super) service_startup: Option<Box<super::fixed_service_startup::FixedServiceStartupOriginalV4>>,
    pub(super) startup_admission: Option<Result<ResourceVector, AccountingError>>,
    pub(super) listener_entered: bool,
    pub(super) operation_active: bool,
    pub(super) operation_closed: bool,
    pub(super) operation_files: u64,
    pub(super) operation_ordinal: u64,
    pub(super) inventory_disposal_pending: Option<u64>,
    pub(crate) closed: Option<E>,
    table: FixedServiceInitialTableV1,
    pub(crate) entries: Option<[Option<OwnedFd>; 4]>,
    /// Retains the role-bound companion original, never a caller-supplied FD.
    pub root_profile: Option<File>,
    pub(crate) names: Option<Result<Vec<String>, super::names::ActivationNamesErrorV1>>,
    pub(crate) channel: Option<Result<SeqpacketSocket, RetainedSeqpacketAdmissionErrorV1>>,
    pub(crate) peer: Option<Result<(), E>>,
    pub(crate) polls: [Option<Result<usize, rustix::io::Errno>>; MAXIMUM_PARTS],
    pub(crate) receive_failures: [Option<RetainedSeqpacketReceiveErrorV1>; MAXIMUM_PARTS],
    pub(crate) parts: [Option<FixedServiceOriginalPart<E>>; MAXIMUM_PARTS],
    pub(crate) part_checks: [Option<Result<(), E>>; MAXIMUM_PARTS],
    pub(crate) pair: OriginalEnrollmentPairAttemptV1,
    pub(crate) enrollment: Option<OriginalEnrollment>,
    pub(crate) parent_metadata: Option<std::io::Result<std::fs::Metadata>>,
    pub(crate) parent_filesystem: Option<Result<rustix::fs::StatFs, rustix::io::Errno>>,
    pub(crate) parent_flags: Option<Result<rustix::fs::OFlags, rustix::io::Errno>>,
    pub(crate) parent_read: Option<std::io::Result<()>>,
    pub(crate) parent_size: Option<Result<usize, std::num::TryFromIntError>>,
    pub(crate) parent_bytes: [u8; PARENT_MAXIMUM],
    pub(crate) parent_len: usize,
    pub(crate) parent: Option<Result<(ResourceVector, u64, usize), E>>,
    /// Retains the sole restrictive representation debit original.
    pub representation: FixedServiceRepresentationSlotV1,
    /// Retains checked fixed-startup representation DATA and its original refusal.
    pub demand: Option<Result<ResourceVector, AccountingError>>,
    /// Retains this process original; role-private stages prepay every observation.
    pub process: CurrentSelfPidFdCustodyV1,
    /// Retains the exact initial process identity Result.
    pub process_before: Option<Result<PidFdProcessIdentity, aos_sandbox_linux::Error>>,
    cgroup_capture: FixedServiceInitialCgroupV1,
    pub(super) network_aggregate: Option<Box<super::network_receiving_aggregate::NetworkReceivingAggregateOriginalV4>>,
    pub(crate) cgroup_result: Option<NativeResult>,
    pub(crate) hierarchy: Option<CgroupV2Root>,
    /// Retains the actual fixed-role cgroup anchor after complete initial capture.
    pub cgroup: Option<RetainedCgroupAnchor>,
    /// Retains the original exact cgroup membership comparison Result.
    pub membership: Option<Result<aos_sandbox_linux::pidfd::PidFdInfo, E>>,
    membership_capture: ExactCgroupMembershipReadbackV1,
    membership_entry: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    /// Retains the actual installed hard-limit readers and all initial Results.
    pub limits: ReceivingContainmentReadbackV1,
    pub(crate) process_after: Option<Result<PidFdProcessIdentity, aos_sandbox_linux::Error>>,
    /// Retains the actual final startup conjunction Result.
    pub final_binding: Option<Result<(), E>>,
    pub(crate) transfer: super::fixed_service_transfer::FixedServiceExecTransferReadbackV1<E>,
    pub(crate) profile: super::fixed_service_profile::FixedServiceProfileReadbackV1<E>,
    /// Retains the complete startup native/currentness observation.
    pub startup_currentness: super::fixed_service_currentness::FixedServiceCurrentnessSampleV1<E>,
    pub(crate) startup_currentness_result: Option<Result<(), E>>,
}

impl<E: Copy + Default + Error + 'static> FixedServiceReceivingCaptureV1<E> {
    /// Creates empty fixed Source destinations for the component-image recipe.
    ///
    /// The actual two-entry table, PID1 original, Source subdivision, F3 and
    /// native containment must authenticate before a debit becomes available.
    /// The canonical component decoder checks every static image constraint;
    /// the Controller separately checks its compiled P/I/Q/J layouts before
    /// entering those Controller-only operations. Neither layout DATA nor this
    /// inert constructor grants a Source purpose or receiving allowance.
    #[must_use]
    pub fn new_source_component_v1(upper_inline_bytes: usize) -> Self {
        Self::new(FixedServiceRoleV1::Source, upper_inline_bytes)
    }

    /// Creates only empty fixed Ownership capture destinations.
    pub fn new_ownership(upper_inline_bytes: usize) -> Self {
        Self::new(FixedServiceRoleV1::Ownership, upper_inline_bytes)
    }

    /// Creates only empty fixed Cache signer capture destinations.
    ///
    /// The actual two-entry initial table, original PID1 delivery and complete
    /// Cache F subdivision must authenticate before any debit is available.
    /// Caller layout DATA cannot create a successful receiving original.
    #[must_use]
    pub fn new_cache(upper_inline_bytes: usize) -> Self {
        Self::new(FixedServiceRoleV1::Cache, upper_inline_bytes)
    }

    /// Creates empty Mount destinations for the genuine Parent04 service flight.
    ///
    /// This selects no effect, provider-Acquire claim or receiving allowance.
    /// The actual fixed PID1/image/profile/native capture must succeed first.
    #[must_use]
    pub fn new_mount_v4(upper_inline_bytes: usize) -> Self {
        Self::new(FixedServiceRoleV1::Mount, upper_inline_bytes)
    }

    /// Creates empty Network destinations for its distinct Parent04 service slice.
    ///
    /// No decoded vector, Session or role DATA can complete this capture.
    #[must_use]
    pub fn new_network_v4(upper_inline_bytes: usize) -> Self {
        Self::new(FixedServiceRoleV1::Network, upper_inline_bytes)
    }

    pub(super) fn new_boot_preparation_v1(upper_inline_bytes: usize) -> Self {
        Self::new(FixedServiceRoleV1::BootPreparation, upper_inline_bytes)
    }

    fn new(role: FixedServiceRoleV1, upper_inline_bytes: usize) -> Self {
        Self {
            role, upper_inline_bytes,
            entered: false, first: None, service_startup: None, startup_admission: None, listener_entered: false, operation_active: false, operation_closed: false, operation_files: 0, operation_ordinal: 0, inventory_disposal_pending: None, closed: None,
            table: FixedServiceInitialTableV1::new(role), entries: None, root_profile: None,
            names: None, channel: None, peer: None,
            polls: std::array::from_fn(|_| None), receive_failures: std::array::from_fn(|_| None),
            parts: std::array::from_fn(|_| None), part_checks: std::array::from_fn(|_| None),
            pair: OriginalEnrollmentPairAttemptV1::new_component(), enrollment: None,
            parent_metadata: None, parent_filesystem: None, parent_flags: None,
            parent_read: None, parent_size: None, parent_bytes: [0; PARENT_MAXIMUM], parent_len: 0,
            parent: None, representation: FixedServiceRepresentationSlotV1::empty(), demand: None, process: CurrentSelfPidFdCustodyV1::new(),
            process_before: None,
            cgroup_capture: FixedServiceInitialCgroupV1::new(role), network_aggregate: None, cgroup_result: None,
            hierarchy: None, cgroup: None, membership: None,
            membership_capture: ExactCgroupMembershipReadbackV1::new(), membership_entry: None,
            limits: ReceivingContainmentReadbackV1::default(), process_after: None,
            final_binding: None, transfer: super::fixed_service_transfer::FixedServiceExecTransferReadbackV1::<E>::default(),
            profile: super::fixed_service_profile::FixedServiceProfileReadbackV1::<E>::new(role.profile()),
            startup_currentness: super::fixed_service_currentness::FixedServiceCurrentnessSampleV1::<E>::default(),
            startup_currentness_result: None,
        }
    }

    /// Captures the role-selected image-paid bootstrap entrance once.
    ///
    /// PID1 assigns the distinct whole-service slice before exec and descriptor
    /// delivery. This first fixed prefix only authenticates that original;
    /// the private ledger charges startup before subsequent native readbacks.
    /// No key, domain journal, contacted request or plan is touched here.
    ///
    /// # Errors
    /// Retains the actual first native/protocol/accounting cause in this owner.
    /// Reentry cannot resample, replace a failed result or reissue the slice.
    pub fn capture_once(&mut self) -> Result<(), E> {
        if self.entered {
            self.closed.get_or_insert(E::default());
            self.first.get_or_insert(Failure::Closed);
            return Err(E::default());
        }
        self.entered = true;
        let result = self.capture_inner();
        if result.is_err() && self.first.is_none() {
            self.closed = Some(E::default());
            self.first = Some(Failure::Closed);
        }
        result
    }

    fn fail(&mut self, site: Failure) -> E {
        self.first.get_or_insert(site);
        self.closed.get_or_insert(E::default());
        E::default()
    }

    fn capture_inner(&mut self) -> Result<(), E> {
        if self.table.observe_once().is_err() { return Err(self.fail(Failure::Table)); }
        self.entries = self.table.take_completed_entries();
        let role_count = if self.role == FixedServiceRoleV1::BootPreparation { 4 } else { 2 };
        self.names = Some(super::names::original_activation_names_v1(role_count));
        let names = match self.names.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(names) => names,
            None => return Err(self.fail(Failure::Names)),
        };
        let origin_index = names.iter().position(|name| name == ROLE_NAME);
        let profile_index = names.iter().position(|name| name == self.role.auxiliary_name());
        if self.role == FixedServiceRoleV1::BootPreparation
            && ![ROLE_NAME, self.role.auxiliary_name(), "aos-runtime-deployment",
                "aos-runtime-deployment-pid1-image"].iter().all(|expected|
                names.iter().filter(|name| name.as_str() == *expected).count() == 1)
        {
            return Err(self.fail(Failure::Names));
        }
        let (origin_index, profile_index) = match (origin_index, profile_index) {
            (Some(origin), Some(profile)) if names.len() == role_count && origin != profile => (origin, profile),
            _ => return Err(self.fail(Failure::Names)),
        };
        let original = self.entries.as_mut().and_then(|entries| entries[origin_index].take())
            .ok_or_else(|| self.fail(Failure::Table))?;
        self.root_profile = self.entries.as_mut().and_then(|entries| entries[profile_index].take()).map(File::from);
        if self.root_profile.is_none() { return Err(self.fail(Failure::Table)); }
        self.channel = Some(SeqpacketSocket::from_owned_retaining(original));
        if self.channel.as_ref().is_none_or(Result::is_err) { return Err(self.fail(Failure::Channel)); }
        self.peer = Some(self.require_pid1_peer());
        if self.peer.as_ref().is_none_or(Result::is_err) { return Err(self.fail(Failure::Peer)); }

        // The authenticated original pair precedes Parent/drop-count access.
        for index in 0..3 {
            self.receive_part_once(index)?;
        }
        let policy = self.parts[0].as_ref().ok_or(E::default())?.file()?;
        let capsule = self.parts[2].as_ref().ok_or(E::default())?.file()?;
        match self.pair.observe_once(policy, capsule) {
            Ok(enrollment) => self.enrollment = Some(*enrollment),
            Err(_) => return Err(self.fail(Failure::Pair)),
        }
        self.capture_parent()?;
        let (ceiling, nofile, source_index) = self.parent.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(E::default())?;
        let row_start = PARENT_HEADER + source_index * PARENT_ROW;
        let drops = usize::from(u16::from_be_bytes([self.parent_bytes[row_start + 352], self.parent_bytes[row_start + 353]]));
        if drops > 4 { return Err(self.fail(Failure::Profile)); }
        for file_index in 0..=drops {
            self.receive_part_once(4 + file_index)?;
        }
        // F3 is physically last, after real exec and all original file delivery.
        self.receive_part_once(3)?;
        let packet = &self.parts[3].as_ref().ok_or(E::default())?.payload;
        if self.transfer.prepare_once(packet, ceiling, nofile).is_err() {
            return Err(self.fail(Failure::Transfer));
        }
        if !self.representation.install_once(ceiling) {
            return Err(self.fail(Failure::Accounting));
        }
        let persistent = self.transfer.persistent_usage()?;
        if self.representation.as_mut().ok_or(E::default())?.reserve(persistent).is_err() {
            return Err(self.fail(Failure::Accounting));
        }
        self.demand = Some(self.fixed_startup_demand());
        let demand = match self.demand.as_ref().and_then(|result| result.as_ref().ok()).copied() {
            Some(demand) => demand,
            None => return Err(self.fail(Failure::Demand)),
        };
        if self.representation.as_mut().ok_or(E::default())?.reserve(demand.with(D::OpenFiles, 0)).is_err() {
            return Err(self.fail(Failure::Accounting));
        }
        // The fixed demand includes the full permanent FD debt. These actual
        // kernel/profile observations cannot enable recurring coverage early.
        let executable = self.parts[3].as_ref().ok_or(E::default())?.file()?;
        if self.transfer.capture_once(executable).is_err() {
            return Err(self.fail(Failure::Transfer));
        }
        for file_index in 0..=drops {
            let file = self.parts[4 + file_index].as_ref().ok_or(E::default())?.file()?;
            let row = &self.parent_bytes[row_start..row_start + PARENT_ROW];
            if self.profile.observe_next_file_once(file, row).is_err() {
                return Err(self.fail(Failure::Profile));
            }
        }
        if self.profile.require_complete().is_err() { return Err(self.fail(Failure::Profile)); }
        self.capture_native(ceiling.with(D::OpenFiles, nofile))
    }

    fn receive_part_once(&mut self, index: usize) -> Result<(), E> {
        if index >= MAXIMUM_PARTS || self.parts[index].is_some() || self.polls[index].is_some() {
            return Err(self.fail(Failure::Closed));
        }
        let socket = self.channel.as_mut().and_then(|result| result.as_mut().ok()).ok_or(E::default())?;
        let descriptor = socket.as_fd().map_err(|_| E::default())?;
        let mut readiness = [PollFd::new(&descriptor, PollFlags::IN)];
        self.polls[index] = Some(rustix::event::poll(&mut readiness, Some(&Timespec { tv_sec: 5, tv_nsec: 0 })));
        if !self.polls[index].as_ref().is_some_and(|result| result.as_ref().is_ok_and(|count| *count > 0)) {
            return Err(self.fail(Failure::Poll(index)));
        }
        // No competing reader owns this original endpoint. Interruption is
        // retained and cannot retry or consume the next logical delivery part.
        let received = if index == 3 {
            socket.receive_pid1_service_origin_payload_retaining_v1(FIXED_SERVICE_FINAL_TRANSFER_BYTES)
        } else {
            socket.receive_pid1_service_origin_descriptor_retaining_v1()
        };
        match received {
            Ok(record) => self.parts[index] = Some(FixedServiceOriginalPart::retain(record)),
            Err(error) => {
                self.receive_failures[index] = Some(error);
                return Err(self.fail(Failure::Receive(index)));
            }
        }
        self.part_checks[index] = Some(self.require_part(index));
        if self.part_checks[index].as_ref().is_none_or(Result::is_err) {
            return Err(self.fail(Failure::Part(index)));
        }
        Ok(())
    }

    pub(crate) fn require_pid1_peer(&self) -> Result<(), E> {
        let socket = self.channel.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
        let peer = socket.peer();
        let credentials = peer.credentials();
        if credentials.pid().get() != 1 || credentials.uid() != 0 || credentials.gid() != 0
            || peer.initial_info().pid() != 1 { return Err(E::default()); }
        Ok(())
    }

    fn require_part(&self, index: usize) -> Result<(), E> {
        let part = self.parts[index].as_ref().ok_or(E::default())?;
        let credentials = part.subject.credentials();
        if credentials.pid().get() != 1 || credentials.uid() != 0 || credentials.gid() != 0
            || part.subject.initial_info().pid() != 1 || part.file.is_none() || !part.descriptor_slots.is_empty()
        {
            return Err(E::default());
        }
        require_origin_header::<E>(&part.payload, index, self.role, std::process::id())?;
        if index == 0 {
            return if part.payload[120..128] == [0; 8] { Ok(()) } else { Err(E::default()) };
        }
        let first = &self.parts[0].as_ref().ok_or(E::default())?.payload;
        if part.payload[9..56] != first[9..56] { return Err(E::default()); }
        if index < 3 {
            if part.payload[56..] != first[56..] { return Err(E::default()); }
        } else if index == 3 {
            if read_u64::<E>(&part.payload[120..128])? != 1 { return Err(E::default()); }
        } else {
            let (_, _, source_index) = self.parent.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(E::default())?;
            let start = PARENT_HEADER + source_index * PARENT_ROW;
            let row = &self.parent_bytes[start..start + PARENT_ROW];
            let file_index = index - 4;
            let drops = usize::from(u16::from_be_bytes([row[352], row[353]]));
            if file_index > drops { return Err(E::default()); }
            let digest_start = if file_index == 0 { 320 } else { 354 + (file_index - 1) * 288 + 256 };
            if part.payload[56..88] != first[56..88]
                || part.payload[88..120] != row[digest_start..digest_start + 32]
                || part.payload[120..128] != [0; 8]
            {
                return Err(E::default());
            }
        }
        Ok(())
    }

    fn capture_parent(&mut self) -> Result<(), E> {
        let parent = self.parts[1].as_ref().ok_or(E::default())?.file()?;
        self.parent_metadata = Some(parent.metadata());
        self.parent_filesystem = Some(rustix::fs::fstatfs(parent));
        self.parent_flags = Some(rustix::fs::fcntl_getfl(parent));
        let metadata = match self.parent_metadata.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(value) => value,
            None => return Err(self.fail(Failure::ParentMetadata)),
        };
        let filesystem = match self.parent_filesystem.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(value) => value,
            None => return Err(self.fail(Failure::ParentFilesystem)),
        };
        let flags = match self.parent_flags.as_ref().and_then(|result| result.as_ref().ok()) {
            Some(value) => value,
            None => return Err(self.fail(Failure::ParentFlags)),
        };
        self.parent_size = Some(usize::try_from(metadata.len()));
        let length = match self.parent_size.as_ref() {
            Some(Ok(length)) => *length,
            _ => return Err(self.fail(Failure::ParentSize)),
        };
        if metadata.mode() & 0o170000 != 0o100000 || metadata.mode() & 0o222 != 0
            || metadata.uid() != 0 || metadata.gid() != 0
            || filesystem.f_type as u64 != 0xe0f5_e1e2
            || flags.contains(rustix::fs::OFlags::PATH)
            || flags.intersects(rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR)
            || !((PARENT_HEADER + 32)..=PARENT_MAXIMUM).contains(&length) {
            return Err(self.fail(Failure::Parent));
        }
        self.parent_len = length;
        self.parent_read = Some(parent.read_exact_at(&mut self.parent_bytes[..length], 0));
        if self.parent_read.as_ref().is_none_or(Result::is_err) { return Err(self.fail(Failure::ParentRead)); }
        self.parent = Some(self.require_parent());
        if self.parent.as_ref().is_none_or(Result::is_err) { return Err(self.fail(Failure::Parent)); }
        Ok(())
    }

    fn require_parent(&self) -> Result<(ResourceVector, u64, usize), E> {
        let bytes = &self.parent_bytes[..self.parent_len];
        let enrollment = self.enrollment.ok_or(E::default())?;
        let packet = &self.parts[0].as_ref().ok_or(E::default())?.payload;
        let count = usize::from(u16::from_be_bytes(bytes[452..454].try_into().map_err(|_| E::default())?));
        if &bytes[..8] != b"AOSRPE05" || !(1..=16).contains(&count)
            || bytes.len() != PARENT_HEADER + 32 + count * PARENT_ROW
            || Sha256::digest(&bytes[..bytes.len() - 32]).as_slice() != &bytes[bytes.len() - 32..]
            || Sha256::digest(bytes).as_slice() != &packet[56..88]
            || bytes[8..40] != self.pair.policy_commitment().ok_or(E::default())?
            || packet[16..32] != enrollment.recipient_invocation
            || enrollment.recipient_invocation == [0; 16] {
            return Err(E::default());
        }
        let source = read_vector::<E>(&bytes[454..630])?;
        let sender = read_vector::<E>(&bytes[630..806])?;
        let controller_sender = read_vector::<E>(&bytes[806..982])?;
        let ownership = read_vector::<E>(&bytes[982..1158])?;
        let ownership_sender = read_vector::<E>(&bytes[1158..1334])?;
        let cache = read_vector::<E>(&bytes[1334..1510])?;
        let cache_sender = read_vector::<E>(&bytes[1510..1686])?;
        let mount = read_vector::<E>(&bytes[1686..1862])?;
        let mount_sender = read_vector::<E>(&bytes[1862..2038])?;
        let network = read_vector::<E>(&bytes[2038..2214])?;
        let network_sender = read_vector::<E>(&bytes[2214..2390])?;
        let boot_receiving = read_vector::<E>(&bytes[2390..2566])?;
        let boot_sender = read_vector::<E>(&bytes[2566..2742])?;
        let manager = read_vector::<E>(&bytes[40..216])?;
        let fixed = read_vector::<E>(&bytes[216..392])?;
        for dimension in D::ALL {
            if source.get(dimension) > fixed.get(dimension)
                || sender.get(dimension) > manager.get(dimension)
                || controller_sender.get(dimension) > manager.get(dimension) - sender.get(dimension)
                || ownership.get(dimension) > fixed.get(dimension) - source.get(dimension)
                || ownership_sender.get(dimension) > manager.get(dimension)
                    - sender.get(dimension) - controller_sender.get(dimension)
                || cache.get(dimension) > fixed.get(dimension)
                    - source.get(dimension) - ownership.get(dimension)
                || cache_sender.get(dimension) > manager.get(dimension)
                    - sender.get(dimension) - controller_sender.get(dimension)
                    - ownership_sender.get(dimension)
                || mount.get(dimension) > fixed.get(dimension)
                    - source.get(dimension) - ownership.get(dimension) - cache.get(dimension)
                || mount_sender.get(dimension) > manager.get(dimension)
                    - sender.get(dimension) - controller_sender.get(dimension)
                    - ownership_sender.get(dimension) - cache_sender.get(dimension)
                || network.get(dimension) > fixed.get(dimension)
                    - source.get(dimension) - ownership.get(dimension) - cache.get(dimension) - mount.get(dimension)
                || network_sender.get(dimension) > manager.get(dimension)
                    - sender.get(dimension) - controller_sender.get(dimension)
                    - ownership_sender.get(dimension) - cache_sender.get(dimension) - mount_sender.get(dimension)
                || boot_sender.get(dimension) > manager.get(dimension)
                    - sender.get(dimension) - controller_sender.get(dimension)
                    - ownership_sender.get(dimension) - cache_sender.get(dimension)
                    - mount_sender.get(dimension) - network_sender.get(dimension) {
                return Err(E::default());
            }
            if boot_receiving.get(dimension) > enrollment.policy.host_service_envelope_data_v1()
                .unwrap_or(ResourceVector::ZERO).get(dimension)
            {
                return Err(E::default());
            }
        }
        let nofile = read_u64::<E>(&bytes[400..408])?;
        let (selected, selected_sender) = match self.role {
            FixedServiceRoleV1::Source => (source, sender),
            FixedServiceRoleV1::Ownership => (ownership, ownership_sender),
            FixedServiceRoleV1::Cache => (cache, cache_sender),
            FixedServiceRoleV1::Mount => (mount, mount_sender),
            FixedServiceRoleV1::Network => (network, network_sender),
            FixedServiceRoleV1::BootPreparation => (boot_receiving, boot_sender),
        };
        let cpu = selected.get(D::CpuMicrosPerPeriod);
        let memory = selected.get(D::MemoryBytes);
        let tasks = selected.get(D::Pids);
        if cpu == 0 || cpu % 1000 != 0 || cpu.checked_mul(10).is_none()
            || memory == 0 || memory % 4096 != 0 || memory > i64::MAX as u64
            || tasks == 0 || tasks > i64::MAX as u64
            || nofile == 0 || nofile > u32::MAX as u64
            || nofile > selected.get(D::OpenFiles)
            || selected.get(D::ConcurrentOperations) == 0 || selected_sender.get(D::ConcurrentOperations) != 1 {
            return Err(E::default());
        }
        let mut source_found = None;
        for index in 0..count {
            let row = &bytes[PARENT_HEADER + index * PARENT_ROW..][..PARENT_ROW];
            let name = &row[..64];
            if name.starts_with(self.role.unit()) && name[self.role.unit().len()..].iter().all(|byte| *byte == 0) {
                if source_found.is_some() || row[320..352] != packet[88..120] { return Err(E::default()); }
                source_found = Some(index);
            }
        }
        let source_index = source_found.ok_or(E::default())?;
        Ok((selected, nofile, source_index))
    }

    /// Computes the actual inline/native receiving representation DATA.
    ///
    /// # Errors
    /// Rejects overflow or a physical FD peak exceeding the transferred bound.
    pub fn fixed_startup_demand(&self) -> Result<ResourceVector, AccountingError> {
        let (ordinary_bytes, ordinary_files) = SeqpacketSocket::pid1_service_origin_receive_obligations_v1();
        let (transfer_bytes, transfer_files) = SeqpacketSocket::pid1_service_origin_payload_receive_obligations_v1(
            FIXED_SERVICE_FINAL_TRANSFER_BYTES,
        ).ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        let receive_files = ordinary_files.max(transfer_files);
        // Retained successful parts and the one failed raw receive peak are
        // bounded together. Conservatively count each original part's complete
        // lower receive footprint; no failed sample is disposed for credit.
        let memory = std::mem::size_of::<Self>().checked_add(self.upper_inline_bytes)
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?
            .checked_add(ordinary_bytes.checked_mul(MAXIMUM_PARTS - 1).ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?)
            .and_then(|value| value.checked_add(transfer_bytes))
            // Parent05 also retains the actual BootPreparation receiving and
            // sender temporaries beside the existing complete receiver.
            .and_then(|value| value.checked_add(8 * std::mem::size_of::<ResourceVector>()))
            .and_then(|value| value.checked_add(512 +
                (if self.role == FixedServiceRoleV1::BootPreparation { 4 } else { 2 }) * std::mem::size_of::<String>()))
            .and_then(|value| value.checked_add(8 * 4096 + 2 * 4097))
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        let membership_residual = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1()
            .and_then(|bytes| bytes.checked_sub(std::mem::size_of::<ExactCgroupMembershipReadbackV1>()))
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        let memory = memory.checked_add(membership_residual)
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?;
        let membership_files = ExactCgroupMembershipReadbackV1::MAXIMUM_RETAINED_FILES_V1;
        let initial_roles = if self.role == FixedServiceRoleV1::BootPreparation { 4 } else { 2 };
        let physical_files = receive_files.checked_add(2 * MAXIMUM_PARTS + initial_roles + 2 + 6 + 2 + 2 + membership_files)
            .ok_or(AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
        let permanent = self.transfer.permanent_open_files().map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?;
        let mut physical = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::MemoryBytes })?)
            .with(D::OpenFiles, u64::try_from(physical_files).map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::OpenFiles })?)
            // Count the native descriptor entries. Inline ResourceVector
            // cells and their Rust carrier introduce no namespace entries.
            .with(D::MetadataEntries, u64::try_from(physical_files)
                .map_err(|_| AccountingError::ArithmeticOverflow { dimension: D::MetadataEntries })?)
            .checked_add(ReceivingContainmentReadbackV1::fixed_demand())?
            .checked_add(super::fixed_service_currentness::FixedServiceCurrentnessSampleV1::<E>::dynamic_demand()?)?;
        if matches!(self.role, FixedServiceRoleV1::Source | FixedServiceRoleV1::Cache) {
            // Preserve the non-root signer listener duplicate and second sample
            // before the first native observation, including their simultaneous
            // descriptor peak. Ownership has its own later operation entrance.
            physical = physical.checked_add(
                super::fixed_service_currentness::FixedServiceCurrentnessSampleV1::<E>::dynamic_demand()?
                    .checked_add(ResourceVector::ZERO.with(D::OpenFiles, 1).with(D::MetadataEntries, 1))?,
            )?;
        }
        if matches!(self.role, FixedServiceRoleV1::Network) {
            physical = physical.checked_add(super::network_receiving_aggregate::
                NetworkReceivingAggregateOriginalV4::receiving_demand_v4()?)?
                .checked_add(super::fixed_service_currentness::FixedServiceCurrentnessSampleV1::<E>::
                    network_aggregate_dynamic_demand_v4()?)?
                // Actual main capture: root4 + three subtree components +
                // root/main cgroup.procs2. The existing six native entries
                // already cover six of those nine names.
                .checked_add(ResourceVector::ZERO.with(D::MetadataEntries, 3))?;
        }
        if self.role == FixedServiceRoleV1::BootPreparation {
            // The actual aos.slice/aos-control.slice/publisher path has three
            // components, like Network's main path. Count those native names
            // before capture; the inline policy vectors add no namespaces.
            physical = physical.checked_add(
                ResourceVector::ZERO.with(D::MetadataEntries, 3),
            )?;
        }
        if physical.get(D::OpenFiles) > permanent {
            return Err(AccountingError::LimitExceeded { dimension: D::OpenFiles, limit: permanent, attempted: physical.get(D::OpenFiles) });
        }
        // Actual persistent usage, including H+N, was charged first from the
        // SAME genuine final transfer. This fresh debit preserves every other
        // dimension and adds no duplicate descriptor-table promise.
        Ok(physical)
    }

    fn capture_native(&mut self, hardcap: ResourceVector) -> Result<(), E> {
        self.process_before = Some(self.process.capture_current());
        if self.process_before.as_ref().is_none_or(Result::is_err) { return Err(self.fail(Failure::Process)); }
        self.cgroup_result = Some(self.cgroup_capture.capture_once());
        if self.cgroup_result.as_ref().is_none_or(Result::is_err) { return Err(self.fail(Failure::Cgroup)); }
        let (hierarchy, cgroup) = self.cgroup_capture.take_validated_pair().ok_or(E::default())?;
        self.hierarchy = Some(hierarchy);
        self.cgroup = Some(cgroup);
        let cgroup = self.cgroup.as_ref().ok_or(E::default())?;
        self.membership_entry = Some(self.membership_capture.capture_once(
            cgroup, self.process.pidfd().map_err(|_| E::default())?,
        ));
        self.membership = Some(if matches!(self.membership_entry, Some(Ok(()))) {
            self.membership_capture.result().and_then(|result| result.as_ref().ok())
                .copied().ok_or(E::default())
        } else {
            Err(E::default())
        });
        if self.membership.as_ref().is_none_or(Result::is_err) { return Err(self.fail(Failure::Membership)); }
        self.limits.capture(cgroup, hardcap);
        if self.limits.require_initial().is_err() { return Err(self.fail(Failure::Limits)); }
        self.limits.recheck(cgroup);
        if self.limits.require_current().is_err() { return Err(self.fail(Failure::Limits)); }
        if matches!(self.role, FixedServiceRoleV1::Network) {
            self.network_aggregate = Some(Box::new(super::network_receiving_aggregate::
                NetworkReceivingAggregateOriginalV4::new()));
            let aggregate = self.network_aggregate.as_mut().ok_or(E::default())?;
            if aggregate.capture_once_v4(cgroup, hardcap).is_err() {
                return Err(self.fail(Failure::NetworkAggregate));
            }
        }
        let initial_info = self.membership.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(E::default())?;
        let initial_identity = self.process_before.as_ref().and_then(|result| result.as_ref().ok()).copied().ok_or(E::default())?;
        self.startup_currentness_result = Some(match self.network_aggregate.as_ref() {
            Some(aggregate) => self.startup_currentness.observe_network_aggregate_once_v4(
                &mut self.process, cgroup, &self.limits, initial_info, initial_identity,
                self.role.context(), self.role.context().is_some(), aggregate),
            None => self.startup_currentness.observe_once(&mut self.process, cgroup, &self.limits,
                initial_info, initial_identity, self.role.context(), self.role.context().is_some()),
        });
        if !matches!(self.startup_currentness_result, Some(Ok(()))) {
            return Err(self.fail(Failure::StartupCurrentness));
        }
        self.process_after = Some(self.process.observe_identity());
        if self.process_after.as_ref().is_none_or(Result::is_err) { return Err(self.fail(Failure::ProcessPost)); }
        self.final_binding = Some(self.require_final_binding());
        if self.final_binding.as_ref().is_none_or(Result::is_err) { return Err(self.fail(Failure::FinalBinding)); }
        Ok(())
    }

    fn require_final_binding(&self) -> Result<(), E> {
        let before = self.process_before.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
        let after = self.process_after.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::default())?;
        let packet = &self.parts[0].as_ref().ok_or(E::default())?.payload;
        let expected_cgroup = read_u64::<E>(&packet[32..40])?;
        let ticks_per_second = rustix::param::clock_ticks_per_second();
        let start = u128::from(before.start_time_ticks()).checked_mul(1_000_000)
            .and_then(|value| value.checked_div(u128::from(ticks_per_second))).ok_or(E::default())?;
        if matches!(self.role, FixedServiceRoleV1::Ownership | FixedServiceRoleV1::Mount
            | FixedServiceRoleV1::Network | FixedServiceRoleV1::BootPreparation) {
            let credentials = self.membership.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|info| info.credentials()).ok_or(E::default())?;
            if [
                credentials.real_user_id(), credentials.real_group_id(),
                credentials.effective_user_id(), credentials.effective_group_id(),
                credentials.saved_user_id(), credentials.saved_group_id(),
                credentials.filesystem_user_id(), credentials.filesystem_group_id(),
            ].iter().any(|identity| *identity != 0) {
                return Err(E::default());
            }
        }
        if before != after || before.pid() != std::process::id() || before.parent_pid() != 1
            || before.thread_group_id() != std::process::id() || expected_cgroup == 0
            || before.cgroup_id() != Some(expected_cgroup)
            || self.cgroup.as_ref().ok_or(E::default())?.kernel_id() != expected_cgroup
            || start != u128::from(read_u64::<E>(&packet[48..56])?)
            || !self.role.identity_matches() {
            return Err(E::default());
        }
        self.require_pid1_peer()
    }

    /// Checks complete actual F3/profile/native conjunction and the same debit.
    ///
    /// # Errors
    /// Refuses any incomplete, changed or undercharged actual original.
    pub fn require_permanent_fd_coverage_v1(&self) -> Result<(), E> {
        if self.first.is_some() || !self.transfer.complete()
            || self.profile.require_complete().is_err()
            || !matches!(self.final_binding, Some(Ok(())))
            || !matches!(self.startup_currentness_result, Some(Ok(())))
            || self.startup_currentness.failure().is_some()
            || self.limits.require_current().is_err()
        {
            return Err(E::default());
        }
        if matches!(self.role, FixedServiceRoleV1::Network)
            && self.network_aggregate.as_ref().is_none_or(|owner| owner.require_current_data_v4().is_err())
        { return Err(E::default()); }
        let peak = self.transfer.permanent_open_files()?;
        if self.representation.as_ref().ok_or(E::default())?.charged().get(D::OpenFiles) != peak {
            return Err(E::default());
        }
        Ok(())
    }

    /// Returns the actual final transfer's permanent descriptor debt DATA.
    ///
    /// # Errors
    /// Refuses an incomplete or malformed original transfer.
    pub fn permanent_open_files(&self) -> Result<u64, E> {
        self.transfer.permanent_open_files()
    }

    /// Borrows the earliest retained failure without resampling any original.
    pub fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let site = self.first?;
        match site {
            Failure::Table => self.table.failure().map(|error| error as _),
            Failure::Names => failure(&self.names),
            Failure::Channel => failure(&self.channel),
            Failure::Peer => failure(&self.peer),
            Failure::Poll(index) => failure(&self.polls[index]),
            Failure::Receive(index) => self.receive_failures[index].as_ref().map(|error| error as _),
            Failure::Part(index) => failure(&self.part_checks[index]),
            Failure::Pair => self.pair.failure(),
            Failure::ParentMetadata => failure(&self.parent_metadata),
            Failure::ParentFilesystem => failure(&self.parent_filesystem),
            Failure::ParentFlags => failure(&self.parent_flags),
            Failure::ParentSize => failure(&self.parent_size),
            Failure::ParentRead => failure(&self.parent_read),
            Failure::Parent => failure(&self.parent).or_else(|| self.closed.as_ref().map(|cause| cause as _)),
            Failure::Demand => failure(&self.demand),
            Failure::Accounting => self.representation.as_ref().and_then(|ledger| ledger.failure()).map(|error| error as _),
            Failure::Process => failure(&self.process_before),
            Failure::Cgroup => self.cgroup_capture.failure().or_else(|| failure(&self.cgroup_result)),
            Failure::NetworkAggregate => self.network_aggregate.as_ref().and_then(|owner| owner.failure()),
            Failure::Membership => self.membership_capture.failure()
                .map(|cause| cause as &(dyn Error + 'static))
                .or_else(|| failure(&self.membership_entry))
                .or_else(|| failure(&self.membership)),
            Failure::Limits => self.limits.failure(),
            Failure::ProcessPost => failure(&self.process_after),
            Failure::FinalBinding => failure(&self.final_binding),
            Failure::Transfer => self.transfer.failure(),
            Failure::Profile => self.profile.failure(),
            Failure::StartupCurrentness => self.startup_currentness.failure().or_else(|| failure(&self.startup_currentness_result)),
            Failure::Closed => self.closed.as_ref().map(|error| error as _),
        }.or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl<E> Drop for FixedServiceReceivingCaptureV1<E> {
    fn drop(&mut self) {
        if self.entered { std::process::abort(); }
    }
}

fn failure<T, E: Error + 'static>(result: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    result.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}

fn read_u64<E: Default>(bytes: &[u8]) -> Result<u64, E> {
    super::fixed_service_transfer::read_u64::<E>(bytes)
}

fn read_vector<E: Default>(bytes: &[u8]) -> Result<ResourceVector, E> {
    super::fixed_service_transfer::read_vector::<E>(bytes)
}

fn require_origin_header<E: Default>(payload: &[u8], index: usize, role: FixedServiceRoleV1, pid: u32)
    -> Result<(), E>
{
    let magic = match role {
        FixedServiceRoleV1::Network => b"AOSRSO02",
        FixedServiceRoleV1::BootPreparation => b"AOSRSO03",
        _ => b"AOSRSO01",
    };
    if payload.len() != if index == 3 { FIXED_SERVICE_FINAL_TRANSFER_BYTES } else { FIXED_SERVICE_ORIGIN_HEADER_BYTES }
        || &payload[..8] != magic || payload[8] != index as u8
        || payload[9] != role as u8 || payload[10..16] != [0; 6]
        || read_u64::<E>(&payload[40..48])? != u64::from(pid) {
        return Err(E::default());
    }
    Ok(())
}

#[cfg(test)]
mod origin_header_tests {
    use super::*;

    #[test]
    fn boot_origin_never_reuses_canary_or_another_service_contract() {
        for index in 0..MAXIMUM_PARTS {
            let length = if index == 3 {
                FIXED_SERVICE_FINAL_TRANSFER_BYTES
            } else {
                FIXED_SERVICE_ORIGIN_HEADER_BYTES
            };
            let mut payload = vec![0u8; length];
            payload[..8].copy_from_slice(b"AOSRSO03");
            payload[8] = index as u8;
            payload[9] = FixedServiceRoleV1::BootPreparation as u8;
            payload[40..48].copy_from_slice(&42u64.to_be_bytes());

            assert!(require_origin_header::<()>(&payload, index, FixedServiceRoleV1::BootPreparation, 42).is_ok());
            for old_magic in [b"AOSRSO01", b"AOSRSO02"] {
                payload[..8].copy_from_slice(old_magic);
                assert!(require_origin_header::<()>(&payload, index, FixedServiceRoleV1::BootPreparation, 42).is_err());
            }

            payload[..8].copy_from_slice(b"AOSRSO03");
            for foreign in [FixedServiceRoleV1::Source, FixedServiceRoleV1::Ownership,
                FixedServiceRoleV1::Cache, FixedServiceRoleV1::Mount, FixedServiceRoleV1::Network]
            {
                payload[9] = foreign as u8;
                assert!(require_origin_header::<()>(&payload, index, foreign, 42).is_err());
            }
        }
    }

    #[test]
    fn cache_origin_is_never_a_source_or_ownership_delivery() {
        let mut payload = [0u8; FIXED_SERVICE_ORIGIN_HEADER_BYTES];
        payload[..8].copy_from_slice(b"AOSRSO01");
        payload[9] = FixedServiceRoleV1::Cache as u8;
        payload[40..48].copy_from_slice(&42u64.to_be_bytes());

        assert!(require_origin_header::<()>(&payload, 0, FixedServiceRoleV1::Cache, 42).is_ok());
        for foreign in [FixedServiceRoleV1::Source, FixedServiceRoleV1::Ownership] {
            assert!(require_origin_header::<()>(&payload, 0, foreign, 42).is_err());
            payload[9] = foreign as u8;
            assert!(require_origin_header::<()>(&payload, 0, FixedServiceRoleV1::Cache, 42).is_err());
            payload[9] = FixedServiceRoleV1::Cache as u8;
        }
    }

    #[test]
    fn actual_common_predicate_refuses_foreign_role_and_unrelated_reserved_header() {
        let mut payload = [0u8; FIXED_SERVICE_ORIGIN_HEADER_BYTES];
        payload[..8].copy_from_slice(b"AOSRSO01");
        payload[9] = FixedServiceRoleV1::Ownership as u8;
        payload[40..48].copy_from_slice(&42u64.to_be_bytes());
        assert!(require_origin_header::<()>(&payload, 0, FixedServiceRoleV1::Ownership, 42).is_ok());
        assert!(require_origin_header::<()>(&payload, 0, FixedServiceRoleV1::Source, 42).is_err());
        payload[10] = 1;
        assert!(require_origin_header::<()>(&payload, 0, FixedServiceRoleV1::Ownership, 42).is_err());
        payload[10] = 0;
        payload[8] = 1;
        assert!(require_origin_header::<()>(&payload, 0, FixedServiceRoleV1::Ownership, 42).is_err());
        assert!(require_origin_header::<()>(&payload[..20], 0, FixedServiceRoleV1::Ownership, 42).is_err());
    }
    #[test]
    fn network_source_requires_new_native_contract_on_every_original_record() {
        for index in 0..4 {
            let length = if index == 3 {
                FIXED_SERVICE_FINAL_TRANSFER_BYTES
            } else {
                FIXED_SERVICE_ORIGIN_HEADER_BYTES
            };
            let mut payload = vec![0u8; length];
            payload[..8].copy_from_slice(b"AOSRSO01");
            payload[8] = index as u8;
            payload[9] = FixedServiceRoleV1::Network as u8;
            payload[40..48].copy_from_slice(&42u64.to_be_bytes());
            assert!(require_origin_header::<()>(&payload, index, FixedServiceRoleV1::Network, 42).is_err());

            payload[..8].copy_from_slice(b"AOSRSO02");
            assert!(require_origin_header::<()>(&payload, index, FixedServiceRoleV1::Network, 42).is_ok());
            assert!(require_origin_header::<()>(&payload[..length - 1], index, FixedServiceRoleV1::Network, 42).is_err());
            payload.push(0);
            assert!(require_origin_header::<()>(&payload, index, FixedServiceRoleV1::Network, 42).is_err());
            payload.pop();

            for role in [FixedServiceRoleV1::Source, FixedServiceRoleV1::Ownership,
                         FixedServiceRoleV1::Cache, FixedServiceRoleV1::Mount] {
                payload[9] = role as u8;
                assert!(require_origin_header::<()>(&payload, index, role, 42).is_err());
                payload[..8].copy_from_slice(b"AOSRSO01");
                assert!(require_origin_header::<()>(&payload, index, role, 42).is_ok());
                payload[..8].copy_from_slice(b"AOSRSO02");
            }
        }
    }

}
