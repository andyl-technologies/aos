//! Shares actual ordinary and original authenticated root-mount export.
//!
//! The complete original Host request crosses the existing Storage socket.
//! Only the genuine original Launch borrower funds this mechanical owner;
//! Storage independently authenticates and finances its own actual export.

use std::error::Error;
use std::mem::size_of;
use std::os::fd::AsFd as _;
use std::path::Path;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_guest_root_realization::guest_root_label::GuestRootLabelReadOriginalV1;
use aos_sandbox_linux::cgroup::{
    CgroupV2Root, ExactCgroupMembershipReadbackV1, RetainedCgroupAnchor,
    RuntimeScopeMembershipOriginalV1, WorkerCgroupOpeningV1,
};
use aos_sandbox_linux::mount::{DetachedMount, MountAdoptionFailureV2};
use aos_sandbox_linux::seqpacket::descriptor_subject::{
    DescriptorSubjectSocket, ReceivedDescriptorRecord,
};
use aos_sandbox_linux::seqpacket::{
    RecordBindingError, RetainedSeqpacketAdmissionErrorV1, SeqpacketError,
};
use aos_sandbox_protocol::session::AuthorizationArtifactBytes;
use aos_sandbox_protocol::storage_root_export::launch::StorageRootLaunchExportRequestV2;
use aos_sandbox_protocol::storage_root_export::{
    STORAGE_ROOT_EXPORT_REQUEST_BYTES_V1, STORAGE_ROOT_EXPORT_RESPONSE_BYTES_V1, StorageRootExportProtocolErrorV1,
    StorageRootExportRequestV1, StorageRootExportResponseV1,
};
use rand::{TryRngCore as _, rngs::OsRng};

use super::transport_v2::{self, StorageClientTransportErrorV2};

mod receiving;
use crate::plan::{HostLaunchCatalogReceivingV2, ResolvedWorkspace};
use crate::{HostError, Result};
use receiving::label_receiving_limits;

#[derive(Debug, thiserror::Error)]
enum SocketOpeningErrorV2 {
    #[error(transparent)]
    Ordinary(SeqpacketError),
    #[error(transparent)]
    Retained(RetainedSeqpacketAdmissionErrorV1),
}

#[derive(Debug)]
enum MountOpeningErrorV2 {
    Ordinary(aos_linux_descriptors::Error),
    Retained(MountAdoptionFailureV2),
}

impl MountOpeningErrorV2 {
    fn cause(&self) -> &aos_linux_descriptors::Error {
        match self {
            Self::Ordinary(cause) => cause,
            Self::Retained(failure) => failure.cause(),
        }
    }

    fn retained_fd(&self) -> Option<std::os::fd::BorrowedFd<'_>> {
        match self {
            Self::Ordinary(_) => None,
            Self::Retained(failure) => Some(failure.as_fd()),
        }
    }
}

#[derive(Clone, Copy)]
enum FirstV2 {
    Fixed,
    Funding,
    Opening,
    Active,
    Socket,
    Entropy,
    Deadline,
    Frame,
    FrameFunding,
    Send,
    Receive,
    Binding,
    Membership,
    Alive,
    Response,
    Mount,
    Stat,
    FinalMembership,
    FinalAlive,
    FinalClock,
    LabelFunding,
    Labels,
    Returned,
}

/// Retains one whole actual root-export native flight without lending authority.
pub(crate) struct HostRootMountExportOriginalV2 {
    fixed: Option<Result<ResourceVector>>,
    funding: Option<Result<()>>,
    opening: WorkerCgroupOpeningV1,
    opening_result: Option<Result<()>>,
    opening_clock: Option<std::result::Result<u64, StorageClientTransportErrorV2>>,
    opening_gate: Option<Result<()>>,
    native: RootMountRecipeOriginalV2,
    returned: Option<Result<DetachedMount>>,
    cutoff: Option<u64>,
    mount_post: Option<aos_linux_descriptors::Result<aos_sandbox_linux::inventory::MountId>>,
    parent_post: Option<Result<()>>,
    socket_post: Option<std::result::Result<(), SeqpacketError>>,
    posts: Option<Result<()>>,
    final_current: Option<Result<()>>,
    entered: bool,
    closed: Option<HostError>,
}

impl HostRootMountExportOriginalV2 {
    /// Creates inert fixed custody without opening native resources.
    pub(crate) fn new() -> Self {
        Self {
            fixed: None,
            funding: None,
            opening: WorkerCgroupOpeningV1::new(),
            opening_result: None,
            opening_clock: None,
            opening_gate: None,
            native: RootMountRecipeOriginalV2::new(),
            returned: None,
            cutoff: None,
            mount_post: None,
            parent_post: None,
            socket_post: None,
            posts: None,
            final_current: None,
            entered: false,
            closed: None,
        }
    }

    /// Exports only under the matching actual original paid Launch flight.
    ///
    /// # Errors
    /// Refuses reentry, funding/currentness, native prefixes, authenticated
    /// response/mount/label predicates, timeout, or independently owed posts.
    pub(crate) fn export_launch_once(
        &mut self,
        root: &CgroupV2Root,
        workspace: &ResolvedWorkspace,
        receiving: &mut HostLaunchCatalogReceivingV2<'_, '_>,
    ) -> Result<DetachedMount> {
        if self.entered {
            self.closed.get_or_insert_with(closed);
            return Err(closed());
        }
        self.entered = true;
        self.cutoff = Some(receiving.original_deadline_v2());
        self.fixed = Some(Self::fixed_demand());
        self.funding = Some(receiving.admit_additional_demand_v2(*positive(&self.fixed)?));
        positive(&self.funding)?;
        self.opening_clock = Some(transport_v2::boottime_v2());
        self.opening_gate = Some((|| {
            let now = *positive_transport(&self.opening_clock)?;
            if self.cutoff.is_none_or(|deadline| now >= deadline) {
                return Err(closed());
            }
            Ok(())
        })());
        if !matches!(self.opening_gate, Some(Ok(()))) {
            return Err(closed());
        }
        self.opening_result = Some(
            self.opening
                .capture_root_descendant_once(root, Path::new(super::STORAGE_CGROUP))
                .map_err(|_| closed()),
        );
        self.returned = Some(match positive(&self.opening_result) {
            Ok(()) => match self.opening.anchor() {
                Some(anchor) => {
                    // The existing child recipe owns this actual anchor. This
                    // borrow stays under the same outer native owner throughout.
                    export_recipe(
                        anchor,
                        workspace,
                        ExportModeV2::Launch(receiving),
                        &mut self.native,
                    )
                }
                None => Err(closed()),
            },
            Err(_) => Err(closed()),
        });
        self.finish_posts(root);
        self.final_current = Some(receiving.require_current_v2());
        if !matches!(self.returned, Some(Ok(_)))
            || !matches!(self.posts, Some(Ok(())))
            || !matches!(self.final_current, Some(Ok(())))
        {
            return Err(closed());
        }
        match self.returned.take() {
            Some(Ok(mount)) => Ok(mount),
            _ => std::process::abort(),
        }
    }
}

fn closed() -> HostError {
    HostError::Fence("original Host root export is incomplete; native custody retained")
}

fn positive<T, E: std::fmt::Display>(slot: &Option<std::result::Result<T, E>>) -> Result<&T> {
    match slot {
        Some(Ok(value)) => Ok(value),
        Some(Err(cause)) => Err(super::export_error(cause)),
        None => Err(closed()),
    }
}

enum ExportFrameV2 {
    Ordinary([u8; STORAGE_ROOT_EXPORT_REQUEST_BYTES_V1]),
    Launch(Vec<u8>),
}

impl ExportFrameV2 {
    fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Ordinary(bytes) => bytes,
            Self::Launch(bytes) => bytes,
        }
    }
}

struct RootMountRecipeOriginalV2 {
    active: RuntimeScopeMembershipOriginalV1,
    active_result: Option<aos_linux_descriptors::Result<()>>,
    socket: Option<std::result::Result<DescriptorSubjectSocket, SocketOpeningErrorV2>>,
    nonce: [u8; 32],
    entropy: Option<std::result::Result<(), rand::rand_core::OsError>>,
    deadline: Option<Result<u64>>,
    frame: Option<std::result::Result<ExportFrameV2, StorageRootExportProtocolErrorV1>>,
    frame_funding: Option<Result<()>>,
    digest: Option<[u8; 32]>,
    send: Option<std::result::Result<(), StorageClientTransportErrorV2>>,
    receive: Option<std::result::Result<ReceivedDescriptorRecord, StorageClientTransportErrorV2>>,
    binding: Option<std::result::Result<(), RecordBindingError>>,
    membership: [ExactCgroupMembershipReadbackV1; 3],
    alive: [Option<aos_linux_descriptors::Result<bool>>; 3],
    response:
        Option<std::result::Result<StorageRootExportResponseV1, StorageRootExportProtocolErrorV1>>,
    payload: Option<Vec<u8>>,
    subject: Option<aos_sandbox_linux::seqpacket::KernelAuthorizedRecordSubject>,
    descriptors: Vec<std::os::fd::OwnedFd>,
    mount: Option<std::result::Result<DetachedMount, MountOpeningErrorV2>>,
    stat: [Option<rustix::io::Result<rustix::fs::Stat>>; 2],
    clock: [Option<std::result::Result<u64, StorageClientTransportErrorV2>>; 3],
    labels: Option<GuestRootLabelReadOriginalV1>,
    label_funding: Option<Result<()>>,
    label_demand: Option<ResourceVector>,
    labels_result: Option<Result<()>>,
    label_clock: Option<std::result::Result<u64, StorageClientTransportErrorV2>>,
    membership_results: [Option<Result<aos_linux_descriptors::pidfd::PidFdInfo>>; 3],
    first: Option<FirstV2>,
}

impl RootMountRecipeOriginalV2 {
    fn new() -> Self {
        Self {
            active: RuntimeScopeMembershipOriginalV1::new(),
            active_result: None,
            socket: None,
            nonce: [0; 32],
            entropy: None,
            deadline: None,
            frame: None,
            frame_funding: None,
            digest: None,
            send: None,
            receive: None,
            binding: None,
            membership: std::array::from_fn(|_| ExactCgroupMembershipReadbackV1::new()),
            alive: std::array::from_fn(|_| None),
            response: None,
            payload: None,
            subject: None,
            descriptors: Vec::new(),
            mount: None,
            stat: std::array::from_fn(|_| None),
            clock: std::array::from_fn(|_| None),
            labels: None,
            label_funding: None,
            label_demand: None,
            labels_result: None,
            label_clock: None,
            membership_results: std::array::from_fn(|_| None),
            first: None,
        }
    }
}

// Ordinary acquisition keeps its original timeout, IO/check order and local
// disposition. The selected path uses only the real original Launch cutoff.
enum ExportModeV2<'visit, 'catalog, 'original> {
    Ordinary,
    Launch(&'visit mut HostLaunchCatalogReceivingV2<'catalog, 'original>),
}

impl ExportModeV2<'_, '_, '_> {
    fn retained(&self) -> bool {
        matches!(self, Self::Launch(_))
    }
}

pub(super) fn export_ordinary(
    anchor: &RetainedCgroupAnchor,
    workspace: &ResolvedWorkspace,
) -> Result<DetachedMount> {
    let mut native = RootMountRecipeOriginalV2::new();
    let result = export_recipe(anchor, workspace, ExportModeV2::Ordinary, &mut native);
    native.dispose_ordinary();
    result
}

fn export_recipe(
    anchor: &RetainedCgroupAnchor,
    workspace: &ResolvedWorkspace,
    mut mode: ExportModeV2<'_, '_, '_>,
    native: &mut RootMountRecipeOriginalV2,
) -> Result<DetachedMount> {
    // One shared recipe parks the actual returned Result before interpreting
    // it. An ordinary local owner ends at the same returning error frontier;
    // a selected owner survives through every independently owed post.
    macro_rules! observe {
        ($field:ident, $stage:ident, $operation:expr) => {{
            native.$field = Some($operation);
            if native.$field.as_ref().is_some_and(|value| value.is_err()) {
                native.first.get_or_insert(FirstV2::$stage);
            }
            positive(&native.$field)?
        }};
    }

    let retained = mode.retained();
    let proof = workspace.guest_root_publication().ok_or_else(|| {
        HostError::Catalog("workspace lacks guest-root publication proof".to_owned())
    })?;
    observe!(
        active_result,
        Active,
        if retained {
            native.active.capture_active_once(anchor)
        } else {
            anchor.validate_current()
        }
    );
    observe!(
        socket,
        Socket,
        if retained {
            DescriptorSubjectSocket::connect_retaining_raw_v2(Path::new(super::EXPORT_SOCKET))
                .map_err(SocketOpeningErrorV2::Retained)
        } else {
            DescriptorSubjectSocket::connect(Path::new(super::EXPORT_SOCKET))
                .map_err(SocketOpeningErrorV2::Ordinary)
        }
    );
    native.entropy = Some(OsRng.try_fill_bytes(&mut native.nonce));
    if !matches!(native.entropy, Some(Ok(()))) {
        native.first.get_or_insert(FirstV2::Entropy);
        return Err(HostError::State(
            "root export entropy unavailable".to_owned(),
        ));
    }
    if native.nonce == [0; 32] {
        return Err(HostError::State("root export nonce is invalid".to_owned()));
    }
    native.clock[0] = Some(transport_v2::boottime_v2());
    native.deadline = Some((|| {
        let now = *positive_transport(&native.clock[0])?;
        match &mode {
            ExportModeV2::Ordinary => now
                .checked_add(super::EXPORT_DEADLINE_NANOSECONDS)
                .ok_or_else(|| HostError::State("root export deadline overflow".to_owned())),
            ExportModeV2::Launch(receiving) => {
                let deadline = receiving.original_deadline_v2();
                if now >= deadline {
                    return Err(closed());
                }
                Ok(deadline)
            }
        }
    })());
    if native.deadline.as_ref().is_some_and(|value| value.is_err()) {
        native.first.get_or_insert(FirstV2::Deadline);
    }
    let deadline = copied_host(&mut native.deadline, retained)?;
    let request = StorageRootExportRequestV1 {
        nonce: native.nonce,
        deadline_boottime_nanoseconds: deadline,
        proof,
    };
    match &mut mode {
        ExportModeV2::Ordinary => {
            native.frame = Some(request.encode().map(ExportFrameV2::Ordinary));
            // Preserve the ordinary response's original request digest recipe.
        }
        ExportModeV2::Launch(receiving) => {
            // Measure the already-owned exact original segments before the
            // frame allocation; these borrowed bytes grant no authority.
            let input = receiving.authenticated_request_v2();
            let authorization = input.authorization().ok_or_else(closed)?;
            let bytes = [input.exact_body(), authorization.broker_plan(),
                authorization.broker_plan_signature(), authorization.ownership_lease(),
                authorization.ownership_lease_signature()].into_iter()
                .try_fold(aos_sandbox_protocol::storage_root_export::launch::STORAGE_ROOT_LAUNCH_EXPORT_PREFIX_BYTES_V2,
                    |sum, bytes| sum.checked_add(bytes.len()))
                .ok_or(HostError::ResourceExhausted)?;
            let memory = bytes
                .checked_mul(2)
                .and_then(|n| n.checked_add(2 * size_of::<StorageRootLaunchExportRequestV2<'_>>()))
                .ok_or(HostError::ResourceExhausted)?;
            native.frame_funding = Some(
                receiving.admit_additional_demand_v2(
                    ResourceVector::ZERO
                        .with(
                            D::MemoryBytes,
                            u64::try_from(memory).map_err(|_| HostError::ResourceExhausted)?,
                        )
                        .with(
                            D::OutputBytes,
                            u64::try_from(bytes).map_err(|_| HostError::ResourceExhausted)?,
                        )
                        .with(
                            D::NetworkBytes,
                            u64::try_from(bytes).map_err(|_| HostError::ResourceExhausted)?,
                        ),
                ),
            );
            if !matches!(native.frame_funding, Some(Ok(()))) {
                native.first.get_or_insert(FirstV2::FrameFunding);
                return Err(closed());
            }
            let input = receiving.authenticated_request_v2();
            let authorization = input.authorization().ok_or_else(closed)?;
            native.frame = Some(
                StorageRootLaunchExportRequestV2::new(
                    request,
                    input.exact_body(),
                    AuthorizationArtifactBytes {
                        broker_plan: authorization.broker_plan(),
                        broker_plan_signature: authorization.broker_plan_signature(),
                        ownership_lease: authorization.ownership_lease(),
                        ownership_lease_signature: authorization.ownership_lease_signature(),
                    },
                )
                .map(|frame| {
                    native.digest = Some(frame.digest());
                    ExportFrameV2::Launch(frame.encode())
                }),
            );
        }
    }
    if native.frame.as_ref().is_some_and(|value| value.is_err()) {
        native.first.get_or_insert(FirstV2::Frame);
    }
    let bytes = positive(&native.frame)?.as_bytes();
    let socket = native
        .socket
        .as_mut()
        .and_then(|value| value.as_mut().ok())
        .ok_or_else(closed)?;
    native.send = Some(transport_v2::send_request_recipe_v2(
        socket, bytes, deadline, retained,
    ));
    if !matches!(native.send, Some(Ok(()))) {
        native.first.get_or_insert(FirstV2::Send);
        positive_transport(&native.send)?;
        return Err(closed());
    }
    native.receive = Some(if retained {
        transport_v2::receive_root_mount_reply_retaining_v2(
            socket,
            deadline,
            STORAGE_ROOT_EXPORT_RESPONSE_BYTES_V1,
        )
    } else {
        transport_v2::receive_reply_recipe_v2(
            socket,
            deadline,
            STORAGE_ROOT_EXPORT_RESPONSE_BYTES_V1,
            1,
            false,
        )
    });
    if native.receive.as_ref().is_some_and(|value| value.is_err()) {
        native.first.get_or_insert(FirstV2::Receive);
    }
    let record = positive_transport(&native.receive)?;
    native.binding = Some(if retained {
        socket.validate_received_origin_retaining(record)
    } else {
        socket.validate_received_origin(record)
    });
    if !matches!(native.binding, Some(Ok(()))) {
        native.first.get_or_insert(FirstV2::Binding);
    }
    positive(&native.binding)?;
    let credentials = record.subject().credentials();
    if credentials.uid() != 0 || credentials.gid() != 0 {
        return Err(HostError::State(
            "root export responder is invalid".to_owned(),
        ));
    }
    native.membership_results[0] = Some(observe_membership(
        anchor,
        record.subject().pidfd(),
        retained,
        &mut native.membership[0],
    ));
    if !matches!(native.membership_results[0], Some(Ok(_))) {
        native.first.get_or_insert(FirstV2::Membership);
    }
    let info = copied_host(&mut native.membership_results[0], retained)?;
    if info.pid() != credentials.pid().get() || info.thread_group_id() != info.pid() {
        return Err(HostError::State(
            "root export responder is invalid".to_owned(),
        ));
    }
    native.alive[0] = Some(record.subject().is_alive());
    if native.alive[0].as_ref().is_some_and(|value| value.is_err()) {
        native.first.get_or_insert(FirstV2::Alive);
    }
    if !*positive(&native.alive[0])? || record.descriptors().len() != 1 {
        return Err(HostError::State(
            "root export responder is invalid".to_owned(),
        ));
    }
    observe!(
        response,
        Response,
        StorageRootExportResponseV1::decode(record.payload())
    );
    let response = positive(&native.response)?;
    let request_digest = if retained {
        native.digest.ok_or_else(closed)?
    } else {
        request.digest().map_err(super::export_error)?
    };
    if response.nonce != native.nonce
        || response.request_digest != request_digest
        || response.root_device != workspace.device
        || response.root_inode != workspace.inode
    {
        return Err(HostError::State(
            "root export reply differs from catalog".to_owned(),
        ));
    }
    let (payload, subject, descriptors) = match native.receive.take() {
        Some(Ok(record)) => record.into_parts(),
        _ => std::process::abort(),
    };
    if retained {
        native.payload = Some(payload);
    } else {
        drop(payload);
    }
    native.subject = Some(subject);
    native.descriptors = descriptors;
    let descriptor = native
        .descriptors
        .pop()
        .ok_or_else(|| HostError::State("root export FD absent".to_owned()))?;
    native.mount = Some(if retained {
        DetachedMount::from_inherited_retaining_v2(descriptor)
            .map_err(MountOpeningErrorV2::Retained)
    } else {
        DetachedMount::from_inherited(descriptor).map_err(MountOpeningErrorV2::Ordinary)
    });
    if !matches!(native.mount, Some(Ok(_))) {
        native.first.get_or_insert(FirstV2::Mount);
    }
    let mount = match native.mount.as_ref() {
        Some(Ok(mount)) => mount,
        Some(Err(failure)) => return Err(super::export_error(failure.cause())),
        None => return Err(closed()),
    };
    native.stat[0] = Some(rustix::fs::fstat(mount.as_fd()));
    if native.stat[0].as_ref().is_some_and(|value| value.is_err()) {
        native.first.get_or_insert(FirstV2::Stat);
    }
    let stat = positive(&native.stat[0])?;
    let response = positive(&native.response)?;
    if stat.st_dev != response.root_device
        || stat.st_ino != response.root_inode
        || mount.mount_id().get() != response.detached_mount_id
    {
        return Err(HostError::State(
            "root export mount identity changed".to_owned(),
        ));
    }
    native.clock[1] = Some(transport_v2::boottime_v2());
    if native.clock[1].as_ref().is_some_and(|value| value.is_err()) {
        native.first.get_or_insert(FirstV2::FinalClock);
    }
    if *positive_transport(&native.clock[1])? >= deadline {
        return Err(HostError::State(
            "root export mount identity changed".to_owned(),
        ));
    }
    let subject = native.subject.as_ref().ok_or_else(closed)?;
    native.membership_results[1] = Some(observe_membership(
        anchor,
        subject.pidfd(),
        retained,
        &mut native.membership[1],
    ));
    if !matches!(native.membership_results[1], Some(Ok(_))) {
        native.first.get_or_insert(FirstV2::FinalMembership);
    }
    if copied_host(&mut native.membership_results[1], retained)? != info {
        return Err(HostError::State(
            "root export mount identity changed".to_owned(),
        ));
    }
    native.alive[1] = Some(subject.is_alive());
    if native.alive[1].as_ref().is_some_and(|value| value.is_err()) {
        native.first.get_or_insert(FirstV2::FinalAlive);
    }
    if !*positive(&native.alive[1])? {
        return Err(HostError::State(
            "root export mount identity changed".to_owned(),
        ));
    }
    match &mut mode {
        ExportModeV2::Ordinary => {
            aos_sandbox_guest_root_realization::guest_root_label::verify_copied_guest_executable_labels_fd_v1(mount.as_fd())
                .map_err(|error| HostError::State(format!("root export payload labels invalid: {error}")))?;
        }
        ExportModeV2::Launch(receiving) => {
            let (depth, entries, demand) =
                label_receiving_limits(receiving.remaining_capacity_v2()?)?;
            native.label_demand = Some(demand);
            native.label_funding = Some(receiving.admit_additional_demand_v2(demand));
            if !matches!(native.label_funding, Some(Ok(()))) {
                native.first.get_or_insert(FirstV2::LabelFunding);
                return Err(closed());
            }
            native.labels = Some(
                GuestRootLabelReadOriginalV1::with_receiving_limits_v2(depth, entries)
                    .ok_or(HostError::ResourceExhausted)?,
            );
            let clock = &mut native.label_clock;
            native.labels_result = Some(
                native
                    .labels
                    .as_mut()
                    .ok_or_else(closed)?
                    .verify_before_once_v1(mount.as_fd(), &mut || {
                        if clock.as_ref().is_some_and(|value| value.is_err()) {
                            return false;
                        }
                        *clock = Some(transport_v2::boottime_v2());
                        matches!(clock, Some(Ok(now)) if *now < deadline)
                    })
                    .map_err(|_| closed()),
            );
            if !matches!(native.labels_result, Some(Ok(()))) {
                native.first.get_or_insert(FirstV2::Labels);
            }
            positive(&native.labels_result)?;
        }
    }
    match native.mount.take() {
        Some(Ok(mount)) => Ok(mount),
        _ => std::process::abort(),
    }
}

fn observe_membership(
    anchor: &RetainedCgroupAnchor,
    process: &aos_linux_descriptors::pidfd::PidFd,
    retained: bool,
    original: &mut ExactCgroupMembershipReadbackV1,
) -> Result<aos_linux_descriptors::pidfd::PidFdInfo> {
    if !retained {
        return anchor
            .verify_exact_membership(process)
            .map_err(super::export_error);
    }
    original
        .capture_once(anchor, process)
        .map_err(|_| closed())?;
    match original.result() {
        Some(Ok(info)) => Ok(*info),
        _ => Err(closed()),
    }
}

fn positive_transport<T>(
    slot: &Option<std::result::Result<T, StorageClientTransportErrorV2>>,
) -> Result<&T> {
    match slot {
        Some(Ok(value)) => Ok(value),
        Some(Err(StorageClientTransportErrorV2::Deadline)) => {
            Err(HostError::State("root export deadline elapsed".to_owned()))
        }
        Some(Err(StorageClientTransportErrorV2::ClockOverflow)) => {
            Err(HostError::State("root export clock overflow".to_owned()))
        }
        Some(Err(cause)) => Err(super::export_error(cause)),
        None => Err(closed()),
    }
}

fn cause<T, E: Error + 'static>(
    slot: &Option<std::result::Result<T, E>>,
) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

impl RootMountRecipeOriginalV2 {
    fn dispose_ordinary(&mut self) {
        // The old consuming recipe closes an unsuccessful mount first, then
        // its descriptor vector/record subject and finally the connection.
        // Selected custody never enters this ordinary destruction adapter.
        drop(self.mount.take());
        drop(std::mem::take(&mut self.descriptors));
        drop(self.subject.take());
        drop(self.receive.take());
        drop(self.payload.take());
        drop(self.frame.take());
        drop(self.socket.take());
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            FirstV2::Active => self
                .active
                .failure()
                .map(|cause| cause as _)
                .or_else(|| cause(&self.active_result)),
            FirstV2::Socket => cause(&self.socket),
            FirstV2::Entropy => cause(&self.entropy),
            FirstV2::Deadline => cause(&self.clock[0]).or_else(|| cause(&self.deadline)),
            FirstV2::Frame => cause(&self.frame),
            FirstV2::FrameFunding => cause(&self.frame_funding),
            FirstV2::Send => cause(&self.send),
            FirstV2::Receive => cause(&self.receive),
            FirstV2::Binding => cause(&self.binding),
            FirstV2::Membership => self.membership[0]
                .failure()
                .map(|cause| cause as _)
                .or_else(|| cause(&self.membership_results[0])),
            FirstV2::Alive => cause(&self.alive[0]),
            FirstV2::Response => cause(&self.response),
            FirstV2::Mount => self
                .mount
                .as_ref()?
                .as_ref()
                .err()
                .map(|failure| failure.cause() as _),
            FirstV2::Stat => cause(&self.stat[0]),
            FirstV2::FinalMembership => self.membership[1]
                .failure()
                .map(|cause| cause as _)
                .or_else(|| cause(&self.membership_results[1])),
            FirstV2::FinalAlive => cause(&self.alive[1]),
            FirstV2::FinalClock => cause(&self.clock[1]),
            FirstV2::LabelFunding => cause(&self.label_funding),
            FirstV2::Labels => cause(&self.label_clock)
                .or_else(|| self.labels.as_ref()?.failure())
                .or_else(|| cause(&self.labels_result)),
            FirstV2::Fixed | FirstV2::Funding | FirstV2::Opening | FirstV2::Returned => None,
        }
    }
}

impl HostRootMountExportOriginalV2 {
    fn finish_posts(&mut self, root: &CgroupV2Root) {
        // Every already-entered acquisition owes its independent native posts.
        // Do not interpret an earlier post until all reachable posts ran.
        if self.opening_result.is_some() {
            self.parent_post = Some(
                self.opening
                    .observe_root_parent_after_attempt_once(root)
                    .map_err(|_| closed()),
            );
        }
        if let Some(Ok(socket)) = self.native.socket.as_ref() {
            self.socket_post =
                Some(socket.observe_owed_peer_filesystem_path_v2(Path::new(super::EXPORT_SOCKET)));
        }
        let subject = self.native.subject.as_ref().or_else(|| {
            self.native
                .receive
                .as_ref()?
                .as_ref()
                .ok()
                .map(ReceivedDescriptorRecord::subject)
        });
        if let (Some(anchor), Some(subject)) = (self.opening.anchor(), subject) {
            self.native.membership_results[2] = Some(observe_membership(
                anchor,
                subject.pidfd(),
                true,
                &mut self.native.membership[2],
            ));
            self.native.alive[2] = Some(subject.is_alive());
        }
        let mount_fd = match &self.returned {
            Some(Ok(mount)) => Some(mount.as_fd()),
            _ => match self.native.mount.as_ref() {
                Some(Ok(mount)) => Some(mount.as_fd()),
                Some(Err(failure)) => failure.retained_fd(),
                None => None,
            },
        };
        if let Some(fd) = mount_fd {
            self.native.stat[1] = Some(rustix::fs::fstat(fd));
            self.mount_post = Some(aos_sandbox_linux::inventory::MountId::from_fd(fd));
        }
        if self.opening_result.is_some() {
            self.native.clock[2] = Some(transport_v2::boottime_v2());
        }
        self.posts = Some((|| {
            if self.opening_result.is_some() {
                positive(&self.parent_post)?;
            }
            if self
                .native
                .socket
                .as_ref()
                .is_some_and(|value| value.is_ok())
            {
                positive(&self.socket_post)?;
            }
            if self.native.membership_results[2].is_some() {
                let after = positive(&self.native.membership_results[2])?;
                if let Some(Ok(before)) = &self.native.membership_results[0] {
                    if before != after {
                        return Err(closed());
                    }
                }
                if !*positive(&self.native.alive[2])? {
                    return Err(closed());
                }
            }
            if self.native.stat[1].is_some() {
                let stat = positive(&self.native.stat[1])?;
                let mount = positive(&self.mount_post)?;
                if let Some(Ok(response)) = &self.native.response {
                    if stat.st_dev != response.root_device
                        || stat.st_ino != response.root_inode
                        || mount.get() != response.detached_mount_id
                    {
                        return Err(closed());
                    }
                }
            }
            if self.native.clock[2].is_some() {
                let now = *positive_transport(&self.native.clock[2])?;
                if self.cutoff.is_none_or(|deadline| now >= deadline) {
                    return Err(closed());
                }
            }
            Ok(())
        })());
    }

    /// Bounds completed export scratch while preserving the returned mount fee.
    ///
    /// # Errors
    /// Refuses an incomplete export, failed native post, or missing paid bound.
    pub(crate) fn completed_temporary_files_v2(&self) -> Result<u64> {
        if !self.entered || self.failure().is_some() || self.returned.is_some()
            || !matches!(self.posts, Some(Ok(())))
            || !matches!(self.final_current, Some(Ok(())))
            || !matches!(self.native.label_funding, Some(Ok(())))
            || !matches!(self.native.labels_result, Some(Ok(())))
        {
            return Err(closed());
        }
        // Keep the returned mount's FD charged even though compilation has
        // since moved its duplicate into the final payload pins.
        positive(&self.fixed)?.get(D::OpenFiles).checked_sub(1)
            .and_then(|files| files.checked_add(self.native.label_demand?.get(D::OpenFiles)))
            .ok_or(HostError::ResourceExhausted)
    }

    /// Borrows the chronological original cause without reentry or native IO.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.fixed)
            .or_else(|| cause(&self.funding))
            .or_else(|| cause(&self.opening_clock))
            .or_else(|| cause(&self.opening_gate))
            .or_else(|| {
                if self
                    .opening_result
                    .as_ref()
                    .is_some_and(|value| value.is_err())
                {
                    self.opening
                        .failure()
                        .or_else(|| cause(&self.opening_result))
                } else {
                    None
                }
            })
            .or_else(|| self.native.failure())
            .or_else(|| cause(&self.returned))
            .or_else(|| self.opening.failure())
            .or_else(|| cause(&self.socket_post))
            .or_else(|| self.native.membership[2].failure().map(|cause| cause as _))
            .or_else(|| cause(&self.native.membership_results[2]))
            .or_else(|| cause(&self.native.alive[2]))
            .or_else(|| cause(&self.native.stat[1]))
            .or_else(|| cause(&self.mount_post))
            .or_else(|| cause(&self.native.clock[2]))
            .or_else(|| cause(&self.posts))
            .or_else(|| cause(&self.final_current))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn copied_host<T: Copy>(slot: &mut Option<Result<T>>, retained: bool) -> Result<T> {
    if let Some(Ok(value)) = slot {
        return Ok(*value);
    }
    if retained {
        return Err(closed());
    }
    match slot.take() {
        Some(Err(cause)) => Err(cause),
        _ => Err(closed()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd as _, AsRawFd as _};

    #[test]
    fn inspectable_mount_identity_does_not_validate_a_guest_root() {
        use aos_sandbox_guest_root_realization::guest_root_label::GuestRootLabelErrorV1;

        let file = std::fs::File::open("/dev/null").unwrap();
        let fd = file.as_raw_fd();
        let expected = rustix::fs::fstat(&file).unwrap();

        // This mechanical adoption inspects the containing mount. It does not
        // claim that a character device is a detached guest-root directory.
        let mount = DetachedMount::from_inherited_retaining_v2(file.into()).unwrap();
        let mut labels = GuestRootLabelReadOriginalV1::with_receiving_limits_v2(1, 1).unwrap();
        let refused = labels.verify_once_v1(mount.as_fd());

        assert!(refused.is_err());
        assert!(matches!(
            labels.failure().unwrap().downcast_ref::<GuestRootLabelErrorV1>(),
            Some(GuestRootLabelErrorV1::Path(
                aos_linux_descriptors::Error::WrongDescriptorType { expected: "directory" }
            ))
        ));
        let actual = rustix::fs::fstat(mount.as_fd()).unwrap();
        assert_eq!(mount.as_fd().as_raw_fd(), fd);
        assert_eq!((actual.st_dev, actual.st_ino), (expected.st_dev, expected.st_ino));
    }

    #[test]
    fn rejected_root_labels_keep_the_actual_mount_and_original_cause_through_later_posts() {
        use aos_sandbox_guest_root_realization::guest_root_label::GuestRootLabelErrorV1;

        let file = std::fs::File::open("/dev/null").unwrap();
        let fd = file.as_raw_fd();
        let expected = rustix::fs::fstat(&file).unwrap();
        let mount = DetachedMount::from_inherited_retaining_v2(file.into()).unwrap();
        let mut labels = GuestRootLabelReadOriginalV1::with_receiving_limits_v2(1, 1).unwrap();
        assert!(labels.verify_once_v1(mount.as_fd()).is_err());
        let mut original = HostRootMountExportOriginalV2::new();
        original.native.mount = Some(Ok(mount));
        original.native.labels = Some(labels);
        original.native.labels_result = Some(Err(closed()));
        original.native.first = Some(FirstV2::Labels);
        original.returned = Some(Err(closed()));
        let original_cause = original.failure().unwrap()
            .downcast_ref::<GuestRootLabelErrorV1>().unwrap() as *const GuestRootLabelErrorV1;

        original.parent_post = Some(Err(closed()));
        original.native.clock[2] = Some(Err(StorageClientTransportErrorV2::Deadline));

        let mount = original.native.mount.as_ref().unwrap().as_ref().unwrap();
        let actual = rustix::fs::fstat(mount.as_fd()).unwrap();
        assert_eq!(mount.as_fd().as_raw_fd(), fd);
        assert_eq!((actual.st_dev, actual.st_ino), (expected.st_dev, expected.st_ino));
        assert!(matches!(original.failure().unwrap().downcast_ref::<GuestRootLabelErrorV1>(),
            Some(GuestRootLabelErrorV1::Path(
                aos_linux_descriptors::Error::WrongDescriptorType { expected: "directory" }))));
        assert!(std::ptr::eq(
            original.failure().unwrap().downcast_ref::<GuestRootLabelErrorV1>().unwrap(),
            original_cause,
        ));
    }

    #[test]
    fn earlier_body_refusal_precedes_a_later_native_clock_post() {
        let mut original = HostRootMountExportOriginalV2::new();
        original.returned = Some(Err(HostError::State("primary reply mismatch".to_owned())));
        original.native.clock[2] = Some(Err(StorageClientTransportErrorV2::Deadline));

        assert!(
            matches!(original.failure().unwrap().downcast_ref::<HostError>(),
            Some(HostError::State(message)) if message == "primary reply mismatch")
        );
    }
}
