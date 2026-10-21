//! Owns one actual peer sample and its independently owed local/socket posts.

use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;

use aos_sandbox_broker::profile_data::{delivery, root_peer_data};
use aos_sandbox_linux::cgroup::{
    CgroupV2Root, ExactCgroupMembershipReadbackV1, ExactCgroupMembershipRefusalV1,
    RetainedCgroupAnchor, RootInitialCgroupReadbackV1,
};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_linux_descriptors::unix_stream::UnixStreamOriginalCurrentnessV1;
use aos_sandbox_linux::unix_stream::UnixStreamSubjectChunk;
use aos_systemd_client::{FixedPid1PropertyArchiveV1, FixedPid1PropertyErrorV1, FixedPid1PropertyWorkerSlotV1, OwnedValue};
use super::queued_cutoff::PropertyQueuedCutoffOriginalV1;
use sha2::{Digest as _, Sha256};

use crate::immutable_image::{ImmutableImageErrorV1, PendingImmutableFileV1};

use aos_sandbox_broker::controller_receiving::profile::ControllerProfileLocalPrefixOriginalV1;
use super::super::ControllerProfileLocalCurrentnessOriginalV1;
use super::{MATERIALIZED_BYTES, ProductionControllerNormalRootProfileV1, Refusal,
    RootPropertiesV1, StableRootPeerV1, RootPeerBindingRefV1, error, profile};

type PropertiesV1 = (Arc<Vec<OwnedValue>>, Arc<Vec<OwnedValue>>);

// The existing Controller delivery comparison plus its actual fixed runtime
// task ceiling are one bounded flight before starting any subsequent worker.
const CONTROLLER_PROPERTIES: &[&str] = &[
    "ControlGroup", "OpenFile", "ExtraFileDescriptorNames", "FileDescriptorStoreMax",
    "NFileDescriptorStore", "SELinuxContext", "CapabilityBoundingSet", "AmbientCapabilities",
    "NoNewPrivileges", "TasksMax",
];

pub(in crate::normal_root::client) struct PeerSampleV1 {
    controller_archive: FixedPid1PropertyArchiveV1,
    root_archive: FixedPid1PropertyArchiveV1,
    controller_prepare: Option<Result<(), FixedPid1PropertyErrorV1>>,
    root_prepare: Option<Result<(), FixedPid1PropertyErrorV1>>,
    controller_local: ControllerProfileLocalPrefixOriginalV1,
    controller_prefix: Option<Result<(), Refusal>>,
    controller_cutoff: PropertyQueuedCutoffOriginalV1,
    controller_properties: Option<Result<PropertiesV1, FixedPid1PropertyErrorV1>>,
    controller_decoded: Option<Result<delivery::ServiceObservationV1, Refusal>>,
    controller_tasks: Option<Result<(), Refusal>>,
    controller_canonical: Option<std::io::Result<PathBuf>>,
    controller_binding: Option<Result<(), Refusal>>,
    controller_primary: Option<Result<(), Refusal>>,
    stream_before: UnixStreamOriginalCurrentnessV1,
    stream_before_result: Option<Result<(), aos_linux_descriptors::Error>>,
    nomination: Option<Result<(), Refusal>>,
    root_capture: RootInitialCgroupReadbackV1,
    root_capture_result: Option<Result<(), aos_linux_descriptors::Error>>,
    root_pair: Option<(CgroupV2Root, RetainedCgroupAnchor)>,
    held_root: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    current_root: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    held_anchor: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    current_anchor: Option<Result<rustix::fs::Stat, rustix::io::Errno>>,
    cgroup_binding: Option<Result<(), Refusal>>,
    membership: ExactCgroupMembershipReadbackV1,
    membership_result: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    identity: Option<Result<(), Refusal>>,
    root_cutoff: PropertyQueuedCutoffOriginalV1,
    root_properties: Option<Result<PropertiesV1, FixedPid1PropertyErrorV1>>,
    canonical: Option<std::io::Result<PathBuf>>,
    observed: Option<Result<RootPropertiesV1, Refusal>>,
    root_binding: Option<Result<(), Refusal>>,
    fragment: Option<PendingImmutableFileV1>,
    fragment_open: Option<Result<(), ImmutableImageErrorV1>>,
    fragment_read: Option<Result<(), ImmutableImageErrorV1>>,
    normalized: Option<Result<Vec<u8>, Refusal>>,
    unit_binding: Option<Result<(), Refusal>>,
    chunk_binding: Option<Result<(), Refusal>>,
    chunk_alive: Option<Result<bool, aos_linux_descriptors::Error>>,
    chunk_liveness: Option<Result<(), Refusal>>,
    chunk_membership: ExactCgroupMembershipReadbackV1,
    chunk_membership_result: Option<Result<(), ExactCgroupMembershipRefusalV1>>,
    chunk_identity: Option<Result<(), Refusal>>,
    root_primary: Option<Result<(), Refusal>>,
    stream_after: UnixStreamOriginalCurrentnessV1,
    stream_after_result: Option<Result<(), aos_linux_descriptors::Error>>,
    controller_post: ControllerProfileLocalCurrentnessOriginalV1,
    controller_post_result: Option<Result<(), Refusal>>,
    completion: Option<Result<(), Refusal>>,
    controller_settlement: Option<Result<(), FixedPid1PropertyErrorV1>>,
    root_settlement: Option<Result<(), FixedPid1PropertyErrorV1>>,
    pid: Option<u32>,
    delete_post_cutoff: PropertyQueuedCutoffOriginalV1,
}

impl PeerSampleV1 {
    pub(in crate::normal_root::client) fn new() -> Self {
        Self {
            controller_archive: FixedPid1PropertyArchiveV1::with_materialization_limit(1, MATERIALIZED_BYTES),
            root_archive: FixedPid1PropertyArchiveV1::with_materialization_limit(1, MATERIALIZED_BYTES),
            controller_prepare: None,
            root_prepare: None,

            controller_local: ControllerProfileLocalPrefixOriginalV1::new(),
            controller_prefix: None,
            controller_cutoff: PropertyQueuedCutoffOriginalV1::new(),
            controller_properties: None,
            controller_decoded: None,
            controller_tasks: None,
            controller_canonical: None,
            controller_binding: None,
            controller_primary: None,

            stream_before: UnixStreamOriginalCurrentnessV1::new(),
            stream_before_result: None,
            nomination: None,
            root_capture: RootInitialCgroupReadbackV1::new(),
            root_capture_result: None,
            root_pair: None,
            held_root: None,
            current_root: None,
            held_anchor: None,
            current_anchor: None,
            cgroup_binding: None,

            membership: ExactCgroupMembershipReadbackV1::new(),
            membership_result: None,
            identity: None,

            root_cutoff: PropertyQueuedCutoffOriginalV1::new(),
            root_properties: None,
            canonical: None,
            observed: None,
            root_binding: None,

            fragment: Some(PendingImmutableFileV1::default()),
            fragment_open: None,
            fragment_read: None,
            normalized: None,
            unit_binding: None,

            chunk_binding: None,
            chunk_alive: None,
            chunk_liveness: None,
            chunk_membership: ExactCgroupMembershipReadbackV1::new(),
            chunk_membership_result: None,
            chunk_identity: None,
            root_primary: None,

            stream_after: UnixStreamOriginalCurrentnessV1::new(),
            stream_after_result: None,
            controller_post: ControllerProfileLocalCurrentnessOriginalV1::new(),
            controller_post_result: None,
            completion: None,
            controller_settlement: None,
            root_settlement: None,
            pid: None,
            delete_post_cutoff: PropertyQueuedCutoffOriginalV1::new(),
        }
    }

    pub(in crate::normal_root::client) fn observe_once(
        &mut self,
        actual: &ProductionControllerNormalRootProfileV1,
        stream: &RetainedUnixStream,
        stable: Option<&StableRootPeerV1>,
        chunk: Option<&UnixStreamSubjectChunk>,
        owed: bool,
        cutoff: u64,
    ) -> Result<(), Refusal> {
        self.observe_with_binding_once(actual, stream, stable.map(StableRootPeerV1::as_binding), chunk, owed, cutoff)
    }

    fn observe_with_binding_once(
        &mut self,
        actual: &ProductionControllerNormalRootProfileV1,
        stream: &RetainedUnixStream,
        stable: Option<RootPeerBindingRefV1<'_>>,
        chunk: Option<&UnixStreamSubjectChunk>,
        owed: bool,
        cutoff: u64,
    ) -> Result<(), Refusal> {
        self.controller_prepare = Some(self.controller_archive.prepare_once());
        self.root_prepare = Some(self.root_archive.prepare_once());
        self.controller_primary = Some(self.observe_controller(actual, cutoff));
        // A prearmed independently owed peer pass still observes the fixed Root
        // after a Controller local refusal. It cannot install an initial peer.
        if matches!(self.controller_primary, Some(Ok(()))) || owed {
            self.root_primary = Some(self.observe_root(actual, stream, stable, chunk, cutoff));
        }
        self.stream_after_result = Some(stream.revalidate_original_retaining_v1(&mut self.stream_after));
        self.controller_post_result = Some(actual.observe_local_currentness_retaining_v1(&mut self.controller_post));
        self.completion = Some((|| {
            positive(&self.controller_primary)?;
            positive(&self.root_primary)?;
            positive(&self.stream_after_result)?;
            positive(&self.controller_post_result)
        })());
        positive(&self.completion)
    }

    // The closed D caller selects the same full native body, then retains an
    // actual trailing cutoff before any positive archive/native retirement.
    // Ordinary J observation retains its original native schedule.
    pub(in crate::normal_root::client) fn observe_delete_once_v1(
        &mut self,
        actual: &ProductionControllerNormalRootProfileV1,
        stream: &RetainedUnixStream,
        stable: Option<&StableRootPeerV1>,
        chunk: Option<&UnixStreamSubjectChunk>,
        owed: bool,
        cutoff: u64,
    ) -> Result<(), Refusal> {
        self.observe_with_cutoff_once_v1(actual, stream, stable, chunk, owed, cutoff)
    }

    // The new C purpose shares this exact native frontier with D. Its caller
    // retains its own financial owner and prepaid independent post destination.
    pub(in crate::normal_root::client) fn observe_with_cutoff_once_v1(
        &mut self,
        actual: &ProductionControllerNormalRootProfileV1,
        stream: &RetainedUnixStream,
        stable: Option<&StableRootPeerV1>,
        chunk: Option<&UnixStreamSubjectChunk>,
        owed: bool,
        cutoff: u64,
    ) -> Result<(), Refusal> {
        let primary = self.observe_once(actual, stream, stable, chunk, owed, cutoff);
        let after = self.delete_post_cutoff.observe_once(cutoff);
        primary.and(after)
    }

    pub(in crate::normal_root::client) fn observe_delete_against_sample_once_v1(
        &mut self,
        actual: &ProductionControllerNormalRootProfileV1,
        stream: &RetainedUnixStream,
        held: &PeerSampleV1,
        chunk: Option<&UnixStreamSubjectChunk>,
        owed: bool,
        cutoff: u64,
    ) -> Result<(), Refusal> {
        self.observe_against_sample_with_cutoff_once_v1(actual, stream, held, chunk, owed, cutoff)
    }

    // Both closed purposes use the same retained native anchor and late cutoff.
    pub(in crate::normal_root::client) fn observe_against_sample_with_cutoff_once_v1(
        &mut self,
        actual: &ProductionControllerNormalRootProfileV1,
        stream: &RetainedUnixStream,
        held: &PeerSampleV1,
        chunk: Option<&UnixStreamSubjectChunk>,
        owed: bool,
        cutoff: u64,
    ) -> Result<(), Refusal> {
        let primary = held.held_binding_v1().and_then(|binding|
            self.observe_with_binding_once(actual, stream, Some(binding), chunk, owed, cutoff));
        let after = self.delete_post_cutoff.observe_once(cutoff);
        primary.and(after)
    }

    fn held_binding_v1(&self) -> Result<RootPeerBindingRefV1<'_>, Refusal> {
        positive(&self.completion)?;
        if self.failure().is_some() { return Err(Refusal::Service); }
        Ok(RootPeerBindingRefV1 {
            pair: self.root_pair.as_ref().ok_or(Refusal::Service)?,
            fragment: self.fragment.as_ref().ok_or(Refusal::Service)?,
            observed: value(&self.observed)?,
            pid: self.pid.ok_or(Refusal::Service)?,
        })
    }

    fn observe_controller(&mut self, actual: &ProductionControllerNormalRootProfileV1, cutoff: u64)
        -> Result<(), Refusal>
    {
        positive(&self.controller_prepare)?;
        self.controller_prefix = Some(self.controller_local.capture_prefix_once_v1(actual.lower_original_v1()).map_err(Into::into));
        positive(&self.controller_prefix)?;
        let mut slot = FixedPid1PropertyWorkerSlotV1::acquire();
        self.controller_cutoff.observe_once(cutoff)?;
        self.controller_properties = Some(self.controller_archive.read_under_slot(
            &mut slot,
            delivery::CONTROLLER_UNIT, std::process::id(), CONTROLLER_PROPERTIES,
            delivery::UNIT_PROPERTIES,
        ));
        drop(slot);
        let properties = value(&self.controller_properties)?;
        let (tasks, common) = properties.0.split_last().ok_or(Refusal::Service)?;
        self.controller_decoded = Some(super::super::decode_delivery_with_resource_launch(
            common, &properties.1, actual.original.profile_measurement().path(), actual.original.has_tpm_image_delivery(),
            actual.original.nix_delivery_measurement().map(|file| file.path()), actual.original.has_resource_delivery(), actual.original.has_resource_launch(),
        ));
        self.controller_binding = Some((|| {
            let observed = self.controller_decoded.as_mut().and_then(|result| result.as_mut().ok())
                .ok_or(Refusal::Service)?;
            delivery::immutable_observation_in_place(observed, &mut self.controller_canonical)
                .map_err(Refusal::from)?;
            delivery::require_same(actual.original.original_unit_observation(), observed).map_err(Refusal::from)?;
            self.controller_local.capture_fragment_once_v1(actual.lower_original_v1()).map_err(Into::into)
        })());
        positive(&self.controller_binding)?;
        // This is the SAME installed runtime ceiling used by the existing
        // closed Controller startup recipe. It creates no task grant.
        self.controller_tasks = Some(if properties.0.len() == CONTROLLER_PROPERTIES.len()
            && u64::try_from(tasks).ok() == Some(8)
        { Ok(()) } else { Err(Refusal::Service) });
        positive(&self.controller_tasks)
    }

    fn observe_root(
        &mut self,
        actual: &ProductionControllerNormalRootProfileV1,
        stream: &RetainedUnixStream,
        stable: Option<RootPeerBindingRefV1<'_>>,
        chunk: Option<&UnixStreamSubjectChunk>,
        cutoff: u64,
    ) -> Result<(), Refusal> {
        self.stream_before_result = Some(stream.revalidate_original_retaining_v1(&mut self.stream_before));
        positive(&self.stream_before_result)?;
        let credentials = stream.peer().credentials();
        self.pid = Some(credentials.pid().get());
        self.nomination = Some(if credentials.uid() == 0 && credentials.gid() == actual.original.schema().identities[1]
            && stable.is_none_or(|original| original.pid == credentials.pid().get())
        { Ok(()) } else { Err(Refusal::Service) });
        positive(&self.nomination)?;
        self.root_capture_result = Some(self.root_capture.capture_once());
        positive(&self.root_capture_result)?;
        self.root_pair = self.root_capture.take_validated_pair();
        let pair = self.root_pair.as_ref().ok_or(Refusal::Service)?;
        if let Some(original) = stable {
            self.held_root = Some(rustix::fs::fstat(original.pair.0.as_fd()));
            self.current_root = Some(rustix::fs::fstat(pair.0.as_fd()));
            self.held_anchor = Some(rustix::fs::fstat(original.pair.1.as_fd()));
            self.current_anchor = Some(rustix::fs::fstat(pair.1.as_fd()));
            self.cgroup_binding = Some((|| {
                same_inode(value(&self.held_root)?, value(&self.current_root)?)?;
                same_inode(value(&self.held_anchor)?, value(&self.current_anchor)?)
            })());
            positive(&self.cgroup_binding)?;
        }
        self.membership_result = Some(self.membership.capture_once(&pair.1, stream.peer().pidfd()));
        positive(&self.membership_result)?;
        self.identity = Some(self.membership.result().and_then(|result| result.as_ref().ok())
            .ok_or(Refusal::Service).and_then(|info| aos_sandbox_broker::receiving::require_root_process_identity_v1(
                credentials.pid(), actual.original.schema().identities[1], info,
            ).map_err(Into::into)));
        positive(&self.identity)?;
        positive(&self.root_prepare)?;
        let mut slot = FixedPid1PropertyWorkerSlotV1::acquire();
        self.root_cutoff.observe_once(cutoff)?;
        self.root_properties = Some(self.root_archive.read_under_slot(
            &mut slot,
            profile::UNIT, credentials.pid().get(), root_peer_data::SELECTED_RESOURCE_PEER_PROPERTIES_V1,
            delivery::UNIT_PROPERTIES,
        ));
        drop(slot);
        let properties = value(&self.root_properties)?;
        self.observed = Some(root_peer_data::decode_selected_root_peer_with_producer_into(
            actual.original.profile_measurement().path(), credentials.pid().get(), actual.original.schema(),
            &properties.0, &properties.1, &mut self.canonical,
        ).map_err(Refusal::from));
        let observed = value(&self.observed)?;
        self.root_binding = Some((|| {
            if let Some(original) = stable {
                delivery::require_same(&original.observed.0, &observed.0).map_err(Refusal::from)?;
                if original.observed.1 != observed.1 { return Err(Refusal::Service); }
            }
            Ok(())
        })());
        positive(&self.root_binding)?;
        let fragment = self.fragment.as_mut().ok_or(Refusal::Service)?;
        self.fragment_open = Some(fragment.open_and_measure(observed.0.fragment.clone(), None, 64 * 1024, false));
        positive(&self.fragment_open)?;
        self.fragment_read = Some(fragment.read_bounded());
        positive(&self.fragment_read)?;
        self.normalized = Some(profile::normalized_unit(fragment.bytes(), actual.original.profile_measurement().path()
            .to_str().ok_or(Refusal::Profile)?));
        self.unit_binding = Some((|| {
            if <[u8; 32]>::from(Sha256::digest(value(&self.normalized)?)) != actual.original.schema().unit_sha256 {
                return Err(Refusal::Service);
            }
            if let Some(original) = stable {
                let expected = original.fragment.measurement().map_err(|_| Refusal::Service)?;
                let current = fragment.measurement().map_err(|_| Refusal::Service)?;
                if expected.physical_identity() != current.physical_identity()
                    || expected.measured_digest_v1() != current.measured_digest_v1()
                { return Err(Refusal::Service); }
            }
            Ok(())
        })());
        positive(&self.unit_binding)?;
        if let Some(chunk) = chunk {
            self.observe_chunk(actual, stream, chunk)?;
        }
        Ok(())
    }

    fn observe_chunk(
        &mut self,
        actual: &ProductionControllerNormalRootProfileV1,
        stream: &RetainedUnixStream,
        chunk: &UnixStreamSubjectChunk,
    ) -> Result<(), Refusal> {
        let expected = stream.peer().credentials();
        let observed = chunk.subject().credentials();
        self.chunk_binding = Some(if chunk.socket_context() == profile::CONTEXT.as_bytes()
            && observed.pid() == expected.pid() && observed.uid() == expected.uid()
            && observed.gid() == expected.gid()
        { Ok(()) } else { Err(Refusal::Service) });
        positive(&self.chunk_binding)?;
        self.chunk_alive = Some(chunk.subject().is_alive());
        self.chunk_liveness = Some(if *value(&self.chunk_alive)? { Ok(()) } else { Err(Refusal::Service) });
        positive(&self.chunk_liveness)?;
        let anchor = &self.root_pair.as_ref().ok_or(Refusal::Service)?.1;
        self.chunk_membership_result = Some(self.chunk_membership.capture_once(anchor, chunk.subject().pidfd()));
        positive(&self.chunk_membership_result)?;
        self.chunk_identity = Some(self.chunk_membership.result().and_then(|result| result.as_ref().ok())
            .ok_or(Refusal::Service).and_then(|info| aos_sandbox_broker::receiving::require_root_process_identity_v1(
                expected.pid(), actual.original.schema().identities[1], info,
            ).map_err(Into::into)));
        positive(&self.chunk_identity)
    }

    pub(in crate::normal_root::client) fn settle_positive_once(&mut self) -> Result<(), Refusal> {
        positive(&self.completion)?;
        if self.delete_post_cutoff.failure().is_some() { return Err(Refusal::Service); }
        self.controller_settlement = Some(self.controller_archive.settle_positive_once());
        positive(&self.controller_settlement)?;
        self.root_settlement = Some(self.root_archive.settle_positive_once());
        positive(&self.root_settlement)
    }

    pub(in crate::normal_root::client) fn take_initial_binding(&mut self) -> Option<StableRootPeerV1> {
        if self.delete_post_cutoff.failure().is_some() || !matches!(self.completion, Some(Ok(()))) || !matches!(self.controller_settlement, Some(Ok(())))
            || !matches!(self.root_settlement, Some(Ok(()))) { return None; }
        let (Some(pair), Some(fragment), Some(Ok(observed)), Some(pid)) = (
            self.root_pair.take(), self.fragment.take(), self.observed.take(), self.pid,
        ) else { std::process::abort(); };
        Some(StableRootPeerV1 { pair, fragment, observed, pid })
    }

    // A nested worker cause can only be lent while its actual mutex guard is
    // held. Match the exact thin pointer of the first stored row marker before
    // exposing that SAME archive view; a later row never overrides a local or
    // semantic primary error.
    pub(in crate::normal_root::client) fn property_failure_view_v1(&self)
        -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>>
    {
        let first = self.failure()?.downcast_ref::<FixedPid1PropertyErrorV1>()?;
        for (slot, archive) in [
            (&self.controller_prepare, &self.controller_archive),
            (&self.root_prepare, &self.root_archive),
            (&self.controller_settlement, &self.controller_archive),
            (&self.root_settlement, &self.root_archive),
        ] {
            if let Some(Err(cause)) = slot {
                if std::ptr::eq(first, cause) { return archive.failure_view(); }
            }
        }
        if let Some(Err(cause)) = &self.controller_properties {
            if std::ptr::eq(first, cause) { return self.controller_archive.failure_view(); }
        }
        if let Some(Err(cause)) = &self.root_properties {
            if std::ptr::eq(first, cause) { return self.root_archive.failure_view(); }
        }
        None
    }

    pub(in crate::normal_root::client) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.controller_prepare).or_else(|| error(&self.root_prepare))
            .or_else(|| self.controller_local.failure())
            .or_else(|| error(&self.controller_prefix)).or_else(|| self.controller_cutoff.failure())
            .or_else(|| error(&self.controller_properties))
            .or_else(|| error(&self.controller_decoded)).or_else(|| error(&self.controller_canonical))
            .or_else(|| error(&self.controller_binding)).or_else(|| error(&self.controller_tasks))
            .or_else(|| error(&self.controller_primary))
            .or_else(|| self.stream_before.failure()).or_else(|| error(&self.stream_before_result))
            .or_else(|| error(&self.nomination)).or_else(|| self.root_capture.failure())
            .or_else(|| error(&self.root_capture_result)).or_else(|| error(&self.held_root))
            .or_else(|| error(&self.current_root)).or_else(|| error(&self.held_anchor))
            .or_else(|| error(&self.current_anchor)).or_else(|| error(&self.cgroup_binding))
            .or_else(|| self.membership.failure().map(|cause| cause as _))
            .or_else(|| error(&self.membership_result)).or_else(|| error(&self.identity))
            .or_else(|| self.root_cutoff.failure()).or_else(|| error(&self.root_properties)).or_else(|| error(&self.canonical))
            .or_else(|| error(&self.observed)).or_else(|| error(&self.root_binding))
            .or_else(|| self.fragment.as_ref().and_then(PendingImmutableFileV1::native_failure))
            .or_else(|| error(&self.fragment_open)).or_else(|| error(&self.fragment_read))
            .or_else(|| error(&self.normalized)).or_else(|| error(&self.unit_binding))
            .or_else(|| error(&self.chunk_binding)).or_else(|| error(&self.chunk_alive))
            .or_else(|| error(&self.chunk_liveness))
            .or_else(|| self.chunk_membership.failure().map(|cause| cause as _))
            .or_else(|| error(&self.chunk_membership_result)).or_else(|| error(&self.chunk_identity))
            .or_else(|| error(&self.root_primary)).or_else(|| self.stream_after.failure())
            .or_else(|| error(&self.stream_after_result)).or_else(|| self.controller_post.failure())
            .or_else(|| error(&self.controller_post_result)).or_else(|| error(&self.completion))
            .or_else(|| error(&self.controller_settlement)).or_else(|| error(&self.root_settlement))
            .or_else(|| self.delete_post_cutoff.failure())
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<(), Refusal> { value(slot).map(|_| ()) }

fn value<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, Refusal> {
    slot.as_ref().and_then(|value| value.as_ref().ok()).ok_or(Refusal::Service)
}

fn same_inode(held: &rustix::fs::Stat, current: &rustix::fs::Stat) -> Result<(), Refusal> {
    if held.st_dev == current.st_dev && held.st_ino == current.st_ino { Ok(()) } else { Err(Refusal::Service) }
}
