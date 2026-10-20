//! Keeps Source's genuine financial interval around the shared Root observer.
//!
//! Archive preparation, image bookends, native stages and positive worker
//! disposal retain their original order. The lower observer yields comparison
//! DATA only; Source retains its actual F, row lifetime and operation result.

use std::error::Error;
use std::num::NonZeroU32;

use aos_sandbox_broker::receiving::{RootPeerObservationOriginalsV1,
    RootObservationErrorV1, require_root_process_identity_v1};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1;
use aos_sandbox_linux::pidfd::PidFdInfo;
use aos_sandbox_linux::selinux_policy::RetainedLiveSelinuxPolicyReadbackV1;
use aos_sandbox_linux::unix_stream::RetainedUnixStream;

use crate::signer::SourceReceivingGeometryErrorV1 as ResourceReservationErrorV1;
use aos_sandbox_broker::receiving::ObservationLifetimeV1 as ObserverLifetime;
use aos_sandbox_broker::receiving::RootObservationErrorV1 as Refusal;
use aos_sandbox_broker::profile_data::schema as profile;
mod service {
    pub(super) use aos_sandbox_broker::receiving::{
        FixedPropertyArchiveV1 as FirstGlobalPropertyArchive,
        fixed_property_archive_demand_v1 as fixed_property_observer_demand_v1,
        ROOT_PEER_PROPERTIES_V1 as PEER_PROPERTIES,
    };
}

mod inputs;
mod chunk;
pub(crate) use inputs::SourceRootPeerInputsV1;
pub(crate) use chunk::SourceRootChunkReadbackV1;
pub(crate) use aos_sandbox_broker::receiving::RootPeerConnectionOriginalsV1 as SourceRootPeerConnectionV1;

const MATERIALIZED_PROPERTY_BYTES: usize =
    aos_sandbox_broker::receiving::ROOT_PEER_MATERIALIZED_PROPERTY_BYTES_V1;

pub(super) fn require_root_process_identity(pid: NonZeroU32, gid: u32, info: &PidFdInfo)
    -> Result<(), Refusal>
{
    require_root_process_identity_v1(pid, gid, info).map_err(Into::into)
}

pub(crate) struct SourceRootPeerStageV1 {
    archive: service::FirstGlobalPropertyArchive,
    native: RootPeerObservationOriginalsV1<Refusal>,
    preparation: Option<Result<(), Refusal>>,
    images_before: Option<Result<(), Refusal>>,
    begin: Option<Result<(), Refusal>>,
    images_after: Option<Result<(), Refusal>>,
    finish: Option<Result<(), Refusal>>,
    settlement: Option<Result<(), Refusal>>,
    closed: Option<Refusal>,
}

impl SourceRootPeerStageV1 {
    pub(crate) fn new(lifetime: ObserverLifetime) -> Self {
        Self::with_native(lifetime, RootPeerObservationOriginalsV1::ordinary())
    }

    // The actual selected Source purpose chooses this fixed four-role entry.
    // It grants no lifetime and accepts no caller-selected decoder flag.
    pub(crate) fn selected(lifetime: ObserverLifetime) -> Self {
        Self::with_native(lifetime, RootPeerObservationOriginalsV1::selected())
    }

    fn with_native(lifetime: ObserverLifetime, native: RootPeerObservationOriginalsV1<Refusal>) -> Self {
        Self {
            archive: service::FirstGlobalPropertyArchive::with_materialization_limit(2,
                lifetime, MATERIALIZED_PROPERTY_BYTES), native,
            preparation: None, images_before: None, begin: None,
            images_after: None, finish: None, settlement: None, closed: None,
        }
    }

    pub(crate) fn demand() -> Result<ResourceVector, ResourceReservationErrorV1> {
        let error = || ResourceReservationErrorV1::EnrollmentUnavailable;
        let observer = service::fixed_property_observer_demand_v1(MATERIALIZED_PROPERTY_BYTES)
            .map_err(|_| error())?;
        let policy = RetainedLiveSelinuxPolicyReadbackV1::receiving_demand_v1();
        let membership = ExactCgroupMembershipReadbackV1::dominant_requested_bytes_v1().ok_or_else(error)?;
        let memory = std::mem::size_of::<Self>()
            .checked_add(membership.checked_mul(2).ok_or_else(error)?)
            .and_then(|bytes| bytes.checked_add(policy.memory_bytes.checked_mul(2)?))
            // Fragment bytes, normalization/read overlap, native path/errors,
            // same-image digest transient and fixed running cgroup carriers.
            .and_then(|bytes| bytes.checked_add(8 * 65_536 + 32 * 4096))
            // The same fragment File is already in the physical roster below;
            // explicitly add its newly retained initial acquisition bytes.
            .and_then(|bytes| bytes.checked_add(usize::try_from(
                SourceRootPeerConnectionV1::fragment_acquisition_demand_v1()?.get(D::MemoryBytes),
            ).ok()?))
            .ok_or_else(error)?;
        let fixed = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).map_err(|_| error())?)
            .with(D::OpenFiles, 6 + 1 + 2 * 2 + 2 * policy.open_files as u64)
            .with(D::MetadataEntries, 64 + 2 * policy.metadata_entries)
            .with(D::Pids, 1);
        fixed.checked_add(observer).and_then(|demand| demand.checked_add(observer))
            .map_err(|_| error())
    }

    pub(crate) fn begin_once(&mut self, inputs: &mut SourceRootPeerInputsV1,
        peer: &mut SourceRootPeerConnectionV1, stream: &RetainedUnixStream,
    ) -> Result<(), Refusal> {
        if self.begin.is_some() {
            self.closed.get_or_insert(Refusal::Service);
            return Err(Refusal::Service);
        }
        self.begin = Some(self.begin_inner(inputs, peer, stream));
        positive(&self.begin).map(|_| ())
    }

    fn begin_inner(&mut self, inputs: &mut SourceRootPeerInputsV1,
        peer: &mut SourceRootPeerConnectionV1, stream: &RetainedUnixStream,
    ) -> Result<(), Refusal> {
        self.preparation = Some(self.archive.prepare());
        positive(&self.preparation)?;
        self.images_before = Some(inputs.recheck_images());
        positive(&self.images_before)?;
        self.native.begin_before_properties_once(inputs.profile().map_err(|_| RootObservationErrorV1::Profile), peer, stream)?;
        let properties = self.archive.read(profile::UNIT, stream.peer().credentials().pid().get(),
            service::PEER_PROPERTIES);
        self.native.begin_after_properties_once(inputs.profile().map_err(|_| RootObservationErrorV1::Profile),
            inputs.profile_file().map(|file| file.path()).map_err(|_| RootObservationErrorV1::Profile),
            peer, stream, properties).map_err(Into::into)
    }

    // These native posts remain independently owed even after an earlier image
    // or body refusal. Their archive read retains the original lifetime check.
    pub(crate) fn finish_once(&mut self, inputs: &mut SourceRootPeerInputsV1,
        peer: &mut SourceRootPeerConnectionV1, stream: &RetainedUnixStream,
    ) -> Result<(), Refusal> {
        if self.finish.is_some() || self.begin.is_none() {
            self.closed.get_or_insert(Refusal::Service);
            return Err(Refusal::Service);
        }
        self.images_after = Some(inputs.recheck_images());
        self.native.finish_before_properties_once(inputs.profile().map_err(|_| RootObservationErrorV1::Profile), peer, stream)?;
        let properties = if matches!(self.preparation, Some(Ok(()))) {
            Some(self.archive.read(profile::UNIT, stream.peer().credentials().pid().get(),
                service::PEER_PROPERTIES))
        } else { None };
        let native = self.native.finish_after_properties_once(inputs.profile().map_err(|_| RootObservationErrorV1::Profile),
            inputs.profile_file().map(|file| file.path()).map_err(|_| RootObservationErrorV1::Profile),
            peer, stream, properties);
        self.finish = Some((|| {
            positive(&self.begin)?;
            positive(&self.images_after)?;
            native?;
            Ok(())
        })());
        if matches!(self.finish, Some(Ok(()))) {
            self.settlement = Some(self.archive.settle_positive_once());
            positive(&self.settlement)?;
            self.native.retain_completed_baseline_once(peer)?;
        }
        positive(&self.finish).map(|_| ())
    }

    pub(crate) fn can_dispose(&self) -> bool {
        self.closed.is_none() && matches!(self.finish, Some(Ok(())))
            && matches!(self.settlement, Some(Ok(()))) && self.native.complete()
    }

    pub(crate) fn failure<'a>(&'a self, inputs: &'a SourceRootPeerInputsV1,
        peer: &'a SourceRootPeerConnectionV1,
    ) -> Option<&'a (dyn Error + 'static)> {
        failure(&self.preparation)
            .or_else(|| if matches!(self.images_before, Some(Err(_))) {
                inputs.failure().or_else(|| failure(&self.images_before))
            } else { None })
            .or_else(|| self.native.before_failure(peer))
            .or_else(|| failure(&self.begin))
            .or_else(|| if matches!(self.images_after, Some(Err(_))) {
                inputs.failure().or_else(|| failure(&self.images_after))
            } else { None })
            .or_else(|| self.native.after_failure(peer))
            .or_else(|| failure(&self.finish)).or_else(|| failure(&self.settlement))
            .or_else(|| self.closed.as_ref().map(|error| error as _))
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, Refusal> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(Refusal::Service)
}

fn failure<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}
