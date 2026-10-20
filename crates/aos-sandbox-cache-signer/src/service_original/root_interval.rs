//! Keeps the genuine Cache purpose's complete selected Root observation.
//!
//! The enclosing private F owner pays both property rows and every native post
//! before constructing this owner. The shared engines keep the same Root
//! image, cgroup, unit, delivery and loaded-policy checks; no caller-supplied
//! profile or successful comparison can grant Cache's signing purpose.

use std::error::Error;
use std::mem::size_of;

use aos_sandbox_broker::cache_signer_connection::{
    CacheSignerConnectionClosedV1, deadline_timeout_v1,
};
use aos_sandbox_broker::profile_data::{
    property_values::PropertyValuesV1, root_peer_data::SELECTED_RESOURCE_PEER_PROPERTIES_V1, schema,
};
use aos_sandbox_broker::receiving::{
    ROOT_PEER_MATERIALIZED_PROPERTY_BYTES_V1, RootObservationErrorV1 as RootError,
    RootPeerConnectionOriginalsV1, RootPeerImageObservationsV1, RootPeerObservationOriginalsV1,
    RootProfileOriginalCaptureV1,
};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::unix_stream::RetainedUnixStream;
use aos_systemd::{
    FixedPid1PropertyArchiveV1, FixedPid1PropertyErrorV1, FixedPid1PropertyFailureViewV1,
};
use rustix::time::{ClockId, Timespec, clock_gettime};

use super::{CacheSignerReceivingClosedV1 as Closed, cause};

type Native = RootPeerObservationOriginalsV1<RootError>;

#[derive(Clone, Copy)]
enum First {
    Order,
    BeginDeadline,
    Preparation,
    ImagesBefore,
    NativeBefore,
    BeginLate,
    ImagesAfter,
    NativeAfter,
    FinishLate,
    Settlement,
    SettlementLate,
    Baseline,
}

pub(super) struct CacheRootIntervalOriginalV1 {
    archive: FixedPid1PropertyArchiveV1,
    peer: RootPeerConnectionOriginalsV1,
    native: Native,
    preparation: Option<Result<(), FixedPid1PropertyErrorV1>>,
    images_before: Option<Result<(), aos_sandbox_broker::profile_data::ControllerProfileErrorV1>>,
    begin: Option<Result<(), RootError>>,
    images_after: Option<Result<(), aos_sandbox_broker::profile_data::ControllerProfileErrorV1>>,
    finish: Option<Result<(), RootError>>,
    settlement: Option<Result<(), FixedPid1PropertyErrorV1>>,
    baseline: Option<Result<(), RootError>>,
    clocks: [Option<Timespec>; 4],
    deadlines: [Option<Result<Timespec, CacheSignerConnectionClosedV1>>; 4],
    property_before_failed: bool,
    property_after_failed: bool,
    entered: bool,
    first: Option<First>,
}

impl CacheRootIntervalOriginalV1 {
    // Empty construction follows, and never substitutes for, SAME-F payment.
    pub(super) fn new() -> Self {
        Self {
            archive: FixedPid1PropertyArchiveV1::with_materialization_limit(
                2,
                ROOT_PEER_MATERIALIZED_PROPERTY_BYTES_V1,
            ),
            peer: RootPeerConnectionOriginalsV1::new(),
            native: Native::selected_with_resource_producer_v1(),
            preparation: None,
            images_before: None,
            begin: None,
            images_after: None,
            finish: None,
            settlement: None,
            baseline: None,
            clocks: [None; 4],
            deadlines: [None, None, None, None],
            property_before_failed: false,
            property_after_failed: false,
            entered: false,
            first: None,
        }
    }

    pub(super) fn receiving_demand_v1() -> Option<ResourceVector> {
        let shape = FixedPid1PropertyArchiveV1::fixed_property_geometry_v1(
            ROOT_PEER_MATERIALIZED_PROPERTY_BYTES_V1,
        )
        .ok()?;
        // Both rows may retain their complete negative results. The worker
        // thread is sequential; the second can coexist with first-row errors.
        let row = ResourceVector::ZERO
            .with(D::MemoryBytes, shape.memory_bytes)
            .with(D::OpenFiles, shape.open_files)
            .with(D::NetworkBytes, shape.wire_io_bytes)
            .with(D::LogBytes, shape.maximum_log_bytes);
        let own =
            ResourceVector::ZERO
                .with(
                    D::MemoryBytes,
                    u64::try_from(size_of::<Self>().checked_mul(2)?.checked_add(
                        2 * size_of::<
                            aos_sandbox_broker::profile_data::property_values::PropertyPairV1,
                        >(),
                    )?)
                    .ok()?,
                )
                .with(D::Pids, shape.worker_threads);
        // These are process/property carriers, not namespace metadata entries.
        own.checked_add(row)
            .ok()?
            .checked_add(row)
            .ok()?
            .checked_add(Native::receiving_demand_v1()?)
            .ok()
    }

    pub(super) fn begin_once(
        &mut self,
        profile: &RootProfileOriginalCaptureV1,
        images: &mut RootPeerImageObservationsV1,
        stream: &RetainedUnixStream,
        cutoff: u64,
    ) -> Result<(), Closed> {
        if self.entered {
            return self.refuse(First::Order);
        }
        self.entered = true;
        self.sample_deadline(0, cutoff);
        if !matches!(self.deadlines[0], Some(Ok(_))) {
            return self.refuse(First::BeginDeadline);
        }
        self.preparation = Some(self.archive.prepare_once());
        if !matches!(self.preparation, Some(Ok(()))) {
            return self.refuse(First::Preparation);
        }
        self.images_before = Some(images.recheck_images());
        if !matches!(self.images_before, Some(Ok(()))) {
            return self.refuse(First::ImagesBefore);
        }
        self.begin = Some(self.begin_native(profile, stream));
        if !matches!(self.begin, Some(Ok(()))) {
            self.mark(First::NativeBefore);
        }
        self.sample_deadline(1, cutoff);
        if !matches!(self.deadlines[1], Some(Ok(_))) {
            self.mark(First::BeginLate);
        }
        self.result()
    }

    fn begin_native(
        &mut self,
        profile: &RootProfileOriginalCaptureV1,
        stream: &RetainedUnixStream,
    ) -> Result<(), RootError> {
        self.native.begin_before_properties_once(
            profile.profile().ok_or(RootError::Profile),
            &mut self.peer,
            stream,
        )?;
        let properties = self.archive.read(
            schema::UNIT,
            stream.peer().credentials().pid().get(),
            SELECTED_RESOURCE_PEER_PROPERTIES_V1,
            aos_sandbox_broker::profile_data::delivery::UNIT_PROPERTIES,
        );
        self.property_before_failed = properties.is_err();
        let properties = properties
            .map(|(values, unit)| {
                (
                    PropertyValuesV1::retained_owned(values),
                    PropertyValuesV1::retained_owned(unit),
                )
            })
            .map_err(|_| RootError::Service);
        self.native.begin_after_properties_once(
            profile.profile().ok_or(RootError::Profile),
            profile
                .measurement()
                .map(|file| file.path())
                .map_err(|_| RootError::Profile),
            &mut self.peer,
            stream,
            properties,
        )
    }

    pub(super) fn subjects(&self) -> Option<([u8; 16], [u8; 16])> {
        self.native.selected_resource_subjects_v1()
    }

    // An entered before owns this independently paid post, even after an
    // expired deadline, failed property worker, image check or signing body.
    pub(super) fn finish_once(
        &mut self,
        profile: &RootProfileOriginalCaptureV1,
        images: &mut RootPeerImageObservationsV1,
        stream: &RetainedUnixStream,
        cutoff: u64,
    ) -> Result<(), Closed> {
        if !self.entered || self.finish.is_some() {
            return self.refuse(First::Order);
        }
        self.images_after = Some(images.recheck_images());
        if !matches!(self.images_after, Some(Ok(()))) {
            self.mark(First::ImagesAfter);
        }
        self.finish = Some(self.finish_native(profile, stream));
        if !matches!(self.finish, Some(Ok(()))) {
            self.mark(First::NativeAfter);
        }
        self.sample_deadline(2, cutoff);
        if !matches!(self.deadlines[2], Some(Ok(_))) {
            self.mark(First::FinishLate);
        }
        self.result()
    }

    fn finish_native(
        &mut self,
        profile: &RootProfileOriginalCaptureV1,
        stream: &RetainedUnixStream,
    ) -> Result<(), RootError> {
        self.native.finish_before_properties_once(
            profile.profile().ok_or(RootError::Profile),
            &mut self.peer,
            stream,
        )?;
        let properties = if matches!(self.preparation, Some(Ok(()))) {
            let properties = self.archive.read(
                schema::UNIT,
                stream.peer().credentials().pid().get(),
                SELECTED_RESOURCE_PEER_PROPERTIES_V1,
                aos_sandbox_broker::profile_data::delivery::UNIT_PROPERTIES,
            );
            self.property_after_failed = properties.is_err();
            Some(
                properties
                    .map(|(values, unit)| {
                        (
                            PropertyValuesV1::retained_owned(values),
                            PropertyValuesV1::retained_owned(unit),
                        )
                    })
                    .map_err(|_| RootError::Service),
            )
        } else {
            None
        };
        self.native.finish_after_properties_once(
            profile.profile().ok_or(RootError::Profile),
            profile
                .measurement()
                .map(|file| file.path())
                .map_err(|_| RootError::Profile),
            &mut self.peer,
            stream,
            properties,
        )
    }

    // Private enclosing service calls this only at its complete positive
    // native/sign/send/F-post frontier. It closes no financial stage or grant.
    pub(super) fn settle_native_once(&mut self, cutoff: u64) -> Result<(), Closed> {
        if self.first.is_some()
            || !matches!(self.begin, Some(Ok(())))
            || !matches!(self.finish, Some(Ok(())))
            || self.settlement.is_some()
        {
            return self.refuse(First::Order);
        }
        self.settlement = Some(self.archive.settle_positive_once());
        if !matches!(self.settlement, Some(Ok(()))) {
            self.mark(First::Settlement);
        }
        if self.first.is_none() {
            self.baseline = Some(self.native.retain_completed_baseline_once(&mut self.peer));
            if !matches!(self.baseline, Some(Ok(()))) {
                self.mark(First::Baseline);
            }
        }
        // Ended/shutdown and every actual returned row remain resident. Check
        // their own final native cutoff before the enclosing owner may retire
        // this interval and reuse its positive descriptor peak.
        self.sample_deadline(3, cutoff);
        if !matches!(self.deadlines[3], Some(Ok(_))) {
            self.mark(First::SettlementLate);
        }
        self.result()
    }

    fn sample_deadline(&mut self, index: usize, cutoff: u64) {
        let now = clock_gettime(ClockId::Boottime);
        self.clocks[index] = Some(now);
        self.deadlines[index] = Some(deadline_timeout_v1(now, cutoff));
    }

    fn mark(&mut self, stage: First) {
        self.first.get_or_insert(stage);
    }

    fn refuse(&mut self, stage: First) -> Result<(), Closed> {
        self.mark(stage);
        Err(Closed)
    }

    fn result(&self) -> Result<(), Closed> {
        if self.first.is_none() {
            Ok(())
        } else {
            Err(Closed)
        }
    }

    // This guard must outlive a borrowed worker cause; a temporary diagnostic
    // view cannot lend an Error after releasing its actual original's Mutex.
    pub(super) fn property_failure_view(&self) -> Option<FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            First::Preparation | First::Settlement => self.archive.failure_view(),
            First::NativeBefore if self.property_before_failed => self.archive.failure_view(),
            First::NativeAfter if self.property_after_failed => self.archive.failure_view(),
            _ => None,
        }
    }

    pub(super) fn failure<'a>(
        &'a self,
        images: &'a RootPeerImageObservationsV1,
    ) -> Option<&'a (dyn Error + 'static)> {
        match self.first? {
            First::Order => Some(&Closed),
            First::BeginDeadline => cause(&self.deadlines[0]),
            First::Preparation => cause(&self.preparation),
            First::ImagesBefore => images.failure().or_else(|| cause(&self.images_before)),
            First::NativeBefore => self
                .native
                .before_failure(&self.peer)
                .or_else(|| cause(&self.begin)),
            First::BeginLate => cause(&self.deadlines[1]),
            First::ImagesAfter => images.failure().or_else(|| cause(&self.images_after)),
            First::NativeAfter => self
                .native
                .after_failure(&self.peer)
                .or_else(|| cause(&self.finish)),
            First::FinishLate => cause(&self.deadlines[2]),
            First::Settlement => cause(&self.settlement),
            First::SettlementLate => cause(&self.deadlines[3]),
            First::Baseline => cause(&self.baseline),
        }
    }
}
