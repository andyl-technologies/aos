//! Retains bounded PID1 and native comparisons for Root's actual Controller peer.
//!
//! The original Root receiver supplies this finite three-observation archive
//! before construction. Delivery DATA selects only the existing strict parser;
//! it grants neither Controller receiving nor executable/Ready authority.

use std::error::Error as StdError;
use std::path::PathBuf;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::{
    CgroupV2Root, ControllerInitialCgroupReadbackV1, RetainedCgroupAnchor,
};
use aos_sandbox_linux::unix_stream::RetainedUnixStream;

use crate::immutable_image::ImmutableFileAcquisitionOriginalV1;
use crate::immutable_image::{ImmutableFileRevalidationOriginalV1, ImmutableImageErrorV1};
use crate::receiving::ObservationLifetimeV1 as ObserverLifetime;

use super::super::{RootObservationErrorV1 as Error, RootStartupNativeOriginalV1};
mod service;

use super::{
    decode_controller_policy_delivery_data_v1 as decode_delivery_with_resource_pair,
    selected_controller_nix_profile_data_v1 as selected_nix_profile,
    selected_controller_resource_pair_data_v1 as selected_resource_pair,
};

fn require_controller_process_identity(
    startup: &RootStartupNativeOriginalV1,
    pid: std::num::NonZeroU32,
    info: &aos_sandbox_linux::pidfd::PidFdInfo,
) -> Result<(), Error> {
    super::require_controller_process_identity_data_v1(
        startup.fields().profile.identities,
        pid,
        info,
    )
}

mod membership;
use membership::RootControllerMembershipV1;

mod subject;
pub use subject::RootSelectedControllerSubjectSampleV1;

const MATERIALIZED_PROPERTY_BYTES: usize = 64 * 1024;
type Properties = service::PropertyPairV1;

/// Retains the actual selected Controller qualifier and all native bookends.
///
/// The genuine Root caller prepays its full fixed recipe before construction.
/// Only actual native observation and explicit positive settlement complete it;
/// this observation owner does not authorize a protected role mutation.
pub struct RootSelectedControllerPeerOriginalV1<'startup> {
    startup: &'startup RootStartupNativeOriginalV1,
    archive: Option<service::FirstGlobalPropertyArchive>,
    preparation: Option<Result<(), Error>>,
    stream_before: Option<Result<(), aos_sandbox_linux::Error>>,
    initial_properties: Option<Result<Properties, Error>>,
    selection: Option<Result<(Option<PathBuf>, bool, bool), Error>>,
    nix_profile: ImmutableFileAcquisitionOriginalV1,
    nix_measurement: Option<Result<(), ImmutableImageErrorV1>>,
    nix_read: Option<Result<(), ImmutableImageErrorV1>>,
    initial_fragment_name: Option<std::io::Result<PathBuf>>,
    initial: Option<Result<service::ServiceObservationV1, Error>>,
    producer_properties: Option<Result<Properties, Error>>,
    producer_binding: Option<Result<[u8; 16], Error>>,
    producer_fragment_name: Option<std::io::Result<PathBuf>>,
    fragment: ImmutableFileAcquisitionOriginalV1,
    fragment_measurement: Option<Result<(), ImmutableImageErrorV1>>,
    cgroup_capture: ControllerInitialCgroupReadbackV1,
    cgroup_result: Option<Result<(), aos_sandbox_linux::Error>>,
    cgroup: Option<(CgroupV2Root, RetainedCgroupAnchor)>,
    membership_before: RootControllerMembershipV1,
    identity_before: Option<Result<(), Error>>,
    capture: Option<Result<(), Error>>,
    final_properties: Option<Result<Properties, Error>>,
    final_binding: Option<Result<(), Error>>,
    final_fragment_name: Option<std::io::Result<PathBuf>>,
    nix_post: Option<Result<(), ImmutableImageErrorV1>>,
    nix_post_original: ImmutableFileRevalidationOriginalV1,
    fragment_post: Option<Result<(), ImmutableImageErrorV1>>,
    fragment_post_original: ImmutableFileRevalidationOriginalV1,
    stream_after: Option<Result<(), aos_sandbox_linux::Error>>,
    membership_after: RootControllerMembershipV1,
    identity_after: Option<Result<(), Error>>,
    settlement: Option<Result<(), Error>>,
    closed: Option<Error>,
    complete: bool,
    capture_entered: bool,
    finish_entered: bool,
    finish_unwinds: [Option<Box<dyn std::any::Any + Send>>; 5],
    body_unwind: Option<Box<dyn std::any::Any + Send>>,
    after_unwind: Option<Box<dyn std::any::Any + Send>>,
}

impl<'startup> RootSelectedControllerPeerOriginalV1<'startup> {
    /// Creates the existing bounded destinations after the real caller prepays.
    ///
    /// The original observation lifetime is moved unchanged; this constructor
    /// does not sample a new clock or admit a financial or effect interval.
    pub fn new(startup: &'startup RootStartupNativeOriginalV1, lifetime: ObserverLifetime) -> Self {
        Self {
            startup,
            archive: Some(
                service::FirstGlobalPropertyArchive::with_materialization_limit(
                    3,
                    lifetime,
                    MATERIALIZED_PROPERTY_BYTES,
                ),
            ),
            preparation: None,
            stream_before: None,
            initial_properties: None,
            selection: None,
            nix_profile: ImmutableFileAcquisitionOriginalV1::new(),
            nix_measurement: None,
            nix_read: None,
            initial_fragment_name: None,
            initial: None,
            producer_properties: None,
            producer_binding: None,
            producer_fragment_name: None,
            fragment: ImmutableFileAcquisitionOriginalV1::new(),
            fragment_measurement: None,
            cgroup_capture: ControllerInitialCgroupReadbackV1::new(),
            cgroup_result: None,
            cgroup: None,
            membership_before: RootControllerMembershipV1::default(),
            identity_before: None,
            capture: None,
            final_properties: None,
            final_binding: None,
            final_fragment_name: None,
            nix_post: None,
            nix_post_original: Default::default(),
            fragment_post: None,
            fragment_post_original: Default::default(),
            stream_after: None,
            membership_after: RootControllerMembershipV1::default(),
            identity_after: None,
            settlement: None,
            closed: None,
            complete: false,
            capture_entered: false,
            finish_entered: false,
            finish_unwinds: std::array::from_fn(|_| None),
            body_unwind: None,
            after_unwind: None,
        }
    }

    /// Measures the actual qualifier and every retained native prefix.
    ///
    /// # Errors
    /// Refuses checked geometry overflow or unavailable native suppliers.
    pub fn fixed_demand() -> Result<ResourceVector, Error> {
        let error = || Error::Service;
        let observation = service::fixed_property_observer_demand_v1(MATERIALIZED_PROPERTY_BYTES)
            .map_err(|_| error())?;
        // The Controller profile is an opaque bounded immutable image here,
        // not another JSON decoder: 1 MiB retained read plus measured/hash
        // overlap and path copies. Fragment measurement is capped at 64 KiB.
        // Six actual cgroup FDs, two images and bounded native/proc/name temps
        // are separate from the three observer archives' real seven FDs each.
        // Original membership bookends and conservative native/proc/name
        // construction overlap are separate from current samples, whose own
        // canonical one-row supplier is admitted before each recurring call.
        let membership = aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1::
            dominant_requested_bytes_v1().ok_or_else(error)?;
        let membership = u64::try_from(membership)
            .map_err(|_| error())?
            .checked_mul(4)
            .ok_or_else(error)?;
        let construction = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Result<Result<(), Error>, Box<dyn std::any::Any + Send>>>()
                        .checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Result<(), Box<dyn std::any::Any + Send>>>()
                        .checked_mul(3)?,
                )
            })
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(error)?;
        let memory = construction.checked_add(4 * 1_048_576 + 8 * 65_536 + 32 * 4096)
            .ok_or_else(error)?
            .checked_add(membership)
            .ok_or_else(error)?;
        let fixed = ResourceVector::ZERO
            .with(D::MemoryBytes, memory)
            .with(D::OutputBytes, memory)
            .with(D::OpenFiles, 24)
            .with(D::Pids, 3);
        // The full locator comes from a paid64KiB property row. Acquisition
        // and post sinks retain their actual native prefixes; scalar controls
        // and metadata observations create no resident namespace entries.
        let acquisition =
            ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(MATERIALIZED_PROPERTY_BYTES)
                .ok_or_else(error)?;
        let post = ImmutableFileRevalidationOriginalV1::receiving_demand_v1().ok_or_else(error)?;
        fixed
            .checked_add(observation)
            .and_then(|demand| demand.checked_add(observation))
            .and_then(|demand| demand.checked_add(observation))
            .and_then(|demand| demand.checked_add(acquisition))
            .and_then(|demand| demand.checked_add(acquisition))
            .and_then(|demand| demand.checked_add(post))
            .and_then(|demand| demand.checked_add(post))
            .map_err(|_| error())
    }

    /// Runs the actual qualifier once and its independent native afters.
    ///
    /// # Errors
    /// Retains the first native, image, property, identity or comparison failure.
    /// Reentry never replaces an entered sample or permits positive settlement.
    pub fn capture_once(&mut self, stream: &RetainedUnixStream) -> Result<(), Error> {
        if self.capture_entered {
            self.closed.get_or_insert(Error::Service);
            return Err(Error::Service);
        }
        self.capture_entered = true;
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.capture = Some(self.capture_inner(stream));
        }));
        if let Err(payload) = body {
            self.body_unwind = Some(payload);
            self.closed.get_or_insert(Error::Service);
        }
        // Reached immutable/native members and an independent PID1 observation
        // are posted even when the initial comparison/measurement failed.
        let after = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.finish_once(stream)));
        if let Err(payload) = after {
            self.after_unwind = Some(payload);
            self.closed.get_or_insert(Error::Service);
        }
        // Resume only after the independently owed native after was attempted.
        // A second panic stays resident with the same native prefix.
        if let Some(payload) = self.body_unwind.take().or_else(|| self.after_unwind.take()) {
            std::panic::resume_unwind(payload);
        }
        if self.failure().is_none() && matches!(self.final_binding, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Error::Service)
        }
    }

    fn capture_inner(&mut self, stream: &RetainedUnixStream) -> Result<(), Error> {
        self.stream_before = Some(stream.revalidate_original());
        positive(&self.stream_before)?;
        let credentials = stream.peer().credentials();
        if credentials.uid() != self.startup.fields().profile.identities[0]
            || credentials.gid() != self.startup.fields().profile.identities[1]
        {
            return Err(Error::Service);
        }
        let archive = self.archive.as_mut().ok_or(Error::Service)?;
        self.preparation = Some(archive.prepare());
        positive(&self.preparation)?;
        self.initial_properties = Some(archive.read(
            service::CONTROLLER_UNIT,
            credentials.pid().get(),
            service::SERVICE_PROPERTIES,
        ));
        let (properties, _) = positive(&self.initial_properties)?;
        self.selection = Some((|| {
            let profile = selected_nix_profile(properties)?;
            let (resource_delivery, resource_launch) = selected_resource_pair(properties)?;
            // This new Create entrance requires the actual resource-delivered
            // Controller. Its optional launch member is selected by the same
            // original ordered PID1 table and remains fixed through rechecks.
            if !resource_delivery {
                return Err(Error::Service);
            }
            Ok((profile, resource_delivery, resource_launch))
        })());
        let (path, resource_delivery, resource_launch) = positive(&self.selection)?;
        if let Some(path) = path {
            self.nix_measurement =
                Some(
                    self.nix_profile
                        .open_and_measure_once(path.clone(), None, 1_048_576, false),
                );
            positive(&self.nix_measurement)?;
            self.nix_read = Some(self.nix_profile.read_completed_bounded());
            positive(&self.nix_read)?;
        }
        let (properties, unit) = positive(&self.initial_properties)?;
        self.initial = Some(
            service::immutable_observation_into(
                decode_delivery_with_resource_pair(
                    properties,
                    unit,
                    self.startup.fields().profile_file.path(),
                    path.as_deref(),
                    *resource_delivery,
                    *resource_launch,
                )?,
                &mut self.initial_fragment_name,
            )
            .map_err(Error::from),
        );
        let initial = positive(&self.initial)?;
        self.producer_properties = Some(self.archive.as_mut().ok_or(Error::Service)?.read(
            service::CONTROLLER_UNIT,
            credentials.pid().get(),
            service::RESOURCE_SERVICE_PROPERTIES,
        ));
        self.producer_binding = Some((|| {
            let (properties, unit) = positive(&self.producer_properties)?;
            let (producer, common) = properties.split_last().ok_or(Error::Service)?;
            let current = service::immutable_observation_into(
                decode_delivery_with_resource_pair(
                    common,
                    unit,
                    self.startup.fields().profile_file.path(),
                    path.as_deref(),
                    *resource_delivery,
                    *resource_launch,
                )?,
                &mut self.producer_fragment_name,
            )?;
            service::require_same(initial, &current)?;
            service::decode_resource_producer(producer).map_err(Error::from)
        })());
        positive(&self.producer_binding)?;
        self.fragment_measurement = Some(self.fragment.open_and_measure_once(
            initial.fragment.clone(),
            None,
            64 * 1024,
            false,
        ));
        positive(&self.fragment_measurement)?;
        self.cgroup_result = Some(self.cgroup_capture.capture_once());
        positive(&self.cgroup_result)?;
        self.cgroup = self.cgroup_capture.take_validated_pair();
        let (_, cgroup) = self.cgroup.as_ref().ok_or(Error::Service)?;
        let _membership = self
            .membership_before
            .capture_once(cgroup, stream.peer().pidfd());
        let info = self.membership_before.info()?;
        self.identity_before = Some(require_controller_process_identity(
            self.startup,
            credentials.pid(),
            info,
        ));
        positive(&self.identity_before).map(|_| ())
    }

    fn finish_once(&mut self, stream: &RetainedUnixStream) {
        if self.finish_entered {
            self.closed.get_or_insert(Error::Service);
            return;
        }
        self.finish_entered = true;
        let pid = stream.peer().credentials().pid();
        // Each independently owed member is attempted once before the first
        // unwind is resumed. Its actual result and any later panic stay here.
        macro_rules! finish_member {
            ($index:expr, $body:block) => {
                if let Err(payload) = std::panic::catch_unwind(
                    std::panic::AssertUnwindSafe(|| $body),
                ) {
                    self.finish_unwinds[$index] = Some(payload);
                    self.closed.get_or_insert(Error::Service);
                }
            };
        }
        finish_member!(0, {
            if matches!(self.preparation, Some(Ok(()))) {
                self.final_properties = Some(match self.archive.as_mut() {
                    Some(archive) => archive.read(
                        service::CONTROLLER_UNIT,
                        pid.get(),
                        service::RESOURCE_SERVICE_PROPERTIES,
                    ),
                    None => Err(Error::Service),
                });
                self.final_binding = Some((|| {
                    let (properties, unit) = positive(&self.final_properties)?;
                    let (producer, common) = properties.split_last().ok_or(Error::Service)?;
                    let (path, resource_delivery, resource_launch) = positive(&self.selection)?;
                    let current = service::immutable_observation_into(
                        decode_delivery_with_resource_pair(
                            common,
                            unit,
                            self.startup.fields().profile_file.path(),
                            path.as_deref(),
                            *resource_delivery,
                            *resource_launch,
                        )?,
                        &mut self.final_fragment_name,
                    )?;
                    service::require_same(positive(&self.initial)?, &current)?;
                    if service::decode_resource_producer(producer)?
                        != *positive(&self.producer_binding)?
                    {
                        return Err(Error::Service);
                    }
                    Ok(())
                })());
            }
        });
        finish_member!(1, {
            self.nix_post = self
                .nix_profile
                .observe_available_held_once_v1(&mut self.nix_post_original);
        });
        finish_member!(2, {
            self.fragment_post = self
                .fragment
                .observe_available_held_once_v1(&mut self.fragment_post_original);
        });
        finish_member!(3, {
            self.stream_after = Some(stream.revalidate_original());
        });
        finish_member!(4, {
            if let Some((_, cgroup)) = &self.cgroup {
                let _membership = self
                    .membership_after
                    .capture_once(cgroup, stream.peer().pidfd());
                self.identity_after = Some(
                    self.membership_after
                        .info()
                        .and_then(|info| require_controller_process_identity(self.startup, pid, info)),
                );
            }
        });
        if let Some(payload) = self.finish_unwinds.iter_mut().find_map(Option::take) {
            std::panic::resume_unwind(payload);
        }
    }

    // The actual caller first posts the independently retained original Root.
    // Only that full success permits explicit transport settlement and actual
    // disposal of these three positive archives. Failure keeps every original.
    /// Settles only the complete positive qualifier after its Root post.
    ///
    /// # Errors
    /// Refuses failed, incomplete, repeated or unsettled native custody.
    pub fn settle_positive_once(&mut self) -> Result<(), Error> {
        if self.settlement.is_some()
            || self.failure().is_some()
            || !matches!(self.capture, Some(Ok(())))
            || !matches!(self.final_binding, Some(Ok(())))
            || !matches!(self.identity_after, Some(Ok(())))
            || !matches!(self.fragment_post, Some(Ok(())))
        {
            self.closed.get_or_insert(Error::Service);
            return Err(Error::Service);
        }
        self.settlement = Some(match self.archive.as_mut() {
            Some(archive) => archive.settle_positive_once(),
            None => Err(Error::Service),
        });
        positive(&self.settlement)?;
        drop(self.archive.take());
        drop(self.initial_properties.take());
        drop(self.producer_properties.take());
        drop(self.final_properties.take());
        self.complete = true;
        Ok(())
    }

    /// Requires the original completed qualifier without another observation.
    ///
    /// # Errors
    /// Refuses missing settlement, incomplete custody or any retained cause.
    pub fn require_completed(&self) -> Result<(), Error> {
        if self.complete && self.failure().is_none() {
            Ok(())
        } else {
            Err(Error::Service)
        }
    }

    // Select only the actual chronological property marker. A later archive
    // refusal cannot hide an earlier native, parser or comparison cause.
    /// Borrows only the property failure selected by the actual first cause.
    pub fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        let first = self.failure()?;
        if selected_error(first, &self.preparation)
            || selected_error(first, &self.initial_properties)
            || selected_error(first, &self.producer_properties)
            || selected_error(first, &self.final_properties)
            || selected_error(first, &self.settlement)
        {
            self.archive.as_ref()?.failure_view()
        } else {
            None
        }
    }

    /// Borrows the earliest actual resident cause without native entry.
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        macro_rules! cause {
            ($slot:expr) => {
                $slot
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn StdError + 'static))
            };
        }
        cause!(self.stream_before)
            .or_else(|| cause!(self.preparation))
            .or_else(|| cause!(self.initial_properties))
            .or_else(|| cause!(self.selection))
            .or_else(|| self.nix_profile.failure())
            .or_else(|| cause!(self.nix_measurement))
            .or_else(|| cause!(self.nix_read))
            .or_else(|| cause!(self.initial_fragment_name))
            .or_else(|| cause!(self.initial))
            .or_else(|| cause!(self.producer_properties))
            .or_else(|| cause!(self.producer_fragment_name))
            .or_else(|| cause!(self.producer_binding))
            .or_else(|| self.fragment.failure())
            .or_else(|| cause!(self.fragment_measurement))
            .or_else(|| self.cgroup_capture.failure())
            .or_else(|| cause!(self.cgroup_result))
            .or_else(|| self.membership_before.failure())
            .or_else(|| cause!(self.identity_before))
            .or_else(|| cause!(self.capture))
            .or_else(|| cause!(self.final_properties))
            .or_else(|| cause!(self.final_fragment_name))
            .or_else(|| cause!(self.final_binding))
            .or_else(|| self.nix_post_original.failure())
            .or_else(|| cause!(self.nix_post))
            .or_else(|| self.fragment_post_original.failure())
            .or_else(|| cause!(self.fragment_post))
            .or_else(|| cause!(self.stream_after))
            .or_else(|| self.membership_after.failure())
            .or_else(|| cause!(self.identity_after))
            .or_else(|| cause!(self.settlement))
            .or_else(|| {
                self.closed
                    .as_ref()
                    .map(|cause| cause as &(dyn StdError + 'static))
            })
    }
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, Error> {
    slot.as_ref()
        .and_then(|result| result.as_ref().ok())
        .ok_or(Error::Service)
}

// A current sample is retained by its actual prearmed caller until both
// independent Root comparison and explicit transport settlement succeed. Its actual disposal
// frees the prepaid peak; no failed or ambiguous sample can be replaced.
/// Retains one prepaid current sample under the same actual Controller owner.
///
/// Failed native and PID1 prefixes remain resident; only a complete sample can
/// reach explicit settlement after the enclosing independent Root posts.
pub struct RootSelectedControllerCurrentSampleV1 {
    body_unwind: Option<Box<dyn std::any::Any + Send>>,
    after_unwind: Option<Box<dyn std::any::Any + Send>>,
    entry: Option<Result<(), Error>>,
    archive: service::FirstGlobalPropertyArchive,
    preparation: Option<Result<(), Error>>,
    before: RootControllerPeerNativeSampleV1,
    properties: Option<Result<Properties, Error>>,
    fragment_name: Option<std::io::Result<PathBuf>>,
    binding: Option<Result<(), Error>>,
    after: RootControllerPeerNativeSampleV1,
    completion: Option<Result<(), Error>>,
    settlement: Option<Result<(), Error>>,
    closed: Option<Error>,
}

impl RootSelectedControllerCurrentSampleV1 {
    /// Measures the actual current sample and its simultaneous native backing.
    ///
    /// # Errors
    /// Refuses checked geometry overflow or unavailable native suppliers.
    pub fn demand_v1() -> Result<ResourceVector, Error> {
        let invalid = || Error::Service;
        let row = service::fixed_property_observer_demand_v1(MATERIALIZED_PROPERTY_BYTES)
            .map_err(|_| invalid())?;
        let membership = aos_sandbox_linux::cgroup::ExactCgroupMembershipReadbackV1::
            dominant_requested_bytes_v1().ok_or_else(invalid)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(3)
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Result<Result<(), Error>, Box<dyn std::any::Any + Send>>>()
                        .checked_mul(3)?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    std::mem::size_of::<Result<(), Box<dyn std::any::Any + Send>>>()
                        .checked_mul(3)?,
                )
            })
            .and_then(|bytes| bytes.checked_add(membership.checked_mul(2)?))
            .and_then(|bytes| bytes.checked_add(8 * 4096))
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or_else(invalid)?;
        // One archive row and the actual two native bookends coexist. Each
        // membership bookend owns two descriptors. The four same-file image
        // probes retain their original metadata/digest results separately.
        let mut demand = row
            .checked_add(
                ResourceVector::ZERO
                    .with(D::MemoryBytes, bytes)
                    .with(D::OpenFiles, 4),
            )
            .map_err(|_| invalid())?;
        let image =
            crate::immutable_image::ImmutableFileRevalidationOriginalV1::receiving_demand_v1()
                .ok_or_else(invalid)?;
        for _ in 0..4 {
            demand = demand.checked_add(image).map_err(|_| invalid())?;
        }
        Ok(demand)
    }

    /// Creates the existing bounded destinations after the real caller prepays.
    ///
    /// The original observation lifetime is moved unchanged; this constructor
    /// does not sample a new clock or admit a financial or effect interval.
    pub fn new(lifetime: ObserverLifetime) -> Self {
        Self {
            body_unwind: None,
            after_unwind: None,
            entry: None,
            archive: service::FirstGlobalPropertyArchive::with_materialization_limit(
                1,
                lifetime,
                MATERIALIZED_PROPERTY_BYTES,
            ),
            preparation: None,
            before: RootControllerPeerNativeSampleV1::default(),
            properties: None,
            fragment_name: None,
            binding: None,
            after: RootControllerPeerNativeSampleV1::default(),
            completion: None,
            settlement: None,
            closed: None,
        }
    }

    /// Settles the complete current sample after the independent Root post.
    ///
    /// # Errors
    /// Refuses failed, incomplete, repeated or unsettled native custody.
    pub fn settle_after_root_post_once_v1(&mut self) -> Result<(), Error> {
        if self.settlement.is_some()
            || self.failure().is_some()
            || !matches!(self.completion, Some(Ok(())))
            || self.after.require_positive().is_err()
        {
            return Err(Error::Service);
        }
        self.settlement = Some(self.archive.settle_positive_once());
        positive(&self.settlement).map(|_| ())
    }

    /// Borrows only the property failure selected by the actual first cause.
    pub fn property_failure_view_v1(
        &self,
    ) -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>> {
        let first = self.failure()?;
        if selected_error(first, &self.preparation)
            || selected_error(first, &self.properties)
            || selected_error(first, &self.settlement)
        {
            self.archive.failure_view()
        } else {
            None
        }
    }

    /// Borrows the earliest actual resident cause without native entry.
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        macro_rules! cause {
            ($slot:expr) => {
                $slot
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn StdError + 'static))
            };
        }
        cause!(self.entry)
            .or_else(|| self.before.failure())
            .or_else(|| cause!(self.preparation))
            .or_else(|| cause!(self.properties))
            .or_else(|| cause!(self.fragment_name))
            .or_else(|| cause!(self.binding))
            .or_else(|| cause!(self.completion))
            .or_else(|| self.after.failure())
            .or_else(|| cause!(self.settlement))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

#[derive(Default)]
struct RootControllerPeerNativeSampleV1 {
    unwinds: [Option<Box<dyn std::any::Any + Send>>; 4],
    entered: bool,
    closed: Option<Error>,
    stream: Option<Result<(), aos_sandbox_linux::Error>>,
    profile: Option<Result<(), ImmutableImageErrorV1>>,
    profile_original: crate::immutable_image::ImmutableFileRevalidationOriginalV1,
    fragment: Option<Result<(), ImmutableImageErrorV1>>,
    fragment_original: crate::immutable_image::ImmutableFileRevalidationOriginalV1,
    membership: RootControllerMembershipV1,
    identity: Option<Result<(), Error>>,
}

impl RootControllerPeerNativeSampleV1 {
    fn capture(
        &mut self,
        startup: &RootStartupNativeOriginalV1,
        stream: &RetainedUnixStream,
        profile: Option<&crate::immutable_image::RetainedImmutableFileV1>,
        fragment: &crate::immutable_image::RetainedImmutableFileV1,
        cgroup: &RetainedCgroupAnchor,
    ) {
        if self.entered {
            self.closed.get_or_insert(Error::Service);
            return;
        }
        self.entered = true;
        // Keep every independently reached native post resident and attempt
        // the remaining members even if one adapter unwinds.
        macro_rules! capture_member {
            ($index:expr, $body:block) => {
                if let Err(payload) = std::panic::catch_unwind(
                    std::panic::AssertUnwindSafe(|| $body),
                ) {
                    self.unwinds[$index] = Some(payload);
                    self.closed.get_or_insert(Error::Service);
                }
            };
        }
        capture_member!(0, {
            self.stream = Some(stream.revalidate_original());
        });
        capture_member!(1, {
            if let Some(profile) = profile {
                self.profile = Some(profile.revalidate_retaining(&mut self.profile_original));
            }
        });
        capture_member!(2, {
            self.fragment = Some(fragment.revalidate_retaining(&mut self.fragment_original));
        });
        capture_member!(3, {
            let _membership = self.membership.capture_once(cgroup, stream.peer().pidfd());
            self.identity = Some((|| {
                let credentials = stream.peer().credentials();
                if credentials.uid() != startup.fields().profile.identities[0]
                    || credentials.gid() != startup.fields().profile.identities[1]
                {
                    return Err(Error::Service);
                }
                require_controller_process_identity(startup, credentials.pid(), self.membership.info()?)
            })());
        });
        if let Some(payload) = self.unwinds.iter_mut().find_map(Option::take) {
            std::panic::resume_unwind(payload);
        }
    }

    fn require_positive(&self) -> Result<(), Error> {
        if self.closed.is_some() {
            return Err(Error::Service);
        }
        positive(&self.stream)?;
        if self.profile.is_some() {
            positive(&self.profile)?;
        }
        positive(&self.fragment)?;
        self.membership.info()?;
        positive(&self.identity).map(|_| ())
    }

    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        macro_rules! cause {
            ($slot:expr) => {
                $slot
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as &(dyn StdError + 'static))
            };
        }
        cause!(self.stream)
            .or_else(|| self.profile_original.failure())
            .or_else(|| cause!(self.profile))
            .or_else(|| self.fragment_original.failure())
            .or_else(|| cause!(self.fragment))
            .or_else(|| self.membership.failure())
            .or_else(|| cause!(self.identity))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

impl RootSelectedControllerPeerOriginalV1<'_> {
    /// Observes the same Controller into its separately prepaid current sample.
    ///
    /// # Errors
    /// Refuses an incomplete or closed qualifier or changed native, image,
    /// property or identity binding. Both actual native bookends stay resident.
    pub fn observe_prearmed_current_into_v1(
        &self,
        stream: &RetainedUnixStream,
        sample: &mut RootSelectedControllerCurrentSampleV1,
    ) -> Result<(), Error> {
        if sample.entry.is_some() || sample.closed.is_some() {
            sample.closed.get_or_insert(Error::Service);
            return Err(Error::Service);
        }
        sample.entry = Some(
            if !self.complete
                || self.closed.is_some()
                || !matches!(self.capture, Some(Ok(())))
                || !matches!(self.settlement, Some(Ok(())))
            {
                Err(Error::Service)
            } else {
                Ok(())
            },
        );
        positive(&sample.entry)?;
        observe_current_sample_v1(
            self.startup,
            &self.selection,
            &self.nix_profile,
            &self.fragment,
            &self.cgroup,
            &self.initial,
            &self.producer_binding,
            stream,
            sample,
        )
    }
}

fn observe_current_sample_v1(
    startup: &RootStartupNativeOriginalV1,
    selection: &Option<Result<(Option<PathBuf>, bool, bool), Error>>,
    nix_profile: &ImmutableFileAcquisitionOriginalV1,
    fragment: &ImmutableFileAcquisitionOriginalV1,
    cgroup: &Option<(CgroupV2Root, RetainedCgroupAnchor)>,
    initial: &Option<Result<service::ServiceObservationV1, Error>>,
    producer_binding: &Option<Result<[u8; 16], Error>>,
    stream: &RetainedUnixStream,
    sample: &mut RootSelectedControllerCurrentSampleV1,
) -> Result<(), Error> {
    let profile = match positive(selection)?.0.as_ref() {
        Some(_) => Some(nix_profile.completed_measurement().ok_or(Error::Profile)?),
        None => None,
    };
    let fragment = fragment.completed_measurement().ok_or(Error::Service)?;
    let (_, cgroup) = cgroup.as_ref().ok_or(Error::Service)?;
    let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sample.before.capture(startup, stream, profile, fragment, cgroup);
        sample.completion = Some((|| {
            sample.before.require_positive()?;
            sample.preparation = Some(sample.archive.prepare());
            positive(&sample.preparation)?;
            sample.properties = Some(sample.archive.read(
                service::CONTROLLER_UNIT,
                stream.peer().credentials().pid().get(),
                service::RESOURCE_SERVICE_PROPERTIES,
            ));
            sample.binding = Some((|| {
                let (properties, unit) = positive(&sample.properties)?;
                let (producer, common) = properties.split_last().ok_or(Error::Service)?;
                let (path, resource_delivery, resource_launch) = positive(selection)?;
                let observed = service::immutable_observation_into(
                    decode_delivery_with_resource_pair(
                        common,
                        unit,
                        startup.fields().profile_file.path(),
                        path.as_deref(),
                        *resource_delivery,
                        *resource_launch,
                    )?,
                    &mut sample.fragment_name,
                )?;
                service::require_same(positive(initial)?, &observed)?;
                if service::decode_resource_producer(producer)? != *positive(producer_binding)? {
                    return Err(Error::Service);
                }
                Ok(())
        })());
        positive(&sample.binding).map(|_| ())
        })());
    }));
    if let Err(payload) = body {
        sample.body_unwind = Some(payload);
        sample.closed.get_or_insert(Error::Service);
    }
    // Every reached native member gets an independent post even when the
    // preceding PID1 comparison/decoder failed. Root posts outside next.
    let after = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sample.after.capture(startup, stream, profile, fragment, cgroup);
    }));
    if let Err(payload) = after {
        sample.after_unwind = Some(payload);
        sample.closed.get_or_insert(Error::Service);
    }
    if let Some(payload) = sample
        .body_unwind
        .take()
        .or_else(|| sample.after_unwind.take())
    {
        std::panic::resume_unwind(payload);
    }
    if sample.failure().is_none() {
        sample.after.require_positive()
    } else {
        Err(Error::Service)
    }
}

// Error-address comparison selects diagnostics only. It does not authenticate
// an observation or change the actual source/cause retained by its owner.
fn selected_error<T, E: StdError + 'static>(
    first: &(dyn StdError + 'static),
    slot: &Option<Result<T, E>>,
) -> bool {
    slot.as_ref()
        .and_then(|result| result.as_ref().err())
        .is_some_and(|cause| {
            std::ptr::addr_eq(
                first as *const (dyn StdError + 'static),
                cause as &(dyn StdError + 'static) as *const (dyn StdError + 'static),
            )
        })
}
