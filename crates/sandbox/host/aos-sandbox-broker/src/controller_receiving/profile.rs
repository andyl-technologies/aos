//! Owns original Controller profile admission and complete self observations.
//!
//! The first-table router alone supplies the private capture. Selected admission
//! joins the same genuine Controller original before measurement or growth.
//! Complete local/PID1/control observers retain failures and privately retire
//! only their own native peak; they never finish an upper protected effect.

mod admission;
pub(in crate::controller_receiving) mod baseline;
pub mod delivery;
mod error;
mod external_observation;
pub mod images;
mod local_currentness;
mod local_recipe;
mod local_prefix;
pub use local_prefix::ControllerProfileLocalPrefixOriginalV1;
pub mod observer;
mod status;
mod startup_peer;
pub mod root_flight;
mod original_observers;
pub use original_observers::{
    ControllerCreateIntakeObserverGrowthLoanV1,
    ControllerCreateIntakeObserverGrowthPreparationErrorV1,
};
pub use startup_peer::ControllerStartupRootPeerV1;
pub mod property_data;
pub mod property_values;
pub mod root_peer_data;
pub mod schema;

use std::os::fd::OwnedFd;
use std::path::Path;
use aos_sandbox_linux::guest_confinement::require_subject;
use self::delivery::{CONTEXT, CONTROLLER_UNIT as UNIT};
use self::status::require_status;
use self::observer as service;
use std::sync::Arc;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::RetainedCgroupAnchor;
use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_linux::selinux_policy::VerifiedLiveSelinuxPolicy;
use aos_systemd_client::FixedPid1PropertyArchiveV1;

use crate::immutable_image::RetainedImmutableFileV1;

use super::{ControllerReceivingErrorV1, ControllerReceivingOriginalV1};

pub use admission::{ControllerProfileAdmissionFailureV1, ControllerSelectedProfileAdmissionV1};
pub use error::ControllerProfileErrorV1;
pub use external_observation::ControllerExternalProfileObservationOriginalV1;
pub use local_currentness::ControllerProfileLocalCurrentnessOriginalV1;

/// Carries only the actual first-table router's original profile inputs.
///
/// Its fields and constructor remain inside the genuine receiving subtree.
/// Parsed models, caller files, identities and amounts cannot construct it.
pub struct ControllerProfileCaptureV1 {
    profile: Option<OwnedFd>,
    tpm_image: bool,
    nix_delivery: Option<OwnedFd>,
    resource_delivery: bool,
    resource_launch: bool,
}

impl ControllerProfileCaptureV1 {
    // The same opaque router parts may take an ordinary capture only when
    // neither actual selected resource role was delivered. No public caller
    // can create a capture or separate selected profile/enrollment inputs.
    pub(in crate::controller_receiving) fn is_ordinary_delivery_v1(&self) -> bool {
        !self.resource_delivery && !self.resource_launch
    }

    pub(in crate::controller_receiving) fn has_original_tpm_image_delivery_v1(&self) -> bool {
        self.tpm_image
    }

    pub(in crate::controller_receiving) fn from_initial_delivery(
        profile: Option<OwnedFd>,
        tpm_image: bool,
        nix_delivery: Option<OwnedFd>,
        resource_delivery: bool,
        resource_launch: bool,
    ) -> Self {
        Self {
            profile,
            tpm_image,
            nix_delivery,
            resource_delivery,
            resource_launch,
        }
    }
}

/// Owns one actual admitted Controller self profile and its native originals.
///
/// Only the shared complete admission recipe constructs this object. The
/// selected form retains the same C original and one private complete-observer
/// state. Neither DATA models nor returned property equality construct it.
pub struct ControllerSelfProfileOriginalV1 {
    profile_file: RetainedImmutableFileV1,
    profile: schema::NormalRootProfileV1,
    files: Vec<RetainedImmutableFileV1>,
    policy: VerifiedLiveSelinuxPolicy,
    fragment: RetainedImmutableFileV1,
    observed: delivery::ServiceObservationV1,
    process: PidFd,
    cgroup: RetainedCgroupAnchor,
    tpm_image: bool,
    nix_delivery: Option<RetainedImmutableFileV1>,
    resource_delivery: bool,
    resource_launch: bool,
    baseline: Option<Arc<baseline::ControllerBaselineProfileV1>>,
    original_observers: original_observers::OriginalObserverRegistryV1,
}

impl ControllerSelfProfileOriginalV1 {
    /// Borrows the actual measured profile pathname as comparison DATA.
    #[must_use]
    pub fn profile_path(&self) -> &Path {
        self.profile_file.path()
    }

    /// Reports identity association with the same retained original C.
    ///
    /// This comparison grants no scope, financial claim or operation readiness.
    #[must_use]
    pub fn has_same_baseline_original(&self, original: &ControllerReceivingOriginalV1) -> bool {
        self.baseline.as_ref().is_some_and(|baseline| {
            std::ptr::eq(Arc::as_ptr(baseline.original()), original)
        })
    }

    /// Describes this same original's complete fixed profile/credential/posts.
    ///
    /// # Errors
    /// Refuses a foreign original, missing selected admission or invalid bounds.
    pub fn original_startup_pool_bounds(
        &self,
        original: &ControllerReceivingOriginalV1,
    ) -> Result<(ResourceVector, ResourceVector, ResourceVector), ControllerReceivingErrorV1> {
        if !self.has_same_baseline_original(original) {
            return Err(ControllerReceivingErrorV1::Conflict);
        }
        self.baseline.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?
            .startup_pool_bounds()
    }

    /// Borrows immutable schema DATA from this actual admitted original.
    #[doc(hidden)]
    #[must_use]
    pub fn schema(&self) -> &schema::NormalRootProfileV1 {
        &self.profile
    }

    /// Borrows this actual profile measurement without creating another owner.
    #[doc(hidden)]
    #[must_use]
    pub fn profile_measurement(&self) -> &RetainedImmutableFileV1 {
        &self.profile_file
    }

    /// Borrows the actual runtime image measurements as comparison DATA.
    #[doc(hidden)]
    #[must_use]
    pub fn runtime_measurements(&self) -> &[RetainedImmutableFileV1] {
        &self.files
    }

    /// Borrows the same actual unit fragment measurement.
    #[doc(hidden)]
    #[must_use]
    pub fn fragment_measurement(&self) -> &RetainedImmutableFileV1 {
        &self.fragment
    }

    /// Returns this original's actual verified policy comparison DATA.
    #[doc(hidden)]
    #[must_use]
    pub fn verified_policy(&self) -> VerifiedLiveSelinuxPolicy {
        self.policy
    }

    /// Borrows the original admitted unit observation as nonauthorizing DATA.
    #[doc(hidden)]
    #[must_use]
    pub fn original_unit_observation(&self) -> &delivery::ServiceObservationV1 {
        &self.observed
    }

    /// Borrows the same original process pin without creating a process role.
    #[doc(hidden)]
    #[must_use]
    pub fn original_process(&self) -> &PidFd {
        &self.process
    }

    /// Borrows the same original cgroup anchor as native comparison DATA.
    #[doc(hidden)]
    #[must_use]
    pub fn original_cgroup(&self) -> &RetainedCgroupAnchor {
        &self.cgroup
    }

    /// Reports actual named PID1-image delivery, not physical floor authority.
    #[doc(hidden)]
    #[must_use]
    pub const fn has_tpm_image_delivery(&self) -> bool {
        self.tpm_image
    }

    /// Borrows the actual optional Nix delivery measurement.
    #[doc(hidden)]
    #[must_use]
    pub fn nix_delivery_measurement(&self) -> Option<&RetainedImmutableFileV1> {
        self.nix_delivery.as_ref()
    }

    /// Reports original resource-pair delivery as comparison DATA.
    #[doc(hidden)]
    #[must_use]
    pub const fn has_resource_delivery(&self) -> bool {
        self.resource_delivery
    }

    /// Reports the original successor-channel delivery as comparison DATA.
    #[doc(hidden)]
    #[must_use]
    pub const fn has_resource_launch(&self) -> bool {
        self.resource_launch
    }
}

// All C Runtime/credential/Publisher consumers use this one mapping of the
// same actual mechanical receiver. Caller-specific thread capacity and row
// backing remain their own explicit original-funded obligations.
pub(in crate::controller_receiving) fn fixed_property_observer_demand_v1(
    materialized_bytes: usize,
) -> Result<ResourceVector, ControllerReceivingErrorV1> {
    let geometry = FixedPid1PropertyArchiveV1::fixed_property_geometry_v1(materialized_bytes)
        .map_err(|_| ControllerReceivingErrorV1::EnrollmentUnavailable)?;
    Ok(ResourceVector::ZERO
        .with(D::MemoryBytes, geometry.memory_bytes)
        .with(D::OpenFiles, geometry.open_files)
        .with(D::MetadataEntries, geometry.metadata_entries)
        .with(D::NetworkBytes, geometry.wire_io_bytes)
        .with(D::OutputBytes, geometry.wire_io_bytes)
        .with(D::LogBytes, geometry.maximum_log_bytes))
}

impl ControllerSelfProfileOriginalV1 {
    pub(in crate::controller_receiving) fn observe_original_runtime_startup(
        &self,
        original: &std::sync::Arc<crate::controller_receiving::ControllerReceivingOriginalV1>,
        compare: impl FnOnce() -> Result<(), ControllerProfileErrorV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.baseline.as_ref().ok_or(ControllerProfileErrorV1::Service)?
            .run_runtime_startup(original, compare)
    }

    pub(in crate::controller_receiving) fn require_runtime_tasks_max(&self) -> Result<(), ControllerProfileErrorV1> {
        let (properties, _unit) = self.read_original_properties(
            UNIT, std::process::id(), service::RUNTIME_TASK_PROPERTIES,
        )?;
        let [maximum] = properties.as_slice() else {
            return Err(ControllerProfileErrorV1::Service);
        };
        if u64::try_from(maximum).ok() == Some(8) {
            Ok(())
        } else {
            Err(ControllerProfileErrorV1::Service)
        }
    }

    pub(in crate::controller_receiving) fn capture_runtime_pids(
        &self,
        read: &mut aos_sandbox_linux::cgroup::PidsLimitReadbackV1,
    ) -> Result<(), aos_sandbox_linux::cgroup::PidsLimitReadbackRefusalV1> {
        read.capture_once(&self.cgroup)
    }

    pub(in crate::controller_receiving) fn recheck_runtime_pids(
        &self,
        read: &mut aos_sandbox_linux::cgroup::PidsLimitReadbackV1,
    ) -> Result<(), aos_sandbox_linux::cgroup::PidsLimitReadbackRefusalV1> {
        read.recheck_once(&self.cgroup)
    }

    pub(in crate::controller_receiving) fn require_resource_producer(
        &self,
    ) -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1> {
        let startup = self.use_original_startup_receiver_v1()?;
        if let Some(baseline) = self.baseline.as_ref().filter(|_| startup) {
            return baseline.run_producer(|| {
                let returned = match self.require_resource_producer_original() {
                    Ok(pair) => Ok(pair),
                    Err(cause) => {
                        let retained = baseline.retain_comparison(Err(cause));
                        retained.and(Err(ControllerProfileErrorV1::Service))
                    }
                };
                let post = baseline.capture_local(self);
                match (returned, post) {
                    (Err(first), _) => Err(first),
                    (Ok(pair), Ok(())) => Ok(pair),
                    (Ok(_), Err(post)) => Err(post),
                }
            });
        }
        self.require_resource_producer_original()
    }

    pub(in crate::controller_receiving) fn observe_operation_intake_producer_v1(
        &self,
        original: &Arc<super::ControllerReceivingOriginalV1>,
        purpose: super::operation_intake::OperationIntakePurposeV1,
        slot: usize,
    ) -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1> {
        self.baseline.as_ref().ok_or(ControllerProfileErrorV1::Service)?
            .run_operation_intake_producer_v1(original, purpose, slot, || self.require_resource_producer())
    }

    pub(in crate::controller_receiving) fn operation_intake_pool_resident_demand_v1(purpose: super::operation_intake::OperationIntakePurposeV1)
        -> Result<aos_sandbox_model::ResourceVector, ControllerReceivingErrorV1>
    {
        baseline::ControllerBaselineProfileV1::operation_intake_pool_resident_demand_v1(purpose)
    }

    pub(in crate::controller_receiving) fn prepare_operation_intake_pool_once_v1(
        &self, original: &Arc<super::ControllerReceivingOriginalV1>,
        purpose: super::operation_intake::OperationIntakePurposeV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.baseline.as_ref().ok_or(ControllerProfileErrorV1::Service)?
            .prepare_operation_intake_pool_once_v1(original, purpose)
    }

    pub(in crate::controller_receiving) fn operation_intake_demand_v1(&self)
        -> Result<aos_sandbox_model::ResourceVector, ControllerReceivingErrorV1>
    {
        self.baseline.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?
            .operation_intake_demand_v1()
    }

    fn require_resource_producer_original(
        &self,
    ) -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1> {
        if !self.resource_delivery {
            return Err(ControllerProfileErrorV1::Activation);
        }
        self.recheck()?;
        let (properties, unit) = self.read_original_properties(
            UNIT, std::process::id(), service::RESOURCE_SERVICE_PROPERTIES,
        )?;
        let (producer, common) = properties.split_last()
            .ok_or(ControllerProfileErrorV1::Service)?;
        let observed = self.immutable_observation(delivery::decode_delivery_with_resource_launch(
            common, &unit, self.profile_file.path(), self.tpm_image,
            self.nix_delivery.as_ref().map(|file| file.path()), true, self.resource_launch,
        )?)?;
        delivery::require_same(&self.observed, &observed)?;
        Ok((observed.invocation, service::decode_resource_producer(producer)?))
    }

    /// Rechecks the complete same-original profile through its private receiver.
    ///
    /// # Errors
    /// Refuses changed original files, policy, process, unit or incomplete native posts.
    pub fn recheck(&self) -> Result<(), ControllerProfileErrorV1> {
        let startup = self.use_original_startup_receiver_v1()?;
        if let Some(baseline) = self.baseline.as_ref().filter(|_| startup) {
            return baseline.run(baseline::ScopeKind::Recheck, || {
                let compared = (|| {
                    baseline.capture_local(self)?;
                    let (properties, unit) = self.read_original_properties(
                        UNIT, std::process::id(), service::SERVICE_PROPERTIES,
                    )?;
                    let observed = self.immutable_observation(delivery::decode_delivery_with_resource_launch(
                        &properties, &unit, self.profile_file.path(), self.tpm_image,
                        self.nix_delivery.as_ref().map(|file| file.path()), self.resource_delivery, self.resource_launch,
                    )?)?;
                    delivery::require_same(&self.observed, &observed)
                })();
                let compared = baseline.retain_comparison(compared);
                let post = baseline.capture_local(self);
                match (compared, post) {
                    (Err(first), _) => Err(first),
                    (Ok(()), post) => post,
                }
            });
        }
        self.recheck_original()
    }

    fn recheck_original(&self) -> Result<(), ControllerProfileErrorV1> {
        self.profile_file
            .revalidate()
            .map_err(|_| ControllerProfileErrorV1::Profile)?;
        for file in &self.files {
            file.revalidate()
                .map_err(|_| ControllerProfileErrorV1::Image)?;
        }
        if let Some(profile) = &self.nix_delivery {
            profile.revalidate().map_err(|_| ControllerProfileErrorV1::Profile)?;
        }
        self.policy
            .revalidate(&self.profile.canonical_policy.path)
            .map_err(|_| ControllerProfileErrorV1::Confinement)?;
        require_subject(CONTEXT).map_err(|_| ControllerProfileErrorV1::Confinement)?;
        if rustix::process::getuid().as_raw() != self.profile.identities[0]
            || rustix::process::geteuid().as_raw() != self.profile.identities[0]
            || rustix::process::getgid().as_raw() != self.profile.identities[1]
            || rustix::process::getegid().as_raw() != self.profile.identities[1]
        {
            return Err(ControllerProfileErrorV1::Confinement);
        }
        require_status(&read_bounded("/proc/self/status", 64 * 1024)?)?;
        let info = self
            .cgroup
            .verify_exact_membership(&self.process)
            .map_err(|_| ControllerProfileErrorV1::Service)?;
        if info.parent_pid() != 1
            || !self
                .process
                .is_alive()
                .map_err(|_| ControllerProfileErrorV1::Service)?
        {
            return Err(ControllerProfileErrorV1::Service);
        }
        let (properties, unit) = self.read_original_properties(
            UNIT, std::process::id(), service::SERVICE_PROPERTIES,
        )?;
        let observed = self.immutable_observation(delivery::decode_delivery_with_resource_launch(
            &properties, &unit, self.profile_file.path(), self.tpm_image,
            self.nix_delivery.as_ref().map(|file| file.path()), self.resource_delivery, self.resource_launch,
        )?)?;
        delivery::require_same(&self.observed, &observed)?;
        self.fragment
            .revalidate()
            .map_err(|_| ControllerProfileErrorV1::Service)
    }
}

impl ControllerSelfProfileOriginalV1 {
    fn read_original_properties(
        &self,
        unit_name: &'static str,
        pid: u32,
        properties: &'static [&'static str],
    ) -> Result<service::PropertyPairV1, ControllerProfileErrorV1> {
        if !self.use_original_startup_receiver_v1()? {
            return self.original_observers.read(unit_name, pid, properties);
        }
        if let Some(baseline) = &self.baseline {
            return baseline.read(unit_name, pid, properties);
        }
        service::read_properties(unit_name, pid, properties)
            .map(|(service, unit)| (property_values::PropertyValuesV1::ordinary(service), property_values::PropertyValuesV1::ordinary(unit)))
    }
}

fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>, ControllerProfileErrorV1> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    std::fs::File::open(path).map_err(|_| ControllerProfileErrorV1::Confinement)?
        .take((maximum + 1) as u64).read_to_end(&mut bytes)
        .map_err(|_| ControllerProfileErrorV1::Confinement)?;
    if bytes.len() > maximum {
        return Err(ControllerProfileErrorV1::Confinement);
    }
    Ok(bytes)
}

/// Reports the SAME selected-profile demand engine's passive comparison DATA.
///
/// The startup and construction scopes belong to one owner, so `complete`
/// uses their componentwise high water. No count creates payment or authority.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct ControllerProfileRequestedCountsV1 {
    /// Four fixed image/policy pins plus the measured runtime-file count.
    pub pin_files: usize,
    /// Complete five-row RuntimeStartup profile scope, including pids readback.
    pub runtime_startup: crate::controller_receiving::ControllerRuntimeRequestedCountsV1,
    /// Complete twelve-row primary and independent construction-post owner.
    pub construction: crate::controller_receiving::ControllerRuntimeRequestedCountsV1,
    /// Same owner's complete high water; these scopes are not summed twice.
    pub complete: crate::controller_receiving::ControllerRuntimeRequestedCountsV1,
}


impl ControllerSelfProfileOriginalV1 {
    fn immutable_observation(
        &self,
        observed: delivery::ServiceObservationV1,
    ) -> Result<delivery::ServiceObservationV1, ControllerProfileErrorV1> {
        if !self.use_original_startup_receiver_v1()? {
            return observer::immutable_observation(observed);
        }
        match &self.baseline {
            Some(baseline) => baseline.canonicalize_observation(observed),
            None => observer::immutable_observation(observed),
        }
    }
}

impl ControllerProfileCaptureV1 {
    /// Runs the ordinary consuming admission with its original no-C behavior.
    ///
    /// The capture still comes only from the actual first-table router. A
    /// returned ordinary profile cannot satisfy selected same-C association.
    ///
    /// # Errors
    /// Preserves the original profile, image, service or confinement refusal.
    pub fn admit_ordinary(
        self,
        uid: u32,
        gid: u32,
    ) -> Result<Option<ControllerSelfProfileOriginalV1>, ControllerProfileErrorV1> {
        admission::legacy_recipe(self, uid, gid)
    }
}

impl ControllerSelfProfileOriginalV1 {
    pub(in crate::controller_receiving) fn begin_original_construction_receiving_v1(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
        purpose: super::construction::ControllerProfileConstructionPurposeV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.baseline.as_ref().ok_or(ControllerProfileErrorV1::Service)?
            .begin_construction_receiving(self, original, purpose)
    }

    pub(in crate::controller_receiving) fn finish_original_construction_receiving_v1(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
        purpose: super::construction::ControllerProfileConstructionPurposeV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.baseline.as_ref().ok_or(ControllerProfileErrorV1::Service)?
            .finish_construction_receiving(self, original, purpose)
    }
}

impl ControllerProfileCaptureV1 {
    /// Begins retained ordinary admission only when no actual C was delivered.
    ///
    /// The opaque capture still comes from the original first-table router.
    /// Selected C startup must instead remain paired in its StartupOpening.
    ///
    /// # Errors
    /// Returns the whole capture untouched if either resource role is present.
    pub fn begin_retained_ordinary_admission_v1(
        self,
    ) -> Result<ControllerSelectedProfileAdmissionV1, Self> {
        if self.resource_delivery || self.resource_launch {
            Err(self)
        } else {
            Ok(ControllerSelectedProfileAdmissionV1::new(self))
        }
    }
}

impl ControllerSelfProfileOriginalV1 {
    /// Performs this actual profile's complete fixed resource-producer comparison.
    ///
    /// The private same-C receiver drives all native/semantic/control posts. Its
    /// returned identities are comparison DATA, never an operation admission.
    ///
    /// # Errors
    /// Retains unavailable, changed or incomplete same-original observations.
    #[doc(hidden)]
    pub fn observe_controller_resource_producer_v1(
        &self,
    ) -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1> {
        self.require_resource_producer()
    }

    /// Reports the current thread's private observation dispatch as DATA only.
    ///
    /// # Errors
    /// Refuses unavailable, contended or poisoned original scheduling state.
    #[doc(hidden)]
    pub fn is_original_receiving_scope_current_v1(&self) -> Result<bool, ControllerProfileErrorV1> {
        match &self.baseline {
            Some(baseline) => baseline.is_receiving_scope_current(),
            None => Ok(false),
        }
    }

    /// Computes the same private receiver's passive bounded profile counts.
    ///
    /// # Errors
    /// Rejects unsupported pin counts or checked representation arithmetic.
    #[doc(hidden)]
    pub fn profile_receiving_requested_counts_for_runtime_files_v1(
        runtime_files: usize,
    ) -> Result<ControllerProfileRequestedCountsV1, ControllerReceivingErrorV1> {
        baseline::ControllerBaselineProfileV1::requested_counts_v1(runtime_files)
    }

    /// Computes this same original startup envelope's passive carrier counts.
    ///
    /// # Errors
    /// Rejects unsupported counts, incomplete shape or checked arithmetic failure.
    #[doc(hidden)]
    pub fn startup_envelope_requested_counts_for_runtime_files_v1(
        runtime_files: usize,
        shape: super::ControllerRuntimeStartupShapeV1,
        credentials: super::ControllerRuntimeCredentialShapeV1,
    ) -> Result<super::ControllerRuntimeRequestedCountsV1, ControllerReceivingErrorV1> {
        baseline::ControllerBaselineProfileV1::startup_envelope_requested_counts_v1(
            runtime_files, shape, credentials,
        )
    }
}

/// Borrows one actual retained profile failure and its native receiver storage.
///
/// The guard keeps the exact owning scope locked. Fixed classification and
/// phase do not replace a native cause; property-native and panic details are
/// available through the nested actual Systemd failure guard when that was
/// the selected chronological stage. Neither guard grants observation reuse.
pub struct ControllerProfileFailureViewV1<'profile> {
    inner: baseline::BaselineFailureView<'profile>,
}

impl ControllerProfileFailureViewV1<'_> {
    /// Borrows the first directly stored cause without moving any original.
    #[must_use]
    pub fn cause(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.cause()
    }

    /// Reports the selected original phase as fixed diagnostic DATA.
    #[must_use]
    pub fn phase(&self) -> &'static str {
        self.inner.phase()
    }

    /// Reports the original fixed privacy-preserving classification.
    #[must_use]
    pub fn classification(&self) -> ControllerProfileErrorV1 {
        self.inner.classification()
    }

    /// Borrows the actual native property flight for its selected first stage.
    ///
    /// A later failed owed flight cannot replace an earlier semantic/local
    /// cause. The returned view and any nested native loan borrow this guard.
    #[must_use]
    pub fn property_failure(&self) -> Option<aos_systemd_client::FixedPid1PropertyFailureViewV1<'_>> {
        self.inner.property_failure()
    }
}

impl ControllerSelfProfileOriginalV1 {
    /// Borrows the original primary profile failure without cloning its cause.
    #[must_use]
    pub fn failure_view_v1(&self) -> Option<ControllerProfileFailureViewV1<'_>> {
        Some(ControllerProfileFailureViewV1 { inner: self.baseline.as_ref()?.failure_view()? })
    }
}

impl ControllerSelfProfileOriginalV1 {
    /// Reports whether this actual profile retained an original selected C.
    ///
    /// This readonly projection cannot enter or settle its private receiver.
    #[doc(hidden)]
    #[must_use]
    pub fn has_selected_receiving_original_v1(&self) -> bool {
        self.baseline.is_some()
    }

    /// Runs the fixed Publisher producer comparison under this same original.
    ///
    /// # Errors
    /// Retains a foreign original, unavailable native input or failed comparison.
    #[doc(hidden)]
    pub fn observe_publisher_resource_producer_v1(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
    ) -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1> {
        self.baseline.as_ref().ok_or(ControllerProfileErrorV1::Service)?
            .run_publisher_producer(original, || self.require_resource_producer())
    }

    /// Reports the actual complete two-row Producer scope's receiving cost.
    ///
    /// The same private scope recipe funds the real selected C entry before
    /// archive/worker construction. This passive projection admits no IO,
    /// constructs no scope and issues no C, J or U permission.
    ///
    /// # Errors
    /// Rejects missing original custody, contention or checked recipe overflow.
    #[doc(hidden)]
    pub fn create_storage_producer_receiving_demand_v1(
        &self,
    ) -> Result<aos_sandbox_model::ResourceVector, ControllerReceivingErrorV1> {
        self.baseline.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?
            .create_storage_producer_demand_v1()
    }

    /// Reports cumulative wire and log bounds for actual Producer calls.
    ///
    /// Each call executes two sequential property reads through the same real
    /// selected-C scope. Its resident/native peak remains separately funded;
    /// disposing a successful scope never refunds these cumulative byte costs.
    /// Returns `None` for unavailable original cost DATA or checked overflow.
    #[doc(hidden)]
    #[must_use]
    pub fn create_storage_producer_traffic_v1(&self, producer_calls: usize) -> Option<(u64, u64)> {
        // Preserve actual original availability; the bound itself is also
        // available to the pure identical Root/C recipe below.
        self.create_storage_producer_receiving_demand_v1().ok()?;
        Self::create_storage_producer_traffic_bound_v1(producer_calls)
    }

    /// Reports the fixed Producer wire/log bound without an original owner.
    ///
    /// This passive geometry uses the same native row supplier and Producer
    /// row count as the actual private scope. It selects no file count, payer,
    /// entry, role or result and cannot substitute for actual C admission.
    /// Returns `None` on checked arithmetic or native geometry overflow.
    #[doc(hidden)]
    #[must_use]
    pub fn create_storage_producer_traffic_bound_v1(producer_calls: usize) -> Option<(u64, u64)> {
        baseline::ControllerBaselineProfileV1::create_storage_producer_traffic_bound_v1(producer_calls)
    }

    /// Runs only the fixed same-profile receiving producer comparison for J.
    ///
    /// The genuine upper J purpose keeps its own financial and lifetime guards.
    ///
    /// # Errors
    /// Retains unavailable original input or failed native/semantic posts.
    #[doc(hidden)]
    pub fn observe_create_storage_resource_producer_v1(
        &self,
    ) -> Result<([u8; 16], [u8; 16]), ControllerProfileErrorV1> {
        self.baseline.as_ref().ok_or(ControllerProfileErrorV1::Service)?
            .run_create_storage_producer(|| self.require_resource_producer())
    }
}

impl ControllerSelfProfileOriginalV1 {
    /// Reserves the two existing fixed construction post lanes on the same C.
    ///
    /// # Errors
    /// Retains the actual original/profile/phase/financial refusal.
    #[doc(hidden)]
    pub fn reserve_fixed_construction_posts_once_v1(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.baseline.as_ref().ok_or(ControllerProfileErrorV1::Service)?
            .reserve_construction_posts_once(original)
    }

    /// Runs only the actual fixed Source construction post on this same C.
    ///
    /// # Errors
    /// Retains the same profile/control/pair/native refusal; no caller body is
    /// accepted and an earlier pair error still runs its independent post.
    #[doc(hidden)]
    pub fn observe_source_construction_post_retaining_v1(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
        observation: &mut super::ControllerOriginalObservationV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.observe_fixed_construction_post_retaining_v1(original, observation,
            super::original::ControllerConstructionPostV1::SourceConstruction)
    }

    /// Runs only the actual fixed Controller construction post on this same C.
    ///
    /// # Errors
    /// Retains the same profile/control/pair/native refusal and independent post.
    #[doc(hidden)]
    pub fn observe_controller_construction_post_retaining_v1(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
        observation: &mut super::ControllerOriginalObservationV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.observe_fixed_construction_post_retaining_v1(original, observation,
            super::original::ControllerConstructionPostV1::ControllerConstruction)
    }

    fn observe_fixed_construction_post_retaining_v1(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
        observation: &mut super::ControllerOriginalObservationV1,
        purpose: super::original::ControllerConstructionPostV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        if !self.has_same_baseline_original(original) {
            return Err(ControllerProfileErrorV1::Service);
        }
        self.baseline.as_ref().ok_or(ControllerProfileErrorV1::Service)?
            .run_construction_post(purpose, || {
                observation.observe_once(original, self)
                    .map(|_| ()).map_err(|_| ControllerProfileErrorV1::Service)
            })
    }
}

impl ControllerSelfProfileOriginalV1 {
    pub(in crate::controller_receiving) fn begin_startup_credential_receiving_v1(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
        purpose: super::startup_envelope::CredentialPurposeV1,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.baseline.as_ref().ok_or(ControllerProfileErrorV1::Service)?
            .begin_startup_credential_receiving(original, purpose)
    }

    pub(in crate::controller_receiving) fn finish_startup_credential_receiving_v1(
        &self,
        original: &Arc<ControllerReceivingOriginalV1>,
        purpose: super::startup_envelope::CredentialPurposeV1,
        comparison: Result<(), ControllerProfileErrorV1>,
    ) -> Result<(), ControllerProfileErrorV1> {
        self.baseline.as_ref().ok_or(ControllerProfileErrorV1::Service)?
            .finish_startup_credential_receiving(original, purpose, comparison)
    }
}

impl ControllerSelfProfileOriginalV1 {
    /// Compares only an inert completed Cache association with this profile.
    ///
    /// This readonly DATA comparison enters no scope, performs no IO and
    /// establishes neither currentness nor financial admission.
    #[must_use]
    pub fn matches_cache_original_data_v1(
        &self,
        held: &super::bank_launch::CacheControllerOriginalRefV1,
    ) -> bool {
        held.matches_profile_original(self)
    }
}

pub(in crate::controller_receiving) use baseline::BaselineFailureView;

impl ControllerSelfProfileOriginalV1 {
    pub(in crate::controller_receiving) fn operation_intake_failure_view_v1(
        &self, purpose: super::operation_intake::OperationIntakePurposeV1, slot: usize,
    ) -> Option<BaselineFailureView<'_>> {
        self.baseline.as_ref()?.operation_intake_failure_view_v1(purpose, slot)
    }
}


impl ControllerSelfProfileOriginalV1 {
    // The owned staged receiver shares only the actual private scope owner.
    // Immutable profile anchors stay with the genuine upper profile; each
    // native reborrow rejoins this exact Arc before using those anchors.
    pub(in crate::controller_receiving) fn provisioning_scope_owner_v1(
        &self,
    ) -> Option<&Arc<baseline::ControllerBaselineProfileV1>> {
        self.baseline.as_ref()
    }
}

impl ControllerSelfProfileOriginalV1 {
    pub(in crate::controller_receiving) fn provisioning_receiving_demand_v1(
        &self,
    ) -> Result<ResourceVector, ControllerReceivingErrorV1> {
        self.baseline.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?
            .provisioning_demand_v1()
    }
}

impl<'owner> ControllerProfileFailureViewV1<'owner> {
    pub(in crate::controller_receiving) fn from_baseline_v1(inner: baseline::BaselineFailureView<'owner>) -> Self {
        Self { inner }
    }
}

impl ControllerSelfProfileOriginalV1 {
    pub(in crate::controller_receiving) fn provisioning_completion_receiving_demand_v1(&self)
        -> Result<ResourceVector, ControllerReceivingErrorV1> {
        self.baseline.as_ref().ok_or(ControllerReceivingErrorV1::Conflict)?
            .provisioning_completion_demand_v1()
    }
}
