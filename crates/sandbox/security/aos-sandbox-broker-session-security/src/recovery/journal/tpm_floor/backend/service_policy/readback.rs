//! Retains one bounded PID1 policy flight and both actual launch-profile posts.
//!
//! The genuine physical purpose supplies its same launch image, prepays this
//! complete receiving geometry and retains the whole failed owner. This sink
//! has no public constructor, payer, role claim or native completion callback.

use std::error::Error;
use std::path::PathBuf;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::StorageCgroupLayoutV1;
use aos_systemd_client::{
    FixedPid1PropertyArchiveV1, FixedPid1PropertyErrorV1, FixedPid1PropertyWorkerSlotV1,
    FixedPid1PropertyFailureViewV1, FixedPid1PropertyValuesV1,
    PropertyValueErrorV1,
};

use crate::production_startup::{LaunchProfileCurrentnessOriginalV1, Pid1LaunchImageV1};
use crate::BrokerSessionSecurityError;

use super::{FloorEndpointV1, FloorErrorV1, OwnedValue, PolicyObservationV1,
    SERVICE_PROPERTIES, UNIT_PROPERTIES, fixed_endpoint, unit_name,
    has_exact_launch_fd_properties, has_exact_owner_context};

const MATERIALIZED_BYTES: usize = 64 * 1024;

struct PolicyClaimsOriginalV1 {
    layout: StorageCgroupLayoutV1,
    drop_clone: Option<Result<(), PropertyValueErrorV1>>,
    drop_ins: Option<Result<Vec<String>, PropertyValueErrorV1>>,
    invocation_clone: Option<Result<(), PropertyValueErrorV1>>,
    invocation: Option<Result<Vec<u8>, PropertyValueErrorV1>>,
    expected_cgroup: Option<&'static str>,
    strings: [Option<Result<(), PropertyValueErrorV1>>; 2],
    cgroup: Option<Result<(), PropertyValueErrorV1>>,
    timeout: Option<Result<u64, PropertyValueErrorV1>>,
    transient: Option<Result<bool, PropertyValueErrorV1>>,
    store_maximum: Option<Result<u32, PropertyValueErrorV1>>,
    stored_fds: Option<Result<u32, PropertyValueErrorV1>>,
    fragment: Option<Result<(), PropertyValueErrorV1>>,
}

impl PolicyClaimsOriginalV1 {
    fn new(layout: StorageCgroupLayoutV1) -> Self {
        Self { layout, drop_clone: None, drop_ins: None, invocation_clone: None,
            invocation: None, expected_cgroup: None,
            strings: [None, None], cgroup: None, timeout: None, transient: None,
            store_maximum: None, stored_fds: None, fragment: None,
        }
    }

    fn capture_string<'value>(
        value: &'value OwnedValue,
        original: &mut Option<Result<(), PropertyValueErrorV1>>,
    ) -> Result<&'value str, FloorErrorV1> {
        match <&str>::try_from(value) {
            Ok(value) => {
                *original = Some(Ok(()));
                Ok(value)
            }
            Err(cause) => {
                *original = Some(Err(cause));
                Err(FloorErrorV1::Provisioning)
            }
        }
    }

    fn cgroup<'value>(&mut self, value: &'value OwnedValue) -> Result<&'value str, FloorErrorV1> {
        Self::capture_string(value, &mut self.cgroup)
    }

    fn fragment<'value>(&mut self, value: &'value OwnedValue) -> Result<&'value str, FloorErrorV1> {
        Self::capture_string(value, &mut self.fragment)
    }

    fn string_is(&mut self, value: &OwnedValue, index: usize, expected: &str) -> bool {
        Self::capture_string(value, &mut self.strings[index])
            .is_ok_and(|value| value == expected)
    }

    fn capture_drop_ins(&mut self, input: &OwnedValue) -> Result<bool, FloorErrorV1> {
        let value = match input.try_clone() {
            Ok(value) => { self.drop_clone = Some(Ok(())); value }
            Err(cause) => {
                self.drop_clone = Some(Err(cause));
                return Err(FloorErrorV1::Provisioning);
            }
        };
        self.drop_ins = Some(Vec::<String>::try_from(value));
        match &self.drop_ins {
            Some(Ok(values)) => Ok(values.is_empty()),
            _ => Err(FloorErrorV1::Provisioning),
        }
    }

    fn capture_invocation(&mut self, input: &OwnedValue) -> Result<usize, FloorErrorV1> {
        let value = match input.try_clone() {
            Ok(value) => { self.invocation_clone = Some(Ok(())); value }
            Err(cause) => {
                self.invocation_clone = Some(Err(cause));
                return Err(FloorErrorV1::Provisioning);
            }
        };
        self.invocation = Some(Vec::<u8>::try_from(value));
        match &self.invocation {
            Some(Ok(value)) => Ok(value.len()),
            _ => Err(FloorErrorV1::Provisioning),
        }
    }

    fn invocation_is_zero(&self) -> bool {
        matches!(&self.invocation, Some(Ok(value)) if value.iter().all(|byte| *byte == 0))
    }

    fn take_invocation(&mut self) -> Result<Vec<u8>, FloorErrorV1> {
        match self.invocation.take() {
            Some(Ok(value)) => Ok(value),
            original => {
                self.invocation = original;
                Err(FloorErrorV1::Provisioning)
            }
        }
    }

    fn expected_cgroup(&mut self, endpoint: FloorEndpointV1) -> Result<&'static str, FloorErrorV1> {
        self.expected_cgroup = Some(match (endpoint, self.layout) {
            (FloorEndpointV1::StorageBroker, layout) => layout.main_control_group_v1(),
            (FloorEndpointV1::ControllerStorageClient, StorageCgroupLayoutV1::Ordinary) => {
                "/aos.slice/aos-control.slice/aos-sandboxd.service"
            }
            (FloorEndpointV1::ControllerStorageClient, StorageCgroupLayoutV1::ReceivingAggregate) => {
                return Err(FloorErrorV1::Provisioning);
            }
        });
        self.expected_cgroup.ok_or(FloorErrorV1::Provisioning)
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        error(&self.drop_clone).or_else(|| error(&self.drop_ins))
            .or_else(|| error(&self.invocation_clone)).or_else(|| error(&self.invocation))
            .or_else(|| error(&self.cgroup))
            .or_else(|| error(&self.strings[0])).or_else(|| error(&self.strings[1]))
            .or_else(|| error(&self.timeout)).or_else(|| error(&self.transient))
            .or_else(|| error(&self.store_maximum)).or_else(|| error(&self.stored_fds))
            .or_else(|| error(&self.fragment))
    }
}

#[derive(Clone, Copy)]
enum FirstV1 { Preparation, Before, Deadline, Properties, Claims, Canonical, After, Settlement, Closed }

pub(crate) struct FloorServicePolicyReadbackV1 {
    archive: FixedPid1PropertyArchiveV1,
    preparation: Option<Result<(), FixedPid1PropertyErrorV1>>,
    profile_before: LaunchProfileCurrentnessOriginalV1,
    before: Option<Result<Option<PathBuf>, BrokerSessionSecurityError>>,
    deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    deadline_original: crate::dormant_handshake::BrokerColdDeadlineObservationV1,
    deadline_result: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    worker_entry: Option<Result<(), FixedPid1PropertyErrorV1>>,
    values: Option<Result<FixedPid1PropertyValuesV1, FixedPid1PropertyErrorV1>>,
    claims: PolicyClaimsOriginalV1,
    decoded: Option<Result<PolicyObservationV1, FloorErrorV1>>,
    canonical: Option<std::io::Result<PathBuf>>,
    canonical_binding: Option<Result<(), FloorErrorV1>>,
    profile_after: LaunchProfileCurrentnessOriginalV1,
    after: Option<Result<(), BrokerSessionSecurityError>>,
    settlement: Option<Result<(), FixedPid1PropertyErrorV1>>,
    returned: Option<Result<(), FloorErrorV1>>,
    reentry: Option<FloorErrorV1>,
    first: Option<FirstV1>,
    entered: bool,
    taken: bool,
}

impl FloorServicePolicyReadbackV1 {
    /// Creates inert storage for one fixed closed cgroup recipe.
    pub(crate) fn new(layout: StorageCgroupLayoutV1) -> Self {
        Self {
            archive: FixedPid1PropertyArchiveV1::with_materialization_limit(1, MATERIALIZED_BYTES),
            preparation: None,
            profile_before: LaunchProfileCurrentnessOriginalV1::new(), before: None,
            deadline: None,
            deadline_original: crate::dormant_handshake::BrokerColdDeadlineObservationV1::new(),
            deadline_result: None, worker_entry: None, values: None, claims: PolicyClaimsOriginalV1::new(layout), decoded: None,
            canonical: None, canonical_binding: None,
            profile_after: LaunchProfileCurrentnessOriginalV1::new(), after: None,
            settlement: None, returned: None, reentry: None, first: None,
            entered: false, taken: false,
        }
    }

    pub(crate) fn with_shared_provider_v1(
        layout: StorageCgroupLayoutV1, provider: std::sync::Arc<aos_systemd_client::SharedFixedPid1PropertyProviderV1>,
    ) -> Self {
        let mut original = Self::new(layout);
        original.archive = FixedPid1PropertyArchiveV1::with_shared_provider_v1(
            1, MATERIALIZED_BYTES, std::sync::Arc::clone(&provider),
        );
        original.profile_before = LaunchProfileCurrentnessOriginalV1::with_shared_provider_v1(
            std::sync::Arc::clone(&provider),
        );
        original.profile_after = LaunchProfileCurrentnessOriginalV1::with_shared_provider_v1(provider);
        original
    }

    pub(crate) fn receiving_shared_demand_v1(image: &Pid1LaunchImageV1) -> Option<ResourceVector> {
        let full = Self::receiving_demand_v1(image)?;
        let profile = image.profile_currentness_shared_receiving_demand_v1()?;
        Some(full.with(D::OpenFiles, profile.get(D::OpenFiles).checked_mul(2)?))
    }

    /// Describes this real row and both simultaneous failed profile samples.
    ///
    /// The caller separately funds its fixed original images/service owner and
    /// independently associates the chosen layout with its admitted role.
    pub(crate) fn receiving_demand_v1(image: &Pid1LaunchImageV1) -> Option<ResourceVector> {
        let row = FixedPid1PropertyArchiveV1::fixed_property_geometry_v1(MATERIALIZED_BYTES).ok()?;
        let profile = image.profile_currentness_receiving_demand_v1()?;
        // Every admitted encoded byte can nominate one actual cloned Value,
        // one converted String header and one byte of payload. The two typed
        // conversion prefixes coexist on failure. Four bounded path buffers
        // retain expected delivery, decoded/canonical and updated fragment.
        let cell = std::mem::size_of::<OwnedValue>()
            .checked_add(std::mem::size_of::<String>())?.checked_add(1)?;
        let conversions = MATERIALIZED_BYTES.checked_mul(cell.checked_mul(2)?)?;
        let memory = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(FixedPid1PropertyArchiveV1::entry_bytes_v1())?
            .checked_add(conversions)?.checked_add(4096_usize.checked_mul(4)?)?
            .checked_add(std::mem::size_of::<rustix::time::Timespec>().checked_mul(2)?)?;
        // These native/property/decoded carriers create no resident namespace
        // entries. Their concrete layouts and conservative decoder overhead
        // remain byte provision; descriptors and traffic are separate below.
        let own = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).ok()?.checked_add(row.memory_bytes)?)
            .with(D::OpenFiles, row.open_files)
            .with(D::MetadataEntries, 0)
            .with(D::Pids, row.worker_threads)
            .with(D::NetworkBytes, row.wire_io_bytes)
            .with(D::LogBytes, row.maximum_log_bytes);
        own.checked_add(profile).ok()?.checked_add(profile).ok()
    }

    /// Prices only the ordinary short-circuit policy comparison's FD peak.
    ///
    /// A failed before-profile skips the central row but still owes the after
    /// profile. A successful before-profile has disposed its native probes;
    /// a failed central row then coexists with the full after-profile. The
    /// independently owed policy recipe instead keeps its full summed bound.
    pub(crate) fn receiving_primary_demand_v1(image: &Pid1LaunchImageV1) -> Option<ResourceVector> {
        let complete = Self::receiving_demand_v1(image)?;
        let profile = image.profile_currentness_receiving_demand_v1()?.get(D::OpenFiles);
        let row = aos_systemd_client::FixedPid1PropertyArchiveV1::fixed_property_geometry_v1(MATERIALIZED_BYTES).ok()?;
        let files = profile.checked_mul(2)?.max(row.open_files.checked_add(profile)?);
        Some(complete.with(D::OpenFiles, files))
    }

    /// Captures one same-image policy comparison and its independent profile post.
    pub(crate) fn observe_once(&mut self, endpoint: FloorEndpointV1, image: &Pid1LaunchImageV1)
        -> Result<(), FloorErrorV1>
    {
        self.observe_with_deadline(endpoint, image, None)
    }

    // The actual physical caller supplies its already retained original cutoff.
    // None preserves callers without that deadline; it does not renew one.
    pub(crate) fn observe_with_deadline(
        &mut self,
        endpoint: FloorEndpointV1,
        image: &Pid1LaunchImageV1,
        deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    ) -> Result<(), FloorErrorV1> {
        self.observe_with_deadline_recipe(endpoint, image, deadline, false)
    }

    // Only the prearmed Controller physical continuation selects this route.
    // The whole result remains negative if the earlier profile comparison
    // failed; available bounded PID1 IO and its independent post still run.
    pub(crate) fn observe_controller_owed_with_deadline_v1(
        &mut self, image: &Pid1LaunchImageV1,
        deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    ) -> Result<(), FloorErrorV1> {
        self.observe_with_deadline_recipe(FloorEndpointV1::ControllerStorageClient, image, deadline, true)
    }

    fn observe_with_deadline_recipe(
        &mut self, endpoint: FloorEndpointV1, image: &Pid1LaunchImageV1,
        deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>, owed: bool,
    ) -> Result<(), FloorErrorV1> {
        if self.entered {
            self.reentry.get_or_insert(FloorErrorV1::Provisioning);
            self.first.get_or_insert(FirstV1::Closed);
            return Err(FloorErrorV1::Provisioning);
        }
        self.entered = true;
        self.deadline = deadline;
        self.preparation = Some(self.archive.prepare_once());
        let primary = if matches!(self.preparation, Some(Ok(()))) {
            self.observe_policy(endpoint, image, owed)
        } else {
            self.first = Some(FirstV1::Preparation);
            Err(FloorErrorV1::Unavailable)
        };
        // This post is independently owed even when the bounded worker or its
        // actual typed comparison refuses. It grants no healthy continuation.
        self.after = Some(image.recheck_profile_delivery_retaining_with_deadline_v1(
            fixed_endpoint(endpoint), &mut self.profile_after, self.deadline,
        ).map(|_| ()));
        if self.first.is_none() && !matches!(self.after, Some(Ok(()))) {
            self.first = Some(FirstV1::After);
        }
        if primary.is_ok() && matches!(self.after, Some(Ok(()))) {
            self.settlement = Some(self.archive.settle_positive_once());
            if !matches!(self.settlement, Some(Ok(()))) { self.first = Some(FirstV1::Settlement); }
        }
        self.returned = Some(match self.first {
            None => Ok(()),
            Some(FirstV1::Before | FirstV1::Claims | FirstV1::Canonical | FirstV1::After) => {
                Err(FloorErrorV1::Provisioning)
            }
            Some(FirstV1::Preparation | FirstV1::Deadline | FirstV1::Properties | FirstV1::Settlement | FirstV1::Closed) => {
                Err(FloorErrorV1::Unavailable)
            }
        });
        if !matches!(self.returned, Some(Ok(()))) {
            // A later independently owed comparison must never retire this
            // earlier failed comparison's shared raw/native interval.
            self.archive.preserve_shared_interval_failure_v1();
        }
        match self.returned {
            Some(result) => result,
            None => Err(FloorErrorV1::Unavailable),
        }
    }

    fn observe_policy(&mut self, endpoint: FloorEndpointV1, image: &Pid1LaunchImageV1, owed: bool)
        -> Result<(), FloorErrorV1>
    {
        self.before = Some(image.recheck_profile_delivery_retaining_with_deadline_v1(
            fixed_endpoint(endpoint), &mut self.profile_before, self.deadline,
        ).map(|path| path.map(PathBuf::from)));
        if !matches!(self.before, Some(Ok(_))) {
            self.first.get_or_insert(FirstV1::Before);
            if !owed { return Err(FloorErrorV1::Provisioning); }
        }
        let mut slot = FixedPid1PropertyWorkerSlotV1::acquire();
        self.deadline_result = Some(match self.deadline {
            Some(deadline) => deadline.check_retaining_once_v1(&mut self.deadline_original),
            None => Ok(()),
        });
        if !matches!(self.deadline_result, Some(Ok(()))) {
            self.first.get_or_insert(FirstV1::Deadline);
            return Err(FloorErrorV1::Unavailable);
        }
        if let Some(deadline) = self.deadline {
            self.worker_entry = Some(self.archive.restrict_shared_entry_boottime_v1(deadline.value()));
            if !matches!(self.worker_entry, Some(Ok(()))) {
                self.first.get_or_insert(FirstV1::Deadline);
                return Err(FloorErrorV1::Unavailable);
            }
        }
        self.values = Some(self.archive.read_under_slot(
            &mut slot, unit_name(endpoint), std::process::id(),
            SERVICE_PROPERTIES, UNIT_PROPERTIES,
        ));
        // The real worker has joined, including on native failure. Release
        // only its task slot before decoding and the independently owed post.
        drop(slot);
        let Some(Ok(values)) = &self.values else {
            self.first.get_or_insert(FirstV1::Properties);
            return Err(FloorErrorV1::Unavailable);
        };
        let service = values.0.as_slice();
        let unit = values.1.as_slice();
        let expected_profile = self.before.as_ref().and_then(|result| result.as_ref().ok())
            .and_then(|path| path.as_deref());
        let claims = &mut self.claims;
        self.decoded = Some((|| {
            policy_claim_recipe!(Retained, claims, service, unit, endpoint, expected_profile)
        })());
        let Some(Ok(observed)) = self.decoded.as_mut() else {
            self.first.get_or_insert(FirstV1::Claims);
            return Err(FloorErrorV1::Provisioning);
        };
        self.canonical = Some(std::fs::canonicalize(&observed.fragment));
        self.canonical_binding = Some((|| {
            let path = self.canonical.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(FloorErrorV1::Provisioning)?;
            if !path.starts_with("/nix/store")
                || path.file_name().is_none_or(|name| name != unit_name(endpoint))
            {
                return Err(FloorErrorV1::Provisioning);
            }
            observed.fragment = path.clone();
            Ok(())
        })());
        if !matches!(self.canonical_binding, Some(Ok(()))) {
            self.first.get_or_insert(FirstV1::Canonical);
            return Err(FloorErrorV1::Provisioning);
        }
        Ok(())
    }

    /// Moves only this actual positive observation, retaining its native archive.
    pub(crate) fn take_completed_once(&mut self) -> Option<PolicyObservationV1> {
        if self.taken || self.reentry.is_some() || !matches!(self.returned, Some(Ok(()))) {
            return None;
        }
        match self.decoded.take() {
            Some(Ok(observed)) => { self.taken = true; Some(observed) }
            original => { self.decoded = original; None }
        }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            FirstV1::Preparation => error(&self.preparation),
            FirstV1::Before => self.profile_before.failure().or_else(|| error(&self.before)),
            FirstV1::Deadline => self.deadline_original.failure().or_else(|| error(&self.deadline_result))
                .or_else(|| error(&self.worker_entry)),
            FirstV1::Properties => error(&self.values),
            FirstV1::Claims => self.claims.failure().or_else(|| error(&self.decoded)),
            FirstV1::Canonical => error(&self.canonical).or_else(|| error(&self.canonical_binding)),
            FirstV1::After => self.profile_after.failure().or_else(|| error(&self.after)),
            FirstV1::Settlement => error(&self.settlement),
            FirstV1::Closed => self.reentry.as_ref().map(|cause| cause as _),
        }
    }

    /// Borrows richer native errors only when the actual worker failed first.
    pub(crate) fn property_failure_view_v1(&self) -> Option<FixedPid1PropertyFailureViewV1<'_>> {
        match self.first? {
            FirstV1::Before => self.profile_before.property_failure_view_v1(),
            FirstV1::After => self.profile_after.property_failure_view_v1(),
            FirstV1::Preparation | FirstV1::Properties | FirstV1::Settlement => self.archive.failure_view(),
            _ => None,
        }
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_systemd_client::Value;

    fn value(value: impl Into<Value<'static>>) -> OwnedValue {
        OwnedValue::try_from(value.into()).unwrap()
    }

    fn controller_claims() -> (Vec<OwnedValue>, Vec<OwnedValue>) {
        let service = vec![
            value("cgroup"),
            value("control-group"),
            OwnedValue::from(u64::MAX),
            value("/aos.slice/aos-control.slice/aos-sandboxd.service"),
            value(vec![(
                "/proc/1/exe".to_owned(),
                aos_sandbox_storage::activation::PID1_LAUNCH_IMAGE_FD_NAME.to_owned(),
                1_u64,
            )]),
            value(Vec::<String>::new()),
            OwnedValue::from(0_u32),
            OwnedValue::from(0_u32),
            value((false, "system_u:system_r:aos_sandbox_controller_t")),
        ];
        let unit = vec![
            value("/nix/store/fixture/aos-sandboxd.service"),
            value(Vec::<String>::new()),
            OwnedValue::from(false),
            value(vec![1_u8; 16]),
        ];
        (service, unit)
    }

    #[test]
    fn retained_policy_claims_match_the_ordinary_decoder() {
        let (service, unit) = controller_claims();
        let endpoint = FloorEndpointV1::ControllerStorageClient;
        let expected_profile = None;
        let service = service.as_slice();
        let unit = unit.as_slice();
        let ordinary = super::super::decode_policy_claims(
            &service, &unit, endpoint, expected_profile,
        ).unwrap();
        let mut claims = PolicyClaimsOriginalV1::new(StorageCgroupLayoutV1::Ordinary);
        let retained: Result<PolicyObservationV1, FloorErrorV1> = (|| {
            policy_claim_recipe!(Retained, claims, service, unit, endpoint, expected_profile)
        })();
        let retained = retained.unwrap();

        assert_eq!(retained.fragment, ordinary.fragment);
        assert_eq!(retained.control_group, ordinary.control_group);
        assert_eq!(retained.invocation, ordinary.invocation);
        assert!(matches!(claims.invocation, None));
        assert!(claims.failure().is_none());
    }

    #[test]
    fn rejected_policy_retains_actual_converted_invocation_and_drop_ins() {
        let (service, mut unit) = controller_claims();
        unit[3] = value(vec![0_u8; 16]);
        let endpoint = FloorEndpointV1::ControllerStorageClient;
        let expected_profile = None;
        let service = service.as_slice();
        let unit = unit.as_slice();
        let mut claims = PolicyClaimsOriginalV1::new(StorageCgroupLayoutV1::Ordinary);
        let retained: Result<PolicyObservationV1, FloorErrorV1> = (|| {
            policy_claim_recipe!(Retained, claims, service, unit, endpoint, expected_profile)
        })();

        assert!(retained.is_err());
        assert!(matches!(&claims.drop_ins, Some(Ok(paths)) if paths.is_empty()));
        assert!(matches!(&claims.invocation, Some(Ok(bytes)) if bytes == &[0_u8; 16]));
        assert!(super::super::decode_policy_claims(
            &service, &unit, endpoint, expected_profile,
        ).is_err());
    }

    #[test]
    fn rejected_typed_policy_conversion_lends_its_actual_error() {
        let mut claims = PolicyClaimsOriginalV1::new(StorageCgroupLayoutV1::Ordinary);
        let input = OwnedValue::from(3_u32);
        assert!(claims.capture_drop_ins(&input).is_err());
        let original = claims.drop_ins.as_ref().unwrap().as_ref().unwrap_err();
        let borrowed = claims.failure().unwrap().downcast_ref::<PropertyValueErrorV1>().unwrap();

        assert!(std::ptr::eq(original, borrowed));
        assert!(claims.invocation_clone.is_none());
        assert!(claims.invocation.is_none());
    }
}
