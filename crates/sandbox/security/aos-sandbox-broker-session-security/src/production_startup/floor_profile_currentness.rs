//! Keeps the actual launch image's complete Controller profile comparison.
//!
//! The image holds its genuine admitted profile. Its same local/PID1/delivery
//! engine borrows this paid archive without entering a second C scope. The
//! caller's original absolute deadline is checked after the worker-slot wait;
//! the joined slot drops before decoding and the independently owed local post.

use std::error::Error;
use std::path::Path;

use aos_sandbox_broker::controller_receiving::profile::ControllerExternalProfileObservationOriginalV1;
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_systemd_client::{FixedPid1PropertyArchiveV1, FixedPid1PropertyErrorV1,
    FixedPid1PropertyFailureViewV1, FixedPid1PropertyWorkerSlotV1};

use super::{ControllerProfileDeliveryV1, Pid1LaunchImageV1};
use crate::{BrokerSessionSecurityError, ProtectedBrokerSessionFixedEndpointV1};

const MATERIALIZED_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy)]
enum FirstV1 { Endpoint, Preparation, Prefix, Deadline, Properties, Comparison, Settlement, Reentry }

pub(crate) struct LaunchProfileCurrentnessOriginalV1 {
    endpoint: Option<Result<(), BrokerSessionSecurityError>>,
    archive: FixedPid1PropertyArchiveV1,
    preparation: Option<Result<(), FixedPid1PropertyErrorV1>>,
    profile: ControllerExternalProfileObservationOriginalV1,
    prefix: Option<Result<(), aos_sandbox_controller_domain::normal_root::NormalRootStartupErrorV1>>,
    deadline: crate::dormant_handshake::BrokerColdDeadlineObservationV1,
    cutoff: Option<Result<(), crate::DormantBrokerSessionHandshakeErrorV1>>,
    worker_entry: Option<Result<(), FixedPid1PropertyErrorV1>>,
    properties: Option<Result<(), aos_sandbox_controller_domain::normal_root::NormalRootStartupErrorV1>>,
    compared: Option<Result<(), aos_sandbox_controller_domain::normal_root::NormalRootStartupErrorV1>>,
    settlement: Option<Result<(), FixedPid1PropertyErrorV1>>,
    returned: Option<Result<(), BrokerSessionSecurityError>>,
    entered: bool,
    reentry: Option<BrokerSessionSecurityError>,
    first: Option<FirstV1>,
}

impl LaunchProfileCurrentnessOriginalV1 {
    pub(crate) fn new() -> Self {
        Self {
            endpoint: None,
            archive: FixedPid1PropertyArchiveV1::with_materialization_limit(1, MATERIALIZED_BYTES),
            preparation: None,
            profile: ControllerExternalProfileObservationOriginalV1::new(),
            prefix: None,
            deadline: crate::dormant_handshake::BrokerColdDeadlineObservationV1::new(),
            cutoff: None, worker_entry: None, properties: None, compared: None, settlement: None,
            returned: None, entered: false, reentry: None, first: None,
        }
    }

    pub(crate) fn with_shared_provider_v1(provider: std::sync::Arc<aos_systemd_client::SharedFixedPid1PropertyProviderV1>) -> Self {
        let mut original = Self::new();
        original.archive = FixedPid1PropertyArchiveV1::with_shared_provider_v1(
            1, MATERIALIZED_BYTES, provider,
        );
        original
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first? {
            FirstV1::Endpoint => failure(&self.endpoint),
            FirstV1::Preparation => failure(&self.preparation),
            FirstV1::Prefix => self.profile.failure().or_else(|| failure(&self.prefix)),
            FirstV1::Deadline => self.deadline.failure().or_else(|| failure(&self.cutoff))
                .or_else(|| failure(&self.worker_entry)),
            FirstV1::Properties => self.profile.failure().or_else(|| failure(&self.properties)),
            FirstV1::Comparison => self.profile.failure().or_else(|| failure(&self.compared)),
            FirstV1::Settlement => failure(&self.settlement),
            FirstV1::Reentry => self.reentry.as_ref().map(|cause| cause as _),
        }
    }

    pub(crate) fn property_failure_view_v1(&self) -> Option<FixedPid1PropertyFailureViewV1<'_>> {
        if matches!(self.first, Some(FirstV1::Properties))
            && self.profile.property_failure_is_first_v1()
        { self.archive.failure_view() } else { None }
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.reentry.is_none() && matches!(self.returned, Some(Ok(())))
    }
}

impl Pid1LaunchImageV1 {
    pub(crate) fn profile_currentness_receiving_demand_v1(&self) -> Option<ResourceVector> {
        let memory = std::mem::size_of::<LaunchProfileCurrentnessOriginalV1>().checked_mul(2)?
            .checked_add(FixedPid1PropertyArchiveV1::entry_bytes_v1().checked_mul(2)?)?
            .checked_add(std::mem::size_of::<rustix::time::Timespec>().checked_mul(2)?)?;
        let own = ResourceVector::ZERO.with(D::MemoryBytes, u64::try_from(memory).ok()?);
        let ControllerProfileDeliveryV1::Admitted(binding) = &self.profile_delivery else {
            return Some(own);
        };
        let profile = binding.profile()?;
        let archive = FixedPid1PropertyArchiveV1::with_materialization_limit(1, MATERIALIZED_BYTES);
        let receiver = profile.external_currentness_receiving_demand_v1(&archive)?;
        let row = FixedPid1PropertyArchiveV1::fixed_property_geometry_v1(MATERIALIZED_BYTES).ok()?;
        let demand = own.checked_add(receiver).ok()?.checked_add(ResourceVector::ZERO
            .with(D::MemoryBytes, row.memory_bytes)
            .with(D::OpenFiles, row.open_files)
            .with(D::Pids, row.worker_threads)
            .with(D::NetworkBytes, row.wire_io_bytes)
            .with(D::LogBytes, row.maximum_log_bytes)).ok()?;
        let local_files = profile.local_currentness_receiving_demand_v1()?.get(D::OpenFiles);
        // A refused local prefix keeps its native files and runs the independent
        // local post, but never enters PID1. A positive prefix actually retires
        // its policy/subject/status/membership probes before the worker starts.
        // A failed PID1 row retains ALL its files through the owed local post.
        let files = local_files.checked_mul(2)?
            .max(row.open_files.checked_add(local_files)?);
        Some(demand.with(D::OpenFiles, files))
    }

    // The actual external provider separately owns/funds its one native
    // connection and uses the already-held main Runtime. Both failed local
    // destinations remain independent; no native Result is discarded.
    pub(crate) fn profile_currentness_shared_receiving_demand_v1(&self) -> Option<ResourceVector> {
        let demand = self.profile_currentness_receiving_demand_v1()?;
        let ControllerProfileDeliveryV1::Admitted(binding) = &self.profile_delivery else {
            return Some(demand);
        };
        let profile = binding.profile()?;
        let local = profile.local_currentness_receiving_demand_v1()?.get(D::OpenFiles);
        Some(demand.with(D::OpenFiles, local.checked_mul(2)?))
    }

    pub(crate) fn recheck_profile_delivery_retaining_v1<'image>(
        &'image self, endpoint: ProtectedBrokerSessionFixedEndpointV1,
        original: &mut LaunchProfileCurrentnessOriginalV1,
    ) -> Result<Option<&'image Path>, BrokerSessionSecurityError> {
        self.recheck_profile_delivery_retaining_with_deadline_v1(endpoint, original, None)
    }

    pub(crate) fn recheck_profile_delivery_retaining_with_deadline_v1<'image>(
        &'image self, endpoint: ProtectedBrokerSessionFixedEndpointV1,
        original: &mut LaunchProfileCurrentnessOriginalV1,
        deadline: Option<crate::handshake::OriginalBrokerColdDeadlineV1>,
    ) -> Result<Option<&'image Path>, BrokerSessionSecurityError> {
        if original.entered {
            original.reentry.get_or_insert(BrokerSessionSecurityError::Currentness);
            original.first.get_or_insert(FirstV1::Reentry);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        original.entered = true;
        original.endpoint = Some(self.require_endpoint(endpoint));
        original.returned = Some((|| {
            if !matches!(original.endpoint, Some(Ok(()))) {
                original.first = Some(FirstV1::Endpoint);
                return Err(BrokerSessionSecurityError::Currentness);
            }
            let profile = match &self.profile_delivery {
                ControllerProfileDeliveryV1::Admitted(binding) => binding.profile(),
                ControllerProfileDeliveryV1::Storage => None,
                ControllerProfileDeliveryV1::Pending => {
                    original.first = Some(FirstV1::Endpoint);
                    return Err(BrokerSessionSecurityError::Currentness);
                }
            };
            if let Some(profile) = profile {
                original.preparation = Some(original.archive.prepare_once());
                if !matches!(original.preparation, Some(Ok(()))) {
                    original.first = Some(FirstV1::Preparation);
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                original.prefix = Some(profile.capture_external_prefix_once_v1(&mut original.profile));
                if !matches!(original.prefix, Some(Ok(()))) {
                    original.first = Some(FirstV1::Prefix);
                    original.compared = Some(profile.observe_external_local_post_without_properties_once_v1(
                        &mut original.profile,
                    ));
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                let mut slot = FixedPid1PropertyWorkerSlotV1::acquire();
                original.cutoff = Some(match deadline {
                    Some(deadline) => deadline.check_retaining_once_v1(&mut original.deadline),
                    None => Ok(()),
                });
                if !matches!(original.cutoff, Some(Ok(()))) {
                    original.first = Some(FirstV1::Deadline);
                    drop(slot);
                    original.compared = Some(profile.observe_external_local_post_without_properties_once_v1(
                        &mut original.profile,
                    ));
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                if let Some(deadline) = deadline {
                    original.worker_entry = Some(original.archive.restrict_shared_entry_boottime_v1(deadline.value()));
                    if !matches!(original.worker_entry, Some(Ok(()))) {
                        original.first = Some(FirstV1::Deadline);
                        drop(slot);
                        original.compared = Some(profile.observe_external_local_post_without_properties_once_v1(
                            &mut original.profile,
                        ));
                        return Err(BrokerSessionSecurityError::Currentness);
                    }
                }
                original.properties = Some(profile.observe_external_prepared_under_slot_once_v1(
                    &mut original.profile, &mut original.archive, &mut slot,
                ));
                // The actual joined worker releases its single shared task
                // slot before canonical comparison and any native local post.
                drop(slot);
                if !matches!(original.properties, Some(Ok(()))) {
                    original.first = Some(FirstV1::Properties);
                }
                original.compared = Some(profile.finish_external_prepared_properties_once_v1(
                    &mut original.profile,
                ));
                if original.first.is_none() && !matches!(original.compared, Some(Ok(()))) {
                    original.first = Some(FirstV1::Comparison);
                }
                if original.first.is_none() {
                    original.settlement = Some(original.archive.settle_positive_once());
                    if !matches!(original.settlement, Some(Ok(()))) {
                        original.first = Some(FirstV1::Settlement);
                    }
                }
                if original.first.is_some() { return Err(BrokerSessionSecurityError::Currentness); }
            }
            Ok(())
        })());
        if !original.is_complete() { return Err(BrokerSessionSecurityError::Currentness); }
        match &self.profile_delivery {
            ControllerProfileDeliveryV1::Admitted(binding) => Ok(binding.profile().map(|profile| profile.profile_path())),
            ControllerProfileDeliveryV1::Storage => Ok(None),
            ControllerProfileDeliveryV1::Pending => Err(BrokerSessionSecurityError::Currentness),
        }
    }
}

fn failure<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
