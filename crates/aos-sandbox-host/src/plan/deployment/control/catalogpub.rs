//! Lends only authenticated catalog publication from the actual Host Control.
//!
//! The finite preparation uses the shared PID1/process/Root observer and its
//! independent post. Every addition preserves all previous Control debt.

use super::terminal_inventory::{ControlPreparationPurposeV5, HostControlPreparationReceivingV5};
use super::*;
use aos_sandbox_broker::paired_clock::{PairedClockBaselineV1, PairedClockSamplesV1};
use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};
use aos_sandbox_protocol::ValidatedHeader;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodRequestV1, AuthenticatedBrokerRequestDirectionV1,
};

pub(crate) struct CatalogClockOriginalV2 {
    baseline: Option<PairedClockBaselineV1>,
    samples: [Option<PairedClockSamplesV1>; 3],
    results: [Option<Result<RawPairedClockSample>>; 4],
    disposal: Option<Result<()>>,
    first: Option<usize>,
}

impl CatalogClockOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            baseline: None,
            samples: std::array::from_fn(|_| None),
            results: std::array::from_fn(|_| None),
            disposal: None,
            first: None,
        }
    }

    pub(crate) fn demand_v2() -> Result<ResourceVector> {
        use aos_sandbox_core::ResourceDimension as D;
        let boot = RootOriginalKernelBootIdAttemptV1::dominant_requested_bytes_v1()
            .ok_or(HostError::ResourceExhausted)?;
        let memory = PairedClockSamplesV1::representation_memory_bytes()
            .checked_mul(3)
            .and_then(|bytes| bytes.checked_add(boot.checked_mul(13)?))
            .ok_or(HostError::ResourceExhausted)?;
        Ok(ResourceVector::ZERO
            .with(
                D::MemoryBytes,
                u64::try_from(memory).map_err(|_| HostError::ResourceExhausted)?,
            )
            .with(D::OpenFiles, 15)
            .with(D::MetadataEntries, 15))
    }

    fn capture_v2(&mut self) {
        self.baseline = Some(PairedClockBaselineV1::capture(
            RawClockProvenance::new_untrusted(crate::KERNEL_CLOCK_PROVENANCE),
        ));
        if self.baseline.as_ref().and_then(|baseline| baseline.failure()).is_some() {
            self.first = Some(0);
        }
        self.samples = std::array::from_fn(|_| Some(PairedClockSamplesV1::new()));
    }

    fn check_v2(&mut self, index: usize, header: &ValidatedHeader, boot: &[u8; 16]) -> Result<()> {
        if self.results[index].is_some() {
            return Err(HostError::Fence("catalog clock slot occupied"));
        }
        let sampler = match index {
            0 | 1 => 0,
            2 => 1,
            _ => 2,
        };
        self.results[index] = Some((|| {
            let sample = self.samples[sampler]
                .as_mut()
                .ok_or(HostError::ResourceExhausted)?
                .sample(self.baseline.as_mut().ok_or(HostError::ResourceExhausted)?)
                .map_err(|_| {
                    HostError::Fence("Host catalog paired clock refused; original retained")
                })?;
            if sample.host_boot_id() != *boot
                || sample.boottime_nanoseconds() >= header.deadline_boottime_nanoseconds()
            {
                return Err(HostError::Fence(
                    "Host catalog original request deadline expired",
                ));
            }
            Ok(sample)
        })());
        if !matches!(self.results[index], Some(Ok(_))) {
            self.first.get_or_insert(index);
            return Err(HostError::Fence("Host catalog original clock refused"));
        }
        Ok(())
    }

    pub(crate) fn failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        if self.first.is_none() {
            return self
                .disposal
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn Error + 'static))
                .and_then(|marker| {
                    self.baseline
                        .as_ref()
                        .and_then(|clock| clock.failure())
                        .or_else(|| {
                            self.samples.iter().flatten().find_map(|samples| {
                                samples
                                    .observation_failure(0)
                                    .or_else(|| samples.observation_failure(1))
                            })
                        })
                        .or(Some(marker))
                });
        }
        let index = self.first?;
        let sampler = match index {
            0 | 1 => 0,
            2 => 1,
            _ => 2,
        };
        let observation = usize::from(index == 1);
        self.baseline
            .as_ref()
            .and_then(|clock| clock.failure())
            .or_else(|| {
                self.samples[sampler]
                    .as_ref()?
                    .observation_failure(observation)
            })
            .or_else(|| {
                self.results[index]
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.disposal
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
    }

    fn retire_v2(&mut self) -> Result<()> {
        self.disposal = Some((|| {
            self.baseline
                .as_mut()
                .ok_or(HostError::ResourceExhausted)?
                .retire_positive_native_file_v2()
                .map_err(|_| HostError::Fence("Host catalog baseline disposal refused"))?;
            for sampler in self.samples.iter_mut().flatten() {
                sampler
                    .retire_positive_native_files_v2()
                    .map_err(|_| HostError::Fence("Host catalog clock disposal refused"))?;
            }
            Ok(())
        })());
        self.disposal
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(HostError::Fence("Host catalog clock disposal refused"))
    }
}

pub(crate) struct HostCatalogReceivingV2<'original, 'clock> {
    preparation: HostControlPreparationReceivingV5<'original>,
    clock: &'clock mut CatalogClockOriginalV2,
    header: ValidatedHeader,
    boot: [u8; 16],
    financial_refusal: bool,
}

impl HostComponentControlStartupV2 {
    pub(crate) fn completed_catalog_control_demand_data_v2(&self) -> Result<ResourceVector> {
        self.require_admitted_original()?;
        self.execution_receiving.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host catalog Control invoice is absent"))?
            .completed_catalog_control_demand_data_v2()
            .map_err(|_| HostError::Fence("Host catalog Control invoice is incomplete"))
    }

    pub(crate) fn begin_catalog_preparation_v2<'original>(
        &'original mut self,
        request: &AuthenticatedBrokerMethodRequestV1,
        fixed: ResourceVector,
    ) -> Result<HostControlPreparationReceivingV5<'original>> {
        use aos_proto::aos::sandbox::local::v1::BrokerMethod;
        self.require_admitted_original()?;
        if request.direction() != AuthenticatedBrokerRequestDirectionV1::ServerReceive
            || request.method() != BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
            || request.authorization().is_some()
            || request.host_catalog_publication_data_v2().is_none()
        {
            return Err(HostError::Fence(
                "Host catalog requires the actual authenticated method17",
            ));
        }
        let (native, maximum) = self.recurring_observation_demand_v4()?;
        let complete = fixed
            .checked_add(native)
            .map_err(|_| HostError::ResourceExhausted)?;
        let admitted = self
            .execution_receiving
            .as_mut()
            .and_then(|value| value.as_mut().ok())
            .ok_or(execution_receiving::Closed)
            .and_then(|owner| owner.admit_catalog_publication_v2(complete));
        if admitted.is_err() {
            self.first.get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence(
                "Host catalog exceeds its consumed Control original",
            ));
        }
        let destinations = self.append_recurring_observation_destinations_v4(maximum)?;
        Ok(HostControlPreparationReceivingV5 {
            original: self,
            purpose: ControlPreparationPurposeV5::CatalogPublication,
            destinations,
            before: false,
            after: false,
            completed: false,
            extension: false,
            cleanup: None,
        })
    }
}

impl<'original, 'clock> HostCatalogReceivingV2<'original, 'clock> {
    pub(crate) fn new_v2(
        preparation: HostControlPreparationReceivingV5<'original>,
        clock: &'clock mut CatalogClockOriginalV2,
        header: &ValidatedHeader,
    ) -> Result<Self> {
        let boot = preparation
            .original
            .original_boot
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .ok_or(HostError::Fence("Host catalog original boot is absent"))?
            .into_bytes();
        clock.capture_v2();
        Ok(Self {
            preparation,
            clock,
            header: header.clone(),
            boot,
            financial_refusal: false,
        })
    }

    pub(crate) async fn observe_before_v2(&mut self) -> Result<()> {
        self.preparation.observe_before_once_v5().await?;
        self.clock.check_v2(0, &self.header, &self.boot)
    }

    pub(crate) fn admit_additional_v2(&mut self, amount: ResourceVector) -> Result<()> {
        let admitted = self
            .preparation
            .original
            .execution_receiving
            .as_mut()
            .and_then(|value| value.as_mut().ok())
            .ok_or(execution_receiving::Closed)
            .and_then(|owner| owner.admit_catalog_publication_v2(amount));
        if admitted.is_err() {
            self.financial_refusal = true;
            self.preparation
                .original
                .first
                .get_or_insert(FirstCauseV2::ExecutionReceiving);
            return Err(HostError::Fence(
                "Host catalog dynamic representation exceeds Control",
            ));
        }
        Ok(())
    }

    pub(crate) fn financial_refusal_v2(&self) -> bool {
        self.financial_refusal
    }

    pub(crate) fn clock_failure_v2(&self) -> Option<&(dyn Error + 'static)> {
        self.clock.failure_v2()
    }

    pub(crate) fn require_write_clock_v2(&mut self) -> Result<()> {
        self.clock.check_v2(1, &self.header, &self.boot)
    }

    pub(crate) fn require_rename_clock_v2(&mut self) -> Result<()> {
        self.clock.check_v2(2, &self.header, &self.boot)
    }

    pub(crate) async fn observe_after_owed_v2(&mut self) -> Result<()> {
        self.preparation.observe_after_once_v5().await
    }

    pub(crate) fn final_clock_after_owed_v2(&mut self) -> Result<()> {
        // Separate native destination still samples after an earlier clock,
        // body or Host post refusal. It cannot rearm any failed clock owner.
        self.clock.check_v2(3, &self.header, &self.boot)
    }

    pub(crate) fn fence_refusal_v2(&mut self) {
        self.preparation.original.armed = true;
        self.preparation
            .original
            .first
            .get_or_insert(FirstCauseV2::ExecutionReceiving);
        if let Some(Ok(owner)) = self.preparation.original.execution_receiving.as_mut() {
            owner.close();
        }
    }

    pub(crate) fn dispose_positive_v2(&mut self, wrote: bool) -> Result<()> {
        if self.clock.first.is_some() {
            return Err(HostError::Fence("Host catalog clock refused"));
        }
        // Exact replay does not enter either mutation clock destination.
        if !wrote {
            self.clock.samples[1] = None;
        }
        self.clock.retire_v2()?;
        self.preparation.dispose_positive_once_v5()
    }
}
