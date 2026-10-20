//! One bounded mechanical currentness attempt under the same whole-service R.
//!
//! A settled positive observer may be disposed before another sequential
//! service comparison. The permanent RootR claim is never charged, released,
//! refunded or recreated by this DATA lifetime. Any failed attempt remains
//! resident and permanently closes subsequent service borrowing.

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

use super::{RootObservationErrorV1 as NormalRootStartupErrorV1,
    RootKernelOriginalCaptureV1 as RootOriginalKernelReceivingV1};
use super::root_startup_native::RootStartupNativeOriginalV1 as ProductionNormalRootStartupV1;
use super::root_service as service;

use super::receiving_limits::ReceivingContainmentCurrentnessV1;

const MATERIALIZED_PROPERTY_BYTES: usize = 64 * 1024;

/// Retains one actual Root sampler and its independently owed native posts.
///
/// Only the same Root native receiver constructs and enters this owner. Its
/// public views are diagnostic; no field DTO or callback admits currentness.
pub struct RootServiceCurrentnessOriginalV1 {
    before_limits: ReceivingContainmentCurrentnessV1,
    after_limits: ReceivingContainmentCurrentnessV1,
    archive: service::FirstGlobalPropertyArchive,
    initial_containment: Option<Result<(), NormalRootStartupErrorV1>>,
    local_before: Option<Result<(), NormalRootStartupErrorV1>>,
    local_before_original: super::root_startup_native::RootLocalCurrentnessOriginalV1,
    local_after_original: super::root_startup_native::RootLocalCurrentnessOriginalV1,
    unit_after_original: super::root_startup_native::RootUnitCurrentnessOriginalV1,
    prepare: Option<Result<(), NormalRootStartupErrorV1>>,
    observed: Option<Result<(service::ServiceObservationV1, [u8; 16]), NormalRootStartupErrorV1>>,
    canonical: Option<std::io::Result<std::path::PathBuf>>,
    comparison: Option<Result<(), NormalRootStartupErrorV1>>,
    entered: Option<Result<(), NormalRootStartupErrorV1>>,
    local_after: Option<Result<(), NormalRootStartupErrorV1>>,
    complete: Option<Result<(), NormalRootStartupErrorV1>>,
    settlement: Option<Result<(), NormalRootStartupErrorV1>>,
}

impl RootServiceCurrentnessOriginalV1 {
    pub(super) fn new() -> Self {
        let lifetime = service::RootObserverLifetimeV1::begin();
        Self {
            before_limits: ReceivingContainmentCurrentnessV1::default(),
            after_limits: ReceivingContainmentCurrentnessV1::default(),
            archive: service::FirstGlobalPropertyArchive::with_materialization_limit(
                1, lifetime, MATERIALIZED_PROPERTY_BYTES,
            ),
            initial_containment: None,
            local_before: None,
            local_before_original: super::root_startup_native::RootLocalCurrentnessOriginalV1::new(),
            local_after_original: super::root_startup_native::RootLocalCurrentnessOriginalV1::new(),
            unit_after_original: super::root_startup_native::RootUnitCurrentnessOriginalV1::new(),
            prepare: None,
            observed: None,
            canonical: None,
            comparison: None,
            entered: None,
            local_after: None,
            complete: None,
            settlement: None,
        }
    }

    /// Prices the same actual fixed currentness sampler without admission.
    #[must_use]
    pub fn demand() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>().checked_mul(2)?
            .checked_add(std::mem::size_of::<(usize, usize, std::sync::atomic::AtomicBool)>())?
            .checked_add(std::mem::size_of::<ResourceVector>().checked_mul(4)?)?
            .checked_add(2 * 1024 * 1024)?
            // The single materialized property row bounds the fragment input;
            // canonicalization retains its own output and native error.
            .checked_add(2 * MATERIALIZED_PROPERTY_BYTES)?;
        // Inline/native buffers are bytes. Actual resident namespace entries
        // remain priced by the containment and observer providers below.
        let fixed = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(bytes).ok()?);
        let observer = service::fixed_property_observer_demand_v1(MATERIALIZED_PROPERTY_BYTES)?;
        fixed.checked_add(ReceivingContainmentCurrentnessV1::fixed_demand()).ok()?
            .checked_add(ReceivingContainmentCurrentnessV1::fixed_demand()).ok()?
            .checked_add(observer).ok()?
            .checked_add(super::root_startup_native::RootLocalCurrentnessOriginalV1::demand_v1()?).ok()?
            .checked_add(super::root_startup_native::RootLocalCurrentnessOriginalV1::demand_v1()?).ok()?
            .checked_add(super::root_startup_native::RootUnitCurrentnessOriginalV1::demand_v1()?).ok()
    }

    // Only the actual Root original owner enters this with the same retained
    // startup and expected pair fields. None of these DATA arguments pays it.
    pub(super) fn observe_once(
        &mut self,
        startup: &ProductionNormalRootStartupV1,
        kernel: &RootOriginalKernelReceivingV1,
        invocation: [u8; 16],
        producer: [u8; 16],
    ) {
        if self.entered.is_some() {
            return;
        }
        self.entered = Some((|| {
            kernel.observe_service_limits(&startup.cgroup, &mut self.before_limits);
            self.initial_containment = Some(self.before_limits.require_current()
                .map_err(|_| NormalRootStartupErrorV1::Service));
            require_positive(&self.initial_containment)?;
            self.local_before = Some(startup.require_local_current_retaining_v1(&mut self.local_before_original));
            require_positive(&self.local_before)?;
            self.prepare = Some(self.archive.prepare());
            require_positive(&self.prepare)?;
            let path = startup.profile_file.path().to_str()
                .ok_or(NormalRootStartupErrorV1::Profile)?;
            self.observed = Some(service::observe_root_resource_with_archive_retaining_v1(
                &mut self.archive, path, &mut self.canonical,
            ));
            let observed = self.observed.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(NormalRootStartupErrorV1::Service)?;
            self.comparison = Some((|| {
                service::require_same(&startup.observed, &observed.0)?;
                if observed.0.invocation != invocation || observed.1 != producer {
                    return Err(NormalRootStartupErrorV1::Service);
                }
                Ok(())
            })());
            require_positive(&self.comparison)
        })());

        // Complete both independent native/local posts before projecting the
        // first receiving result. A later post never heals an earlier failure.
        kernel.observe_service_limits(&startup.cgroup, &mut self.after_limits);
        self.local_after = Some(startup.require_local_current_retaining_v1(&mut self.local_after_original)
            .and_then(|_| startup.require_final_unit_current_retaining_v1(&mut self.unit_after_original)));
        self.complete = Some((|| {
            require_positive(&self.entered)?;
            self.after_limits.require_current().map_err(|_| NormalRootStartupErrorV1::Service)?;
            require_positive(&self.local_after)
        })());
        if matches!(self.complete, Some(Ok(()))) {
            self.settlement = Some(self.archive.settle_positive_once());
        }
    }

    /// Reports complete physical comparison and actual positive disposal.
    #[must_use]
    pub fn is_positive(&self) -> bool {
        matches!(self.complete, Some(Ok(())))
            && matches!(self.settlement, Some(Ok(())))
            && self.failure().is_none()
    }

    /// Borrows the earliest existing sampler diagnostic without disposing it.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        macro_rules! cause {
            ($slot:expr) => { $slot.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn std::error::Error + 'static)) };
        }
        let initial = if matches!(self.initial_containment, Some(Err(_))) {
            self.before_limits.failure().or_else(|| cause!(self.initial_containment))
        } else {
            None
        };
        initial.or_else(|| self.local_before_original.failure()).or_else(|| cause!(self.local_before))
            .or_else(|| cause!(self.prepare))
            .or_else(|| cause!(self.canonical))
            .or_else(|| cause!(self.observed))
            .or_else(|| cause!(self.comparison))
            .or_else(|| cause!(self.entered))
            .or_else(|| self.after_limits.failure())
            .or_else(|| self.local_after_original.failure()).or_else(|| self.unit_after_original.failure())
            .or_else(|| cause!(self.local_after))
            .or_else(|| cause!(self.complete))
            .or_else(|| cause!(self.settlement))
    }
}

fn require_positive(
    result: &Option<Result<(), NormalRootStartupErrorV1>>,
) -> Result<(), NormalRootStartupErrorV1> {
    if matches!(result, Some(Ok(()))) {
        Ok(())
    } else {
        Err(NormalRootStartupErrorV1::Service)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_fragment_keeps_native_canonical_error_before_later_posts() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing-fragment");
        let mut original = RootServiceCurrentnessOriginalV1::new();
        original.canonical = Some(std::fs::canonicalize(&missing));
        original.observed = Some(Err(NormalRootStartupErrorV1::Service));
        original.local_after = Some(Err(NormalRootStartupErrorV1::Profile));
        let native = original.canonical.as_ref().unwrap().as_ref().unwrap_err();

        let first = original.failure().unwrap().downcast_ref::<std::io::Error>().unwrap();

        assert_eq!(first.kind(), std::io::ErrorKind::NotFound);
        assert!(std::ptr::eq(first, native));
        assert!(!original.is_positive());
    }
}
