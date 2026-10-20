//! Keeps the issue executable's actual file acquisition and native comparisons.
//!
//! This private consumer supplies no image or role authority. The enclosing
//! genuine issue owner keeps its selected profile and the same measured file.

use std::error::Error;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::path::Path;

use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

use aos_sandbox_broker::immutable_image::{
    ImmutableExecutedFileOriginalV1, ImmutableFileAcquisitionOriginalV1,
    ImmutableFileAcquisitionRefusalV1, ImmutableFileRevalidationOriginalV1,
};

use super::SourceSuccessorCredentialErrorV2;

struct ExecutableComparisonV1 {
    currentness: ImmutableFileRevalidationOriginalV1,
    executed: ImmutableExecutedFileOriginalV1,
}

impl ExecutableComparisonV1 {
    fn new() -> Self {
        Self {
            currentness: ImmutableFileRevalidationOriginalV1::new(),
            executed: ImmutableExecutedFileOriginalV1::new(),
        }
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.currentness.failure().or_else(|| self.executed.failure())
    }
}

pub(super) struct IssueExecutableOriginalV1 {
    opened: Option<io::Result<File>>,
    transferred: bool,
    acquisition: ImmutableFileAcquisitionOriginalV1,
    adoption: Option<Result<(), ImmutableFileAcquisitionRefusalV1>>,
    comparison: Option<ExecutableComparisonV1>,
}

impl IssueExecutableOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            opened: None,
            transferred: false,
            acquisition: ImmutableFileAcquisitionOriginalV1::new(),
            adoption: None,
            comparison: None,
        }
    }

    pub(super) fn receiving_demand_v1() -> Option<ResourceVector> {
        // The parent pays two compiled copies of this entire owner before IO.
        // Keep the canonical acquisition/hash scratch and native locator terms,
        // removing only that explicitly included compiled inline contribution.
        let acquisition = ImmutableFileAcquisitionOriginalV1::receiving_demand_v1(4097)?;
        let acquisition_inline = size_of::<ImmutableFileAcquisitionOriginalV1>().checked_mul(2)?;
        let acquisition_extra = acquisition.get(D::MemoryBytes)
            .checked_sub(u64::try_from(acquisition_inline).ok()?)?;
        let currentness = ImmutableFileRevalidationOriginalV1::receiving_demand_v1()?;
        let currentness_extra = currentness.get(D::MemoryBytes)
            .checked_sub(u64::try_from(size_of::<ImmutableFileRevalidationOriginalV1>()).ok()?)?;
        let bytes = acquisition_extra.checked_add(currentness_extra)?
            .checked_add(4097)?;
        // The original measured executable occupies the parent's existing file
        // lane. One additional executed-inode probe can remain on refusal.
        Some(ResourceVector::ZERO.with(D::MemoryBytes, bytes).with(D::OpenFiles, 1))
    }

    pub(super) fn capture_once(&mut self, path: String) -> Result<(), SourceSuccessorCredentialErrorV2> {
        if self.opened.is_some() || self.transferred || self.adoption.is_some() {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.opened = Some(File::open("/proc/self/exe"));
        if !matches!(self.opened, Some(Ok(_))) {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        let file = match self.opened.take() {
            Some(Ok(file)) => file,
            original => {
                self.opened = original;
                return Err(SourceSuccessorCredentialErrorV2::Rejected);
            }
        };
        self.transferred = true;
        self.adoption = Some(self.acquisition.measure_original_once(
            path.into(), file, None, 64 * 1024 * 1024, true,
        ));
        if !matches!(self.adoption, Some(Ok(()))) {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.compare_once(false)
    }

    pub(super) fn recheck(&mut self, path: &str) -> Result<(), SourceSuccessorCredentialErrorV2> {
        let measured = self.acquisition.completed_measurement()
            .ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        if measured.path() != Path::new(path) {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.compare_once(true)
    }

    fn compare_once(&mut self, revalidate: bool) -> Result<(), SourceSuccessorCredentialErrorV2> {
        if self.comparison.is_some() {
            return Err(SourceSuccessorCredentialErrorV2::Rejected);
        }
        self.comparison = Some(ExecutableComparisonV1::new());
        let comparison = self.comparison.as_mut()
            .ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        let measured = self.acquisition.completed_measurement()
            .ok_or(SourceSuccessorCredentialErrorV2::Rejected)?;
        if revalidate {
            measured.revalidate_retaining(&mut comparison.currentness)
                .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;
        }
        measured.require_executed_retaining_v1(std::process::id(), &mut comparison.executed)
            .map_err(|_| SourceSuccessorCredentialErrorV2::Rejected)?;

        // Both comparisons completed. This temporary executable probe has no
        // later identity-anchor duty; the same measured File stays in acquisition.
        // Failed probes never reach this disposition or the next comparison.
        comparison.executed.retire_positive_probe_once_v1();
        drop(self.comparison.take());
        Ok(())
    }

    pub(super) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.opened.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &dyn Error)
            .or_else(|| self.acquisition.failure())
            .or_else(|| self.adoption.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &dyn Error))
            .or_else(|| self.comparison.as_ref().and_then(ExecutableComparisonV1::failure))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refused_adoption_keeps_the_actual_opened_file_and_first_cause() {
        let mut original = IssueExecutableOriginalV1::new();

        assert!(original.capture_once("/not-an-immutable-name".into()).is_err());
        let first = std::ptr::from_ref(original.failure().unwrap());
        let mut held = ImmutableFileRevalidationOriginalV1::new();
        assert!(matches!(original.acquisition.observe_available_held_once_v1(&mut held), Some(Err(_))));
        assert!(original.capture_once("/not-another-name".into()).is_err());

        assert!(original.transferred);
        assert!(matches!(original.adoption, Some(Err(_))));
        assert!(original.comparison.is_none());
        assert!(std::ptr::eq(std::ptr::from_ref(original.failure().unwrap()), first));
    }
}
