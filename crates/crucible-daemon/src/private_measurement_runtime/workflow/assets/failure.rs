//! Prepays the fixed artifact refusal body before file, parser or import work.
//!
//! Working helpers return an empty marker after publishing the first typed
//! cause into the borrowed body. The returned owner frees that body before its
//! external scratch receipt and original custody. Preparation refusal needs no
//! artifact body, and never allocates one after an operation has failed.

use std::cell::RefCell;

use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeCustody, DecodeScratch};
use crucible_linux_resource::host_supervision::HostSupervisionError;

use super::ArtifactCause;

/// Retains the actual artifact refusal and its independent original postcheck.
#[derive(Debug, thiserror::Error)]
#[error("original workflow artifacts refused: {failure}")]
pub struct OriginalWorkflowArtifactsError {
    #[source]
    failure: ArtifactFailure,
}

#[derive(Debug, thiserror::Error)]
enum ArtifactFailure {
    #[error("original artifact account refused: {0}")]
    Account(#[source] crucible_qemu::OriginalActorAccountError),
    #[error("artifact failure storage refused: {source}; original: {original_after:?}")]
    Admission {
        #[source]
        source: DecodeAdmissionError,
        original_after: Option<HostSupervisionError>,
    },
    #[error("original prepared service is unavailable")]
    MissingService,
    #[error(transparent)]
    Retained(ArtifactFailurePurpose),
}

pub(super) struct ArtifactFailurePurpose {
    data: Box<ArtifactFailureData>,
    _credit: DecodeScratch,
    _custody: DecodeCustody,
}

#[derive(Debug)]
struct ArtifactFailureData {
    source: Option<ArtifactCause>,
    original_after: Option<HostSupervisionError>,
}

impl std::fmt::Debug for ArtifactFailurePurpose {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.data.fmt(formatter)
    }
}

impl std::fmt::Display for ArtifactFailurePurpose {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.data.source {
            Some(source) => write!(
                formatter,
                "{source}; original: {:?}",
                self.data.original_after
            ),
            None => formatter.write_str("artifact failure body has no initiating cause"),
        }
    }
}

impl std::error::Error for ArtifactFailurePurpose {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.data
            .source
            .as_ref()
            .map(|source| source as &dyn std::error::Error)
    }
}

impl ArtifactFailurePurpose {
    #[cfg(test)]
    pub(super) fn body_bytes_for_test() -> usize {
        std::mem::size_of::<ArtifactFailureData>()
    }

    pub(super) fn prepare(
        budget: &DecodeBudget,
        original: &impl Fn() -> Result<(), HostSupervisionError>,
    ) -> Result<Self, OriginalWorkflowArtifactsError> {
        let credit = budget
            .reserve_scratch_array::<ArtifactFailureData>(1)
            .map_err(|source| OriginalWorkflowArtifactsError {
                failure: ArtifactFailure::Admission {
                    source,
                    original_after: original().err(),
                },
            })?;
        Ok(Self {
            data: Box::new(ArtifactFailureData {
                source: None,
                original_after: None,
            }),
            _credit: credit,
            _custody: budget.custody(),
        })
    }

    pub(super) fn work<'body, 'original>(
        &'body mut self,
        original: &'original dyn Fn() -> Result<(), HostSupervisionError>,
    ) -> ArtifactWork<'body, 'original> {
        ArtifactWork {
            data: RefCell::new(&mut self.data),
            original,
        }
    }

    pub(super) fn finish<T>(
        self,
        work: Result<T, ArtifactRefusal>,
    ) -> Result<T, OriginalWorkflowArtifactsError> {
        work.map_err(|ArtifactRefusal| OriginalWorkflowArtifactsError {
            failure: ArtifactFailure::Retained(self),
        })
    }
}

impl OriginalWorkflowArtifactsError {
    pub(super) fn account(source: crucible_qemu::OriginalActorAccountError) -> Self {
        Self {
            failure: ArtifactFailure::Account(source),
        }
    }

    pub(super) fn missing_service() -> Self {
        Self {
            failure: ArtifactFailure::MissingService,
        }
    }

    #[cfg(test)]
    pub(super) fn cause(&self) -> Option<&ArtifactCause> {
        match &self.failure {
            ArtifactFailure::Retained(purpose) => purpose.data.source.as_ref(),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(super) fn original_after(&self) -> Option<HostSupervisionError> {
        match &self.failure {
            ArtifactFailure::Retained(purpose) => purpose.data.original_after,
            ArtifactFailure::Admission { original_after, .. } => *original_after,
            _ => None,
        }
    }

    #[cfg(test)]
    pub(super) fn is_storage_admission(&self) -> bool {
        matches!(self.failure, ArtifactFailure::Admission { .. })
    }
}

#[derive(Debug)]
pub(super) struct ArtifactRefusal;

pub(super) struct ArtifactWork<'body, 'original> {
    data: RefCell<&'body mut ArtifactFailureData>,
    original: &'original dyn Fn() -> Result<(), HostSupervisionError>,
}

impl ArtifactWork<'_, '_> {
    pub(super) fn verify_original(&self) -> Result<(), HostSupervisionError> {
        (self.original)()
    }

    pub(super) fn checked<T>(&self, work: Result<T, ArtifactCause>) -> Result<T, ArtifactRefusal> {
        let after = self.verify_original();
        match (work, after) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(source), after) => Err(self.record(source, after.err())),
            (Ok(_), Err(source)) => Err(self.error(ArtifactCause::OriginalBoundary(source))),
        }
    }

    pub(super) fn error(&self, source: ArtifactCause) -> ArtifactRefusal {
        self.record(source, None)
    }

    fn record(
        &self,
        source: ArtifactCause,
        original_after: Option<HostSupervisionError>,
    ) -> ArtifactRefusal {
        // This private, synchronous borrow writes only the already-owned slot.
        // It ends before any original callback, formatting or helper reentry.
        let mut data = self.data.borrow_mut();
        if data.source.is_none() {
            data.source = Some(source);
            data.original_after = original_after;
        }
        ArtifactRefusal
    }
}
