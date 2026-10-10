//! Preallocated final capture failures and their original actor custody.
//!
//! Storage admission precedes its safe boxed body and every transport effect.
//! An admission refusal retains the actual decoder cause and independent raw
//! postcut without allocating another carrier. The final body, including its
//! purpose and error payloads, closes before the external scratch and custody.

use std::error::Error;
use std::fmt;

use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeCustody, DecodeScratch};
use crucible_linux_resource::host_supervision::HostSupervisionError;

use super::{ActorBackingTransportPurpose, BackingTransportCause, BackingTransportFailure};
use crate::OriginalActorAccountError;

/// Retains a capture's first cause and independent raw original refusal.
///
/// Failure storage is admitted before transport construction. Uncertain native
/// imports remain quarantined for physical actor containment; destruction of
/// this facade never certifies monitor descriptor closure.
pub struct BackingCaptureFailure<'owner> {
    failure: CaptureFailure<'owner>,
}

enum CaptureFailure<'owner> {
    Unavailable {
        original_after: Option<HostSupervisionError>,
    },
    Admission {
        source: DecodeAdmissionError,
        original_after: Option<HostSupervisionError>,
    },
    Retained(PreparedBackingCaptureFailure<'owner>),
}

// Actual body declaration order closes error payloads before the purpose.
struct CaptureFailureData<'owner> {
    first: Option<BackingTransportFailure>,
    purpose: ActorBackingTransportPurpose<'owner>,
}

// Box destruction includes the body and its purpose. Credit and original
// custody therefore stay external through the physical body deallocation.
pub(crate) struct PreparedBackingCaptureFailure<'owner> {
    data: Box<CaptureFailureData<'owner>>,
    _credit: DecodeScratch,
    _custody: DecodeCustody,
}

impl<'owner> PreparedBackingCaptureFailure<'owner> {
    #[cfg(test)]
    pub(crate) fn body_layout() -> std::alloc::Layout {
        std::alloc::Layout::new::<CaptureFailureData<'owner>>()
    }

    pub(crate) fn prepare(
        budget: &DecodeBudget,
        purpose: ActorBackingTransportPurpose<'owner>,
        original_after: impl FnOnce() -> Option<HostSupervisionError>,
    ) -> Result<Self, BackingCaptureFailure<'owner>> {
        let credit = budget
            .reserve_scratch_array::<CaptureFailureData<'owner>>(1)
            .map_err(|source| BackingCaptureFailure {
                failure: CaptureFailure::Admission {
                    source,
                    original_after: original_after(),
                },
            })?;
        Ok(Self {
            data: Box::new(CaptureFailureData {
                first: None,
                purpose,
            }),
            _credit: credit,
            _custody: budget.custody(),
        })
    }

    pub(crate) fn parts(
        &mut self,
    ) -> (
        &mut ActorBackingTransportPurpose<'owner>,
        &mut Option<BackingTransportFailure>,
    ) {
        (&mut self.data.purpose, &mut self.data.first)
    }

    pub(crate) fn refuse(mut self) -> BackingCaptureFailure<'owner> {
        if self.data.first.is_none() {
            use super::BackingTransportPurpose;
            self.data.first = Some(BackingTransportFailure {
                primary: BackingTransportCause::Invalid("capture lost its initiating cause"),
                original_post: self.data.purpose.check_original_post().err(),
            });
        }
        BackingCaptureFailure {
            failure: CaptureFailure::Retained(self),
        }
    }
}

impl BackingCaptureFailure<'_> {
    pub(crate) fn unavailable(original_after: Option<HostSupervisionError>) -> Self {
        Self {
            failure: CaptureFailure::Unavailable { original_after },
        }
    }

    /// Borrows the independent raw original refusal sampled after failure.
    #[must_use]
    pub fn original_post(&self) -> Option<&HostSupervisionError> {
        match &self.failure {
            CaptureFailure::Unavailable { original_after }
            | CaptureFailure::Admission { original_after, .. } => original_after.as_ref(),
            CaptureFailure::Retained(prepared) => prepared
                .data
                .first
                .as_ref()
                .and_then(|failure| failure.original_post.as_ref())
                .and_then(|source| match source {
                    OriginalActorAccountError::Supervision(source) => Some(source),
                    _ => None,
                }),
        }
    }
}

impl fmt::Debug for BackingCaptureFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.failure {
            CaptureFailure::Unavailable { original_after } => formatter
                .debug_struct("BackingCaptureUnavailable")
                .field("original_after", original_after)
                .finish(),
            CaptureFailure::Admission {
                source,
                original_after,
            } => formatter
                .debug_struct("BackingCaptureAdmission")
                .field("source", source)
                .field("original_after", original_after)
                .finish(),
            CaptureFailure::Retained(prepared) => formatter
                .debug_struct("BackingCaptureFailure")
                .field("failure", &prepared.data.first)
                .finish_non_exhaustive(),
        }
    }
}

impl fmt::Display for BackingCaptureFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("backing capture refused: ")?;
        match &self.failure {
            CaptureFailure::Unavailable { .. } => {
                formatter.write_str("original actor authority unavailable")?;
            }
            CaptureFailure::Admission { source, .. } => write!(formatter, "{source}")?,
            CaptureFailure::Retained(prepared) => match prepared.data.first.as_ref() {
                Some(failure) => match &failure.primary {
                    BackingTransportCause::Invalid(message) => formatter.write_str(message)?,
                    primary => write!(formatter, "{primary:?}")?,
                },
                None => formatter.write_str("missing initiating cause")?,
            },
        }
        write!(formatter, "; original: {:?}", self.original_post())
    }
}

impl Error for BackingCaptureFailure<'_> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.failure {
            CaptureFailure::Unavailable { .. } => {
                static UNAVAILABLE: OriginalActorAccountError =
                    OriginalActorAccountError::Unavailable;
                Some(&UNAVAILABLE)
            }
            CaptureFailure::Admission { source, .. } => Some(source),
            CaptureFailure::Retained(prepared) => {
                let failure = prepared.data.first.as_ref()?;
                match &failure.primary {
                    BackingTransportCause::Original(source) => Some(source),
                    BackingTransportCause::Qmp(source) => Some(source),
                    BackingTransportCause::Spawn(source) => Some(source),
                    BackingTransportCause::Io(source) => Some(source),
                    BackingTransportCause::Json(source) => Some(source),
                    BackingTransportCause::Allocation(source) => Some(source),
                    BackingTransportCause::Stream(source) => Some(source),
                    BackingTransportCause::Invalid(_) => None,
                }
            }
        }
    }
}
