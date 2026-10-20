//! Retains actual transition preparation outputs before later failure frontiers.
//!
//! Ordinary and selected preparation share this owner and the same checks.
//! Only selected mutation custody keeps it resident beyond the returned error.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum PreparationFailureV1 {
    ResultState,
    Transition,
    TransitionBytes,
    TransitionBound,
    Digest,
    HeadBytes,
    HeadBound,
}

/// Follows the old reverse-local drop order from head bytes to result state.
pub(crate) struct CatalogTransitionPreparationOriginalV1 {
    pub(super) head_bound: Option<Result<(), StorageStateError>>,
    pub(super) head_bytes: Option<Result<Vec<u8>, StorageStateError>>,
    pub(super) head_payload: Option<HeadPayload>,
    pub(super) digest: Option<Result<ObjectDigest, StorageStateError>>,
    pub(super) transition_bound: Option<Result<(), StorageStateError>>,
    pub(super) transition_bytes: Option<Result<Vec<u8>, StorageStateError>>,
    pub(super) transition: Option<Result<TransitionPayload, StorageStateError>>,
    pub(super) result_state: Option<Result<PhysicalCatalogState, StorageStateError>>,
    pub(super) first: Option<PreparationFailureV1>,
}

impl CatalogTransitionPreparationOriginalV1 {
    pub(crate) const fn new() -> Self {
        Self {
            head_bound: None,
            head_bytes: None,
            head_payload: None,
            digest: None,
            transition_bound: None,
            transition_bytes: None,
            transition: None,
            result_state: None,
            first: None,
        }
    }

    pub(crate) fn failure(&self) -> Option<&StorageStateError> {
        match self.first? {
            PreparationFailureV1::ResultState => self.result_state.as_ref()
                .and_then(|result| result.as_ref().err()),
            PreparationFailureV1::Transition => self.transition.as_ref()
                .and_then(|result| result.as_ref().err()),
            PreparationFailureV1::TransitionBytes => self.transition_bytes.as_ref()
                .and_then(|result| result.as_ref().err()),
            PreparationFailureV1::TransitionBound => self.transition_bound.as_ref()
                .and_then(|result| result.as_ref().err()),
            PreparationFailureV1::Digest => self.digest.as_ref()
                .and_then(|result| result.as_ref().err()),
            PreparationFailureV1::HeadBytes => self.head_bytes.as_ref()
                .and_then(|result| result.as_ref().err()),
            PreparationFailureV1::HeadBound => self.head_bound.as_ref()
                .and_then(|result| result.as_ref().err()),
        }
    }

    pub(super) fn take_failure(&mut self) -> Option<StorageStateError> {
        match self.first? {
            PreparationFailureV1::ResultState => self.result_state.take().and_then(Result::err),
            PreparationFailureV1::Transition => self.transition.take().and_then(Result::err),
            PreparationFailureV1::TransitionBytes => self.transition_bytes.take().and_then(Result::err),
            PreparationFailureV1::TransitionBound => self.transition_bound.take().and_then(Result::err),
            PreparationFailureV1::Digest => self.digest.take().and_then(Result::err),
            PreparationFailureV1::HeadBytes => self.head_bytes.take().and_then(Result::err),
            PreparationFailureV1::HeadBound => self.head_bound.take().and_then(Result::err),
        }
    }
}
