//! Forwards the single strict selected-image DATA schema below Domain.
//!
//! Root admission and currentness remain above this schema. The lower decoder
//! owns the actual serde/allocation results; wrappers preserve fixed Root error
//! classification without cloning or discarding the original lower causes.

use std::path::Path;

use aos_sandbox_broker::profile_data::{
    ControllerProfileErrorV1,
    schema as shared,
};

use super::NormalRootStartupErrorV1;

pub(super) use shared::{
    CONTEXT, ImagePinV1, MAXIMUM_PROFILE_BYTES, MAXIMUM_RUNTIME_FILES,
    NormalRootProfileV1, PROFILE_PLACEHOLDER, UNIT,
    bounded_profile_representation_bytes_v1,
};

#[derive(Default)]
pub(super) struct RootProfileDecodeAttemptV1 {
    original: shared::RootProfileDecodeAttemptV1,
    classification: Option<NormalRootStartupErrorV1>,
}

impl RootProfileDecodeAttemptV1 {
    pub(super) fn decode_once(&mut self, bytes: &[u8]) -> Result<&NormalRootProfileV1, NormalRootStartupErrorV1> {
        if let Some(cause) = self.original.decode_once(bytes).err() {
            self.classification = self.original.failure()
                .and_then(|actual| actual.downcast_ref::<ControllerProfileErrorV1>())
                .map(|actual| (*actual).into());
            return Err(cause.into());
        }
        self.original.profile().ok_or(NormalRootStartupErrorV1::Profile)
    }

    pub(super) fn profile(&self) -> Option<&NormalRootProfileV1> {
        self.original.profile()
    }

    pub(super) fn take_completed(&mut self) -> Option<NormalRootProfileV1> {
        self.original.take_completed()
    }

    pub(super) fn restore_completed(&mut self, profile: NormalRootProfileV1) {
        self.original.restore_completed(profile);
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        let actual = self.original.failure()?;
        if actual.is::<ControllerProfileErrorV1>() {
            self.classification.as_ref().map(|cause| cause as &(dyn std::error::Error + 'static))
        } else {
            Some(actual)
        }
    }
}

pub(crate) fn require_store_path(path: &str) -> Result<(), NormalRootStartupErrorV1> {
    shared::require_store_path(path).map_err(Into::into)
}

pub(super) fn normalized_unit(bytes: &[u8], path: &str) -> Result<Vec<u8>, NormalRootStartupErrorV1> {
    shared::normalized_unit(bytes, path).map_err(Into::into)
}

impl From<ControllerProfileErrorV1> for NormalRootStartupErrorV1 {
    fn from(error: ControllerProfileErrorV1) -> Self {
        match error {
            ControllerProfileErrorV1::Activation => Self::Activation,
            ControllerProfileErrorV1::Profile => Self::Profile,
            ControllerProfileErrorV1::Image => Self::Image,
            ControllerProfileErrorV1::Service => Self::Service,
            ControllerProfileErrorV1::Confinement => Self::Confinement,
        }
    }
}

#[cfg(test)]
mod retained_decoder_tests {
    use super::*;

    #[test]
    fn native_schema_projection_retains_its_original_error_class() {
        let mut decode = RootProfileDecodeAttemptV1::default();

        assert!(decode.decode_once(&[]).is_err());
        let cause = decode.failure().unwrap();
        assert!(matches!(cause.downcast_ref::<NormalRootStartupErrorV1>(),
            Some(NormalRootStartupErrorV1::Profile)));
        assert!(!cause.is::<ControllerProfileErrorV1>());
    }

    #[test]
    fn malformed_json_keeps_the_same_actual_serde_error_on_retry() {
        let mut decode = RootProfileDecodeAttemptV1::default();

        assert!(decode.decode_once(b"{").is_err());
        let first = decode.failure().unwrap().downcast_ref::<serde_json::Error>().unwrap()
            as *const serde_json::Error;
        assert!(decode.decode_once(b"{}").is_err());
        assert_eq!(decode.failure().unwrap().downcast_ref::<serde_json::Error>().unwrap()
            as *const serde_json::Error, first);
        assert!(decode.profile().is_none());
    }
}
