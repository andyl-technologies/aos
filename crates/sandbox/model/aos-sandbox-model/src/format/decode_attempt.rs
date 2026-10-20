//! Owns shared canonical decode results and their once-only model transfer.
//!
//! Pure schema codecs retain one complete model or the original canonical
//! refusal and typed semantic cause. Failed inert prefixes may drop; their
//! prepaid debit remains with the caller's ledger. This owner has no refund,
//! reset, verification, or native authority.

use std::error::Error;

use crate::broker_authorization::InvalidBrokerAuthorizationPlan;
use crate::model::{InvalidAssignmentManifest, InvalidDomainModel, InvalidTrustModel};
use crate::ownership_lease::InvalidOwnershipLease;
use crate::selector::{InvalidFeatureNamespace, InvalidMediaType};
use crate::RegistryError;

use super::CanonicalCborError;

pub(super) fn closed() -> CanonicalCborError {
    CanonicalCborError::InvalidSemantics {
        object: "retained authorization DATA",
        message: "capture is incomplete, repeated or already moved".to_owned(),
    }
}

pub(crate) type DecodeResult<T> = Result<T, DecodeFailure>;

/// Owns an exact canonical refusal and its original typed semantic cause.
#[derive(Debug)]
pub(crate) struct DecodeFailure {
    pub(crate) canonical: CanonicalCborError,
    semantic: Option<SemanticCause>,
}

impl From<CanonicalCborError> for DecodeFailure {
    fn from(canonical: CanonicalCborError) -> Self {
        Self {
            canonical,
            semantic: None,
        }
    }
}

macro_rules! semantic_causes {
    ($($variant:ident($cause:ty)),+ $(,)?) => {
        #[derive(Debug)]
        pub(super) enum SemanticCause {
            $($variant($cause),)+
        }

        $(impl From<$cause> for SemanticCause {
            fn from(cause: $cause) -> Self {
                Self::$variant(cause)
            }
        })+

        impl SemanticCause {
            fn error(&self) -> &(dyn Error + 'static) {
                match self {
                    $(Self::$variant(cause) => cause,)+
                }
            }
        }
    };
}

semantic_causes! {
    MediaType(InvalidMediaType),
    Feature(InvalidFeatureNamespace),
    Registry(RegistryError),
    Trust(InvalidTrustModel),
    Domain(InvalidDomainModel),
    Assignment(InvalidAssignmentManifest),
    Broker(InvalidBrokerAuthorizationPlan),
    Lease(InvalidOwnershipLease),
}

impl DecodeFailure {
    pub(crate) fn into_canonical(self) -> CanonicalCborError {
        self.canonical
    }

    fn cause(&self) -> &(dyn Error + 'static) {
        self.semantic.as_ref().map_or(
            &self.canonical as &(dyn Error + 'static),
            SemanticCause::error,
        )
    }
}

pub(super) fn typed_semantics<E: std::fmt::Display + Into<SemanticCause>>(
    object: &'static str,
    cause: E,
) -> DecodeFailure {
    DecodeFailure {
        canonical: super::tree::semantics(object, &cause),
        semantic: Some(cause.into()),
    }
}

/// Retains one final model or original failure without archiving inert prefixes.
pub(super) struct DecodeAttempt<T> {
    result: Option<DecodeResult<T>>,
    entered: bool,
    repeated: bool,
}

impl<T> Default for DecodeAttempt<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> DecodeAttempt<T> {
    pub(super) const fn new() -> Self {
        Self {
            result: None,
            entered: false,
            repeated: false,
        }
    }

    pub(super) fn begin(&mut self) -> Result<(), CanonicalCborError> {
        if self.entered {
            self.repeated = true;
            return Err(closed());
        }
        self.entered = true;
        Ok(())
    }

    pub(super) fn finish(&mut self, result: DecodeResult<T>) -> Result<(), CanonicalCborError> {
        self.result = Some(result);
        match self.result.as_ref() {
            Some(Ok(_)) => Ok(()),
            Some(Err(cause)) => Err(cause.canonical.clone()),
            None => Err(closed()),
        }
    }

    pub(super) fn failure(&self) -> Option<&CanonicalCborError> {
        self.result
            .as_ref()?
            .as_ref()
            .err()
            .map(|failure| &failure.canonical)
    }

    pub(super) fn cause(&self) -> Option<&(dyn Error + 'static)> {
        self.result
            .as_ref()?
            .as_ref()
            .err()
            .map(DecodeFailure::cause)
    }

    pub(super) fn model(&self) -> Option<&T> {
        if self.repeated {
            return None;
        }
        self.result.as_ref()?.as_ref().ok()
    }

    // This path only tests enums and moves a successful model. In particular,
    // None never clones a refusal or constructs the allocating closed error.
    pub(super) fn take_model_option_once(&mut self) -> Option<T> {
        if self.repeated || !matches!(self.result.as_ref(), Some(Ok(_))) {
            return None;
        }
        self.result.take().and_then(Result::ok)
    }

    pub(super) fn take_model_once(&mut self) -> Result<T, CanonicalCborError> {
        if let Some(cause) = self.failure() {
            return Err(cause.clone());
        }
        self.take_model_option_once().ok_or_else(closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_vector_prefix_drops_without_refunding_prepaid_bytes() {
        use crate::component_receiving::ComponentServiceReceivingLedgerV1;
        use crate::{ResourceDimension as D, ResourceVector};
        use std::{cell::Cell, rc::Rc};

        use super::super::cbor::Decoder;
        use super::super::DecodeLimits;

        struct PurePrefix(Rc<Cell<usize>>);

        impl Drop for PurePrefix {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }

        // Canonical CBOR [1, "bad"] passes prevalidation but the second
        // element fails this schema after the first private value is allocated.
        let input = [0x82, 0x01, 0x63, b'b', b'a', b'd'];
        let mut decoder = Decoder::new(&input, DecodeLimits::default()).unwrap();
        let drops = Rc::new(Cell::new(0));
        let demand = ResourceVector::ZERO.with(D::MemoryBytes, 4096);
        let mut ledger = ComponentServiceReceivingLedgerV1::new(demand);
        ledger.reserve(demand).unwrap();
        let mut attempt = DecodeAttempt::<Vec<PurePrefix>>::new();
        attempt.begin().unwrap();

        let decoded = decoder.bounded_vec(2, |decoder| {
            decoder.unsigned()?;
            Ok::<_, DecodeFailure>(PurePrefix(drops.clone()))
        });
        assert!(attempt.finish(decoded).is_err());

        assert_eq!(drops.get(), 1);
        assert!(attempt.model().is_none());
        assert!(attempt.failure().is_some());
        assert_eq!(ledger.charged(), demand);
        assert!(
            ledger
                .reserve(ResourceVector::ZERO.with(D::MemoryBytes, 1))
                .is_err()
        );
        assert_eq!(ledger.charged(), demand);
    }

    #[test]
    fn optional_take_moves_once_and_keeps_failed_causes_resident() {
        let mut attempt = DecodeAttempt::<String>::new();
        assert!(attempt.take_model_option_once().is_none());
        attempt.begin().unwrap();

        let value = "model".to_owned();
        let backing = value.as_ptr();
        attempt.finish(Ok(value)).unwrap();
        let model = attempt.take_model_option_once().unwrap();
        assert_eq!(model, "model");
        assert_eq!(backing, model.as_ptr());
        assert!(attempt.take_model_option_once().is_none());

        let mut failed = DecodeAttempt::<String>::new();
        failed.begin().unwrap();
        assert!(
            failed
                .finish(Err(typed_semantics(
                    "stable key ID",
                    InvalidTrustModel::InvalidStableKeyId,
                )))
                .is_err()
        );
        let canonical = std::ptr::from_ref(failed.failure().unwrap());
        let typed = std::ptr::from_ref(
            failed
                .cause()
                .unwrap()
                .downcast_ref::<InvalidTrustModel>()
                .unwrap(),
        );

        assert!(failed.take_model_option_once().is_none());
        assert!(failed.take_model_once().is_err());
        assert!(failed.begin().is_err());
        assert!(failed.take_model_option_once().is_none());
        assert_eq!(canonical, std::ptr::from_ref(failed.failure().unwrap()));
        assert_eq!(
            typed,
            std::ptr::from_ref(
                failed
                    .cause()
                    .unwrap()
                    .downcast_ref::<InvalidTrustModel>()
                    .unwrap(),
            )
        );
    }

    #[test]
    fn optional_take_does_not_move_a_model_after_reentry() {
        let mut attempt = DecodeAttempt::<String>::new();
        attempt.begin().unwrap();
        attempt.finish(Ok("model".to_owned())).unwrap();

        assert!(attempt.begin().is_err());
        assert!(attempt.take_model_option_once().is_none());
        assert!(attempt.model().is_none());
        assert!(matches!(attempt.result.as_ref(), Some(Ok(model)) if model == "model"));
    }
}
