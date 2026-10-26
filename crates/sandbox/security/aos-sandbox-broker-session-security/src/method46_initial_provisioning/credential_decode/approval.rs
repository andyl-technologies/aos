//! Retains the bounded signature attempt without supplying key provenance.
//!
//! Only the enclosing genuine credential owner supplies the request and pin.
//! This passive carrier shares the canonical intent verifier and grants no
//! independent-key, durable publication or physical TPM authority.

use crate::method46_initial_provisioning::METHOD46_INITIAL_INTENT_BYTES_V1;

use super::{
    Method46InitialDataErrorV1, Method46InitialIntentDataV1, Method46InitialRequestDataV1,
};

enum ApprovalInput {
    Signature([u8; 64]),
    Intent([u8; METHOD46_INITIAL_INTENT_BYTES_V1]),
}

pub(super) struct ApprovalVerificationOriginal {
    request: Option<Result<Method46InitialRequestDataV1, Method46InitialDataErrorV1>>,
    input: Option<ApprovalInput>,
    decoded: Option<Result<Method46InitialIntentDataV1, Method46InitialDataErrorV1>>,
    pin: Option<Result<[u8; 32], Method46InitialDataErrorV1>>,
    verified: Option<Result<Method46InitialIntentDataV1, Method46InitialDataErrorV1>>,
    entered: bool,
    closed: bool,
}

impl ApprovalVerificationOriginal {
    pub(super) fn verified_intent(
        &self,
    ) -> Result<Method46InitialIntentDataV1, Method46InitialDataErrorV1> {
        if !self.entered || self.closed {
            return Err(Method46InitialDataErrorV1::Conflict);
        }
        self.verified.ok_or(Method46InitialDataErrorV1::Conflict)?
    }

    pub(super) fn require_fresh(&self) -> Result<(), Method46InitialDataErrorV1> {
        if self.entered || self.closed {
            Err(Method46InitialDataErrorV1::Conflict)
        } else {
            Ok(())
        }
    }

    pub(super) fn new() -> Self {
        Self {
            request: None,
            input: None,
            decoded: None,
            pin: None,
            verified: None,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn verify_once(
        &mut self,
        request: Result<Method46InitialRequestDataV1, Method46InitialDataErrorV1>,
        signature: [u8; 64],
        pin: Result<[u8; 32], Method46InitialDataErrorV1>,
    ) -> Result<Method46InitialIntentDataV1, Method46InitialDataErrorV1> {
        self.capture_once(request, ApprovalInput::Signature(signature), pin)
    }

    pub(super) fn decode_once(
        &mut self,
        request: Result<Method46InitialRequestDataV1, Method46InitialDataErrorV1>,
        bytes: [u8; METHOD46_INITIAL_INTENT_BYTES_V1],
        pin: Result<[u8; 32], Method46InitialDataErrorV1>,
    ) -> Result<Method46InitialIntentDataV1, Method46InitialDataErrorV1> {
        self.capture_once(request, ApprovalInput::Intent(bytes), pin)
    }

    fn capture_once(
        &mut self,
        request: Result<Method46InitialRequestDataV1, Method46InitialDataErrorV1>,
        input: ApprovalInput,
        pin: Result<[u8; 32], Method46InitialDataErrorV1>,
    ) -> Result<Method46InitialIntentDataV1, Method46InitialDataErrorV1> {
        if self.entered || self.closed {
            self.closed = true;
            return Err(Method46InitialDataErrorV1::Conflict);
        }
        self.entered = true;
        self.request = Some(request);
        self.input = Some(input);
        self.pin = Some(pin);

        // Park every supplied DATA result before propagating a prerequisite
        // refusal. A later valid signature cannot replace the reached prefix.
        let result = (|| {
            let request = request?;
            let pin = pin?;
            self.decoded = Some(match self.input.as_ref() {
                Some(ApprovalInput::Signature(signature)) => {
                    Method46InitialIntentDataV1::from_approval(request, *signature, pin)
                }
                Some(ApprovalInput::Intent(bytes)) => {
                    Method46InitialIntentDataV1::decode(bytes, pin)
                }
                None => return Err(Method46InitialDataErrorV1::Conflict),
            });
            let intent = self.decoded.ok_or(Method46InitialDataErrorV1::Conflict)??;
            if intent.request() != request {
                return Err(Method46InitialDataErrorV1::Conflict);
            }
            Ok(intent)
        })();
        self.verified = Some(result);
        self.closed = result.is_err();
        result
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;
    use crate::method46_initial_provisioning::Method46InitialPurposeV1;

    fn request() -> Method46InitialRequestDataV1 {
        let mut salt = [4; 34];
        salt[..2].copy_from_slice(&[0, 0x0b]);
        Method46InitialRequestDataV1::new(
            Method46InitialPurposeV1::StorageBroker,
            [1; 16],
            [2; 16],
            [3; 32],
            salt,
            4,
            [5; 32],
        )
        .unwrap()
    }

    #[test]
    fn method46_initial_signature_retains_the_verified_request_and_rejects_reentry() {
        let request = request();
        let key = SigningKey::from_bytes(&[6; 32]);
        let signature = key.sign(&request.encode()).to_bytes();
        let pin = key.verifying_key().to_bytes();
        let mut original = ApprovalVerificationOriginal::new();
        assert!(original.require_fresh().is_ok());
        assert!(original.verified_intent().is_err());

        let intent = original
            .verify_once(Ok(request), signature, Ok(pin))
            .unwrap();
        assert_eq!(original.verified_intent(), Ok(intent));

        assert_eq!(intent.request(), request);
        assert_eq!(original.verified, Some(Ok(intent)));
        assert!(original.require_fresh().is_err());
        assert!(original.verify_once(Ok(request), [0; 64], Ok(pin)).is_err());
        assert!(
            matches!(original.input, Some(ApprovalInput::Signature(held)) if held == signature)
        );
        assert_eq!(original.verified, Some(Ok(intent)));
        assert!(original.closed);
        assert!(original.verified_intent().is_err());
    }

    #[test]
    fn method46_initial_wrong_pin_failure_cannot_be_healed_with_another_key() {
        let request = request();
        let key = SigningKey::from_bytes(&[6; 32]);
        let signature = key.sign(&request.encode()).to_bytes();
        let wrong_pin = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        let mut original = ApprovalVerificationOriginal::new();

        assert_eq!(
            original.verify_once(Ok(request), signature, Ok(wrong_pin)),
            Err(Method46InitialDataErrorV1::Approval)
        );

        assert!(
            original
                .verify_once(Ok(request), signature, Ok(key.verifying_key().to_bytes()))
                .is_err()
        );
        assert_eq!(original.pin, Some(Ok(wrong_pin)));
        assert_eq!(
            original.verified,
            Some(Err(Method46InitialDataErrorV1::Approval))
        );
    }

    #[test]
    fn method46_initial_request_refusal_retains_signature_and_pin_without_verifying() {
        let key = SigningKey::from_bytes(&[6; 32]);
        let pin = key.verifying_key().to_bytes();
        let mut original = ApprovalVerificationOriginal::new();

        assert_eq!(
            original.verify_once(Err(Method46InitialDataErrorV1::Conflict), [8; 64], Ok(pin)),
            Err(Method46InitialDataErrorV1::Conflict)
        );

        assert!(matches!(original.input, Some(ApprovalInput::Signature(held)) if held == [8; 64]));
        assert_eq!(original.pin, Some(Ok(pin)));
        assert!(original.decoded.is_none());
        assert_eq!(
            original.verified,
            Some(Err(Method46InitialDataErrorV1::Conflict))
        );
    }

    #[test]
    fn method46_initial_cold_signature_requires_the_same_current_request() {
        let current = request();
        let mut salt = [4; 34];
        salt[..2].copy_from_slice(&[0, 0x0b]);
        let changed = Method46InitialRequestDataV1::new(
            current.purpose(),
            [1; 16],
            [2; 16],
            [3; 32],
            salt,
            5,
            [9; 32],
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[6; 32]);
        let pin = key.verifying_key().to_bytes();
        let intent = Method46InitialIntentDataV1::from_approval(
            changed,
            key.sign(&changed.encode()).to_bytes(),
            pin,
        )
        .unwrap();
        let bytes = intent.encode();
        let mut original = ApprovalVerificationOriginal::new();

        assert_eq!(
            original.decode_once(Ok(current), bytes, Ok(pin)),
            Err(Method46InitialDataErrorV1::Conflict)
        );

        assert_eq!(original.decoded, Some(Ok(intent)));
        assert!(matches!(original.input, Some(ApprovalInput::Intent(held)) if held == bytes));
        assert!(
            original
                .verify_once(Ok(current), key.sign(&current.encode()).to_bytes(), Ok(pin))
                .is_err()
        );
        assert_eq!(
            original.verified,
            Some(Err(Method46InitialDataErrorV1::Conflict))
        );
    }

    #[test]
    fn method46_initial_cold_approval_uses_the_ordinary_strict_intent_decoder() {
        let request = request();
        let key = SigningKey::from_bytes(&[6; 32]);
        let pin = key.verifying_key().to_bytes();
        let intent = Method46InitialIntentDataV1::from_approval(
            request,
            key.sign(&request.encode()).to_bytes(),
            pin,
        )
        .unwrap();
        let mut original = ApprovalVerificationOriginal::new();

        assert_eq!(
            original.decode_once(Ok(request), intent.encode(), Ok(pin)),
            Ok(intent)
        );

        assert_eq!(original.decoded, Some(Ok(intent)));
        assert_eq!(original.verified, Some(Ok(intent)));
    }

    #[test]
    fn method46_initial_malformed_cold_input_stays_resident_before_a_fresh_retry() {
        let request = request();
        let key = SigningKey::from_bytes(&[6; 32]);
        let pin = key.verifying_key().to_bytes();
        let signature = key.sign(&request.encode()).to_bytes();
        let intent = Method46InitialIntentDataV1::from_approval(request, signature, pin).unwrap();
        let mut bytes = intent.encode();
        bytes[0] ^= 1;
        let mut original = ApprovalVerificationOriginal::new();

        assert_eq!(
            original.decode_once(Ok(request), bytes, Ok(pin)),
            Err(Method46InitialDataErrorV1::Encoding)
        );

        assert!(
            original
                .verify_once(Ok(request), signature, Ok(pin))
                .is_err()
        );
        assert!(matches!(original.input, Some(ApprovalInput::Intent(held)) if held == bytes));
        assert_eq!(
            original.decoded,
            Some(Err(Method46InitialDataErrorV1::Encoding))
        );
        assert_eq!(
            original.verified,
            Some(Err(Method46InitialDataErrorV1::Encoding))
        );
    }
}
