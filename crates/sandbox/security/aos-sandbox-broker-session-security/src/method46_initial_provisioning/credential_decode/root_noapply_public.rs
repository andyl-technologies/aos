//! Excludes Root's separately delivered NoApply public pin from initial approval.
//!
//! The genuine startup loan supplies the optional original bytes. Canonical
//! framing and strict point decoding remain resident, including failed results.
//! This comparison supplies no private key, signing owner or effect authority.
//!
//! ```text
//! AOSRNP02 | generation:u64be | Ed25519-public:32 | checksum:32
//! ```

use aos_sandbox_protocol::host_execution_no_apply::root_attestation::{
    RootNoApplyAttestationDataErrorV2, RootNoApplyPublicPinDataV2,
};
use ed25519_dalek::{SignatureError, VerifyingKey};

pub(super) struct RootNoApplyPublicPinOriginal {
    decoded: Option<Result<RootNoApplyPublicPinDataV2, RootNoApplyAttestationDataErrorV2>>,
    key: Option<Result<VerifyingKey, SignatureError>>,
    separate: Option<bool>,
    absent: bool,
    entered: bool,
    closed: bool,
}

impl RootNoApplyPublicPinOriginal {
    pub(super) fn new() -> Self {
        Self {
            decoded: None,
            key: None,
            separate: None,
            absent: false,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn observe_once(&mut self, bytes: Option<&[u8]>, approval: [u8; 32]) {
        if self.entered || self.closed {
            self.closed = true;
            return;
        }
        self.entered = true;
        if let Some(bytes) = bytes {
            self.decoded = Some(RootNoApplyPublicPinDataV2::decode_canonical(bytes));
            if let Some(Ok(pin)) = &self.decoded {
                self.key = Some(VerifyingKey::from_bytes(&pin.public_key_v2()));
                self.separate = self
                    .key
                    .as_ref()
                    .and_then(|key| key.as_ref().ok())
                    .map(|key| !key.is_weak() && key.to_bytes() != approval);
            }
        } else {
            self.absent = true;
        }
        self.closed = !self.admitted();
    }

    pub(super) fn admitted(&self) -> bool {
        self.entered
            && !self.closed
            && if self.absent {
                self.decoded.is_none() && self.key.is_none() && self.separate.is_none()
            } else {
                matches!(self.decoded, Some(Ok(_)))
                    && matches!(self.key, Some(Ok(_)))
                    && self.separate == Some(true)
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn dedicated_root_pin_excludes_approval_under_every_generation() {
        let strong = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let weak = VerifyingKey::from_bytes(&[0; 32]).unwrap();
        for key in [strong, weak] {
            for generation in [1, 2, u64::MAX] {
                let pin = RootNoApplyPublicPinDataV2::new(generation, key.to_bytes()).unwrap();
                for approval in [key.to_bytes(), [3; 32]] {
                    let mut original = RootNoApplyPublicPinOriginal::new();

                    original.observe_once(Some(&pin.encode_canonical()), approval);

                    assert_eq!(
                        original.admitted(),
                        !key.is_weak() && approval != key.to_bytes()
                    );
                    assert_eq!(original.decoded.as_ref().unwrap().as_ref().unwrap(), &pin);
                    assert!(original.key.as_ref().unwrap().is_ok());
                }
            }
        }
    }

    #[test]
    fn malformed_first_frame_cannot_be_replaced_by_a_valid_pin_or_absence() {
        let key = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let pin = RootNoApplyPublicPinDataV2::new(7, key.to_bytes())
            .unwrap()
            .encode_canonical();
        let mut checksum = pin;
        checksum[79] ^= 1;
        let mut foreign = pin;
        foreign[..8].copy_from_slice(b"AOSRNK02");
        for bytes in [&pin[..79], &checksum[..], &foreign[..]] {
            for replacement in [None, Some(pin.as_slice())] {
                let mut original = RootNoApplyPublicPinOriginal::new();
                original.observe_once(Some(bytes), [3; 32]);
                assert!(!original.admitted());
                assert!(matches!(original.decoded, Some(Err(_))));

                original.observe_once(replacement, [3; 32]);

                assert!(!original.admitted());
                assert!(matches!(original.decoded, Some(Err(_))));
                assert!(original.key.is_none());
                assert!(!original.absent);
            }
        }
    }

    #[test]
    fn selected_absence_and_presence_cannot_replace_each_other() {
        let key = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let pin = RootNoApplyPublicPinDataV2::new(7, key.to_bytes())
            .unwrap()
            .encode_canonical();
        for bytes in [None, Some(pin.as_slice())] {
            let mut original = RootNoApplyPublicPinOriginal::new();
            original.observe_once(bytes, [3; 32]);
            assert!(original.admitted());

            original.observe_once(if bytes.is_some() { None } else { Some(&pin) }, [3; 32]);

            assert!(!original.admitted());
            assert_eq!(original.absent, bytes.is_none());
            assert_eq!(original.decoded.is_some(), bytes.is_some());
        }
    }
}
