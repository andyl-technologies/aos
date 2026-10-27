//! Compares an actual normal ONLINE floor issuer against initial approval.
//!
//! The enclosing genuine readback loan supplies either the original public
//! credential or its compared absence. Both the decode and comparison remain
//! resident for each Controller and Nix-owner input. They may share a public
//! ONLINE issuer, but neither may reuse the initial approval key. Offline Nix
//! approval keys require a separate purpose and delivery comparison.

use aos_sandbox_protocol::nix_online_floor_initialization::{
    OnlineFloorInitializationErrorV2, OnlineFloorIssuerDataV2,
};

pub(super) struct OnlineFloorIssuerOriginal {
    decoded: Option<Result<OnlineFloorIssuerDataV2, OnlineFloorInitializationErrorV2>>,
    separate: Option<bool>,
    absent: bool,
    entered: bool,
    closed: bool,
}

impl OnlineFloorIssuerOriginal {
    pub(super) fn new() -> Self {
        Self {
            decoded: None,
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
            self.decoded = Some(OnlineFloorIssuerDataV2::decode(bytes));
            self.separate = self.decoded.as_ref().and_then(|decoded| {
                decoded
                    .as_ref()
                    .ok()
                    .map(|issuer| issuer.public_key() != approval)
            });
        } else {
            self.absent = true;
        }
        self.closed = !self.admitted();
    }

    pub(super) fn admitted(&self) -> bool {
        self.entered
            && !self.closed
            && if self.absent {
                self.decoded.is_none() && self.separate.is_none()
            } else {
                matches!(self.decoded, Some(Ok(_))) && self.separate == Some(true)
            }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn issuer() -> [u8; 48] {
        let mut bytes = [1; 48];
        bytes[16..].copy_from_slice(&SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes());
        bytes
    }

    #[test]
    fn same_public_pin_refuses_even_under_another_issuer_id() {
        let mut bytes = issuer();
        let approval = OnlineFloorIssuerDataV2::decode(&bytes)
            .unwrap()
            .public_key();
        for id in [1, 3] {
            bytes[..16].fill(id);
            let mut original = OnlineFloorIssuerOriginal::new();

            original.observe_once(Some(&bytes), approval);

            assert!(!original.admitted());
            assert!(matches!(original.decoded, Some(Ok(_))));
            assert_eq!(original.separate, Some(false));
        }
    }

    #[test]
    fn malformed_issuer_or_reentry_keeps_its_original_refusal() {
        let mut bytes = issuer();
        bytes[..16].fill(0);
        let mut original = OnlineFloorIssuerOriginal::new();

        original.observe_once(Some(&bytes), [3; 32]);
        assert!(!original.admitted());
        assert!(matches!(original.decoded, Some(Err(_))));

        original.observe_once(Some(&issuer()), [3; 32]);
        assert!(!original.admitted());
        assert!(matches!(original.decoded, Some(Err(_))));
    }

    #[test]
    fn genuine_loan_selected_absence_cannot_replace_a_present_original() {
        for present in [false, true] {
            let bytes = issuer();
            let mut original = OnlineFloorIssuerOriginal::new();

            original.observe_once(present.then_some(bytes.as_slice()), [3; 32]);
            assert!(original.admitted());
            assert_eq!(original.absent, !present);

            original.observe_once((!present).then_some(bytes.as_slice()), [3; 32]);
            assert!(!original.admitted());
            assert_eq!(original.absent, !present);
            assert_eq!(original.decoded.is_some(), present);
        }
    }

    #[test]
    fn each_online_owner_excludes_approval_even_when_the_other_issuer_is_distinct() {
        let bytes = issuer();
        let mut other = bytes;
        other[..16].fill(4);
        other[16..].copy_from_slice(&SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes());
        for pair in [[bytes, bytes], [bytes, other], [other, bytes]] {
            let approval = OnlineFloorIssuerDataV2::decode(&bytes)
                .unwrap()
                .public_key();
            let mut originals =
                std::array::from_fn::<_, 2, _>(|_| OnlineFloorIssuerOriginal::new());

            for (original, pin) in originals.iter_mut().zip(pair) {
                original.observe_once(Some(&pin), approval);
            }

            assert!(!originals.iter().all(OnlineFloorIssuerOriginal::admitted));
            for (original, pin) in originals.iter().zip(pair) {
                assert_eq!(original.admitted(), pin != bytes);
                assert!(matches!(original.decoded, Some(Ok(_))));
            }
        }
        // Sharing an ONLINE issuer is legitimate when approval is independent.
        let approval = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
        for _ in 0..2 {
            let mut original = OnlineFloorIssuerOriginal::new();
            original.observe_once(Some(&bytes), approval);
            assert!(original.admitted());
        }
    }
}
