//! Retains original raw32 normal public pins and approval-key exclusions.
//!
//! Actual Source-bound loans and PID1 deliveries select each role. These are
//! the existing Ed25519 public-key bytes, without a policy or signing seed.
//! Neither their canonical decode nor compared absence grants authority.
//!
//! ```text
//! public-policy-pin: Ed25519-public-key[32]
//! ```

use aos_sandbox_controller_domain::method46_initial_startup::{
    Method46InitialPublicPinMemberV1 as Member, Method46InitialPublicPinOwnerV1 as Owner,
};
use ed25519_dalek::{SignatureError, VerifyingKey};

#[derive(Clone, Copy)]
enum PublicPinOwner {
    Normal(Owner),
    Root,
}

pub(super) struct PublicPolicyPinOriginal {
    member: Option<Member>,
    owner: Option<PublicPinOwner>,
    bytes: Option<Result<[u8; 32], std::array::TryFromSliceError>>,
    key: Option<Result<VerifyingKey, SignatureError>>,
    separate: Option<bool>,
    absent: bool,
    entered: bool,
    closed: bool,
}

impl PublicPolicyPinOriginal {
    pub(super) fn new() -> Self {
        Self {
            member: None,
            owner: None,
            bytes: None,
            key: None,
            separate: None,
            absent: false,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn observe_once(
        &mut self,
        owner: Owner,
        member: Member,
        bytes: Option<&[u8]>,
        approval: [u8; 32],
    ) {
        self.observe_member_once(PublicPinOwner::Normal(owner), member, bytes, approval);
    }

    pub(super) fn observe_root_once(
        &mut self,
        member: Member,
        bytes: Option<&[u8]>,
        approval: [u8; 32],
    ) {
        self.observe_member_once(PublicPinOwner::Root, member, bytes, approval);
    }

    fn observe_member_once(
        &mut self,
        owner: PublicPinOwner,
        member: Member,
        bytes: Option<&[u8]>,
        approval: [u8; 32],
    ) {
        if self.entered || self.closed {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.owner = Some(owner);
        self.member = Some(member);
        if matches!(owner, PublicPinOwner::Root) && member == Member::NixRecipeIssuer {
            self.closed = true;
            return;
        }
        if let Some(bytes) = bytes {
            self.bytes = Some(bytes.try_into());
            if let Some(Ok(bytes)) = self.bytes.as_ref() {
                self.key = Some(VerifyingKey::from_bytes(bytes));
                self.separate = self.key.as_ref().and_then(|key| {
                    key.as_ref()
                        .ok()
                        .map(|key| !key.is_weak() && key.to_bytes() != approval)
                });
            }
        } else {
            self.absent = !matches!(owner, PublicPinOwner::Normal(Owner::Controller))
                || member == Member::NixRecipeIssuer;
        }
        self.closed = !self.admitted();
    }

    pub(super) fn admitted(&self) -> bool {
        self.entered
            && self.owner.is_some()
            && self.member.is_some()
            && !self.closed
            && if self.absent {
                self.bytes.is_none() && self.key.is_none() && self.separate.is_none()
            } else {
                matches!(self.bytes, Some(Ok(_)))
                    && matches!(self.key, Some(Ok(_)))
                    && self.separate == Some(true)
            }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn all_eight_public_roles_exclude_approval_without_requiring_distinct_normal_keys() {
        let key = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
        let other = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
        for owner in [Owner::Controller, Owner::NixBroker] {
            for member in Member::ALL {
                for approval in [key, other] {
                    let mut original = PublicPolicyPinOriginal::new();

                    original.observe_once(owner, member, Some(&key), approval);

                    assert_eq!(original.admitted(), approval != key);
                    assert!(matches!(original.bytes, Some(Ok(_))));
                    assert!(matches!(original.key, Some(Ok(_))));
                    assert_eq!(original.separate, Some(approval != key));
                }
            }
        }
    }

    #[test]
    fn only_optional_roles_can_retain_genuine_loan_selected_absence() {
        for owner in [Owner::Controller, Owner::NixBroker] {
            for member in Member::ALL {
                let mut original = PublicPolicyPinOriginal::new();

                original.observe_once(owner, member, None, [3; 32]);

                assert_eq!(
                    original.admitted(),
                    owner == Owner::NixBroker || member == Member::NixRecipeIssuer
                );
                assert!(original.bytes.is_none());
                assert!(original.key.is_none());

                original.observe_once(owner, member, None, [3; 32]);
                assert!(!original.admitted());
            }
        }
    }

    #[test]
    fn malformed_widths_weak_keys_and_reentry_retain_the_first_decode() {
        let key = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
        let mut weak = [0; 32];
        weak[0] = 1;
        let invalid = (0..=u8::MAX)
            .map(|byte| [byte; 32])
            .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
            .expect("some compressed Ed25519 points are invalid");
        for bytes in [vec![1; 31], vec![1; 33], weak.to_vec(), invalid.to_vec()] {
            let mut original = PublicPolicyPinOriginal::new();

            original.observe_once(
                Owner::Controller,
                Member::OwnershipLease,
                Some(&bytes),
                [3; 32],
            );
            assert!(!original.admitted());
            let first_bytes = original.bytes;
            let first_key_failed = matches!(original.key, Some(Err(_)));

            original.observe_once(
                Owner::Controller,
                Member::OwnershipLease,
                Some(&key),
                [3; 32],
            );

            assert!(!original.admitted());
            match first_bytes {
                Some(Ok(bytes)) => {
                    assert!(matches!(original.bytes, Some(Ok(retained)) if retained == bytes))
                }
                Some(Err(_)) => assert!(matches!(original.bytes, Some(Err(_)))),
                None => panic!("the first width decode must remain resident"),
            }
            assert_eq!(matches!(original.key, Some(Err(_))), first_key_failed);
        }
    }

    #[test]
    fn root_public_policy_pins_exclude_approval_and_only_admit_actual_optional_members() {
        let key = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
        for member in Member::ALL {
            for bytes in [None, Some(key.as_slice())] {
                for approval in [key, [3; 32]] {
                    let mut original = PublicPolicyPinOriginal::new();

                    original.observe_root_once(member, bytes, approval);

                    assert_eq!(
                        original.admitted(),
                        member != Member::NixRecipeIssuer && (bytes.is_none() || approval != key)
                    );
                    original.observe_root_once(member, bytes, approval);
                    assert!(!original.admitted());
                }
            }
        }
    }
}
