//! Excludes captured administrative genesis verifier pins from initial approval.
//!
//! Both owners retain their existing role-specific canonical decodes, including
//! failures. These public-only comparisons grant no seed or genesis authority.
//!
//! ```text
//! Source verifier: AOSCSK01 role credential (80 bytes)
//! Project issuer: AOSPAK02 role credential (80 bytes)
//! ```

use aos_sandbox_controller_domain::method46_initial_startup::Method46InitialGenesisPublicPinV1 as Member;
use aos_sandbox_protocol::controller_source_seed::{
    ControllerSourceTreeSeedErrorV1, PinnedControllerSourceTreeSeedIssuerV1,
};
use aos_sandbox_protocol::publisher_project_authorization::{
    PinnedPublisherProjectAuthorizationIssuerV2, ProjectAuthorizationSignatureErrorV2,
};
use ed25519_dalek::VerifyingKey;

enum Decoded {
    Source(Result<PinnedControllerSourceTreeSeedIssuerV1, ControllerSourceTreeSeedErrorV1>),
    Project(
        Result<PinnedPublisherProjectAuthorizationIssuerV2, ProjectAuthorizationSignatureErrorV2>,
    ),
}

impl Decoded {
    fn key(&self) -> Option<&VerifyingKey> {
        match self {
            Self::Source(result) => result
                .as_ref()
                .ok()
                .map(PinnedControllerSourceTreeSeedIssuerV1::verifying_key),
            Self::Project(result) => result
                .as_ref()
                .ok()
                .map(PinnedPublisherProjectAuthorizationIssuerV2::verifying_key),
        }
    }
}

pub(super) struct GenesisPublicPinOriginal {
    member: Option<Member>,
    decoded: Option<Decoded>,
    separate: Option<bool>,
    absent: bool,
    entered: bool,
    closed: bool,
}

impl GenesisPublicPinOriginal {
    pub(super) fn new() -> Self {
        Self {
            member: None,
            decoded: None,
            separate: None,
            absent: false,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn observe_once(
        &mut self,
        member: Member,
        bytes: Option<&[u8]>,
        approval: [u8; 32],
    ) {
        if self.entered || self.closed {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.member = Some(member);
        if let Some(bytes) = bytes {
            self.decoded = Some(match member {
                Member::RootSourceTreeSeed | Member::ControllerSourceTreeSeed => {
                    Decoded::Source(PinnedControllerSourceTreeSeedIssuerV1::decode(bytes))
                }
                Member::RootProjectAuthorization | Member::ControllerProjectAuthorization => {
                    Decoded::Project(PinnedPublisherProjectAuthorizationIssuerV2::decode(bytes))
                }
            });
            self.separate = self
                .decoded
                .as_ref()
                .and_then(Decoded::key)
                .map(|key| !key.is_weak() && key.to_bytes() != approval);
        } else {
            self.absent = true;
        }
        self.closed = !self.admitted();
    }

    pub(super) fn admitted(&self) -> bool {
        self.entered
            && self.member.is_some()
            && !self.closed
            && if self.absent {
                self.decoded.is_none() && self.separate.is_none()
            } else {
                self.decoded.as_ref().and_then(Decoded::key).is_some()
                    && self.separate == Some(true)
            }
    }
}

#[cfg(test)]
mod tests {
    use aos_sandbox_protocol::controller_source_seed::encode_controller_source_tree_seed_credential_v1;
    use aos_sandbox_protocol::publisher_project_authorization::encode_project_authorization_issuer_credential_v2;
    use ed25519_dalek::SigningKey;

    use super::*;

    fn credential(member: Member, generation: u64, key: &VerifyingKey) -> [u8; 80] {
        match member {
            Member::RootSourceTreeSeed | Member::ControllerSourceTreeSeed => {
                encode_controller_source_tree_seed_credential_v1(generation, key).unwrap()
            }
            Member::RootProjectAuthorization | Member::ControllerProjectAuthorization => {
                encode_project_authorization_issuer_credential_v2(generation, key).unwrap()
            }
        }
    }

    #[test]
    fn every_genesis_pin_excludes_approval_under_any_generation() {
        let strong = SigningKey::from_bytes(&[1; 32]).verifying_key();
        let weak = VerifyingKey::from_bytes(&[0; 32]).unwrap();
        for key in [strong, weak] {
            for member in Member::ALL {
                for generation in [1, 2, u64::MAX] {
                    let bytes = credential(member, generation, &key);
                    for approval in [key.to_bytes(), [3; 32]] {
                        let mut original = GenesisPublicPinOriginal::new();

                        original.observe_once(member, Some(&bytes), approval);

                        assert_eq!(
                            original.admitted(),
                            !key.is_weak() && approval != key.to_bytes()
                        );
                        assert!(original.decoded.as_ref().and_then(Decoded::key).is_some());
                    }
                }
            }
        }
    }

    #[test]
    fn foreign_frames_or_changed_checksums_retain_the_original_decode_failure() {
        let key = SigningKey::from_bytes(&[1; 32]).verifying_key();
        for member in Member::ALL {
            let foreign = match member {
                Member::RootSourceTreeSeed | Member::ControllerSourceTreeSeed => {
                    Member::RootProjectAuthorization
                }
                _ => Member::RootSourceTreeSeed,
            };
            let mut changed = credential(member, 1, &key);
            changed[79] ^= 1;
            for bytes in [credential(foreign, 1, &key), changed] {
                let mut original = GenesisPublicPinOriginal::new();

                original.observe_once(member, Some(&bytes), [3; 32]);
                assert!(!original.admitted());
                assert!(original.decoded.is_some());
                assert!(original.decoded.as_ref().and_then(Decoded::key).is_none());

                original.observe_once(member, None, [3; 32]);
                assert!(!original.admitted());
                assert!(original.decoded.is_some());
            }
        }
    }

    #[test]
    fn genuine_loan_selected_absence_cannot_replace_a_present_genesis_readback() {
        let key = SigningKey::from_bytes(&[1; 32]).verifying_key();
        for member in Member::ALL {
            let bytes = credential(member, 1, &key);
            for present in [false, true] {
                let mut original = GenesisPublicPinOriginal::new();

                original.observe_once(member, present.then_some(bytes.as_slice()), [3; 32]);
                assert!(original.admitted());
                assert_eq!(original.absent, !present);

                original.observe_once(member, (!present).then_some(bytes.as_slice()), [3; 32]);
                assert!(!original.admitted());
                assert_eq!(original.absent, !present);
            }
        }
    }
}
