//! Excludes actual normal-Root public signer pins from initial approval.
//!
//! The enclosing Source-bound loan supplies five existing role credentials or
//! their compared optional absence. Canonical decoders retain their typed
//! results, including errors. Additional Root trust families, native Root
//! authority and installed provisioning qualification remain separate.

use aos_sandbox_ledger_replay::source_signer_data::{
    PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackErrorV1,
};
use aos_sandbox_policy::controller_readback::{
    ControllerHoldReadbackDataErrorV1, PinnedControllerHoldSignerV1,
};
use aos_sandbox_policy::policy_signer_credential::{PinnedPolicySignerV1, PolicySignerRoleV1};
use aos_sandbox_policy::signed_inputs::RootStartupCredentialMemberV1 as Member;
use aos_sandbox_protocol::cache_owner_readback::{
    CacheOwnerReadbackDataErrorV1, PinnedCacheOwnerReadbackSignerV1,
};
use ed25519_dalek::VerifyingKey;

// Covers fixed policy-credential error allocations and codec/hash/key scratch.
// The enclosing compiled bound separately includes two complete owner layouts;
// raw bytes and native observations belong to the genuine credential owner.
pub(super) const DECODE_SCRATCH_BYTES: usize = 2048;

enum Decoded {
    Policy(std::io::Result<PinnedPolicySignerV1>),
    Cache(Result<PinnedCacheOwnerReadbackSignerV1, CacheOwnerReadbackDataErrorV1>),
    Controller(Result<PinnedControllerHoldSignerV1, ControllerHoldReadbackDataErrorV1>),
    Source(Result<PinnedSourceHoldReadbackSignerV1, SourceHoldReadbackErrorV1>),
}

impl Decoded {
    fn key(&self) -> Option<&VerifyingKey> {
        match self {
            Self::Policy(result) => result
                .as_ref()
                .ok()
                .map(PinnedPolicySignerV1::verifying_key),
            Self::Cache(result) => result
                .as_ref()
                .ok()
                .map(PinnedCacheOwnerReadbackSignerV1::verifying_key),
            Self::Controller(result) => result
                .as_ref()
                .ok()
                .map(PinnedControllerHoldSignerV1::verifying_key),
            Self::Source(result) => result
                .as_ref()
                .ok()
                .map(PinnedSourceHoldReadbackSignerV1::verifying_key),
        }
    }
}

pub(super) struct RootPublicKeyOriginal {
    member: Option<Member>,
    decoded: Option<Decoded>,
    separate: Option<bool>,
    absent: bool,
    entered: bool,
    closed: bool,
}

impl RootPublicKeyOriginal {
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
                Member::DeploymentKey => Decoded::Policy(PinnedPolicySignerV1::decode(
                    PolicySignerRoleV1::Deployment,
                    bytes,
                )),
                Member::ProjectKey => Decoded::Policy(PinnedPolicySignerV1::decode(
                    PolicySignerRoleV1::Project,
                    bytes,
                )),
                Member::CachePin => Decoded::Cache(PinnedCacheOwnerReadbackSignerV1::decode(bytes)),
                Member::ControllerPin => {
                    Decoded::Controller(PinnedControllerHoldSignerV1::decode(bytes))
                }
                Member::SourcePin => {
                    Decoded::Source(PinnedSourceHoldReadbackSignerV1::decode(bytes))
                }
                _ => {
                    self.closed = true;
                    return;
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
            && !self.closed
            && if self.absent {
                matches!(
                    self.member,
                    Some(Member::CachePin | Member::ControllerPin | Member::SourcePin)
                ) && self.decoded.is_none()
                    && self.separate.is_none()
            } else {
                self.decoded.as_ref().and_then(Decoded::key).is_some()
                    && self.separate == Some(true)
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_controller_domain::method46_initial_startup::METHOD46_INITIAL_ROOT_PUBLIC_KEY_MEMBERS_V1 as MEMBERS;
    use ed25519_dalek::SigningKey;

    fn credential(member: Member, generation: u64, key: &VerifyingKey) -> [u8; 80] {
        use aos_sandbox_policy::policy_signer_credential::encode_policy_signer_credential_v1;
        match member {
            Member::DeploymentKey => encode_policy_signer_credential_v1(PolicySignerRoleV1::Deployment, generation, key).unwrap(),
            Member::ProjectKey => encode_policy_signer_credential_v1(PolicySignerRoleV1::Project, generation, key).unwrap(),
            Member::CachePin => aos_sandbox_protocol::cache_owner_readback::encode_cache_owner_readback_signer_credential_v1(generation, key).unwrap(),
            Member::ControllerPin => aos_sandbox_policy::controller_readback::encode_controller_hold_signer_credential_v1(generation, key).unwrap(),
            Member::SourcePin => aos_sandbox_ledger_replay::source_signer_data::encode_source_hold_readback_signer_credential_v1(generation, key).unwrap(),
            _ => panic!("not a public signer credential"),
        }
    }

    #[test]
    fn all_five_canonical_roles_exclude_the_same_pin_under_any_generation() {
        let pin = SigningKey::from_bytes(&[2; 32]).verifying_key();
        let independent = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        for member in MEMBERS {
            for generation in [1, 2, u64::MAX] {
                let bytes = credential(member, generation, &pin);
                let mut original = RootPublicKeyOriginal::new();
                original.observe_once(member, Some(&bytes), independent);
                assert!(original.admitted());

                let mut reused = RootPublicKeyOriginal::new();
                reused.observe_once(member, Some(&bytes), pin.to_bytes());
                assert!(!reused.admitted());
                assert!(reused.decoded.as_ref().and_then(Decoded::key).is_some());
                assert_eq!(reused.separate, Some(false));
            }
        }
    }

    #[test]
    fn foreign_roles_or_changed_frames_preserve_the_actual_decoder_failure() {
        let pin = SigningKey::from_bytes(&[2; 32]).verifying_key();
        for member in MEMBERS {
            for foreign in MEMBERS {
                if member == foreign {
                    continue;
                }
                let bytes = credential(foreign, 1, &pin);
                let mut original = RootPublicKeyOriginal::new();

                original.observe_once(member, Some(&bytes), [3; 32]);

                assert!(!original.admitted());
                assert!(original.decoded.is_some());
                assert!(original.decoded.as_ref().and_then(Decoded::key).is_none());
                original.observe_once(member, Some(&credential(member, 1, &pin)), [3; 32]);
                assert!(!original.admitted());
                assert!(original.decoded.as_ref().and_then(Decoded::key).is_none());
            }
            let mut bytes = credential(member, 1, &pin);
            bytes[48] ^= 1;
            let mut original = RootPublicKeyOriginal::new();
            original.observe_once(member, Some(&bytes), [3; 32]);
            assert!(!original.admitted());
            assert!(original.decoded.as_ref().and_then(Decoded::key).is_none());
        }
    }

    #[test]
    fn only_optional_public_pins_accept_compared_absence_and_reentry_never_replaces_it() {
        for member in Member::ALL {
            let mut original = RootPublicKeyOriginal::new();
            original.observe_once(member, None, [3; 32]);
            assert_eq!(
                original.admitted(),
                matches!(
                    member,
                    Member::CachePin | Member::ControllerPin | Member::SourcePin
                )
            );
            original.observe_once(Member::CachePin, None, [3; 32]);
            assert!(!original.admitted());
            assert_eq!(original.member, Some(member));
            assert!(original.absent);
        }
    }
}
