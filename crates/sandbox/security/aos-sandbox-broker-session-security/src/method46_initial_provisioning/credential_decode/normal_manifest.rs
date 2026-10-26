//! Compares the original public Storage manifest without private endpoint keys.
//!
//! The enclosing Source-paid readback owner supplies these inputs from its
//! retained credentials and genuine origin. The sole canonical manifest codec,
//! its result and all reached comparisons stay resident on refusal. Matching
//! this DATA does not replace normal unit image or live endpoint admission.

use aos_sandbox_broker::receiving::Method46InitialServiceRoleV1;
use aos_sandbox_broker_session_protocol::manifest::{
    BrokerSessionManifestAudienceV1, BrokerSessionManifestErrorV1, BrokerSessionManifestV1,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionDurableEndpointV1, BrokerSessionProtocolV1,
};

use crate::tpm_nv_custody::{FloorEndpointV1, FloorProfileV1};

pub(super) struct NormalManifestOriginal {
    decoded: Option<Result<BrokerSessionManifestV1, BrokerSessionManifestErrorV1>>,
    scope_match: Option<bool>,
    identity: Option<[u8; 32]>,
    stable_match: Option<bool>,
    approval_separate: Option<bool>,
    entered: bool,
    closed: bool,
}

impl NormalManifestOriginal {
    pub(super) fn new() -> Self {
        Self {
            decoded: None,
            scope_match: None,
            identity: None,
            stable_match: None,
            approval_separate: None,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn observe_once(
        &mut self,
        bytes: &[u8],
        role: Method46InitialServiceRoleV1,
        node: [u8; 16],
        profile: FloorProfileV1,
        approval: [u8; 32],
    ) {
        if self.entered || self.closed {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.decoded = Some(BrokerSessionManifestV1::decode(bytes));
        let Some(Ok(manifest)) = self.decoded.as_ref() else {
            self.closed = true;
            return;
        };
        let (endpoint, floor) = match role {
            Method46InitialServiceRoleV1::ControllerStorageClient => (
                BrokerSessionDurableEndpointV1::Client,
                FloorEndpointV1::ControllerStorageClient,
            ),
            Method46InitialServiceRoleV1::StorageBroker => (
                BrokerSessionDurableEndpointV1::Broker,
                FloorEndpointV1::StorageBroker,
            ),
        };
        self.scope_match = Some(
            manifest.protocol() == BrokerSessionProtocolV1::Storage
                && manifest.audience() == BrokerSessionManifestAudienceV1::NodeController
                && manifest.node_id() == node
                && profile.node() == node
                && profile.endpoint() == floor,
        );
        self.identity = Some(
            manifest
                .binding()
                .stable_endpoint_identity_data_v2(BrokerSessionProtocolV1::Storage, endpoint),
        );
        self.stable_match = self
            .identity
            .map(|identity| identity == profile.stable_endpoint());
        // Include revoked/superseded delivered pins: revocation alone cannot
        // turn one of these endpoint keys into an independent approval key.
        self.approval_separate = Some(
            manifest
                .key_pins()
                .iter()
                .all(|pin| *pin.public_key() != approval),
        );
        self.closed = !self.admitted();
    }

    pub(super) fn manifest(&self) -> Option<&BrokerSessionManifestV1> {
        self.admitted()
            .then(|| self.decoded.as_ref()?.as_ref().ok())
            .flatten()
    }

    pub(super) fn admitted(&self) -> bool {
        !self.closed
            && matches!(self.decoded, Some(Ok(_)))
            && self.scope_match == Some(true)
            && self.stable_match == Some(true)
            && self.approval_separate == Some(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(
        role: Method46InitialServiceRoleV1,
    ) -> (BrokerSessionManifestV1, FloorProfileV1, [u8; 32]) {
        let (manifest, _) =
            crate::test_signed_endpoint::manifest_and_secrets(BrokerSessionProtocolV1::Storage);
        let (endpoint, floor) = match role {
            Method46InitialServiceRoleV1::ControllerStorageClient => (
                BrokerSessionDurableEndpointV1::Client,
                FloorEndpointV1::ControllerStorageClient,
            ),
            Method46InitialServiceRoleV1::StorageBroker => (
                BrokerSessionDurableEndpointV1::Broker,
                FloorEndpointV1::StorageBroker,
            ),
        };
        let stable = manifest
            .binding()
            .stable_endpoint_identity_data_v2(BrokerSessionProtocolV1::Storage, endpoint);
        let profile =
            FloorProfileV1::new(floor, manifest.node_id(), [4; 16], stable, [5; 32]).unwrap();
        let approval = ed25519_dalek::SigningKey::from_bytes(&[99; 32])
            .verifying_key()
            .to_bytes();
        (manifest, profile, approval)
    }

    #[test]
    fn normal_public_manifest_matches_both_fixed_purposes_without_private_endpoint() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let (manifest, profile, approval) = fixture(role);
            let mut original = NormalManifestOriginal::new();

            original.observe_once(
                &manifest.encode(),
                role,
                manifest.node_id(),
                profile,
                approval,
            );

            assert!(original.admitted());
            assert_eq!(original.identity, Some(profile.stable_endpoint()));
            assert_eq!(
                original.decoded.as_ref().unwrap().as_ref().unwrap(),
                &manifest
            );
        }
    }

    #[test]
    fn every_normal_signing_pin_is_refused_as_initial_approval() {
        let role = Method46InitialServiceRoleV1::StorageBroker;
        let (manifest, profile, _) = fixture(role);
        for pin in manifest.key_pins() {
            let mut original = NormalManifestOriginal::new();

            original.observe_once(
                &manifest.encode(),
                role,
                manifest.node_id(),
                profile,
                *pin.public_key(),
            );

            assert!(!original.admitted());
            assert_eq!(original.approval_separate, Some(false));
            assert_eq!(original.stable_match, Some(true));
            assert!(matches!(original.decoded, Some(Ok(_))));
        }
    }

    #[test]
    fn revoked_delivered_pins_still_cannot_approve_initial_provisioning() {
        let role = Method46InitialServiceRoleV1::StorageBroker;
        let (manifest, _, _) = fixture(role);
        for index in 0..4 {
            let mut bytes = manifest.encode();
            bytes[184 + index * 184 + 168] = 1;
            let manifest = BrokerSessionManifestV1::decode(&bytes).unwrap();
            let stable = manifest.binding().stable_endpoint_identity_data_v2(
                BrokerSessionProtocolV1::Storage,
                BrokerSessionDurableEndpointV1::Broker,
            );
            let profile = FloorProfileV1::new(
                FloorEndpointV1::StorageBroker,
                manifest.node_id(),
                [4; 16],
                stable,
                [5; 32],
            )
            .unwrap();
            let mut original = NormalManifestOriginal::new();

            original.observe_once(
                &bytes,
                role,
                manifest.node_id(),
                profile,
                *manifest.key_pins()[index].public_key(),
            );

            assert!(!original.admitted());
            assert_eq!(original.scope_match, Some(true));
            assert_eq!(original.stable_match, Some(true));
            assert_eq!(original.approval_separate, Some(false));
        }
    }

    #[test]
    fn foreign_protocol_is_refused_even_with_a_self_consistent_stable_comparison() {
        let role = Method46InitialServiceRoleV1::StorageBroker;
        let (_, _, approval) = fixture(role);
        let (manifest, _) =
            crate::test_signed_endpoint::manifest_and_secrets(BrokerSessionProtocolV1::Host);
        let stable = manifest.binding().stable_endpoint_identity_data_v2(
            BrokerSessionProtocolV1::Storage,
            BrokerSessionDurableEndpointV1::Broker,
        );
        let profile = FloorProfileV1::new(
            FloorEndpointV1::StorageBroker,
            manifest.node_id(),
            [4; 16],
            stable,
            [5; 32],
        )
        .unwrap();
        let mut original = NormalManifestOriginal::new();

        original.observe_once(
            &manifest.encode(),
            role,
            manifest.node_id(),
            profile,
            approval,
        );

        assert!(!original.admitted());
        assert_eq!(original.scope_match, Some(false));
        assert_eq!(original.stable_match, Some(true));
        assert_eq!(original.approval_separate, Some(true));
    }

    #[test]
    fn successful_decode_is_retained_but_reentry_fences_its_comparison() {
        let role = Method46InitialServiceRoleV1::StorageBroker;
        let (manifest, profile, approval) = fixture(role);
        let mut original = NormalManifestOriginal::new();
        original.observe_once(
            &manifest.encode(),
            role,
            manifest.node_id(),
            profile,
            approval,
        );
        assert!(original.admitted());
        let first = std::ptr::from_ref(original.decoded.as_ref().unwrap().as_ref().unwrap());

        original.observe_once(b"replacement", role, manifest.node_id(), profile, approval);

        assert!(!original.admitted());
        assert_eq!(
            std::ptr::from_ref(original.decoded.as_ref().unwrap().as_ref().unwrap()),
            first
        );
        assert_eq!(original.identity, Some(profile.stable_endpoint()));
    }

    #[test]
    fn substituted_scope_and_endpoint_identity_remain_failed_with_original_decode() {
        let role = Method46InitialServiceRoleV1::StorageBroker;
        let (manifest, profile, approval) = fixture(role);
        let mut wrong_node = NormalManifestOriginal::new();
        wrong_node.observe_once(&manifest.encode(), role, [7; 16], profile, approval);
        assert!(!wrong_node.admitted());
        assert_eq!(wrong_node.scope_match, Some(false));

        let mut wrong_role = NormalManifestOriginal::new();
        wrong_role.observe_once(
            &manifest.encode(),
            Method46InitialServiceRoleV1::ControllerStorageClient,
            manifest.node_id(),
            profile,
            approval,
        );
        assert!(!wrong_role.admitted());
        assert_eq!(wrong_role.scope_match, Some(false));
        assert_eq!(wrong_role.stable_match, Some(false));
        assert!(matches!(wrong_role.decoded, Some(Ok(_))));

        let bad_profile = FloorProfileV1::new(
            FloorEndpointV1::StorageBroker,
            manifest.node_id(),
            [4; 16],
            [9; 32],
            [5; 32],
        )
        .unwrap();
        let mut wrong_stable = NormalManifestOriginal::new();
        wrong_stable.observe_once(
            &manifest.encode(),
            role,
            manifest.node_id(),
            bad_profile,
            approval,
        );
        assert!(!wrong_stable.admitted());
        assert_eq!(wrong_stable.scope_match, Some(true));
        assert_eq!(wrong_stable.stable_match, Some(false));
    }

    #[test]
    fn malformed_original_cannot_be_healed_by_a_valid_manifest_retry() {
        let role = Method46InitialServiceRoleV1::StorageBroker;
        let (manifest, profile, approval) = fixture(role);
        let mut original = NormalManifestOriginal::new();
        original.observe_once(b"invalid", role, manifest.node_id(), profile, approval);
        let first = std::ptr::from_ref(original.decoded.as_ref().unwrap().as_ref().unwrap_err());

        original.observe_once(
            &manifest.encode(),
            role,
            manifest.node_id(),
            profile,
            approval,
        );

        assert!(!original.admitted());
        assert_eq!(
            std::ptr::from_ref(original.decoded.as_ref().unwrap().as_ref().unwrap_err()),
            first
        );
        assert!(original.identity.is_none());
    }
}
