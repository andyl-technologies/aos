//! Excludes mandatory normal endpoint pins from the initial approval purpose.
//!
//! The enclosing original lends actual Source-paid Host, Mount and Network
//! credential readbacks. Each canonical decode and comparison stays resident,
//! including revoked and superseded pins. Configured Mount FUSE and Nix use
//! that same codec. Their absence is accepted only from the genuine readback
//! loan's compared roster. Nix floor-authority and Root key separation and
//! native effects remain owed.

use aos_sandbox_broker_session_protocol::BrokerSessionProtocolV1;
use aos_sandbox_broker_session_protocol::manifest::{
    BrokerSessionManifestAudienceV1, BrokerSessionManifestErrorV1, BrokerSessionManifestV1,
};

pub(super) const PROTOCOLS: [BrokerSessionProtocolV1; 5] = [
    BrokerSessionProtocolV1::Host,
    BrokerSessionProtocolV1::Mount,
    BrokerSessionProtocolV1::Network,
    BrokerSessionProtocolV1::MountFuse,
    BrokerSessionProtocolV1::Nix,
];

pub(super) struct OtherNormalManifestOriginal {
    decoded: Option<Result<BrokerSessionManifestV1, BrokerSessionManifestErrorV1>>,
    scope_match: Option<bool>,
    approval_separate: Option<bool>,
    absent: Option<BrokerSessionProtocolV1>,
    entered: bool,
    closed: bool,
}

impl OtherNormalManifestOriginal {
    pub(super) fn new() -> Self {
        Self {
            decoded: None,
            scope_match: None,
            approval_separate: None,
            absent: None,
            entered: false,
            closed: false,
        }
    }

    pub(super) fn observe_once(
        &mut self,
        bytes: &[u8],
        protocol: BrokerSessionProtocolV1,
        node: [u8; 16],
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

        self.scope_match = Some(
            PROTOCOLS.contains(&protocol)
                && manifest.protocol() == protocol
                && manifest.audience() == BrokerSessionManifestAudienceV1::NodeController
                && manifest.node_id() == node,
        );
        self.approval_separate = Some(
            manifest
                .key_pins()
                .iter()
                .all(|pin| *pin.public_key() != approval),
        );
        self.closed = !self.admitted();
    }

    pub(super) fn admitted(&self) -> bool {
        if self.closed || self.scope_match != Some(true) {
            return false;
        }
        match self.absent {
            Some(BrokerSessionProtocolV1::MountFuse | BrokerSessionProtocolV1::Nix) => {
                self.decoded.is_none() && self.approval_separate.is_none()
            }
            Some(_) => false,
            None => matches!(self.decoded, Some(Ok(_))) && self.approval_separate == Some(true),
        }
    }

    pub(super) fn observe_optional_absence_once(&mut self, protocol: BrokerSessionProtocolV1) {
        if self.entered || self.closed {
            self.closed = true;
            return;
        }
        self.entered = true;
        self.absent = Some(protocol);
        self.scope_match = Some(matches!(
            protocol,
            BrokerSessionProtocolV1::MountFuse | BrokerSessionProtocolV1::Nix
        ));
        self.closed = !self.admitted();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn independent_approval() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[99; 32])
            .verifying_key()
            .to_bytes()
    }

    #[test]
    fn every_mandatory_endpoint_pin_is_excluded_from_initial_approval() {
        for protocol in PROTOCOLS {
            let (manifest, _) = crate::test_signed_endpoint::manifest_and_secrets(protocol);
            let mut admitted = OtherNormalManifestOriginal::new();
            admitted.observe_once(
                &manifest.encode(),
                protocol,
                manifest.node_id(),
                independent_approval(),
            );
            assert!(admitted.admitted());

            for pin in manifest.key_pins() {
                let mut original = OtherNormalManifestOriginal::new();
                original.observe_once(
                    &manifest.encode(),
                    protocol,
                    manifest.node_id(),
                    *pin.public_key(),
                );

                assert!(!original.admitted());
                assert_eq!(original.scope_match, Some(true));
                assert_eq!(original.approval_separate, Some(false));
                assert!(matches!(original.decoded, Some(Ok(_))));
            }
        }
    }

    #[test]
    fn retired_endpoint_pins_cannot_become_independent_approval_keys() {
        for protocol in PROTOCOLS {
            let (manifest, _) = crate::test_signed_endpoint::manifest_and_secrets(protocol);
            for index in 0..manifest.key_pins().len() {
                let offset = 184 + index * 184;
                // The canonical key record permits either revoked or
                // superseded history. Neither status confers independence.
                for superseded in [false, true] {
                    let mut bytes = manifest.encode();
                    if superseded {
                        bytes[offset + 169] = 1;
                        let generation = manifest.key_pins()[index].signer().key_generation() + 1;
                        bytes[offset + 176..offset + 184]
                            .copy_from_slice(&generation.to_be_bytes());
                    } else {
                        bytes[offset + 168] = 1;
                    }
                    let parsed = BrokerSessionManifestV1::decode(&bytes);
                    assert!(parsed.is_ok(), "canonical retired fixture: {parsed:?}");
                    let mut original = OtherNormalManifestOriginal::new();
                    original.observe_once(
                        &bytes,
                        protocol,
                        manifest.node_id(),
                        *manifest.key_pins()[index].public_key(),
                    );

                    assert!(!original.admitted());
                    assert_eq!(original.approval_separate, Some(false));
                }
            }
        }
    }

    #[test]
    fn substituted_node_protocol_audience_or_malformed_data_stays_refused() {
        for protocol in PROTOCOLS {
            let (manifest, _) = crate::test_signed_endpoint::manifest_and_secrets(protocol);
            let mut wrong_node = OtherNormalManifestOriginal::new();
            wrong_node.observe_once(
                &manifest.encode(),
                protocol,
                [77; 16],
                independent_approval(),
            );
            assert_eq!(wrong_node.scope_match, Some(false));

            for foreign in [
                BrokerSessionProtocolV1::Host,
                BrokerSessionProtocolV1::Storage,
                BrokerSessionProtocolV1::Mount,
                BrokerSessionProtocolV1::Network,
                BrokerSessionProtocolV1::MountFuse,
                BrokerSessionProtocolV1::Nix,
            ] {
                if foreign == protocol {
                    continue;
                }
                let mut wrong_protocol = OtherNormalManifestOriginal::new();
                wrong_protocol.observe_once(
                    &manifest.encode(),
                    foreign,
                    manifest.node_id(),
                    independent_approval(),
                );
                assert_eq!(wrong_protocol.scope_match, Some(false));
            }

            let mut original = OtherNormalManifestOriginal::new();
            original.observe_once(
                b"malformed",
                protocol,
                manifest.node_id(),
                independent_approval(),
            );
            let first =
                std::ptr::from_ref(original.decoded.as_ref().unwrap().as_ref().unwrap_err());
            original.observe_once(
                &manifest.encode(),
                protocol,
                manifest.node_id(),
                independent_approval(),
            );

            assert!(!original.admitted());
            assert_eq!(
                std::ptr::from_ref(original.decoded.as_ref().unwrap().as_ref().unwrap_err()),
                first
            );
        }

        let (manifest, _) = crate::test_signed_endpoint::manifest_and_secrets_for_audience(
            BrokerSessionProtocolV1::Host,
            BrokerSessionManifestAudienceV1::RootMount,
        );
        let mut original = OtherNormalManifestOriginal::new();
        original.observe_once(
            &manifest.encode(),
            BrokerSessionProtocolV1::Host,
            manifest.node_id(),
            independent_approval(),
        );
        assert_eq!(original.scope_match, Some(false));
    }

    #[test]
    fn successful_endpoint_comparison_cannot_be_reentered_or_replaced() {
        for protocol in PROTOCOLS {
            let (manifest, _) = crate::test_signed_endpoint::manifest_and_secrets(protocol);
            let mut original = OtherNormalManifestOriginal::new();
            original.observe_once(
                &manifest.encode(),
                protocol,
                manifest.node_id(),
                independent_approval(),
            );
            assert!(original.admitted());
            let first = std::ptr::from_ref(original.decoded.as_ref().unwrap().as_ref().unwrap());

            original.observe_once(
                b"replacement",
                protocol,
                manifest.node_id(),
                independent_approval(),
            );

            assert!(!original.admitted());
            assert_eq!(
                std::ptr::from_ref(original.decoded.as_ref().unwrap().as_ref().unwrap()),
                first
            );
            assert_eq!(original.approval_separate, Some(true));
        }
    }

    #[test]
    fn only_optional_protocols_can_retain_a_compared_absence() {
        for protocol in PROTOCOLS
            .into_iter()
            .chain([BrokerSessionProtocolV1::Storage])
        {
            let mut original = OtherNormalManifestOriginal::new();
            original.observe_optional_absence_once(protocol);

            assert_eq!(
                original.admitted(),
                matches!(
                    protocol,
                    BrokerSessionProtocolV1::MountFuse | BrokerSessionProtocolV1::Nix
                )
            );
            assert_eq!(original.absent, Some(protocol));
            assert!(original.decoded.is_none());
            assert!(original.approval_separate.is_none());

            let (manifest, _) = crate::test_signed_endpoint::manifest_and_secrets(protocol);
            original.observe_once(
                &manifest.encode(),
                protocol,
                manifest.node_id(),
                independent_approval(),
            );
            assert!(!original.admitted());
            assert!(original.decoded.is_none());
            assert_eq!(original.absent, Some(protocol));
        }
        for protocol in [
            BrokerSessionProtocolV1::MountFuse,
            BrokerSessionProtocolV1::Nix,
        ] {
            let (manifest, _) = crate::test_signed_endpoint::manifest_and_secrets(protocol);
            let mut original = OtherNormalManifestOriginal::new();
            original.observe_once(
                &manifest.encode(),
                protocol,
                manifest.node_id(),
                independent_approval(),
            );
            original.observe_optional_absence_once(protocol);
            assert!(!original.admitted());
            assert!(original.absent.is_none());
            assert!(matches!(original.decoded, Some(Ok(_))));
        }
    }
}
