//! Distinct nonterminal framing for the original purpose-57 FUSE intent.
//!
//! ```text
//! authenticated Mount wrapper v1, kind=4 ||
//! AOSMFI01 || version:u16be=1 || pending:u8=0 || purpose:u8=1 ||
//! the common exact effect fields (Resource target, zero FDs, empty receipt)
//! ```
//!
//! The local purpose code is not a native Mount verb. Native `AOSMAE` and
//! codes 1 through 8 remain unchanged and refuse this payload. This intent
//! retains admission/ambiguity history only; it cannot be completed into a
//! readiness receipt or establish a live worker or resource-read grant.

use super::{
    AuthorizationRecordError, BrokerDomain, BrokerEffectIntentV1, BrokerVerb, EffectPayloadProfile,
    decode_effect_fields, encode_effect_fields,
};

pub(super) const MAGIC: &[u8; 8] = b"AOSMFI01";

pub(super) fn encode(
    intent: &BrokerEffectIntentV1,
    domain: BrokerDomain,
) -> Result<Vec<u8>, AuthorizationRecordError> {
    if domain != BrokerDomain::Mount || intent.verb != BrokerVerb::MountReserveFuseWorkerIntent {
        return Err(AuthorizationRecordError::InvalidPayload);
    }
    intent.validate()?;
    encode_effect_fields(intent, MAGIC, 1)
}

pub(super) fn decode(bytes: &[u8]) -> Result<BrokerEffectIntentV1, AuthorizationRecordError> {
    decode_effect_fields(bytes, EffectPayloadProfile::MountFuseIntent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{
        AuthenticatedValueKind, BrokerEffectStatusV1, BrokerGrantTarget, NodeJournalMacKey,
        RecordNamespace, decode_effect, open, open_effect_intent, seal, seal_effect_intent,
    };
    use aos_sandbox_core::BrokerResourceHandle;
    use sha2::Digest as _;

    #[test]
    fn fuse_intent_roundtrip_is_separate_from_native_effects_and_terminal_receipts() {
        let key = NodeJournalMacKey::new(BrokerDomain::Mount, [90; 16], [91; 32]).unwrap();
        let native = super::super::tests::sample_intent();
        let mut intent = native.clone();
        intent.verb = BrokerVerb::MountReserveFuseWorkerIntent;
        intent.target =
            BrokerGrantTarget::Resource(BrokerResourceHandle::from_bytes([7; 32]).unwrap());
        intent.maximum_descriptors = 0;
        intent.maximum_request_bytes = 4096;
        let bytes = seal_effect_intent(&key, RecordNamespace::Effect, intent.request_id(), &intent)
            .unwrap();

        assert_eq!(bytes[10], 4);
        assert_eq!(&bytes[32..40], MAGIC);
        assert!(intent.clone().complete(vec![1]).is_err());
        // Independently reproduced with the network-order fixture fields and
        // location-bound HMAC, after reproducing the existing native golden.
        assert_eq!(
            hex::encode(sha2::Sha256::digest(&bytes)),
            "6d6b4916743ac1414a416160e7d5d88ef86e5f07944f2dae8268ec8d1b9e898d"
        );
        assert_eq!(
            open_effect_intent(&key, RecordNamespace::Effect, intent.request_id(), &bytes).unwrap(),
            intent
        );
        assert!(decode_effect(&bytes[32..bytes.len() - 32], BrokerDomain::Mount).is_err());
        assert!(aos_sandbox_protocol::mount_source_consumption_state::structurally_decode_mount_effect_v1(&bytes).is_err());
        assert!(
            open(
                &key,
                RecordNamespace::Effect,
                intent.request_id(),
                AuthenticatedValueKind::EffectIntent,
                &bytes
            )
            .is_err()
        );

        let payload = encode(&intent, BrokerDomain::Mount).unwrap();
        let wrong_kind = seal(
            &key,
            RecordNamespace::Effect,
            intent.request_id(),
            AuthenticatedValueKind::EffectIntent,
            &payload,
        )
        .unwrap();
        assert!(
            open_effect_intent(
                &key,
                RecordNamespace::Effect,
                intent.request_id(),
                &wrong_kind
            )
            .is_err()
        );
        let native_payload = super::super::encode_effect(&native, BrokerDomain::Mount).unwrap();
        let wrong_payload = seal(
            &key,
            RecordNamespace::Effect,
            intent.request_id(),
            AuthenticatedValueKind::MountFuseIntent,
            &native_payload,
        )
        .unwrap();
        assert!(
            open_effect_intent(
                &key,
                RecordNamespace::Effect,
                intent.request_id(),
                &wrong_payload
            )
            .is_err()
        );

        for case in 0..4 {
            let mut changed = intent.clone();
            match case {
                0 => changed.target = BrokerGrantTarget::Assignment,
                1 => changed.maximum_descriptors = 1,
                2 => changed.maximum_request_bytes = 1024 * 1024 + 1,
                3 => {
                    changed.status = BrokerEffectStatusV1::Complete;
                    changed.receipt = vec![1];
                }
                _ => unreachable!(),
            }
            assert!(
                encode(&changed, BrokerDomain::Mount).is_err(),
                "changed profile {case}"
            );
        }
        for domain in [
            BrokerDomain::Host,
            BrokerDomain::Storage,
            BrokerDomain::Network,
        ] {
            assert!(encode(&intent, domain).is_err());
        }
        for code in [0, 2, 57, 255] {
            let mut changed = payload.clone();
            changed[11] = code;
            assert!(decode(&changed).is_err());
        }
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }
}
