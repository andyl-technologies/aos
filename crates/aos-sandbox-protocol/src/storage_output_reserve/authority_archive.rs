//! Bounded historical bytes for one original Storage output reserve.
//!
//! The Output-specific codecs retain complete preimages. They borrow the sole
//! shared manifest and historical checkpoint codecs; they never construct a
//! current Session, protected owner, floor, resend permit or Storage admission.
//! The canonical method-46 carrier remains unsupported by the existing profile.
//!
//! ```text
//! AOSCSA01: original envelope + pin manifest + checkpoint + public pins + cut
//! AOSCOC01: six ordered historical owner-cut entries
//! AOSCPN01: exact historical Controller plan/lease public policy bytes
//! ```

mod companion;
mod owner_cut;
mod trust_capsule;

pub use companion::{
    HistoricalStorageOutputAuthorityArchiveV1, HistoricalStorageOutputCoordinatesV1,
    require_original_carrier_profile_v1,
};
pub use owner_cut::HistoricalControllerOutputOwnerCutV1;
pub use trust_capsule::HistoricalControllerOutputPublicPinsV1;

use sha2::{Digest as _, Sha256};

/// Reports malformed historical Output bytes or an unavailable carrier profile.
#[derive(Debug, thiserror::Error)]
pub enum HistoricalStorageOutputArchiveErrorV1 {
    /// The bounded canonical format or a nested comparison field is invalid.
    #[error("invalid historical Storage output authority archive")]
    Invalid,
    /// A declared or actual byte length exceeds its closed format ceiling.
    #[error("historical Storage output authority archive is too large")]
    TooLarge,
    /// The reserved Host48 companion is not implemented by this archive format.
    #[error("historical Storage output archive kind is not supported")]
    UnsupportedFutureKind,
    /// The sole authenticated method profile does not support the carrier.
    #[error("historical Storage output carrier profile is unavailable")]
    UnsupportedCarrierProfile,
    /// The sole canonical Session carrier validator rejected the packet.
    #[error(transparent)]
    Carrier(#[from] aos_sandbox_broker_session_protocol::BrokerSessionProjectionError),
}

pub(super) type ArchiveResult<T> = Result<T, HistoricalStorageOutputArchiveErrorV1>;

pub(super) fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(domain).chain_update(bytes).finalize().into()
}

pub(super) fn nonzero(bytes: &[u8]) -> ArchiveResult<()> {
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
    }
    Ok(())
}

/// Advances through already bounded format bytes using checked offsets.
pub(super) struct Reader<'bytes> {
    bytes: &'bytes [u8],
    cursor: usize,
}

impl<'bytes> Reader<'bytes> {
    pub(super) fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub(super) fn take(&mut self, length: usize) -> ArchiveResult<&'bytes [u8]> {
        let end = self.cursor.checked_add(length)
            .ok_or(HistoricalStorageOutputArchiveErrorV1::TooLarge)?;
        let bytes = self.bytes.get(self.cursor..end)
            .ok_or(HistoricalStorageOutputArchiveErrorV1::Invalid)?;
        self.cursor = end;
        Ok(bytes)
    }

    pub(super) fn array<const N: usize>(&mut self) -> ArchiveResult<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)
    }

    pub(super) fn u8(&mut self) -> ArchiveResult<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub(super) fn u16(&mut self) -> ArchiveResult<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(super) fn u32(&mut self) -> ArchiveResult<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(super) fn u64(&mut self) -> ArchiveResult<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(super) fn i64(&mut self) -> ArchiveResult<i64> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    pub(super) fn zero(&mut self, length: usize) -> ArchiveResult<()> {
        if self.take(length)?.iter().any(|byte| *byte != 0) {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        Ok(())
    }

    pub(super) fn field(&mut self, maximum: usize) -> ArchiveResult<&'bytes [u8]> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| HistoricalStorageOutputArchiveErrorV1::TooLarge)?;
        if length > maximum {
            return Err(HistoricalStorageOutputArchiveErrorV1::TooLarge);
        }
        self.take(length)
    }

    pub(super) fn finish(self) -> ArchiveResult<()> {
        if self.cursor != self.bytes.len() {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::Audience;
    use aos_sandbox_broker_session_protocol::manifest::{
        BrokerSessionManifestAudienceV1, BrokerSessionManifestKeyPinV1, BrokerSessionManifestV1,
    };
    use aos_sandbox_broker_session_protocol::{
        BrokerClientHelloSubjectV1, BrokerHelloSubjectV1, BrokerSessionKeyUsageV1,
        BrokerSessionProtocolV1, BrokerSessionSignerReferenceV1, client_hello_fields_digest_v1,
        complete_signed_client_hello_digest_v1, encode_signed_client_hello_packet_v1,
        encode_signed_server_hello_packet_v1, production_broker_client_hello_v1,
        production_broker_server_hello_v1, server_hello_fields_digest_v1,
        sign_broker_hello_v1, sign_client_hello_v1, verify_broker_session_transcript_v1,
        decode_canonical_client_hello_v1, decode_canonical_server_hello_v1,
    };
    use aos_sandbox_core::format::encode_trust_policy;
    use aos_sandbox_core::model::{KeyReference, StableKeyId, TrustPolicy};
    use aos_sandbox_core::{KeyUsage, ObjectDigest, SignaturePurpose, TrustScopeId};
    use ed25519_dalek::SigningKey;

    use crate::PeerCredentials;
    use crate::authenticated_session::historical_checkpoint::HistoricalSessionCheckpointV1;

    use super::*;

    // These deliberately synthetic cut commitments are DATA. Real signed hello
    // evidence exercises the shared codec; no method46 packet or live owner is
    // fabricated, and the embedded opaque carrier remains explicitly unsupported.
    fn fixture() -> Vec<u8> {
        let (manifest, checkpoint, session_binding) = hello_evidence();
        let cut = owner_cut();
        let pins = public_pins();
        let packet = b"opaque unprofiled method46 carrier DATA";
        let mut bytes = b"AOSCSA01".to_vec();
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&46_u16.to_be_bytes());
        bytes.extend_from_slice(&[1, 0, 0, 0]);
        for identity in [[1; 16], [2; 16], [18; 16], [18; 16]] {
            bytes.extend_from_slice(&identity);
        }
        bytes.extend_from_slice(&[9; 32]);
        bytes.extend_from_slice(&[0; 32]);
        bytes.extend_from_slice(&[10; 32]);
        bytes.extend_from_slice(&cut[cut.len() - 32..]);
        bytes.extend_from_slice(&digest(
            b"aos.sandbox.controller-storage-output-original-carrier.v1\0", packet,
        ));
        bytes.extend_from_slice(&session_binding);
        bytes.extend_from_slice(&session_binding);
        bytes.extend_from_slice(&1_u64.to_be_bytes());
        bytes.extend_from_slice(&950_u64.to_be_bytes());
        bytes.extend_from_slice(&100_i64.to_be_bytes());
        bytes.extend_from_slice(&130_i64.to_be_bytes());
        bytes.extend_from_slice(&8_u16.to_be_bytes());
        bytes.extend_from_slice(&[0; 2]);
        bytes.extend_from_slice(&[0; 4]);
        assert_eq!(bytes.len(), 344);

        for field in [packet.as_slice(), manifest.as_slice(), &[], checkpoint.as_slice(), &[],
            pins.as_slice(), cut.as_slice(), &[]]
        {
            bytes.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(field);
        }
        let total = u32::try_from(bytes.len() + 32).unwrap();
        bytes[340..344].copy_from_slice(&total.to_be_bytes());
        seal(b"aos.sandbox.controller-storage-output-authority.v1\0", &mut bytes);
        bytes
    }

    fn hello_evidence() -> ([u8; 920], Vec<u8>, [u8; 32]) {
        let keys = [1_u8, 2, 3, 4].map(|seed| SigningKey::from_bytes(&[seed; 32]));
        let usages = [BrokerSessionKeyUsageV1::ClientHello, BrokerSessionKeyUsageV1::BrokerHello,
            BrokerSessionKeyUsageV1::ClientRecord, BrokerSessionKeyUsageV1::BrokerOutcome];
        let pins: [BrokerSessionManifestKeyPinV1; 4] = std::array::from_fn(|index| {
            let signer = BrokerSessionSignerReferenceV1::for_signing_key(
                [30; 16], 1, [31; 32], [u8::try_from(index + 1).unwrap(); 16],
                1, usages[index], &keys[index],
            ).unwrap();
            BrokerSessionManifestKeyPinV1::new(
                signer, keys[index].verifying_key().to_bytes(), 1, 1, false, None,
            ).unwrap()
        });
        let manifest = BrokerSessionManifestV1::new(
            BrokerSessionProtocolV1::Storage, BrokerSessionManifestAudienceV1::NodeController,
            1, 0, [32; 16], [33; 16], 1, [34; 32], 1, [35; 32], 1, [36; 32], [11; 16], pins,
        ).unwrap();
        let context = manifest.verification_context([4; 16], [37; 16], [38; 16]).unwrap();
        let client = production_broker_client_hello_v1(
            BrokerSessionProtocolV1::Storage, Audience::AUDIENCE_NODE_CONTROLLER, 4_096,
        ).unwrap();
        let client_subject = BrokerClientHelloSubjectV1::new(
            context.node_id(), context.boot_id(), context.protocol(), 1, 0, context.audience(),
            context.client_process(), [39; 32], context.protected_context_digest(),
            client_hello_fields_digest_v1(&client).unwrap(),
        ).unwrap();
        let signed_client = sign_client_hello_v1(
            client_subject, manifest.key_pins()[0].signer().clone(), &keys[0],
        ).unwrap();
        let client_packet = encode_signed_client_hello_packet_v1(client, &signed_client).unwrap();
        let broker = production_broker_server_hello_v1(
            BrokerSessionProtocolV1::Storage, Audience::AUDIENCE_NODE_CONTROLLER, 4_096,
        ).unwrap();
        let broker_subject = BrokerHelloSubjectV1::new(
            context.node_id(), context.boot_id(), context.protocol(), 1, 0, context.audience(),
            context.broker_process(), [40; 32], context.protected_context_digest(),
            complete_signed_client_hello_digest_v1(&signed_client),
            server_hello_fields_digest_v1(&broker).unwrap(),
        ).unwrap();
        let signed_broker = sign_broker_hello_v1(
            broker_subject, manifest.key_pins()[1].signer().clone(), &keys[1],
        ).unwrap();
        let broker_packet = encode_signed_server_hello_packet_v1(broker, &signed_broker).unwrap();
        let transcript = verify_broker_session_transcript_v1(
            &decode_canonical_client_hello_v1(&client_packet).unwrap(),
            &decode_canonical_server_hello_v1(&broker_packet).unwrap(), &context,
        ).unwrap();
        let checkpoint = HistoricalSessionCheckpointV1::new(
            context, &client_packet, &broker_packet,
            PeerCredentials { uid: 1, gid: 2, pid: Some(3) }, &transcript,
        ).unwrap();
        (manifest.encode(), checkpoint.encode().unwrap(), transcript.session_binding())
    }

    fn owner_cut() -> Vec<u8> {
        let mut bytes = b"AOSCOC01".to_vec();
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[1, 6, 0, 0, 0, 0]);
        for identity in [[1; 16], [2; 16], [18; 16], [4; 16]] {
            bytes.extend_from_slice(&identity);
        }
        bytes.extend_from_slice(&950_u64.to_be_bytes());
        bytes.extend_from_slice(&100_i64.to_be_bytes());
        bytes.extend_from_slice(&130_i64.to_be_bytes());
        bytes.extend_from_slice(&[7; 32]);
        bytes.extend_from_slice(&[8; 32]);
        for _ in 0..3 {
            bytes.extend_from_slice(&1_u64.to_be_bytes());
        }
        bytes.extend_from_slice(&[0; 16]);
        assert_eq!(bytes.len(), 208);

        for code in 1_u8..=6 {
            bytes.extend_from_slice(&[code, 0, 0, 0, 0, 0, 0, 0]);
            bytes.extend_from_slice(&(if code < 5 { 1_u64 } else { 0 }).to_be_bytes());
            let generations = match code { 1 | 3 => [0_u64; 3], 2 | 4 => [1, 0, 0], _ => [1; 3] };
            for generation in generations {
                bytes.extend_from_slice(&generation.to_be_bytes());
            }
            bytes.extend_from_slice(&[code; 96]);
            bytes.extend_from_slice(&(if code == 3 { 200_u64 } else { 0 }).to_be_bytes());
        }
        seal(b"aos.sandbox.controller-storage-output-owner-cut.v1\0", &mut bytes);
        assert_eq!(bytes.len(), 1_104);
        bytes
    }

    fn public_pins() -> Vec<u8> {
        let mut bytes = b"AOSCPN01".to_vec();
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&[2, 0, 0, 0, 0, 0]);
        for (seed, purpose, usage) in [
            (41, SignaturePurpose::BrokerAuthorization, KeyUsage::BrokerAuthorization),
            (42, SignaturePurpose::OwnershipLease, KeyUsage::OwnershipLease),
        ] {
            let public = SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
            let key = KeyReference::new(StableKeyId::new("historical-key".to_owned()).unwrap(),
                1, ObjectDigest::from_bytes(Sha256::digest(public).into()), usage);
            let policy = TrustPolicy::new(TrustScopeId::from_bytes([43; 16]), purpose,
                vec![key], Vec::new()).unwrap();
            let policy_bytes = encode_trust_policy(&policy);
            bytes.extend_from_slice(&u32::try_from(policy_bytes.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(&policy_bytes);
            bytes.extend_from_slice(&public);
            bytes.extend_from_slice(if purpose == SignaturePurpose::BrokerAuthorization { &[44; 16] } else { &[11; 16] });
        }
        seal(b"aos.sandbox.controller-storage-output-public-pins.v1\0", &mut bytes);
        bytes
    }

    fn seal(domain: &[u8], bytes: &mut Vec<u8>) {
        let checksum = digest(domain, bytes);
        bytes.extend_from_slice(&checksum);
    }

    #[test]
    fn complete_outer_data_retains_exact_bytes_but_never_opens_method46() {
        let bytes = fixture();
        let archive = HistoricalStorageOutputAuthorityArchiveV1::decode(&bytes).unwrap();
        assert_eq!(archive.canonical_bytes(), bytes);
        assert_eq!(archive.original_coordinates().request_id(), [18; 16]);
        assert_eq!(archive.owner_cut_data().canonical_bytes().len(), 1_104);
        assert!(matches!(archive.canonical_carrier(),
            Err(HistoricalStorageOutputArchiveErrorV1::UnsupportedCarrierProfile)));
    }

    #[test]
    fn changed_packet_and_declared_oversize_are_not_canonical_outer_data() {
        let mut changed = fixture();
        changed[348] ^= 1;
        let end = changed.len() - 32;
        let checksum = digest(b"aos.sandbox.controller-storage-output-authority.v1\0", &changed[..end]);
        changed[end..].copy_from_slice(&checksum);
        assert!(HistoricalStorageOutputAuthorityArchiveV1::decode(&changed).is_err());

        let mut oversized = fixture();
        oversized[344..348].copy_from_slice(&1_048_577_u32.to_be_bytes());
        assert!(matches!(HistoricalStorageOutputAuthorityArchiveV1::decode(&oversized),
            Err(HistoricalStorageOutputArchiveErrorV1::TooLarge)));
    }
}
