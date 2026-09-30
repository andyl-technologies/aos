//! Complete Original46 historical authority companion framing.
//!
//! ```text
//! AOSCSA01 | fixed header:344 | eight (length:u32be | exact bytes) |
//! SHA256("aos.sandbox.controller-storage-output-authority.v1\0" | prefix):32
//! ```
//!
//! The sole shared manifest/checkpoint modules own their nested codecs. An
//! outer checksum and complete byte custody do not prove current authority.

use std::ops::Range;

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_broker_session_protocol::manifest::{
    BROKER_SESSION_MANIFEST_BYTES, BrokerSessionManifestAudienceV1, BrokerSessionManifestV1,
};
use aos_sandbox_broker_session_protocol::{
    AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES, BrokerSessionProtocolV1,
    CanonicalBrokerRequestEnvelopeV1, authenticated_broker_method_profile_v1,
    decode_canonical_request_v1,
};
use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId};

use crate::authenticated_session::historical_checkpoint::{
    HistoricalSessionCheckpointV1, MAXIMUM_BYTES as MAXIMUM_CHECKPOINT_BYTES,
};

use super::trust_capsule::MAXIMUM_BYTES as MAXIMUM_PUBLIC_PIN_BYTES;
use super::{
    ArchiveResult, HistoricalControllerOutputOwnerCutV1, HistoricalControllerOutputPublicPinsV1,
    HistoricalStorageOutputArchiveErrorV1, Reader, digest, nonzero,
};

const DOMAIN: &[u8] = b"aos.sandbox.controller-storage-output-authority.v1\0";
const CARRIER_DOMAIN: &[u8] = b"aos.sandbox.controller-storage-output-original-carrier.v1\0";
const HEADER_BYTES: usize = 344;
const MAXIMUM_BYTES: usize = 408 + AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES
    + BROKER_SESSION_MANIFEST_BYTES + MAXIMUM_CHECKPOINT_BYTES + MAXIMUM_PUBLIC_PIN_BYTES + 1_104;
const METHOD: BrokerMethod = BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_OUTPUT;

/// Retains original coordinates as historical comparison data only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalStorageOutputCoordinatesV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    request_id: [u8; 16],
    session_binding: [u8; 32],
    client_sequence: u64,
    deadline: u64,
    not_before: i64,
    not_after: i64,
}

impl HistoricalStorageOutputCoordinatesV1 {
    /// Returns the recorded execution identity.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the recorded Create operation identity.
    #[must_use]
    pub const fn create_operation(&self) -> OperationId {
        self.create_operation
    }

    /// Returns the sole original method-46 request ID.
    #[must_use]
    pub const fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    /// Returns the recorded original session binding, not a live Session.
    #[must_use]
    pub const fn session_binding(&self) -> [u8; 32] {
        self.session_binding
    }

    /// Returns the recorded client sequence comparison value.
    #[must_use]
    pub const fn client_sequence(&self) -> u64 {
        self.client_sequence
    }

    /// Returns the recorded original boottime deadline.
    #[must_use]
    pub const fn deadline_boottime_nanoseconds(&self) -> u64 {
        self.deadline
    }

    /// Returns the recorded original wall validity interval.
    #[must_use]
    pub const fn wall_interval(&self) -> (i64, i64) {
        (self.not_before, self.not_after)
    }
}

/// Retains a complete bounded Original46 outer archive as historical DATA.
///
/// Decoding this value verifies the nested historical hello evidence, not a
/// current socket, independent protected pins, floor or Storage effect source.
/// The embedded carrier may remain unsupported by the sole method profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalStorageOutputAuthorityArchiveV1 {
    bytes: Vec<u8>,
    packet: Range<usize>,
    coordinates: HistoricalStorageOutputCoordinatesV1,
    attempt_digest: ObjectDigest,
    publication_digest: ObjectDigest,
    manifest: BrokerSessionManifestV1,
    checkpoint: HistoricalSessionCheckpointV1,
    owner_cut: HistoricalControllerOutputOwnerCutV1,
    public_pins: HistoricalControllerOutputPublicPinsV1,
    digest: [u8; 32],
}

impl HistoricalStorageOutputAuthorityArchiveV1 {
    /// Decodes bounded canonical Original46 outer framing and historical inputs.
    ///
    /// The packet is retained verbatim, even when its method profile is closed.
    /// Use [`Self::canonical_carrier`] separately; no fallback packet parser or
    /// historical-to-live conversion is provided.
    ///
    /// # Errors
    ///
    /// Rejects oversize/truncated bytes, illegal fields/kinds, reserved bytes,
    /// altered checksums, incompatible manifest/checkpoint/cut identities or
    /// noncanonical nested historical formats.
    pub fn decode(bytes: &[u8]) -> Result<Self, HistoricalStorageOutputArchiveErrorV1> {
        if bytes.len() > MAXIMUM_BYTES {
            return Err(HistoricalStorageOutputArchiveErrorV1::TooLarge);
        }
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != b"AOSCSA01" || reader.u16()? != 1 {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        let method = reader.u16()?;
        let kind = reader.u8()?;
        if method == 48 || kind == 2 {
            return Err(HistoricalStorageOutputArchiveErrorV1::UnsupportedFutureKind);
        }
        if method != 46 || kind != 1 {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        reader.zero(3)?;
        let execution = reader.array()?;
        let create_operation = reader.array()?;
        let request_id = reader.array()?;
        if reader.array::<16>()? != request_id {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        for identity in [&execution, &create_operation, &request_id] {
            nonzero(identity)?;
        }
        let attempt_digest = reader.array()?;
        nonzero(&attempt_digest)?;
        reader.zero(32)?;
        let publication_digest = reader.array()?;
        let owner_cut_digest = reader.array()?;
        let carrier_digest = reader.array()?;
        nonzero(&publication_digest)?;
        let session_binding = reader.array()?;
        nonzero(&session_binding)?;
        if reader.array::<32>()? != session_binding {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        let client_sequence = reader.u64()?;
        let deadline = reader.u64()?;
        let not_before = reader.i64()?;
        let not_after = reader.i64()?;
        if client_sequence == 0 || client_sequence == u64::MAX || deadline == 0
            || not_after <= not_before || reader.u16()? != 8
        {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        reader.zero(2)?;
        if usize::try_from(reader.u32()?).ok() != Some(bytes.len()) {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }

        let packet = reader.field(AUTHENTICATED_ORDINARY_REQUEST_MAXIMUM_BYTES)?;
        if packet.is_empty() || carrier_digest != digest(CARRIER_DOMAIN, packet) {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        let packet_range = HEADER_BYTES + 4..HEADER_BYTES + 4 + packet.len();
        let manifest_bytes = reader.field(BROKER_SESSION_MANIFEST_BYTES)?;
        let manifest = BrokerSessionManifestV1::decode(manifest_bytes)
            .map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?;
        if !reader.field(0)?.is_empty() {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        let checkpoint = HistoricalSessionCheckpointV1::decode(reader.field(MAXIMUM_CHECKPOINT_BYTES)?)
            .map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?;
        if !reader.field(0)?.is_empty() {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        let public_pins =
            HistoricalControllerOutputPublicPinsV1::decode(reader.field(MAXIMUM_PUBLIC_PIN_BYTES)?)?;
        let owner_cut = HistoricalControllerOutputOwnerCutV1::decode(reader.field(1_104)?)?;
        if !reader.field(0)?.is_empty() {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        let recorded_digest = reader.array()?;
        reader.finish()?;
        if recorded_digest != digest(DOMAIN, &bytes[..bytes.len() - 32]) {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }

        let coordinates = HistoricalStorageOutputCoordinatesV1 {
            execution: ExecutionId::from_bytes(execution),
            create_operation: OperationId::from_bytes(create_operation),
            request_id,
            session_binding,
            client_sequence,
            deadline,
            not_before,
            not_after,
        };
        validate_inputs(&coordinates, &manifest, &checkpoint, &owner_cut, &public_pins, owner_cut_digest)?;
        Ok(Self {
            bytes: bytes.to_vec(),
            packet: packet_range,
            coordinates,
            attempt_digest: ObjectDigest::from_bytes(attempt_digest),
            publication_digest: ObjectDigest::from_bytes(publication_digest),
            manifest,
            checkpoint,
            owner_cut,
            public_pins,
            digest: recorded_digest,
        })
    }

    /// Borrows every unchanged byte of the complete historical companion.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows historical original coordinates without granting currentness.
    #[must_use]
    pub const fn original_coordinates(&self) -> &HistoricalStorageOutputCoordinatesV1 {
        &self.coordinates
    }

    /// Borrows the exact full packet, including all retained signature bytes.
    #[must_use]
    pub fn packet_bytes(&self) -> &[u8] {
        &self.bytes[self.packet.clone()]
    }

    /// Borrows the historical unsigned ControllerStorage pin manifest.
    #[must_use]
    pub const fn controller_manifest(&self) -> &BrokerSessionManifestV1 {
        &self.manifest
    }

    /// Borrows the sole canonical historical hello/context checkpoint.
    #[must_use]
    pub const fn original_checkpoint(&self) -> &HistoricalSessionCheckpointV1 {
        &self.checkpoint
    }

    /// Borrows historical owner-cut DATA, not a current owner witness.
    #[must_use]
    pub const fn owner_cut_data(&self) -> &HistoricalControllerOutputOwnerCutV1 {
        &self.owner_cut
    }

    /// Borrows historical public pin DATA without choosing receiver trust.
    #[must_use]
    pub const fn public_pin_data(&self) -> &HistoricalControllerOutputPublicPinsV1 {
        &self.public_pins
    }

    /// Returns the unchanged AOSCST01 historical record commitment.
    #[must_use]
    pub const fn attempt_digest(&self) -> ObjectDigest {
        self.attempt_digest
    }

    /// Returns the complete historical publication commitment.
    #[must_use]
    pub const fn publication_digest(&self) -> ObjectDigest {
        self.publication_digest
    }

    /// Returns the full companion checksum, not an authority grant.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Uses the sole canonical Session decoder for the retained carrier.
    ///
    /// Successful decoding remains historical projection DATA, not protected
    /// Session admission. No signature or traffic validator is reimplemented.
    ///
    /// # Errors
    ///
    /// Returns `UnsupportedCarrierProfile` while method46 is unprofiled;
    /// otherwise propagates canonical carrier rejection without a bypass.
    pub fn canonical_carrier(
        &self,
    ) -> Result<CanonicalBrokerRequestEnvelopeV1, HistoricalStorageOutputArchiveErrorV1> {
        require_original_carrier_profile_v1()?;
        let carrier = decode_canonical_request_v1(self.packet_bytes())?;
        let signed = carrier.signed_artifact();
        let subject = signed.subject();
        let context = self.checkpoint.context();
        let key = &context.keys()[2];
        if signed.method() != METHOD || signed.signer() != key.signer()
            || subject.request_id() != self.coordinates.request_id
            || subject.sequence() != self.coordinates.client_sequence
            || subject.session_binding() != self.coordinates.session_binding
            || subject.client_process() != context.client_process()
            || subject.cleared_fields_digest() != carrier.cleared_fields_digest()
        {
            return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
        }
        // This existing primitive checks a historical signature under recorded
        // pins. It does not select a receiver's independent current authority.
        signed.verify_with_public_key(key.public_key())
            .map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?;
        let quartet = carrier.message().authorization.as_option()
            .ok_or(HistoricalStorageOutputArchiveErrorV1::Invalid)?;
        self.public_pins.validate_quartet(
            quartet, self.coordinates.wall_interval(), self.owner_cut.generations(),
        )?;
        Ok(carrier)
    }
}

/// Requires the existing method46 profile without opening or replacing it.
///
/// # Errors
///
/// Returns `UnsupportedCarrierProfile` while the sole profile remains absent.
pub fn require_original_carrier_profile_v1() -> Result<(), HistoricalStorageOutputArchiveErrorV1> {
    if authenticated_broker_method_profile_v1(METHOD).is_none() {
        return Err(HistoricalStorageOutputArchiveErrorV1::UnsupportedCarrierProfile);
    }
    Ok(())
}

fn validate_inputs(
    coordinates: &HistoricalStorageOutputCoordinatesV1,
    manifest: &BrokerSessionManifestV1,
    checkpoint: &HistoricalSessionCheckpointV1,
    cut: &HistoricalControllerOutputOwnerCutV1,
    public_pins: &HistoricalControllerOutputPublicPinsV1,
    cut_digest: [u8; 32],
) -> ArchiveResult<()> {
    let context = checkpoint.context();
    let expected_context = manifest.verification_context(
        context.boot_id(), context.client_process(), context.broker_process(),
    ).map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?;
    let transcript = checkpoint.verify().map_err(|_| HistoricalStorageOutputArchiveErrorV1::Invalid)?;
    if manifest.protocol() != BrokerSessionProtocolV1::Storage
        || manifest.audience() != BrokerSessionManifestAudienceV1::NodeController
        || manifest.protocol_version() != (1, 0)
        || context != &expected_context
        || transcript.session_binding() != coordinates.session_binding
        || cut.execution() != coordinates.execution
        || cut.create_operation() != coordinates.create_operation
        || cut.request_id() != coordinates.request_id
        || cut.boot_id() != context.boot_id()
        || cut.deadline_boottime_nanoseconds() != coordinates.deadline
        || cut.wall_interval() != coordinates.wall_interval()
        || cut.digest() != cut_digest
        || cut.endpoint_generations() != [manifest.route_generation(), manifest.trust_generation(),
            manifest.revocation_generation()]
        || public_pins.node().as_bytes() != &manifest.node_id()
    {
        return Err(HistoricalStorageOutputArchiveErrorV1::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn companion_size_and_future_kind_are_refused_before_nested_decode() {
        assert_eq!(MAXIMUM_BYTES, 1_314_394);
        assert!(matches!(HistoricalStorageOutputAuthorityArchiveV1::decode(&vec![0; MAXIMUM_BYTES + 1]),
            Err(HistoricalStorageOutputArchiveErrorV1::TooLarge)));

        let mut bytes = b"AOSCSA01".to_vec();
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&48_u16.to_be_bytes());
        bytes.push(2);
        assert!(matches!(HistoricalStorageOutputAuthorityArchiveV1::decode(&bytes),
            Err(HistoricalStorageOutputArchiveErrorV1::UnsupportedFutureKind)));
    }

    #[test]
    fn canonical_method46_remains_unsupported_without_any_fallback_parser() {
        assert!(matches!(require_original_carrier_profile_v1(),
            Err(HistoricalStorageOutputArchiveErrorV1::UnsupportedCarrierProfile)));
    }
}
