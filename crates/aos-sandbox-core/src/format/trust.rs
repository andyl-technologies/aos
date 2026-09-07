//! Canonical codecs for trust policies, signed statements, and signatures.

use crate::model::{
    KeyReference, KeyUsage, Signature, SignatureBytes, SignaturePurpose, SignatureStatement,
    StableKeyId, TrustPolicy,
};
use crate::registry::{DescriptorRole, validate_signature_subject};
use crate::{ObjectDigest, TrustScopeId};

use super::cbor::{CanonicalCborError, DecodeLimits, Decoder, Encoder};
use super::tree::{
    decode_descriptor, decode_descriptor_for_role, decode_feature, decode_vec, encode_descriptor,
    encode_feature, encode_slice, exact_bytes, semantics,
};

/// Encodes one trust policy in its exact portable v1 CBOR form.
#[must_use]
pub fn encode_trust_policy(policy: &TrustPolicy) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(5);
    encoder.unsigned(1);
    encoder.bytes(policy.trust_scope().as_bytes());
    encoder.unsigned(purpose_code(policy.purpose()));
    encode_slice(&mut encoder, policy.allowed_keys(), encode_key_reference);
    encode_slice(&mut encoder, policy.required_features(), encode_feature);
    encoder.finish()
}

/// Decodes and validates one exact portable v1 trust-policy object.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for profile, schema, registry, key ordering,
/// usage, or feature-set violations.
pub fn decode_trust_policy(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<TrustPolicy, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(5)?;
    decoder.exact("trust policy version", 1)?;
    let trust_scope = decode_trust_scope_id(&mut decoder)?;
    let purpose = decode_purpose(&mut decoder)?;
    let allowed_keys = decode_vec(&mut decoder, decode_key_reference)?;
    let required_features = decode_vec(&mut decoder, decode_feature)?;
    decoder.finish()?;
    TrustPolicy::new(trust_scope, purpose, allowed_keys, required_features)
        .map_err(|error| semantics("trust policy", error))
}

/// Encodes one signature statement in the exact bytes covered by Ed25519.
#[must_use]
pub fn encode_signature_statement(statement: &SignatureStatement) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encode_statement(&mut encoder, statement);
    encoder.finish()
}

/// Decodes and validates one exact portable v1 signature statement.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for profile, schema, registry, signer usage,
/// or validity-interval violations.
pub fn decode_signature_statement(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<SignatureStatement, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    let statement = decode_statement(&mut decoder)?;
    decoder.finish()?;
    Ok(statement)
}

/// Encodes one detached signature envelope in portable v1 CBOR.
#[must_use]
pub fn encode_signature(signature: &Signature) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.array(2);
    encode_statement(&mut encoder, signature.statement());
    encoder.bytes(signature.signature().as_bytes());
    encoder.finish()
}

/// Decodes and validates one exact portable v1 detached signature envelope.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] for profile, schema, registry, statement
/// semantics, or a signature byte string whose length is not exactly 64.
pub fn decode_signature(
    bytes: &[u8],
    limits: DecodeLimits,
) -> Result<Signature, CanonicalCborError> {
    let mut decoder = Decoder::new(bytes, limits)?;
    decoder.array(2)?;
    let statement = decode_statement(&mut decoder)?;
    let signature = SignatureBytes::new(exact_bytes::<64>(&mut decoder, 64)?);
    decoder.finish()?;
    Ok(Signature::new(statement, signature))
}

fn encode_statement(encoder: &mut Encoder, statement: &SignatureStatement) {
    encoder.array(9);
    encoder.unsigned(1);
    encode_descriptor(encoder, statement.subject());
    encoder.bytes(statement.trust_scope().as_bytes());
    encode_key_reference(encoder, statement.signer());
    encoder.unsigned(1);
    encoder.unsigned(purpose_code(statement.purpose()));
    encoder.signed(statement.issued_seconds());
    match statement.expires_seconds() {
        Some(expiry) => encoder.signed(expiry),
        None => encoder.null(),
    }
    encode_descriptor(encoder, statement.verification_policy());
}

fn decode_statement(decoder: &mut Decoder<'_>) -> Result<SignatureStatement, CanonicalCborError> {
    decoder.array(9)?;
    decoder.exact("signature statement version", 1)?;
    let subject = decode_descriptor(decoder)?;
    let trust_scope = decode_trust_scope_id(decoder)?;
    let signer = decode_key_reference(decoder)?;
    decoder.exact("signature algorithm", 1)?;
    let purpose = decode_purpose(decoder)?;
    let issued_seconds = decoder.signed()?;
    let expires_seconds = decoder.nullable(Decoder::signed)?;
    let verification_policy =
        decode_descriptor_for_role(decoder, DescriptorRole::SignatureVerificationPolicy)?;
    validate_signature_subject(purpose, &subject)
        .map_err(|error| semantics("signature subject", error))?;
    SignatureStatement::new(
        subject,
        trust_scope,
        signer,
        purpose,
        issued_seconds,
        expires_seconds,
        verification_policy,
    )
    .map_err(|error| semantics("signature statement", error))
}

pub(super) fn encode_key_reference(encoder: &mut Encoder, key: &KeyReference) {
    encoder.array(4);
    encoder.text(key.stable_key_id().as_str());
    encoder.unsigned(key.generation());
    encoder.bytes(key.public_key_sha256().as_bytes());
    encoder.unsigned(usage_code(key.usage()));
}

pub(super) fn decode_key_reference(
    decoder: &mut Decoder<'_>,
) -> Result<KeyReference, CanonicalCborError> {
    decoder.array(4)?;
    let stable_key_id = StableKeyId::new(decoder.text(255)?.to_owned())
        .map_err(|error| semantics("stable key ID", error))?;
    let generation = decoder.unsigned()?;
    let public_key_sha256 = ObjectDigest::from_bytes(exact_bytes::<32>(decoder, 32)?);
    let usage = decode_usage(decoder)?;
    Ok(KeyReference::new(
        stable_key_id,
        generation,
        public_key_sha256,
        usage,
    ))
}

const fn purpose_code(purpose: SignaturePurpose) -> u64 {
    match purpose {
        SignaturePurpose::Policy => 0,
        SignaturePurpose::Tree => 1,
        SignaturePurpose::Snapshot => 2,
        SignaturePurpose::Distribution => 3,
        SignaturePurpose::BrokerAuthorization => 4,
        SignaturePurpose::OwnershipLease => 5,
        SignaturePurpose::PublisherAuthorization => 6,
    }
}

fn decode_purpose(decoder: &mut Decoder<'_>) -> Result<SignaturePurpose, CanonicalCborError> {
    match decoder.closed("signature purpose", 6)? {
        0 => Ok(SignaturePurpose::Policy),
        1 => Ok(SignaturePurpose::Tree),
        2 => Ok(SignaturePurpose::Snapshot),
        3 => Ok(SignaturePurpose::Distribution),
        4 => Ok(SignaturePurpose::BrokerAuthorization),
        5 => Ok(SignaturePurpose::OwnershipLease),
        6 => Ok(SignaturePurpose::PublisherAuthorization),
        value => Err(CanonicalCborError::UnknownRegistryValue {
            registry: "signature purpose",
            value,
            offset: decoder.position(),
        }),
    }
}

const fn usage_code(usage: KeyUsage) -> u64 {
    match usage {
        KeyUsage::Policy => 0,
        KeyUsage::Tree => 1,
        KeyUsage::Snapshot => 2,
        KeyUsage::Distribution => 3,
        KeyUsage::BrokerAuthorization => 4,
        KeyUsage::OwnershipLease => 5,
        KeyUsage::PublisherAuthorization => 6,
    }
}

fn decode_usage(decoder: &mut Decoder<'_>) -> Result<KeyUsage, CanonicalCborError> {
    match decoder.closed("key usage", 6)? {
        0 => Ok(KeyUsage::Policy),
        1 => Ok(KeyUsage::Tree),
        2 => Ok(KeyUsage::Snapshot),
        3 => Ok(KeyUsage::Distribution),
        4 => Ok(KeyUsage::BrokerAuthorization),
        5 => Ok(KeyUsage::OwnershipLease),
        6 => Ok(KeyUsage::PublisherAuthorization),
        value => Err(CanonicalCborError::UnknownRegistryValue {
            registry: "key usage",
            value,
            offset: decoder.position(),
        }),
    }
}

fn decode_trust_scope_id(decoder: &mut Decoder<'_>) -> Result<TrustScopeId, CanonicalCborError> {
    Ok(TrustScopeId::from_bytes(exact_bytes::<16>(decoder, 16)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MediaType, ObjectDescriptor};

    const STATEMENT_HEX: &str = "890184782a6170706c69636174696f6e2f766e642e616f732e73616e64626f782e706f6c6963792e76312b63626f7201582000000000000000000000000000000000000000000000000000000000000000000050000102030405060708090a0b0c0d0e0f8468746573742d6b657901582021fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b900010000f68478306170706c69636174696f6e2f766e642e616f732e73616e64626f782e74727573742d706f6c6963792e76312b63626f72015820111111111111111111111111111111111111111111111111111111111111111100";

    fn descriptor(media_type: &str, byte: u8) -> ObjectDescriptor {
        ObjectDescriptor::new(
            MediaType::new(media_type.to_owned())
                .unwrap_or_else(|error| panic!("test media type failed: {error}")),
            ObjectDigest::from_bytes([byte; 32]),
            0,
        )
    }

    fn vector_statement() -> SignatureStatement {
        SignatureStatement::new(
            descriptor("application/vnd.aos.sandbox.policy.v1+cbor", 0),
            TrustScopeId::from_bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            KeyReference::new(
                StableKeyId::new("test-key".to_owned())
                    .unwrap_or_else(|error| panic!("test key ID failed: {error}")),
                1,
                ObjectDigest::from_bytes(
                    hex::decode("21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9")
                        .unwrap_or_else(|error| panic!("test digest hex failed: {error}"))
                        .try_into()
                        .unwrap_or_else(|_| panic!("test digest length is wrong")),
                ),
                KeyUsage::Policy,
            ),
            SignaturePurpose::Policy,
            0,
            None,
            descriptor("application/vnd.aos.sandbox.trust-policy.v1+cbor", 0x11),
        )
        .unwrap_or_else(|error| panic!("test statement failed: {error}"))
    }

    #[test]
    fn publisher_tags_append_without_reassigning_existing_trust_codes() {
        let purposes = [
            SignaturePurpose::Policy,
            SignaturePurpose::Tree,
            SignaturePurpose::Snapshot,
            SignaturePurpose::Distribution,
            SignaturePurpose::BrokerAuthorization,
            SignaturePurpose::OwnershipLease,
            SignaturePurpose::PublisherAuthorization,
        ];
        let usages = [
            KeyUsage::Policy,
            KeyUsage::Tree,
            KeyUsage::Snapshot,
            KeyUsage::Distribution,
            KeyUsage::BrokerAuthorization,
            KeyUsage::OwnershipLease,
            KeyUsage::PublisherAuthorization,
        ];
        for (code, (purpose, usage)) in purposes.into_iter().zip(usages).enumerate() {
            let encoded = [u8::try_from(code)
                .unwrap_or_else(|error| panic!("test registry code exceeds one byte: {error}"))];
            assert_eq!(purpose_code(purpose), code as u64);
            assert_eq!(usage_code(usage), code as u64);
            let mut decoder = Decoder::new(&encoded, DecodeLimits::default())
                .unwrap_or_else(|error| panic!("test purpose decoder failed: {error}"));
            assert_eq!(decode_purpose(&mut decoder), Ok(purpose));
            decoder
                .finish()
                .unwrap_or_else(|error| panic!("test purpose has trailing bytes: {error}"));
            let mut decoder = Decoder::new(&encoded, DecodeLimits::default())
                .unwrap_or_else(|error| panic!("test usage decoder failed: {error}"));
            assert_eq!(decode_usage(&mut decoder), Ok(usage));
            decoder
                .finish()
                .unwrap_or_else(|error| panic!("test usage has trailing bytes: {error}"));
        }
        for encoded in [&[7][..], &[0x18, 0xff][..]] {
            let mut decoder = Decoder::new(encoded, DecodeLimits::default())
                .unwrap_or_else(|error| panic!("unknown-purpose decoder failed: {error}"));
            assert!(matches!(
                decode_purpose(&mut decoder),
                Err(CanonicalCborError::UnknownRegistryValue { .. })
            ));
            let mut decoder = Decoder::new(encoded, DecodeLimits::default())
                .unwrap_or_else(|error| panic!("unknown-usage decoder failed: {error}"));
            assert!(matches!(
                decode_usage(&mut decoder),
                Err(CanonicalCborError::UnknownRegistryValue { .. })
            ));
        }
    }

    #[test]
    fn signature_statement_matches_rfc_golden_vector() {
        let statement = vector_statement();
        let encoded = encode_signature_statement(&statement);

        assert_eq!(hex::encode(&encoded), STATEMENT_HEX);
        assert_eq!(
            decode_signature_statement(&encoded, DecodeLimits::default()),
            Ok(statement)
        );
    }

    #[test]
    fn signature_envelope_round_trips_exact_bytes() {
        let signature = Signature::new(vector_statement(), SignatureBytes::new([7; 64]));
        let encoded = encode_signature(&signature);

        assert_eq!(
            decode_signature(&encoded, DecodeLimits::default()),
            Ok(signature)
        );
    }
}
