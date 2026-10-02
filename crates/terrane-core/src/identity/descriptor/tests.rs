//! Exercises canonical descriptor bytes and bounded profile-specific decoding.

#![allow(clippy::expect_used)]

use alloc::{vec, vec::Vec};

use super::{Descriptor, Error, IdentityError};
use crate::cbor;
use crate::identity::{
    DomainRegistration, IdentityHasher, IdentityKind, IdentityProfile, TERRANE_V1,
};

const GOLDENS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/rfcs/0024-terrane/spec/reference/golden-vectors.md"
));

fn wire(algorithm: &str, domain: &str, digest: &[u8], size: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    cbor::write_array(&mut bytes, 4);
    cbor::write_text(&mut bytes, algorithm);
    cbor::write_text(&mut bytes, domain);
    cbor::write_bytes(&mut bytes, digest);
    cbor::write_uint(&mut bytes, size);
    bytes
}

#[test]
fn published_descriptor_codec_preserves_bytes_and_model() -> Result<(), Error> {
    let source = GOLDENS
        .split_once("## Descriptor\n")
        .expect("descriptor reference exists")
        .1
        .split_once("```hex\n")
        .expect("descriptor bytes exist")
        .1
        .split_once("```")
        .expect("descriptor fence ends")
        .0;
    let hex: alloc::string::String = source
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect();
    let published: Vec<_> = (0..hex.len())
        .step_by(2)
        .map(|offset| u8::from_str_radix(&hex[offset..offset + 2], 16).expect("reference hex"))
        .collect();
    let plaintext = b"hello, terrane\n";
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, plaintext)?;
    let expected = Descriptor::from_identity(&TERRANE_V1, &identity, plaintext)?;

    assert_eq!(expected.encode(), published);
    assert_eq!(Descriptor::decode(&TERRANE_V1, &published)?, expected);
    assert_eq!(
        expected.verify_bytes(&TERRANE_V1, IdentityKind::Chunk, plaintext)?,
        identity
    );
    Ok(())
}

#[test]
fn descriptor_codec_roundtrips_every_domain_and_size_boundary() -> Result<(), Error> {
    for registration in TERRANE_V1.domains() {
        for size in [0, 1, 23, 24, 255, 256, u64::from(u32::MAX), u64::MAX] {
            let model =
                Descriptor::from_wire(&TERRANE_V1, "blake3", registration.name(), &[7; 32], size)?;
            let bytes = model.encode();

            assert_eq!(Descriptor::decode(&TERRANE_V1, &bytes)?, model);
            assert_eq!(model.encode(), bytes);
            for end in 0..bytes.len() {
                assert!(Descriptor::decode(&TERRANE_V1, &bytes[..end]).is_err());
            }
        }
    }
    Ok(())
}

#[test]
fn descriptor_codec_rejects_unknown_fields_and_noncanonical_shapes() {
    let valid = wire("blake3", "terrane-chunk-v1", &[1; 32], 0);
    assert_eq!(
        Descriptor::decode(
            &TERRANE_V1,
            &wire("sha256", "terrane-chunk-v1", &[1; 32], 0)
        ),
        Err(Error::Identity(IdentityError::UnknownAlgorithm))
    );
    assert_eq!(
        Descriptor::decode(&TERRANE_V1, &wire("blake3", "unknown", &[1; 32], 0)),
        Err(Error::Identity(IdentityError::UnknownDomain))
    );
    assert_eq!(
        Descriptor::decode(
            &TERRANE_V1,
            &wire("blake3", "terrane-chunk-v1", &[1; 31], 0)
        ),
        Err(Error::Identity(IdentityError::InvalidDigestLength))
    );

    let mut trailing = valid.clone();
    trailing.push(0);
    assert_eq!(
        Descriptor::decode(&TERRANE_V1, &trailing),
        Err(Error::Cbor(cbor::Error::TrailingData))
    );
    let mut nonminimal = vec![0x98, 4];
    nonminimal.extend_from_slice(&valid[1..]);
    assert_eq!(
        Descriptor::decode(&TERRANE_V1, &nonminimal),
        Err(Error::Cbor(cbor::Error::NonCanonical))
    );
    let mut nonminimal_size = valid[..valid.len() - 1].to_vec();
    nonminimal_size.extend_from_slice(&[0x18, 0]);
    assert_eq!(
        Descriptor::decode(&TERRANE_V1, &nonminimal_size),
        Err(Error::Cbor(cbor::Error::NonCanonical))
    );

    for invalid in [
        vec![0x83, 0, 0, 0],
        vec![0x85, 0, 0, 0, 0, 0],
        vec![0x9f, 0xff],
        vec![0xa0],
        vec![0x84, 0, 0, 0, 0],
    ] {
        assert!(Descriptor::decode(&TERRANE_V1, &invalid).is_err());
    }
}

#[test]
fn descriptor_codec_rejects_oversized_headers_before_owned_allocation() {
    let mut algorithm = vec![0x84];
    cbor::write_argument(&mut algorithm, 3, u64::MAX);
    let mut domain = vec![0x84];
    cbor::write_text(&mut domain, "blake3");
    cbor::write_argument(&mut domain, 3, u64::MAX);
    let mut digest = vec![0x84];
    cbor::write_text(&mut digest, "blake3");
    cbor::write_text(&mut digest, "terrane-chunk-v1");
    cbor::write_argument(&mut digest, 2, u64::MAX);

    for invalid in [algorithm, domain, digest] {
        assert_eq!(
            Descriptor::decode(&TERRANE_V1, &invalid),
            Err(Error::Cbor(cbor::Error::Limit))
        );
    }
}

struct ShortHasher;

impl IdentityHasher for ShortHasher {
    fn identifier(&self) -> &'static str {
        "descriptor-test-digest"
    }

    fn output_len(&self) -> usize {
        17
    }

    fn digest(&self, _domain: &str, _bytes: &[u8]) -> Vec<u8> {
        vec![9; 17]
    }
}

static SHORT_HASHER: ShortHasher = ShortHasher;
static TEST_DOMAINS: [DomainRegistration; 11] = [
    DomainRegistration::new(IdentityKind::Chunk, "descriptor-test-chunk"),
    DomainRegistration::new(IdentityKind::Manifest, "descriptor-test-manifest"),
    DomainRegistration::new(IdentityKind::Node, "descriptor-test-node"),
    DomainRegistration::new(IdentityKind::Commit, "descriptor-test-commit"),
    DomainRegistration::new(IdentityKind::Bundle, "descriptor-test-bundle"),
    DomainRegistration::new(IdentityKind::Pack, "descriptor-test-pack"),
    DomainRegistration::new(IdentityKind::Index, "descriptor-test-index"),
    DomainRegistration::new(IdentityKind::Filter, "descriptor-test-filter"),
    DomainRegistration::new(IdentityKind::Attribute, "descriptor-test-attribute"),
    DomainRegistration::new(IdentityKind::Policy, "descriptor-test-policy"),
    DomainRegistration::new(IdentityKind::Memo, "descriptor-test-memo"),
];

#[test]
fn descriptor_codec_bounds_follow_the_actual_configured_profile() -> Result<(), Error> {
    // This hasher is a format fixture, not a registered production algorithm.
    let profile = IdentityProfile::register("descriptor-tests", &SHORT_HASHER, &TEST_DOMAINS)?;
    let model = Descriptor::from_wire(
        &profile,
        SHORT_HASHER.identifier(),
        "descriptor-test-manifest",
        &[9; 17],
        u64::MAX,
    )?;
    let bytes = model.encode();

    assert_eq!(Descriptor::decode(&profile, &bytes)?, model);
    assert!(Descriptor::decode(&TERRANE_V1, &bytes).is_err());
    assert!(
        Descriptor::decode(&profile, &wire("blake3", "terrane-chunk-v1", &[9; 17], 0)).is_err()
    );
    assert_eq!(
        Descriptor::decode(
            &profile,
            &wire(
                SHORT_HASHER.identifier(),
                "descriptor-test-manifest",
                &[9; 16],
                0
            )
        ),
        Err(Error::Identity(IdentityError::InvalidDigestLength))
    );
    Ok(())
}
