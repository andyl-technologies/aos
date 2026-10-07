//! Independent framing and finite-account regressions for envelope streaming.

use std::error::Error;
use std::sync::Arc;

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};

struct Authority(FixtureResourceBudget);

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        self.0
            .usage()
            .map(|_| ())
            .map_err(DecodeAdmissionError::new)
    }

    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.0.reserve(0, bytes).map_err(DecodeAdmissionError::new)
    }
}

fn independent_bytes(envelope: &ContentEnvelope) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"CRUCOBJE");
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&(envelope.schema_name.len() as u16).to_be_bytes());
    bytes.extend_from_slice(envelope.schema_name.as_bytes());
    bytes.extend_from_slice(&envelope.schema_version.to_be_bytes());
    bytes.extend_from_slice(&(envelope.children.len() as u32).to_be_bytes());
    for child in &envelope.children {
        bytes.extend_from_slice(&(child.role.len() as u16).to_be_bytes());
        bytes.extend_from_slice(child.role.as_bytes());
        let id = format!(
            "{}.{}.",
            child.id.kind().as_str(),
            child.id.schema_version()
        );
        let mut id = id.into_bytes();
        for byte in child.id.digest() {
            id.extend_from_slice(format!("{byte:02x}").as_bytes());
        }
        bytes.extend_from_slice(&(id.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&id);
    }
    bytes.extend_from_slice(&(envelope.body.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&envelope.body);
    bytes
}

#[test]
fn streamed_envelope_identity_preserves_independent_framing_and_digest()
-> Result<(), Box<dyn Error>> {
    let children = [
        ContentChild::new(
            "a",
            ContentId::for_bytes(ObjectKind::CampaignSnapshot, 0, b"a"),
        )?,
        ContentChild::new(
            "max",
            ContentId::for_bytes(ObjectKind::CampaignSnapshot, u32::MAX, b"max"),
        )?,
        ContentChild::new(
            "z",
            ContentId::for_bytes(ObjectKind::RamTree, u32::MAX, b"z"),
        )?,
    ]
    .into_iter()
    .collect();
    let envelope = ContentEnvelope::new("example.record", u32::MAX, children, vec![0, 255, 1])?;
    let expected = independent_bytes(&envelope);

    assert_eq!(envelope.canonical_bytes(), expected);
    assert_eq!(
        envelope.content_id(ObjectKind::Finding),
        ContentId::for_bytes(ObjectKind::Finding, u32::MAX, &expected)
    );
    assert!(envelope.matches_canonical_bytes(&expected));
    let mut changed = expected.clone();
    changed[0] ^= 1;
    assert!(!envelope.matches_canonical_bytes(&changed));
    assert!(!envelope.matches_canonical_bytes(&expected[..expected.len() - 1]));
    assert!(!envelope.matches_canonical_bytes(&[expected.as_slice(), &[0]].concat()));
    Ok(())
}

#[test]
fn repeated_identity_and_canonical_checks_keep_original_credit_constant()
-> Result<(), Box<dyn Error>> {
    let children = [ContentChild::new(
        "payload",
        ContentId::for_bytes(ObjectKind::RamExtent, 1, b"child"),
    )?]
    .into_iter()
    .collect();
    let envelope = ContentEnvelope::new("example.record", 1, children, vec![7; 4096])?;
    let expected = independent_bytes(&envelope);
    let identity = ContentId::for_bytes(ObjectKind::Finding, 1, &expected);
    let authority = Arc::new(Authority(FixtureResourceBudget::new(0, 16 * 1024)));
    let budget = DecodeBudget::new(authority.clone(), 16 * 1024)?;
    let scope = budget.enter();
    let exported = envelope.canonical_bytes();
    budget.check()?;
    let retained = authority.0.usage()?;

    for _ in 0..1000 {
        assert_eq!(envelope.content_id(ObjectKind::Finding), identity);
        assert!(envelope.matches_canonical_bytes(&expected));
        budget.check()?;
        assert_eq!(authority.0.usage()?, retained);
    }

    assert_eq!(exported, expected);
    drop(exported);
    drop(scope);
    drop(budget);
    assert_eq!(authority.0.usage()?, (0, 0));
    Ok(())
}

#[test]
fn canonical_decode_retains_body_without_duplicate_authentication_images()
-> Result<(), Box<dyn Error>> {
    let envelope = ContentEnvelope::new("example.record", 1, BTreeSet::new(), vec![7; 4096])?;
    let bytes = independent_bytes(&envelope);
    let authority = Arc::new(Authority(FixtureResourceBudget::new(0, 8 * 1024)));
    let budget = DecodeBudget::new(authority.clone(), 8 * 1024)?;
    let scope = budget.enter();

    let decoded = ContentEnvelope::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded, envelope);
    budget.check()?;
    assert!(authority.0.usage()?.1 < 2 * envelope.body.len() as u64);

    drop(decoded);
    drop(scope);
    drop(budget);
    assert_eq!(authority.0.usage()?, (0, 0));
    Ok(())
}
