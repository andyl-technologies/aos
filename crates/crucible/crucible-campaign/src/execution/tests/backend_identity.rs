//! Preserves legacy positional campaign bytes behind neutral Rust build names.

use super::*;
use crate::{ConfigurationId, ScenarioArtifactId, ScenarioDefId};
use crucible_store::content_envelope::{ContentChild, ContentEnvelope};
use std::collections::BTreeSet;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn lineage(build: &str) -> Result<CampaignLineage, CampaignCodecError> {
    CampaignLineage::new(
        ScenarioDefId::from_hash(CampaignHash::from_bytes([1; 32])),
        ScenarioArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Scenario,
            1,
            b"legacy-scenario",
        ))?,
        ConfigurationId::from_hash(CampaignHash::from_bytes([2; 32])),
        ConfigurationArtifactId::from_content_id(ContentId::for_bytes(
            ObjectKind::Configuration,
            1,
            b"legacy-genesis",
        ))?,
        "crucible-compatibility",
        build,
        BTreeMap::from([
            (String::from("control"), 3),
            (String::from("shared-memory"), 26),
        ]),
        5,
        5,
    )
}

// Spell the original positional grammar independently of the renamed fields.
fn legacy_profile_bytes(build: &str) -> Vec<u8> {
    let mut encoder = Encoder::new();
    String::from("crucible-compatibility").encode(&mut encoder);
    String::from(build).encode(&mut encoder);
    BTreeMap::from([
        (String::from("control"), 3_u32),
        (String::from("shared-memory"), 26),
    ])
    .encode(&mut encoder);
    5_u32.encode(&mut encoder);
    5_u32.encode(&mut encoder);
    encoder.finish()
}

#[test]
fn neutral_lineage_build_alias_preserves_legacy_bytes_and_content_identity() -> TestResult {
    let original = lineage("qemu-legacy-build")?;
    let mut encoder = Encoder::new();
    1_u32.encode(&mut encoder);
    original.scenario().encode(&mut encoder);
    original.scenario_content().encode(&mut encoder);
    original.genesis().encode(&mut encoder);
    original.genesis_content().encode(&mut encoder);
    let mut expected = encoder.finish();
    expected.extend(legacy_profile_bytes("qemu-legacy-build"));

    assert_eq!(original.canonical_bytes(), expected);
    let decoded = CampaignLineage::from_canonical_bytes(&expected)?;
    assert_eq!(decoded, original);
    assert_eq!(decoded.backend_build_identity(), "qemu-legacy-build");
    assert_eq!(decoded.qemu_build(), decoded.backend_build_identity());
    assert!(std::ptr::eq(
        decoded.qemu_build(),
        decoded.backend_build_identity()
    ));

    let legacy_envelope = ContentEnvelope::new(
        "crucible.campaign.lineage",
        1,
        BTreeSet::from([
            ContentChild::new("scenario", original.scenario_content().content_id())?,
            ContentChild::new("genesis", original.genesis_content().content_id())?,
        ]),
        expected,
    )?;
    assert_eq!(
        original.id()?.content_id(),
        legacy_envelope.content_id(ObjectKind::CampaignFact)
    );
    let mut trailing = original.canonical_bytes();
    trailing.push(0);
    assert!(CampaignLineage::from_canonical_bytes(&trailing).is_err());
    Ok(())
}

#[test]
fn neutral_executor_build_alias_preserves_legacy_profile_bytes_and_admission() -> TestResult {
    for build in [
        "qemu-legacy-build",
        "gem5-build",
        "native-kvm-provider-build",
    ] {
        let original = lineage(build)?;
        let profile = ExecutorCompatibilityProfile::from_lineage(&original);
        let expected = legacy_profile_bytes(build);

        assert_eq!(codec::encode(&profile), expected);
        let decoded: ExecutorCompatibilityProfile = codec::decode(&expected)?;
        assert_eq!(decoded, profile);
        assert_eq!(decoded.backend_build_identity(), build);
        assert_eq!(decoded.qemu_build(), decoded.backend_build_identity());
        assert!(std::ptr::eq(
            decoded.qemu_build(),
            decoded.backend_build_identity()
        ));
        assert!(decoded.admits(&original));
        assert!(!decoded.admits(&lineage("different-build")?));
    }
    Ok(())
}
