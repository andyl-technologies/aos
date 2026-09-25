//! Source-backed coverage for durable campaign and operator formats.

use std::collections::{BTreeMap, BTreeSet};

const SOURCES: &[(&str, &str)] = &[
    (
        "crates/crucible/src/model/store_artifacts.rs",
        include_str!("../../../crucible/src/model/store_artifacts.rs"),
    ),
    (
        "crates/crucible/src/trigger/evidence.rs",
        include_str!("../../../crucible/src/trigger/evidence.rs"),
    ),
    (
        "tests/crucible/_e2e-determinism-native-runner.sh",
        include_str!("../../../../tests/crucible/_e2e-determinism-native-runner.sh"),
    ),
    (
        "tests/crucible/_phase9-campaign-release-acceptance.sh",
        include_str!("../../../../tests/crucible/_phase9-campaign-release-acceptance.sh"),
    ),
    (
        "tests/crucible/_campaign-manual-evidence-spec.nix",
        include_str!("../../../../tests/crucible/_campaign-manual-evidence-spec.nix"),
    ),
    (
        "tests/crucible/e2e-determinism-evidence-contract.toml",
        include_str!("../../../../tests/crucible/e2e-determinism-evidence-contract.toml"),
    ),
    (
        "tests/crucible/campaign-release-acceptance-contract.toml",
        include_str!("../../../../tests/crucible/campaign-release-acceptance-contract.toml"),
    ),
    (
        "tests/crucible/campaign-gate-matrix-inventory.toml",
        include_str!("../../../../tests/crucible/campaign-gate-matrix-inventory.toml"),
    ),
    (
        "docs/rfcs/0020-crucible-campaigns/fixtures/campaign-operator-flight-contract.toml",
        include_str!(
            "../../../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-operator-flight-contract.toml"
        ),
    ),
    (
        "docs/rfcs/0020-crucible-campaigns/fixtures/campaign-operator-acceptance-contract.toml",
        include_str!(
            "../../../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-operator-acceptance-contract.toml"
        ),
    ),
    (
        "docs/rfcs/0020-crucible-campaigns/fixtures/campaign-destructive-recovery-contract.toml",
        include_str!(
            "../../../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-destructive-recovery-contract.toml"
        ),
    ),
    (
        "docs/rfcs/0020-crucible-campaigns/fixtures/campaign-dogfood-contract.toml",
        include_str!(
            "../../../../docs/rfcs/0020-crucible-campaigns/fixtures/campaign-dogfood-contract.toml"
        ),
    ),
];

#[test]
fn reviewed_durable_source_tags_have_matching_registry_versions() {
    let registry = super::SCHEMA_REGISTRY
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.split('\t');
            let name = fields.next().expect("registry name");
            let version = fields
                .next()
                .expect("registry version")
                .parse::<u32>()
                .expect("numeric registry version");
            (name, version)
        })
        .collect::<BTreeMap<_, _>>();

    let mut covered = BTreeSet::new();
    for (path, source) in SOURCES {
        let tags = versioned_tags(source);
        assert!(!tags.is_empty(), "{path} has no versioned source tags");

        for (name, version) in tags {
            // This token domains a ContentHash; it is not encoded or decoded
            // as an independently versioned object.
            if name == "crucible.reproduction.event-log-artifact" {
                assert_eq!(version, 1, "{path} hash domain changed");
                continue;
            }

            assert_eq!(
                registry.get(name),
                Some(&version),
                "{path} source format {name}.v{version} lacks a matching registry row"
            );
            covered.insert(name);
        }
    }

    for name in [
        "crucible.dag-store.scenario-def",
        "crucible.dag-store.checkpoint-node",
        "crucible.dag-store.schedule-delta",
        "crucible.dag-store.cow-delta-ref",
        "crucible.external-formal-trace",
        "crucible.e2e.native-host-evidence",
        "aos.crucible.campaign-release-acceptance",
    ] {
        assert!(
            covered.contains(name),
            "reviewed source format {name} disappeared"
        );
    }

    let evaluator = include_str!("../../../crucible/src/model/fault_signal/evaluator.rs");
    assert!(evaluator.contains("EVALUATOR_CHECKPOINT_MAGIC: &[u8; 8] = b\"CREVAL01\""));
    let evaluator_version = include_str!("../../../crucible/src/model/fault_signal/mod.rs");
    assert!(evaluator_version.contains("SIGNAL_EVALUATOR_VERSION: u16 = 1"));
    assert_eq!(
        registry.get("crucible.execution.signal-evaluator-checkpoint"),
        Some(&1)
    );
}

fn versioned_tags(source: &str) -> BTreeSet<(&str, u32)> {
    source
        .split(|byte: char| !byte.is_ascii_alphanumeric() && !matches!(byte, '.' | '-' | '_'))
        .filter(|token| token.starts_with("crucible.") || token.starts_with("aos.crucible."))
        .filter_map(|token| {
            let (name, version) = token.rsplit_once(".v")?;
            let version = version.parse::<u32>().ok()?;
            Some((name, version))
        })
        .collect()
}
