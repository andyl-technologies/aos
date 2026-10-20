//! Constructs every field of populated Guard snapshots and nested configuration.
//!
//! ```text
//! guard = {0: 1, 1: registration, 2: issuer_rows, 3: disclosure_rows,
//!          4: configuration, 5: registry_inputs}
//! ```

use super::{
    original,
    wire::{self, Value, a, b, m, s, u},
};
use terrane_format::{gc::publication::evidence::*, refs::Locality};

const BEHAVIOR: &str = "acl baseline chunk classify compaction_threshold compression dedup degraded domain durability encryption gap_merge_bytes hashes home index merge on-release passthrough prefetch quota reassembly redundancy reflog_retain replicate retain span_max_bytes store strict-attrs trust warm whole_pack_threshold wipe writers";

/// Constructs all six public seeded-profile inputs as inert data.
pub(super) fn profile() -> SeededChunkProfile {
    SeededChunkProfile {
        minimum: 262144,
        target: 1048576,
        maximum: 4194304,
        window: 48,
        normalization: 2,
        seed: [9; 32],
    }
}

/// Constructs primitive profile inputs independently.
pub(super) fn profile_wire() -> Value {
    a(vec![
        u(262144),
        u(1048576),
        u(4194304),
        u(48),
        u(2),
        b(9, 32),
    ])
}

/// Constructs every public configuration field and absent/empty/present labels.
pub(super) fn config(mode: usize) -> TrustedGuardConfig {
    let home = match mode {
        0 => Locality::default(),
        1 => Locality {
            region: Some(String::new()),
            zone: None,
            host: Some(String::new()),
        },
        _ => Locality {
            region: Some("region".into()),
            zone: Some("zone".into()),
            host: Some("host".into()),
        },
    };
    TrustedGuardConfig {
        store_name: "store".into(),
        private_domain_hint: if mode == 1 {
            String::new()
        } else {
            "hint".into()
        },
        home,
        initial_acl: original::acl(),
        minimum_chunk_size: 262144,
        storage_domain: "public".into(),
        chunk_profile_name: "cdc-1m".into(),
        chunk_profile: profile(),
        policy_authority: match mode {
            0 => None,
            1 => Some(String::new()),
            _ => Some("policy".into()),
        },
    }
}

/// Constructs every primitive configuration slot independently.
pub(super) fn config_wire(mode: usize) -> Value {
    let home = match mode {
        0 => m(vec![]),
        1 => m(vec![(1, s("")), (3, s(""))]),
        _ => m(vec![(1, s("region")), (2, s("zone")), (3, s("host"))]),
    };
    m(vec![
        (0, u(1)),
        (1, s("store")),
        (2, s(if mode == 1 { "" } else { "hint" })),
        (3, home),
        (4, original::acl_wire()),
        (5, u(262144)),
        (6, s("public")),
        (7, s("cdc-1m")),
        (8, profile_wire()),
        (
            9,
            match mode {
                0 => Value::Null,
                1 => s(""),
                _ => s("policy"),
            },
        ),
    ])
}

/// Constructs complete registry revisions, behavioral set and inert later names.
pub(super) fn registry() -> ConfiguredRegistryInputs {
    ConfiguredRegistryInputs {
        property_revision: 1,
        behavioral_properties: BEHAVIOR.split_whitespace().map(String::from).collect(),
        attribute_revision: 1,
        selector_revision: 1,
        tree_revision: 1,
        chunk_revision: 1,
        identity_profile: "terrane-v1".into(),
        later_properties: vec!["future-a".into(), "future-z".into()],
    }
}

/// Constructs primitive registry fields separately from the public structure.
pub(super) fn registry_wire() -> Value {
    m(vec![
        (0, u(1)),
        (1, u(1)),
        (2, a(BEHAVIOR.split_whitespace().map(s).collect())),
        (3, u(1)),
        (4, u(1)),
        (5, u(1)),
        (6, u(1)),
        (7, s("terrane-v1")),
        (8, a(vec![s("future-a"), s("future-z")])),
    ])
}

/// Constructs every nested Guard field without a trusted holder or factory.
pub(super) fn model(kind: &str, mode: usize) -> GuardSnapshot {
    GuardSnapshot {
        registration: original::physical(kind),
        issuers: original::issuers(),
        disclosures: original::disclosures(),
        configuration: config(mode),
        registries: registry(),
    }
}

/// Constructs complete primitive Guard fields independently.
pub(super) fn primitive(kind: &str, mode: usize) -> Value {
    m(vec![
        (0, u(1)),
        (1, original::physical_wire(kind)),
        (2, original::issuers_wire()),
        (3, original::disclosures_wire()),
        (4, config_wire(mode)),
        (5, registry_wire()),
    ])
}

/// Checks populated local/S3/GCS Guard snapshots and complete nested records.
///
/// # Panics
/// Panics if any field, optional state or encoded byte differs.
pub(super) fn check_models() {
    for (mode, kind) in ["local", "s3", "gcs"].into_iter().enumerate() {
        let config = config(mode);
        wire::check(
            &format!("control-config-{mode}"),
            config.clone(),
            config_wire(mode),
            config.encode(),
            TrustedGuardConfig::decode,
        );
        let guard = model(kind, mode);
        wire::check(
            &format!("control-guard-{kind}"),
            guard.clone(),
            primitive(kind, mode),
            guard.encode(),
            GuardSnapshot::decode,
        );
    }
    let model = registry();
    wire::check(
        "control-registry",
        model.clone(),
        registry_wire(),
        model.encode(),
        ConfiguredRegistryInputs::decode,
    );
    let model = profile();
    wire::check(
        "control-profile",
        model.clone(),
        profile_wire(),
        model.encode(),
        SeededChunkProfile::decode,
    );
}

/// Checks independently recorded attribute revisions without activating a carrier.
///
/// The complete property-revision-one fields remain unchanged for both registered
/// attribute revisions. Neither record represents the property-three context
/// required for active structural carrier interpretation.
///
/// # Panics
/// Panics for any complete field/reference mismatch, rejected registered revision
/// or accepted independently encoded unregistered revision.
pub(super) fn check_attribute_revisions() {
    for (name, revision) in [
        ("control-registry", 1),
        ("control-registry-attribute-two", 2),
    ] {
        let mut model = registry();
        model.attribute_revision = revision;

        let mut primitive = registry_wire();
        primitive.replace(3, u(revision));

        wire::check(
            name,
            model.clone(),
            primitive,
            model.encode(),
            ConfiguredRegistryInputs::decode,
        );
    }

    let mut unknown = registry_wire();
    unknown.replace(3, u(3));
    wire::reject(
        "registry-revision",
        unknown.encode(),
        ConfiguredRegistryInputs::decode,
    );
}
