//! Exercises opened-expression compatibility and a genuine file-bucket probe.
//!
//! Report fixtures test validation logic; they establish no provider, native
//! custody or authorization claim. The native case uses an actually opened
//! bucket instead of choosing its capabilities from configuration.

#![cfg(feature = "std")]
#![allow(
    clippy::unwrap_used,
    reason = "Fixture and validation assertions intentionally panic."
)]

use terrane_format::refs::Locality;
use terrane_sdk::{
    config::expression::{
        StoreExpression,
        validation::{OpenedStore, PositionRequirements, ValidationError},
    },
    store::{Capabilities, CapabilityReport, Durability, RangeCapability, RefCapability},
};

struct Backend(Capabilities);

#[cfg(all(feature = "tokio", unix))]
struct NativeDirectory(std::path::PathBuf);

#[cfg(all(feature = "tokio", unix))]
impl Drop for NativeDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Backend {
    fn new(refs: RefCapability) -> Self {
        Self(Capabilities {
            refs,
            ranges: RangeCapability::Ranges,
            presign: false,
            locality: Locality::default(),
            durability: Durability::Local,
            sealed: false,
        })
    }
}

impl CapabilityReport for Backend {
    fn capabilities(&self) -> &Capabilities {
        &self.0
    }
}

fn node<'store>(
    backend: &'store Backend,
    children: Vec<OpenedStore<'store>>,
) -> OpenedStore<'store> {
    OpenedStore {
        backend,
        children,
        requirements: PositionRequirements::default(),
    }
}

fn check(expression: &str, opened: &OpenedStore<'_>) -> Result<(), ValidationError> {
    StoreExpression::parse(expression)
        .unwrap()
        .validate_opened(opened)
}

#[test]
fn leaf_authority_modes_follow_opened_reports() {
    for mode in [
        RefCapability::None,
        RefCapability::SingleWriter,
        RefCapability::Cas,
    ] {
        let backend = Backend::new(mode);
        for expression in [
            "bucket(file:///objects)",
            "disk(/cache)",
            "remote(https://warehouse)",
        ] {
            check(expression, &OpenedStore::leaf(&backend)).unwrap();
        }
    }
}

#[test]
fn routed_spines_accept_zero_or_one_authority_in_configured_order() {
    let cache = Backend::new(RefCapability::None);
    check(
        "routed[disk(/a),disk(/b)]",
        &node(
            &cache,
            vec![OpenedStore::leaf(&cache), OpenedStore::leaf(&cache)],
        ),
    )
    .unwrap();

    for mode in [RefCapability::SingleWriter, RefCapability::Cas] {
        let authority = Backend::new(mode);
        check(
            "routed[remote(https://warehouse),disk(/cache)]",
            &node(
                &authority,
                vec![OpenedStore::leaf(&authority), OpenedStore::leaf(&cache)],
            ),
        )
        .unwrap();
        check(
            "routed[disk(/cache),routed[remote(https://warehouse)]]",
            &node(
                &authority,
                vec![
                    OpenedStore::leaf(&cache),
                    node(&authority, vec![OpenedStore::leaf(&authority)]),
                ],
            ),
        )
        .unwrap();
    }
}

#[test]
fn multiple_authorities_refuse_direct_nested_and_cache_wrapped_routes() {
    let authority = Backend::new(RefCapability::Cas);
    let cache = Backend::new(RefCapability::None);
    let invalid_route = || {
        node(
            &authority,
            vec![OpenedStore::leaf(&authority), OpenedStore::leaf(&authority)],
        )
    };

    assert_eq!(
        check(
            "routed[bucket(file:///a),remote(https://b)]",
            &invalid_route()
        ),
        Err(ValidationError::MultipleAuthorities)
    );
    assert_eq!(
        check(
            "routed[disk(/cache),routed[bucket(file:///a),remote(https://b)]]",
            &node(&authority, vec![OpenedStore::leaf(&cache), invalid_route()])
        ),
        Err(ValidationError::MultipleAuthorities)
    );
    assert_eq!(
        check(
            "cache(eviction)(routed[bucket(file:///a),remote(https://b)])",
            &node(&cache, vec![invalid_route()])
        ),
        Err(ValidationError::MultipleAuthorities)
    );
}

#[test]
fn cache_erases_ref_authority_and_guard_preserves_its_exact_mode() {
    let cache = Backend::new(RefCapability::None);
    for mode in [
        RefCapability::None,
        RefCapability::SingleWriter,
        RefCapability::Cas,
    ] {
        let backend = Backend::new(mode);
        check(
            "cache(eviction)(bucket(file:///a))",
            &node(&cache, vec![OpenedStore::leaf(&backend)]),
        )
        .unwrap();
        check(
            "guard(warehouse)(bucket(file:///a))",
            &node(&backend, vec![OpenedStore::leaf(&backend)]),
        )
        .unwrap();
        if mode != RefCapability::None {
            assert_eq!(
                check(
                    "cache(eviction)(bucket(file:///a))",
                    &node(&backend, vec![OpenedStore::leaf(&backend)])
                ),
                Err(ValidationError::RefCapability)
            );
            assert_eq!(
                check(
                    "guard(warehouse)(bucket(file:///a))",
                    &node(&cache, vec![OpenedStore::leaf(&backend)])
                ),
                Err(ValidationError::RefCapability)
            );
        }
    }
}

#[test]
fn shared_directory_never_supplies_ref_authority() {
    for mode in [RefCapability::SingleWriter, RefCapability::Cas] {
        let backend = Backend::new(mode);
        assert_eq!(
            check("shared-dir(/objects)", &OpenedStore::leaf(&backend)),
            Err(ValidationError::SharedDirectoryAuthority)
        );
        let cache = Backend::new(RefCapability::None);
        assert_eq!(
            check(
                "cache(eviction)(shared-dir(/objects))",
                &node(&cache, vec![OpenedStore::leaf(&backend)])
            ),
            Err(ValidationError::SharedDirectoryAuthority)
        );
    }
    check(
        "shared-dir(/objects)",
        &OpenedStore::leaf(&Backend::new(RefCapability::None)),
    )
    .unwrap();
}

#[test]
fn concurrent_writer_guard_requires_a_cas_authority() {
    for mode in [
        RefCapability::None,
        RefCapability::SingleWriter,
        RefCapability::Cas,
    ] {
        let backend = Backend::new(mode);
        let mut opened = node(&backend, vec![OpenedStore::leaf(&backend)]);
        check("guard(warehouse)(bucket(file:///a))", &opened).unwrap();
        opened.requirements.multiple_writers = true;
        assert_eq!(
            check("guard(warehouse)(bucket(file:///a))", &opened),
            if mode == RefCapability::SingleWriter {
                Err(ValidationError::SingleWriter)
            } else {
                Ok(())
            }
        );
    }

    // A single-writer child used only as cache content supplies no ref writer.
    let single = Backend::new(RefCapability::SingleWriter);
    let cache = Backend::new(RefCapability::None);
    let mut opened = node(&cache, vec![node(&cache, vec![OpenedStore::leaf(&single)])]);
    opened.requirements.multiple_writers = true;
    check(
        "guard(warehouse)(cache(eviction)(bucket(file:///a)))",
        &opened,
    )
    .unwrap();
}

#[test]
fn required_presigning_checks_the_actual_configured_position() {
    let mut supported = Backend::new(RefCapability::Cas);
    supported.0.presign = true;
    let unavailable = Backend::new(RefCapability::Cas);

    for (backend, expected) in [
        (&supported, Ok(())),
        (&unavailable, Err(ValidationError::Presign)),
    ] {
        let mut opened = OpenedStore::leaf(backend);
        opened.requirements.presign = true;
        assert_eq!(check("bucket(s3://warehouse/objects)", &opened), expected);
        assert_eq!(
            check(
                "guard(warehouse)(bucket(s3://warehouse/objects))",
                &node(&supported, vec![opened])
            ),
            expected
        );
    }
}

#[test]
fn misplaced_writer_policy_and_incompatible_parent_reports_refuse() {
    let cache = Backend::new(RefCapability::None);
    let authority = Backend::new(RefCapability::Cas);
    let mut opened = OpenedStore::leaf(&authority);
    opened.requirements.multiple_writers = true;
    assert_eq!(
        check("bucket(file:///a)", &opened),
        Err(ValidationError::WriterPolicy)
    );
    assert_eq!(
        check(
            "routed[bucket(file:///a)]",
            &node(&cache, vec![OpenedStore::leaf(&authority)])
        ),
        Err(ValidationError::RefCapability)
    );
    assert_eq!(
        check(
            "routed[disk(/cache)]",
            &node(&authority, vec![OpenedStore::leaf(&cache)])
        ),
        Err(ValidationError::RefCapability)
    );
}

#[test]
fn shape_mismatches_and_unavailable_combinators_do_not_validate() {
    let backend = Backend::new(RefCapability::None);
    assert_eq!(
        check("guard(warehouse)(disk(/a))", &OpenedStore::leaf(&backend)),
        Err(ValidationError::Shape)
    );
    assert_eq!(
        check(
            "disk(/a)",
            &node(&backend, vec![OpenedStore::leaf(&backend)])
        ),
        Err(ValidationError::Shape)
    );
    for expression in [
        "replicated(1,ack=1)[disk(/a)]",
        "striped(1,parity=1)[disk(/a)]",
    ] {
        assert_eq!(
            check(
                expression,
                &node(&backend, vec![OpenedStore::leaf(&backend)])
            ),
            Err(ValidationError::UnsupportedCombinator)
        );
    }
}

#[cfg(all(feature = "tokio", unix))]
#[tokio::test]
async fn native_validation_uses_actual_file_bucket_and_routed_reports() {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };
    use terrane_format::chunking::ChunkProfile;
    use terrane_sdk::{
        bucket::{FileBucket, FileBucketConfig, FileBucketPublicationConfig},
        repository::MetadataValidator,
        store::{
            LocalFs, TokioClock, TokioLocalFs,
            routed::{Routed, RoutingPolicy},
        },
    };

    let entropy = TokioLocalFs.random_bytes(16).await.unwrap();
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let directory = std::env::temp_dir().join(format!("terrane-expression-{suffix}"));
    fs::create_dir(&directory).unwrap();
    let cleanup = NativeDirectory(directory.clone());
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

    let profile = ChunkProfile::cdc_1m([0; 32]);
    let root = directory.join("bucket");
    let bucket = FileBucket::open(
        FileBucketConfig {
            root: root.clone(),
            chunk_profile_name: "cdc-1m".into(),
            chunk_profile: profile.clone(),
            locality: Locality::default(),
            publication_control: Some(FileBucketPublicationConfig {
                operator_uid: fs::metadata(&directory).unwrap().uid(),
                control: Some(directory.join("control")),
            }),
        },
        TokioLocalFs,
        TokioClock,
        MetadataValidator::new(profile),
    )
    .await
    .unwrap();
    let expression = StoreExpression::parse(&format!("bucket(file://{})", root.display())).unwrap();

    assert_eq!(bucket.capabilities().refs, RefCapability::Cas);
    let mut opened = OpenedStore::leaf(&bucket);
    expression.validate_opened(&opened).unwrap();
    opened.requirements.presign = true;
    assert_eq!(
        expression.validate_opened(&opened),
        Err(ValidationError::Presign)
    );

    let policy = RoutingPolicy {
        read_budget: std::time::Duration::from_secs(5),
        child_budget: std::time::Duration::from_secs(5),
        failure_threshold: 1,
        probe_interval: std::time::Duration::from_secs(1),
        max_children: 2,
        max_membership: 4096,
    };
    let caches: Vec<FileBucket<TokioLocalFs, TokioClock, MetadataValidator>> = Vec::new();
    let routed = Routed::new(
        caches,
        bucket.clone(),
        0,
        Locality::default(),
        TokioClock,
        policy.clone(),
    )
    .unwrap();
    StoreExpression::parse(&format!("routed[bucket(file://{})]", root.display()))
        .unwrap()
        .validate_opened(&OpenedStore {
            backend: &routed,
            children: vec![OpenedStore::leaf(&bucket)],
            requirements: PositionRequirements::default(),
        })
        .unwrap();
    assert!(
        Routed::new(
            vec![bucket.clone()],
            bucket.clone(),
            1,
            Locality::default(),
            TokioClock,
            policy,
        )
        .is_err()
    );

    drop(routed);
    drop(bucket);
    drop(cleanup);
}
