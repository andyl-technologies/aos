//! Static derivation output revalidation cache coverage.

use super::*;

#[test]
fn static_derivation_output_path_revalidating_hit_misses_changed_dirty_node() {
    let mut cache = EvalCache::new();
    let prior = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let changed = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[(\"env\",\"new\")])";
    let output_paths = CachedDerivationOutputPaths::new(
        [8; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );
    let observed = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            prior,
            output_paths,
        )
        .expect("static derivation output paths observe");
    cache
        .graph
        .mark_dirty(observed.node())
        .expect("node dirties");

    let hit = cache
        .lookup_static_derivation_output_paths_hit_revalidating(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            changed,
        )
        .expect("revalidating changed static output path lookup succeeds");

    assert!(hit.is_none());
    assert_eq!(
        cache
            .graph()
            .node(observed.node())
            .expect("node exists")
            .freshness(),
        NodeFreshness::Dirty
    );
}

#[test]
fn static_derivation_output_path_observation_reconsiders_full_payload() {
    let mut cache = EvalCache::new();
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let first = CachedDerivationOutputPaths::new(
        [1; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );
    let changed_path = CachedDerivationOutputPaths::new(
        [1; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x".to_vec(),
        )],
    );
    let changed_hash = CachedDerivationOutputPaths::new(
        [2; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-x".to_vec(),
        )],
    );

    let first_reconsideration = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            pre_output_aterm,
            first,
        )
        .expect("first static output observation succeeds");
    let changed_path_reconsideration = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            pre_output_aterm,
            changed_path,
        )
        .expect("changed-path static output observation succeeds");
    let changed_hash_reconsideration = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            pre_output_aterm,
            changed_hash.clone(),
        )
        .expect("changed-hash static output observation succeeds");
    let same_reconsideration = cache
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            pre_output_aterm,
            changed_hash.clone(),
        )
        .expect("same static output observation succeeds");
    let lookup = cache
        .lookup_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            pre_output_aterm,
        )
        .expect("static output lookup succeeds");

    assert_eq!(first_reconsideration.decision(), CutoffDecision::Propagate);
    assert_eq!(
        changed_path_reconsideration.decision(),
        CutoffDecision::Propagate
    );
    assert_eq!(
        changed_hash_reconsideration.decision(),
        CutoffDecision::Propagate
    );
    assert_eq!(same_reconsideration.decision(), CutoffDecision::CutOff);
    assert_eq!(lookup, Some(changed_hash));
}
