//! Eval-cache runtime delegation coverage for derivation payloads.

use super::*;

#[test]
fn disabled_eval_cache_runtime_skips_derivation_aterm_path_lookup_and_observation() {
    let mut runtime = EvalCacheRuntime::disabled();
    let aterm = b"Derive([],[],[],\":\",\":\",[],[])";

    let observation = runtime
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [value_hash(b"free-var")],
            aterm,
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv",
        )
        .expect("disabled observation succeeds");
    let lookup = runtime
        .lookup_derivation_aterm_path(identity(b"derivation", 7), [value_hash(b"free-var")], aterm)
        .expect("disabled lookup succeeds");

    assert!(observation.is_none());
    assert!(lookup.is_none());
    assert!(runtime.cache().is_none());
}

#[test]
fn disabled_eval_cache_runtime_skips_static_derivation_output_path_lookup_and_observation() {
    let mut runtime = EvalCacheRuntime::disabled();
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let output_paths = CachedDerivationOutputPaths::new(
        [9; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );

    let observation = runtime
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            pre_output_aterm,
            output_paths,
        )
        .expect("disabled static output observation succeeds");
    let lookup = runtime
        .lookup_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            pre_output_aterm,
        )
        .expect("disabled static output lookup succeeds");

    assert!(observation.is_none());
    assert!(lookup.is_none());
    assert!(runtime.cache().is_none());
}

#[test]
fn enabled_eval_cache_runtime_delegates_derivation_aterm_path_roundtrip() {
    let mut runtime = EvalCacheRuntime::enabled();
    let aterm = b"Derive([],[],[],\":\",\":\",[],[])";
    let drv_path = b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x.drv";

    let observation = runtime
        .observe_derivation_aterm_expression_path(
            identity(b"derivation", 7),
            [value_hash(b"free-var")],
            aterm,
            drv_path,
        )
        .expect("enabled observation succeeds")
        .expect("enabled runtime observes derivation ATerm path");
    let lookup = runtime
        .lookup_derivation_aterm_path(identity(b"derivation", 7), [value_hash(b"free-var")], aterm)
        .expect("enabled lookup succeeds");

    assert_eq!(observation.decision(), CutoffDecision::Propagate);
    assert_eq!(lookup.as_deref(), Some(drv_path.as_slice()));
}

#[test]
fn enabled_eval_cache_runtime_delegates_static_derivation_output_path_roundtrip() {
    let mut runtime = EvalCacheRuntime::enabled();
    let pre_output_aterm = b"Derive([(\"out\",\"\",\"\",\"\")],[],[],\":\",\":\",[],[])";
    let output_paths = CachedDerivationOutputPaths::new(
        [10; 32],
        vec![CachedDerivationOutputPath::new(
            b"out".to_vec(),
            b"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-x".to_vec(),
        )],
    );

    let observation = runtime
        .observe_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            pre_output_aterm,
            output_paths.clone(),
        )
        .expect("enabled static output observation succeeds")
        .expect("enabled runtime observes static output paths");
    let lookup = runtime
        .lookup_static_derivation_output_paths(
            identity(b"derivation-outputs", 7),
            [value_hash(b"free-var")],
            pre_output_aterm,
        )
        .expect("enabled static output lookup succeeds");

    assert_eq!(observation.decision(), CutoffDecision::Propagate);
    assert_eq!(lookup, Some(output_paths));
}

#[test]
fn disabled_eval_cache_runtime_skips_derivation_aterm_observation() {
    let mut runtime = EvalCacheRuntime::disabled();

    let observation = runtime
        .observe_derivation_aterm_expression(
            identity(b"derivation", 7),
            [value_hash(b"free-var")],
            b"Derive([],[],[],\":\",\":\",[],[])",
        )
        .expect("disabled observation succeeds");

    assert!(observation.is_none());
    assert!(runtime.cache().is_none());
}

#[test]
fn enabled_eval_cache_runtime_delegates_derivation_aterm_observation() {
    let mut runtime = EvalCacheRuntime::enabled();
    let aterm = b"Derive([],[],[],\":\",\":\",[],[])";

    let first = runtime
        .observe_derivation_aterm_expression(
            identity(b"derivation", 7),
            [value_hash(b"free-var")],
            aterm,
        )
        .expect("enabled observation succeeds")
        .expect("enabled runtime observes derivation ATerm");
    let same = runtime
        .observe_derivation_aterm_expression(
            identity(b"derivation", 7),
            [value_hash(b"free-var")],
            aterm,
        )
        .expect("enabled observation succeeds")
        .expect("enabled runtime observes derivation ATerm");

    assert_eq!(first.decision(), CutoffDecision::Propagate);
    assert_eq!(same.decision(), CutoffDecision::CutOff);
    assert_eq!(runtime.cache().expect("cache is enabled").len(), 1);
}
