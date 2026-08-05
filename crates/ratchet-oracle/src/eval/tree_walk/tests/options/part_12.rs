//! Split-out tests (part_12). See parent module.

use super::*;

#[test]
fn version_gated_builtin_names_match_pinned_flakes_surface() {
    for name in VERSION_GATED_BUILTIN_NAMES {
        let fixture_contains = PINNED_NIX_2_24_12_FLAKES_BUILTIN_NAMES.contains(name);
        let registry_contains = BUILTINS.lookup(name.as_bytes()).is_some();
        assert_eq!(
            registry_contains, fixture_contains,
            "{name} local registration should match the pinned flake-enabled fixture",
        );

        let source = format!("builtins.hasAttr {} builtins", nix_string_literal(name));
        assert_eq!(
            eval(&source).as_bool(),
            Ok(fixture_contains),
            "{name} runtime presence should match the pinned flake-enabled fixture",
        );
    }
}

#[test]
fn custom_effectful_unary_builtin_declarations_match_runtime_impls() {
    for name in [
        b"pathExists".as_slice(),
        b"readDir".as_slice(),
        b"readFile".as_slice(),
        b"readFileType".as_slice(),
        b"storePath".as_slice(),
    ] {
        assert_eq!(
            direct_builtin(name),
            Some(BuiltinDirect::StrictUnary {
                effect: BuiltinEffect::Effectful
            })
        );
        let builtin = lookup_builtin(name).expect("builtin is registered");

        assert_eq!(builtin.first_class_arity(), Some(1));
        assert!(!builtin.docs().summary().is_empty());
    }
}

#[test]
fn tree_walk_options_normalize_store_dir() {
    let defaulted = TreeWalkOptions::with_store_dir(Vec::new()).expect("empty store dir defaults");
    assert_eq!(defaulted.store_dir(), b"/nix/store");

    let normalized = TreeWalkOptions::with_store_dir(b"//tmp//aos-store/./".to_vec())
        .expect("absolute store dir normalizes");
    assert_eq!(normalized.store_dir(), b"/tmp/aos-store");

    let parent_normalized = TreeWalkOptions::with_store_dir(b"/tmp/../aos-store".to_vec())
        .expect("parent components reduce");
    assert_eq!(parent_normalized.store_dir(), b"/aos-store");

    let nested_parent_normalized =
        TreeWalkOptions::with_store_dir(b"/tmp/aos-store/../other".to_vec())
            .expect("nested parent components reduce");
    assert_eq!(nested_parent_normalized.store_dir(), b"/tmp/other");

    let mut options = TreeWalkOptions::new();
    options
        .set_store_dir(b"/var//aos/store//".to_vec())
        .expect("absolute store dir sets");
    assert_eq!(options.store_dir(), b"/var/aos/store");

    assert_eq!(
        TreeWalkOptions::with_store_dir(b"relative/store".to_vec())
            .expect_err("relative store dir is rejected"),
        TreeWalkOptionsError::RelativeStoreDir
    );

    let base = TreeWalkOptions::with_search_path_base(b"//tmp//aos-search/./".to_vec())
        .expect("absolute search-path base normalizes");
    assert_eq!(base.search_path_base(), b"/tmp/aos-search");

    let mut options = TreeWalkOptions::new();
    options
        .set_search_path_base(b"/var//aos/search//".to_vec())
        .expect("absolute search-path base sets");
    assert_eq!(options.search_path_base(), b"/var/aos/search");

    assert_eq!(
        TreeWalkOptions::with_search_path_base(b"relative/search".to_vec())
            .expect_err("relative search-path base is rejected"),
        TreeWalkOptionsError::RelativeSearchPathBase
    );

    let path_base = TreeWalkOptions::with_path_literal_base(b"//tmp//aos-source/./".to_vec())
        .expect("absolute path-literal base normalizes");
    assert_eq!(
        path_base.path_literal_base(),
        Some(b"/tmp/aos-source".as_slice())
    );

    let mut options = TreeWalkOptions::new();
    assert_eq!(options.path_literal_base(), None);
    options
        .set_path_literal_base(b"/var//aos/source//".to_vec())
        .expect("absolute path-literal base sets");
    assert_eq!(
        options.path_literal_base(),
        Some(b"/var/aos/source".as_slice())
    );
    options.clear_path_literal_base();
    assert_eq!(options.path_literal_base(), None);

    assert_eq!(
        TreeWalkOptions::with_path_literal_base(b"relative/source".to_vec())
            .expect_err("relative path-literal base is rejected"),
        TreeWalkOptionsError::RelativePathLiteralBase
    );

    let home_dir = TreeWalkOptions::with_home_dir(b"//tmp//aos-home/./".to_vec())
        .expect("absolute home directory normalizes");
    assert_eq!(home_dir.home_dir(), Some(b"/tmp/aos-home".as_slice()));

    let mut options = TreeWalkOptions::new();
    assert_eq!(options.home_dir(), None);
    options
        .set_home_dir(b"/var//aos/home//".to_vec())
        .expect("absolute home directory sets");
    assert_eq!(options.home_dir(), Some(b"/var/aos/home".as_slice()));
    options.clear_home_dir();
    assert_eq!(options.home_dir(), None);

    assert_eq!(
        TreeWalkOptions::with_home_dir(b"relative/home".to_vec())
            .expect_err("relative home directory is rejected"),
        TreeWalkOptionsError::RelativeHomeDir
    );
    assert_eq!(
        TreeWalkOptions::with_home_dir(Vec::new()).expect_err("empty home directory is rejected"),
        TreeWalkOptionsError::RelativeHomeDir
    );
}

#[test]
fn to_file_uses_configured_store_dir() {
    let options = TreeWalkOptions::with_store_dir(b"/custom/store".to_vec())
        .expect("custom store dir configures");
    let path = eval_string_bytes_with_options(r#"builtins.toFile "x" "abc""#, options);

    assert!(path.starts_with(b"/custom/store/"), "{path:?}");
    assert!(path.ends_with(b"-x"), "{path:?}");
}

#[test]
fn tree_walk_options_configure_current_system() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.current_system(), None);

    let configured = TreeWalkOptions::with_current_system(b"aarch64-linux".to_vec())
        .expect("currentSystem configures");
    assert_eq!(
        configured.current_system(),
        Some(b"aarch64-linux".as_slice())
    );

    let mut options = TreeWalkOptions::new();
    options
        .set_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem sets");
    assert_eq!(options.current_system(), Some(b"x86_64-linux".as_slice()));
    options.clear_current_system();
    assert_eq!(options.current_system(), None);

    assert_eq!(
        TreeWalkOptions::with_current_system(Vec::new())
            .expect_err("empty currentSystem is rejected"),
        TreeWalkOptionsError::EmptyCurrentSystem
    );
}

#[test]
fn tree_walk_options_configure_current_time() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.current_time(), None);

    let configured =
        TreeWalkOptions::with_current_time(1_700_000_000).expect("currentTime configures");
    assert_eq!(configured.current_time(), Some(1_700_000_000));

    let mut options = TreeWalkOptions::new();
    options
        .set_current_time(1_700_000_001)
        .expect("currentTime sets");
    assert_eq!(options.current_time(), Some(1_700_000_001));
    options.clear_current_time();
    assert_eq!(options.current_time(), None);

    assert_eq!(
        TreeWalkOptions::with_current_time(-1).expect_err("negative currentTime is rejected"),
        TreeWalkOptionsError::NegativeCurrentTime
    );
}

#[test]
fn tree_walk_options_configure_trace_verbose() {
    let defaulted = TreeWalkOptions::new();
    assert!(!defaulted.trace_verbose());

    let configured = TreeWalkOptions::with_trace_verbose(true);
    assert!(configured.trace_verbose());

    let mut options = TreeWalkOptions::new();
    options.set_trace_verbose(true);
    assert!(options.trace_verbose());
    options.set_trace_verbose(false);
    assert!(!options.trace_verbose());
}

#[test]
fn tree_walk_options_configure_abort_on_warn() {
    let defaulted = TreeWalkOptions::new();
    assert!(!defaulted.abort_on_warn());

    let configured = TreeWalkOptions::with_abort_on_warn(true);
    assert!(configured.abort_on_warn());

    let mut options = TreeWalkOptions::new();
    options.set_abort_on_warn(true);
    assert!(options.abort_on_warn());
    options.set_abort_on_warn(false);
    assert!(!options.abort_on_warn());
}

#[test]
fn tree_walk_options_configure_max_call_depth() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.max_call_depth(), DEFAULT_MAX_CALL_DEPTH);

    let configured = TreeWalkOptions::with_max_call_depth(10);
    assert_eq!(configured.max_call_depth(), 10);

    let mut options = TreeWalkOptions::new();
    options.set_max_call_depth(0);
    assert_eq!(options.max_call_depth(), 0);
}

#[test]
fn tree_walk_options_configure_filesystem_access_policy() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.eval_mode(), EvalMode::Impure);
    assert!(defaulted.allowed_paths().is_empty());
    assert!(defaulted.allowed_uris().is_empty());

    let restricted = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    assert_eq!(restricted.eval_mode(), EvalMode::Restricted);

    let mut options = TreeWalkOptions::new();
    options.set_eval_mode(EvalMode::Pure);
    assert_eq!(options.eval_mode(), EvalMode::Pure);
    options
        .add_allowed_path(b"/tmp//allowed/./".to_vec())
        .expect("absolute allowed path configures");
    assert_eq!(options.allowed_paths(), &[b"/tmp/allowed".to_vec()]);
    options
        .set_allowed_paths(vec![b"/var/../tmp/other".to_vec()])
        .expect("allowed paths replace");
    assert_eq!(options.allowed_paths(), &[b"/tmp/other".to_vec()]);
    options.clear_allowed_paths();
    assert!(options.allowed_paths().is_empty());

    options
        .add_allowed_uri(b"https://cache.example/".to_vec())
        .expect("allowed URI prefix configures");
    assert_eq!(
        options.allowed_uris(),
        &[b"https://cache.example/".to_vec()]
    );
    assert!(options.uri_is_allowed(b"https://cache.example/source.tar.gz"));
    assert!(!options.uri_is_allowed(b"https://other.example/source.tar.gz"));
    options
        .set_allowed_uris(vec![b"github:".to_vec()])
        .expect("allowed URI prefixes replace");
    assert_eq!(options.allowed_uris(), &[b"github:".to_vec()]);
    options.clear_allowed_uris();
    assert!(options.allowed_uris().is_empty());

    assert_eq!(
        options
            .add_allowed_path(b"relative/path".to_vec())
            .expect_err("relative allowed paths are rejected"),
        TreeWalkOptionsError::RelativeAllowedPath
    );
    assert_eq!(
        options
            .add_allowed_path(Vec::new())
            .expect_err("empty allowed paths are rejected"),
        TreeWalkOptionsError::RelativeAllowedPath
    );
    assert_eq!(
        options
            .add_allowed_uri(Vec::new())
            .expect_err("empty allowed URI prefixes are rejected"),
        TreeWalkOptionsError::EmptyAllowedUri
    );
}

#[test]
fn tree_walk_options_configure_environment_variables() {
    let defaulted = TreeWalkOptions::new();
    assert_eq!(defaulted.env_var(b"HOME"), None);

    let configured = TreeWalkOptions::with_env_var(b"HOME".to_vec(), b"/homeless".to_vec());
    assert_eq!(configured.env_var(b"HOME"), Some(b"/homeless".as_slice()));
    assert_eq!(configured.env_var(b"USER"), None);

    let mut options = TreeWalkOptions::new();
    options.set_env_var(b"USER".to_vec(), b"builder".to_vec());
    assert_eq!(options.env_var(b"USER"), Some(b"builder".as_slice()));
    options.set_env_var(b"USER".to_vec(), b"overridden".to_vec());
    assert_eq!(options.env_var(b"USER"), Some(b"overridden".as_slice()));
    options.clear_env_var(b"USER");
    assert_eq!(options.env_var(b"USER"), None);
}

#[test]
fn tree_walk_options_configure_ambient_search_path_rejection() {
    let mut options = TreeWalkOptions::new();
    assert!(!options.reject_ambient_search_path());

    options.set_reject_ambient_search_path(true);
    assert!(options.reject_ambient_search_path());

    options.set_reject_ambient_search_path(false);
    assert!(!options.reject_ambient_search_path());
}
