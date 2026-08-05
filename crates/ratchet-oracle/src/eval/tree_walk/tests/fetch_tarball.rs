//! Tree-walk evaluator tests: fetch tarball.

use super::*;
use crate::cache::{
    DurableBlake3Hash, PARSE_CACHE_SCHEMA_VERSION, ParseCache, ParseCacheFlags, ParseCacheKey,
    ParseFileKey, PersistCache, PersistFileArtifactKey,
};
use crate::string::NixString;

#[test]
fn fetch_tarball_primop_unpacks_root_and_hashes_recursive_tree() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tarball");
    let store_dir = unique_temp_dir("fetch-tarball-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";

    let path = eval_string_bytes_with_options(
        &format!(r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#),
        options.clone(),
    );
    let path_text = std::str::from_utf8(&path)
        .expect("store path is UTF-8")
        .to_owned();
    assert!(path_text.starts_with(path_source(&store_dir).as_str()));
    assert!(path_text.ends_with("-source"));
    assert_eq!(
        fs::read(PathBuf::from(&path_text).join("file.txt"))
            .expect("fetchTarball materializes root-stripped file"),
        b"data"
    );
    assert_eq!(
        fs::read(PathBuf::from(&path_text).join("sub").join("nested.txt"))
            .expect("fetchTarball materializes nested file"),
        b"inner"
    );

    assert_eq!(
        eval_json_bytes_with_options(
            &format!(
                r#"builtins.readDir (builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }})"#
            ),
            options,
        ),
        br#"{"file.txt":"regular","sub":"directory"}"#.to_vec()
    );

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn configured_import_cache_preserves_fetch_tarball_store_path_surface() {
    fn evaluate_fetch_tarball_surface(
        source: &str,
        options: TreeWalkOptions,
    ) -> (Vec<u8>, (usize, usize)) {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let value = evaluator
            .eval_root()
            .expect("fetchTarball expression evaluates");
        let import_stats = evaluator.import_parse_cache_stats();
        let output = evaluator
            .heap()
            .get_string(value)
            .expect("fetchTarball result is a string")
            .bytes()
            .to_vec();
        (output, import_stats)
    }

    fn checked_store_path(output: &[u8], store_dir: &Path) -> PathBuf {
        let path = PathBuf::from(std::str::from_utf8(output).expect("store path is UTF-8"));
        assert!(
            path.starts_with(store_dir),
            "fetchTarball store path {path:?} should stay under configured store dir {store_dir:?}"
        );
        path
    }

    fn assert_materialized_fetch_tarball_file(output: &[u8], store_dir: &Path) {
        assert_eq!(
            fs::read(checked_store_path(output, store_dir).join("file.txt"))
                .expect("fetchTarball materializes root-stripped file"),
            b"data"
        );
    }

    fn remove_store_path(output: &[u8], store_dir: &Path) {
        fs::remove_dir_all(checked_store_path(output, store_dir))
            .expect("materialized store path removes");
    }

    fn hot_string_surface_canaries(label: &str, bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let hot_canary = NixString::from_bytes(bytes.to_vec())
            .structural_hash_xxh3()
            .raw_for_tests();
        vec![
            (
                format!("{label} hot xxh3 decimal"),
                hot_canary.to_string().into_bytes(),
            ),
            (
                format!("{label} hot xxh3 hex"),
                format!("{hot_canary:016x}").into_bytes(),
            ),
            (
                format!("{label} hot xxh3 little-endian bytes"),
                hot_canary.to_le_bytes().to_vec(),
            ),
            (
                format!("{label} hot xxh3 big-endian bytes"),
                hot_canary.to_be_bytes().to_vec(),
            ),
        ]
    }

    let root = fs::canonicalize(unique_temp_dir("import-cache-fetch-tarball-surface-parity"))
        .expect("temp directory canonicalizes");
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tarball-cache-surface");
    let archive_bytes = fs::read(&archive_path).expect("archive fixture reads");
    let first_parse_root = root.join("first-parse-cache");
    let second_parse_root = root.join("second-parse-cache");
    let persist_root = root.join("persist-cache");
    let store_dir = root.join("store");
    fs::create_dir(&store_dir).expect("store directory creates");
    let import_path = root.join("fetch-tarball-args.nix");
    let url = format!("file://{}", path_source(&archive_path));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";
    let name = b"tarball-surface";
    let imported_source = format!(
        r#"{{ url = {}; sha256 = "{recursive_digest}"; name = "{}"; }}"#,
        nix_string_literal(&url),
        std::str::from_utf8(name).expect("name is UTF-8"),
    )
    .into_bytes();
    fs::write(&import_path, &imported_source).expect("fetchTarball args import writes");
    let import_realpath = fs::canonicalize(&import_path).expect("import path canonicalizes");
    let source = format!("builtins.fetchTarball (import {})", import_path.display());

    let mut uncached_options = TreeWalkOptions::with_store_dir(path_bytes(&store_dir))
        .expect("store directory configures");
    uncached_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let (uncached_output, uncached_stats) =
        evaluate_fetch_tarball_surface(&source, uncached_options);
    assert_eq!(uncached_stats, (0, 0));
    assert!(
        uncached_output.ends_with(b"-tarball-surface"),
        "fetchTarball surface should expose the requested fixed-output name: {uncached_output:?}"
    );
    assert_materialized_fetch_tarball_file(&uncached_output, &store_dir);
    remove_store_path(&uncached_output, &store_dir);

    let mut miss_options = TreeWalkOptions::with_store_dir(path_bytes(&store_dir))
        .expect("store directory configures");
    miss_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    miss_options.set_parse_cache_root(&first_parse_root);
    miss_options.set_persist_cache_root(&persist_root);
    let (miss_output, miss_stats) = evaluate_fetch_tarball_surface(&source, miss_options);
    assert_eq!(miss_stats, (0, 1));
    assert_eq!(miss_output, uncached_output);
    assert_materialized_fetch_tarball_file(&miss_output, &store_dir);
    remove_store_path(&miss_output, &store_dir);

    let mut hit_options = TreeWalkOptions::with_store_dir(path_bytes(&store_dir))
        .expect("store directory configures");
    hit_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    hit_options.set_parse_cache_root(&second_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    let (hit_output, hit_stats) = evaluate_fetch_tarball_surface(&source, hit_options);
    assert_eq!(hit_stats, (1, 0));
    assert_eq!(hit_output, uncached_output);
    assert_materialized_fetch_tarball_file(&hit_output, &store_dir);
    assert!(
        ParseCache::new(&second_parse_root)
            .entry_for_source(&imported_source)
            .is_complete(),
        "persistent hit should hydrate the runtime parse-cache entry"
    );

    let root_parse_key = ParseCacheKey::for_source(
        source.as_bytes(),
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let imported_parse_key = ParseCacheKey::for_source(
        &imported_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let file_key = ParseFileKey::for_source(&import_realpath, &imported_source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, imported_parse_key);
    assert!(
        PersistCache::open(&persist_root)
            .expect("persistent cache opens")
            .lookup_file_artifact(artifact_key)
            .expect("persistent file-artifact lookup succeeds")
            .is_some(),
        "fetchTarball canary import should materialize a persistent file-artifact mapping"
    );

    let mut canaries =
        durable_hash_surface_canaries("root parse-cache BLAKE3", root_parse_key.as_durable_hash());
    canaries.extend(durable_hash_surface_canaries(
        "import parse-cache BLAKE3",
        imported_parse_key.as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "import file-content BLAKE3",
        file_key.content_hash().as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "archive bytes BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(&archive_bytes),
    ));
    canaries.extend(hot_string_surface_canaries(
        "fetchTarball URL",
        url.as_bytes(),
    ));
    canaries.extend(hot_string_surface_canaries("fetchTarball name", name));

    for (surface_name, output) in [
        ("cache-disabled fetchTarball surface", &uncached_output),
        ("persistent miss fetchTarball surface", &miss_output),
        ("persistent hit fetchTarball surface", &hit_output),
    ] {
        assert_surface_canaries_absent(surface_name, "store path", output, &canaries);
    }

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn fetch_tarball_primop_sniffs_extensionless_archives() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tarball-extensionless");
    let extensionless_path = archive_dir.join("archive");
    fs::copy(&archive_path, &extensionless_path).expect("extensionless tarball copies");
    let store_dir = unique_temp_dir("fetch-tarball-extensionless-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&extensionless_path)));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";

    let path = eval_string_bytes_with_options(
        &format!(r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#),
        options,
    );
    let path_text = std::str::from_utf8(&path).expect("store path is UTF-8");
    assert_eq!(
        fs::read(PathBuf::from(path_text).join("file.txt"))
            .expect("extensionless fetchTarball materializes file"),
        b"data"
    );

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tarball_reuse_trusts_only_default_nix_store_paths() {
    let mut default_eval = TreeWalk::new(&lower("null"));
    assert!(
        default_eval.should_query_default_nix_store_for_fetch_tarball_path(
            b"/nix/store/00000000000000000000000000000000-source"
        )
    );
    assert!(!default_eval.can_trust_existing_fetch_tarball_store_path(
        b"/nix/store/00000000000000000000000000000000-source"
    ));
    assert!(
        !default_eval
            .should_query_default_nix_store_for_fetch_tarball_path(b"/tmp/store/not-a-store-path")
    );

    let store_dir = unique_temp_dir("fetch-tarball-trust-store");
    let custom_options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let custom_eval = TreeWalk::with_options(&lower("null"), custom_options);
    assert!(
        !custom_eval.should_query_default_nix_store_for_fetch_tarball_path(
            b"/nix/store/00000000000000000000000000000000-source"
        )
    );
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tarball_default_store_validity_pins_local_store_and_scrubs_env() {
    let command =
        TreeWalk::nix_store_validity_command("/nix/store/00000000000000000000000000000000-source");
    let args = command
        .get_args()
        .map(|arg| arg.as_bytes())
        .collect::<Vec<_>>();
    assert_eq!(
        args,
        [
            b"--store".as_slice(),
            b"daemon".as_slice(),
            b"--check-validity".as_slice(),
            b"/nix/store/00000000000000000000000000000000-source".as_slice(),
        ]
    );
    for (key, value) in [
        ("HOME", "/var/empty"),
        ("XDG_CONFIG_HOME", "/var/empty/.config"),
        ("XDG_CONFIG_DIRS", "/var/empty"),
        ("NIX_USER_CONF_FILES", ""),
    ] {
        assert!(
            matches!(
                command.get_envs().find(|(name, _)| *name == key),
                Some((_, Some(found))) if found == std::ffi::OsStr::new(value)
            ),
            "{key} should be pinned for nix-store validity checks"
        );
    }
    for key in [
        "AOS_NIX_NATIVE",
        "AOS_NIX_NATIVE_VERIFY",
        "NIX_REMOTE",
        "NIX_CONFIG",
        "NIX_CONF_DIR",
        "NIX_STORE_DIR",
        "NIX_STATE_DIR",
        "NIX_LOG_DIR",
    ] {
        assert!(
            matches!(
                command.get_envs().find(|(name, _)| *name == key),
                Some((_, None))
            ),
            "{key} should be explicitly removed from nix-store validity checks"
        );
    }
}

#[test]
fn fetch_tarball_primop_rejects_unwritable_store_materialization() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tarball-unwritable-store");
    let store_dir = unique_temp_dir("fetch-tarball-unwritable-store-root");
    let url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o555))
        .expect("store directory permissions tighten");

    let result = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#
        )),
        options,
    );

    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o755))
        .expect("store directory permissions restore");
    let error = result.expect_err("unwritable store rejects fetchTarball materialization");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarball { .. }
    ));

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tarball_primop_rejects_corrupt_existing_store_path() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tarball-corrupt-store");
    let store_dir = unique_temp_dir("fetch-tarball-corrupt-store-root");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";
    let source =
        format!(r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#);
    let path = eval_string_bytes_with_options(&source, options.clone());
    let path_text = std::str::from_utf8(&path)
        .expect("store path is UTF-8")
        .to_owned();
    fs::remove_file(PathBuf::from(&path_text).join("sub").join("nested.txt"))
        .expect("materialized store path corrupts");

    let error = eval_whnf_owned_with_options(&lower(&source), options)
        .expect_err("corrupt existing fetchTarball store path rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarballHashMismatch { .. }
    ));

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tarball_primop_validates_arguments_and_hashes() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tarball-invalid");
    let url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";

    let ir = lower(&format!(
        r#"builtins.fetchTarball {{ url = {url}; sha256 = "0000000000000000000000000000000000000000000000000000000000000000"; }}"#
    ));
    let error = eval_whnf_owned(&ir).expect_err("hash mismatch rejects fetchTarball");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarballHashMismatch { .. }
    ));

    let ir = lower(&format!(
        "builtins.fetchTarball {{ url = {url}; sha256 = \"\"; }}"
    ));
    let mut evaluator = TreeWalk::new(&ir);
    let error = evaluator
        .eval_root()
        .expect_err("empty fetchTarball hash warns and mismatches real content");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarballHashMismatch { expected, .. }
            if expected.as_slice() == [0_u8; 32]
    ));
    assert_eq!(evaluator.warning_output().len(), 1);
    assert_warning_output(
        evaluator
            .warning_output()
            .first()
            .expect("warning output exists"),
        EMPTY_FETCHURL_SHA256_WARNING,
    );

    let ir = lower(&format!(
        r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; bogus = 1; }}"#
    ));
    let error = eval_whnf_owned(&ir).expect_err("unknown fetchTarball attr rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTarballAttr { attr, .. }
            if attr.as_slice() == b"bogus"
    ));

    let ir = lower(&format!(
        r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; name = "bad/name"; }}"#
    ));
    let error = eval_whnf_owned(&ir).expect_err("invalid store name rejects fetchTarball");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarballStoreName { .. }
    ));

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
}

#[test]
fn fetch_tarball_primop_obeys_eval_mode_gates() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tarball-mode");
    let store_dir = unique_temp_dir("fetch-tarball-mode-store");
    let path = path_source(&archive_path);
    let url = nix_string_literal(&format!("file://{path}"));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";

    let error = eval_whnf_owned_with_options(
        &lower(&format!("builtins.fetchTarball {url}")),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure eval rejects unpinned fetchTarball before URL access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarballHashRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    let mut pure_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    pure_options.set_eval_mode(EvalMode::Pure);
    assert!(
        String::from_utf8(eval_string_bytes_with_options(
            &format!(r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#),
            pure_options,
        ))
        .expect("store path is UTF-8")
        .ends_with("-source")
    );

    let error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted eval rejects disallowed file fetchTarball");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            path: denied,
            mode: EvalMode::Restricted,
            ..
        } if denied.as_slice() == path.as_bytes()
    ));

    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    options.set_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(path.as_bytes().to_vec())
        .expect("allowed path accepts absolute path");
    assert!(
        String::from_utf8(eval_string_bytes_with_options(
            &format!(r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#),
            options,
        ))
        .expect("store path is UTF-8")
        .ends_with("-source")
    );

    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    options.set_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri(format!("file://{path}").into_bytes())
        .expect("file URL prefix configures as allowed URI");
    assert!(
        String::from_utf8(eval_string_bytes_with_options(
            &format!(r#"builtins.fetchTarball {{ url = {url}; sha256 = "{recursive_digest}"; }}"#),
            options,
        ))
        .expect("store path is UTF-8")
        .ends_with("-source")
    );

    let error = eval_whnf_owned_with_options(
            &lower(
                r#"builtins.fetchTarball { url = "https://cache.example/src.tar.gz"; sha256 = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2"; }"#,
            ),
            TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
        )
        .expect_err("restricted eval rejects disallowed network fetchTarball before network access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTarballAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn path_primop_supports_flat_hashing_and_sha256_checks() {
    let (dir, path) = temp_file_with_bytes("path-primop-flat", b"abc");
    let path = path_source(&path);
    let recursive_digest = "11a71b4754d812f4aea20161c533bdaa112ac5c853013e65d3aa9640b5735230";
    let flat_digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.path {{ path = {path}; sha256 = \"{recursive_digest}\"; }}"
        )),
        b"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.path {{ path = {path}; recursive = false; }}"
        )),
        b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.path {{ path = {path}; recursive = false; sha256 = \"{flat_digest}\"; }}"
        )),
        b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt"
    );

    let ir = lower(&format!(
        "builtins.path {{ path = {path}; sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("sha256 mismatch rejects source path");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::SourcePathHashMismatch { .. }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn configured_import_cache_preserves_path_store_path_surface() {
    fn evaluate_path_surface(source: &str, options: TreeWalkOptions) -> (Vec<u8>, (usize, usize)) {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let value = evaluator.eval_root().expect("path expression evaluates");
        let import_stats = evaluator.import_parse_cache_stats();
        let output = evaluator
            .heap()
            .get_string(value)
            .expect("path result is a string")
            .bytes()
            .to_vec();
        (output, import_stats)
    }

    fn hot_string_surface_canaries(label: &str, bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
        let hot_canary = NixString::from_bytes(bytes.to_vec())
            .structural_hash_xxh3()
            .raw_for_tests();
        vec![
            (
                format!("{label} hot xxh3 decimal"),
                hot_canary.to_string().into_bytes(),
            ),
            (
                format!("{label} hot xxh3 hex"),
                format!("{hot_canary:016x}").into_bytes(),
            ),
            (
                format!("{label} hot xxh3 little-endian bytes"),
                hot_canary.to_le_bytes().to_vec(),
            ),
            (
                format!("{label} hot xxh3 big-endian bytes"),
                hot_canary.to_be_bytes().to_vec(),
            ),
        ]
    }

    let root = fs::canonicalize(unique_temp_dir("import-cache-path-surface-parity"))
        .expect("temp directory canonicalizes");
    let first_parse_root = root.join("first-parse-cache");
    let second_parse_root = root.join("second-parse-cache");
    let persist_root = root.join("persist-cache");
    let import_path = root.join("path-args.nix");
    let payload_path = root.join("payload.txt");
    let payload = b"abc";
    let flat_digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let name = b"path-surface";
    fs::write(&payload_path, payload).expect("payload writes");
    let source_path = path_source(&payload_path);
    let imported_source = format!(
        r#"{{ path = {source_path}; recursive = false; sha256 = "{flat_digest}"; name = "{}"; }}"#,
        std::str::from_utf8(name).expect("name is UTF-8"),
    )
    .into_bytes();
    fs::write(&import_path, &imported_source).expect("path args import writes");
    let import_realpath = fs::canonicalize(&import_path).expect("import path canonicalizes");
    let source = format!("builtins.path (import {})", import_path.display());

    let mut uncached_options = TreeWalkOptions::new();
    uncached_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let (uncached_output, uncached_stats) = evaluate_path_surface(&source, uncached_options);
    assert_eq!(uncached_stats, (0, 0));
    assert!(
        uncached_output.ends_with(b"-path-surface"),
        "path surface should expose the requested source path name: {uncached_output:?}"
    );

    let mut miss_options = TreeWalkOptions::new();
    miss_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    miss_options.set_parse_cache_root(&first_parse_root);
    miss_options.set_persist_cache_root(&persist_root);
    let (miss_output, miss_stats) = evaluate_path_surface(&source, miss_options);
    assert_eq!(miss_stats, (0, 1));
    assert_eq!(miss_output, uncached_output);

    let mut hit_options = TreeWalkOptions::new();
    hit_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    hit_options.set_parse_cache_root(&second_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    let (hit_output, hit_stats) = evaluate_path_surface(&source, hit_options);
    assert_eq!(hit_stats, (1, 0));
    assert_eq!(hit_output, uncached_output);
    assert!(
        ParseCache::new(&second_parse_root)
            .entry_for_source(&imported_source)
            .is_complete(),
        "persistent hit should hydrate the runtime parse-cache entry"
    );

    let root_parse_key = ParseCacheKey::for_source(
        source.as_bytes(),
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let imported_parse_key = ParseCacheKey::for_source(
        &imported_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let file_key = ParseFileKey::for_source(&import_realpath, &imported_source);
    let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, imported_parse_key);
    assert!(
        PersistCache::open(&persist_root)
            .expect("persistent cache opens")
            .lookup_file_artifact(artifact_key)
            .expect("persistent file-artifact lookup succeeds")
            .is_some(),
        "path canary import should materialize a persistent file-artifact mapping"
    );

    let mut canaries =
        durable_hash_surface_canaries("root parse-cache BLAKE3", root_parse_key.as_durable_hash());
    canaries.extend(durable_hash_surface_canaries(
        "import parse-cache BLAKE3",
        imported_parse_key.as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "import file-content BLAKE3",
        file_key.content_hash().as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "path payload BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(payload),
    ));
    canaries.extend(hot_string_surface_canaries(
        "source path",
        source_path.as_bytes(),
    ));
    canaries.extend(hot_string_surface_canaries("source path name", name));

    for (surface_name, output) in [
        ("cache-disabled path surface", &uncached_output),
        ("persistent miss path surface", &miss_output),
        ("persistent hit path surface", &hit_output),
    ] {
        assert_surface_canaries_absent(surface_name, "store path", output, &canaries);
    }

    fs::remove_dir_all(root).expect("temp directory removes");
}
