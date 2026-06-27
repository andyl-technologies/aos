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

    let mut canaries = durable_hash_surface_canaries(
        "root parse-cache BLAKE3",
        DurableBlake3Hash::from_bytes(root_parse_key.as_bytes()),
    );
    canaries.extend(durable_hash_surface_canaries(
        "import parse-cache BLAKE3",
        DurableBlake3Hash::from_bytes(imported_parse_key.as_bytes()),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "import file-content BLAKE3",
        file_key.content_hash(),
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
    let default_eval = TreeWalk::new(&lower("null"));
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

    let mut canaries = durable_hash_surface_canaries(
        "root parse-cache BLAKE3",
        DurableBlake3Hash::from_bytes(root_parse_key.as_bytes()),
    );
    canaries.extend(durable_hash_surface_canaries(
        "import parse-cache BLAKE3",
        DurableBlake3Hash::from_bytes(imported_parse_key.as_bytes()),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "import file-content BLAKE3",
        file_key.content_hash(),
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

#[test]
fn configured_import_cache_preserves_find_file_path_store_path_surface() {
    fn evaluate_find_file_path_surface(
        source: &str,
        options: TreeWalkOptions,
    ) -> (Vec<u8>, (usize, usize)) {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let value = evaluator
            .eval_root()
            .expect("findFile path expression evaluates");
        let import_stats = evaluator.import_parse_cache_stats();
        let output = evaluator
            .heap()
            .get_string(value)
            .expect("findFile path result is a string")
            .bytes()
            .to_vec();
        (output, import_stats)
    }

    fn configured_options(root: &Path, store_dir: &Path) -> TreeWalkOptions {
        let mut options = TreeWalkOptions::with_store_dir(path_bytes(store_dir))
            .expect("store directory configures");
        options
            .set_path_literal_base(path_bytes(root))
            .expect("path base configures");
        options
    }

    fn checked_store_path(output: &[u8], store_dir: &Path) -> PathBuf {
        let path = PathBuf::from(std::str::from_utf8(output).expect("store path is UTF-8"));
        assert!(
            path.starts_with(store_dir),
            "findFile-fed store path {path:?} should stay under configured store dir {store_dir:?}"
        );
        path
    }

    fn assert_persistent_artifact(
        persist_root: &Path,
        realpath: &Path,
        source: &[u8],
        parse_key: ParseCacheKey,
    ) {
        let file_key = ParseFileKey::for_source(realpath, source);
        let artifact_key = PersistFileArtifactKey::from_parse_file_key(&file_key, parse_key);
        assert!(
            PersistCache::open(persist_root)
                .expect("persistent cache opens")
                .lookup_file_artifact(artifact_key)
                .expect("persistent file-artifact lookup succeeds")
                .is_some(),
            "findFile canary import should materialize a persistent file-artifact mapping"
        );
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

    let root = fs::canonicalize(unique_temp_dir(
        "import-cache-find-file-path-surface-parity",
    ))
    .expect("temp directory canonicalizes");
    let first_parse_root = root.join("first-parse-cache");
    let second_parse_root = root.join("second-parse-cache");
    let persist_root = root.join("persist-cache");
    let store_dir = root.join("store");
    let search_root = root.join("search-root");
    let found_tree = search_root.join("source");
    let nested = found_tree.join("nested");
    fs::create_dir(&store_dir).expect("store directory creates");
    fs::create_dir_all(&nested).expect("findFile source tree creates");
    let payload = b"findFile path store payload";
    let nested_payload = b"findFile nested payload";
    fs::write(found_tree.join("payload.txt"), payload).expect("payload writes");
    fs::write(nested.join("payload.txt"), nested_payload).expect("nested payload writes");

    let root_path = root.join("find-file-root.nix");
    let prefix_path = root.join("find-file-prefix.nix");
    let lookup_path = root.join("find-file-lookup.nix");
    let name_path = root.join("find-file-name.nix");
    let prefix = b"pkg";
    let lookup = b"pkg/source";
    let name = b"find-file-surface";
    let search_root_text = path_source(&search_root);
    let root_source = format!("{search_root_text}\n").into_bytes();
    let prefix_source = format!("{}\n", nix_string_literal("pkg")).into_bytes();
    let lookup_source = format!("{}\n", nix_string_literal("pkg/source")).into_bytes();
    let name_source = format!("{}\n", nix_string_literal("find-file-surface")).into_bytes();
    fs::write(&root_path, &root_source).expect("findFile root import writes");
    fs::write(&prefix_path, &prefix_source).expect("findFile prefix import writes");
    fs::write(&lookup_path, &lookup_source).expect("findFile lookup import writes");
    fs::write(&name_path, &name_source).expect("findFile name import writes");

    let root_realpath = fs::canonicalize(&root_path).expect("root path canonicalizes");
    let prefix_realpath = fs::canonicalize(&prefix_path).expect("prefix path canonicalizes");
    let lookup_realpath = fs::canonicalize(&lookup_path).expect("lookup path canonicalizes");
    let name_realpath = fs::canonicalize(&name_path).expect("name path canonicalizes");
    let source = format!(
        r#"let
  searchRoot = import {};
  prefix = import {};
  lookup = import {};
  name = import {};
  found = builtins.findFile [ {{ inherit prefix; path = searchRoot; }} ] lookup;
in builtins.path {{ path = found; inherit name; }}"#,
        path_source(&root_path),
        path_source(&prefix_path),
        path_source(&lookup_path),
        path_source(&name_path)
    );
    let resolved_source = format!(
        r#"let
  searchRoot = import {};
  prefix = import {};
  lookup = import {};
  found = builtins.findFile [ {{ inherit prefix; path = searchRoot; }} ] lookup;
in builtins.toString found"#,
        path_source(&root_path),
        path_source(&prefix_path),
        path_source(&lookup_path)
    );
    let direct_source = format!(
        r#"builtins.path {{ path = {}; name = "find-file-surface"; }}"#,
        path_source(&found_tree)
    );

    assert_eq!(
        eval_string_bytes_with_options(&resolved_source, configured_options(&root, &store_dir)),
        path_bytes(&found_tree),
        "findFile should resolve the expected source tree before path hashing"
    );
    let direct_output =
        eval_string_bytes_with_options(&direct_source, configured_options(&root, &store_dir));

    let uncached_options = configured_options(&root, &store_dir);
    let (uncached_output, uncached_stats) =
        evaluate_find_file_path_surface(&source, uncached_options);
    assert_eq!(uncached_stats, (0, 0));
    assert!(
        uncached_output.ends_with(b"-find-file-surface"),
        "findFile-fed path surface should expose the requested name: {uncached_output:?}"
    );
    checked_store_path(&uncached_output, &store_dir);
    assert_eq!(
        uncached_output, direct_output,
        "findFile-fed path hashing should match direct hashing of the resolved source tree"
    );

    let mut miss_options = configured_options(&root, &store_dir);
    miss_options.set_parse_cache_root(&first_parse_root);
    miss_options.set_persist_cache_root(&persist_root);
    let (miss_output, miss_stats) = evaluate_find_file_path_surface(&source, miss_options);
    assert_eq!(miss_stats, (0, 4));
    assert_eq!(miss_output, uncached_output);

    let mut hit_options = configured_options(&root, &store_dir);
    hit_options.set_parse_cache_root(&second_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    let (hit_output, hit_stats) = evaluate_find_file_path_surface(&source, hit_options);
    assert_eq!(hit_stats, (4, 0));
    assert_eq!(hit_output, uncached_output);

    let second_parse = ParseCache::new(&second_parse_root);
    assert!(
        second_parse.entry_for_source(&root_source).is_complete(),
        "persistent hit should hydrate the imported search-root parse-cache entry"
    );
    assert!(
        second_parse.entry_for_source(&prefix_source).is_complete(),
        "persistent hit should hydrate the imported prefix parse-cache entry"
    );
    assert!(
        second_parse.entry_for_source(&lookup_source).is_complete(),
        "persistent hit should hydrate the imported lookup parse-cache entry"
    );
    assert!(
        second_parse.entry_for_source(&name_source).is_complete(),
        "persistent hit should hydrate the imported name parse-cache entry"
    );

    let root_parse_key = ParseCacheKey::for_source(
        source.as_bytes(),
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let root_import_parse_key = ParseCacheKey::for_source(
        &root_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let prefix_parse_key = ParseCacheKey::for_source(
        &prefix_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let lookup_parse_key = ParseCacheKey::for_source(
        &lookup_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    let name_parse_key = ParseCacheKey::for_source(
        &name_source,
        PARSE_CACHE_SCHEMA_VERSION,
        ParseCacheFlags::new(),
    );
    assert_persistent_artifact(
        &persist_root,
        &root_realpath,
        &root_source,
        root_import_parse_key,
    );
    assert_persistent_artifact(
        &persist_root,
        &prefix_realpath,
        &prefix_source,
        prefix_parse_key,
    );
    assert_persistent_artifact(
        &persist_root,
        &lookup_realpath,
        &lookup_source,
        lookup_parse_key,
    );
    assert_persistent_artifact(&persist_root, &name_realpath, &name_source, name_parse_key);

    let mut canaries = durable_hash_surface_canaries(
        "root parse-cache BLAKE3",
        DurableBlake3Hash::from_bytes(root_parse_key.as_bytes()),
    );
    for (label, key) in [
        (
            "search-root import parse-cache BLAKE3",
            root_import_parse_key,
        ),
        ("prefix import parse-cache BLAKE3", prefix_parse_key),
        ("lookup import parse-cache BLAKE3", lookup_parse_key),
        ("name import parse-cache BLAKE3", name_parse_key),
    ] {
        canaries.extend(durable_hash_surface_canaries(
            label,
            DurableBlake3Hash::from_bytes(key.as_bytes()),
        ));
    }
    for (label, realpath, imported_source) in [
        (
            "search-root import file-content BLAKE3",
            root_realpath.as_path(),
            root_source.as_slice(),
        ),
        (
            "prefix import file-content BLAKE3",
            prefix_realpath.as_path(),
            prefix_source.as_slice(),
        ),
        (
            "lookup import file-content BLAKE3",
            lookup_realpath.as_path(),
            lookup_source.as_slice(),
        ),
        (
            "name import file-content BLAKE3",
            name_realpath.as_path(),
            name_source.as_slice(),
        ),
    ] {
        canaries.extend(durable_hash_surface_canaries(
            label,
            ParseFileKey::for_source(realpath, imported_source).content_hash(),
        ));
    }
    canaries.extend(durable_hash_surface_canaries(
        "findFile payload BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(payload),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "findFile nested payload BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(nested_payload),
    ));
    canaries.extend(hot_string_surface_canaries(
        "findFile search root",
        search_root_text.as_bytes(),
    ));
    canaries.extend(hot_string_surface_canaries(
        "findFile resolved path",
        path_bytes(&found_tree).as_slice(),
    ));
    canaries.extend(hot_string_surface_canaries("findFile prefix", prefix));
    canaries.extend(hot_string_surface_canaries("findFile lookup", lookup));
    canaries.extend(hot_string_surface_canaries("findFile store name", name));
    canaries.extend(hot_string_surface_canaries(
        "findFile payload file name",
        b"payload.txt",
    ));

    for (surface_name, output) in [
        ("cache-disabled findFile path surface", &uncached_output),
        ("persistent miss findFile path surface", &miss_output),
        ("persistent hit findFile path surface", &hit_output),
    ] {
        assert_surface_canaries_absent(surface_name, "store path", output, &canaries);
    }

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn filter_source_primop_filters_recursive_source_trees() {
    let dir = unique_temp_dir("filter-source");
    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("tree directory creates");
    fs::write(tree.join("a"), b"one").expect("included file writes");
    fs::write(tree.join("b"), b"two").expect("excluded file writes");
    let tree = path_source(&tree);
    let keep = r#"path: type: type != "directory" && builtins.hasContext path == false && builtins.baseNameOf path == "a""#;

    let filtered = eval_string_bytes(&format!("builtins.filterSource ({keep}) {tree}"));
    assert_eq!(
        filtered,
        eval_string_bytes(&format!(
            "builtins.path {{ path = {tree}; filter = ({keep}); }}"
        ))
    );
    assert_eq!(
        filtered,
        eval_string_bytes(&format!(
            "let filterSource = builtins.filterSource; in filterSource ({keep}) {tree}"
        ))
    );
    assert_ne!(
        filtered,
        eval_string_bytes(&format!("builtins.path {{ path = {tree}; }}"))
    );
    assert!(
        String::from_utf8(filtered)
            .expect("store path is UTF-8")
            .ends_with("-tree")
    );

    let traced = eval_owned(&format!(
        "builtins.path {{ path = {tree}; filter = path: type: builtins.trace (builtins.baseNameOf path) true; }}"
    ));
    let traces = traced.trace_output();
    assert_eq!(traces.len(), 2);
    assert_trace_output(&traces[0], EvalTraceKind::Trace, b"a");
    assert_trace_output(&traces[1], EvalTraceKind::Trace, b"b");

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn configured_import_cache_preserves_filter_source_store_path_surface() {
    fn evaluate_filter_source_surface(
        source: &str,
        options: TreeWalkOptions,
    ) -> (Vec<u8>, (usize, usize)) {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let value = evaluator
            .eval_root()
            .expect("filterSource expression evaluates");
        let import_stats = evaluator.import_parse_cache_stats();
        let output = evaluator
            .heap()
            .get_string(value)
            .expect("filterSource result is a string")
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

    let root = fs::canonicalize(unique_temp_dir("import-cache-filter-source-surface-parity"))
        .expect("temp directory canonicalizes");
    let tree = root.join("tree");
    fs::create_dir(&tree).expect("tree directory creates");
    fs::write(tree.join("a"), b"one").expect("included file writes");
    fs::write(tree.join("b"), b"two").expect("excluded file writes");
    let first_parse_root = root.join("first-parse-cache");
    let second_parse_root = root.join("second-parse-cache");
    let persist_root = root.join("persist-cache");
    let import_path = root.join("filter-source-path.nix");
    let tree_path = path_source(&tree);
    let imported_source = tree_path.as_bytes().to_vec();
    fs::write(&import_path, &imported_source).expect("filterSource path import writes");
    let import_realpath = fs::canonicalize(&import_path).expect("import path canonicalizes");
    let keep = r#"path: type: type != "directory" && builtins.baseNameOf path == "a""#;
    let source = format!(
        "builtins.filterSource ({keep}) (import {})",
        import_path.display()
    );

    let mut uncached_options = TreeWalkOptions::new();
    uncached_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let (uncached_output, uncached_stats) =
        evaluate_filter_source_surface(&source, uncached_options);
    assert_eq!(uncached_stats, (0, 0));
    assert!(
        uncached_output.ends_with(b"-tree"),
        "filterSource surface should expose the default source path name: {uncached_output:?}"
    );
    assert_ne!(
        uncached_output,
        eval_string_bytes(&format!("builtins.path {{ path = {tree_path}; }}")),
        "filterSource surface should differ from the unfiltered source path"
    );

    let mut miss_options = TreeWalkOptions::new();
    miss_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    miss_options.set_parse_cache_root(&first_parse_root);
    miss_options.set_persist_cache_root(&persist_root);
    let (miss_output, miss_stats) = evaluate_filter_source_surface(&source, miss_options);
    assert_eq!(miss_stats, (0, 1));
    assert_eq!(miss_output, uncached_output);

    let mut hit_options = TreeWalkOptions::new();
    hit_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    hit_options.set_parse_cache_root(&second_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    let (hit_output, hit_stats) = evaluate_filter_source_surface(&source, hit_options);
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
        "filterSource canary import should materialize a persistent file-artifact mapping"
    );

    let mut canaries = durable_hash_surface_canaries(
        "root parse-cache BLAKE3",
        DurableBlake3Hash::from_bytes(root_parse_key.as_bytes()),
    );
    canaries.extend(durable_hash_surface_canaries(
        "import parse-cache BLAKE3",
        DurableBlake3Hash::from_bytes(imported_parse_key.as_bytes()),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "import file-content BLAKE3",
        file_key.content_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "included file BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(b"one"),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "excluded file BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(b"two"),
    ));
    canaries.extend(hot_string_surface_canaries(
        "source tree path",
        tree_path.as_bytes(),
    ));
    canaries.extend(hot_string_surface_canaries("included file name", b"a"));
    canaries.extend(hot_string_surface_canaries("excluded file name", b"b"));

    for (surface_name, output) in [
        ("cache-disabled filterSource surface", &uncached_output),
        ("persistent miss filterSource surface", &miss_output),
        ("persistent hit filterSource surface", &hit_output),
    ] {
        assert_surface_canaries_absent(surface_name, "store path", output, &canaries);
    }

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn filter_source_does_not_filter_root_files() {
    let (dir, path) = temp_file_with_bytes("filter-source-root-file", b"abc");
    let path = path_source(&path);

    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.filterSource (path: type: builtins.throw \"called\") {path}"
        )),
        b"/nix/store/ffb76bbyqzzqzwb8yg9a8kqsj75by509-data.txt"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_primop_rejects_invalid_arguments() {
    let dir = unique_temp_dir("path-primop-invalid");
    let file = dir.join("data.txt");
    fs::write(&file, b"abc").expect("temp file writes");
    let tree = dir.join("tree");
    fs::create_dir(&tree).expect("tree directory creates");
    fs::write(tree.join("data.txt"), b"abc").expect("tree file writes");
    let file = path_source(&file);
    let tree = path_source(&tree);

    let ir = lower(&format!("builtins.path {{ path = {file}; bogus = 1; }}"));
    let error = eval_whnf_owned(&ir).expect_err("unknown path attr rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedSourcePathAttr { attr, .. }
            if attr.as_slice() == b"bogus"
    ));

    let ir = lower(&format!(
        "builtins.path {{ path = {file}; filter = null; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("filter must be callable");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::Null,
            ..
        }
    ));

    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.path {{ path = {file}; recursive = false; filter = path: type: builtins.throw \"called\"; }}"
        )),
        b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt"
    );

    let ir = lower(&format!(
        "builtins.path {{ path = {tree}; recursive = false; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("flat directory source paths reject");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::SourcePathArchive { .. }
    ));

    let ir = lower(&format!("builtins.filterSource null {file}"));
    let error = eval_whnf_owned(&ir).expect_err("filterSource filter must be callable");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "lambda",
            actual: ValueTag::Null,
            ..
        }
    ));

    for source in [
        r#"builtins.filterSource null (builtins.throw "path")"#,
        r#"let filterSource = builtins.filterSource; in filterSource null (builtins.throw "path")"#,
    ] {
        let ir = lower(source);
        let error = eval_whnf_owned(&ir).expect_err("filterSource forces path before filter");
        assert!(matches!(error.kind(), TreeWalkErrorKind::Thrown { .. }));
    }

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn path_store_coercion_rejects_invalid_source_store_names() {
    let dir = unique_temp_dir("invalid-store-name");
    let path = dir.join("a b.txt");
    fs::write(&path, b"abc").expect("temp file writes");
    let source = format!(
        r#"let p = builtins.findFile [ {{ path = {}; }} ] "a b.txt"; in "${{p}}""#,
        nix_string_literal(&path_source(&dir))
    );
    let ir = lower(&source);
    let error = eval_whnf_owned(&ir).expect_err("invalid source names reject store coercion");

    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::SourcePathStoreName { .. }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn string_coercion_primops_accept_paths_without_store_copy() {
    let (dir, path) = temp_file_with_bytes("path-string-coercion", b"abc");
    let path = path_source(&path);
    let expected_dir = path_source(&dir);

    assert_eq!(
        eval_string_bytes(&format!("builtins.toString {path}")),
        path.as_bytes()
    );
    assert_eq!(
        eval(&format!("builtins.stringLength {path}")).as_int(),
        Ok(path.len() as i64)
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.substring 0 1 {path}")),
        b"/"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.concatStringsSep \",\" [ \"x\" {path} ]")),
        format!("x,{path}").as_bytes()
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.baseNameOf {path}")),
        b"data.txt"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.typeOf (builtins.dirOf {path})")),
        b"path"
    );
    assert_eq!(
        eval_string_bytes(&format!("builtins.toString (builtins.dirOf {path})")),
        expected_dir.as_bytes()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}
