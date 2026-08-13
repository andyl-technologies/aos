//! Tree-walk evaluator tests: fetchurl.

use super::*;
use crate::cache::{
    DurableBlake3Hash, PARSE_CACHE_SCHEMA_VERSION, ParseCache, ParseCacheFlags, ParseCacheKey,
    ParseFileKey, PersistCache, PersistFileArtifactKey,
};
use crate::string::NixString;

#[test]
fn fetchurl_primop_fetches_file_urls_and_records_context() {
    let (dir, path) = temp_file_with_bytes("fetchurl", b"abc");
    let url = format!("file://{}", path_source(&path));
    let url = nix_string_literal(&url);
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let sri = "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";
    let nix32 = "1b8m03r63zqhnjf7l5wnldhh7c134ap5vpj0850ymkq1iyzicy5s";
    let store_path = b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt";
    let renamed = b"/nix/store/hy1mq1p855x9m96mxz4b9qaf1w0jjl5q-renamed";

    assert_eq!(
        eval_string_bytes(&format!("builtins.fetchurl {url}")),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }}"
        )),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.fetchurl {{ url = {url}; sha256 = \"{sri}\"; }}"
        )),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.fetchurl {{ url = {url}; sha256 = \"{nix32}\"; }}"
        )),
        store_path
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let fetchurl = builtins.fetchurl; in fetchurl {{ url = {url}; sha256 = \"{digest}\"; name = \"renamed\"; }}"
        )),
        renamed
    );
    assert_eq!(
        eval_json_bytes(&format!(
            "builtins.getContext (builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }})"
        )),
        br#"{"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt":{"path":true}}"#.to_vec()
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let p = builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }}; in builtins.readFile p"
        )),
        b"abc"
    );
    assert_eq!(
        eval_string_bytes(&format!(
            "let p = builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }}; in builtins.hashFile \"sha256\" p"
        )),
        digest.as_bytes()
    );
    assert_eq!(
        eval_json_bytes(&format!(
            "let p = builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; }}; in [ (builtins.pathExists p) (builtins.readFileType p) ]"
        )),
        br#"[true,"regular"]"#.to_vec()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn configured_import_cache_preserves_fetchurl_store_path_surface() {
    fn evaluate_fetchurl_surface(
        source: &str,
        options: TreeWalkOptions,
    ) -> (Vec<u8>, (usize, usize)) {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let value = evaluator
            .eval_root()
            .expect("fetchurl expression evaluates");
        let import_stats = evaluator.import_parse_cache_stats();
        let output = evaluator
            .heap()
            .get_string(value)
            .expect("fetchurl result is a string")
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

    let root = fs::canonicalize(unique_temp_dir("import-cache-fetchurl-surface-parity"))
        .expect("temp directory canonicalizes");
    let first_parse_root = root.join("first-parse-cache");
    let second_parse_root = root.join("second-parse-cache");
    let persist_root = root.join("persist-cache");
    let import_path = root.join("fetch-args.nix");
    let payload_path = root.join("payload.txt");
    let payload = b"abc";
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let name = b"fetch-surface";
    fs::write(&payload_path, payload).expect("payload writes");
    let url = format!("file://{}", path_source(&payload_path));
    let imported_source = format!(
        r#"{{ url = {}; sha256 = "{digest}"; name = "{}"; }}"#,
        nix_string_literal(&url),
        std::str::from_utf8(name).expect("name is UTF-8"),
    )
    .into_bytes();
    fs::write(&import_path, &imported_source).expect("fetchurl args import writes");
    let import_realpath = fs::canonicalize(&import_path).expect("import path canonicalizes");
    let source = format!("builtins.fetchurl (import {})", import_path.display());

    let mut uncached_options = TreeWalkOptions::new();
    uncached_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let (uncached_output, uncached_stats) = evaluate_fetchurl_surface(&source, uncached_options);
    assert_eq!(uncached_stats, (0, 0));
    assert!(
        uncached_output.ends_with(b"-fetch-surface"),
        "fetchurl surface should expose the requested fixed-output name: {uncached_output:?}"
    );

    let mut miss_options = TreeWalkOptions::new();
    miss_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    miss_options.set_parse_cache_root(&first_parse_root);
    miss_options.set_persist_cache_root(&persist_root);
    let (miss_output, miss_stats) = evaluate_fetchurl_surface(&source, miss_options);
    assert_eq!(miss_stats, (0, 1));
    assert_eq!(miss_output, uncached_output);

    let mut hit_options = TreeWalkOptions::new();
    hit_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    hit_options.set_parse_cache_root(&second_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    let (hit_output, hit_stats) = evaluate_fetchurl_surface(&source, hit_options);
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
        "fetchurl canary import should materialize a persistent file-artifact mapping"
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
        "fetched payload BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(payload),
    ));
    canaries.extend(hot_string_surface_canaries("fetchurl URL", url.as_bytes()));
    canaries.extend(hot_string_surface_canaries("fetchurl name", name));

    for (surface_name, output) in [
        ("cache-disabled fetchurl surface", &uncached_output),
        ("persistent miss fetchurl surface", &miss_output),
        ("persistent hit fetchurl surface", &hit_output),
    ] {
        assert_surface_canaries_absent(surface_name, "store path", output, &canaries);
    }

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_uses_raw_url_basename_for_default_name() {
    let (dir, path) = temp_file_with_bytes("fetchurl-query", b"abc");
    let url = format!("file://{}?foo=bar", path_source(&path));
    let url = nix_string_literal(&url);

    assert_eq!(
        eval_string_bytes(&format!(
            "builtins.fetchurl {{ url = {url}; sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; }}"
        )),
        b"/nix/store/cnsr0sbn6xzksm6fa7dh81a1d2yxx0fk-data.txt?foo=bar"
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_rejects_invalid_arguments() {
    let (dir, path) = temp_file_with_bytes("fetchurl-invalid", b"abc");
    let url = format!("file://{}", path_source(&path));
    let url = nix_string_literal(&url);

    let ir = lower(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("hash mismatch rejects fetchurl");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlHashMismatch { .. }
    ));

    let ir = lower(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"\"; }}"
    ));
    let mut evaluator = TreeWalk::new(&ir);
    let error = evaluator
        .eval_root()
        .expect_err("empty fetchurl hash warns and then mismatches real content");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlHashMismatch { expected, .. }
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
        "builtins.fetchurl {{ url = {url}; sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; bogus = 1; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("unknown fetchurl attr rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchUrlAttr { attr, .. }
            if attr.as_slice() == b"bogus"
    ));

    let ir = lower(
        r#"builtins.fetchurl { sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; }"#,
    );
    let error = eval_whnf_owned(&ir).expect_err("missing url rejects fetchurl");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let ir = lower(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; name = \"bad/name\"; }}"
    ));
    let error = eval_whnf_owned(&ir).expect_err("invalid store name rejects fetchurl");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlStoreName { .. }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_obeys_eval_mode_gates() {
    let (dir, path) = temp_file_with_bytes("fetchurl-mode", b"abc");
    let path = path_source(&path);
    let url = nix_string_literal(&format!("file://{path}"));
    let source = format!("builtins.fetchurl {url}");

    let error = eval_whnf_owned_with_options(
        &lower(&source),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure eval rejects unpinned fetchurl before URL access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlHashRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                "builtins.fetchurl {{ url = {url}; sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"; }}"
            ),
            TreeWalkOptions::with_eval_mode(EvalMode::Pure),
        ),
        b"/nix/store/mypqc3c8w9d2adal1lax2yd0kkx186vg-data.txt"
    );

    let error = eval_whnf_owned_with_options(
            &lower(
                r#"builtins.fetchurl { url = "https://cache.example/data.txt"; sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; }"#,
            ),
            TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
        )
        .expect_err("restricted eval rejects disallowed network fetchurl before network access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchUrlAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_fetches_http_urls_as_identity_bytes() {
    let (url, body_hash, handle) = gzip_encoded_http_fixture("/data.txt", b"abc");
    let url = nix_string_literal(&url);
    let store_dir = unique_temp_dir("fetchurl-http-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                r#"
                let p = builtins.fetchurl {{
                  url = {url};
                  name = "http-identity-data";
                  sha256 = "{body_hash}";
                }};
                in builtins.hashFile "sha256" p
                "#
            ),
            options,
        ),
        body_hash.as_bytes()
    );
    fs::remove_dir_all(store_dir).expect("store temp directory removes");

    assert_http_fixture_requested_identity(
        handle.join().expect("HTTP fixture thread completes"),
        "fetchurl",
    );
}

#[test]
fn fetchurl_primop_reuses_materialized_fixed_output_paths_before_fetching() {
    let (dir, path) = temp_file_with_bytes("fetchurl-reuse", b"abc");
    let path = path_source(&path);
    let url = nix_string_literal(&format!("file://{path}"));
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let expected_path = String::from_utf8(eval_string_bytes(&format!(
        "builtins.fetchurl {{ url = {url}; sha256 = \"{digest}\"; name = \"cached\"; }}"
    )))
    .expect("store paths are UTF-8");

    let pure_source = format!(
        r#"[
              (builtins.fetchurl {{ url = {url}; sha256 = "{digest}"; name = "cached"; }})
              (builtins.fetchurl {{ url = "https://example.invalid/missing"; sha256 = "{digest}"; name = "cached"; }})
            ]"#
    );
    let pure_options = TreeWalkOptions::with_eval_mode(EvalMode::Pure);
    assert_eq!(
        eval_json_bytes_with_options(&pure_source, pure_options),
        format!(r#"["{expected_path}","{expected_path}"]"#).into_bytes()
    );

    let restricted_source = format!(
        r#"[
              (builtins.fetchurl {{ url = {url}; sha256 = "{digest}"; name = "cached"; }})
              (builtins.fetchurl {{ url = "https://cache.example/missing"; sha256 = "{digest}"; name = "cached"; }})
            ]"#
    );
    let mut restricted_options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_path(path.as_bytes().to_vec())
        .expect("allowed path accepts absolute path");
    restricted_options
        .add_allowed_uri(b"https://cache.example/".to_vec())
        .expect("allowed URI prefix configures");
    assert_eq!(
        eval_json_bytes_with_options(&restricted_source, restricted_options),
        format!(r#"["{expected_path}","{expected_path}"]"#).into_bytes()
    );

    fs::remove_dir_all(dir).expect("temp directory removes");
}

#[test]
fn fetchurl_primop_rejects_reuse_through_restricted_file_url_policy() {
    let (allowed_dir, allowed_path) = temp_file_with_bytes("fetchurl-allowed", b"abc");
    let (blocked_dir, blocked_path) = temp_file_with_bytes("fetchurl-blocked", b"abc");
    let allowed_path = path_source(&allowed_path);
    let blocked_path = path_source(&blocked_path);
    let allowed_url = nix_string_literal(&format!("file://{allowed_path}"));
    let blocked_url = nix_string_literal(&format!("file://{blocked_path}"));
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let source = format!(
        r#"builtins.toJSON [
              (builtins.fetchurl {{ url = {allowed_url}; sha256 = "{digest}"; name = "cached"; }})
              (builtins.fetchurl {{ url = {blocked_url}; sha256 = "{digest}"; name = "cached"; }})
            ]"#
    );
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_path(allowed_path.as_bytes().to_vec())
        .expect("allowed path accepts absolute path");

    let error = eval_whnf_owned_with_options(&lower(&source), options)
        .expect_err("restricted file URL policy is checked before fixed-output reuse");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            path,
            mode: EvalMode::Restricted,
            ..
        } if path.as_slice() == blocked_path.as_bytes()
    ));

    fs::remove_dir_all(allowed_dir).expect("allowed temp directory removes");
    fs::remove_dir_all(blocked_dir).expect("blocked temp directory removes");
}

#[test]
fn fetchurl_primop_reuses_existing_configured_store_paths() {
    let store_dir = unique_temp_dir("fetchurl-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let (source_dir, source_path) = temp_file_with_bytes("fetchurl-existing-store", b"abc");
    let source_url = nix_string_literal(&format!("file://{}", path_source(&source_path)));
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let expected_path = eval_string_bytes_with_options(
        &format!(
            r#"builtins.fetchurl {{ url = {source_url}; sha256 = "{digest}"; name = "cached"; }}"#
        ),
        options.clone(),
    );
    let expected_path_text = std::str::from_utf8(&expected_path)
        .expect("store path is UTF-8")
        .to_owned();
    let expected_path_buf = PathBuf::from(expected_path_text.clone());
    fs::create_dir_all(
        expected_path_buf
            .parent()
            .expect("store path has parent directory"),
    )
    .expect("store directory creates");
    fs::write(&expected_path_buf, b"abc").expect("existing store path writes");
    options.set_eval_mode(EvalMode::Pure);

    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                r#"builtins.fetchurl {{ url = "https://example.invalid/missing"; sha256 = "{digest}"; name = "cached"; }}"#
            ),
            options,
        ),
        expected_path,
    );

    fs::remove_dir_all(source_dir).expect("source temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}
