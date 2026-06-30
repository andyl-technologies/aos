//! Tree-walk evaluator tests: fetch tree (part 1).

use super::*;
use crate::cache::{
    DurableBlake3Hash, PARSE_CACHE_SCHEMA_VERSION, ParseCache, ParseCacheFlags, ParseCacheKey,
    ParseFileKey, PersistCache, PersistFileArtifactKey,
};
use crate::string::NixString;

#[test]
fn fetch_tree_path_input_returns_locked_tree_metadata() {
    let dir = unique_temp_dir("fetch-tree-path");
    let source_dir = dir.join("source");
    fs::create_dir(&source_dir).expect("source directory creates");
    fs::write(source_dir.join("file.txt"), b"path-data").expect("source file writes");
    fs::create_dir(source_dir.join("sub")).expect("source subdirectory creates");
    fs::write(source_dir.join("sub").join("nested.txt"), b"nested")
        .expect("source nested file writes");
    let store_dir = unique_temp_dir("fetch-tree-path-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let path = nix_string_literal(&path_source(&source_dir));

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchTree {{ type = "path"; path = {path}; }};
                in {{
                  keys = builtins.attrNames x;
                  data = builtins.readFile "${{x.outPath}}/file.txt";
                  nested = builtins.readFile "${{x.outPath}}/sub/nested.txt";
                  narHash = x.narHash;
                  pathValue = x.outPath;
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree path JSON parses");
    assert_eq!(
        value["keys"],
        serde_json::json!(["lastModified", "lastModifiedDate", "narHash", "outPath"])
    );
    assert_eq!(value["data"], "path-data");
    assert_eq!(value["nested"], "nested");
    assert!(
        value["narHash"]
            .as_str()
            .expect("narHash is a string")
            .starts_with("sha256-")
    );
    assert!(
        value["pathValue"]
            .as_str()
            .expect("pathValue is a string")
            .starts_with(path_source(&store_dir).as_str())
    );

    let nar_hash = value["narHash"].as_str().expect("narHash is a string");
    let denied_pure_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "path"; path = {path}; narHash = "{nar_hash}"; }}"#
        )),
        {
            let mut options = options.clone();
            options.set_eval_mode(EvalMode::Pure);
            options
        },
    )
    .expect_err("pure fetchTree path requires an allowed source path");
    assert!(matches!(
        denied_pure_error.kind(),
        TreeWalkErrorKind::PathAccessDenied {
            path: denied,
            mode: EvalMode::Pure,
            ..
        } if denied.as_slice() == source_dir.as_os_str().as_bytes()
    ));

    let mut pure_options = options.clone();
    pure_options.set_eval_mode(EvalMode::Pure);
    pure_options
        .add_allowed_path(source_dir.as_os_str().as_bytes().to_vec())
        .expect("pure fetchTree source path configures as allowed");
    let pure_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchTree {{ type = "path"; path = {path}; narHash = "{nar_hash}"; }};
                in x.narHash
                "#
        ),
        pure_options,
    );
    assert_eq!(
        pure_json,
        serde_json::to_vec(nar_hash).expect("narHash JSON serializes")
    );

    let error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "path"; path = {path}; }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure fetchTree path requires narHash");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeLockedInputRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    fs::remove_dir_all(dir).expect("source temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn configured_import_cache_preserves_fetch_tree_path_store_path_surface() {
    fn evaluate_fetch_tree_surface(
        source: &str,
        options: TreeWalkOptions,
    ) -> (Vec<u8>, (usize, usize)) {
        let ir = lower(source);
        let mut evaluator = TreeWalk::with_options(&ir, options);
        let value = evaluator
            .eval_root()
            .expect("fetchTree expression evaluates");
        let import_stats = evaluator.import_parse_cache_stats();
        let output = evaluator
            .heap()
            .get_string(value)
            .expect("fetchTree outPath is a string")
            .bytes()
            .to_vec();
        (output, import_stats)
    }

    fn checked_store_path(output: &[u8], store_dir: &Path) -> PathBuf {
        let path = PathBuf::from(std::str::from_utf8(output).expect("store path is UTF-8"));
        assert!(
            path.starts_with(store_dir),
            "fetchTree store path {path:?} should stay under configured store dir {store_dir:?}"
        );
        path
    }

    fn assert_materialized_fetch_tree_file(output: &[u8], store_dir: &Path) {
        let path = checked_store_path(output, store_dir);
        assert_eq!(
            fs::read(path.join("file.txt")).expect("fetchTree materializes fixture file"),
            b"path-data"
        );
        assert_eq!(
            fs::read(path.join("sub").join("nested.txt"))
                .expect("fetchTree materializes nested fixture file"),
            b"nested"
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

    let root = fs::canonicalize(unique_temp_dir(
        "import-cache-fetch-tree-path-surface-parity",
    ))
    .expect("temp directory canonicalizes");
    let source_dir = root.join("source");
    fs::create_dir(&source_dir).expect("source directory creates");
    fs::write(source_dir.join("file.txt"), b"path-data").expect("source file writes");
    fs::create_dir(source_dir.join("sub")).expect("source subdirectory creates");
    fs::write(source_dir.join("sub").join("nested.txt"), b"nested")
        .expect("source nested file writes");
    let first_parse_root = root.join("first-parse-cache");
    let second_parse_root = root.join("second-parse-cache");
    let persist_root = root.join("persist-cache");
    let store_dir = root.join("store");
    fs::create_dir(&store_dir).expect("store directory creates");
    let import_path = root.join("fetch-tree-path.nix");
    let source_path = path_source(&source_dir);
    let imported_source = nix_string_literal(&source_path).into_bytes();
    fs::write(&import_path, &imported_source).expect("fetchTree path import writes");
    let import_realpath = fs::canonicalize(&import_path).expect("import path canonicalizes");
    let source = format!(
        r#"let x = builtins.fetchTree {{ type = "path"; path = import {}; }}; in x.outPath"#,
        import_path.display()
    );

    let mut uncached_options = TreeWalkOptions::with_store_dir(path_bytes(&store_dir))
        .expect("store directory configures");
    uncached_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    let (uncached_output, uncached_stats) = evaluate_fetch_tree_surface(&source, uncached_options);
    assert_eq!(uncached_stats, (0, 0));
    assert!(
        uncached_output.ends_with(b"-source"),
        "fetchTree path surface should expose the default source name: {uncached_output:?}"
    );
    assert_materialized_fetch_tree_file(&uncached_output, &store_dir);
    remove_store_path(&uncached_output, &store_dir);

    let mut miss_options = TreeWalkOptions::with_store_dir(path_bytes(&store_dir))
        .expect("store directory configures");
    miss_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    miss_options.set_parse_cache_root(&first_parse_root);
    miss_options.set_persist_cache_root(&persist_root);
    let (miss_output, miss_stats) = evaluate_fetch_tree_surface(&source, miss_options);
    assert_eq!(miss_stats, (0, 1));
    assert_eq!(miss_output, uncached_output);
    assert_materialized_fetch_tree_file(&miss_output, &store_dir);
    remove_store_path(&miss_output, &store_dir);

    let mut hit_options = TreeWalkOptions::with_store_dir(path_bytes(&store_dir))
        .expect("store directory configures");
    hit_options
        .set_path_literal_base(root.as_os_str().as_bytes().to_vec())
        .expect("path base configures");
    hit_options.set_parse_cache_root(&second_parse_root);
    hit_options.set_persist_cache_root(&persist_root);
    let (hit_output, hit_stats) = evaluate_fetch_tree_surface(&source, hit_options);
    assert_eq!(hit_stats, (1, 0));
    assert_eq!(hit_output, uncached_output);
    assert_materialized_fetch_tree_file(&hit_output, &store_dir);
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
        "fetchTree canary import should materialize a persistent file-artifact mapping"
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
        file_key.content_hash().as_durable_hash(),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "fetchTree file payload BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(b"path-data"),
    ));
    canaries.extend(durable_hash_surface_canaries(
        "fetchTree nested payload BLAKE3 sentinel",
        DurableBlake3Hash::for_bytes(b"nested"),
    ));
    canaries.extend(hot_string_surface_canaries(
        "fetchTree source path",
        source_path.as_bytes(),
    ));
    canaries.extend(hot_string_surface_canaries(
        "fetchTree source name",
        b"source",
    ));

    for (surface_name, output) in [
        ("cache-disabled fetchTree path surface", &uncached_output),
        ("persistent miss fetchTree path surface", &miss_output),
        ("persistent hit fetchTree path surface", &hit_output),
    ] {
        assert_surface_canaries_absent(surface_name, "store path", output, &canaries);
    }

    fs::remove_dir_all(root).expect("temp directory removes");
}

#[test]
fn fetch_tree_file_and_tarball_inputs_materialize_expected_store_paths() {
    let (file_dir, file_path) = temp_file_with_bytes("fetch-tree-file", b"plain-data");
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tree-tarball");
    let store_dir = unique_temp_dir("fetch-tree-file-tarball-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let file_url = nix_string_literal(&format!("file://{}", path_source(&file_path)));
    let tarball_url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let recursive_digest = "da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2";

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let
                  file = builtins.fetchTree {{ type = "file"; url = {file_url}; }};
                  fileUnpack = builtins.fetchTree {{ type = "file"; url = {file_url}; unpack = true; }};
                  tarball = builtins.fetchTree {{
                    type = "tarball";
                    url = {tarball_url};
                    narHash = "{recursive_digest}";
                    rev = "abcdef1234567890";
                    revCount = 7;
                  }};
                  tarballNoUnpack = builtins.fetchTree {{
                    type = "tarball";
                    url = {tarball_url};
                    narHash = "{recursive_digest}";
                    unpack = false;
                  }};
                in {{
                  fileKeys = builtins.attrNames file;
                  fileData = builtins.readFile file.outPath;
                  fileUnpackData = builtins.readFile fileUnpack.outPath;
                  tarballKeys = builtins.attrNames tarball;
                  tarballData = builtins.readFile "${{tarball.outPath}}/file.txt";
                  tarballNested = builtins.readFile "${{tarball.outPath}}/sub/nested.txt";
                  tarballNoUnpackData = builtins.readFile "${{tarballNoUnpack.outPath}}/file.txt";
                  tarballRev = tarball.rev;
                  tarballShortRev = tarball.shortRev;
                  tarballRevCount = tarball.revCount;
                }}
                "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree file/tarball JSON parses");
    assert_eq!(value["fileKeys"], serde_json::json!(["narHash", "outPath"]));
    assert_eq!(value["fileData"], "plain-data");
    assert_eq!(value["fileUnpackData"], "plain-data");
    assert_eq!(
        value["tarballKeys"],
        serde_json::json!([
            "lastModified",
            "lastModifiedDate",
            "narHash",
            "outPath",
            "rev",
            "revCount",
            "shortRev"
        ])
    );
    assert_eq!(value["tarballData"], "data");
    assert_eq!(value["tarballNested"], "inner");
    assert_eq!(value["tarballNoUnpackData"], "data");
    assert_eq!(value["tarballRev"], "abcdef1234567890");
    assert_eq!(value["tarballShortRev"], "abcdef1");
    assert_eq!(value["tarballRevCount"], 7);

    let error = eval_whnf_owned(&lower(&format!(
            r#"builtins.fetchTree {{ type = "tarball"; url = {tarball_url}; narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="; }}"#
        )))
        .expect_err("wrong fetchTree tarball hash rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeHashMismatch { .. }
    ));

    fs::remove_dir_all(file_dir).expect("file temp directory removes");
    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_direct_path_and_tarball_reject_last_modified_mismatch() {
    fn current_unix_seconds() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock is after Unix epoch")
                .as_secs(),
        )
        .expect("current Unix time fits in Nix int")
    }

    fn mismatched_timestamp(actual: i64) -> i64 {
        actual
            .checked_add(31_536_000)
            .unwrap_or(actual - 31_536_000)
    }

    fn append_future_tar_bytes<W: std::io::Write>(
        builder: &mut tar::Builder<W>,
        path: &str,
        mode: u32,
        bytes: &[u8],
        mtime: i64,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_path(path).expect("tar path is valid");
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_mtime(u64::try_from(mtime).expect("test mtime is non-negative"));
        header.set_cksum();
        builder
            .append(&header, bytes)
            .expect("tar fixture entry appends");
    }

    let dir = unique_temp_dir("fetch-tree-metadata-mismatch");
    let source_dir = dir.join("source");
    fs::create_dir(&source_dir).expect("source directory creates");
    fs::write(source_dir.join("file.txt"), b"path-data").expect("source file writes");
    let future_tarball_last_modified = current_unix_seconds()
        .checked_add(31_536_000)
        .expect("future test mtime fits in Nix int");
    let archive_dir = unique_temp_dir("fetch-tree-metadata-tarball");
    let archive_path = archive_dir.join("root.tar.gz");
    let file = fs::File::create(&archive_path).expect("tarball fixture creates");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    append_future_tar_bytes(
        &mut builder,
        "root/file.txt",
        0o644,
        b"data",
        future_tarball_last_modified,
    );
    append_future_tar_bytes(
        &mut builder,
        "root/sub/nested.txt",
        0o644,
        b"inner",
        future_tarball_last_modified,
    );
    let encoder = builder.into_inner().expect("tar fixture finalizes");
    encoder.finish().expect("gzip fixture finalizes");
    let store_dir = unique_temp_dir("fetch-tree-metadata-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let path = nix_string_literal(&path_source(&source_dir));
    let tarball_url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let
                  pathTree = builtins.fetchTree {{ type = "path"; path = {path}; }};
                  tarballTree = builtins.fetchTree {{ type = "tarball"; url = {tarball_url}; }};
                in {{
                  pathLastModified = pathTree.lastModified;
                  tarballLastModified = tarballTree.lastModified;
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree metadata JSON parses");
    let path_last_modified = value["pathLastModified"]
        .as_i64()
        .expect("path lastModified is an integer");
    let tarball_last_modified = value["tarballLastModified"]
        .as_i64()
        .expect("tarball lastModified is an integer");
    assert_eq!(tarball_last_modified, future_tarball_last_modified);
    let wrong_path_last_modified = mismatched_timestamp(path_last_modified);
    let wrong_tarball_last_modified = mismatched_timestamp(tarball_last_modified);

    let error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "path"; path = {path}; lastModified = {wrong_path_last_modified}; }}"#
        )),
        options.clone(),
    )
    .expect_err("direct path fetchTree rejects mismatched lastModified");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeLastModifiedMismatch {
            expected,
            actual,
            ..
        } if expected == wrong_path_last_modified && actual == path_last_modified
    ));

    let error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "tarball"; url = {tarball_url}; lastModified = {wrong_tarball_last_modified}; }}"#
        )),
        options,
    )
    .expect_err("direct tarball fetchTree rejects mismatched lastModified");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeLastModifiedMismatch {
            expected,
            actual,
            ..
        } if expected == wrong_tarball_last_modified && actual == future_tarball_last_modified
    ));

    fs::remove_dir_all(dir).expect("source temp directory removes");
    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_file_http_input_uses_identity_bytes() {
    let (url, body_hash, handle) = gzip_encoded_http_fixture("/tree-data.bin", b"abc");
    let url = nix_string_literal(&url);
    let store_dir = unique_temp_dir("fetch-tree-http-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");

    assert_eq!(
        eval_string_bytes_with_options(
            &format!(
                r#"
                    let x = builtins.fetchTree {{ type = "file"; url = {url}; }};
                    in builtins.hashFile "sha256" x.outPath
                    "#
            ),
            options,
        ),
        body_hash.as_bytes()
    );
    fs::remove_dir_all(store_dir).expect("store temp directory removes");

    assert_http_fixture_requested_identity(
        handle.join().expect("HTTP fixture thread completes"),
        "fetchTree",
    );
}

#[test]
fn fetch_tree_string_refs_dispatch_to_supported_inputs() {
    let dir = unique_temp_dir("fetch-tree-string-refs");
    let source_dir = dir.join("source");
    fs::create_dir(&source_dir).expect("source directory creates");
    fs::write(source_dir.join("file.txt"), b"path-data").expect("source file writes");
    let (file_dir, file_path) = temp_file_with_bytes("fetch-tree-string-file", b"plain-data");
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tree-string-tarball");
    let store_dir = unique_temp_dir("fetch-tree-string-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let path_ref = nix_string_literal(&format!("path:{}", path_source(&source_dir)));
    let file_ref = nix_string_literal(&format!("file+file://{}", path_source(&file_path)));
    let tarball_ref = nix_string_literal(&format!(
        "file://{}?lastModified=1&narHash=da1b902a95e82957778f23ddd9648dbe96983d13155a63a4f9e84265536adca2&rev=abcdef1234567890&revCount=7",
        path_source(&archive_path)
    ));

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let
                  pathTree = builtins.fetchTree {path_ref};
                  fileTree = builtins.fetchTree {file_ref};
                  tarballTree = builtins.fetchTree {tarball_ref};
                in {{
                  pathData = builtins.readFile "${{pathTree.outPath}}/file.txt";
                  fileData = builtins.readFile fileTree.outPath;
                  tarballData = builtins.readFile "${{tarballTree.outPath}}/file.txt";
                  tarballRev = tarballTree.rev;
                  tarballShortRev = tarballTree.shortRev;
                  tarballRevCount = tarballTree.revCount;
                  tarballLastModified = tarballTree.lastModified;
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree string ref JSON parses");
    assert_eq!(value["pathData"], "path-data");
    assert_eq!(value["fileData"], "plain-data");
    assert_eq!(value["tarballData"], "data");
    assert_eq!(value["tarballRev"], "abcdef1234567890");
    assert_eq!(value["tarballShortRev"], "abcdef1");
    assert_eq!(value["tarballRevCount"], 7);
    assert_eq!(value["tarballLastModified"], 1);

    let bare_path_ref = nix_string_literal(&path_source(&source_dir));
    let error = eval_whnf_owned_with_options(
        &lower(&format!(r#"builtins.fetchTree {bare_path_ref}"#)),
        options,
    )
    .expect_err("bare absolute path string fetchTree rejects");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));

    fs::remove_dir_all(dir).expect("source temp directory removes");
    fs::remove_dir_all(file_dir).expect("file temp directory removes");
    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_refs_reroot_dir_metadata() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tree-string-dir-tarball");
    let (repo_dir, _) = git_repo_with_file("fetch-tree-string-dir-git");
    let repo = git2::Repository::open(&repo_dir).expect("git fixture repo opens");
    let oid = git_commit_file(&repo, "sub/nested.txt", b"git-subdir", 1_700_000_120);
    let store_dir = unique_temp_dir("fetch-tree-string-dir-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let tarball_url = nix_string_literal(&format!("file://{}", path_source(&archive_path)));
    let tarball_ref = nix_string_literal(&format!("file://{}?dir=sub", path_source(&archive_path)));
    let raw_git_ref = format!("git+file://{}?dir=sub&rev={}", path_source(&repo_dir), oid);
    let git_ref = nix_string_literal(&raw_git_ref);
    let git_url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let expected_git_url = format!("file://{}?dir=sub", path_source(&repo_dir));
    let expected_git_transport_url = format!("file://{}", path_source(&repo_dir));
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let evaluator = TreeWalk::new(&ir);
    let attrs = TreeWalk::parse_flake_ref_attrs(ir.root, span, raw_git_ref.as_bytes())
        .expect("git dir flake ref parses");
    let arguments = evaluator
        .fetch_tree_flake_ref_arguments(ir.root, span, raw_git_ref.as_bytes(), &attrs)
        .expect("git dir flake ref lowers to fetchTree arguments");
    let FetchTreeArguments::Git { args, .. } = arguments else {
        panic!("git dir flake ref lowers to git arguments");
    };
    assert_eq!(args.url, expected_git_url.as_bytes());
    assert_eq!(
        args.transport_url.as_deref(),
        Some(expected_git_transport_url.as_bytes())
    );

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let
                  tarballTree = builtins.fetchTree {tarball_ref};
                  directTarballTree = builtins.fetchTree {{ type = "tarball"; url = {tarball_url}; dir = "sub"; }};
                  gitTree = builtins.fetchTree {git_ref};
                  directGitTree = builtins.fetchTree {{ type = "git"; url = {git_url}; rev = "{oid}"; dir = "sub"; }};
                in {{
                  tarballNested = builtins.readFile "${{tarballTree.outPath}}/nested.txt";
                  directTarballNested = builtins.readFile "${{directTarballTree.outPath}}/nested.txt";
                  tarballRootFile = builtins.pathExists "${{tarballTree.outPath}}/file.txt";
                  tarballSubNested = builtins.pathExists "${{tarballTree.outPath}}/sub/nested.txt";
                  gitNested = builtins.readFile "${{gitTree.outPath}}/nested.txt";
                  directGitNested = builtins.readFile "${{directGitTree.outPath}}/nested.txt";
                  gitRootData = builtins.pathExists "${{gitTree.outPath}}/data.txt";
                  gitSubNested = builtins.pathExists "${{gitTree.outPath}}/sub/nested.txt";
                  gitRev = gitTree.rev;
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree dir string ref JSON parses");
    assert_eq!(value["tarballNested"], "inner");
    assert_eq!(value["directTarballNested"], "inner");
    assert_eq!(value["tarballRootFile"], false);
    assert_eq!(value["tarballSubNested"], false);
    assert_eq!(value["gitNested"], "git-subdir");
    assert_eq!(value["directGitNested"], "git-subdir");
    assert_eq!(value["gitRootData"], false);
    assert_eq!(value["gitSubNested"], false);
    assert_eq!(value["gitRev"], oid.to_string());

    let escaping_dir_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "tarball"; url = {tarball_url}; dir = "../root"; }}"#
        )),
        options.clone(),
    )
    .expect_err("fetchTree dir cannot escape the fetched tree");
    assert!(matches!(
        escaping_dir_error.kind(),
        TreeWalkErrorKind::FetchTree { .. }
    ));

    let missing_dir_ref = nix_string_literal(&format!(
        "git+file://{}?dir=missing&rev={}",
        path_source(&repo_dir),
        oid
    ));
    let missing_dir_error = eval_whnf_owned_with_options(
        &lower(&format!(r#"builtins.fetchTree {missing_dir_ref}"#)),
        options.clone(),
    )
    .expect_err("fetchTree dir must exist");
    assert!(matches!(
        missing_dir_error.kind(),
        TreeWalkErrorKind::FetchTree { .. }
    ));

    let mut stripped_uri_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    stripped_uri_options.set_eval_mode(EvalMode::Restricted);
    stripped_uri_options
        .add_allowed_uri(
            format!(
                "git+file://{}?rev={oid}&shallow=1&exportIgnore=1",
                path_source(&repo_dir)
            )
            .into_bytes(),
        )
        .expect("stripped git allowed URI configures");
    let error = eval_whnf_owned_with_options(
        &lower(&format!(r#"builtins.fetchTree {git_ref}"#)),
        stripped_uri_options,
    )
    .expect_err("restricted fetchTree git dir requires original URI");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    let mut original_uri_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    original_uri_options.set_eval_mode(EvalMode::Restricted);
    original_uri_options
        .add_allowed_uri(
            format!(
                "git+file://{}?dir=sub&rev={oid}&shallow=1&exportIgnore=1",
                path_source(&repo_dir)
            )
            .into_bytes(),
        )
        .expect("original git allowed URI configures");
    let restricted_json = eval_json_bytes_with_options(
        &format!(r#"let x = builtins.fetchTree {git_ref}; in x.rev"#),
        original_uri_options,
    );
    assert_eq!(
        restricted_json,
        serde_json::to_vec(&oid.to_string()).expect("rev JSON serializes")
    );

    let file_ref = nix_string_literal(&format!(
        "file+file://{}?dir=sub",
        path_source(&archive_path)
    ));
    let error = eval_whnf_owned_with_options(
        &lower(&format!(r#"builtins.fetchTree {file_ref}"#)),
        options,
    )
    .expect_err("fetchTree file refs reject dir metadata");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_dir_rejects_symlinked_intermediate_components() {
    let root = unique_temp_dir("fetch-tree-dir-symlink-root");
    let outside = unique_temp_dir("fetch-tree-dir-symlink-outside");
    fs::create_dir(root.join("sub")).expect("valid subdir creates");
    fs::create_dir(outside.join("nested")).expect("outside nested dir creates");
    std::os::unix::fs::symlink(&outside, root.join("link")).expect("symlink creates");

    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let valid =
        TreeWalk::fetch_tree_subdir_root(ir.root, span, b"fetchTree", &root, Some(b"./sub"))
            .expect("ordinary subdir resolves");
    assert_eq!(valid, root.join("sub"));

    let error =
        TreeWalk::fetch_tree_subdir_root(ir.root, span, b"fetchTree", &root, Some(b"link/nested"))
            .expect_err("intermediate symlink cannot escape fetched tree");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));

    fs::remove_dir_all(root).expect("root temp directory removes");
    fs::remove_dir_all(outside).expect("outside temp directory removes");
}
