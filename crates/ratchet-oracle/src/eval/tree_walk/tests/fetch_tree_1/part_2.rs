//! Split-out tests (part_2). See parent module.

use super::*;

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
