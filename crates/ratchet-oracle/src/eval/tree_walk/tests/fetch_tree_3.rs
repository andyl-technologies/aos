//! Tree-walk evaluator tests: fetch tree (part 3).

use super::*;

#[test]
fn fetch_tree_git_input_returns_flake_lock_metadata() {
    let (repo_dir, _) = git_repo_with_file("fetch-tree-git");
    let repo = git2::Repository::open(&repo_dir).expect("git fixture repo opens");
    fs::write(
        repo_dir.join(".gitattributes"),
        b"ignored.txt export-ignore\n",
    )
    .expect("git attributes file writes");
    fs::write(repo_dir.join("ignored.txt"), b"ignored").expect("ignored file writes");
    let mut index = repo.index().expect("git index opens");
    for path in [".gitattributes", "ignored.txt"] {
        index
            .add_path(Path::new(path))
            .expect("git fixture path stages");
    }
    index.write().expect("git index writes");
    drop(index);
    let oid = git_commit_index(&repo, "export-ignore fixture commit", 1_700_000_060);
    let store_dir = unique_temp_dir("fetch-tree-git-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url_text = format!("file://{}", path_source(&repo_dir));
    let url = nix_string_literal(&url_text);
    let rev = oid.to_string();
    let public_keys_json = r#"[{"key":"abc","type":"ssh-ed25519"},{"key":"def","type":"ssh-rsa"}]"#;
    let public_keys_query = String::from_utf8(TreeWalk::percent_encode_flake_ref_query(
        public_keys_json.as_bytes(),
    ))
    .expect("publicKeys query is UTF-8");
    let combined_public_keys_json =
        r#"[{"key":"abc","type":"ssh-ed25519"},{"key":"def","type":"ssh-ed25519"}]"#;
    let combined_public_keys_query = String::from_utf8(TreeWalk::percent_encode_flake_ref_query(
        combined_public_keys_json.as_bytes(),
    ))
    .expect("combined publicKeys query is UTF-8");

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let
                  shallow = builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; }};
                  noExportIgnore = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    exportIgnore = false;
                  }};
                  dirty = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    dirtyRev = "{rev}-dirty";
                    dirtyShortRev = "dirty-lock";
                  }};
                  full = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    shallow = false;
                    revCount = 2;
                  }};
                  publicKey = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKey = "abc";
                  }};
                  publicKeys = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [ {{ type = "ssh-ed25519"; key = "abc"; }} ];
                  }};
                  emptyPublicKeys = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [];
                    publicKey = "abc";
                  }};
                  combinedPublicKeys = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [ {{ type = "ssh-ed25519"; key = "abc"; }} ];
                    publicKey = "def";
                  }};
                  multiPublicKeys = builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [
                      {{ type = "ssh-ed25519"; key = "abc"; }}
                      {{ type = "ssh-rsa"; key = "def"; }}
                    ];
                  }};
                in {{
                  keys = builtins.attrNames shallow;
                  rev = shallow.rev;
                  shortRev = shallow.shortRev;
                  submodules = shallow.submodules;
                  hasRevCount = shallow ? revCount;
                  data = builtins.readFile "${{shallow.outPath}}/data.txt";
                  ignored = builtins.pathExists "${{shallow.outPath}}/ignored.txt";
                  noExportIgnored = builtins.readFile "${{noExportIgnore.outPath}}/ignored.txt";
                  dirtyKeys = builtins.attrNames dirty;
                  dirtyRev = dirty.dirtyRev;
                  dirtyShortRev = dirty.dirtyShortRev;
                  dirtyHasRev = dirty ? rev;
                  fullRevCount = full.revCount;
                  publicKeyData = builtins.readFile "${{publicKey.outPath}}/data.txt";
                  publicKeysData = builtins.readFile "${{publicKeys.outPath}}/data.txt";
                  emptyPublicKeysData = builtins.readFile "${{emptyPublicKeys.outPath}}/data.txt";
                  combinedPublicKeysData = builtins.readFile "${{combinedPublicKeys.outPath}}/data.txt";
                  multiPublicKeysData = builtins.readFile "${{multiPublicKeys.outPath}}/data.txt";
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree git JSON parses");
    assert_eq!(
        value["keys"],
        serde_json::json!([
            "lastModified",
            "lastModifiedDate",
            "narHash",
            "outPath",
            "rev",
            "shortRev",
            "submodules"
        ])
    );
    assert_eq!(value["rev"], rev);
    assert_eq!(value["shortRev"], &rev[..7]);
    assert_eq!(value["submodules"], false);
    assert_eq!(value["hasRevCount"], false);
    assert_eq!(value["data"], "git-data");
    assert_eq!(value["ignored"], false);
    assert_eq!(value["noExportIgnored"], "ignored");
    assert_eq!(
        value["dirtyKeys"],
        serde_json::json!([
            "dirtyRev",
            "dirtyShortRev",
            "lastModified",
            "lastModifiedDate",
            "narHash",
            "outPath",
            "submodules"
        ])
    );
    assert_eq!(value["dirtyRev"], format!("{rev}-dirty"));
    assert_eq!(value["dirtyShortRev"], "dirty-lock");
    assert_eq!(value["dirtyHasRev"], false);
    assert_eq!(value["fullRevCount"], 2);
    assert_eq!(value["publicKeyData"], "git-data");
    assert_eq!(value["publicKeysData"], "git-data");
    assert_eq!(value["emptyPublicKeysData"], "git-data");
    assert_eq!(value["combinedPublicKeysData"], "git-data");
    assert_eq!(value["multiPublicKeysData"], "git-data");

    let mut pure_options = options.clone();
    pure_options.set_eval_mode(EvalMode::Pure);
    let pure_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; }};
                in x.rev
                "#
        ),
        pure_options,
    );
    assert_eq!(
        pure_json,
        serde_json::to_vec(&rev).expect("rev JSON serializes")
    );

    let restricted_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted fetchTree git rejects disallowed canonical URI");
    assert!(matches!(
        restricted_error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    let mut restricted_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    restricted_options.set_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_uri(format!("git+{url_text}?rev={rev}&shallow=1&exportIgnore=1").into_bytes())
        .expect("git allowed URI configures");
    let restricted_json = eval_json_bytes_with_options(
        &format!(
            r#"let x = builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; }}; in x.rev"#
        ),
        restricted_options,
    );
    assert_eq!(
        restricted_json,
        serde_json::to_vec(&rev).expect("rev JSON serializes")
    );

    let restricted_keyed_error = eval_whnf_owned_with_options(
            &lower(&format!(
                r#"builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; verifyCommit = false; publicKey = "abc"; }}"#
            )),
            TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
        )
        .expect_err("restricted keyed fetchTree git rejects disallowed canonical URI");
    assert!(matches!(
        restricted_keyed_error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!(
            "git+{url_text}?keytype=ssh-ed25519&publicKey=abc&rev={rev}&shallow=1&exportIgnore=1"
        ).as_bytes()
    ));

    let restricted_empty_keyed_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [];
                    publicKey = "abc";
                }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted empty publicKeys fetchTree git uses singular key URI");
    assert!(matches!(
        restricted_empty_keyed_error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!(
            "git+{url_text}?keytype=ssh-ed25519&publicKey=abc&rev={rev}&shallow=1&exportIgnore=1"
        ).as_bytes()
    ));

    let restricted_combined_keyed_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [ {{ type = "ssh-ed25519"; key = "abc"; }} ];
                    publicKey = "def";
                }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted combined publicKeys fetchTree git appends singular key");
    assert!(matches!(
        restricted_combined_keyed_error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!(
            "git+{url_text}?publicKeys={combined_public_keys_query}&rev={rev}&shallow=1&exportIgnore=1"
        ).as_bytes()
    ));

    let restricted_multi_keyed_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{
                    type = "git";
                    url = {url};
                    rev = "{rev}";
                    verifyCommit = false;
                    publicKeys = [
                      {{ type = "ssh-ed25519"; key = "abc"; }}
                      {{ type = "ssh-rsa"; key = "def"; }}
                    ];
                }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted multi-key fetchTree git rejects disallowed canonical URI");
    assert!(matches!(
        restricted_multi_keyed_error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!(
            "git+{url_text}?publicKeys={public_keys_query}&rev={rev}&shallow=1&exportIgnore=1"
        ).as_bytes()
    ));

    let mut restricted_keyed_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    restricted_keyed_options.set_eval_mode(EvalMode::Restricted);
    restricted_keyed_options
            .add_allowed_uri(
                format!(
                    "git+{url_text}?keytype=ssh-ed25519&publicKey=abc&rev={rev}&shallow=1&exportIgnore=1"
                )
                .into_bytes(),
            )
            .expect("keyed git allowed URI configures");
    let restricted_keyed_json = eval_json_bytes_with_options(
        &format!(
            r#"let x = builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; verifyCommit = false; publicKey = "abc"; }}; in x.rev"#
        ),
        restricted_keyed_options,
    );
    assert_eq!(
        restricted_keyed_json,
        serde_json::to_vec(&rev).expect("rev JSON serializes")
    );

    let verified_error = eval_whnf_owned_with_options(
            &lower(&format!(
                r#"builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; verifyCommit = true; publicKey = "abc"; }}"#
            )),
            options.clone(),
        )
        .expect_err("verified fetchTree git remains unsupported");
    assert!(matches!(
        verified_error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeFeature {
            feature: "verified git fetches",
            ..
        }
    ));

    let last_modified_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; lastModified = 1700000061; }}"#
        )),
        options.clone(),
    )
    .expect_err("direct git fetchTree rejects mismatched lastModified");
    assert!(matches!(
        last_modified_error.kind(),
        TreeWalkErrorKind::FetchTreeLastModifiedMismatch {
            expected: 1_700_000_061,
            actual: 1_700_000_060,
            ..
        }
    ));

    let rev_count_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchTree {{ type = "git"; url = {url}; rev = "{rev}"; revCount = 3; }}"#
        )),
        options,
    )
    .expect_err("direct git fetchTree rejects mismatched revCount");
    assert!(matches!(
        rev_count_error.kind(),
        TreeWalkErrorKind::FetchTreeRevCountMismatch {
            expected: 3,
            actual: 2,
            ..
        }
    ));

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_git_string_ref_returns_flake_lock_metadata() {
    let (repo_dir, _) = git_repo_with_file("fetch-tree-git-string");
    let repo = git2::Repository::open(&repo_dir).expect("git fixture repo opens");
    let oid = repo
        .head()
        .expect("git fixture HEAD exists")
        .target()
        .expect("git fixture HEAD targets a commit");
    let store_dir = unique_temp_dir("fetch-tree-git-string-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let rev = oid.to_string();
    let raw_git_ref = format!("git+file://{}?rev={rev}", path_source(&repo_dir));
    let git_ref = nix_string_literal(&raw_git_ref);
    let raw_keyed_git_ref = format!(
        "git+file://{}?rev={rev}&publicKey=abc",
        path_source(&repo_dir)
    );
    let keyed_git_ref = nix_string_literal(&raw_keyed_git_ref);

    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let evaluator = TreeWalk::new(&ir);
    let attrs = TreeWalk::parse_flake_ref_attrs(ir.root, span, raw_keyed_git_ref.as_bytes())
        .expect("keyed git flake ref parses");
    let arguments = evaluator
        .fetch_tree_flake_ref_arguments(ir.root, span, raw_keyed_git_ref.as_bytes(), &attrs)
        .expect("keyed git flake ref lowers to fetchTree arguments");
    let FetchTreeArguments::Git { args, .. } = arguments else {
        panic!("keyed git flake ref lowers to git arguments");
    };
    assert_eq!(
        args.url,
        format!("file://{}", path_source(&repo_dir)).as_bytes()
    );
    assert_eq!(args.transport_url, None);
    assert_eq!(
        TreeWalk::fetch_tree_git_canonical_uri(&args),
        format!(
            "git+file://{}?keytype=ssh-ed25519&publicKey=abc&rev={rev}&shallow=1&exportIgnore=1",
            path_source(&repo_dir)
        )
        .into_bytes()
    );

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchTree {git_ref};
                    keyed = builtins.fetchTree {keyed_git_ref};
                in {{
                  data = builtins.readFile "${{x.outPath}}/data.txt";
                  keyedData = builtins.readFile "${{keyed.outPath}}/data.txt";
                  rev = x.rev;
                  keyedRev = keyed.rev;
                  shortRev = x.shortRev;
                  submodules = x.submodules;
                  narHash = x.narHash;
                  lastModified = x.lastModified;
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchTree git string JSON parses");
    assert_eq!(value["data"], "git-data");
    assert_eq!(value["keyedData"], "git-data");
    assert_eq!(value["rev"], rev);
    assert_eq!(value["keyedRev"], rev);
    assert_eq!(value["shortRev"], &rev[..7]);
    assert_eq!(value["submodules"], false);
    assert_eq!(value["lastModified"], 1_700_000_000);
    let nar_hash = value["narHash"]
        .as_str()
        .expect("fetchTree git result exposes narHash");
    let nar_hash_query =
        url::form_urlencoded::byte_serialize(nar_hash.as_bytes()).collect::<String>();

    let locked_metadata_ref = nix_string_literal(&format!(
        "git+file://{}?rev={rev}&narHash={nar_hash_query}&lastModified=1700000000&revCount=1&shallow=0",
        path_source(&repo_dir)
    ));
    let locked_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchTree {locked_metadata_ref};
                in {{
                  data = builtins.readFile "${{x.outPath}}/data.txt";
                  rev = x.rev;
                  revCount = x.revCount;
                  lastModified = x.lastModified;
                  narHash = x.narHash;
                }}
                "#
        ),
        options.clone(),
    );
    let locked_value: serde_json::Value =
        serde_json::from_slice(&locked_json).expect("locked fetchTree git string JSON parses");
    assert_eq!(locked_value["data"], "git-data");
    assert_eq!(locked_value["rev"], rev);
    assert_eq!(locked_value["revCount"], 1);
    assert_eq!(locked_value["lastModified"], 1_700_000_000);
    assert_eq!(locked_value["narHash"], nar_hash);

    let mismatched_metadata_ref = nix_string_literal(&format!(
        "git+file://{}?rev={rev}&narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&lastModified=1700000001&revCount=2&shallow=0",
        path_source(&repo_dir)
    ));
    let mismatched_error = eval_whnf_owned_with_options(
        &lower(&format!(r#"builtins.fetchTree {mismatched_metadata_ref}"#)),
        options.clone(),
    )
    .expect_err("mismatched fetchTree git narHash rejects");
    assert!(matches!(
        mismatched_error.kind(),
        TreeWalkErrorKind::FetchTreeHashMismatch { .. }
    ));

    let mut pure_options = options.clone();
    pure_options.set_eval_mode(EvalMode::Pure);
    let pure_json = eval_json_bytes_with_options(
        &format!(r#"let x = builtins.fetchTree {git_ref}; in x.rev"#),
        pure_options,
    );
    assert_eq!(
        pure_json,
        serde_json::to_vec(&rev).expect("rev JSON serializes")
    );

    let restricted_error = eval_whnf_owned_with_options(
        &lower(&format!(r#"builtins.fetchTree {git_ref}"#)),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted fetchTree git string rejects disallowed canonical URI");
    assert!(matches!(
        restricted_error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    let mut restricted_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    restricted_options.set_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_uri(
            format!(
                "git+file://{}?rev={rev}&shallow=1&exportIgnore=1",
                path_source(&repo_dir)
            )
            .into_bytes(),
        )
        .expect("git string allowed URI configures");
    let restricted_json = eval_json_bytes_with_options(
        &format!(r#"let x = builtins.fetchTree {git_ref}; in x.rev"#),
        restricted_options,
    );
    assert_eq!(
        restricted_json,
        serde_json::to_vec(&rev).expect("rev JSON serializes")
    );

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}
