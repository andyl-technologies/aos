//! Tree-walk evaluator tests: fetch git.

use super::*;

#[test]
fn fetch_git_primop_fetches_local_repo_and_returns_metadata() {
    let (repo_dir, oid) = git_repo_with_file("fetch-git");
    let store_dir = unique_temp_dir("fetch-git-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url_text = format!("file://{}", path_source(&repo_dir));
    let url = nix_string_literal(&url_text);
    let rev = oid.to_string();

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; rev = "{rev}"; }};
                in {{
                  names = builtins.attrNames x;
                  pathValue = x.outPath;
                  rev = x.rev;
                  shortRev = x.shortRev;
                  revCount = x.revCount;
                  lastModified = x.lastModified;
                  lastModifiedDate = x.lastModifiedDate;
                  narPrefix = builtins.substring 0 7 x.narHash;
                  submodules = x.submodules;
                  dir = builtins.readDir x;
                }}
                "#
        ),
        options.clone(),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("fetchGit metadata JSON parses");
    assert_eq!(
        value["names"],
        serde_json::json!([
            "lastModified",
            "lastModifiedDate",
            "narHash",
            "outPath",
            "rev",
            "revCount",
            "shortRev",
            "submodules"
        ])
    );
    assert_eq!(value["rev"], rev);
    assert_eq!(value["shortRev"], &rev[..7]);
    assert_eq!(value["revCount"], 1);
    assert_eq!(value["lastModified"], 1_700_000_000);
    assert_eq!(value["lastModifiedDate"], "20231114221320");
    assert_eq!(value["narPrefix"], "sha256-");
    assert_eq!(value["submodules"], false);
    assert_eq!(value["dir"], serde_json::json!({ "data.txt": "regular" }));
    let out_path = value["pathValue"].as_str().expect("outPath is a string");
    assert!(out_path.starts_with(&path_source(&store_dir)));
    assert!(out_path.ends_with("-source"));
    assert_eq!(
        fs::read(Path::new(out_path).join("data.txt")).expect("fetchGit materializes file"),
        b"git-data"
    );
    assert!(!Path::new(out_path).join(".git").exists());

    let context = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; rev = "{rev}"; }};
                in builtins.getContext (toString x)
                "#
        ),
        options,
    );
    let context: serde_json::Value =
        serde_json::from_slice(&context).expect("fetchGit context JSON parses");
    assert_eq!(context[out_path]["path"], true);

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_exports_dirty_local_worktrees() {
    let (repo_dir, oid) = git_repo_with_file("fetch-git-dirty");
    fs::write(repo_dir.join("data.txt"), b"dirty-data").expect("tracked file dirties");
    fs::write(repo_dir.join("extra.txt"), b"untracked").expect("untracked file writes");
    let store_dir = unique_temp_dir("fetch-git-dirty-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let head_rev = oid.to_string();

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; }};
                in {{
                  names = builtins.attrNames x;
                  rev = x.rev;
                  shortRev = x.shortRev;
                  dirtyRev = x.dirtyRev;
                  dirtyShortRev = x.dirtyShortRev;
                  revCount = x.revCount;
                  data = builtins.readFile "${{x}}/data.txt";
                  extra = builtins.pathExists "${{x}}/extra.txt";
                }}
                "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("dirty fetchGit JSON parses");
    assert_eq!(
        value["names"],
        serde_json::json!([
            "dirtyRev",
            "dirtyShortRev",
            "lastModified",
            "lastModifiedDate",
            "narHash",
            "outPath",
            "rev",
            "revCount",
            "shortRev",
            "submodules"
        ])
    );
    assert_eq!(value["rev"], "0000000000000000000000000000000000000000");
    assert_eq!(value["shortRev"], "0000000");
    assert_eq!(value["dirtyRev"], format!("{head_rev}-dirty"));
    assert_eq!(value["dirtyShortRev"], format!("{}-dirty", &head_rev[..7]));
    assert_eq!(value["revCount"], 0);
    assert_eq!(value["data"], "dirty-data");
    assert_eq!(value["extra"], false);

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_honors_export_ignore_attributes() {
    let repo_dir = unique_temp_dir("fetch-git-export-ignore");
    let repo = git2::Repository::init(&repo_dir).expect("git fixture repo initializes");
    fs::write(
        repo_dir.join(".gitattributes"),
        b"ignored.txt export-ignore\nsub/ignored.txt export-ignore\nignored-dir/** export-ignore\n",
    )
    .expect("git attributes file writes");
    fs::write(repo_dir.join("included.txt"), b"included").expect("included file writes");
    fs::write(repo_dir.join("ignored.txt"), b"ignored").expect("ignored file writes");
    fs::create_dir(repo_dir.join("sub")).expect("subdirectory creates");
    fs::write(repo_dir.join("sub").join("included.txt"), b"sub-included")
        .expect("sub included file writes");
    fs::write(repo_dir.join("sub").join("ignored.txt"), b"sub-ignored")
        .expect("sub ignored file writes");
    fs::create_dir(repo_dir.join("ignored-dir")).expect("ignored directory creates");
    fs::write(
        repo_dir.join("ignored-dir").join("leaf.txt"),
        b"ignored-leaf",
    )
    .expect("ignored directory leaf writes");
    let mut index = repo.index().expect("git index opens");
    for path in [
        ".gitattributes",
        "included.txt",
        "ignored.txt",
        "sub/included.txt",
        "sub/ignored.txt",
        "ignored-dir/leaf.txt",
    ] {
        index
            .add_path(Path::new(path))
            .expect("git fixture path stages");
    }
    index.write().expect("git index writes");
    drop(index);
    let oid = git_commit_index(&repo, "fixture commit", 1_700_000_000);
    let store_dir = unique_temp_dir("fetch-git-export-ignore-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let rev = oid.to_string();

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; rev = "{rev}"; }};
                in {{
                  included = builtins.readFile "${{x}}/included.txt";
                  ignored = builtins.pathExists "${{x}}/ignored.txt";
                  subIncluded = builtins.readFile "${{x}}/sub/included.txt";
                  subIgnored = builtins.pathExists "${{x}}/sub/ignored.txt";
                  ignoredDir = builtins.pathExists "${{x}}/ignored-dir";
                }}
                "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("export-ignore fetchGit JSON parses");
    assert_eq!(value["included"], "included");
    assert_eq!(value["ignored"], false);
    assert_eq!(value["subIncluded"], "sub-included");
    assert_eq!(value["subIgnored"], false);
    assert_eq!(value["ignoredDir"], false);

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_resolves_ref_without_rev() {
    let (repo_dir, tagged_oid) = git_repo_with_tag("fetch-git-ref-without-rev");
    let repo = git2::Repository::open(&repo_dir).expect("git fixture repo opens");
    let head_oid = git_commit_file(&repo, "data.txt", b"head-data", 1_700_000_060);
    assert_ne!(tagged_oid, head_oid);
    let store_dir = unique_temp_dir("fetch-git-ref-without-rev-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let tagged_rev = tagged_oid.to_string();

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; ref = "refs/tags/v1"; }};
                in {{ rev = x.rev; data = builtins.readFile "${{x}}/data.txt"; }}
                "#
        ),
        options,
    );
    let value: serde_json::Value = serde_json::from_slice(&json).expect("ref fetchGit JSON parses");
    assert_eq!(value["rev"], tagged_rev);
    assert_eq!(value["data"], "git-data");

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_resolves_fetched_ref_without_local_name() {
    let repo_dir = unique_temp_dir("fetch-git-fetch-head-ref");
    let repo = git2::Repository::init(&repo_dir).expect("git fixture repo initializes");
    let custom_oid = git_commit_file(&repo, "data.txt", b"custom-data", 1_700_000_000);
    repo.reference("refs/custom/v1", custom_oid, false, "fixture custom ref")
        .expect("git fixture custom ref creates");
    let head_oid = git_commit_file(&repo, "data.txt", b"head-data", 1_700_000_060);
    assert_ne!(custom_oid, head_oid);
    let store_dir = unique_temp_dir("fetch-git-fetch-head-ref-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let custom_rev = custom_oid.to_string();

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; ref = "refs/custom/v1"; }};
                in {{ rev = x.rev; data = builtins.readFile "${{x}}/data.txt"; }}
                "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("custom-ref fetchGit JSON parses");
    assert_eq!(value["rev"], custom_rev);
    assert_eq!(value["data"], "custom-data");

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_formats_last_modified_date_as_utc() {
    let repo_dir = unique_temp_dir("fetch-git-utc-date");
    let repo = git2::Repository::init(&repo_dir).expect("git fixture repo initializes");
    let oid = git_commit_file_with_offset(&repo, "data.txt", b"git-data", 1_699_967_600, 540);
    let store_dir = unique_temp_dir("fetch-git-utc-date-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let rev = oid.to_string();

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{ url = {url}; rev = "{rev}"; }};
                in {{ lastModified = x.lastModified; lastModifiedDate = x.lastModifiedDate; }}
                "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("UTC-date fetchGit JSON parses");
    assert_eq!(value["lastModified"], 1_699_967_600);
    assert_eq!(value["lastModifiedDate"], "20231114131320");

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_honors_ref_and_submodules() {
    let (tagged_repo_dir, tagged_oid) = git_repo_with_tag("fetch-git-tagged");
    let tag_store_dir = unique_temp_dir("fetch-git-tagged-store");
    let tag_options =
        TreeWalkOptions::with_store_dir(tag_store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    let tag_url = nix_string_literal(&format!("file://{}", path_source(&tagged_repo_dir)));
    let tagged_rev = tagged_oid.to_string();
    let tagged_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{
                  url = {tag_url};
                  ref = "refs/tags/v1";
                  rev = "{tagged_rev}";
                  name = "tagged";
                }};
                in {{ rev = x.rev; pathValue = x.outPath; data = builtins.readFile "${{x}}/data.txt"; }}
                "#
        ),
        tag_options,
    );
    let tagged_value: serde_json::Value =
        serde_json::from_slice(&tagged_json).expect("tagged fetchGit JSON parses");
    assert_eq!(tagged_value["rev"], tagged_rev);
    assert!(
        tagged_value["pathValue"]
            .as_str()
            .expect("tagged outPath is a string")
            .ends_with("-tagged")
    );
    assert_eq!(tagged_value["data"], "git-data");

    let (parent_dir, sub_dir, parent_oid) = git_repo_with_submodule("fetch-git-submodule");
    let sub_store_dir = unique_temp_dir("fetch-git-submodule-store");
    let sub_options =
        TreeWalkOptions::with_store_dir(sub_store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    let parent_url = nix_string_literal(&format!("file://{}", path_source(&parent_dir)));
    let parent_rev = parent_oid.to_string();
    let sub_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{
                  url = {parent_url};
                  rev = "{parent_rev}";
                  submodules = true;
                }};
                in {{
                  submodules = x.submodules;
                  root = builtins.readFile "${{x}}/root.txt";
                  sub = builtins.readFile "${{x}}/deps/sub/sub.txt";
                  subGit = builtins.pathExists "${{x}}/deps/sub/.git";
                }}
                "#
        ),
        sub_options,
    );
    let sub_value: serde_json::Value =
        serde_json::from_slice(&sub_json).expect("submodule fetchGit JSON parses");
    assert_eq!(sub_value["submodules"], true);
    assert_eq!(sub_value["root"], "root-data");
    assert_eq!(sub_value["sub"], "submodule-data");
    assert_eq!(sub_value["subGit"], false);

    fs::remove_dir_all(tagged_repo_dir).expect("tagged repo temp directory removes");
    fs::remove_dir_all(tag_store_dir).expect("tag store temp directory removes");
    fs::remove_dir_all(parent_dir).expect("parent repo temp directory removes");
    fs::remove_dir_all(sub_dir).expect("sub repo temp directory removes");
    fs::remove_dir_all(sub_store_dir).expect("sub store temp directory removes");
}

#[test]
fn fetch_git_primop_validates_arguments_and_store_reuse() {
    let (repo_dir, oid) = git_repo_with_file("fetch-git-invalid");
    let store_dir = unique_temp_dir("fetch-git-invalid-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let url = nix_string_literal(&format!("file://{}", path_source(&repo_dir)));
    let rev = oid.to_string();

    let ir = lower(&format!(
        r#"builtins.fetchGit {{ url = {url}; rev = "{rev}"; bogus = 1; }}"#
    ));
    let error = eval_whnf_owned(&ir).expect_err("unknown fetchGit attr rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchGitAttr { attr, .. } if attr.as_slice() == b"bogus"
    ));

    let ir = lower(&format!(
        r#"builtins.fetchGit {{ url = {url}; rev = "{rev}"; name = "bad/name"; }}"#
    ));
    let error = eval_whnf_owned(&ir).expect_err("invalid fetchGit store name rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchGitStoreName { .. }
    ));

    let ir = lower(&format!(r#"builtins.fetchGit {{ rev = "{rev}"; }}"#));
    let error = eval_whnf_owned(&ir).expect_err("missing fetchGit url rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::MissingAttribute { .. }
    ));

    let ir = lower(&format!(
        r#"builtins.fetchGit {{ url = {url}; rev = "not-a-rev"; }}"#
    ));
    let error = eval_whnf_owned_with_options(&ir, options.clone())
        .expect_err("invalid fetchGit rev rejects");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchGit { .. }));

    let source = format!(r#"builtins.fetchGit {{ url = {url}; rev = "{rev}"; }}"#);
    let path_json = eval_json_bytes_with_options(&source, options.clone());
    let path =
        serde_json::from_slice::<serde_json::Value>(&path_json).expect("fetchGit path JSON parses");
    let out_path = path.as_str().expect("fetchGit coerces to outPath");
    fs::remove_file(Path::new(out_path).join("data.txt"))
        .expect("materialized fetchGit path corrupts");
    let error = eval_whnf_owned_with_options(&lower(&source), options)
        .expect_err("corrupt existing fetchGit store path rejects");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchGitHashMismatch { .. }
    ));

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_git_primop_obeys_eval_mode_gates() {
    let (repo_dir, oid) = git_repo_with_file("fetch-git-mode");
    let store_dir = unique_temp_dir("fetch-git-mode-store");
    let url_text = format!("file://{}", path_source(&repo_dir));
    let url = nix_string_literal(&url_text);
    let rev = oid.to_string();

    let error = eval_whnf_owned_with_options(
        &lower(&format!("builtins.fetchGit {url}")),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure eval rejects unpinned fetchGit before repo access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchGitRevRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    let mut pure_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    pure_options.set_eval_mode(EvalMode::Pure);
    let pure_json = eval_json_bytes_with_options(
        &format!(r#"builtins.fetchGit {{ url = {url}; rev = "{rev}"; }}"#),
        pure_options,
    );
    let pure_path = serde_json::from_slice::<serde_json::Value>(&pure_json)
        .expect("pure fetchGit path JSON parses");
    assert!(
        pure_path
            .as_str()
            .expect("pure fetchGit coerces to outPath")
            .ends_with("-source")
    );

    let restricted_error = eval_whnf_owned_with_options(
        &lower(&format!(
            r#"builtins.fetchGit {{ url = {url}; rev = "{rev}"; }}"#
        )),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted eval rejects disallowed fetchGit before repo access");
    assert!(matches!(
        restricted_error.kind(),
        TreeWalkErrorKind::FetchGitAccessDenied {
            mode: EvalMode::Restricted,
            ..
        }
    ));

    let mut restricted_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    restricted_options.set_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_uri(format!("git+{url_text}?exportIgnore=1&rev={rev}").into_bytes())
        .expect("git allowed URI configures");
    let restricted_json = eval_json_bytes_with_options(
        &format!(r#"builtins.fetchGit {{ url = {url}; rev = "{rev}"; }}"#),
        restricted_options,
    );
    let restricted_path = serde_json::from_slice::<serde_json::Value>(&restricted_json)
        .expect("restricted fetchGit path JSON parses");
    assert!(
        restricted_path
            .as_str()
            .expect("restricted fetchGit coerces to outPath")
            .ends_with("-source")
    );
    let all_refs_canonical_uri = TreeWalk::fetch_git_canonical_uri(&FetchGitArguments {
        url: url_text.as_bytes().to_vec(),
        transport_url: None,
        name: "source".to_owned(),
        rev: Some(rev.as_bytes().to_vec()),
        reference: None,
        submodules: false,
        shallow: false,
        all_refs: true,
        export_ignore: true,
        extra_query: BTreeMap::new(),
    });
    assert_eq!(
        all_refs_canonical_uri,
        format!("git+{url_text}?exportIgnore=1&rev={rev}").into_bytes()
    );
    let queried_canonical_uri = TreeWalk::fetch_git_canonical_uri(&FetchGitArguments {
        url: format!("{url_text}?foo=bar").into_bytes(),
        transport_url: None,
        name: "source".to_owned(),
        rev: Some(rev.as_bytes().to_vec()),
        reference: None,
        submodules: false,
        shallow: false,
        all_refs: false,
        export_ignore: true,
        extra_query: BTreeMap::new(),
    });
    assert_eq!(
        queried_canonical_uri,
        format!("git+{url_text}?foo=bar&exportIgnore=1&rev={rev}").into_bytes()
    );
    let path_with_question_canonical_uri = TreeWalk::fetch_git_canonical_uri(&FetchGitArguments {
        url: b"/tmp/repo?literal".to_vec(),
        transport_url: None,
        name: "source".to_owned(),
        rev: Some(rev.as_bytes().to_vec()),
        reference: None,
        submodules: false,
        shallow: false,
        all_refs: false,
        export_ignore: true,
        extra_query: BTreeMap::new(),
    });
    assert_eq!(
        path_with_question_canonical_uri,
        format!("git+/tmp/repo?literal?exportIgnore=1&rev={rev}").into_bytes()
    );

    let (tagged_repo_dir, tagged_oid) = git_repo_with_tag("fetch-git-mode-tagged");
    let tagged_url_text = format!("file://{}", path_source(&tagged_repo_dir));
    let tagged_url = nix_string_literal(&tagged_url_text);
    let tagged_rev = tagged_oid.to_string();
    let tagged_rev_bytes = tagged_rev.as_bytes().to_vec();
    let canonical_uri = TreeWalk::fetch_git_canonical_uri(&FetchGitArguments {
        url: tagged_url_text.as_bytes().to_vec(),
        transport_url: None,
        name: "source".to_owned(),
        rev: Some(tagged_rev_bytes),
        reference: Some(b"refs/tags/v1".to_vec()),
        submodules: true,
        shallow: true,
        all_refs: false,
        export_ignore: false,
        extra_query: BTreeMap::new(),
    });
    assert_eq!(
        canonical_uri,
        format!("git+{tagged_url_text}?ref=refs/tags/v1&rev={tagged_rev}&shallow=1&submodules=1")
            .into_bytes()
    );
    let mut tagged_restricted_options =
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures");
    tagged_restricted_options.set_eval_mode(EvalMode::Restricted);
    tagged_restricted_options
        .add_allowed_uri(
            format!("git+{tagged_url_text}?ref=refs/tags/v1&rev={tagged_rev}&submodules=1")
                .into_bytes(),
        )
        .expect("ref-qualified git allowed URI configures");
    let tagged_restricted_json = eval_json_bytes_with_options(
        &format!(
            r#"
                let x = builtins.fetchGit {{
                  url = {tagged_url};
                  ref = "refs/tags/v1";
                  rev = "{tagged_rev}";
                  submodules = true;
                }};
                in {{ rev = x.rev; submodules = x.submodules; }}
                "#
        ),
        tagged_restricted_options,
    );
    let tagged_restricted_value: serde_json::Value =
        serde_json::from_slice(&tagged_restricted_json)
            .expect("restricted ref fetchGit JSON parses");
    assert_eq!(tagged_restricted_value["rev"], tagged_rev);
    assert_eq!(tagged_restricted_value["submodules"], true);

    fs::remove_dir_all(repo_dir).expect("repo temp directory removes");
    fs::remove_dir_all(tagged_repo_dir).expect("tagged repo temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}
