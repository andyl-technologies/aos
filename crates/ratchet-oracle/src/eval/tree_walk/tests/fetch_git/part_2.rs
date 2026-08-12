//! Split-out tests (part_2). See parent module.

use super::*;

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
