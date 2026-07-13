//! Split-out tests (part_1). See parent module.

use super::*;

#[test]
fn fetch_tree_forge_refs_lower_to_archive_urls_and_gate_access() {
    let rev = "0000000000000000000000000000000000000000";
    let nar_hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let nar_hash_query = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D";
    let ir = lower("null");
    let span = ir.arena.node(ir.root).expect("root node exists").span;
    let evaluator = TreeWalk::new(&ir);

    for (raw, canonical, archive) in [
        (
            format!("github:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"),
            format!("github:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"),
            format!("https://github.com/NixOS/nixpkgs/archive/{rev}.tar.gz"),
        ),
        (
            format!("github:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}"),
            format!("github:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}"),
            format!("https://github.com/NixOS/nixpkgs/archive/{rev}.tar.gz"),
        ),
        (
            format!("gitlab:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"),
            format!("gitlab:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"),
            format!(
                "https://gitlab.com/api/v4/projects/NixOS%2Fnixpkgs/repository/archive.tar.gz?sha={rev}"
            ),
        ),
        (
            format!("gitlab:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}"),
            format!("gitlab:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}"),
            format!(
                "https://gitlab.com/api/v4/projects/NixOS%2Fnixpkgs/repository/archive.tar.gz?sha={rev}"
            ),
        ),
        (
            format!("sourcehut:~andyl/aos/{rev}?narHash={nar_hash_query}"),
            format!("sourcehut:~andyl/aos/{rev}?narHash={nar_hash_query}"),
            format!("https://git.sr.ht/~andyl/aos/archive/{rev}.tar.gz"),
        ),
        (
            format!("sourcehut:~andyl/aos/{rev}?dir=lib&narHash={nar_hash_query}"),
            format!("sourcehut:~andyl/aos/{rev}?dir=lib&narHash={nar_hash_query}"),
            format!("https://git.sr.ht/~andyl/aos/archive/{rev}.tar.gz"),
        ),
    ] {
        let attrs = TreeWalk::parse_flake_ref_attrs(ir.root, span, raw.as_bytes())
            .expect("forge flake ref parses");
        let arguments = evaluator
            .fetch_tree_flake_ref_arguments(ir.root, span, raw.as_bytes(), &attrs)
            .expect("forge flake ref lowers to fetchTree arguments");
        let FetchTreeArguments::Forge {
            canonical_uri,
            archive_url,
            rev: actual_rev,
            expected_nar_hash,
            ..
        } = arguments
        else {
            panic!("forge flake ref lowers to forge arguments");
        };
        assert_eq!(canonical_uri, canonical.as_bytes());
        assert_eq!(archive_url, archive.as_bytes());
        assert_eq!(actual_rev, rev.as_bytes());
        assert!(expected_nar_hash.is_some());
    }

    let enterprise_url = TreeWalk::fetch_tree_forge_archive_url(
        ir.root,
        span,
        b"github",
        b"NixOS",
        b"nixpkgs",
        Some(b"git.example"),
        rev.as_bytes(),
    )
    .expect("enterprise GitHub archive URL renders");
    assert_eq!(
        enterprise_url,
        format!("https://git.example/api/v3/repos/NixOS/nixpkgs/tarball/{rev}").into_bytes()
    );

    let encoded_url = TreeWalk::fetch_tree_forge_archive_url(
        ir.root,
        span,
        b"github",
        b"NixOS?org",
        b"nixpkgs#repo",
        Some(b"git.example"),
        rev.as_bytes(),
    )
    .expect("enterprise GitHub archive URL encodes path components");
    assert_eq!(
        encoded_url,
        format!("https://git.example/api/v3/repos/NixOS%3Forg/nixpkgs%23repo/tarball/{rev}")
            .into_bytes()
    );

    let github_ref_url = TreeWalk::fetch_tree_github_ref_url(
        ir.root,
        span,
        b"NixOS",
        b"nixpkgs",
        None,
        b"release/23.05",
    )
    .expect("GitHub ref resolution URL renders");
    assert_eq!(
        github_ref_url,
        b"https://api.github.com/repos/NixOS/nixpkgs/commits/release%2F23.05"
    );

    let enterprise_ref_url = TreeWalk::fetch_tree_github_ref_url(
        ir.root,
        span,
        b"NixOS",
        b"nixpkgs",
        Some(b"git.example"),
        b"main",
    )
    .expect("GitHub Enterprise ref resolution URL renders");
    assert_eq!(
        enterprise_ref_url,
        b"https://git.example/api/v3/repos/NixOS/nixpkgs/commits/main"
    );

    let gitlab_ref_url = TreeWalk::fetch_tree_gitlab_ref_url(
        ir.root,
        span,
        b"NixOS",
        b"nixpkgs",
        None,
        b"release/23.05",
    )
    .expect("GitLab ref resolution URL renders");
    assert_eq!(
        gitlab_ref_url,
        b"https://gitlab.com/api/v4/projects/NixOS%2Fnixpkgs/repository/commits/release%2F23.05"
    );

    let custom_gitlab_ref_url = TreeWalk::fetch_tree_gitlab_ref_url(
        ir.root,
        span,
        b"NixOS",
        b"nixpkgs",
        Some(b"git.example"),
        b"main",
    )
    .expect("custom GitLab ref resolution URL renders");
    assert_eq!(
        custom_gitlab_ref_url,
        b"https://git.example/api/v4/projects/NixOS%2Fnixpkgs/repository/commits/main"
    );

    let sourcehut_refs_url =
        TreeWalk::fetch_tree_sourcehut_refs_url(ir.root, span, b"~andyl", b"aos", None)
            .expect("SourceHut refs URL renders");
    assert_eq!(
        sourcehut_refs_url,
        b"https://git.sr.ht/~andyl/aos/info/refs"
    );
    let sourcehut_head_url =
        TreeWalk::fetch_tree_sourcehut_head_url(ir.root, span, b"~andyl", b"aos", None)
            .expect("SourceHut HEAD URL renders");
    assert_eq!(sourcehut_head_url, b"https://git.sr.ht/~andyl/aos/HEAD");

    let sourcehut_rev = TreeWalk::fetch_tree_sourcehut_rev_from_refs_response(
        ir.root,
        span,
        b"sourcehut:~andyl/aos/main",
        b"refs/heads/main",
        b"1111111111111111111111111111111111111111\trefs/heads/dev\nref: refs/heads/main\tHEAD\n0123456789abcdef0123456789abcdef01234567\trefs/heads/main\n",
    )
    .expect("SourceHut info/refs resolves the requested ref");
    assert_eq!(sourcehut_rev, b"0123456789abcdef0123456789abcdef01234567");
    let sourcehut_head_rev = TreeWalk::fetch_tree_sourcehut_rev_from_refs_response(
        ir.root,
        span,
        b"sourcehut:~andyl/aos",
        b"refs/heads/main",
        b"ref: refs/heads/main\tHEAD\n0123456789abcdef0123456789abcdef01234567\trefs/heads/main\n",
    )
    .expect("SourceHut info/refs resolves a symbolic HEAD target");
    assert_eq!(
        sourcehut_head_rev,
        b"0123456789abcdef0123456789abcdef01234567"
    );

    let resolved_rev = TreeWalk::fetch_tree_github_rev_from_commit_response(
        ir.root,
        span,
        b"github:NixOS/nixpkgs/main",
        br#"{"sha":"0123456789abcdef0123456789abcdef01234567"}"#,
    )
    .expect("GitHub commit response exposes a full rev");
    assert_eq!(resolved_rev, b"0123456789abcdef0123456789abcdef01234567");

    let error = TreeWalk::fetch_tree_github_rev_from_commit_response(
        ir.root,
        span,
        b"github:NixOS/nixpkgs/main",
        br#"{"sha":"main"}"#,
    )
    .expect_err("GitHub commit response requires a full rev");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));

    let resolved_rev = TreeWalk::fetch_tree_gitlab_rev_from_commit_response(
        ir.root,
        span,
        b"gitlab:NixOS/nixpkgs/main",
        br#"{"id":"0123456789abcdef0123456789abcdef01234567"}"#,
    )
    .expect("GitLab commit response exposes a full rev");
    assert_eq!(resolved_rev, b"0123456789abcdef0123456789abcdef01234567");

    let error = TreeWalk::fetch_tree_gitlab_rev_from_commit_response(
        ir.root,
        span,
        b"gitlab:NixOS/nixpkgs/main",
        br#"{"id":"main"}"#,
    )
    .expect_err("GitLab commit response requires a full rev");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));

    let pure_attrs = TreeWalk::parse_flake_ref_attrs(ir.root, span, b"github:NixOS/nixpkgs/main")
        .expect("GitHub ref parses");
    let pure_evaluator =
        TreeWalk::with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Pure));
    let error = pure_evaluator
        .fetch_tree_flake_ref_arguments(ir.root, span, b"github:NixOS/nixpkgs/main", &pure_attrs)
        .expect_err("pure GitHub ref rejects before resolver access without narHash");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeLockedInputRequired {
            input,
            mode: EvalMode::Pure,
            ..
        } if input == b"github:NixOS/nixpkgs/main"
    ));

    let restricted_source = format!(
        r#"builtins.fetchTree {{ type = "github"; owner = "NixOS"; repo = "nixpkgs"; rev = "{rev}"; narHash = "{nar_hash}"; host = "git.example"; }}"#
    );
    let error = eval_whnf_owned_with_options(
        &lower(&restricted_source),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted forge fetchTree rejects before archive access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!("github:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}").as_bytes()
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri(format!(
            "github:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"
        ))
        .expect("canonical forge URI is a valid allowed URI prefix");
    let error = eval_whnf_owned_with_options(&lower(&restricted_source), options)
        .expect_err("custom forge host requires archive URL authorization");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!("https://git.example/api/v3/repos/NixOS/nixpkgs/tarball/{rev}").as_bytes()
    ));

    let restricted_gitlab_source = format!(
        r#"builtins.fetchTree {{ type = "gitlab"; owner = "NixOS"; repo = "nixpkgs"; rev = "{rev}"; narHash = "{nar_hash}"; host = "git.example"; }}"#
    );
    let error = eval_whnf_owned_with_options(
        &lower(&restricted_gitlab_source),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted GitLab fetchTree rejects before archive access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!("gitlab:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}").as_bytes()
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri(format!(
            "gitlab:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"
        ))
        .expect("canonical GitLab forge URI is a valid allowed URI prefix");
    let error = eval_whnf_owned_with_options(&lower(&restricted_gitlab_source), options)
        .expect_err("custom GitLab host requires archive URL authorization");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!("https://git.example/api/v4/projects/NixOS%2Fnixpkgs/repository/archive.tar.gz?sha={rev}").as_bytes()
    ));

    let restricted_dir_source = format!(
        r#"builtins.fetchTree "github:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}""#
    );
    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri(format!(
            "github:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"
        ))
        .expect("forge URI without dir is a valid allowed URI prefix");
    let error = eval_whnf_owned_with_options(&lower(&restricted_dir_source), options)
        .expect_err("restricted forge fetchTree canonical URI includes dir metadata");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == format!("github:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}").as_bytes()
    ));

    for (source, allowed_uri, denied_uri) in [
        (
            format!(
                r#"builtins.fetchTree {{ type = "github"; owner = "NixOS"; repo = "nixpkgs"; rev = "{rev}"; narHash = "{nar_hash}"; dir = "lib"; }}"#
            ),
            format!("github:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"),
            format!("github:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}"),
        ),
        (
            format!(
                r#"builtins.fetchTree {{ type = "gitlab"; owner = "NixOS"; repo = "nixpkgs"; rev = "{rev}"; narHash = "{nar_hash}"; dir = "lib"; }}"#
            ),
            format!("gitlab:NixOS/nixpkgs/{rev}?narHash={nar_hash_query}"),
            format!("gitlab:NixOS/nixpkgs/{rev}?dir=lib&narHash={nar_hash_query}"),
        ),
        (
            format!(
                r#"builtins.fetchTree {{ type = "sourcehut"; owner = "~andyl"; repo = "aos"; rev = "{rev}"; narHash = "{nar_hash}"; dir = "lib"; }}"#
            ),
            format!("sourcehut:~andyl/aos/{rev}?narHash={nar_hash_query}"),
            format!("sourcehut:~andyl/aos/{rev}?dir=lib&narHash={nar_hash_query}"),
        ),
    ] {
        let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
        options
            .add_allowed_uri(allowed_uri)
            .expect("forge URI without dir is a valid allowed URI prefix");
        let error = eval_whnf_owned_with_options(&lower(&source), options)
            .expect_err("restricted attrset forge fetchTree canonical URI includes dir metadata");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::FetchTreeAccessDenied {
                input,
                mode: EvalMode::Restricted,
                ..
            } if input == denied_uri.as_bytes()
        ));
    }

    for source in [
        format!(
            r#"builtins.fetchTree {{ type = "gitlab"; owner = "group"; repo = "project/private"; rev = "{rev}"; narHash = "{nar_hash}"; }}"#
        ),
        format!(
            r#"builtins.fetchTree {{ type = "gitlab"; owner = ""; repo = "project"; rev = "{rev}"; narHash = "{nar_hash}"; }}"#
        ),
        format!(
            r#"builtins.fetchTree {{ type = "gitlab"; owner = "group"; repo = ""; rev = "{rev}"; narHash = "{nar_hash}"; }}"#
        ),
    ] {
        let error = eval_whnf_owned(&lower(&source))
            .expect_err("forge owner and repo must be single path segments");
        assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));
    }

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri(format!(
            "gitlab:group/project/{rev}?narHash={nar_hash_query}"
        ))
        .expect("canonical gitlab forge URI is a valid allowed URI prefix");
    let source = format!(
        r#"builtins.fetchTree {{ type = "gitlab"; owner = "group"; repo = "project/private"; rev = "{rev}"; narHash = "{nar_hash}"; }}"#
    );
    let error = eval_whnf_owned_with_options(&lower(&source), options)
        .expect_err("slash-bearing forge repo rejects before restricted prefix can overmatch");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FetchTree { .. }));

    let pure_source = format!(r#"builtins.fetchTree "github:NixOS/nixpkgs/{rev}""#);
    let error = eval_whnf_owned_with_options(
        &lower(&pure_source),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure forge fetchTree requires a narHash lock");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeLockedInputRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    for (source, expected_input) in [
        (
            format!(r#"builtins.fetchTree "github:NixOS/nixpkgs/main?narHash={nar_hash_query}""#),
            format!("github:NixOS/nixpkgs/main?narHash={nar_hash_query}"),
        ),
        (
            format!(
                r#"builtins.fetchTree {{ type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = "main"; narHash = "{nar_hash}"; }}"#
            ),
            format!("github:NixOS/nixpkgs/main?narHash={nar_hash_query}"),
        ),
        (
            format!(r#"builtins.fetchTree "gitlab:NixOS/nixpkgs/main?narHash={nar_hash_query}""#),
            format!("gitlab:NixOS/nixpkgs/main?narHash={nar_hash_query}"),
        ),
        (
            format!(
                r#"builtins.fetchTree {{ type = "gitlab"; owner = "NixOS"; repo = "nixpkgs"; ref = "main"; narHash = "{nar_hash}"; }}"#
            ),
            format!("gitlab:NixOS/nixpkgs/main?narHash={nar_hash_query}"),
        ),
    ] {
        let error = eval_whnf_owned_with_options(
            &lower(&source),
            TreeWalkOptions::with_eval_mode(EvalMode::Pure),
        )
        .expect_err("pure forge fetchTree rejects mutable refs even with narHash");
        assert!(
            matches!(
                error.kind(),
                TreeWalkErrorKind::FetchTreeLockedInputRequired {
                    input,
                    mode: EvalMode::Pure,
                    ..
                } if input == expected_input.as_bytes()
            ),
            "{source}: {error:?}",
        );
    }

    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.fetchTree "github:NixOS/nixpkgs/main""#),
        TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
    )
    .expect_err("restricted unresolved forge ref denies its canonical URI");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == b"github:NixOS/nixpkgs/main"
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri("sourcehut:~andyl/aos/main?dir=lib")
        .expect("dir-bearing forge URI is a valid allowed URI prefix");
    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.fetchTree "sourcehut:~andyl/aos/main?dir=lib""#),
        options,
    )
    .expect_err("unresolved forge access drops dir metadata");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTreeAccessDenied {
            input,
            mode: EvalMode::Restricted,
            ..
        } if input == b"sourcehut:~andyl/aos/main"
    ));

    let mut options = TreeWalkOptions::with_eval_mode(EvalMode::Restricted);
    options
        .add_allowed_uri("sourcehut:~andyl/aos/main")
        .expect("dir-stripped forge URI is a valid allowed URI prefix");
    options.add_fetch_tree_url_response(
        "https://git.sr.ht/~andyl/aos/info/refs",
        b"0123456789abcdef0123456789abcdef01234567\trefs/heads/main\n".to_vec(),
    );
    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.fetchTree "sourcehut:~andyl/aos/main?dir=lib""#),
        options,
    )
    .expect_err("allowed unresolved forge ref resolves before archive access");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTree { message, .. }
            if message.contains("missing test fetchTree URL response")
    ));
}

#[test]
fn fetch_tree_github_refs_resolve_with_test_url_responses() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tree-github-ref");
    let archive_bytes = fs::read(&archive_path).expect("archive fixture reads");
    let store_dir = unique_temp_dir("fetch-tree-github-ref-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let resolved_rev = "0123456789abcdef0123456789abcdef01234567";
    let recursive_nar_hash = "sha256-2huQKpXoKVd3jyPd2WSNvpaYPRMVWmOk+ehCZVNq3KI=";
    let recursive_nar_hash_query =
        url::form_urlencoded::byte_serialize(recursive_nar_hash.as_bytes()).collect::<String>();

    options.add_fetch_tree_url_response(
        "https://api.github.com/repos/NixOS/nixpkgs/commits/main",
        format!(r#"{{"sha":"{resolved_rev}"}}"#).into_bytes(),
    );
    options.add_fetch_tree_url_response(
        format!("https://github.com/NixOS/nixpkgs/archive/{resolved_rev}.tar.gz"),
        archive_bytes,
    );

    let source = format!(
        r#"
            let x = builtins.fetchTree "github:NixOS/nixpkgs/main?narHash={recursive_nar_hash_query}";
            in {{
              data = builtins.readFile "${{x.outPath}}/file.txt";
              nested = builtins.readFile "${{x.outPath}}/sub/nested.txt";
              rev = x.rev;
              shortRev = x.shortRev;
              narHash = x.narHash;
            }}
            "#
    );
    let json = eval_json_bytes_with_options(&source, options.clone());
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("GitHub fetchTree JSON parses");
    assert_eq!(value["data"], "data");
    assert_eq!(value["nested"], "inner");
    assert_eq!(value["rev"], resolved_rev);
    assert_eq!(value["shortRev"], &resolved_rev[..7]);
    assert_eq!(value["narHash"], recursive_nar_hash);

    let mut restricted_options = options;
    restricted_options.set_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_uri(format!(
            "github:NixOS/nixpkgs/main?narHash={recursive_nar_hash_query}"
        ))
        .expect("restricted GitHub ref URI configures");
    let restricted_json = eval_json_bytes_with_options(
        &format!(
            r#"let x = builtins.fetchTree "github:NixOS/nixpkgs/main?narHash={recursive_nar_hash_query}"; in x.rev"#
        ),
        restricted_options,
    );
    assert_eq!(
        restricted_json,
        serde_json::to_vec(resolved_rev).expect("rev JSON serializes")
    );

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_gitlab_refs_resolve_with_test_url_responses() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tree-gitlab-ref");
    let archive_bytes = fs::read(&archive_path).expect("archive fixture reads");
    let store_dir = unique_temp_dir("fetch-tree-gitlab-ref-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let resolved_rev = "0123456789abcdef0123456789abcdef01234567";
    let recursive_nar_hash = "sha256-2huQKpXoKVd3jyPd2WSNvpaYPRMVWmOk+ehCZVNq3KI=";
    let recursive_nar_hash_query =
        url::form_urlencoded::byte_serialize(recursive_nar_hash.as_bytes()).collect::<String>();

    options.add_fetch_tree_url_response(
        "https://gitlab.com/api/v4/projects/NixOS%2Fnixpkgs/repository/commits/main",
        format!(r#"{{"id":"{resolved_rev}"}}"#).into_bytes(),
    );
    options.add_fetch_tree_url_response(
            format!(
                "https://gitlab.com/api/v4/projects/NixOS%2Fnixpkgs/repository/archive.tar.gz?sha={resolved_rev}"
            ),
            archive_bytes,
        );

    let source = format!(
        r#"
            let x = builtins.fetchTree "gitlab:NixOS/nixpkgs/main?narHash={recursive_nar_hash_query}";
            in {{
              data = builtins.readFile "${{x.outPath}}/file.txt";
              nested = builtins.readFile "${{x.outPath}}/sub/nested.txt";
              rev = x.rev;
              shortRev = x.shortRev;
              narHash = x.narHash;
            }}
            "#
    );
    let json = eval_json_bytes_with_options(&source, options.clone());
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("GitLab fetchTree JSON parses");
    assert_eq!(value["data"], "data");
    assert_eq!(value["nested"], "inner");
    assert_eq!(value["rev"], resolved_rev);
    assert_eq!(value["shortRev"], &resolved_rev[..7]);
    assert_eq!(value["narHash"], recursive_nar_hash);

    let mut restricted_options = options;
    restricted_options.set_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_uri(format!(
            "gitlab:NixOS/nixpkgs/main?narHash={recursive_nar_hash_query}"
        ))
        .expect("restricted GitLab ref URI configures");
    let restricted_json = eval_json_bytes_with_options(
        &format!(
            r#"let x = builtins.fetchTree "gitlab:NixOS/nixpkgs/main?narHash={recursive_nar_hash_query}"; in x.rev"#
        ),
        restricted_options,
    );
    assert_eq!(
        restricted_json,
        serde_json::to_vec(resolved_rev).expect("rev JSON serializes")
    );

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_sourcehut_refs_resolve_with_test_url_responses() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tree-sourcehut-ref");
    let archive_bytes = fs::read(&archive_path).expect("archive fixture reads");
    let store_dir = unique_temp_dir("fetch-tree-sourcehut-ref-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let resolved_rev = "0123456789abcdef0123456789abcdef01234567";
    let recursive_nar_hash = "sha256-2huQKpXoKVd3jyPd2WSNvpaYPRMVWmOk+ehCZVNq3KI=";
    let recursive_nar_hash_query =
        url::form_urlencoded::byte_serialize(recursive_nar_hash.as_bytes()).collect::<String>();

    options.add_fetch_tree_url_response(
        "https://git.sr.ht/~andyl/aos/HEAD",
        b"ref: refs/heads/main\n".to_vec(),
    );
    options.add_fetch_tree_url_response(
        "https://git.sr.ht/~andyl/aos/info/refs",
        format!(
            "1111111111111111111111111111111111111111\trefs/heads/dev\nref: refs/heads/main\tHEAD\n{resolved_rev}\trefs/heads/main\n"
        )
        .into_bytes(),
    );
    options.add_fetch_tree_url_response(
        format!("https://git.sr.ht/~andyl/aos/archive/{resolved_rev}.tar.gz"),
        archive_bytes,
    );

    let source = format!(
        r#"
            let
              x = builtins.fetchTree "sourcehut:~andyl/aos/main?narHash={recursive_nar_hash_query}";
              head = builtins.fetchTree "sourcehut:~andyl/aos?narHash={recursive_nar_hash_query}";
              y = builtins.fetchTree {{
                type = "sourcehut";
                owner = "~andyl";
                repo = "aos";
                ref = "main";
                narHash = "{recursive_nar_hash}";
              }};
              default = builtins.fetchTree {{
                type = "sourcehut";
                owner = "~andyl";
                repo = "aos";
                narHash = "{recursive_nar_hash}";
              }};
            in {{
              data = builtins.readFile "${{x.outPath}}/file.txt";
              nested = builtins.readFile "${{y.outPath}}/sub/nested.txt";
              headNested = builtins.readFile "${{head.outPath}}/sub/nested.txt";
              rev = x.rev;
              defaultRev = default.rev;
              shortRev = x.shortRev;
              narHash = y.narHash;
            }}
            "#
    );
    let json = eval_json_bytes_with_options(&source, options.clone());
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("SourceHut fetchTree JSON parses");
    assert_eq!(value["data"], "data");
    assert_eq!(value["nested"], "inner");
    assert_eq!(value["headNested"], "inner");
    assert_eq!(value["rev"], resolved_rev);
    assert_eq!(value["defaultRev"], resolved_rev);
    assert_eq!(value["shortRev"], &resolved_rev[..7]);
    assert_eq!(value["narHash"], recursive_nar_hash);

    let mut restricted_options = options;
    restricted_options.set_eval_mode(EvalMode::Restricted);
    restricted_options
        .add_allowed_uri(format!(
            "sourcehut:~andyl/aos?narHash={recursive_nar_hash_query}"
        ))
        .expect("restricted SourceHut ref URI configures");
    let restricted_json = eval_json_bytes_with_options(
        &format!(
            r#"let x = builtins.fetchTree "sourcehut:~andyl/aos?narHash={recursive_nar_hash_query}"; in x.rev"#
        ),
        restricted_options,
    );
    assert_eq!(
        restricted_json,
        serde_json::to_vec(resolved_rev).expect("rev JSON serializes")
    );

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_tree_forge_refs_reroot_dir_with_test_url_responses() {
    let (archive_dir, archive_path) = fetch_tarball_fixture("fetch-tree-forge-ref-dir");
    let archive_bytes = fs::read(&archive_path).expect("archive fixture reads");
    let store_dir = unique_temp_dir("fetch-tree-forge-ref-dir-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let resolved_rev = "0123456789abcdef0123456789abcdef01234567";
    let subdir_recursive_nar_hash = "sha256-gSl6kgu8AUFiZkLorEwK2W4Cg+knYmndOninCstIAcI=";

    options.add_fetch_tree_url_response(
        "https://api.github.com/repos/NixOS/nixpkgs/commits/main",
        format!(r#"{{"sha":"{resolved_rev}"}}"#).into_bytes(),
    );
    options.add_fetch_tree_url_response(
        format!("https://github.com/NixOS/nixpkgs/archive/{resolved_rev}.tar.gz"),
        archive_bytes.clone(),
    );
    options.add_fetch_tree_url_response(
        "https://gitlab.com/api/v4/projects/NixOS%2Fnixpkgs/repository/commits/main",
        format!(r#"{{"id":"{resolved_rev}"}}"#).into_bytes(),
    );
    options.add_fetch_tree_url_response(
        format!(
            "https://gitlab.com/api/v4/projects/NixOS%2Fnixpkgs/repository/archive.tar.gz?sha={resolved_rev}"
        ),
        archive_bytes.clone(),
    );
    options.add_fetch_tree_url_response(
        "https://git.sr.ht/~andyl/aos/HEAD",
        b"ref: refs/heads/main\n".to_vec(),
    );
    options.add_fetch_tree_url_response(
        "https://git.sr.ht/~andyl/aos/info/refs",
        format!("{resolved_rev}\trefs/heads/main\n").into_bytes(),
    );
    options.add_fetch_tree_url_response(
        format!("https://git.sr.ht/~andyl/aos/archive/{resolved_rev}.tar.gz"),
        archive_bytes,
    );

    let source = r#"
        let
          gh = builtins.fetchTree "github:NixOS/nixpkgs/main?dir=sub";
          gl = builtins.fetchTree "gitlab:NixOS/nixpkgs/main?dir=sub";
          sh = builtins.fetchTree "sourcehut:~andyl/aos?dir=sub";
          ghAttrs = builtins.fetchTree {
            type = "github";
            owner = "NixOS";
            repo = "nixpkgs";
            ref = "main";
            dir = "sub";
          };
          glAttrs = builtins.fetchTree {
            type = "gitlab";
            owner = "NixOS";
            repo = "nixpkgs";
            ref = "main";
            dir = "sub";
          };
          shAttrs = builtins.fetchTree {
            type = "sourcehut";
            owner = "~andyl";
            repo = "aos";
            ref = "main";
            dir = "sub";
          };
        in {
          ghNested = builtins.readFile "${gh.outPath}/nested.txt";
          glNested = builtins.readFile "${gl.outPath}/nested.txt";
          shNested = builtins.readFile "${sh.outPath}/nested.txt";
          ghAttrsNested = builtins.readFile "${ghAttrs.outPath}/nested.txt";
          glAttrsNested = builtins.readFile "${glAttrs.outPath}/nested.txt";
          shAttrsNested = builtins.readFile "${shAttrs.outPath}/nested.txt";
          ghRootFileExists = builtins.pathExists "${gh.outPath}/file.txt";
          ghSubdirStillNested = builtins.pathExists "${gh.outPath}/sub/nested.txt";
          ghRev = gh.rev;
          glRev = gl.rev;
          shRev = sh.rev;
          ghAttrsRev = ghAttrs.rev;
          glAttrsRev = glAttrs.rev;
          shAttrsRev = shAttrs.rev;
          ghNarHash = gh.narHash;
          glNarHash = gl.narHash;
          shNarHash = sh.narHash;
          ghAttrsNarHash = ghAttrs.narHash;
          glAttrsNarHash = glAttrs.narHash;
          shAttrsNarHash = shAttrs.narHash;
        }
        "#;
    let json = eval_json_bytes_with_options(source, options);
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("forge fetchTree dir JSON parses");
    assert_eq!(value["ghNested"], "inner");
    assert_eq!(value["glNested"], "inner");
    assert_eq!(value["shNested"], "inner");
    assert_eq!(value["ghAttrsNested"], "inner");
    assert_eq!(value["glAttrsNested"], "inner");
    assert_eq!(value["shAttrsNested"], "inner");
    assert_eq!(value["ghRootFileExists"], false);
    assert_eq!(value["ghSubdirStillNested"], false);
    assert_eq!(value["ghRev"], resolved_rev);
    assert_eq!(value["glRev"], resolved_rev);
    assert_eq!(value["shRev"], resolved_rev);
    assert_eq!(value["ghAttrsRev"], resolved_rev);
    assert_eq!(value["glAttrsRev"], resolved_rev);
    assert_eq!(value["shAttrsRev"], resolved_rev);
    assert_eq!(value["ghNarHash"], subdir_recursive_nar_hash);
    assert_eq!(value["glNarHash"], subdir_recursive_nar_hash);
    assert_eq!(value["shNarHash"], subdir_recursive_nar_hash);
    assert_eq!(value["ghAttrsNarHash"], subdir_recursive_nar_hash);
    assert_eq!(value["glAttrsNarHash"], subdir_recursive_nar_hash);
    assert_eq!(value["shAttrsNarHash"], subdir_recursive_nar_hash);

    fs::remove_dir_all(archive_dir).expect("archive temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

