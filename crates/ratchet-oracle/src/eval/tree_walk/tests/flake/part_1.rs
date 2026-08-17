//! Split-out tests (part_1). See parent module.

use super::*;

#[test]
fn configured_cpp_nix_restricted_unresolved_forge_fetch_tree_access_matches_tree_walk() {
    let Ok(oracle) = std::env::var("AOS_NIX_ORACLE") else {
        eprintln!("AOS_NIX_ORACLE not set; skipping configured C++ Nix fetchTree access check");
        return;
    };
    assert_pinned_cpp_nix_oracle(&oracle);

    for (source, expected_uri) in [
        (
            r#"builtins.fetchTree "github:NixOS/nixpkgs/main""#,
            "github:NixOS/nixpkgs/main",
        ),
        (
            r#"builtins.fetchTree "github:NixOS/nixpkgs/main?dir=lib""#,
            "github:NixOS/nixpkgs/main",
        ),
        (
            r#"builtins.fetchTree "github:NixOS/nixpkgs/main?dir=lib&narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D""#,
            "github:NixOS/nixpkgs/main?narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D",
        ),
        (
            r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = ""; }"#,
            "github:NixOS/nixpkgs/",
        ),
        (
            r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; ref = "bad?ref"; }"#,
            "github:NixOS/nixpkgs/bad%3Fref",
        ),
        (
            r#"builtins.fetchTree { type = "github"; owner = ""; repo = "nixpkgs"; }"#,
            "github:/nixpkgs",
        ),
        (
            r#"builtins.fetchTree { type = "gitlab"; owner = "group"; repo = "project/private"; }"#,
            "gitlab:group/project/private",
        ),
        (
            r#"builtins.fetchTree { type = "github"; owner = "NixOS"; repo = "nixpkgs"; host = "bad host"; }"#,
            "github:NixOS/nixpkgs",
        ),
    ] {
        let stderr = cpp_nix_eval_failure_stderr_with_nix_options(
            &oracle,
            source,
            &[
                (
                    "experimental-features",
                    PINNED_BUILTIN_SURFACE_EXPERIMENTAL_FEATURES,
                ),
                ("restrict-eval", "true"),
                ("allowed-uris", ""),
            ],
        );
        assert!(
            String::from_utf8_lossy(&stderr)
                .contains(&format!("access to URI '{expected_uri}' is forbidden")),
            "{}",
            String::from_utf8_lossy(&stderr)
        );

        let error = eval_whnf_owned_with_options(
            &lower(source),
            TreeWalkOptions::with_eval_mode(EvalMode::Restricted),
        )
        .expect_err("restricted unresolved forge fetchTree denies the canonical URI");
        assert!(matches!(
            error.kind(),
            TreeWalkErrorKind::FetchTreeAccessDenied {
                input,
                mode: EvalMode::Restricted,
                ..
            } if input == expected_uri.as_bytes()
        ));
    }
}

#[test]
fn parse_flake_ref_parses_github_example() {
    assert_eq!(
        eval_string_bytes(
            r#"builtins.toJSON (builtins.parseFlakeRef "github:NixOS/nixpkgs/23.05?dir=lib")"#
        ),
        br#"{"dir":"lib","owner":"NixOS","ref":"23.05","repo":"nixpkgs","type":"github"}"#,
    );
}

#[test]
fn parse_flake_ref_records_dynamic_repr_decision() {
    let source = r#"builtins.parseFlakeRef "github:NixOS/nixpkgs/23.05?dir=lib""#;
    assert_eq!(
        eval_list_string_bytes(&format!("builtins.attrNames ({source})")),
        vec![
            b"dir".to_vec(),
            b"owner".to_vec(),
            b"ref".to_vec(),
            b"repo".to_vec(),
            b"type".to_vec(),
        ],
    );

    let outcome = eval_whnf_owned(&lower(source)).expect("parseFlakeRef evaluates");

    let attrs = outcome
        .heap()
        .get_attrs(outcome.value())
        .expect("parseFlakeRef returns attrs");
    assert_eq!(attrs.len(), 5);
    let metadata = outcome
        .heap()
        .get_attrs_metadata(outcome.value())
        .expect("parseFlakeRef metadata exists");
    assert!(metadata.projected_shape().is_some());
    assert_eq!(metadata.repr(), AttrSetReprKind::Flat);
    let snapshot = outcome
        .attr_telemetry()
        .update_merge_snapshot()
        .expect("repr telemetry snapshot allocates");
    assert_eq!(snapshot.decisions, 1);
    assert_eq!(snapshot.flat_decisions, 1);
    assert_eq!(snapshot.update_merges, 0);
    assert_eq!(snapshot.reasons.static_literal, 0);
    assert_eq!(snapshot.reasons.small_shape_stable, 1);
    let stats = outcome.attr_telemetry().order_parity_stats();
    assert_eq!(stats.matched, 1);
    assert_eq!(stats.mismatched, 0);
}

#[test]
fn parse_flake_ref_supports_first_class_indirect_refs() {
    assert_eq!(
        eval_string_bytes(
            r#"let parse = builtins.parseFlakeRef; in builtins.toJSON (parse "nixpkgs/unstable")"#
        ),
        br#"{"id":"nixpkgs","ref":"unstable","type":"indirect"}"#,
    );
}

#[test]
fn parse_flake_ref_preserves_git_url_dir_query() {
    assert_eq!(
        eval_string_bytes(
            r#"builtins.toJSON (builtins.parseFlakeRef "git+https://example.com/repo.git?ref=main&dir=lib")"#
        ),
        br#"{"dir":"lib","ref":"main","type":"git","url":"https://example.com/repo.git?dir=lib"}"#,
    );
}

#[test]
fn git_flake_ref_roundtrip_preserves_nar_hash_lock() {
    assert_eq!(
        eval_string_bytes(
            r#"builtins.flakeRefToString
                (builtins.parseFlakeRef
                  "git+https://example.com/repo.git?rev=0000000000000000000000000000000000000000&dir=lib&narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")"#
        ),
        b"git+https://example.com/repo.git?dir=lib&narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&rev=0000000000000000000000000000000000000000",
    );
}

#[test]
fn parse_flake_ref_decodes_query_values_but_not_names() {
    assert_eq!(
        eval_string_bytes(
            r#"builtins.toJSON (builtins.parseFlakeRef "github:NixOS/nixpkgs?%64ir=lib")"#
        ),
        br#"{"owner":"NixOS","repo":"nixpkgs","type":"github"}"#,
    );
}

#[test]
fn parse_flake_ref_supports_file_curl_refs() {
    assert_eq!(
            eval_string_bytes(
                r#"builtins.toJSON (builtins.parseFlakeRef "file+https://example.com/blob.txt?narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D")"#
            ),
            br#"{"narHash":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","type":"file","url":"https://example.com/blob.txt"}"#,
        );
}

#[test]
fn parse_flake_ref_drops_invalid_curl_numeric_metadata() {
    assert_eq!(
        eval_string_bytes(
            r#"builtins.toJSON (builtins.parseFlakeRef "https://example.com/source.tar.gz?revCount=bad&lastModified=nope&foo=bar")"#
        ),
        br#"{"type":"tarball","url":"https://example.com/source.tar.gz?foo=bar"}"#,
    );
}

#[test]
fn flake_ref_to_string_renders_github_example() {
    assert_eq!(
        eval_string_bytes(
            r#"let render = builtins.flakeRefToString; in render {
                    dir = "lib";
                    owner = "NixOS";
                    ref = "23.05";
                    repo = "nixpkgs";
                    type = "github";
                }"#
        ),
        b"github:NixOS/nixpkgs/23.05?dir=lib",
    );
}

#[test]
fn flake_ref_to_string_canonicalizes_hash_attrs() {
    assert_eq!(
            eval_string_bytes(
                r#"builtins.flakeRefToString {
                    narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
                    owner = "NixOS";
                    repo = "nixpkgs";
                    rev = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                    type = "github";
                }"#
            ),
            b"github:NixOS/nixpkgs/0000000000000000000000000000000000000000?narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D",
        );

    assert_eq!(
        eval_string_bytes(
            r#"builtins.flakeRefToString {
                    rev = "sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                    type = "git";
                    url = "https://example.com/repo";
                }"#
        ),
        b"git+https://example.com/repo?rev=0000000000000000000000000000000000000000",
    );
}

#[test]
fn flake_ref_to_string_renders_git_public_keys_like_cpp_nix() {
    assert_eq!(
        eval_string_bytes(
            r#"builtins.flakeRefToString {
                    publicKey = "abc";
                    type = "git";
                    url = "https://example.com/repo";
                }"#
        ),
        b"git+https://example.com/repo?keytype=ssh-ed25519&publicKey=abc",
    );

    assert_eq!(
        eval_string_bytes(
            r#"builtins.flakeRefToString {
                    publicKeys = "[{\"key\":\"abc\",\"type\":\"ssh-ed25519\"}]";
                    type = "git";
                    url = "https://example.com/repo";
                }"#
        ),
        b"git+https://example.com/repo?keytype=ssh-ed25519&publicKey=abc",
    );

    assert_eq!(
            eval_string_bytes(
                r#"builtins.flakeRefToString {
                    publicKey = "def";
                    publicKeys = "[{\"key\":\"abc\",\"type\":\"ssh-ed25519\"}]";
                    type = "git";
                    url = "https://example.com/repo";
                }"#
            ),
            b"git+https://example.com/repo?publicKeys=%5B%7B%22key%22:%22abc%22%2C%22type%22:%22ssh-ed25519%22%7D%2C%7B%22key%22:%22def%22%2C%22type%22:%22ssh-ed25519%22%7D%5D",
        );

    assert_eq!(
        eval_string_bytes(
            r#"builtins.flakeRefToString {
                    publicKey = "abc";
                    publicKeys = "[]";
                    type = "git";
                    url = "https://example.com/repo";
                }"#
        ),
        b"git+https://example.com/repo?keytype=ssh-ed25519&publicKey=abc",
    );
}

#[test]
fn flake_ref_to_string_renders_path_query_attrs() {
    assert_eq!(
            eval_string_bytes(
                r#"builtins.flakeRefToString {
                    type = "path";
                    path = "/tmp/source";
                    revCount = 5;
                    lastModified = 7;
                    rev = "abcdef";
                    narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                }"#
            ),
            b"path:/tmp/source?lastModified=7&narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&rev=abcdef&revCount=5",
        );
}

#[test]
fn flake_ref_to_string_inserts_dir_without_overwriting_url_dir() {
    assert_eq!(
            eval_string_bytes(
                r#"builtins.flakeRefToString {
                    dir = "other";
                    narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                    type = "tarball";
                    url = "https://example.com/source.tar.gz?dir=lib";
                }"#
            ),
            b"https://example.com/source.tar.gz?dir=lib&narHash=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D",
        );
}

#[test]
fn flake_ref_to_string_rejects_unsupported_attrs_and_value_types() {
    let unsupported = eval_whnf_owned(&lower(
        r#"builtins.flakeRefToString {
                type = "github";
                owner = "NixOS";
                repo = "nixpkgs";
                bogus = "x";
            }"#,
    ))
    .expect_err("unsupported flake-ref attrs are rejected");
    assert!(matches!(
        unsupported.kind(),
        TreeWalkErrorKind::UnsupportedFlakeRefAttr { attr, .. } if attr.as_slice() == b"bogus"
    ));

    let bad_type = eval_whnf_owned(&lower(
        r#"builtins.flakeRefToString {
                type = "github";
                owner = null;
                repo = "nixpkgs";
            }"#,
    ))
    .expect_err("flake-ref attrs accept only strings, ints, and bools");
    assert!(matches!(
        bad_type.kind(),
        TreeWalkErrorKind::FlakeRefAttrType { attr, actual: ValueTag::Null, .. }
            if attr.as_slice() == b"owner"
    ));

    let thunk = eval_whnf_owned(&lower(
        r#"builtins.flakeRefToString {
                type = "path";
                path = "/tmp/source";
                revCount = 1 + 1;
            }"#,
    ))
    .expect_err("computed flake-ref attrs are not forced");
    assert!(matches!(
        thunk.kind(),
        TreeWalkErrorKind::FlakeRefAttrType { attr, actual: ValueTag::Thunk, .. }
            if attr.as_slice() == b"revCount"
    ));

    eval_whnf_owned(&lower(
        r#"builtins.flakeRefToString {
                type = "git";
                url = "https://example.com/repo";
                rev = "bad";
            }"#,
    ))
    .expect_err("invalid rendered git rev is rejected");

    eval_whnf_owned(&lower(
        r#"builtins.flakeRefToString {
                type = "tarball";
                url = "https://example.com/source.tar.gz";
                narHash = "not-a-hash";
            }"#,
    ))
    .expect_err("invalid rendered narHash is rejected");

    eval_whnf_owned(&lower(
        r#"builtins.flakeRefToString {
                type = "git";
                url = "https://example.com/repo";
                publicKeys = "not-json";
            }"#,
    ))
    .expect_err("invalid rendered publicKeys JSON is rejected");
}

#[test]
fn present_unimplemented_builtin_stubs_select_as_lambdas() {
    for name in PRESENT_UNIMPLEMENTED_BUILTIN_STUBS {
        let selected = format!("builtins.{name} or 42");

        assert_eq!(
            eval_string_bytes(&format!("builtins.typeOf ({selected})")),
            b"lambda",
            "{name} should select the builtin stub, not the default",
        );
        assert_eq!(
            eval_list_string_bytes(&format!(
                "builtins.attrNames (builtins.functionArgs ({selected}))"
            )),
            Vec::<Vec<u8>>::new(),
            "{name} should expose primop-style empty functionArgs",
        );
    }
}

#[test]
fn present_unimplemented_builtin_stubs_error_when_called() {
    for (source, name) in [(
        r#"builtins.fetchMercurial "https://example.invalid/repo""#,
        b"fetchMercurial".as_slice(),
    )] {
        let ir = lower(source);
        let error = eval_whnf_owned(&ir).expect_err("unimplemented builtin stub errors");

        assert_eq!(
            error.kind(),
            TreeWalkErrorKind::UnsupportedPrimOp {
                id: ir.root,
                symbol: symbol_for(&ir, name),
            }
        );
    }
}

#[test]
fn get_flake_preflights_argument_before_fetching() {
    let error =
        eval_whnf_owned(&lower("builtins.getFlake 1")).expect_err("getFlake requires string");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Int,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"let get = builtins.getFlake; in get (builtins.throw "flake")"#,
    ))
    .expect_err("first-class getFlake forces its argument");
    assert!(matches!(error.kind(), TreeWalkErrorKind::Thrown { .. }));

    let error = eval_whnf_owned(&lower(
        r#"builtins.getFlake (builtins.toFile "flake-ref" "nixpkgs")"#,
    ))
    .expect_err("getFlake rejects context-bearing strings");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed { op: "getFlake", .. }
    ));

    let error = eval_whnf_owned(&lower(r#"builtins.getFlake "unknown+scheme://example""#))
        .expect_err("getFlake validates flake-reference syntax");
    assert!(matches!(error.kind(), TreeWalkErrorKind::FlakeRef { .. }));

    let error = eval_whnf_owned(&lower(r#"let get = builtins.getFlake; in get "nixpkgs""#))
        .expect_err("indirect getFlake refs are not resolved yet");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTree { message, .. }
            if message == "unresolved indirect fetchTree flake reference"
    ));
}

#[test]
fn fetch_tree_resolves_configured_indirect_flake_refs() {
    let root = unique_temp_dir("fetch-tree-indirect");
    fs::write(root.join("payload.txt"), b"configured indirect fetchTree")
        .expect("payload fixture writes");
    let store_dir = unique_temp_dir("fetch-tree-indirect-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    options.set_flake_ref_resolution(
        b"flake:nixpkgs".to_vec(),
        format!("path:{}", path_source(&root)).into_bytes(),
    );

    let json = eval_json_bytes_with_options(
        r#"
        let x = builtins.fetchTree "nixpkgs";
        in {
          keys = builtins.attrNames x;
          payload = builtins.readFile "${x.outPath}/payload.txt";
        }
        "#,
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("indirect fetchTree JSON parses");
    assert_eq!(
        value["keys"],
        serde_json::json!(["lastModified", "lastModifiedDate", "narHash", "outPath"])
    );
    assert_eq!(value["payload"], "configured indirect fetchTree");

    fs::remove_dir_all(root).expect("fetchTree indirect temp directory removes");
    fs::remove_dir_all(store_dir).expect("fetchTree indirect store directory removes");
}

#[test]
fn fetch_tree_resolves_configured_indirect_attrset_refs() {
    let root = unique_temp_dir("fetch-tree-indirect-attrset");
    fs::write(
        root.join("payload.txt"),
        b"configured indirect attrset fetchTree",
    )
    .expect("payload fixture writes");
    let store_dir = unique_temp_dir("fetch-tree-indirect-attrset-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    options.set_flake_ref_resolution(
        b"flake:nixpkgs/unstable".to_vec(),
        format!("path:{}", path_source(&root)).into_bytes(),
    );

    let json = eval_json_bytes_with_options(
        r#"
        let x = builtins.fetchTree {
          type = "indirect";
          id = "nixpkgs";
          ref = "unstable";
        };
        in {
          keys = builtins.attrNames x;
          payload = builtins.readFile "${x.outPath}/payload.txt";
        }
        "#,
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("indirect attrset fetchTree JSON parses");
    assert_eq!(
        value["keys"],
        serde_json::json!(["lastModified", "lastModifiedDate", "narHash", "outPath"])
    );
    assert_eq!(value["payload"], "configured indirect attrset fetchTree");

    fs::remove_dir_all(root).expect("fetchTree indirect attrset temp directory removes");
    fs::remove_dir_all(store_dir).expect("fetchTree indirect attrset store directory removes");
}

#[test]
fn fetch_tree_indirect_attrset_refs_include_rev_and_dir_in_resolution_key() {
    let root = unique_temp_dir("fetch-tree-indirect-attrset-rev-dir");
    fs::write(
        root.join("payload.txt"),
        b"configured indirect attrset rev dir",
    )
    .expect("payload fixture writes");
    let store_dir = unique_temp_dir("fetch-tree-indirect-attrset-rev-dir-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let rev = "0000000000000000000000000000000000000000";
    options.set_flake_ref_resolution(
        format!("flake:nixpkgs/{rev}?dir=sub").into_bytes(),
        format!("path:{}", path_source(&root)).into_bytes(),
    );

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
            let x = builtins.fetchTree {{
              type = "indirect";
              id = "nixpkgs";
              rev = "{rev}";
              dir = "sub";
            }};
            in {{
              keys = builtins.attrNames x;
              payload = builtins.readFile "${{x.outPath}}/payload.txt";
            }}
            "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("indirect attrset rev dir JSON parses");
    assert_eq!(
        value["keys"],
        serde_json::json!(["lastModified", "lastModifiedDate", "narHash", "outPath"])
    );
    assert_eq!(value["payload"], "configured indirect attrset rev dir");

    fs::remove_dir_all(root).expect("fetchTree indirect attrset rev dir temp directory removes");
    fs::remove_dir_all(store_dir)
        .expect("fetchTree indirect attrset rev dir store directory removes");
}

#[test]
fn fetch_tree_indirect_attrsets_reject_unpreserved_metadata() {
    let error = eval_whnf_owned(&lower(
        r#"
        builtins.fetchTree {
          type = "indirect";
          id = "nixpkgs";
          narHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        }
        "#,
    ))
    .expect_err("indirect attrset narHash is not silently ignored");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchTreeAttr { attr, .. }
            if attr.as_slice() == b"narHash"
    ));
}

#[test]
fn fetch_tree_rejects_configured_indirect_ref_resolution_cycles() {
    let mut options = TreeWalkOptions::new();
    options.set_flake_ref_resolution(b"flake:nixpkgs".to_vec(), b"flake:aos".to_vec());
    options.set_flake_ref_resolution(b"flake:aos".to_vec(), b"flake:nixpkgs".to_vec());

    let error = eval_whnf_owned_with_options(&lower(r#"builtins.fetchTree "nixpkgs""#), options)
        .expect_err("indirect fetchTree cycle rejects at bounded depth");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchTree { message, .. }
            if message == "indirect fetchTree flake reference resolution depth exceeded"
    ));
}

#[test]
fn get_flake_resolves_configured_indirect_flake_refs() {
    let root = unique_temp_dir("get-flake-indirect");
    fs::write(
        root.join("flake.nix"),
        br#"
            {
              outputs = { self }: {
                answer = 7;
                fromSelfOutPath = self.outPath;
              };
            }
            "#,
    )
    .expect("flake.nix writes");
    let store_dir = unique_temp_dir("get-flake-indirect-store");
    let mut options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    options.set_flake_ref_resolution(
        b"flake:nixpkgs".to_vec(),
        format!("path:{}", path_source(&root)).into_bytes(),
    );

    let json = eval_json_bytes_with_options(
        r#"
        let f = builtins.getFlake "nixpkgs";
        in {
          answer = f.answer;
          flakeType = f._type;
          inputs = builtins.attrNames f.inputs;
          selfOutPath = f.fromSelfOutPath;
          flakeOutPath = f.outPath;
        }
        "#,
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("indirect getFlake JSON parses");
    assert_eq!(value["answer"], 7);
    assert_eq!(value["flakeType"], "flake");
    assert_eq!(value["inputs"], serde_json::json!([]));
    assert_eq!(value["selfOutPath"], value["flakeOutPath"]);
    let out_path = value["flakeOutPath"]
        .as_str()
        .expect("flakeOutPath is a string");
    assert!(out_path.starts_with(path_source(&store_dir).as_str()));

    fs::remove_dir_all(root).expect("getFlake indirect temp directory removes");
    fs::remove_dir_all(store_dir).expect("getFlake indirect store directory removes");
}

#[test]
fn get_flake_evaluates_local_inputless_flakes() {
    let root = unique_temp_dir("get-flake-local");
    fs::write(
        root.join("flake.nix"),
        br#"
            {
              outputs = { self }: {
                answer = 42;
                foo = "foo";
                fromSelfFoo = self.foo;
                fromSelfOutPath = self.outPath;
                narHash = "output-nar-hash";
                nested.value = "ok";
                outPath = "output-out-path";
                sourceInfo = "output-source-info";
              };
            }
            "#,
    )
    .expect("flake.nix writes");
    let store_dir = unique_temp_dir("get-flake-local-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let flake_ref = nix_string_literal(&path_source(&root));

    let source = format!(
        r#"
                let f = builtins.getFlake {flake_ref};
                in {{
                  answer = f.answer;
                  flakeType = f._type;
                  fromSelfFoo = f.fromSelfFoo;
                  inputs = builtins.attrNames f.inputs;
                  nested = f.nested.value;
                  outputNarHash = f.outputs.narHash;
                  outputNames = builtins.attrNames f.outputs;
                  outputOutPath = f.outputs.outPath;
                  outputSourceInfo = f.outputs.sourceInfo;
                  topNames = builtins.attrNames f;
                  flakeOutPath = f.outPath;
                  flakeNarHash = f.narHash;
                  selfOutPath = f.fromSelfOutPath;
                  sourceOutPath = f.sourceInfo.outPath;
                }}
                "#
    );
    let json = eval_json_bytes_with_options(&source, options);
    let value: serde_json::Value = serde_json::from_slice(&json).expect("flake JSON parses");

    assert_eq!(value["answer"], 42);
    assert_eq!(value["flakeType"], "flake");
    assert_eq!(value["fromSelfFoo"], "foo");
    assert_eq!(value["inputs"], serde_json::json!([]));
    assert_eq!(value["nested"], "ok");
    assert_eq!(value["outputNarHash"], "output-nar-hash");
    assert_eq!(value["outputOutPath"], "output-out-path");
    assert_eq!(value["outputSourceInfo"], "output-source-info");
    assert_eq!(
        value["outputNames"],
        serde_json::json!([
            "answer",
            "foo",
            "fromSelfFoo",
            "fromSelfOutPath",
            "narHash",
            "nested",
            "outPath",
            "sourceInfo"
        ])
    );
    assert_eq!(
        value["topNames"],
        serde_json::json!([
            "_type",
            "answer",
            "foo",
            "fromSelfFoo",
            "fromSelfOutPath",
            "inputs",
            "lastModified",
            "lastModifiedDate",
            "narHash",
            "nested",
            "outPath",
            "outputs",
            "sourceInfo"
        ])
    );
    let out_path = value["flakeOutPath"]
        .as_str()
        .expect("flakeOutPath is a string");
    assert!(out_path.starts_with(path_source(&store_dir).as_str()));
    assert_eq!(value["selfOutPath"], out_path);
    assert_eq!(value["sourceOutPath"], out_path);
    assert!(
        value["flakeNarHash"]
            .as_str()
            .expect("flakeNarHash is a string")
            .starts_with("sha256-")
    );

    fs::remove_dir_all(root).expect("flake temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}
