//! Split-out tests (part_2). See parent module.

use super::*;

#[test]
fn get_flake_resolves_direct_declared_inputs() {
    let child = unique_temp_dir("get-flake-input-child");
    fs::write(
        child.join("flake.nix"),
        br#"
            {
              outputs = { self }: {
                answer = 11;
                fromSelfOutPath = self.outPath;
              };
            }
            "#,
    )
    .expect("child flake.nix writes");
    let alias = unique_temp_dir("get-flake-input-alias");
    fs::write(
        alias.join("flake.nix"),
        br#"
            {
              outputs = { self }: {
                answer = 31;
              };
            }
            "#,
    )
    .expect("alias flake.nix writes");
    let root = unique_temp_dir("get-flake-input-parent");
    fs::write(
        root.join("flake.nix"),
        format!(
            r#"
            {{
              inputs.child.url = "path:{}";
              inputs.alias = "path:{}";
              outputs = {{ self, child, alias }}: {{
                answer = child.answer + alias.answer;
                childType = child._type;
                childSelfOutPath = child.fromSelfOutPath;
                childOutPath = child.outPath;
                inputNames = builtins.attrNames self.inputs;
              }};
            }}
            "#,
            path_source(&child),
            path_source(&alias)
        ),
    )
    .expect("parent flake.nix writes");
    let store_dir = unique_temp_dir("get-flake-input-parent-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let flake_ref = nix_string_literal(&format!("path:{}", path_source(&root)));

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
            let f = builtins.getFlake {flake_ref};
            in {{
              answer = f.answer;
              childType = f.childType;
              childSelfOutPath = f.childSelfOutPath;
              childOutPath = f.childOutPath;
              inputs = f.inputNames;
            }}
            "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("direct input getFlake JSON parses");
    assert_eq!(value["answer"], 42);
    assert_eq!(value["childType"], "flake");
    assert_eq!(value["inputs"], serde_json::json!(["alias", "child"]));
    assert_eq!(value["childSelfOutPath"], value["childOutPath"]);

    fs::remove_dir_all(child).expect("child flake temp directory removes");
    fs::remove_dir_all(alias).expect("alias flake temp directory removes");
    fs::remove_dir_all(root).expect("parent flake temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn get_flake_resolves_bare_absolute_declared_inputs() {
    let child = unique_temp_dir("get-flake-bare-input-child");
    fs::write(
        child.join("flake.nix"),
        br#"
            {
              outputs = { self }: {
                answer = 19;
                fromSelfOutPath = self.outPath;
              };
            }
            "#,
    )
    .expect("child flake.nix writes");
    let alias = unique_temp_dir("get-flake-bare-input-alias");
    fs::write(
        alias.join("flake.nix"),
        br#"
            {
              outputs = { self }: {
                answer = 23;
                fromSelfOutPath = self.outPath;
              };
            }
            "#,
    )
    .expect("alias flake.nix writes");
    let root = unique_temp_dir("get-flake-bare-input-parent");
    fs::write(
        root.join("flake.nix"),
        format!(
            r#"
            {{
              inputs.child = "{}";
              inputs.alias.url = "{}";
              outputs = {{ self, child, alias }}: {{
                answer = child.answer + alias.answer;
                childOutPath = child.outPath;
                childSelfOutPath = child.fromSelfOutPath;
                aliasOutPath = alias.outPath;
                aliasSelfOutPath = alias.fromSelfOutPath;
                inputNames = builtins.attrNames self.inputs;
              }};
            }}
            "#,
            path_source(&child),
            path_source(&alias)
        ),
    )
    .expect("parent flake.nix writes");
    let store_dir = unique_temp_dir("get-flake-bare-input-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let flake_ref = nix_string_literal(&format!("path:{}", path_source(&root)));

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
            let f = builtins.getFlake {flake_ref};
            in {{
              answer = f.answer;
              childOutPath = f.childOutPath;
              childSelfOutPath = f.childSelfOutPath;
              aliasOutPath = f.aliasOutPath;
              aliasSelfOutPath = f.aliasSelfOutPath;
              inputs = f.inputNames;
            }}
            "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("bare declared input getFlake JSON parses");
    assert_eq!(value["answer"], 42);
    assert_eq!(value["inputs"], serde_json::json!(["alias", "child"]));
    assert_eq!(value["childOutPath"], value["childSelfOutPath"]);
    assert_eq!(value["aliasOutPath"], value["aliasSelfOutPath"]);

    fs::remove_dir_all(child).expect("child flake temp directory removes");
    fs::remove_dir_all(alias).expect("alias flake temp directory removes");
    fs::remove_dir_all(root).expect("parent flake temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn get_flake_resolves_declared_input_overrides() {
    let default_deeper = unique_temp_dir("get-flake-override-default-deeper");
    fs::write(
        default_deeper.join("flake.nix"),
        br#"
            {
              outputs = { self }: {
                answer = 5;
                fromSelfOutPath = self.outPath;
              };
            }
            "#,
    )
    .expect("default deeper flake.nix writes");
    let replacement_deeper = unique_temp_dir("get-flake-override-replacement-deeper");
    fs::write(
        replacement_deeper.join("flake.nix"),
        br#"
            {
              outputs = { self }: {
                answer = 41;
                fromSelfOutPath = self.outPath;
              };
            }
            "#,
    )
    .expect("replacement deeper flake.nix writes");
    let child = unique_temp_dir("get-flake-override-child");
    fs::write(
        child.join("flake.nix"),
        format!(
            r#"
            {{
              inputs.deeper.url = "path:{}";
              outputs = {{ self, deeper }}: {{
                answer = deeper.answer + 1;
                deeperOutPath = deeper.outPath;
                deeperSelfOutPath = deeper.fromSelfOutPath;
                inputNames = builtins.attrNames self.inputs;
              }};
            }}
            "#,
            path_source(&default_deeper)
        ),
    )
    .expect("child flake.nix writes");
    let root = unique_temp_dir("get-flake-override-parent");
    fs::write(
        root.join("flake.nix"),
        format!(
            r#"
            {{
              inputs.child = {{
                url = "path:{}";
                inputs.deeper.url = "path:{}";
              }};
              outputs = {{ self, child }}: {{
                answer = child.answer;
                childInputNames = child.inputNames;
                childOutPath = child.outPath;
                deeperOutPath = child.deeperOutPath;
                deeperSelfOutPath = child.deeperSelfOutPath;
                inputNames = builtins.attrNames self.inputs;
              }};
            }}
            "#,
            path_source(&child),
            path_source(&replacement_deeper)
        ),
    )
    .expect("parent flake.nix writes");
    let store_dir = unique_temp_dir("get-flake-override-parent-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let flake_ref = nix_string_literal(&format!("path:{}", path_source(&root)));

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
            let f = builtins.getFlake {flake_ref};
            in {{
              answer = f.answer;
              childInputs = f.childInputNames;
              inputs = f.inputNames;
              deeperOutPath = f.deeperOutPath;
              deeperSelfOutPath = f.deeperSelfOutPath;
            }}
            "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("input override getFlake JSON parses");
    assert_eq!(value["answer"], 42);
    assert_eq!(value["childInputs"], serde_json::json!(["deeper"]));
    assert_eq!(value["inputs"], serde_json::json!(["child"]));
    assert_eq!(value["deeperOutPath"], value["deeperSelfOutPath"]);

    fs::remove_dir_all(default_deeper).expect("default deeper flake temp directory removes");
    fs::remove_dir_all(replacement_deeper)
        .expect("replacement deeper flake temp directory removes");
    fs::remove_dir_all(child).expect("child flake temp directory removes");
    fs::remove_dir_all(root).expect("parent flake temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn get_flake_resolves_follows_input_paths() {
    let deeper = unique_temp_dir("get-flake-follows-deeper");
    fs::write(
        deeper.join("flake.nix"),
        br#"
            {
              outputs = { self }: {
                answer = 23;
                fromSelfOutPath = self.outPath;
              };
            }
            "#,
    )
    .expect("deeper flake.nix writes");
    let child = unique_temp_dir("get-flake-follows-child");
    fs::write(
        child.join("flake.nix"),
        format!(
            r#"
            {{
              inputs.deeper.url = "path:{}";
              outputs = {{ self, deeper }}: {{
                answer = 17;
                fromSelfOutPath = self.outPath;
                deeperAnswer = deeper.answer;
              }};
            }}
            "#,
            path_source(&deeper)
        ),
    )
    .expect("child flake.nix writes");
    let root = unique_temp_dir("get-flake-follows-parent");
    fs::write(
        root.join("flake.nix"),
        format!(
            r#"
            {{
              inputs.child.url = "path:{}";
              inputs.alias.follows = "child";
              inputs.nested.follows = "child/deeper";
              inputs.missing.follows = "missing-target";
              inputs.root.follows = "";
              inputs.self.follows = "self";
              outputs = {{ self, child, alias, root, ... }}: {{
                answer = child.answer + alias.answer;
                aliasOutPath = alias.outPath;
                childOutPath = child.outPath;
                nestedOutPath = self.inputs.nested.outPath;
                rootOutPath = root.outPath;
                inputNames = builtins.attrNames self.inputs;
                missingAnswer = self.inputs.missing.answer;
                nestedAnswer = self.inputs.nested.answer;
                nestedSelfOutPath = self.inputs.nested.fromSelfOutPath;
                selfOutPath = self.outPath;
                selfAnswer = self.inputs.self.answer;
              }};
            }}
            "#,
            path_source(&child)
        ),
    )
    .expect("parent flake.nix writes");
    let store_dir = unique_temp_dir("get-flake-follows-parent-store");
    let options = TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
        .expect("temporary store root configures");
    let flake_ref = nix_string_literal(&format!("path:{}", path_source(&root)));

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
            let f = builtins.getFlake {flake_ref};
            in {{
              answer = f.answer;
              aliasOutPath = f.aliasOutPath;
              childOutPath = f.childOutPath;
              nestedAnswer = f.nestedAnswer;
              nestedOutPath = f.nestedOutPath;
              nestedSelfOutPath = f.nestedSelfOutPath;
              rootOutPath = f.rootOutPath;
              selfOutPath = f.selfOutPath;
              inputs = f.inputNames;
            }}
            "#
        ),
        options,
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("follows getFlake JSON parses");
    assert_eq!(value["answer"], 34);
    assert_eq!(value["aliasOutPath"], value["childOutPath"]);
    assert_eq!(value["nestedAnswer"], 23);
    assert_eq!(value["nestedOutPath"], value["nestedSelfOutPath"]);
    assert_eq!(value["rootOutPath"], value["selfOutPath"]);
    assert_eq!(
        value["inputs"],
        serde_json::json!(["alias", "child", "missing", "nested", "root", "self"])
    );

    let missing_error = eval_whnf_owned_with_options(
        &lower(&format!("(builtins.getFlake {flake_ref}).missingAnswer")),
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures"),
    )
    .expect_err("missing follows target remains unsupported when demanded");
    assert!(matches!(
        missing_error.kind(),
        TreeWalkErrorKind::Thrown { .. }
    ));

    let self_error = eval_whnf_owned_with_options(
        &lower(&format!("(builtins.getFlake {flake_ref}).selfAnswer")),
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures"),
    )
    .expect_err("self follows cycle rejects when demanded");
    assert!(matches!(
        self_error.kind(),
        TreeWalkErrorKind::Force {
            source: ForceError::InfiniteRecursion,
            ..
        }
    ));

    fs::remove_dir_all(deeper).expect("deeper flake temp directory removes");
    fs::remove_dir_all(child).expect("child flake temp directory removes");
    fs::remove_dir_all(root).expect("parent flake temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn get_flake_obeys_fetch_tree_locking_and_rejects_unsupported_declared_inputs() {
    let child = unique_temp_dir("get-flake-unsupported-input-child");
    fs::write(
        child.join("flake.nix"),
        br#"
            {
              outputs = { self }: {
                answer = 13;
              };
            }
            "#,
    )
    .expect("child flake.nix writes");
    let root = unique_temp_dir("get-flake-locked");
    fs::write(
        root.join("flake.nix"),
        format!(
            r#"
            {{
              inputs.bad = {{}};
              inputs.extra = {{ url = "path:{}"; follows = "bad"; }};
              inputs.structured.url = {{ type = "path"; path = "{}"; }};
              inputs.structuredOverride = {{
                url = {{ type = "path"; path = "{}"; }};
                inputs = {{}};
              }};
              outputs = {{ self, bad, extra, structured, structuredOverride }}: {{
                answer = bad.answer;
                extraAnswer = extra.answer;
                structuredAnswer = structured.answer;
                structuredOverrideAnswer = structuredOverride.answer;
                unusedBadNames = builtins.attrNames self.inputs;
                unusedBadValue = 42;
              }};
            }}
            "#,
            path_source(&child),
            path_source(&child),
            path_source(&child)
        ),
    )
    .expect("flake.nix writes");
    let store_dir = unique_temp_dir("get-flake-locked-store");
    let flake_ref = nix_string_literal(&format!("path:{}", path_source(&root)));
    let pure_error = eval_whnf_owned_with_options(
        &lower(&format!("builtins.getFlake {flake_ref}")),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure getFlake path refs require a narHash");
    assert!(matches!(
        pure_error.kind(),
        TreeWalkErrorKind::FetchTreeLockedInputRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    let input_error = eval_whnf_owned_with_options(
        &lower(&format!("(builtins.getFlake {flake_ref}).answer")),
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures"),
    )
    .expect_err("unsupported declared inputs are rejected");
    assert!(matches!(
        input_error.kind(),
        TreeWalkErrorKind::Thrown { .. }
    ));

    let extra_error = eval_whnf_owned_with_options(
        &lower(&format!("(builtins.getFlake {flake_ref}).extraAnswer")),
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures"),
    )
    .expect_err("declared inputs with extra keys are rejected");
    assert!(matches!(
        extra_error.kind(),
        TreeWalkErrorKind::Thrown { .. }
    ));

    let structured_error = eval_whnf_owned_with_options(
        &lower(&format!("(builtins.getFlake {flake_ref}).structuredAnswer")),
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures"),
    )
    .expect_err("declared inputs with non-string url values are rejected");
    assert!(matches!(
        structured_error.kind(),
        TreeWalkErrorKind::Thrown { .. }
    ));

    let structured_override_error = eval_whnf_owned_with_options(
        &lower(&format!(
            "(builtins.getFlake {flake_ref}).structuredOverrideAnswer"
        )),
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures"),
    )
    .expect_err("declared input overrides with non-string url values are rejected");
    assert!(matches!(
        structured_override_error.kind(),
        TreeWalkErrorKind::Thrown { .. }
    ));

    let json = eval_json_bytes_with_options(
        &format!(
            r#"
            let f = builtins.getFlake {flake_ref};
            in {{
              names = f.unusedBadNames;
              value = f.unusedBadValue;
            }}
            "#
        ),
        TreeWalkOptions::with_store_dir(store_dir.as_os_str().as_bytes().to_vec())
            .expect("temporary store root configures"),
    );
    let value: serde_json::Value =
        serde_json::from_slice(&json).expect("lazy unsupported input JSON parses");
    assert_eq!(
        value["names"],
        serde_json::json!(["bad", "extra", "structured", "structuredOverride"])
    );
    assert_eq!(value["value"], 42);

    fs::remove_dir_all(child).expect("child flake temp directory removes");
    fs::remove_dir_all(root).expect("flake temp directory removes");
    fs::remove_dir_all(store_dir).expect("store temp directory removes");
}

#[test]
fn fetch_mercurial_stub_preflights_default_mode_arguments() {
    let error = eval_whnf_owned(&lower("builtins.fetchMercurial null"))
        .expect_err("fetchMercurial rejects invalid argument type before fallback");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "set or string",
            actual: ValueTag::Null,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
            r#"let fetch = builtins.fetchMercurial; in fetch { url = "https://example.invalid/repo"; bogus = 1; }"#,
        ))
        .expect_err("first-class fetchMercurial rejects unsupported attrs before fallback");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchMercurialAttr { attr, .. }
            if attr.as_slice() == b"bogus"
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.fetchMercurial { url = "https://example.invalid/repo"; name = null; }"#,
    ))
    .expect_err("fetchMercurial validates name before fallback");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Null,
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
        r#"builtins.fetchMercurial (builtins.toFile "repo-url" "https://example.invalid/repo")"#,
    ))
    .expect_err("fetchMercurial rejects context-bearing URL strings");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "fetchMercurial",
            ..
        }
    ));

    let error = eval_whnf_owned(&lower(
            r#"builtins.fetchMercurial { url = "https://example.invalid/repo"; rev = builtins.toFile "rev" "abcdef"; }"#,
        ))
        .expect_err("fetchMercurial rejects context-bearing revision strings");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::StringContextNotAllowed {
            op: "fetchMercurial",
            ..
        }
    ));
}

#[test]
fn fetch_mercurial_stub_preflights_pure_mode_pinning() {
    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.fetchMercurial "https://example.invalid/repo""#),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure fetchMercurial rejects unpinned input before fallback");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::FetchMercurialRevRequired {
            mode: EvalMode::Pure,
            ..
        }
    ));

    let ir = lower(
        r#"builtins.fetchMercurial { url = "https://example.invalid/repo"; rev = "abcdef"; }"#,
    );
    let error = eval_whnf_owned_with_options(&ir, TreeWalkOptions::with_eval_mode(EvalMode::Pure))
        .expect_err("pinned fetchMercurial remains a fallback boundary");
    assert_eq!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedPrimOp {
            id: ir.root,
            symbol: symbol_for(&ir, b"fetchMercurial"),
        }
    );

    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.fetchMercurial { url = "https://example.invalid/repo"; bogus = 1; }"#),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure fetchMercurial rejects unsupported attrs before pinning fallback");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::UnsupportedFetchMercurialAttr { attr, .. }
            if attr.as_slice() == b"bogus"
    ));

    let error = eval_whnf_owned_with_options(
        &lower(r#"builtins.fetchMercurial { url = "https://example.invalid/repo"; name = null; }"#),
        TreeWalkOptions::with_eval_mode(EvalMode::Pure),
    )
    .expect_err("pure fetchMercurial validates name before pinning");
    assert!(matches!(
        error.kind(),
        TreeWalkErrorKind::Type {
            expected: "string",
            actual: ValueTag::Null,
            ..
        }
    ));

    let error = eval_whnf_owned_with_options(
            &lower(
                r#"builtins.fetchMercurial { url = "https://example.invalid/repo"; rev = "abcdef"; name = builtins.throw "name"; }"#,
            ),
            TreeWalkOptions::with_eval_mode(EvalMode::Pure),
        )
        .expect_err("pure fetchMercurial forces name before fallback");
    assert!(matches!(error.kind(), TreeWalkErrorKind::Thrown { .. }));
}
