//! Checks harness-lint allow annotations.

// crucible-lint: allow rust-allow -- split support modules are shared across harness-lint regression crates.
#![allow(dead_code, unused_imports)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

#[path = "support/harness_lint/allow.rs"]
mod allow;
#[path = "support/harness_lint/common.rs"]
mod common;
#[path = "support/harness_lint/error_logging.rs"]
mod error_logging;
#[path = "support/harness_lint/lex.rs"]
mod lex;
#[path = "support/harness_lint/scan.rs"]
mod scan;

use allow::*;
use common::*;
use error_logging::*;
use lex::*;
use scan::*;

#[test]
fn harness_lint_recognizes_split_test_modules() {
    let package = Path::new("crucible-example");

    assert!(is_test_only_source(
        package,
        Path::new("crucible-example/src/protocol_test.rs")
    ));
    assert!(is_test_only_source(
        package,
        Path::new("crucible-example/src/protocol_tests.rs")
    ));
    assert!(is_test_only_source(
        package,
        Path::new("crucible-example/src/protocol_test_support.rs")
    ));
    assert!(is_test_only_source(
        package,
        Path::new("crucible-example/tests/support/mod.rs")
    ));
    assert!(!is_test_only_source(
        package,
        Path::new("crucible-example/src/protocol.rs")
    ));
}

#[test]
fn harness_lint_enforces_annotated_exceptions() {
    let map_findings = scan_content(
        Path::new("synthetic.rs"),
        r#"
            fn allowed() {
                // crucible-lint: allow unordered-map-set -- synthetic pure lookup cache, order never escapes
                let _map: std::collections::HashMap<u8, u8> = std::collections::HashMap::new();
            }
        "#,
    );
    assert!(
        map_findings.is_empty(),
        "expected annotated map exception to pass, got {map_findings:?}"
    );

    let default_hasher_findings = scan_content(
        Path::new("synthetic.rs"),
        r#"
            fn allowed() {
                // crucible-lint: allow default-random-hasher -- synthetic fixture proves annotated exceptions for non-identity hashing
                let _hasher = std::collections::hash_map::DefaultHasher::new();
            }
        "#,
    );
    assert!(
        default_hasher_findings.is_empty(),
        "expected annotated default hasher exception to pass, got {default_hasher_findings:?}"
    );

    let iteration_findings = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            use std::collections::HashMap;

            fn allowed() {
                let map: HashMap<u8, u8> = HashMap::new();
                // crucible-lint: allow hash-iteration -- synthetic cache is sorted before any state/log use
                for item in map.iter() {
                    consume(item);
                }
            }
        "#,
    );
    assert!(
        iteration_findings.is_empty(),
        "expected annotated iteration exception to pass, got {iteration_findings:?}"
    );

    let malformed_findings = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            fn bad() {
                // crucible-lint: allow hash-iteration
                work();
            }
        "#,
    );
    assert_contains(&malformed_findings, "malformed crucible-lint allow");

    let unannotated_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            #[allow(clippy::disallowed_types)]
            fn bad() {}
        "#,
    );
    assert_contains(&unannotated_allow, "unannotated allow");

    let mismatched_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            // crucible-lint: allow unordered-map-set -- wrong rule for this clippy allow
            #[allow(clippy::disallowed_types)]
            fn bad() {}
        "#,
    );
    assert_contains(&mismatched_allow, "unannotated allow");

    let cfg_attr_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            #[cfg_attr(test, allow(clippy::disallowed_methods))]
            fn bad() {}
        "#,
    );
    assert_contains(&cfg_attr_allow, "unannotated allow");

    let same_line_unannotated_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            #[derive(Debug)] #[allow(clippy::disallowed_types)]
            fn bad() {}
        "#,
    );
    assert_contains(&same_line_unannotated_allow, "unannotated allow");

    let same_line_annotated_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            // crucible-lint: allow clippy-disallowed-type -- same-line allow attribute is tied to this exception
            #[derive(Debug)] #[allow(clippy::disallowed_types)]
            fn allowed() {}
        "#,
    );
    assert!(
        same_line_annotated_allow.is_empty(),
        "expected annotated same-line allow attribute to pass, got {same_line_annotated_allow:?}"
    );

    let multiline_preceding_same_line_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            #[derive(
                Debug
            )] #[allow(clippy::disallowed_types)]
            fn bad() {}
        "#,
    );
    assert_contains(&multiline_preceding_same_line_allow, "unannotated allow");

    let multi_rule_missing_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            // crucible-lint: allow clippy-disallowed-type -- type allow is tied to this exception
            #[allow(clippy::disallowed_types, clippy::unwrap_used)]
            fn bad() {}
        "#,
    );
    assert_contains(&multi_rule_missing_allow, "unannotated allow");

    let multi_rule_annotated_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            // crucible-lint: allow clippy-disallowed-type -- type allow is tied to this exception
            // crucible-lint: allow panic-shortcut -- panic lint allow is tied to this exception
            #[allow(clippy::disallowed_types, clippy::unwrap_used)]
            fn allowed() {}
        "#,
    );
    assert!(
        multi_rule_annotated_allow.is_empty(),
        "expected fully annotated multi-rule allow attribute to pass, got {multi_rule_annotated_allow:?}"
    );

    let compact_marker_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            //crucible-lint: allow clippy-disallowed-type -- compact marker syntax is invalid
            #[allow(clippy::disallowed_types)]
            fn bad() {}
        "#,
    );
    assert_contains(&compact_marker_allow, "malformed crucible-lint allow");
    assert_contains(&compact_marker_allow, "unannotated allow");

    let token_spaced_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            # [allow(clippy::disallowed_types)]
            fn bad() {}
        "#,
    );
    assert_contains(&token_spaced_allow, "unannotated allow");

    let newline_spaced_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            #
            [allow(clippy::disallowed_types)]
            fn bad() {}
        "#,
    );
    assert_contains(&newline_spaced_allow, "unannotated allow");

    let trailing_marker_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            let _not_a_marker = 0; // crucible-lint: allow clippy-disallowed-type -- trailing marker syntax is invalid
            #[allow(clippy::disallowed_types)]
            fn bad() {}
        "#,
    );
    assert_contains(&trailing_marker_allow, "malformed crucible-lint allow");
    assert_contains(&trailing_marker_allow, "unannotated allow");

    let error_logging_allowed = error_logging_failures(
        Path::new("synthetic.rs"),
        r#"
            fn allowed() {
                // crucible-lint: allow panic-shortcut -- synthetic shortcut is isolated to this regression sample
                maybe().unwrap();
                // crucible-lint: allow direct-diagnostic -- synthetic stdout is isolated to this regression sample
                println!("diagnostic");
                // crucible-lint: allow erased-error -- synthetic erased error is isolated to this regression sample
                anyhow::bail!("error");
                // crucible-lint: allow stringly-error -- synthetic string error is isolated to this regression sample
                let _value: Result<(), String> = Ok(());
            }
        "#,
        false,
    );
    assert!(
        error_logging_allowed.is_empty(),
        "expected annotated error/logging exceptions to pass, got {error_logging_allowed:?}"
    );

    let multiline_mismatched_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            // crucible-lint: allow rust-allow -- wrong rule for multiline clippy allow
            #[allow(
                clippy::disallowed_types
            )]
            fn bad() {}
        "#,
    );
    assert_contains(&multiline_mismatched_allow, "unannotated allow");

    let multiline_annotated_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            // crucible-lint: allow clippy-disallowed-type -- multiline clippy allow is tied to this exception
            #[allow(
                clippy::disallowed_types
            )]
            fn allowed() {}
        "#,
    );
    assert!(
        multiline_annotated_allow.is_empty(),
        "expected annotated multiline allow attribute to pass, got {multiline_annotated_allow:?}"
    );

    let multiline_cfg_attr_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            // crucible-lint: allow clippy-disallowed-method -- multiline cfg_attr clippy allow is tied to this exception
            #[cfg_attr(
                test,
                allow(clippy::disallowed_methods)
            )]
            fn allowed() {}
        "#,
    );
    assert!(
        multiline_cfg_attr_allow.is_empty(),
        "expected annotated multiline cfg_attr allow to pass, got {multiline_cfg_attr_allow:?}"
    );

    let split_head_mismatched_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            // crucible-lint: allow rust-allow -- wrong rule for split-head clippy allow
            #[
                allow(clippy::disallowed_types)
            ]
            fn bad() {}
        "#,
    );
    assert_contains(&split_head_mismatched_allow, "unannotated allow");

    let split_head_annotated_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            // crucible-lint: allow clippy-disallowed-type -- split-head clippy allow is tied to this exception
            #[
                allow(clippy::disallowed_types)
            ]
            fn allowed() {}
        "#,
    );
    assert!(
        split_head_annotated_allow.is_empty(),
        "expected annotated split-head allow attribute to pass, got {split_head_annotated_allow:?}"
    );

    let annotated_allow = custom_static_analysis_failures(
        Path::new("synthetic.rs"),
        r#"
            // crucible-lint: allow clippy-disallowed-type -- synthetic clippy allow is tied to this exception
            #[allow(clippy::disallowed_types)]
            fn allowed() {}
        "#,
    );
    assert!(
        annotated_allow.is_empty(),
        "expected annotated allow attribute to pass, got {annotated_allow:?}"
    );
}
