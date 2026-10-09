//! Ordinary-harness regressions for harness-free fixture discovery and routing.
//!
//! These tests exercise the adapter without running measured workloads or
//! installing the counting allocator in the parallel libtest process.

#[path = "support/fixture_runner.rs"]
mod fixture_runner;

#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "support/allocation.rs"]
mod allocation;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "metadata_scale/report.rs"]
mod report;

#[cfg(target_os = "linux")]
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn nextest_discovery_lists_each_real_case_without_running_it() {
    for case in ["metadata_scale_small", "semantic_no_alloc"] {
        for ignored in [false, true] {
            let mut args = arguments(&["--list", "--format", "terse"]);
            if ignored {
                args.push("--ignored".to_owned());
            }
            let invocation = fixture_runner::parse(&args, case).unwrap();
            let mut output = Vec::new();

            fixture_runner::execute(invocation, case, &mut output, || {
                panic!("discovery entered the measured fixture")
            })
            .unwrap();

            let expected = if ignored {
                String::new()
            } else {
                format!("{case}: test\n")
            };
            assert_eq!(String::from_utf8(output).unwrap(), expected);
        }
    }
}

#[test]
fn nextest_exact_execution_dispatches_the_fixture_operation_once() {
    for case in ["metadata_scale_small", "semantic_no_alloc"] {
        let args = arguments(&["--exact", case, "--nocapture"]);
        let invocation = fixture_runner::parse(&args, case).unwrap();
        let mut output = Vec::new();
        let mut calls = 0;

        fixture_runner::execute(invocation, case, &mut output, || {
            calls += 1;
            Ok(())
        })
        .unwrap();

        assert_eq!(calls, 1);
        assert!(output.is_empty());
    }
}

#[test]
fn fixture_errors_are_not_reported_as_success() {
    let mut output = Vec::new();
    let result = fixture_runner::execute(
        fixture_runner::Invocation::Run,
        "semantic_no_alloc",
        &mut output,
        || Err("fixture failed".into()),
    );

    assert_eq!(result.unwrap_err().to_string(), "fixture failed");
    assert!(output.is_empty());
}

#[test]
fn ordinary_cargo_execution_remains_single_threaded() {
    for args in [
        arguments(&[]),
        arguments(&["--nocapture", "--test-threads", "1"]),
        arguments(&["--include-ignored", "--format", "pretty"]),
    ] {
        assert_eq!(
            fixture_runner::parse(&args, "semantic_no_alloc"),
            Ok(fixture_runner::Invocation::Run)
        );
    }
}

#[test]
fn unknown_names_and_unsupported_or_malformed_arguments_fail() {
    for values in [
        vec!["--exact", "unknown", "--nocapture"],
        vec!["--exact"],
        vec!["--format"],
        vec!["--format", "json"],
        vec!["--test-threads"],
        vec!["--test-threads", "2"],
        vec!["--ignored"],
        vec!["--unknown"],
        vec!["semantic_no_alloc", "semantic_no_alloc"],
        vec!["--million"],
        vec!["--list", "--million"],
        vec![
            "--exact",
            "semantic_no_alloc",
            "--validation-envelope-bytes",
            "1",
        ],
    ] {
        assert!(
            fixture_runner::parse(&arguments(&values), "semantic_no_alloc").is_err(),
            "accepted {values:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn manual_metadata_profiles_keep_their_existing_opt_in_limits() {
    let normal = aos_filesystem_view::TreeCompileLimits::default().working_bytes;
    let small = report::Config::parse(&[]).unwrap();
    let million = report::Config::parse(&arguments(&["--million"])).unwrap();
    let envelope = report::Config::parse(&arguments(&[
        "--million",
        "--validation-envelope-bytes",
        "536870912",
    ]))
    .unwrap();

    assert_eq!(small.profile.children(), 256);
    assert_eq!(small.validation_envelope_bytes, normal);
    assert_eq!(million.profile.children(), 1_000_000);
    assert_eq!(million.validation_envelope_bytes, normal);
    assert_eq!(envelope.validation_envelope_bytes, 536_870_912);

    for values in [
        vec!["--million", "--list", "--format", "terse"],
        vec!["--exact", "metadata_scale_small", "--million"],
        vec!["--validation-envelope-bytes"],
        vec!["--million", "--validation-envelope-bytes", "0"],
        vec!["--validation-envelope-bytes", "1"],
    ] {
        assert!(
            report::Config::parse(&arguments(&values)).is_err(),
            "accepted {values:?}"
        );
    }
}
