//! CLI parsing coverage for the Nix evaluator benchmark modes.

use super::*;

#[test]
fn parses_defaults() {
    let cli = parse_cli(["aos", "nix-bench"]);

    match cli.command {
        Commands::NixBench {
            attr,
            file,
            samples,
            history,
            no_record,
            fail_on_regression,
            require_perf_win,
            regression_threshold,
            memory_regression_threshold,
            changed_tree,
        } => {
            assert!(attr.is_empty());
            assert_eq!(file, None);
            assert_eq!(samples, crate::commands::nix_bench::default_samples());
            assert_eq!(history, None);
            assert!(!no_record);
            assert!(!fail_on_regression);
            assert!(!require_perf_win);
            assert!(!changed_tree);
            assert_eq!(
                regression_threshold,
                crate::commands::nix_bench::default_regression_threshold()
            );
            assert_eq!(
                memory_regression_threshold,
                crate::commands::nix_bench::default_memory_regression_threshold()
            );
        }
        _ => panic!("expected nix-bench command"),
    }
}

#[test]
fn parses_explicit_options() {
    let cli = parse_cli([
        "aos",
        "nix-bench",
        "--attr",
        "pkgs.zlib",
        "-A",
        "systems.server.build.toplevel",
        "--file",
        "default.nix",
        "--samples",
        "5",
        "--history",
        "/tmp/history.jsonl",
        "--no-record",
        "--fail-on-regression",
        "--require-perf-win",
        "--regression-threshold",
        "0.2",
        "--memory-regression-threshold",
        "0.3",
    ]);

    match cli.command {
        Commands::NixBench {
            attr,
            file,
            samples,
            history,
            no_record,
            fail_on_regression,
            require_perf_win,
            regression_threshold,
            memory_regression_threshold,
            changed_tree,
        } => {
            assert_eq!(
                attr,
                vec![
                    "pkgs.zlib".to_string(),
                    "systems.server.build.toplevel".to_string()
                ]
            );
            assert_eq!(file, Some(std::path::PathBuf::from("default.nix")));
            assert_eq!(samples, 5);
            assert_eq!(
                history,
                Some(std::path::PathBuf::from("/tmp/history.jsonl"))
            );
            assert!(no_record);
            assert!(fail_on_regression);
            assert!(require_perf_win);
            assert!(!changed_tree);
            assert_eq!(regression_threshold, 0.2);
            assert_eq!(memory_regression_threshold, 0.3);
        }
        _ => panic!("expected nix-bench command"),
    }
}

#[test]
fn parses_changed_tree_mode() {
    let cli = parse_cli(["aos", "nix-bench", "--changed-tree", "--samples", "2"]);

    match cli.command {
        Commands::NixBench {
            changed_tree,
            samples,
            ..
        } => {
            assert!(changed_tree);
            assert_eq!(samples, 2);
        }
        _ => panic!("expected nix-bench command"),
    }
}

#[test]
fn changed_tree_rejects_normal_corpus_selection() {
    let error = parse_cli_error(["aos", "nix-bench", "--changed-tree", "--attr", "pkgs.zlib"]);

    assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
}
