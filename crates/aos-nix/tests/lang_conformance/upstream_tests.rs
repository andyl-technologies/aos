//! Optional configured upstream `lang.sh` corpus gate.

use super::pinned_cases::PINNED_LANG_2_24_12_CASE_NAMES;
use super::support::*;

#[test]
fn lang_version_skip_rules_react_to_pinned_version() {
    let rules = [
        LangVersionSkipRule {
            name: "eval-okay-future",
            active: LangVersionRange::before(LangVersion::new(2, 25, 0)),
            reason: "requires C++ Nix >= 2.25.0",
        },
        LangVersionSkipRule {
            name: "eval-okay-retired",
            active: LangVersionRange::since(LangVersion::new(2, 25, 0)),
            reason: "covered only before C++ Nix 2.25.0",
        },
    ];

    assert_eq!(
        version_reactive_skip_with_rules("eval-okay-future", PINNED_LANG_CPP_NIX_VERSION, &rules),
        Some("requires C++ Nix >= 2.25.0 (C++ Nix 2.24.12)".to_owned())
    );
    assert_eq!(
        version_reactive_skip_with_rules("eval-okay-future", LangVersion::new(2, 25, 0), &rules),
        None
    );
    assert_eq!(
        version_reactive_skip_with_rules("eval-okay-retired", LangVersion::new(2, 25, 0), &rules),
        Some("covered only before C++ Nix 2.25.0 (C++ Nix 2.25.0)".to_owned())
    );
    assert_eq!(
        version_reactive_skip_with_rules("eval-okay-other", PINNED_LANG_CPP_NIX_VERSION, &rules),
        None
    );
}

#[test]
fn pinned_lang_version_matches_packaged_cpp_nix() -> Result<()> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow!("{} has no repo root parent", manifest_dir.display()))?;
    // SKIP when the packaged derivation is absent, so this runs in a full
    // checkout and is inert in the crates-only Nix build sandbox (`pkgs.aos`
    // uses `src = ../../../crates`, which omits the repo root). Without the
    // skip this `--workspace` integration test fails the hermetic `pkgs.aos`
    // doCheck (the repo root resolves to the sandbox build dir).
    let nix_nix = repo_root.join("pkgs/tools/nix.nix");
    let Ok(package) = fs::read_to_string(&nix_nix) else {
        eprintln!(
            "{} absent (crates-only sandbox); skipping pinned-lang-version check",
            nix_nix.display()
        );
        return Ok(());
    };
    let version = package
        .lines()
        .find_map(|line| {
            let version = line.trim().strip_prefix("version = \"")?;
            version.strip_suffix("\";")
        })
        .ok_or_else(|| anyhow!("pkgs/tools/nix.nix does not declare a version"))?;

    assert_eq!(
        LangVersion::parse(version),
        Some(PINNED_LANG_CPP_NIX_VERSION)
    );
    Ok(())
}

#[test]
fn configured_upstream_lang_corpus_gate_runs_all_categories() -> Result<()> {
    let Some(root) = std::env::var_os("AOS_NIX_LANG_TESTS") else {
        eprintln!("AOS_NIX_LANG_TESTS not set; skipping upstream lang corpus discovery check");
        return Ok(());
    };
    let lang_dir = Path::new(&root);
    let cases = discover_lang_cases(lang_dir)?;
    let discovered_names = cases
        .iter()
        .map(|case| case.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        discovered_names, PINNED_LANG_2_24_12_CASE_NAMES,
        "configured upstream corpus should match the pinned C++ Nix 2.24.12 case set"
    );
    for special_case in PINNED_LANG_2_24_12_SPECIAL_CASE_NAMES {
        assert!(
            lang_dir.join(format!("{special_case}.nix")).exists(),
            "configured upstream corpus should include special lang.sh case {special_case}"
        );
    }
    for exclusion in LANG_CASE_EXCLUSIONS {
        assert!(
            cases.iter().any(|case| case.name == exclusion.name),
            "documented exclusion {} should exist in the configured upstream corpus",
            exclusion.name
        );
    }

    for category in [
        LangCategory::ParseFail,
        LangCategory::ParseOkay,
        LangCategory::EvalFail,
        LangCategory::EvalOkay,
    ] {
        assert!(
            cases.iter().any(|case| case.category == category),
            "configured upstream corpus should include {category:?}"
        );
    }

    let mut failures = Vec::new();
    let mut passed = 0usize;
    let mut skipped = 0usize;
    for case in &cases {
        match run_lang_case_with_exclusions(case, true) {
            Ok(CaseOutcome::Passed) => passed += 1,
            Ok(CaseOutcome::Skipped(reason)) => {
                if configured_skip_is_allowed(case, &reason) {
                    skipped += 1;
                    eprintln!("SKIP {}: {reason}", case.name);
                } else {
                    failures.push(format!("{} skipped unexpectedly: {reason}", case.name));
                }
            }
            Err(error) => failures.push(format!("{}: {error:#}", case.name)),
        }
    }
    match run_non_eval_fail_bad_drv_path(lang_dir) {
        Ok(CaseOutcome::Passed) => passed += 1,
        Ok(CaseOutcome::Skipped(reason)) => {
            failures.push(format!(
                "non-eval-fail-bad-drvPath skipped unexpectedly: {reason}"
            ));
        }
        Err(error) => failures.push(format!("non-eval-fail-bad-drvPath: {error:#}")),
    }
    if passed != PINNED_LANG_2_24_12_PASS_COUNT || skipped != PINNED_LANG_2_24_12_SKIP_COUNT {
        failures.push(format!(
            "configured upstream corpus counts diverged: expected {} passed / {} skipped, got {passed} passed / {skipped} skipped",
            PINNED_LANG_2_24_12_PASS_COUNT, PINNED_LANG_2_24_12_SKIP_COUNT
        ));
    }
    eprintln!(
        "configured upstream corpus: {passed} passed, {skipped} skipped, {} failed",
        failures.len()
    );
    if !failures.is_empty() {
        bail!(
            "configured upstream corpus failures:\n{}",
            failures.join("\n")
        );
    }

    Ok(())
}
