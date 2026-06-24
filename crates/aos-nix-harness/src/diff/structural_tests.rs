//! Structural `.drv` diff tests.

use super::structural::NIX_STORE_DIR;
use super::test_support::*;
use super::*;
use std::collections::BTreeMap;
use std::fs;

#[test]
fn structural_mode_reports_first_parsed_field_difference() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let oracle_root = temp.path().join("oracle-root.drv");
    let candidate_root = temp.path().join("candidate-root.drv");
    fs::write(&oracle_root, structural_drv("oracle"))?;
    fs::write(&candidate_root, structural_drv("candidate"))?;
    let oracle = FakeEval::path(oracle_root.clone());
    let candidate = FakeEval::path(candidate_root.clone());

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Structural,
    )?;

    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::Bytes { oracle, candidate }
                if oracle == &oracle_root && candidate == &candidate_root))
    );
    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::Structural { field, .. }
                if field == "environment"))
    );
    Ok(())
}

#[test]
fn diff_drv_pair_compares_existing_drv_roots_without_evaluation() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let oracle_root = temp.path().join("oracle-root.drv");
    let candidate_root = temp.path().join("candidate-root.drv");
    fs::write(&oracle_root, structural_drv("oracle"))?;
    fs::write(&candidate_root, structural_drv("candidate"))?;

    let report = diff_drv_pair(&oracle_root, &candidate_root, DiffMode::Structural)?;

    assert_eq!(report.oracle_root.as_deref(), Some(oracle_root.as_path()));
    assert_eq!(
        report.candidate_root.as_deref(),
        Some(candidate_root.as_path())
    );
    assert!(report.divergences.iter().any(
        |diff| matches!(diff, DrvDiff::Structural { oracle, candidate, field }
            if oracle == &oracle_root && candidate == &candidate_root && field == "environment")
    ));
    assert_eq!(
        report.root_divergences,
        vec![DrvDiffPair {
            oracle: oracle_root,
            candidate: candidate_root,
        }]
    );
    assert!(report.contaminated_divergences.is_empty());
    Ok(())
}

#[test]
fn structural_mode_classifies_input_path_contamination() -> Result<()> {
    let oracle_input = PathBuf::from("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv");
    let candidate_input = PathBuf::from("/nix/store/wvza442rgjdb2cyhwm59ax3qy0y9skkk-ca.drv");
    let oracle_root = PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
    let candidate_root =
        PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
    let mut oracle_bytes = BTreeMap::new();
    oracle_bytes.insert(oracle_input.clone(), structural_drv("input").into_bytes());
    oracle_bytes.insert(
        oracle_root.clone(),
        structural_drv_with_input(path_str(&oracle_input)?, "root").into_bytes(),
    );
    let mut candidate_bytes = BTreeMap::new();
    candidate_bytes.insert(
        candidate_input.clone(),
        structural_drv("input-changed").into_bytes(),
    );
    candidate_bytes.insert(
        candidate_root.clone(),
        structural_drv_with_input(path_str(&candidate_input)?, "root").into_bytes(),
    );
    let oracle = FakeEval::path_with_bytes(oracle_root.clone(), oracle_bytes);
    let candidate = FakeEval::path_with_bytes(candidate_root.clone(), candidate_bytes);

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Structural,
    )?;

    assert_eq!(
        report.divergences.first(),
        Some(&DrvDiff::Bytes {
            oracle: oracle_root.clone(),
            candidate: candidate_root.clone(),
        })
    );
    assert_eq!(
        report.divergences.get(1),
        Some(&DrvDiff::Structural {
            oracle: oracle_root.clone(),
            candidate: candidate_root.clone(),
            field: "input_derivations".to_string(),
        })
    );
    assert_eq!(
        report.root_divergences,
        vec![DrvDiffPair {
            oracle: oracle_input,
            candidate: candidate_input,
        }]
    );
    assert_eq!(
        report.contaminated_divergences,
        vec![DrvDiffPair {
            oracle: oracle_root,
            candidate: candidate_root,
        }]
    );
    assert!(
        !report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::StructuralParse { .. }))
    );
    Ok(())
}

#[test]
fn structural_mode_parses_custom_store_and_reroots_inputs() -> Result<()> {
    let store = "/tmp/aos-structural-store";
    let input = PathBuf::from(format!("{store}/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv"));
    let root = PathBuf::from(format!("{store}/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-root.drv"));
    let mut oracle_bytes = BTreeMap::new();
    oracle_bytes.insert(
        input.clone(),
        custom_store_drv(structural_drv("input"), store),
    );
    oracle_bytes.insert(
        root.clone(),
        custom_store_drv(structural_drv_with_input(path_str(&input)?, "root"), store),
    );
    let mut candidate_bytes = BTreeMap::new();
    candidate_bytes.insert(
        input.clone(),
        custom_store_drv(structural_drv("input-changed"), store),
    );
    candidate_bytes.insert(
        root.clone(),
        custom_store_drv(
            structural_drv_with_input(path_str(&input)?, "root-changed"),
            store,
        ),
    );
    let oracle = FakeEval::path_with_bytes(root.clone(), oracle_bytes);
    let candidate = FakeEval::path_with_bytes(root.clone(), candidate_bytes);

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Structural,
    )?;

    assert!(report.divergences.iter().any(
        |diff| matches!(diff, DrvDiff::Structural { oracle, field, .. }
                if oracle == &input && field == "environment")
    ));
    assert!(
        !report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::StructuralParse { .. })),
        "custom-store structural parse should not fail: {report:#?}"
    );
    assert_eq!(
        report.contaminated_divergences,
        vec![DrvDiffPair {
            oracle: root.clone(),
            candidate: root,
        }]
    );
    Ok(())
}

#[test]
fn structural_mode_preserves_custom_store_env_differences() -> Result<()> {
    let store = "/tmp/aos-structural-store";
    let root = PathBuf::from(format!("{store}/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-root.drv"));
    let mut oracle_bytes = BTreeMap::new();
    oracle_bytes.insert(
        root.clone(),
        custom_store_drv(
            structural_drv_with_extra_env("root", &[("storeDir", store)]),
            store,
        ),
    );
    let mut candidate_bytes = BTreeMap::new();
    candidate_bytes.insert(
        root.clone(),
        custom_store_drv(
            structural_drv_with_extra_env("root", &[("storeDir", NIX_STORE_DIR)]),
            store,
        ),
    );
    let oracle = FakeEval::path_with_bytes(root.clone(), oracle_bytes);
    let candidate = FakeEval::path_with_bytes(root, candidate_bytes);

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Structural,
    )?;

    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::Structural { field, .. }
                if field == "environment")),
        "store-dir env values should remain semantically compared: {report:#?}"
    );
    assert!(
        !report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::StructuralParse { .. })),
        "custom-store structural parse should not fail: {report:#?}"
    );
    Ok(())
}

#[test]
fn structural_mode_preserves_wrong_store_input_derivation_paths() -> Result<()> {
    let store = "/tmp/aos-structural-store";
    let oracle_input = PathBuf::from(format!("{store}/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv"));
    let candidate_input = PathBuf::from("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv");
    let root = PathBuf::from(format!("{store}/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-root.drv"));
    let output = format!("{store}/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-shared");

    let mut oracle_bytes = BTreeMap::new();
    oracle_bytes.insert(
        oracle_input.clone(),
        custom_store_drv(structural_drv("input"), store),
    );
    oracle_bytes.insert(
        root.clone(),
        structural_drv_with_input_and_output(path_str(&oracle_input)?, &output, "root")
            .into_bytes(),
    );
    let mut candidate_bytes = BTreeMap::new();
    candidate_bytes.insert(
        candidate_input.clone(),
        structural_drv("input").into_bytes(),
    );
    candidate_bytes.insert(
        root.clone(),
        structural_drv_with_input_and_output(path_str(&candidate_input)?, &output, "root")
            .into_bytes(),
    );
    let oracle = FakeEval::path_with_bytes(root.clone(), oracle_bytes);
    let candidate = FakeEval::path_with_bytes(root, candidate_bytes);

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Structural,
    )?;

    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::Structural { field, .. }
                if field == "input_derivations")),
        "wrong-store input derivation refs should remain visible: {report:#?}"
    );
    Ok(())
}

#[test]
fn structural_mode_walks_equal_placeholder_bytes_without_full_parse() -> Result<()> {
    let input = PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-input.drv");
    let root = PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-root.drv");
    let root_bytes = structural_placeholder_drv_with_input(path_str(&input)?, "root");

    let mut oracle_bytes = BTreeMap::new();
    oracle_bytes.insert(input.clone(), structural_drv("input").into_bytes());
    oracle_bytes.insert(root.clone(), root_bytes.clone().into_bytes());
    let mut candidate_bytes = BTreeMap::new();
    candidate_bytes.insert(input.clone(), structural_drv("input-changed").into_bytes());
    candidate_bytes.insert(root.clone(), root_bytes.into_bytes());
    let oracle = FakeEval::path_with_bytes(root.clone(), oracle_bytes);
    let candidate = FakeEval::path_with_bytes(root, candidate_bytes);

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Structural,
    )?;

    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::Bytes { oracle, candidate }
                if oracle == &input && candidate == &input))
    );
    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::Structural { field, .. }
                if field == "environment"))
    );
    assert!(
        !report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::StructuralParse { .. }))
    );
    Ok(())
}

#[test]
fn structural_mode_classifies_output_and_input_divergence() -> Result<()> {
    let oracle_input = PathBuf::from("/nix/store/v1z1rms3n03v2j8icjwqz7w48w624adi-base.drv");
    let candidate_input = PathBuf::from("/nix/store/wvza442rgjdb2cyhwm59ax3qy0y9skkk-ca.drv");
    let oracle_root = PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
    let candidate_root =
        PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
    let mut oracle_bytes = BTreeMap::new();
    oracle_bytes.insert(oracle_input.clone(), structural_drv("input").into_bytes());
    oracle_bytes.insert(
        oracle_root.clone(),
        structural_drv_with_input_and_output(
            path_str(&oracle_input)?,
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-shared",
            "root",
        )
        .into_bytes(),
    );
    let mut candidate_bytes = BTreeMap::new();
    candidate_bytes.insert(
        candidate_input.clone(),
        structural_drv("input").into_bytes(),
    );
    candidate_bytes.insert(
        candidate_root.clone(),
        structural_drv_with_input_and_output(
            path_str(&candidate_input)?,
            "/nix/store/c9hhy38jds9ffzzqwkb50vrv2pi8x614-base",
            "root",
        )
        .into_bytes(),
    );
    let oracle = FakeEval::path_with_bytes(oracle_root.clone(), oracle_bytes);
    let candidate = FakeEval::path_with_bytes(candidate_root.clone(), candidate_bytes);

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Structural,
    )?;

    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::Structural { field, .. }
                if field == "outputs"))
    );
    assert_eq!(
        report.root_divergences,
        vec![DrvDiffPair {
            oracle: oracle_root,
            candidate: candidate_root,
        }]
    );
    assert!(report.contaminated_divergences.is_empty());
    assert!(
        !report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::StructuralParse { .. }))
    );
    Ok(())
}

#[test]
fn structural_mode_reports_parse_failure_as_divergence() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let oracle_root = temp.path().join("oracle-root.drv");
    let candidate_root = temp.path().join("candidate-root.drv");
    fs::write(&oracle_root, structural_drv("oracle"))?;
    fs::write(&candidate_root, b"not-a-derivation")?;
    let oracle = FakeEval::path(oracle_root);
    let candidate = FakeEval::path(candidate_root.clone());

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Structural,
    )?;

    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::StructuralParse {
                side: DiffSide::Candidate,
                path,
                ..
            } if path == &candidate_root))
    );
    Ok(())
}

#[test]
fn diff_closure_reports_one_sided_instantiation_errors() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let oracle = FakeEval::error("oracle failed");
    let candidate = FakeEval::path(temp.path().join("candidate.drv"));

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Path,
    )?;

    assert_eq!(
        report.divergences,
        vec![DrvDiff::Evaluation {
            side: DiffSide::Oracle,
            error: "oracle failed".to_string(),
        }]
    );
    Ok(())
}

#[test]
fn diff_closure_reports_mismatched_two_sided_instantiation_errors() -> Result<()> {
    let oracle = FakeEval::error("oracle failed");
    let candidate = FakeEval::error("candidate failed");

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Path,
    )?;

    assert_eq!(report.oracle_root, None);
    assert_eq!(report.candidate_root, None);
    assert_eq!(
        report.divergences,
        vec![DrvDiff::EvaluationMismatch {
            oracle_error: "oracle failed".to_string(),
            candidate_error: "candidate failed".to_string(),
        }]
    );
    Ok(())
}

#[test]
fn diff_closure_accepts_matching_two_sided_instantiation_errors() -> Result<()> {
    let oracle = FakeEval::error("same failure");
    let candidate = FakeEval::error("same failure");

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Path,
    )?;

    assert!(report.is_match());
    assert_eq!(report.oracle_root, None);
    assert_eq!(report.candidate_root, None);
    Ok(())
}
