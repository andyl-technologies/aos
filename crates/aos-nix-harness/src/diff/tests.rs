//! Path and byte-mode `.drv` diff tests.

use super::test_support::*;
use super::*;
use std::collections::BTreeMap;

#[test]
fn path_mode_reports_root_path_divergence_without_reading_drv_files() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let oracle = FakeEval::path(temp.path().join("oracle.drv"));
    let candidate = FakeEval::path(temp.path().join("candidate.drv"));

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Path,
    )?;

    assert!(!report.is_match());
    assert_eq!(report.divergences.len(), 1);
    assert!(matches!(report.divergences[0], DrvDiff::RootPath { .. }));
    assert!(report.root_divergences.is_empty());
    assert!(report.contaminated_divergences.is_empty());
    Ok(())
}

#[test]
fn path_mode_does_not_require_in_memory_closure_support() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("same.drv");
    let oracle = FakeEval::path(root.clone());
    let candidate = FakeEval::path_with_closure_error(root, "closure failed");

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Path,
    )?;

    assert!(report.is_match());
    Ok(())
}

#[test]
fn byte_mode_walks_input_derivation_pairs() -> Result<()> {
    let oracle_input =
        PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-oracle-input.drv");
    let candidate_input =
        PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-candidate-input.drv");
    let oracle_root = PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
    let candidate_root =
        PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
    let mut oracle_bytes = BTreeMap::new();
    oracle_bytes.insert(oracle_input.clone(), drv(&[], "input").into_bytes());
    oracle_bytes.insert(
        oracle_root.clone(),
        drv(&[(path_str(&oracle_input)?, &["out"])], "root").into_bytes(),
    );
    let mut candidate_bytes = BTreeMap::new();
    candidate_bytes.insert(
        candidate_input.clone(),
        drv(&[], "input-changed").into_bytes(),
    );
    candidate_bytes.insert(
        candidate_root.clone(),
        drv(&[(path_str(&candidate_input)?, &["out"])], "root").into_bytes(),
    );
    let oracle = FakeEval::path_with_bytes(oracle_root.clone(), oracle_bytes);
    let candidate = FakeEval::path_with_bytes(candidate_root.clone(), candidate_bytes);

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Byte,
    )?;

    assert!(!report.is_match());
    assert!(matches!(
        report.divergences.first(),
        Some(DrvDiff::Bytes { oracle, candidate })
            if oracle == &oracle_input && candidate == &candidate_input
    ));
    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::RootPath { .. }))
    );
    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::Bytes { oracle, candidate }
                if oracle == &oracle_input && candidate == &candidate_input))
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
    Ok(())
}

#[test]
fn byte_mode_bundles_in_memory_root_artifacts_for_direct_reruns() -> Result<()> {
    let oracle_input =
        PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-oracle-input.drv");
    let candidate_input =
        PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-candidate-input.drv");
    let oracle_root = PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
    let candidate_root =
        PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
    let mut oracle_bytes = BTreeMap::new();
    oracle_bytes.insert(oracle_input.clone(), drv(&[], "input").into_bytes());
    oracle_bytes.insert(
        oracle_root.clone(),
        drv(&[(path_str(&oracle_input)?, &["out"])], "root").into_bytes(),
    );
    let mut candidate_bytes = BTreeMap::new();
    candidate_bytes.insert(
        candidate_input.clone(),
        drv(&[], "input-changed").into_bytes(),
    );
    candidate_bytes.insert(
        candidate_root.clone(),
        drv(&[(path_str(&candidate_input)?, &["out"])], "root").into_bytes(),
    );
    let oracle = FakeEval::path_with_bytes(oracle_root, oracle_bytes);
    let candidate = FakeEval::path_with_bytes(candidate_root, candidate_bytes);

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Byte,
    )?;

    let root_pair = &report.root_divergences[0];
    let artifact = report
        .node_artifacts
        .iter()
        .find(|artifact| artifact.pair == *root_pair)
        .context("root divergence should have a node artifact")?;
    let oracle_bundle = artifact
        .oracle_bundle
        .as_deref()
        .context("oracle bundle should be persisted")?;
    let candidate_bundle = artifact
        .candidate_bundle
        .as_deref()
        .context("candidate bundle should be persisted")?;
    assert!(oracle_bundle.exists());
    assert!(candidate_bundle.exists());

    let rerun = diff_drv_pair_with_bundles(
        &root_pair.oracle,
        &root_pair.candidate,
        Some(oracle_bundle),
        Some(candidate_bundle),
        DiffMode::Byte,
    )?;

    assert!(!rerun.is_match());
    assert!(rerun.divergences.iter().any(|diff| matches!(
        diff,
        DrvDiff::Bytes { oracle, candidate }
            if oracle == &root_pair.oracle && candidate == &root_pair.candidate
    )));
    Ok(())
}

#[test]
fn byte_mode_classifies_input_output_mismatch_on_parent_drv() -> Result<()> {
    let input = PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-input.drv");
    let root = PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-root.drv");
    let input_bytes = drv(&[], "input").into_bytes();
    let mut oracle_bytes = BTreeMap::new();
    oracle_bytes.insert(input.clone(), input_bytes.clone());
    oracle_bytes.insert(
        root.clone(),
        drv(&[(path_str(&input)?, &["out"])], "root").into_bytes(),
    );
    let mut candidate_bytes = BTreeMap::new();
    candidate_bytes.insert(input.clone(), input_bytes);
    candidate_bytes.insert(
        root.clone(),
        drv(&[(path_str(&input)?, &["dev"])], "root").into_bytes(),
    );
    let oracle = FakeEval::path_with_bytes(root.clone(), oracle_bytes);
    let candidate = FakeEval::path_with_bytes(root.clone(), candidate_bytes);

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Byte,
    )?;

    assert!(report.divergences.iter().any(|diff| matches!(
        diff,
        DrvDiff::InputOutputs {
            parent_oracle,
            parent_candidate,
            oracle,
            candidate,
            ..
        } if parent_oracle == &root
            && parent_candidate == &root
            && oracle == &input
            && candidate == &input
    )));
    assert_eq!(
        report.root_divergences,
        vec![DrvDiffPair {
            oracle: root.clone(),
            candidate: root,
        }]
    );
    assert!(report.contaminated_divergences.is_empty());
    Ok(())
}

#[test]
fn byte_mode_requires_complete_in_memory_closure_bytes() -> Result<()> {
    let oracle_input =
        PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-oracle-input.drv");
    let candidate_input =
        PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-candidate-input.drv");
    let oracle_root = PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
    let candidate_root =
        PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
    let mut oracle_bytes = BTreeMap::new();
    oracle_bytes.insert(oracle_input.clone(), drv(&[], "input").into_bytes());
    oracle_bytes.insert(
        oracle_root.clone(),
        drv(&[(path_str(&oracle_input)?, &["out"])], "root").into_bytes(),
    );
    let mut candidate_bytes = BTreeMap::new();
    candidate_bytes.insert(
        candidate_root.clone(),
        drv(&[(path_str(&candidate_input)?, &["out"])], "root").into_bytes(),
    );
    let oracle = FakeEval::path_with_bytes(oracle_root, oracle_bytes);
    let candidate = FakeEval::path_with_bytes(candidate_root, candidate_bytes);

    let error = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Byte,
    )
    .expect_err("in-memory evaluators must provide every traversed drv");

    assert!(
        error
            .to_string()
            .contains("did not provide in-memory drv bytes")
    );
    Ok(())
}

#[test]
fn byte_mode_walks_non_utf8_drv_bytes() -> Result<()> {
    let oracle_input =
        PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-oracle-input.drv");
    let candidate_input =
        PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-candidate-input.drv");
    let oracle_root = PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
    let candidate_root =
        PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
    let mut oracle_bytes = BTreeMap::new();
    oracle_bytes.insert(oracle_input.clone(), drv(&[], "input").into_bytes());
    oracle_bytes.insert(
        oracle_root.clone(),
        drv_bytes(
            &[(path_str(&oracle_input)?, &["out"])],
            "root",
            Some(&[0xff]),
        ),
    );
    let mut candidate_bytes = BTreeMap::new();
    candidate_bytes.insert(
        candidate_input.clone(),
        drv(&[], "input-changed").into_bytes(),
    );
    candidate_bytes.insert(
        candidate_root.clone(),
        drv_bytes(
            &[(path_str(&candidate_input)?, &["out"])],
            "root",
            Some(&[0xff]),
        ),
    );
    let oracle = FakeEval::path_with_bytes(oracle_root, oracle_bytes);
    let candidate = FakeEval::path_with_bytes(candidate_root, candidate_bytes);

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Byte,
    )?;

    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::Bytes { oracle, candidate }
                if oracle == &oracle_input && candidate == &candidate_input))
    );
    Ok(())
}

#[test]
fn byte_mode_walks_inputs_without_full_structural_parse() -> Result<()> {
    let oracle_input =
        PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-oracle-input.drv");
    let candidate_input =
        PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-candidate-input.drv");
    let oracle_root = PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
    let candidate_root =
        PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
    let mut oracle_bytes = BTreeMap::new();
    oracle_bytes.insert(oracle_input.clone(), drv(&[], "input").into_bytes());
    oracle_bytes.insert(
        oracle_root.clone(),
        drv_input_section_only_bytes(&[(path_str(&oracle_input)?, &["out"])]),
    );
    let mut candidate_bytes = BTreeMap::new();
    candidate_bytes.insert(
        candidate_input.clone(),
        drv(&[], "input-changed").into_bytes(),
    );
    candidate_bytes.insert(
        candidate_root.clone(),
        drv_input_section_only_bytes(&[(path_str(&candidate_input)?, &["out"])]),
    );
    let oracle = FakeEval::path_with_bytes(oracle_root, oracle_bytes);
    let candidate = FakeEval::path_with_bytes(candidate_root, candidate_bytes);

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Byte,
    )?;

    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::Bytes { oracle, candidate }
                if oracle == &oracle_input && candidate == &candidate_input))
    );
    Ok(())
}

#[test]
fn byte_mode_walks_inputs_without_validating_later_sections() -> Result<()> {
    let oracle_input =
        PathBuf::from("/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-oracle-input.drv");
    let candidate_input =
        PathBuf::from("/nix/store/dddddddddddddddddddddddddddddddd-candidate-input.drv");
    let oracle_root = PathBuf::from("/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-oracle-root.drv");
    let candidate_root =
        PathBuf::from("/nix/store/ffffffffffffffffffffffffffffffff-candidate-root.drv");
    let mut oracle_bytes = BTreeMap::new();
    oracle_bytes.insert(oracle_input.clone(), drv(&[], "input").into_bytes());
    oracle_bytes.insert(
        oracle_root.clone(),
        drv_with_malformed_tail_bytes(&[(path_str(&oracle_input)?, &["out"])]),
    );
    let mut candidate_bytes = BTreeMap::new();
    candidate_bytes.insert(
        candidate_input.clone(),
        drv(&[], "input-changed").into_bytes(),
    );
    candidate_bytes.insert(
        candidate_root.clone(),
        drv_with_malformed_tail_bytes(&[(path_str(&candidate_input)?, &["out"])]),
    );
    let oracle = FakeEval::path_with_bytes(oracle_root, oracle_bytes);
    let candidate = FakeEval::path_with_bytes(candidate_root, candidate_bytes);

    let report = diff_closure(
        &oracle,
        &candidate,
        Path::new("default.nix"),
        "pkg",
        DiffMode::Byte,
    )?;

    assert!(
        report
            .divergences
            .iter()
            .any(|diff| matches!(diff, DrvDiff::Bytes { oracle, candidate }
                if oracle == &oracle_input && candidate == &candidate_input))
    );
    Ok(())
}
