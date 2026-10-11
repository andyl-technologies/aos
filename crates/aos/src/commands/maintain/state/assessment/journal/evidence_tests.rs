//! Historical export, non-authoritative import and crash-boundary custody tests.

use super::*;
use aos_assessment::bundle::{AssessmentBundleV1, BundleProfile};

#[test]
fn export_retains_exact_historical_evidence_after_the_inventory_head_moves() -> Result<()> {
    let (_directory, store) = store()?;
    let data = common::fixture("1.2.0")?;
    let first = admit(&store, 1, &data)?;
    store.start_local_assessment_scan(&first.scan_id)?;
    let first = commit_profiles(&store, &first, &data)?;
    let digest = first.assessment_digest.context("first result")?;
    let original = store.export_local_assessment_evidence(digest)?;

    let changed = common::fixture("1.4.0")?;
    let second = admit(&store, 2, &changed)?;
    store.start_local_assessment_scan(&second.scan_id)?;
    let second = commit_profiles(&store, &second, &changed)?;
    assert_ne!(second.assessment_digest, Some(digest));
    let historical = store.export_local_assessment_evidence(digest)?;
    assert_eq!(historical, original);
    assert_eq!(historical.assessment.digest()?, digest);
    historical.verify()?;
    assert!(
        store
            .export_local_assessment_evidence(Sha256Digest::of_bytes("missing"))
            .is_err()
    );
    Ok(())
}

#[test]
fn import_replays_one_receipt_without_changing_heads_and_refuses_corrupt_custody() -> Result<()> {
    let (_directory, store) = store()?;
    let data = common::fixture("1.2.0")?;
    let (input, _) = semantic(&data)?;
    let bundle = AssessmentBundleV1::export(input, data.clone(), BundleProfile::Reference, vec![])?;
    let receipt = admit(&store, 1, &data)?;
    store.start_local_assessment_scan(&receipt.scan_id)?;
    commit_profiles(&store, &receipt, &data)?;
    let journal_path = store.repository.join("assessments/journal.json");
    let before = fs::read(&journal_path)?;

    let imported = store.import_local_assessment_evidence(&bundle, common::evaluated_at()?)?;
    assert_eq!(imported.resource_scope, store.local_assessment_scope()?);
    let later = Timestamp::from_unix_seconds(common::evaluated_at()?.unix_seconds() + 30)?;
    assert_eq!(
        store.import_local_assessment_evidence(&bundle, later)?,
        imported
    );
    assert_eq!(fs::read(&journal_path)?, before);
    let index_path = store.repository.join("assessments/imports/index.json");
    let index = fs::read(&index_path)?;
    let receipt_path = store
        .repository
        .join("assessments/imports")
        .join(format!("receipt-{}.json", imported.digest()?.hex()));
    let mut changed = serde_json::to_value(&imported)?;
    changed["authority"] = "admitted".into();
    fs::write(receipt_path, serde_json::to_vec(&changed)?)?;
    assert!(
        store
            .import_local_assessment_evidence(&bundle, common::evaluated_at()?)
            .is_err()
    );
    assert_eq!(fs::read(&index_path)?, index);
    assert_eq!(fs::read(&journal_path)?, before);
    Ok(())
}

#[test]
fn failed_evidence_reference_write_cannot_commit_an_assessment_head() -> Result<()> {
    let (directory, store) = store()?;
    let data = common::fixture("1.2.0")?;
    let receipt = admit(&store, 1, &data)?;
    store.start_local_assessment_scan(&receipt.scan_id)?;
    let before = fs::read(store.repository.join("assessments/journal.json"))?;
    let external = directory.path().join("outside-references");
    fs::create_dir(&external)?;
    std::os::unix::fs::symlink(
        &external,
        store.repository.join("assessments/evidence-references"),
    )?;
    assert!(commit_profiles(&store, &receipt, &data).is_err());
    assert_eq!(
        fs::read(store.repository.join("assessments/journal.json"))?,
        before
    );
    assert_eq!(
        store.inspect_local_assessment_scan(&receipt.scan_id)?.state,
        ScanState::Running
    );
    assert!(store.local_journal()?.head.is_none());
    assert_eq!(fs::read_dir(external)?.count(), 0);
    Ok(())
}

#[test]
fn import_is_namespace_bound_and_has_a_finite_entry_allowance() -> Result<()> {
    let (_directory, store) = store()?;
    let data = common::fixture("1.2.0")?;
    let base = common::evaluated_at()?.unix_seconds();
    let now = Timestamp::from_unix_seconds(base + 1000)?;
    let mut first = None;
    for index in 0..64 {
        let input = data.freeze(
            vec![Profile::Vulnerabilities],
            Timestamp::from_unix_seconds(base + index)?,
        )?;
        let bundle =
            AssessmentBundleV1::export(input, data.clone(), BundleProfile::Reference, vec![])?;
        let receipt = store.import_local_assessment_evidence(&bundle, now.clone())?;
        receipt.verify_for(&bundle, &store.local_assessment_scope()?, &now)?;
        if index == 0 {
            first = Some((bundle, receipt));
        }
    }
    let input = data.freeze(
        vec![Profile::Vulnerabilities],
        Timestamp::from_unix_seconds(base + 64)?,
    )?;
    let extra = AssessmentBundleV1::export(input, data.clone(), BundleProfile::Reference, vec![])?;
    assert!(
        store
            .import_local_assessment_evidence(&extra, now.clone())
            .is_err()
    );
    let (bundle, receipt) = first.context("first receipt")?;
    assert_eq!(
        store.import_local_assessment_evidence(&bundle, now.clone())?,
        receipt
    );

    let (_other_directory, other) = super::store()?;
    // Test namespaces need distinct identities, independent of temporary roots.
    let different = other
        .repository
        .with_file_name(Sha256Digest::of_bytes("other repository").hex());
    secure_directory(&different)?;
    let other = StateStore {
        root: other.root,
        repository: different,
    };
    let imported = other.import_local_assessment_evidence(&bundle, now.clone())?;
    assert_ne!(imported.resource_scope, receipt.resource_scope);
    assert_ne!(imported.digest()?, receipt.digest()?);
    assert!(
        receipt
            .verify_for(&bundle, &other.local_assessment_scope()?, &now)
            .is_err()
    );
    assert!(
        !other
            .repository
            .join("assessments/journal.json")
            .try_exists()?
    );
    Ok(())
}
