//! Cache reuse retains independent profile evidence and exact immutable custody.

use super::*;

fn updates_only() -> Result<EvaluationData> {
    let mut data = common::fixture("1.2.0")?;
    data.advisory_snapshot = None;
    data.advisories.clear();
    data.upstream.push(aos_assessment::input::UpstreamBinding {
        component_ref: "component".into(),
        response_byte_length: 2,
        source_refs: vec![],
        page_observations: vec![],
        observation: aos_assessment::discovery::UpstreamObservationV1 {
            schema: aos_assessment::UPSTREAM_OBSERVATION_V1.into(),
            provider: "github-releases".into(),
            project: "example/fixture".into(),
            adapter_version: "fixture-v1".into(),
            request_url: "https://api.github.com/repos/example/fixture/releases".into(),
            retrieved_at_unix: common::evaluated_at()?.unix_seconds(),
            response_digest: Sha256Digest::of_bytes(b"[]"),
            coverage: aos_assessment::discovery::ObservationCoverage::Complete,
            candidates: vec![],
        },
    });
    Ok(data)
}

#[test]
fn independent_profile_cache_retains_vulnerability_and_update_evidence_in_either_commit_order()
-> Result<()> {
    for reverse in [false, true] {
        let (_root, store) = store()?;
        let security = common::fixture("1.2.0")?;
        let updates = updates_only()?;
        let first = admit_profiles(&store, 1, &security, vec![Profile::Vulnerabilities])?;
        store.start_local_assessment_scan(&first.scan_id)?;
        let second = admit_profiles(&store, 2, &updates, vec![Profile::Updates])?;
        store.start_local_assessment_scan(&second.scan_id)?;
        if reverse {
            commit_profiles(&store, &second, &updates)?;
            commit_profiles(&store, &first, &security)?;
        } else {
            commit_profiles(&store, &first, &security)?;
            commit_profiles(&store, &second, &updates)?;
        }
        // The compatibility head remains the highest admission generation,
        // while reusable evidence includes both independently committed slots.
        assert!(
            store
                .local_committed_assessment_closure()?
                .context("global closure")?
                .advisory_snapshot
                .is_none()
        );
        let before = fs::read(store.repository.join("assessments/journal.json"))?;
        let cached = store
            .local_cached_assessment_closure()?
            .context("combined cache")?;
        assert_eq!(cached.upstream, updates.upstream);
        assert_eq!(cached.advisory_snapshot, security.advisory_snapshot);
        assert_eq!(cached.advisories, security.advisories);
        let input = cached.freeze(
            vec![Profile::Updates, Profile::Vulnerabilities],
            common::evaluated_at()?,
        )?;
        assert_eq!(
            evaluate(&input, &cached)?.subject_results[0].findings.len(),
            1
        );
        assert_eq!(
            fs::read(store.repository.join("assessments/journal.json"))?,
            before
        );
    }
    Ok(())
}

#[test]
fn independent_cache_refuses_broken_non_global_profile_custody_and_oversized_reads() -> Result<()> {
    let (_root, store) = store()?;
    let security = common::fixture("1.2.0")?;
    let updates = updates_only()?;
    let first = admit_profiles(&store, 1, &security, vec![Profile::Vulnerabilities])?;
    store.start_local_assessment_scan(&first.scan_id)?;
    commit_profiles(&store, &first, &security)?;
    let second = admit_profiles(&store, 2, &updates, vec![Profile::Updates])?;
    store.start_local_assessment_scan(&second.scan_id)?;
    commit_profiles(&store, &second, &updates)?;
    let journal = store.local_journal()?;
    let head = journal
        .profiles
        .get(&profile_key("subject", Profile::Vulnerabilities))
        .and_then(|slot| slot.committed.as_ref())
        .context("security head")?;
    let path = store
        .repository
        .join("assessments")
        .join(format!("data-{}.json", head.closure_digest.hex()));
    let original = fs::read(&path)?;
    fs::write(&path, b"{}")?;
    assert!(store.local_cached_assessment_closure().is_err());
    let file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)?;
    file.set_len(64 * 1024 * 1024 + 1)?;
    drop(file);
    let error = store
        .local_cached_assessment_closure()
        .expect_err("bounded cache read");
    assert!(error.to_string().contains("byte allowance"), "{error}");
    fs::write(path, original)?;
    assert!(store.local_cached_assessment_closure()?.is_some());
    Ok(())
}

#[test]
fn old_inventory_cache_is_historical_until_a_matching_current_head_commits() -> Result<()> {
    let (_root, store) = store()?;
    let security = common::fixture("1.2.0")?;
    let first = admit(&store, 1, &security)?;
    store.start_local_assessment_scan(&first.scan_id)?;
    commit_profiles(&store, &first, &security)?;
    let changed = common::fixture("1.3.0")?;
    let second = admit(&store, 2, &changed)?;
    let prior = store
        .local_cached_assessment_closure()?
        .context("historical cache")?;
    assert_eq!(prior.inventory.digest()?, security.inventory.digest()?);
    assert_ne!(prior.inventory.digest()?, changed.inventory.digest()?);
    store.start_local_assessment_scan(&second.scan_id)?;
    commit_profiles(&store, &second, &changed)?;
    assert_eq!(
        store
            .local_cached_assessment_closure()?
            .context("current cache")?
            .inventory
            .digest()?,
        changed.inventory.digest()?
    );
    Ok(())
}
