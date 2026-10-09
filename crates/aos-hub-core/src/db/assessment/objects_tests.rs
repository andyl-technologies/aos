//! Exact immutable object replay, atomic races and incomplete/corrupt shard refusal.

use anyhow::{Context as _, Result};
use aos_assessment::discovery::{ObservationCandidate, ObservationCoverage, UpstreamObservationV1};
use aos_assessment::input::{ASSESSMENT_POLICY_V1, AssessmentPolicyV1};
use aos_contract::Sha256Digest;

use super::AssessmentObjectKind;
use crate::db::Database;

fn policy() -> AssessmentPolicyV1 {
    AssessmentPolicyV1 {
        schema: ASSESSMENT_POLICY_V1.into(),
        upstream_max_age_seconds: 86400,
        advisory_max_age_seconds: 86400,
        required_advisory_sources: vec!["osv".into()],
        require_dependency_coverage: true,
    }
}

#[tokio::test]
async fn immutable_policy_replay_is_exact_and_authorization_partitions_do_not_cross() -> Result<()>
{
    let db = Database::open_in_memory().await?;
    let policy = policy();
    let digest = policy.digest()?;
    let bytes = aos_contract::canonical::to_vec(&policy)?;
    for _ in 0..2 {
        db.put_assessment_object(
            "registry-fixture",
            AssessmentObjectKind::Policy,
            digest,
            &bytes,
            1,
        )
        .await?;
    }
    assert_eq!(
        db.assessment_object("registry-fixture", AssessmentObjectKind::Policy, digest)
            .await?
            .context("stored policy")?,
        bytes
    );
    assert!(
        db.assessment_object("other-registry", AssessmentObjectKind::Policy, digest)
            .await?
            .is_none()
    );
    assert!(
        db.assessment_object("registry-fixture", AssessmentObjectKind::Definition, digest)
            .await
            .is_err()
    );
    let count = db
        .backend
        .query_opt("SELECT count(*) FROM assessment_objects", &[])
        .await?
        .context("object count")?
        .get::<i64>(0)?;
    assert_eq!(count, 1);
    Ok(())
}

#[tokio::test]
async fn unknown_contract_fields_and_wrong_digests_fail_before_admission() -> Result<()> {
    let db = Database::open_in_memory().await?;
    let policy = policy();
    let mut bytes = serde_json::to_value(&policy)?;
    bytes["executable"] = serde_json::json!("unsupported scanner callback");
    assert!(
        db.put_assessment_object(
            "registry-fixture",
            AssessmentObjectKind::Policy,
            policy.digest()?,
            &serde_json::to_vec(&bytes)?,
            1
        )
        .await
        .is_err()
    );
    assert!(
        db.put_assessment_object(
            "registry-fixture",
            AssessmentObjectKind::Policy,
            Sha256Digest::of_bytes("wrong semantic identity"),
            &serde_json::to_vec(&policy)?,
            1
        )
        .await
        .is_err()
    );
    let count = db
        .backend
        .query_opt("SELECT count(*) FROM assessment_objects", &[])
        .await?
        .context("object count")?
        .get::<i64>(0)?;
    assert_eq!(count, 0);
    Ok(())
}

#[tokio::test]
async fn concurrent_identical_object_insertions_have_one_complete_committed_identity() -> Result<()>
{
    let db = Database::open_in_memory().await?;
    let bytes = serde_json::to_vec(&policy())?;
    let digest = policy().digest()?;
    let (one, two) = tokio::join!(
        db.put_assessment_object(
            "registry-fixture",
            AssessmentObjectKind::Policy,
            digest,
            &bytes,
            1
        ),
        db.put_assessment_object(
            "registry-fixture",
            AssessmentObjectKind::Policy,
            digest,
            &bytes,
            2
        ),
    );
    one?;
    two?;
    assert_eq!(
        db.assessment_object("registry-fixture", AssessmentObjectKind::Policy, digest)
            .await?
            .context("atomic stored policy")?,
        aos_contract::canonical::to_vec(&policy())?
    );
    Ok(())
}

fn large_observation() -> UpstreamObservationV1 {
    UpstreamObservationV1 {
        schema: aos_assessment::UPSTREAM_OBSERVATION_V1.into(),
        provider: "github-releases".into(),
        project: "example/fixture".into(),
        retrieved_at_unix: 1,
        request_url: "https://api.github.com/repos/example/fixture/releases".into(),
        adapter_version: "fixture-adapter/v1".into(),
        coverage: ObservationCoverage::Complete,
        response_digest: Sha256Digest::of_bytes("exact raw evidence kept separately"),
        candidates: (0..1000)
            .map(|index| ObservationCandidate {
                raw_id: format!("v1.{index:04}.0"),
                raw_version: format!("1.{index}.0"),
                published_at_unix: None,
                first_observed_at_unix: 1,
                prerelease: false,
                yanked: false,
                release_url: None,
                status: None,
                vulnerable: None,
                licenses: (0..64)
                    .map(|license| format!("License-{license:02}"))
                    .collect(),
            })
            .collect(),
    }
}

#[tokio::test]
async fn multi_shard_objects_reconstruct_exactly_and_missing_custody_is_an_error() -> Result<()> {
    let db = Database::open_in_memory().await?;
    let observation = large_observation();
    observation.validate()?;
    let bytes = aos_contract::canonical::to_vec(&observation)?;
    assert!(bytes.len() > 256 * 1024);
    let digest = Sha256Digest::of_canonical(aos_assessment::UPSTREAM_OBSERVATION_V1, &observation)?;
    db.put_assessment_object(
        "registry-fixture",
        AssessmentObjectKind::Upstream,
        digest,
        &bytes,
        1,
    )
    .await?;
    assert_eq!(
        db.assessment_object("registry-fixture", AssessmentObjectKind::Upstream, digest)
            .await?
            .context("reconstructed upstream")?,
        bytes
    );
    db.backend.execute("DELETE FROM assessment_object_shards WHERE partition_key = ?1 AND object_digest = ?2 AND shard_ordinal = 0", &vals![@slice "registry-fixture", digest.to_string()]).await?;
    assert!(
        db.assessment_object("registry-fixture", AssessmentObjectKind::Upstream, digest)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn changed_shard_content_never_becomes_an_empty_or_fresh_object() -> Result<()> {
    let db = Database::open_in_memory().await?;
    let digest = policy().digest()?;
    db.put_assessment_object(
        "registry-fixture",
        AssessmentObjectKind::Policy,
        digest,
        &serde_json::to_vec(&policy())?,
        1,
    )
    .await?;
    db.backend.execute("UPDATE assessment_object_shards SET canonical_bytes = ?3 WHERE partition_key = ?1 AND object_digest = ?2", &vals![@slice "registry-fixture", digest.to_string(), b"changed bytes".to_vec()]).await?;
    assert!(
        db.assessment_object("registry-fixture", AssessmentObjectKind::Policy, digest)
            .await
            .is_err()
    );
    assert!(
        db.put_assessment_object(
            "registry-fixture",
            AssessmentObjectKind::Policy,
            digest,
            &serde_json::to_vec(&policy())?,
            2
        )
        .await
        .is_err()
    );
    Ok(())
}
