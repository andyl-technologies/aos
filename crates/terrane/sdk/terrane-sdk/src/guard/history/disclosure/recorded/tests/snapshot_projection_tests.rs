//! Checks ordinary disclosure projection after genuine native certificate history.
//!
//! The reused fixture actually publishes both repositories and the disclosure,
//! checks imported Original/trust controls, and completes the exact signed view.
//! Projection comparisons provide no new checked evidence or current permission.

use super::*;
use crate::guard::consumed::SnapshotDisclosureInputs;
use terrane_format::gc::publication::evidence::{DisclosureRow, GuardSnapshot};

fn actual_rows(guard: &ObservedGuard) -> TestResult<Vec<DisclosureRow>> {
    let mut rows = Vec::new();
    for trust in guard.retained_public_trust()? {
        for role in trust.disclosure_roles {
            rows.push(DisclosureRow {
                repository: role.repository,
                domain: role.domain,
                public_key: role.public_key,
                not_before: role.not_before,
                not_after: role.not_after,
            });
        }
    }
    for role in guard.configured_disclosure_roles()? {
        rows.push(DisclosureRow {
            repository: role.repository,
            domain: role.domain,
            public_key: role.public_key,
            not_before: role.not_before,
            not_after: role.not_after,
        });
    }
    Ok(rows)
}

#[tokio::test]
async fn complete_projection_preserves_actual_configured_and_imported_disclosure_rows() -> TestResult
{
    let fixture = published().await?;
    let guard = reader(&fixture, &[], false)?;
    let (checked, _) = complete(&guard, fixture.certified.commit).await?;
    assert!(
        checked
            .completed()
            .dependencies(fixture.certified.commit)
            .is_some()
    );
    assert!(!guard.configured_disclosure_roles()?.is_empty());
    assert!(
        guard
            .retained_public_trust()?
            .iter()
            .any(|trust| !trust.disclosure_roles.is_empty())
    );

    let owner = guard.configured_original_authority()?;
    let actual = ConsumedResolver::new(&guard, &owner)?.snapshot_bytes()?;
    let adapter = guard.source_requalification_configuration_adapter()?;
    assert!(adapter.configured_original_authority().is_err());
    assert!(adapter.retained_public_trust()?.is_empty());
    assert!(adapter.configured_disclosure_roles()?.is_empty());
    let incomplete = ConsumedResolver::new(&adapter, &owner)?.snapshot_bytes()?;
    assert_ne!(incomplete, actual);

    let inputs = ConsumedResolver::snapshot_disclosure_inputs(&guard)?;
    let reconstructed = ConsumedResolver::new_with_snapshot_disclosures(&adapter, &owner, &inputs)?
        .snapshot_bytes()?;
    assert_eq!(reconstructed, actual);
    guard.store().assert_no_effects();
    Ok(())
}

#[tokio::test]
async fn complete_projection_keeps_omitted_or_changed_actual_roles_distinct() -> TestResult {
    let fixture = published().await?;
    let guard = reader(&fixture, &[], false)?;
    complete(&guard, fixture.certified.commit).await?;
    let owner = guard.configured_original_authority()?;
    let actual = ConsumedResolver::new(&guard, &owner)?.snapshot_bytes()?;
    let expected = GuardSnapshot::decode(&actual)?;
    assert!(!expected.disclosures.is_empty());
    let adapter = guard.source_requalification_configuration_adapter()?;

    let mut rows = actual_rows(&guard)?;
    let omitted = rows.first().ok_or("actual disclosure row absent")?.clone();
    rows.retain(|row| row != &omitted);
    let missing = SnapshotDisclosureInputs::from_rows(rows)?;
    let missing_bytes =
        ConsumedResolver::new_with_snapshot_disclosures(&adapter, &owner, &missing)?
            .snapshot_bytes()?;
    assert_ne!(missing_bytes, actual);

    let mut rows = actual_rows(&guard)?;
    let mut changed = rows.first().ok_or("actual disclosure row absent")?.clone();
    rows.retain(|row| row != &changed);
    changed.public_key[0] ^= 1;
    rows.push(changed);
    let changed = SnapshotDisclosureInputs::from_rows(rows)?;
    let changed_bytes =
        ConsumedResolver::new_with_snapshot_disclosures(&adapter, &owner, &changed)?
            .snapshot_bytes()?;
    assert_ne!(changed_bytes, actual);
    guard.store().assert_no_effects();
    Ok(())
}
