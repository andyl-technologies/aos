//! Reuses independently admitted evidence without renewing freshness or authority.
//!
//! Hosts verify immutable closure custody before calling this merger. All source
//! times, coverage and query bindings survive reuse; current dispositions remain
//! exclusively in the authoritative destination closure.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail};
use aos_assessment::input::EvaluationData;

/// Merges exact committed observations into an identical inventory and policy.
///
/// Upstream and advisory questions retain their latest admitted validation,
/// while candidate history keeps its earliest admitted observation. The caller
/// supplies closures in admission order to resolve equal validation times.
/// Historical dispositions never replace current authoritative statements.
///
/// # Errors
/// Returns an error for changed scope, missing candidate history, malformed
/// snapshots or invalid digest contracts. Callers discard the destination on
/// failure; the function does not establish admission or independently verify
/// frozen closure custody.
pub fn merge_committed_evidence(data: &mut EvaluationData, retained: EvaluationData) -> Result<()> {
    if data.inventory.digest()? != retained.inventory.digest()?
        || data.policy.digest()? != retained.policy.digest()?
    {
        bail!("committed evidence differs from the exact inventory or policy");
    }
    let mut upstream = data
        .upstream
        .drain(..)
        .map(|binding| (binding.component_ref.clone(), binding))
        .collect::<BTreeMap<_, _>>();
    for binding in retained.upstream {
        let replace = upstream
            .get(&binding.component_ref)
            .is_none_or(|previous| binding.validated_at_unix() >= previous.validated_at_unix());
        if replace {
            upstream.insert(binding.component_ref.clone(), binding);
        }
    }
    data.upstream = upstream.into_values().collect();

    let mut history = BTreeMap::new();
    for entry in data.history.drain(..).chain(retained.history) {
        let key = (
            entry.provider.clone(),
            entry.project.clone(),
            entry.raw_id.clone(),
        );
        history
            .entry(key)
            .and_modify(|previous: &mut aos_assessment::input::CandidateHistory| {
                previous.first_observed_at = previous
                    .first_observed_at
                    .clone()
                    .min(entry.first_observed_at.clone());
            })
            .or_insert(entry);
    }
    for binding in &mut data.upstream {
        for candidate in &mut binding.observation.candidates {
            let key = (
                binding.observation.provider.clone(),
                binding.observation.project.clone(),
                candidate.raw_id.clone(),
            );
            let first = history
                .get(&key)
                .context("committed candidate history is absent")?;
            candidate.first_observed_at_unix = first.first_observed_at.unix_seconds();
        }
    }
    data.history = history.into_values().collect();

    let mut records = data
        .advisories
        .drain(..)
        .chain(retained.advisories)
        .map(|record| Ok((record.digest()?, record)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    if let Some(retained) = retained.advisory_snapshot {
        let snapshot = data.advisory_snapshot.get_or_insert_with(|| {
            aos_assessment::advisory::AdvisorySnapshotV1 {
                schema: aos_assessment::advisory::ADVISORY_SNAPSHOT_V1.into(),
                sources: vec![],
                exploit_catalog: None,
            }
        });
        let mut sources = snapshot
            .sources
            .drain(..)
            .map(|source| ((source.provider.clone(), source.project.clone()), source))
            .collect::<BTreeMap<_, _>>();
        for source in retained.sources {
            let key = (source.provider.clone(), source.project.clone());
            if sources.get(&key).is_none_or(|previous| {
                source.observation.validated_at >= previous.observation.validated_at
            }) {
                sources.insert(key, source);
            }
        }
        snapshot.sources = sources.into_values().collect();
        if let Some(catalog) = retained.exploit_catalog
            && snapshot.exploit_catalog.as_ref().is_none_or(|previous| {
                catalog.observation.validated_at >= previous.observation.validated_at
            })
        {
            snapshot.exploit_catalog = Some(catalog);
        }
        snapshot.validate()?;
    }
    let referenced = data
        .advisory_snapshot
        .iter()
        .flat_map(|snapshot| &snapshot.sources)
        .flat_map(|source| source.record_digests.iter().copied())
        .collect::<BTreeSet<_>>();
    records.retain(|digest, _| referenced.contains(digest));
    data.advisories = records.into_values().collect();
    // Dispositions are deliberately taken only from current authoritative
    // inventory admission. A historical closure cannot restore a revoked grant.
    Ok(())
}
