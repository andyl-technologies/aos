//! Reuses independently committed evidence under an exact inventory and policy.
//!
//! Profile heads locate immutable evaluation closures. Their observations keep
//! their original times and completeness; reuse grants no renewed freshness or
//! disposition authority and performs no source or raw-body acquisition.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context as _, Result};
use aos_assessment::input::EvaluationData;

use crate::db::{AssessmentScanRecord, Database};

impl Database {
    pub(super) async fn restore_assessment_committed_evidence(
        &self,
        scan: &AssessmentScanRecord,
        data: &mut EvaluationData,
    ) -> Result<()> {
        let rows = self
            .backend
            .query(
                "SELECT DISTINCT heads.last_scan_id, previous.generation
             FROM assessment_heads AS heads JOIN assessment_scans AS previous
               ON previous.scan_id = heads.last_scan_id AND previous.registry_id = heads.registry_id
             WHERE heads.registry_id = ?1 AND heads.inventory_digest = ?2
               AND heads.policy_digest = ?3 AND heads.committed_generation > 0
               AND previous.admission_complete = 1 AND previous.state IN('succeeded', 'partial')
               AND previous.generation < ?4
             ORDER BY previous.generation, heads.last_scan_id LIMIT 10001",
                &vals![@slice scan.registry_id, scan.request.inventory_digest.to_string(),
                scan.request.policy_digest.to_string(), scan.generation],
            )
            .await?;
        if rows.len() > 10_000 {
            bail!("committed assessment cache exceeds its closure count bound");
        }
        let mut read_bytes = 0_u64;
        let read_limit = scan.request.limits.normalized_bytes.min(64 * 1024 * 1024);
        for row in rows {
            let (input, retained) = self
                .assessment_frozen_evaluation(scan.registry_id, &row.get::<String>(0)?)
                .await?;
            if input.inventory_digest != scan.request.inventory_digest
                || input.policy_digest != scan.request.policy_digest
            {
                bail!("committed cache differs from the requested inventory or policy");
            }
            read_bytes = read_bytes
                .checked_add(super::objects::encode(&retained)?.len() as u64)
                .filter(|bytes| *bytes <= read_limit)
                .context("committed cache exceeds its normalized closure read allowance")?;
            merge_evidence(data, retained)?;
            // Bound the accumulator as well as each retained source closure.
            super::objects::encode(data)?;
        }
        Ok(())
    }
}

fn merge_evidence(data: &mut EvaluationData, retained: EvaluationData) -> Result<()> {
    let mut upstream = data
        .upstream
        .drain(..)
        .map(|binding| (binding.component_ref.clone(), binding))
        .collect::<BTreeMap<_, _>>();
    for binding in retained.upstream {
        let replace = upstream.get(&binding.component_ref).is_none_or(|previous| {
            binding.observation.retrieved_at_unix >= previous.observation.retrieved_at_unix
        });
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
        if let Some(catalog) = retained.exploit_catalog {
            if snapshot.exploit_catalog.as_ref().is_none_or(|previous| {
                catalog.observation.validated_at >= previous.observation.validated_at
            }) {
                snapshot.exploit_catalog = Some(catalog);
            }
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
