//! Independent derivation and commitment checks for actual retained numeric reports.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::captures::{self, Captures};
use super::selection::{DirectReviewReportKind as Kind, DirectReviewSelection};
use super::{files, raw::*, readback};

fn parsed<T: DeserializeOwned>(
    bytes: &[u8],
    artifact: &DirectWorkerQualificationArtifact,
) -> Result<T> {
    let report: DirectReviewRawReport<T> = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("raw observation is not a closed supported format"))?;
    ensure!(
        report.version == 1
            && report.execution_kind == artifact.execution_kind
            && report.deployment_id == artifact.deployment_id
            && report.public_origin == artifact.public_origin
            && report.source_digest == artifact.source_digest
            && report.script_version == artifact.script_version,
        "raw observation audience or current code differs"
    );
    Ok(report.observations)
}

fn same(actual: &impl Serialize, expected: &impl Serialize) -> Result<()> {
    ensure!(
        serde_json::to_vec(actual)? == serde_json::to_vec(expected)?,
        "typed measurements differ from actual retained observations"
    );
    Ok(())
}

fn count(length: usize) -> Result<WireInteger> {
    ensure!(
        (1..=4096).contains(&length),
        "actual measurement rows absent or excessive"
    );
    Ok(WireInteger::new(u64::try_from(length)?))
}

fn clock(
    bytes: &[u8],
    hash: &str,
    artifact: &DirectWorkerQualificationArtifact,
    captures: &Captures,
) -> Result<()> {
    let observed: DirectReviewClockObservations = parsed(bytes, artifact)?;
    count(observed.expired_mutations.len())?;
    let mut skew = 0;
    for sample in &observed.samples {
        let sent = sample.sent_at_millis.get();
        let received = sample.received_at_millis.get();
        let worker = sample.observed_at_millis.get();
        ensure!(
            sent <= received && worker > 0,
            "actual clock bracket invalid"
        );
        let result = captures.result(&sample.reply_sha256)?;
        ensure!(
            captures::text(result, "kind")? == "clock"
                && captures::integer(result, "observedAtMillis")? == worker
                && captures::integer(result, "uncertaintySeconds")?
                    == artifact.evidence.clock_policy.uncertainty_seconds.get(),
            "actual clock reply differs from selected sample"
        );
        skew = skew
            .max(worker.abs_diff(sent))
            .max(worker.abs_diff(received));
    }
    for sample in &observed.expired_mutations {
        let result = captures.result(&sample.reply_sha256)?;
        let before = &result["providerBefore"];
        let after = &result["providerAfter"];
        ensure!(
            captures::text(result, "kind")? == "expired_mutation_refused"
                && captures::integer(result, "cutoff")? == sample.cutoff.get()
                && captures.observed_at_millis(&sample.reply_sha256)?
                    == sample.observed_at_millis.get()
                && captures::integer(result, "observedAt")? >= sample.cutoff.get()
                && captures::text(before, "isolateId")? == sample.isolate_id
                && captures::text(after, "isolateId")? == sample.isolate_id
                && captures::integer(before, "dispatches")?
                    == sample.provider_dispatches_before.get()
                && captures::integer(after, "dispatches")?
                    == sample.provider_dispatches_after.get()
                && sample.provider_dispatches_before == sample.provider_dispatches_after,
            "expired mutation observation changed or dispatched a provider effect"
        );
    }
    same(
        &DirectClockMeasurement {
            observation_sha256: hash.into(),
            samples: count(observed.samples.len())?,
            maximum_observed_skew_millis: WireInteger::new(skew),
            uncertainty_seconds: artifact.evidence.clock_policy.uncertainty_seconds,
            expired_mutation_dispatches: WireInteger::new(0),
        },
        &artifact.evidence.clock,
    )
}

fn runtime(
    bytes: &[u8],
    hash: &str,
    artifact: &DirectWorkerQualificationArtifact,
    captures: &Captures,
) -> Result<()> {
    let observed: DirectReviewRuntimeObservations = parsed(bytes, artifact)?;
    let mut maximum_bytes = 0;
    let mut objects = 0;
    let mut provider = 0;
    let mut verification = 0;
    let mut settlement = 0;
    let mut identities = BTreeSet::new();
    for sample in &observed.samples {
        ensure!(
            identities.insert((&sample.object_id, &sample.isolate_id)),
            "runtime positive sample duplicated"
        );
        let (closed, receipt) = captures.receipt(&sample.reply_sha256, &sample.object_id, None)?;
        captures::proof(
            receipt,
            &sample.sha256,
            sample.byte_size.get(),
            &sample.proof_sha256,
        )?;
        let started = captures::integer(&receipt["attempt"], "startedAtMillis")?;
        let finished = captures::integer(receipt, "finishedAtMillis")?;
        ensure!(
            finished.checked_sub(started) == Some(sample.verification_millis.get())
                && captures::integer(closed, "settlementMillis")? == sample.settlement_millis.get()
                && captures::integer(&receipt["objects"], "aggregateActive")?
                    == sample.peak_parallel_objects.get()
                && captures::integer(&receipt["providerAfter"], "peakActive")?
                    == sample.peak_parallel_provider_requests.get()
                && sample.peak_parallel_objects.get()
                    <= artifact.evidence.runtime.maximum_parallel_objects.get()
                && sample.peak_parallel_provider_requests.get()
                    <= artifact
                        .evidence
                        .runtime
                        .maximum_parallel_provider_requests
                        .get()
                && captures::integer(&receipt["providerAfter"], "maximum")?
                    == artifact
                        .evidence
                        .runtime
                        .maximum_parallel_provider_requests
                        .get()
                && captures::dispatches(receipt, &sample.isolate_id)?
                    == sample.fresh_provider_dispatches.get(),
            "runtime summary differs from retained positive receipt"
        );
        maximum_bytes = maximum_bytes.max(sample.byte_size.get());
        objects = objects.max(sample.peak_parallel_objects.get());
        provider = provider.max(sample.peak_parallel_provider_requests.get());
        verification = verification.max(sample.verification_millis.get());
        settlement = settlement.max(sample.settlement_millis.get());
    }
    same(
        &DirectRuntimeMeasurement {
            observation_sha256: hash.into(),
            samples: count(observed.samples.len())?,
            maximum_verified_object_bytes: WireInteger::new(maximum_bytes),
            peak_parallel_objects: WireInteger::new(objects),
            peak_parallel_provider_requests: WireInteger::new(provider),
            maximum_verification_millis: WireInteger::new(verification),
            maximum_settlement_millis: WireInteger::new(settlement),
        },
        &artifact.evidence.runtime_measurement,
    )
}

fn queue(
    bytes: &[u8],
    hash: &str,
    artifact: &DirectWorkerQualificationArtifact,
    expected: &DirectQueueMeasurement,
    captures: &Captures,
) -> Result<DirectReviewQueueObservations> {
    let observed: DirectReviewQueueObservations = parsed(bytes, artifact)?;
    ensure!(
        observed.queue_name == expected.queue_name
            && observed.dependency_phase == expected.dependency_phase,
        "raw queue class or name differs"
    );
    let mut maximum_bytes = 0;
    let mut peak = 0;
    let mut identities = BTreeSet::new();
    for sample in &observed.samples {
        ensure!(
            identities.insert((&sample.object_id, &sample.message_id)),
            "positive queue receipt duplicated"
        );
        let (_, receipt) = captures.receipt(
            &sample.reply_sha256,
            &sample.object_id,
            Some(&sample.message_id),
        )?;
        captures::proof(
            receipt,
            &sample.sha256,
            sample.byte_size.get(),
            &sample.proof_sha256,
        )?;
        ensure!(
            captures::text(receipt, "queueName")? == observed.queue_name
                && captures::integer(&receipt["attempt"], "startedAtMillis")?
                    == sample.started_at_millis.get()
                && captures::integer(receipt, "finishedAtMillis")?
                    == sample.finished_at_millis.get()
                && sample.finished_at_millis.get() > sample.started_at_millis.get()
                && captures::integer(&receipt["objects"], "aggregateActive")?
                    == sample.aggregate_active.get()
                && captures::integer(&receipt["objects"], "bulkActive")?
                    == sample.bulk_active.get()
                && captures::integer(&receipt["objects"], "metadataActive")?
                    == sample.metadata_active.get()
                && sample.aggregate_active.get()
                    <= artifact.evidence.runtime.maximum_parallel_objects.get()
                && sample.bulk_active.get()
                    <= artifact
                        .evidence
                        .runtime
                        .maximum_parallel_objects
                        .get()
                        .saturating_sub(1)
                && sample
                    .bulk_active
                    .get()
                    .checked_add(sample.metadata_active.get())
                    == Some(sample.aggregate_active.get())
                && captures::dispatches(receipt, &sample.isolate_id)?
                    == sample.fresh_provider_dispatches.get(),
            "raw queue summary differs from retained receipt or aggregate bound"
        );
        maximum_bytes = maximum_bytes.max(sample.byte_size.get());
        peak = peak.max(if observed.dependency_phase == "content" {
            sample.bulk_active.get()
        } else {
            sample.metadata_active.get()
        });
    }
    let mut derived = expected.clone();
    derived.observation_sha256 = hash.into();
    derived.completed_jobs = count(observed.samples.len())?;
    derived.maximum_verified_object_bytes = WireInteger::new(maximum_bytes);
    derived.peak_parallel_objects = WireInteger::new(peak);
    same(&derived, expected)?;
    Ok(observed)
}

fn mixed(
    bytes: &[u8],
    artifact: &DirectWorkerQualificationArtifact,
    bulk: &DirectReviewQueueObservations,
    metadata: &DirectReviewQueueObservations,
    captures: &Captures,
) -> Result<()> {
    let observed: DirectReviewMixedObservations = parsed(bytes, artifact)?;
    let expected = &artifact.evidence.metadata_queue;
    let mut identities = BTreeSet::new();
    for sample in &observed.samples {
        ensure!(
            identities.insert((&sample.isolate_id, &sample.metadata_reply_sha256)),
            "mixed observation duplicated"
        );
        let meta = metadata
            .samples
            .iter()
            .find(|row| {
                row.reply_sha256 == sample.metadata_reply_sha256
                    && row.isolate_id == sample.isolate_id
                    && row.started_at_millis == sample.metadata_started_at_millis
                    && row.finished_at_millis == sample.metadata_finished_at_millis
            })
            .ok_or_else(|| anyhow::anyhow!("mixed metadata positive receipt absent"))?;
        ensure!(
            bulk.samples
                .iter()
                .any(|row| row.isolate_id == sample.isolate_id
                    && row.started_at_millis == sample.bulk_started_at_millis
                    && row.finished_at_millis == sample.bulk_finished_at_millis)
                && sample.bulk_started_at_millis.get() <= sample.metadata_started_at_millis.get()
                && sample.metadata_finished_at_millis.get() <= sample.bulk_finished_at_millis.get()
                && sample.bulk_active == meta.bulk_active
                && sample.bulk_active.get()
                    == artifact
                        .evidence
                        .runtime
                        .maximum_parallel_objects
                        .get()
                        .saturating_sub(1),
            "mixed observation lacks held bulk overlap in the same isolate"
        );
        let (_, receipt) = captures.receipt(
            &sample.metadata_reply_sha256,
            &meta.object_id,
            Some(&meta.message_id),
        )?;
        ensure!(
            captures::integer(
                &receipt["attempt"]["providerBefore"],
                "metadataAdmissionsDuringBulk"
            )? == sample.metadata_admissions_before.get()
                && captures::integer(&receipt["providerAfter"], "metadataAdmissionsDuringBulk")?
                    == sample.metadata_admissions_after.get()
                && sample.metadata_admissions_after.get() > sample.metadata_admissions_before.get(),
            "mixed metadata admission during bulk was not observed"
        );
    }
    ensure!(
        count(observed.samples.len())? == expected.metadata_progress_during_bulk,
        "mixed metadata progress count differs"
    );
    Ok(())
}

pub(super) fn validate(
    base: &Path,
    selection: &DirectReviewSelection,
    artifact: &DirectWorkerQualificationArtifact,
) -> Result<()> {
    let captures = Captures::load(base, selection, artifact)?;
    let mut inputs = BTreeMap::new();
    for report in &selection.reports {
        let bytes = files::selected_observation(base, &report.file)?;
        ensure!(
            inputs
                .insert(report.kind, (report.file.sha256.as_str(), bytes))
                .is_none(),
            "raw report class selected more than once"
        );
    }
    let mut take = |kind, commitment: &str| -> Result<Vec<u8>> {
        let (hash, bytes) = inputs
            .remove(&kind)
            .ok_or_else(|| anyhow::anyhow!("required raw report absent"))?;
        ensure!(
            kind == Kind::SdkChecksumRejection || hash == commitment,
            "typed report commitment differs from reviewed raw bytes"
        );
        Ok(bytes)
    };
    let evidence = &artifact.evidence;
    clock(
        &take(Kind::Clock, &evidence.clock.observation_sha256)?,
        &evidence.clock.observation_sha256,
        artifact,
        &captures,
    )?;
    runtime(
        &take(
            Kind::Runtime,
            &evidence.runtime_measurement.observation_sha256,
        )?,
        &evidence.runtime_measurement.observation_sha256,
        artifact,
        &captures,
    )?;
    let bulk = queue(
        &take(Kind::BulkQueue, &evidence.bulk_queue.observation_sha256)?,
        &evidence.bulk_queue.observation_sha256,
        artifact,
        &evidence.bulk_queue,
        &captures,
    )?;
    let metadata = queue(
        &take(
            Kind::MetadataQueue,
            &evidence.metadata_queue.observation_sha256,
        )?,
        &evidence.metadata_queue.observation_sha256,
        artifact,
        &evidence.metadata_queue,
        &captures,
    )?;
    mixed(
        &take(
            Kind::MixedLoad,
            evidence
                .metadata_queue
                .mixed_load_observation_sha256
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("mixed raw report commitment absent"))?,
        )?,
        artifact,
        &bulk,
        &metadata,
        &captures,
    )?;
    for (kind, queue) in [
        (Kind::BulkConfiguration, &evidence.bulk_queue),
        (Kind::MetadataConfiguration, &evidence.metadata_queue),
    ] {
        let bytes = take(kind, &queue.configuration_readback_sha256)?;
        match artifact.execution_kind {
            DirectWorkerExecutionKind::Hosted => {
                readback::hosted_queue(&bytes, &selection.worker_name, queue)?
            }
            DirectWorkerExecutionKind::EmulatedExternal => {
                readback::emulated_queue(&bytes, artifact, queue)?
            }
        }
    }
    if evidence.managed_profile.is_some() {
        super::privacy::validate(base, selection, artifact, &mut take)?;
    }
    ensure!(
        inputs.is_empty(),
        "raw report classes exceed selected evidence"
    );
    Ok(())
}
