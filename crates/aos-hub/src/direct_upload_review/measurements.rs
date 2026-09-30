//! Typed summaries derived solely from exact selected actual raw observation rows.

use std::path::Path;

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::*;
use serde::de::DeserializeOwned;

use super::selection::{DirectReviewReportKind as Kind, DirectReviewSelection};
use super::{files, raw::*};

pub(super) struct Measurements {
    pub(super) clock: DirectClockMeasurement,
    pub(super) runtime: DirectRuntimeMeasurement,
    pub(super) bulk: DirectQueueMeasurement,
    pub(super) metadata: DirectQueueMeasurement,
}

fn input<'a>(
    selection: &'a DirectReviewSelection,
    kind: Kind,
) -> Result<&'a super::selection::ReviewedFile> {
    let mut matches = selection
        .reports
        .iter()
        .filter(|report| report.kind == kind);
    let selected = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("selected actual raw report absent"))?;
    ensure!(
        matches.next().is_none(),
        "selected actual raw report duplicated"
    );
    Ok(&selected.file)
}

fn observations<T: DeserializeOwned>(
    base: &Path,
    selection: &DirectReviewSelection,
    kind: Kind,
) -> Result<(T, String)> {
    let file = input(selection, kind)?;
    let report: DirectReviewRawReport<T> =
        serde_json::from_slice(&files::selected_observation(base, file)?)
            .map_err(|_| anyhow::anyhow!("raw observation is not a closed supported format"))?;
    ensure!(
        report.version == 1
            && report.execution_kind == selection.execution_kind
            && report.deployment_id == selection.deployment_id
            && report.public_origin == selection.public_origin
            && report.source_digest == selection.source_digest
            && report.script_version == selection.script_version,
        "selected actual raw report current identity differs"
    );
    Ok((report.observations, file.sha256.clone()))
}

fn count(length: usize) -> Result<WireInteger> {
    ensure!(
        (1..=4096).contains(&length),
        "actual measurement rows absent or excessive"
    );
    Ok(WireInteger::new(u64::try_from(length)?))
}

fn queue(
    base: &Path,
    selection: &DirectReviewSelection,
    kind: Kind,
    configuration_kind: Kind,
    policy: &DirectQueueDeliveryPolicy,
    mixed: Option<(u64, &str)>,
) -> Result<DirectQueueMeasurement> {
    let (raw, hash): (DirectReviewQueueObservations, _) = observations(base, selection, kind)?;
    let mut peak = 0;
    let mut size = 0;
    for row in &raw.samples {
        peak = peak.max(if raw.dependency_phase == "content" {
            row.bulk_active.get()
        } else {
            row.metadata_active.get()
        });
        size = size.max(row.byte_size.get());
    }
    Ok(DirectQueueMeasurement {
        delivery_policy: policy.clone(),
        configuration_readback_sha256: input(selection, configuration_kind)?.sha256.clone(),
        observation_sha256: hash,
        queue_name: raw.queue_name,
        dependency_phase: raw.dependency_phase,
        completed_jobs: count(raw.samples.len())?,
        peak_parallel_objects: WireInteger::new(peak),
        maximum_verified_object_bytes: WireInteger::new(size),
        source_digest: selection.source_digest.clone(),
        script_version: selection.script_version.clone(),
        metadata_progress_during_bulk: WireInteger::new(mixed.map_or(0, |(samples, _)| samples)),
        mixed_load_observation_sha256: mixed.map(|(_, hash)| hash.into()),
    })
}

pub(super) fn derive(
    base: &Path,
    selection: &DirectReviewSelection,
    identity: &DirectWorkerDeploymentIdentity,
) -> Result<Measurements> {
    let (clock, clock_hash): (DirectReviewClockObservations, _) =
        observations(base, selection, Kind::Clock)?;
    let mut skew = 0;
    let mut expired_dispatches = 0u64;
    count(clock.expired_mutations.len())?;
    for sample in &clock.samples {
        ensure!(
            sample.sent_at_millis.get() <= sample.received_at_millis.get(),
            "clock send/receive bracket reversed"
        );
        skew = skew
            .max(
                sample
                    .observed_at_millis
                    .get()
                    .abs_diff(sample.sent_at_millis.get()),
            )
            .max(
                sample
                    .observed_at_millis
                    .get()
                    .abs_diff(sample.received_at_millis.get()),
            );
    }
    for sample in &clock.expired_mutations {
        expired_dispatches = expired_dispatches
            .checked_add(
                sample
                    .provider_dispatches_after
                    .get()
                    .checked_sub(sample.provider_dispatches_before.get())
                    .ok_or_else(|| anyhow::anyhow!("expired observation counters reversed"))?,
            )
            .ok_or_else(|| anyhow::anyhow!("expired observation counters overflow"))?;
    }
    let clock = DirectClockMeasurement {
        observation_sha256: clock_hash,
        samples: count(clock.samples.len())?,
        maximum_observed_skew_millis: WireInteger::new(skew),
        uncertainty_seconds: identity.clock_uncertainty_seconds,
        expired_mutation_dispatches: WireInteger::new(expired_dispatches),
    };
    let (runtime, runtime_hash): (DirectReviewRuntimeObservations, _) =
        observations(base, selection, Kind::Runtime)?;
    let mut bytes = 0;
    let mut objects = 0;
    let mut providers = 0;
    let mut verification = 0;
    let mut settlement = 0;
    for sample in &runtime.samples {
        bytes = bytes.max(sample.byte_size.get());
        objects = objects.max(sample.peak_parallel_objects.get());
        providers = providers.max(sample.peak_parallel_provider_requests.get());
        verification = verification.max(sample.verification_millis.get());
        settlement = settlement.max(sample.settlement_millis.get());
    }
    let runtime = DirectRuntimeMeasurement {
        observation_sha256: runtime_hash,
        samples: count(runtime.samples.len())?,
        maximum_verified_object_bytes: WireInteger::new(bytes),
        peak_parallel_objects: WireInteger::new(objects),
        peak_parallel_provider_requests: WireInteger::new(providers),
        maximum_verification_millis: WireInteger::new(verification),
        maximum_settlement_millis: WireInteger::new(settlement),
    };
    let (mixed, mixed_hash): (DirectReviewMixedObservations, _) =
        observations(base, selection, Kind::MixedLoad)?;
    let mixed_count = count(mixed.samples.len())?.get();
    Ok(Measurements {
        clock,
        runtime,
        bulk: queue(
            base,
            selection,
            Kind::BulkQueue,
            Kind::BulkConfiguration,
            &identity.bulk_queue_policy,
            None,
        )?,
        metadata: queue(
            base,
            selection,
            Kind::MetadataQueue,
            Kind::MetadataConfiguration,
            &identity.metadata_queue_policy,
            Some((mixed_count, &mixed_hash)),
        )?,
    })
}
