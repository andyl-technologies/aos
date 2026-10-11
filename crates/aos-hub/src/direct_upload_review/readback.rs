//! Actual hosted provider consumer readback checks, separate from isolate capacities.
//!
//! The provider's GET queue response is documented at
//! <https://developers.cloudflare.com/api/resources/queues/methods/get/>.
//! Provider responses retain unknown provider metadata; authority comes only from
//! the explicitly inspected queue name, Worker consumer and numeric settings.

use anyhow::{ensure, Result};
use aos_hub_core::direct_upload::DirectQueueMeasurement;
use serde::Deserialize;

#[derive(Deserialize)]
struct QueueResponse {
    success: bool,
    errors: Vec<serde_json::Value>,
    result: QueueResult,
}

#[derive(Deserialize)]
struct QueueResult {
    queue_name: String,
    consumers: Vec<Consumer>,
}

#[derive(Deserialize)]
struct Consumer {
    #[serde(rename = "type")]
    kind: String,
    script_name: Option<String>,
    queue_name: Option<String>,
    settings: ConsumerSettings,
}

#[derive(Deserialize)]
struct ConsumerSettings {
    batch_size: Option<u64>,
    max_concurrency: Option<u64>,
}

pub(super) fn hosted_queue(
    bytes: &[u8],
    worker: &str,
    measurement: &DirectQueueMeasurement,
) -> Result<()> {
    let response: QueueResponse = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("provider queue readback malformed"))?;
    ensure!(
        response.success
            && response.errors.is_empty()
            && response.result.queue_name == measurement.queue_name,
        "provider queue readback differs"
    );
    ensure!(
        response.result.consumers.len() == 1,
        "provider queue consumer set differs"
    );
    let consumer = &response.result.consumers[0];
    ensure!(
        consumer.kind == "worker"
            && consumer.script_name.as_deref() == Some(worker)
            && consumer
                .queue_name
                .as_deref()
                .is_none_or(|name| name == measurement.queue_name)
            && consumer.settings.batch_size
                == Some(measurement.delivery_policy.maximum_batch_size.get())
            && consumer.settings.max_concurrency.is_some()
            && consumer.settings.max_concurrency
                == measurement
                    .delivery_policy
                    .maximum_concurrent_invocations
                    .as_ref()
                    .map(|bound| bound.get()),
        "provider queue delivery policy differs or is unbounded"
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EmulatorQueueReadback {
    version: u32,
    execution_kind: aos_hub_core::direct_upload::DirectWorkerExecutionKind,
    deployment_id: String,
    public_origin: String,
    source_digest: String,
    script_version: String,
    queue_name: String,
    maximum_batch_size: aos_hub_core::direct_upload::WireInteger,
    maximum_concurrent_invocations: Option<aos_hub_core::direct_upload::WireInteger>,
    invocation_bound_support: String,
    runtime_bindings_sha256: String,
    distribution_nar_sha256: String,
}

pub(super) fn emulated_queue(
    bytes: &[u8],
    artifact: &aos_hub_core::direct_upload::DirectWorkerQualificationArtifact,
    measurement: &DirectQueueMeasurement,
) -> Result<()> {
    let observed: EmulatorQueueReadback = serde_json::from_slice(bytes).map_err(|_| {
        anyhow::anyhow!("emulator consumer readback is not a closed supported format")
    })?;
    let installed = artifact
        .evidence
        .installation
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("emulator installation readback absent"))?;
    ensure!(
        observed.version == 1
            && observed.execution_kind == artifact.execution_kind
            && observed.deployment_id == artifact.deployment_id
            && observed.public_origin == artifact.public_origin
            && observed.source_digest == artifact.source_digest
            && observed.script_version == artifact.script_version
            && observed.queue_name == measurement.queue_name
            && observed.maximum_batch_size == measurement.delivery_policy.maximum_batch_size
            && observed.maximum_concurrent_invocations.is_none()
            && measurement
                .delivery_policy
                .maximum_concurrent_invocations
                .is_none()
            && observed.invocation_bound_support == "unsupported"
            && observed.runtime_bindings_sha256 == installed.report.runtime_bindings_sha256
            && observed.distribution_nar_sha256 == installed.report.distribution_nar_sha256,
        "emulator consumer configuration differs from actual installed observations"
    );
    Ok(())
}
