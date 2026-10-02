//! Closed actual namespace, process, Clock and one-shot SDK capture formats.

use aos_hub_core::{direct_upload::WireInteger, oci_sdk_emulation::OciSdkObjectObservation};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Namespace {
    pub version: u32,
    pub observation_scope: String,
    pub observed_at: String,
    pub runner_pid: u32,
    pub runner_start_ticks: WireInteger,
    pub configuration_sha256: String,
    pub runner_sha256: String,
    pub miniflare_version: String,
    pub miniflare_module_sha256: String,
    pub miniflare_entry_worker_sha256: String,
    pub miniflare_bucket_worker_sha256: String,
    pub shim_sha256: String,
    pub wasm_sha256: String,
    pub wasm_byte_size: WireInteger,
    pub source_store_path: String,
    pub build_derived_source_digest: String,
    pub build_derived_script_version: String,
    pub worker_name: String,
    pub binding_name: String,
    pub namespace_id: String,
    pub namespace_unique_key: String,
    pub namespace_object_id: String,
    pub persistence_root: String,
    pub workerd_pid: u32,
    pub workerd_start_ticks: WireInteger,
    pub workerd_executable_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Native {
    pub version: u32,
    pub observation_scope: String,
    pub observed_at: u64,
    pub process_id: u32,
    pub start_ticks: WireInteger,
    pub executable_sha256: String,
    pub configuration_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AnchorOriginal {
    pub version: u32,
    pub issued_at: WireInteger,
    pub expires_at: WireInteger,
    pub run_id: String,
    pub namespace_observation_base64: String,
    pub namespace_observation_sha256: String,
    pub payload_base64: String,
    pub payload_sha256: String,
    pub payload_byte_size: WireInteger,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AnchorReceipt {
    pub version: u32,
    pub status: String,
    pub anchor: OciSdkObjectObservation,
    pub run_id: String,
    pub original_sha256: String,
    pub namespace_observation_sha256: String,
    pub completed_at: String,
    pub sdk_invocations: SdkInvocations,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SdkInvocations {
    pub put: u32,
    pub get: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ClockRequest {
    pub version: u32,
    pub run_id: String,
    pub nonce: String,
    pub source_digest: String,
    pub script_version: String,
    pub expires_at: WireInteger,
    pub action: ClockAction,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ClockAction {
    Clock,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ClockReply {
    pub version: u32,
    pub nonce: String,
    pub request_sha256: String,
    pub source_digest: String,
    pub script_version: String,
    pub observed_at_millis: WireInteger,
    pub result: ClockResult,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ClockResult {
    #[serde(rename_all = "camelCase")]
    Clock {
        nonce: String,
        observed_at_millis: WireInteger,
        uncertainty_seconds: WireInteger,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ClockAuthentication {
    pub status: u32,
    pub request_sha256: String,
    pub response_sha256: String,
    pub sent_at_millis: WireInteger,
    pub received_at_millis: WireInteger,
    pub reply_signature: String,
}
