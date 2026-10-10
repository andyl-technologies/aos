//! Authenticated public CNP service for a bounded checksum application process.
//!
//! A private framed bootstrap binds measured executable identity, controller
//! credentials, and admitted resources. The public endpoint retains one native
//! journal across connections and refuses unsupported preservation facets.

mod bootstrap;
mod control;
mod effects;
mod input_reader;
mod input_reader_rows;
mod installed;
mod limits;
mod lineage_launch;
mod lineage_measurement;
mod lineage_reader_launch;
mod native_child;
mod native_supervision;
pub mod profile;
mod progress;
mod resources;
mod retirement;
mod security;
mod server;
mod source_evidence;
mod transfer;

pub use bootstrap::{
    InstalledContent, PublicReferenceProfile, ReferenceServiceBootstrap,
    ReferenceServiceLaunchBootstrap,
};
pub use installed::ReferenceServiceInstalledLaunchBootstrap;
pub use lineage_launch::ReferenceLineageLaunchBootstrap;
pub use lineage_reader_launch::{
    LineageReaderDefinitionSources, ReferenceLineageReaderLaunchBootstrap,
};
pub use profile::{ProfileContent, ReferenceProfile};
pub use progress::{ReferenceProgressLaunchBootstrap, serve_progress};
pub use resources::{ConsumedRequest, PublicationConsumption, RequestConsumption};
pub use server::{serve, serve_installed, serve_lineage, serve_lineage_reader, serve_selected};

use crucible_node_contract::ContractError;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::ProviderError;

fn object(value: impl Serialize) -> Result<Map<String, Value>, ProviderError> {
    serde_json::to_value(value)
        .map_err(ContractError::from)?
        .as_object()
        .cloned()
        .ok_or(ProviderError::Frame("response body is not an object"))
}

fn completed(result: impl Serialize) -> Result<Map<String, Value>, ProviderError> {
    object(
        json!({"status":"completed","operation_state":"completed","result":result,"extensions":{}}),
    )
}

fn refusal(error: &ProviderError) -> Result<Map<String, Value>, ProviderError> {
    let code = match error {
        ProviderError::ResourceExhausted(_) => "RESOURCE_EXHAUSTED",
        ProviderError::Conflict(_) => "CONFLICT",
        ProviderError::Correlation(_) => "BINDING_MISMATCH",
        ProviderError::Contract(_) | ProviderError::Frame(_) => "INVALID_ARGUMENT",
        ProviderError::Io(_) => "OUTCOME_UNKNOWN",
    };
    rejected(code)
}

fn rejected(code: &str) -> Result<Map<String, Value>, ProviderError> {
    object(
        json!({"status":"error","operation_state":"not_started","error":{"code":code,
        "effect":"not_started","retryable":false,"message":"reference request refused",
        "details":{}},"extensions":{}}),
    )
}

fn unknown() -> Result<Map<String, Value>, ProviderError> {
    object(
        json!({"status":"error","operation_state":"unknown","error":{"code":"OUTCOME_UNKNOWN",
        "effect":"unknown","retryable":false,"message":"original native custody remains unresolved",
        "details":{}},"extensions":{}}),
    )
}
