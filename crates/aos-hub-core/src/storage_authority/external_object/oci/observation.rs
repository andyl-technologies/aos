//! Canonical historical External OCI metadata observations without permission.
//!
//! These decoders reuse the production intrinsic shape, original correlation and
//! byte budgets. They neither verify MACs nor accept current SQL, IAM, producer
//! or Delete authority. Actual original/received bytes and accepted-handler
//! evidence remain separate obligations.
//!
//! ```text
//! control: ExternalOciRequest -> ExternalOciReply
//! source: OciSourceLookup -> OciSourceReply
//! cleanup: OciCleanupRequest -> OciCleanupReply
//! ```

use anyhow::{ensure, Result};
use serde::{de::DeserializeOwned, Serialize};

use super::{
    cleanup::{OciCleanupReply, OciCleanupRequest, MAX_OCI_CLEANUP_BYTES},
    control::{ExternalOciRequest, MAX_EXTERNAL_OCI_CONTROL_BYTES},
    reply::{ExternalOciReply, MAX_EXTERNAL_OCI_REPLY_BYTES},
    source::{OciSourceLookup, OciSourceReply, MAX_OCI_SOURCE_BYTES},
};

#[cfg(test)]
mod tests;

/// Decodes canonical retained control metadata and its exact correlated reply.
///
/// This returns unverified records, never an authenticated proof or dispatch grant.
///
/// # Errors
/// Refuses oversized or noncanonical JSON, invalid original/window/actor/phase,
/// request substitution or impossible progress and closure.
pub fn decode_external_oci_control_observation(
    request: &[u8],
    reply: &[u8],
    deployment: &str,
) -> Result<(ExternalOciRequest, ExternalOciReply)> {
    let request: ExternalOciRequest = decode(request, MAX_EXTERNAL_OCI_CONTROL_BYTES)?;
    let reply: ExternalOciReply = decode(reply, MAX_EXTERNAL_OCI_REPLY_BYTES)?;
    request.validate_observation_shape(deployment)?;
    reply.validate_for(&request)?;
    Ok((request, reply))
}

/// Decodes canonical retained source metadata and its exact positive coordinates.
///
/// This observes the closed shape only; it verifies no MAC or present authority.
///
/// # Errors
/// Refuses oversized or noncanonical JSON, foreign writer/source/original,
/// inconsistent closure or an observation outside the original request window.
pub fn decode_external_oci_source_observation(
    request: &[u8],
    reply: &[u8],
    deployment: &str,
) -> Result<(OciSourceLookup, OciSourceReply)> {
    let request: OciSourceLookup = decode(request, MAX_OCI_SOURCE_BYTES)?;
    let reply: OciSourceReply = decode(reply, MAX_OCI_SOURCE_BYTES)?;
    request.validate_observation_shape(deployment)?;
    reply.validate_observation_for(&request)?;
    Ok((request, reply))
}

/// Decodes canonical terminal cleanup metadata and exact conditional-delete facts.
///
/// This neither authenticates deletion nor grants new Delete authority.
///
/// # Errors
/// Refuses oversized or noncanonical JSON, invalid cleanup window or identity,
/// missing positive version and any request/original/receipt substitution.
pub fn decode_external_oci_cleanup_observation(
    request: &[u8],
    reply: &[u8],
    deployment: &str,
) -> Result<(OciCleanupRequest, OciCleanupReply)> {
    let request: OciCleanupRequest = decode(request, MAX_OCI_CLEANUP_BYTES)?;
    let reply: OciCleanupReply = decode(reply, MAX_OCI_CLEANUP_BYTES)?;
    request.validate_observation_shape(deployment)?;
    reply.validate_for(&request)?;
    Ok((request, reply))
}

fn decode<T: DeserializeOwned + Serialize>(body: &[u8], maximum: usize) -> Result<T> {
    ensure!(
        body.len() <= maximum,
        "external OCI observation exceeds its closed bound"
    );
    let value = serde_json::from_slice(body)?;
    ensure!(
        serde_json::to_vec(&value)? == body,
        "external OCI observation noncanonical"
    );
    Ok(value)
}
