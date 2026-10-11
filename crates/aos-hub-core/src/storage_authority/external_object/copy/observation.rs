//! Canonical bounded historical copy observations without execution authority.
//!
//! These decoders share production shape and reply correlation. They do not
//! authenticate transport, accept a current SQL claim or grant provider work.
//! Independent original/received body and accepted-handler joins remain required.
//!
//! ```text
//! control: ExternalCopyRequest -> ExternalCopyReply
//! metadata: CopyMetadataRequest -> CopyMetadataReply
//! ```

use anyhow::{ensure, Result};
use serde::{de::DeserializeOwned, Serialize};

use super::{
    control::{ExternalCopyReply, ExternalCopyRequest, MAX_EXTERNAL_COPY_CONTROL_BYTES},
    metadata::{CopyMetadataReply, CopyMetadataRequest},
};

/// Decodes an exact historical copy control and its correlated compact reply.
///
/// This returns unverified observations, never authenticated permission. The
/// caller must separately bind the request to its independently retained original.
///
/// # Errors
/// Returns an error for excessive or noncanonical JSON, unknown fields,
/// malformed original shape, impossible progress or request substitution.
pub fn decode_copy_control_observation(
    request: &[u8],
    reply: &[u8],
    deployment: &str,
) -> Result<(ExternalCopyRequest, ExternalCopyReply)> {
    let request: ExternalCopyRequest = decode(request)?;
    let reply: ExternalCopyReply = decode(reply)?;
    request.validate_observation_shape(deployment)?;
    reply.validate_observation_for(&request)?;
    Ok((request, reply))
}

/// Decodes an exact historical installed-profile query and retained-owner reply.
///
/// This neither authenticates the transport nor grants physical dispatch. A
/// missing retained original remains an explicit observation of the reply only.
///
/// # Errors
/// Returns an error for excessive or noncanonical JSON, unknown fields,
/// malformed original pins, changed profile or inconsistent retained progress.
pub fn decode_copy_metadata_observation(
    request: &[u8],
    reply: &[u8],
    deployment: &str,
) -> Result<(CopyMetadataRequest, CopyMetadataReply)> {
    let request: CopyMetadataRequest = decode(request)?;
    let reply: CopyMetadataReply = decode(reply)?;
    request.validate_observation_shape(deployment)?;
    reply.validate_observation_for(&request)?;
    Ok((request, reply))
}

fn decode<T: DeserializeOwned + Serialize>(body: &[u8]) -> Result<T> {
    ensure!(
        body.len() <= MAX_EXTERNAL_COPY_CONTROL_BYTES,
        "copy observation exceeds its closed bound"
    );
    let value = serde_json::from_slice(body)?;
    ensure!(
        serde_json::to_vec(&value)? == body,
        "noncanonical copy observation"
    );
    Ok(value)
}
