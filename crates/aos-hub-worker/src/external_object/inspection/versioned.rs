//! Exact immutable-provider identity and conditional range validation.
//!
//! A real non-null version is selected by leased provider HEAD, never from a
//! key name or LIST. These checks confer no permission; the runtime retains
//! the current Read lease, physical-key gate and actual request owner.

use super::super::copy::source_protocol::Request;
use anyhow::{Context as _, Result, ensure};
use aos_hub_core::storage_work::StorageObjectIdentity;

/// Refuses every retained physical owner before selecting a provider version.
///
/// # Errors
/// Refuses pending or unknown work, including Mirror ownership retained until
/// its exact Native commit is acknowledged. Time and HEAD cannot settle it.
pub(in crate::external_object) fn require_idle(head: &super::super::state::Head) -> Result<()> {
    ensure!(
        head.pending.is_none()
            && head.observation.is_none()
            && head.stage.is_none()
            && head.copy.is_none()
            && head.oci.is_none()
            && head.mirror.is_none(),
        "versioned source is active or unknown"
    );
    Ok(())
}

pub(in crate::external_object) fn validate_identity(
    request: &Request,
    source: &StorageObjectIdentity,
) -> Result<()> {
    let selection = request
        .inspection
        .as_ref()
        .context("versioned selection absent")?;
    aos_hub_core::surface_write::strong_if_match_etag(&source.etag)?;
    ensure!(
        source.key == request.plan.object_key(&selection.path)?
            && source.size <= selection.maximum_bytes
            && source
                .provider_version
                .as_deref()
                .is_some_and(|version| version != "null"
                    && aos_hub_core::storage_work::valid_provider_version(version)),
        "versioned inspection source differs from typed selection"
    );
    Ok(())
}

pub(in crate::external_object) fn head_identity(
    request: &Request,
    status: u16,
    length: Option<&str>,
    etag: Option<&str>,
    version: Option<&str>,
    encoding: Option<&str>,
) -> Result<Option<StorageObjectIdentity>> {
    if status == 404 {
        return Ok(None);
    }
    ensure!(
        status == 200 && encoding.is_none_or(|value| value.eq_ignore_ascii_case("identity")),
        "versioned HEAD has unknown status or representation"
    );
    let selection = request
        .inspection
        .as_ref()
        .context("versioned selection absent")?;
    let source = StorageObjectIdentity {
        key: request.plan.object_key(&selection.path)?,
        size: length.context("versioned HEAD length absent")?.parse()?,
        etag: aos_hub_core::surface_write::strong_if_match_etag(
            etag.context("versioned HEAD tag absent")?,
        )?,
        provider_version: Some(
            version
                .context("versioned HEAD immutable version absent")?
                .to_owned(),
        ),
    };
    validate_identity(request, &source)?;
    Ok(Some(source))
}

pub(in crate::external_object) fn validate_range(
    source: &StorageObjectIdentity,
    offset: u64,
    bytes: u64,
    status: u16,
    length: Option<&str>,
    etag: Option<&str>,
    version: Option<&str>,
    range: Option<&str>,
    encoding: Option<&str>,
) -> Result<()> {
    let end = offset
        .checked_add(bytes)
        .context("versioned range overflow")?;
    if source.size == 0 {
        ensure!(
            offset == 0
                && bytes == 0
                && status == 200
                && length == Some("0")
                && etag == Some(source.etag.as_str())
                && version == source.provider_version.as_deref()
                && version.is_some_and(|version| version != "null")
                && range.is_none()
                && encoding.is_none_or(|value| value.eq_ignore_ascii_case("identity")),
            "versioned empty response identity differs"
        );
        return Ok(());
    }
    ensure!(
        bytes > 0
            && end <= source.size
            && status == 206
            && length == Some(bytes.to_string().as_str())
            && etag == Some(source.etag.as_str())
            && version == source.provider_version.as_deref()
            && source
                .provider_version
                .as_deref()
                .is_some_and(|value| value != "null")
            && range == Some(format!("bytes {}-{}/{}", offset, end - 1, source.size).as_str())
            && encoding.is_none_or(|value| value.eq_ignore_ascii_case("identity")),
        "versioned conditional response identity differs"
    );
    Ok(())
}

#[cfg(target_arch = "wasm32")]
mod runtime;
#[cfg(target_arch = "wasm32")]
pub(in crate::external_object) use runtime::fetch;
#[cfg(test)]
mod tests;
