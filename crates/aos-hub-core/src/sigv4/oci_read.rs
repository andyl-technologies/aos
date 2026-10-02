//! Pure conditional transport signing for OCI-owned physical observations.
//!
//! A provider version is a real provider selector. Its absence never substitutes
//! a guard stamp: independent OCI acceptance and held-key validation supply that
//! business invariant outside this signer.

use anyhow::{ensure, Result};
use crate::direct_upload::DirectRequiredHeader;
use super::{presign_url_with_headers, DirectSignedProviderRequest, PresignParams};

/// Signs a strong conditional HEAD or bounded GET with an optional real version.
///
/// This transport helper creates neither OCI admission nor provider acceptance.
/// The caller separately holds its exact guard incarnation and fresh read lease.
///
/// # Errors
/// Refuses weak tags, false versions, unsupported methods, overflowing ranges,
/// excessive read geometry or a lifetime outside the supplied bounded ceiling.
pub fn presign_oci_conditional_read(
    parameters: &PresignParams<'_>,
    head: bool,
    etag: &str,
    provider_version: Option<&str>,
    range: Option<(u64, u64)>,
    maximum_ttl: u32,
) -> Result<DirectSignedProviderRequest> {
    ensure!(
        crate::surface_write::strong_if_match_etag(etag)? == etag
            && provider_version.is_none_or(crate::storage_work::valid_provider_version)
            && parameters.expires_secs > 0
            && parameters.expires_secs <= maximum_ttl
            && (1..=30).contains(&maximum_ttl)
            && (!head || range.is_none()),
        "OCI conditional read identity or lifetime differs"
    );
    let mut headers = vec![("if-match", etag.to_string())];
    if let Some((offset, bytes)) = range {
        let end = offset.checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("OCI conditional range overflow"))?;
        ensure!(bytes > 0 && bytes <= crate::storage_authority::external_object::oci::EXTERNAL_OCI_PART_BYTES,
            "OCI conditional range exceeds fixed producer geometry");
        headers.push(("range", format!("bytes={offset}-{}", end - 1)));
    }
    let query: Vec<_> = provider_version.map(|version| ("versionId", version.to_owned())).into_iter().collect();
    let url = presign_url_with_headers(if head { "HEAD" } else { "GET" }, parameters, &query, &headers)?;
    Ok(DirectSignedProviderRequest { url, required_headers: headers.into_iter()
        .map(|(name, value)| DirectRequiredHeader { name: name.into(), value }).collect() })
}
