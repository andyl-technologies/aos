//! Narrow direct multipart signing using the surface's private parsed credentials.

use anyhow::{ensure, Result};

use crate::direct_upload::{DirectChecksumAlgorithm, DirectPart};
use crate::sigv4::{DirectPartCopySource, DirectSignedProviderRequest, PresignParams};

use super::S3Surface;

impl S3Surface {
    /// Signs one bounded immutable source range with exact version and If-Match.
    ///
    /// # Errors
    /// Returns an error for invalid surface, source version/condition, range,
    /// current material lifetime or signing failure.
    pub fn versioned_conditional_range_request(
        &self,
        path: &str,
        source: &crate::storage_authority::external_object::copy::CopySourceObject,
        offset: u64,
        bytes: u64,
        now: i64,
        maximum_ttl: u32,
    ) -> Result<DirectSignedProviderRequest> {
        self.with_direct_params(path, now, maximum_ttl, |parameters| {
            crate::sigv4::presign_versioned_conditional_range(
                parameters, source, offset, bytes, maximum_ttl,
            )
        })
    }

    /// Signs metadata observation of one exact external provider version.
    ///
    /// # Errors
    /// Returns an error for an invalid path/version, expired material or signing failure.
    pub fn versioned_head_url(
        &self,
        path: &str,
        provider_version: &str,
        now: i64,
        maximum_ttl: u32,
    ) -> Result<String> {
        self.with_direct_params(path, now, maximum_ttl, |params| {
            crate::sigv4::presign_versioned_head(params, provider_version)
        })
    }

    /// Signs one conditional DELETE of the reviewed immutable provider version.
    ///
    /// # Errors
    /// Returns an error for unsafe coordinates, public access, invalid version,
    /// entity tag, clock, lifetime, or signing failure.
    pub fn versioned_conditional_delete_url(
        &self,
        path: &str,
        provider_version: &str,
        etag: &str,
        now: i64,
        maximum_ttl: u32,
    ) -> Result<String> {
        self.with_direct_params(path, now, maximum_ttl, |params| {
            crate::sigv4::presign_versioned_conditional_delete(params, provider_version, etag)
        })
    }

    /// Signs exact private-stage UploadPart with negotiated length/checksum.
    ///
    /// # Errors
    /// Returns a value-free error for unsafe coordinates, public surface,
    /// invalid clock/TTL, malformed part or signing failure.
    pub fn direct_upload_part_request(
        &self,
        path: &str,
        upload_id: &str,
        part: &DirectPart,
        now: i64,
        maximum_ttl: u32,
    ) -> Result<DirectSignedProviderRequest> {
        self.with_direct_params(path, now, maximum_ttl, |params| {
            crate::sigv4::presign_direct_upload_part(params, upload_id, part, maximum_ttl)
        })
    }

    /// Signs server-only UploadPartCopy with exact source bucket/key/range.
    ///
    /// # Errors
    /// Returns a value-free error for invalid surface, source, destination,
    /// clock/TTL or signing. Source immutability must be proven by the caller.
    pub fn direct_upload_part_copy_request(
        &self,
        path: &str,
        upload_id: &str,
        part_number: u32,
        source: &DirectPartCopySource<'_>,
        now: i64,
        maximum_ttl: u32,
    ) -> Result<DirectSignedProviderRequest> {
        self.with_direct_params(path, now, maximum_ttl, |params| {
            crate::sigv4::presign_direct_upload_part_copy(
                params,
                upload_id,
                part_number,
                source,
                maximum_ttl,
            )
        })
    }

    /// Signs a server-only exact private-stage ListParts page.
    ///
    /// # Errors
    /// Returns an error for invalid surface, page coordinates, clock/TTL or signing.
    pub fn direct_list_parts_request(
        &self,
        path: &str,
        upload_id: &str,
        after_part: u32,
        maximum_parts: u32,
        now: i64,
        maximum_ttl: u32,
    ) -> Result<DirectSignedProviderRequest> {
        self.with_direct_params(path, now, maximum_ttl, |params| {
            crate::sigv4::presign_direct_list_parts(
                params,
                upload_id,
                after_part,
                maximum_parts,
                maximum_ttl,
            )
        })
    }

    /// Signs private-stage creation with exact multipart checksum negotiation.
    ///
    /// # Errors
    /// Returns an error for invalid surface, checksum negotiation, clock/TTL or signing.
    pub fn direct_create_multipart_request(
        &self,
        path: &str,
        checksum: DirectChecksumAlgorithm,
        now: i64,
        maximum_ttl: u32,
    ) -> Result<DirectSignedProviderRequest> {
        self.with_direct_params(path, now, maximum_ttl, |params| {
            crate::sigv4::presign_direct_create_multipart(params, checksum, maximum_ttl)
        })
    }

    fn with_direct_params<T>(
        &self,
        path: &str,
        now: i64,
        maximum_ttl: u32,
        sign: impl FnOnce(&PresignParams<'_>) -> Result<T>,
    ) -> Result<T> {
        ensure!(
            now >= 0 && (1..=604800).contains(&maximum_ttl),
            "invalid direct provider clock or lifetime"
        );
        crate::url_guard::validate_http_surface_path(path)
            .map_err(|_| anyhow::anyhow!("invalid direct surface path"))?;
        let creds = self
            .creds
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("direct provider surface requires credentials"))?;
        let key = if self.key_prefix.is_empty() {
            path.to_owned()
        } else {
            format!("{}/{}", self.key_prefix.trim_end_matches('/'), path)
        };
        let object_path = format!("/{key}");
        let amz_date = crate::sigv4::amz_date_from_unix(now);
        sign(&PresignParams {
            access_key: &creds.access_key,
            secret_key: &creds.secret_key,
            region: &creds.region,
            service: "s3",
            scheme: &self.scheme,
            host: &self.host,
            path: &object_path,
            expires_secs: maximum_ttl,
            amz_date: &amz_date,
        })
    }
}
