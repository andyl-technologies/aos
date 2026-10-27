//! Placements helpers in the topology capability.

use super::*;

impl RpcService {
    /// Shared presigner for a read or already-ticketed exact-size direct write.
    ///
    /// `write_size` selects a `PUT` over a `GET`; callers must establish the
    /// durable write ticket before requesting a write signature.
    pub(in crate::service) async fn presign_placement(
        &self,
        placement: &aos_hub_db::db::SurfacePlacementRecord,
        path: &str,
        now: i64,
        write_size: Option<u64>,
        exact_presign_generation: Option<i64>,
    ) -> anyhow::Result<Option<String>> {
        let Some(secret_versions) = self.secret_versions.as_ref() else {
            return Ok(None);
        };
        if write_size.is_some() && !placement.effective_write_enabled {
            anyhow::bail!("presigned write placement is not the reconciled authority");
        }
        let binding = self
            .db
            .binding(placement.binding_id)
            .await?
            .context("placement references a missing binding")?;
        if binding.access_mode.as_deref() != Some("private") {
            return Ok(None);
        }
        let resolver = DatabaseStorageCredentialResolver::new(
            Arc::clone(&self.db),
            Arc::clone(secret_versions),
        );
        let credential = match exact_presign_generation {
            Some(generation) => {
                resolver
                    .resolve_exact(binding.id, "presign", generation)
                    .await
            }
            None => resolver.resolve_current(binding.id, "presign").await,
        };
        let credential = match credential {
            Ok(credential) => credential,
            Err(_) => return Ok(None),
        };
        // The placement prefix is the isolation boundary within a shared bucket.
        // Reject a traversal/structural path BEFORE signing, so a crafted
        // `..` can never mint a valid signature for an object outside this
        // cache's prefix on a path-normalizing origin — the same guard the write
        // path and the local-bytes read path enforce. An invalid path is simply
        // not presignable (`None`); the caller then 404s it.
        if aos_hub_model::url_guard::validate_http_surface_path(path).is_err() {
            return Ok(None);
        }
        let (access_key, rest) = credential
            .secret()?
            .split_once(':')
            .context("presign credential must be access_key:secret_key:region")?;
        let (secret_key, region) = rest
            .rsplit_once(':')
            .context("presign credential must be access_key:secret_key:region")?;

        // Origin scheme + host come from the binding's canonical typed endpoint.
        let scheme = binding
            .endpoint_scheme
            .as_deref()
            .context("presign binding has no typed endpoint scheme")?;
        let host_bytes = binding
            .endpoint_host_bytes
            .as_deref()
            .context("presign binding has no typed endpoint host")?;
        let host_base = match binding.endpoint_host_kind.as_deref() {
            Some("dns") => std::str::from_utf8(host_bytes)
                .context("presign DNS host is not UTF-8")?
                .to_string(),
            Some("ipv4") if host_bytes.len() == 4 => {
                std::net::Ipv4Addr::new(host_bytes[0], host_bytes[1], host_bytes[2], host_bytes[3])
                    .to_string()
            }
            Some("ipv6") if host_bytes.len() == 16 => {
                let bytes: [u8; 16] = host_bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid IPv6 endpoint bytes"))?;
                format!("[{}]", std::net::Ipv6Addr::from(bytes))
            }
            _ => anyhow::bail!("presign binding has an invalid typed endpoint host"),
        };
        let host = binding
            .endpoint_port
            .map_or(host_base.clone(), |port| format!("{host_base}:{port}"));
        // Signed object key: the binding prefix joined with the requested path.
        let object_path = format!(
            "/{}",
            [
                binding.object_bucket.as_deref().unwrap_or(""),
                binding.object_prefix.as_deref().unwrap_or(""),
                placement.prefix.as_str(),
                path,
            ]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("/")
        );

        let params = crate::sigv4::PresignParams {
            access_key,
            secret_key,
            region,
            service: "s3",
            scheme,
            host: &host,
            path: &object_path,
            expires_secs: PRESIGN_EXPIRES_SECS,
            amz_date: &crate::sigv4::amz_date_from_unix(now),
        };
        let url = if let Some(content_length) = write_size {
            crate::sigv4::presign_put_url_with_content_length(&params, content_length)?
        } else {
            crate::sigv4::presign_get_url(&params)?
        };
        Ok(Some(url))
    }
}
