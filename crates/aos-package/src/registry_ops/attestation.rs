//! Attestation metadata and content digests binding published artifacts.

pub(in crate::registry_ops) fn package_nar_root_digest(nar_hash: &str) -> anyhow::Result<String> {
    Ok(format!(
        "sha256:{}",
        aos_registry_surface::store::canonical_digest_hex(nar_hash)?
    ))
}

#[cfg(test)]
mod tests;
