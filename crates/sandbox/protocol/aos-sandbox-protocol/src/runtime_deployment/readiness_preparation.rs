//! Existing node-local readiness preparation JSON wire DATA.
//!
//! The same declaration serves the protected Host loader and normal deployment
//! publisher. Encoding, decoding and public fields grant neither native scope,
//! publisher-generation currentness nor backend launch readiness.
//!
//! ```text
//! {schema,publisher_generation,boot_id,nspawn_store_path,nspawn_device,
//!  nspawn_inode,probe_digest,supervisor_profile_digest,payload_filter_digest}
//! ```

/// Existing bounded readiness preparation JSON schema; ingestion grants no readiness.
pub const BACKEND_READINESS_PREPARATION_SCHEMA_V1: &str = "aos.sandbox.host-backend-readiness.v1";
/// Existing hard maximum for the exact readiness preparation artifact.
pub const MAXIMUM_BACKEND_READINESS_PREPARATION_BYTES_V1: usize = 16 * 1024;

/// Carries the existing protected preparation artifact as untrusted wire DATA.
///
/// The actual Host loader independently checks boot, current immutable nspawn
/// identity, the publisher watermark and every declared claim. A successful
/// decode or encode cannot construct backend readiness or a publication owner.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendReadinessPreparationDataV1 {
    /// Exact supported node-local preparation schema.
    pub schema: String,
    /// Claimed publisher generation, whose durable floor the producer must establish.
    pub publisher_generation: u64,
    /// Claimed physical boot, independently rechecked by the protected Host loader.
    pub boot_id: [u8; 16],
    /// Exact pinned packaged nspawn path, not a caller-selected executable.
    pub nspawn_store_path: String,
    /// Actual immutable nspawn device.
    pub nspawn_device: u64,
    /// Actual immutable nspawn inode.
    pub nspawn_inode: u64,
    /// Complete independently verified signed probe commitment.
    pub probe_digest: [u8; 32],
    /// Packaged fixed compiler supervisor policy, not live supervisor evidence.
    pub supervisor_profile_digest: [u8; 32],
    /// Packaged filter source, not a claim that a payload loaded its filter.
    pub payload_filter_digest: [u8; 32],
}

impl BackendReadinessPreparationDataV1 {
    /// Encodes the sole current JSON field order as comparison DATA.
    ///
    /// The caller prepays the full bounded output before serialization. This
    /// codec neither authenticates the fields nor updates a generation floor.
    ///
    /// # Errors
    /// Refuses an encoding failure or bytes beyond the existing16KiB boundary.
    pub fn encode_data_v1(&self) -> Result<Vec<u8>, super::DeploymentWireErrorV1> {
        // Precompute a conservative complete output bound without allocating.
        // All numeric arrays and fixed keys together occupy fewer than1024B.
        // Strings use the same JSON escaping classes as serde_json.
        let bound = escaped_string_bytes(&self.schema)?
            .checked_add(escaped_string_bytes(&self.nspawn_store_path)?)
            .and_then(|bytes| bytes.checked_add(1024))
            .filter(|bytes| *bytes <= MAXIMUM_BACKEND_READINESS_PREPARATION_BYTES_V1)
            .ok_or(super::DeploymentWireErrorV1)?;
        let bytes = serde_json::to_vec(self).map_err(|_| super::DeploymentWireErrorV1)?;
        if bytes.len() > bound {
            return Err(super::DeploymentWireErrorV1);
        }
        if bytes.len() > MAXIMUM_BACKEND_READINESS_PREPARATION_BYTES_V1 {
            return Err(super::DeploymentWireErrorV1);
        }
        Ok(bytes)
    }
}

fn escaped_string_bytes(value: &str) -> Result<usize, super::DeploymentWireErrorV1> {
    if value.len() > MAXIMUM_BACKEND_READINESS_PREPARATION_BYTES_V1 {
        return Err(super::DeploymentWireErrorV1);
    }
    value.bytes().try_fold(2usize, |bytes, byte| {
        let width = match byte {
            b'"' | b'\\' => 2,
            0..=31 => 6,
            _ => 1,
        };
        bytes.checked_add(width).ok_or(super::DeploymentWireErrorV1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> BackendReadinessPreparationDataV1 {
        BackendReadinessPreparationDataV1 {
            schema: BACKEND_READINESS_PREPARATION_SCHEMA_V1.to_owned(),
            publisher_generation: 9,
            boot_id: [4; 16],
            nspawn_store_path:
                "/nix/store/00000000000000000000000000000000-systemd/bin/systemd-nspawn".to_owned(),
            nspawn_device: 2,
            nspawn_inode: 3,
            probe_digest: [5; 32],
            supervisor_profile_digest: [6; 32],
            payload_filter_digest: [7; 32],
        }
    }

    #[test]
    fn current_json_field_order_and_unknown_field_refusal_are_preserved() {
        let original = artifact();
        let encoded = original.encode_data_v1().unwrap();
        let text = String::from_utf8(encoded.clone()).unwrap();
        assert!(text.starts_with("{\"schema\":\"aos.sandbox.host-backend-readiness.v1\",\"publisher_generation\":9,\"boot_id\":"));
        assert!(text.contains("\"nspawn_device\":2,\"nspawn_inode\":3,\"probe_digest\":"));
        let decoded: BackendReadinessPreparationDataV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.encode_data_v1().unwrap(), encoded);

        let mut unknown = text;
        unknown.pop();
        unknown.push_str(",\"authority\":true}");
        assert!(serde_json::from_str::<BackendReadinessPreparationDataV1>(&unknown).is_err());
    }

    #[test]
    fn string_escaping_is_bounded_before_the_output_is_constructed() {
        let mut original = artifact();
        original.nspawn_store_path = "\u{0}\\\"".repeat(100);
        let encoded = original.encode_data_v1().unwrap();
        assert!(encoded.len() <= MAXIMUM_BACKEND_READINESS_PREPARATION_BYTES_V1);

        original.nspawn_store_path = "\u{0}".repeat(3000);
        assert!(original.encode_data_v1().is_err());
    }
}
