//! Exact emulator audience, installation mapping and OCI-only SDK anchor.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::direct_upload::{
    direct_private_stage_policy_commitment, direct_qualification_digest,
    direct_worker_emulated_script_id, valid_direct_digest, DirectClockPolicy,
    DirectPrivateStagePolicyRef,
};

use super::{valid_identity, OciSdkObjectObservation};

/// Pins one independently observed local Native/workerd OCI document pair.
///
/// These coordinates are distinct from a Direct managed profile. They contain
/// no provider account, S3 endpoint, credential, presigning or mirror authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciSdkEmulationProfile {
    /// Exact protected deployment shared by Native and the Worker.
    pub deployment_id: String,
    /// Reserved local HTTPS Worker origin selected by Native.
    pub public_origin: String,
    /// Reserved local HTTPS Native metadata origin selected by the Worker.
    pub native_origin: String,
    /// Build-derived source identity joined to the installed Worker observation.
    pub worker_source_digest: String,
    /// Explicit source-derived emulator script identity.
    pub worker_script_version: String,
    /// Actual selected worker name reported by the installed runtime.
    pub worker_name: String,
    /// Actual selected R2 attachment; currently `REGISTRY_BUCKET`.
    pub binding_name: String,
    /// Actual normalized local R2 namespace reported by the installed runtime.
    pub namespace_id: String,
    /// Actual R2 bucket durable object ID derived through the installed runtime.
    pub namespace_object_id: String,
    /// Version-pinned local R2 namespace key, never a Cloudflare account ID.
    pub namespace_unique_key: String,
    /// Installed conservative UTC policy; observations remain separate evidence.
    pub clock_policy: DirectClockPolicy,
    /// Installed bounded provider capacity shared with the existing SDK executor.
    pub maximum_provider_requests: u32,
    /// Independently reviewed private namespace and exclusive writer policy.
    pub private_stage_policy: DirectPrivateStagePolicyRef,
    /// Genuine small SDK anchor in an isolated qualification key space.
    pub anchor: OciSdkObjectObservation,
}

impl OciSdkEmulationProfile {
    /// Checks the closed audience, actual mapping and stable policy commitments.
    ///
    /// # Errors
    /// Rejects production origins, unsupported SDK attachment or namespace
    /// mappings, invalid code identities, malformed anchors or changed policies.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            valid_identity(&self.deployment_id)
                && reserved_origin(&self.public_origin)
                && reserved_origin(&self.native_origin)
                && valid_direct_digest(&self.worker_source_digest)
                && self.worker_script_version
                    == direct_worker_emulated_script_id(&self.worker_source_digest)?
                && valid_identity(&self.worker_name)
                && self.binding_name == crate::binding::DEPLOYMENT_R2_ATTACHMENT
                && self
                    .namespace_id
                    .strip_prefix("oci-sdk-qualification-")
                    .is_some_and(|run| {
                        run.len() == 32
                            && run
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                    })
                && valid_direct_digest(&self.namespace_object_id)
                && self.namespace_unique_key == "miniflare-R2BucketObject",
            "OCI SDK emulator audience or actual namespace mapping differs"
        );
        self.clock_policy.commitment()?;
        ensure!(
            (2..=32).contains(&self.maximum_provider_requests),
            "OCI SDK provider capacity is invalid"
        );
        ensure!(
            self.private_stage_policy.namespace == self.namespace_id
                && self.private_stage_policy.policy_digest
                    == direct_private_stage_policy_commitment(
                        &self.private_stage_policy.policy_id,
                        &self.namespace_id,
                    )?,
            "OCI SDK private namespace policy differs"
        );
        self.anchor.validate()?;
        let anchor_parts: Vec<_> = self.anchor.object.key.split('/').collect();
        ensure!(
            self.anchor.object.size <= 1024
                && anchor_parts.len() == 3
                && anchor_parts[0] == ".aos-oci-sdk-qualification"
                && anchor_parts[1].len() == 32
                && anchor_parts[1]
                    .bytes()
                    .all(|byte| { byte.is_ascii_digit() || matches!(byte, b'a'..=b'f') })
                && anchor_parts[2] == "anchor",
            "OCI SDK anchor is outside its isolated bounded key space"
        );
        Ok(())
    }

    /// Returns an OCI-only commitment to the complete selected SDK profile.
    ///
    /// # Errors
    /// Rejects invalid profile coordinates or serialization failure.
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        direct_qualification_digest(&("aos.oci-documents.emulated-sdk-profile.v1", self))
    }
}

// Explicit local origins prevent this purpose from being relabeled as hosted
// readiness. A configured URL remains a pin, not an installation observation.
fn reserved_origin(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.origin().ascii_serialization() == value
        && url.host_str().is_some_and(|host| {
            host == "localhost" || host.ends_with(".localhost") || host.ends_with(".test")
        })
}
