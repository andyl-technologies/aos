//! Image-bound metadata source authorization and immutable source identities.
//!
//! The OS retains this proof with the host evaluation descriptor. It records the
//! original initrd journal decision rather than elevating a new local catalog
//! into authority. Later image boots consume the retained host proof and never
//! replace an operator's accepted runtime module role.
//!
//! ```json
//! {"schema":"aos.boot.metadata-binding","version":1,"metadataSourceRequired":true,"scope":["server","initrd"],"effect":"<effect digest>"}
//! ```

use std::path::{Path, PathBuf};

use anyhow::{Result, ensure};
use aos_contract::Sha256Digest;
use aos_storage_provisioning::{
    AuthorizedProvisioningInput, validate_authorized_provisioning_input,
};
use serde::{Deserialize, Serialize};

use crate::deployment::model::Deployment;
use crate::native_deployment::EvaluationInput;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MetadataBinding {
    schema: String,
    version: u32,
    #[serde(rename = "metadataSourceRequired")]
    pub(super) metadata_source_required: bool,
    #[serde(default)]
    pub(super) scope: Vec<String>,
    #[serde(default)]
    pub(super) effect: String,
}

impl MetadataBinding {
    pub(super) fn required(&self) -> Result<bool> {
        ensure!(
            self.schema == "aos.boot.metadata-binding" && self.version == 1,
            "unsupported image metadata policy"
        );
        ensure!(
            self.metadata_source_required || (self.scope.is_empty() && self.effect.is_empty()),
            "disabled metadata source policy contains a result binding"
        );
        Ok(self.metadata_source_required)
    }

    pub(super) fn validate(&self, deployment: &Deployment) -> Result<()> {
        ensure!(
            self.required()?,
            "image policy declares no metadata source handoff"
        );
        ensure!(
            self.scope == deployment.scope()
                && self.scope.last().is_some_and(|stage| stage == "initrd"),
            "metadata binding differs from the native initrd scope"
        );
        ensure!(
            self.effect.len() == 64
                && self
                    .effect
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "metadata binding has an invalid effect identity"
        );
        ensure!(
            deployment.graph().graph().nodes.contains_key(&self.effect),
            "metadata binding does not select a configured initrd effect"
        );
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreparationResult {
    pub(super) resource: String,
    pub(super) source: String,
    pub(super) committed_plan: PathBuf,
    pub(super) authorized_input: PathBuf,
    pub(super) authorized_input_sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImageAdmission {
    pub(super) path: PathBuf,
    pub(super) sha256: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InitrdDecision {
    pub(super) scope: Vec<String>,
    pub(super) sequence: u64,
    pub(super) content: String,
    pub(super) effect: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactIdentity {
    pub(super) path: PathBuf,
    pub(super) nar_hash: Sha256Digest,
    pub(super) nar_size: u64,
    pub(super) references: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceAuthorization {
    pub(super) schema: String,
    pub(super) version: u32,
    pub(super) image_admission: ImageAdmission,
    pub(super) initrd: InitrdDecision,
    pub(super) authorization: PathBuf,
    pub(super) authorization_sha256: Sha256Digest,
    pub(super) authorization_identity: ArtifactIdentity,
    pub(super) library: ArtifactIdentity,
    pub(super) host: ArtifactIdentity,
    pub(super) facts: ArtifactIdentity,
}

impl SourceAuthorization {
    pub(super) fn validate(&self, descriptor: &EvaluationInput) -> Result<()> {
        ensure!(
            self.schema == "aos.boot.source-authorization" && self.version == 1,
            "unsupported boot source authorization proof"
        );
        ensure!(
            self.initrd.sequence > 0,
            "source authorization has no committed initrd sequence"
        );
        ensure!(
            self.initrd
                .scope
                .last()
                .is_some_and(|stage| stage == "initrd"),
            "source authorization decision is not an initrd scope"
        );
        ensure!(
            self.library.path
                == crate::deployment::nix::store_root_and_suffix(&descriptor.library)?.0
                && self.library.nar_hash == descriptor.library_nar_hash,
            "accepted metadata source uses a different native module library"
        );
        let (authorization_root, _) =
            crate::deployment::nix::store_root_and_suffix(&self.authorization)?;
        ensure!(
            self.authorization_identity.path == authorization_root,
            "source proof authorization NAR names a different root"
        );
        for artifact in [
            &self.library,
            &self.host,
            &self.facts,
            &self.authorization_identity,
        ] {
            let (root, suffix) = crate::deployment::nix::store_root_and_suffix(&artifact.path)?;
            ensure!(
                root == artifact.path && suffix.as_os_str().is_empty(),
                "source authorization NAR does not name a canonical root"
            );
            ensure!(
                artifact.references.windows(2).all(|pair| pair[0] < pair[1]),
                "source authorization references are not sorted and unique"
            );
            for reference in &artifact.references {
                ensure!(
                    reference.len() == 32
                        && reference
                            .bytes()
                            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte)),
                    "source authorization has an invalid direct reference"
                );
            }
            ensure!(
                artifact.nar_size > 0,
                "source authorization contains an empty NAR identity"
            );
        }
        for path in [&self.image_admission.path, &self.authorization] {
            crate::deployment::nix::store_root_and_suffix(path)?;
        }
        Ok(())
    }
}

pub(super) fn validate_authorized_bytes(
    bytes: &[u8],
    expected: Sha256Digest,
    descriptor: &EvaluationInput,
) -> Result<AuthorizedProvisioningInput> {
    ensure!(
        Sha256Digest::of_bytes(bytes) == expected,
        "committed metadata authorization bytes differ from their exact digest"
    );
    let authorized: AuthorizedProvisioningInput =
        aos_contract::canonical::from_slice(bytes, "boot metadata authorization")?;
    validate_authorized_provisioning_input(&authorized)?;
    let (library_root, _) = crate::deployment::nix::store_root_and_suffix(&descriptor.library)?;
    ensure!(
        library_root == Path::new(&authorized.base_library.store_path)
            && descriptor.library_nar_hash.to_string() == authorized.base_library.nar_hash,
        "authorized metadata library differs from the host native descriptor"
    );
    Ok(authorized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> EvaluationInput {
        serde_json::from_value(serde_json::json!({
            "schema":"aos.package.evaluation-input",
            "library":"/nix/store/00000000000000000000000000000000-library/lib",
            "libraryNarHash":Sha256Digest::of_bytes(b"library"),
            "scope":["profile","system"],
            "moduleEnvelopes":{},
            "packages":{"system":"x86_64-linux","artifacts":[],"modules":[]},
            "configuration":[],"runtimeConfiguration":[]
        }))
        .unwrap()
    }

    fn authorization() -> AuthorizedProvisioningInput {
        let facts =
            aos_storage_provisioning::observed_instance_facts(serde_json::json!({})).unwrap();
        AuthorizedProvisioningInput {
            schema: "aos.metadata.authorized-provisioning-input/v1".into(),
            source: aos_storage_provisioning::CanonicalProvisioningSource::Operator,
            host_module: Some("{}\n".into()),
            host_module_sha256: Some(Sha256Digest::of_bytes(b"{}\n").to_string()),
            authorization: aos_storage_provisioning::ProvisioningAuthorization {
                trust_mode: aos_storage_provisioning::ProvisioningTrustMode::Platform,
                platform_id: "offline".into(),
                signer: None,
            },
            facts,
            base_library: aos_storage_provisioning::BaseLibraryIdentity {
                store_path: "/nix/store/00000000000000000000000000000000-library".into(),
                nar_hash: Sha256Digest::of_bytes(b"library").to_string(),
            },
        }
    }

    #[test]
    fn image_policy_explicitly_distinguishes_no_metadata_from_a_missing_binding() {
        let disabled: MetadataBinding = serde_json::from_value(serde_json::json!({
            "schema":"aos.boot.metadata-binding", "version":1, "metadataSourceRequired":false
        }))
        .unwrap();
        assert!(!disabled.required().unwrap());
        assert!(
            serde_json::from_value::<MetadataBinding>(serde_json::json!({
                "schema":"aos.boot.metadata-binding", "version":1
            }))
            .is_err()
        );
        let forged: MetadataBinding = serde_json::from_value(serde_json::json!({
            "schema":"aos.boot.metadata-binding", "version":1, "metadataSourceRequired":false,
            "scope":["boot","initrd"], "effect":"invented"
        }))
        .unwrap();
        assert!(forged.required().is_err());
    }

    #[test]
    fn authorization_binds_original_bytes_and_the_native_library() {
        let authorized = authorization();
        let bytes = aos_contract::canonical::to_vec(&authorized).unwrap();
        let digest = Sha256Digest::of_bytes(&bytes);
        assert!(validate_authorized_bytes(&bytes, digest, &descriptor()).is_ok());
        assert!(
            validate_authorized_bytes(&bytes, Sha256Digest::of_bytes(b"changed"), &descriptor())
                .is_err()
        );

        let mut changed = descriptor();
        changed.library_nar_hash = Sha256Digest::of_bytes(b"different-library");
        assert!(validate_authorized_bytes(&bytes, digest, &changed).is_err());
    }

    #[test]
    fn host_text_cannot_be_changed_inside_an_authorization_receipt() {
        let mut authorized = authorization();
        authorized.host_module = Some("{ aos.networking.hostName = \"unapproved\"; }".into());
        let bytes = aos_contract::canonical::to_vec(&authorized).unwrap();
        assert!(
            validate_authorized_bytes(&bytes, Sha256Digest::of_bytes(&bytes), &descriptor())
                .is_err()
        );
    }
}
