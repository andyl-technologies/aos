//! Verification of runtime artifacts against authenticated packages and the live store.
//!
//! The native verifier first checks that an artifact belongs to the sealed package set,
//! then validates the complete live store object and its exact NAR identity before the
//! transaction can retain or execute it.

use std::path::Path;

use aos_ability_model::ArtifactReference;
use aos_ability_model::document::PlatformIdentity;

use crate::ability_package::VerifiedAbilityPackageSet;
use crate::ability_package::retention::{dump_store_path_identity, run_store_check};

pub(super) trait AbilityArtifactVerifier {
    fn verify(&self, artifact: &ArtifactReference) -> anyhow::Result<()>;
}

#[derive(Debug)]
pub(super) struct NativeAbilityArtifactVerifier {
    pub(super) authenticated: VerifiedAbilityPackageSet,
    pub(super) platform: PlatformIdentity,
}

impl AbilityArtifactVerifier for NativeAbilityArtifactVerifier {
    fn verify(&self, artifact: &ArtifactReference) -> anyhow::Result<()> {
        use anyhow::{Context as _, ensure};

        self.authenticated.verify_plan_inputs(
            &self.platform,
            &[],
            std::slice::from_ref(artifact),
        )?;
        let (store_root, _) =
            crate::config_eval::stock::store_root_and_suffix(Path::new(&artifact.store_path))
                .context("artifact does not name a canonical Nix store path")?;
        let store_root = store_root
            .to_str()
            .context("artifact store root is not UTF-8")?;

        run_store_check(store_root, &["--check-validity", "--recursive"])?;
        let (actual, _) = dump_store_path_identity(store_root)?;
        ensure!(
            actual == artifact.nar_hash,
            "artifact NAR mismatch: expected {}, observed {}",
            artifact.nar_hash,
            actual
        );
        Ok(())
    }
}
