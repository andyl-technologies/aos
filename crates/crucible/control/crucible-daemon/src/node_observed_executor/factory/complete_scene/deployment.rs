//! Retains funded input preparation separately from the old collecting lifecycle.
//!
//! This capsule creates no worker job or native child. The ordinary complete
//! scene capability remains absent; its existing control request therefore
//! returns the existing unavailable/refused result, never preparation success.

use super::*;
use crate::node_control::{NodeOperationalDeployment, deployment::InstalledDeployment};
use crate::node_qualification::{
    InstalledCompleteSceneManifest, PreparedCompleteRestoration, QualificationError,
};
use crucible_engine::node_state::NativeArchiveLimits;

pub(in crate::node_observed_executor::factory) struct FundedTemplateCapsule {
    manifest: Option<InstalledCompleteSceneManifest>,
    directory: PathBuf,
    deployment: Rc<InstalledDeployment>,
    prepared: Option<PreparedCompleteRestoration>,
    attempted: bool,
    failure: Option<QualificationError>,
    retired: bool,
}

impl FundedTemplateCapsule {
    pub(super) fn new(
        manifest: InstalledCompleteSceneManifest,
        directory: PathBuf,
        original: NodeOperationalDeployment,
    ) -> Self {
        Self {
            manifest: Some(manifest),
            directory,
            deployment: InstalledDeployment::new(original),
            prepared: None,
            attempted: false,
            failure: None,
            retired: false,
        }
    }

    pub(super) fn prepare(&mut self) -> Result<(), NodeObservedError> {
        if self.attempted || self.retired {
            return Err(refused("funded input preparation already attempted"));
        }
        self.attempted = true;
        let result = (|| {
            self.deployment.initialize()?;
            let manifest = self.manifest.take().ok_or(QualificationError::Refused(
                "funded collecting manifest is absent",
            ))?;
            PreparedCompleteRestoration::prepare_with_deployment_into(
                manifest,
                self.directory.clone(),
                NativeArchiveLimits::default(),
                self.deployment.clone(),
                &mut self.prepared,
            )?;
            self.prepared
                .as_ref()
                .ok_or(QualificationError::Refused(
                    "funded template output is absent",
                ))?
                .authenticate_funded_templates_data()
        })();
        if let Err(error) = result {
            // Preserve the original typed cause and every populated input owner.
            // The wire receives no rendered policy/source content or fake stage.
            self.failure = Some(error);
            return Err(refused("funded input preparation is unavailable"));
        }
        Ok(())
    }

    pub(super) fn retire(&mut self) -> Result<(), NodeObservedError> {
        if self.retired {
            return Ok(());
        }
        // No job/Child can exist. Revocation precedes receiver closure, then
        // original-descriptor cleanup. Failure keeps this capsule and credit.
        self.deployment.revoke();
        self.prepared.take();
        self.deployment
            .cleanup_namespace()
            .map_err(|_| refused("funded namespace cleanup remains unresolved"))?;
        self.retired = true;
        Ok(())
    }

    pub(super) fn is_reclaimed(&self) -> bool {
        self.retired
    }
}

impl Drop for FundedTemplateCapsule {
    fn drop(&mut self) {
        // Ordinary actor shutdown keeps this slot until explicit cleanup
        // succeeds. Drop itself never produces a reclaimed observation.
        let _ = self.retire();
    }
}

impl InstalledNodeCatalog {
    pub(crate) fn install_funded_input_preparation(
        &mut self,
        manifest: InstalledCompleteSceneManifest,
        original: NodeOperationalDeployment,
    ) -> Result<(), NodeObservedError> {
        if self.complete_scene.is_some() || self.funded_templates.is_some() {
            return Err(refused("collecting installation already retained"));
        }
        self.funded_templates = Some(Box::new(FundedTemplateCapsule::new(
            manifest,
            self.socket_parent.join("complete-scene"),
            original,
        )));
        // Catalog installation retains the capsule only. Fallible mechanism,
        // namespace and Source preparation run on the later original command,
        // after ordinary startup and signal polling are live.
        Ok(())
    }
}
