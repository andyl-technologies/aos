//! Retains funded input preparation separately from the old collecting lifecycle.
//!
//! Supervised jobs remain with their actual Prepared and original cleanup owners.
//! The ordinary complete scene capability remains absent; its control request
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
    started: bool,
    failure: Option<QualificationError>,
    retired: bool,
    templates_authenticated: bool,
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
            started: false,
            failure: None,
            retired: false,
            templates_authenticated: false,
        }
    }

    /// Spends the retained entry and requests setup on the owning actor's poll.
    ///
    /// # Errors
    /// Refuses a repeated or retired capsule without restarting its work.
    pub(super) fn request_preparation(&mut self) -> Result<(), NodeObservedError> {
        if self.attempted || self.retired {
            return Err(refused("funded input preparation already attempted"));
        }
        // Spend the original entry before replying. The same actor performs
        // setup on its subsequent poll, outside the short control exchange.
        self.attempted = true;
        Ok(())
    }

    fn prepare_requested(&mut self) -> Result<(), NodeObservedError> {
        if !self.attempted || self.started || self.retired {
            return Err(refused("funded input preparation cannot start"));
        }
        self.started = true;
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
        // Only this completed authenticator permits later derivation polling;
        // a partial Prepared output cannot select the operational job path.
        self.templates_authenticated = true;
        Ok(())
    }

    #[cfg(feature = "test-support")]
    pub(super) fn observed_phase(&self) -> crate::node_observed_executor::FundedTemplatePhase {
        use crate::node_observed_executor::FundedTemplatePhase;
        if self.retired {
            FundedTemplatePhase::Reclaimed
        } else if !self.attempted {
            FundedTemplatePhase::Unattempted
        } else if !self.started {
            FundedTemplatePhase::PreparationRequested
        } else if self.templates_authenticated && self.failure.is_some() {
            FundedTemplatePhase::DerivationFailed
        } else if self
            .prepared
            .as_ref()
            .is_some_and(PreparedCompleteRestoration::funded_private_births_retained_data)
        {
            FundedTemplatePhase::PrivateBirthsRetained
        } else if self.templates_authenticated {
            FundedTemplatePhase::TemplatesRetained
        } else {
            FundedTemplatePhase::AttemptFailed
        }
    }

    #[cfg(feature = "test-support")]
    pub(super) fn observed_operation_stage(&self) -> Option<&'static str> {
        self.deployment.operation_stage_data()
    }

    #[cfg(feature = "test-support")]
    pub(super) fn observed_failure_reason(&self) -> Option<&'static str> {
        self.failure.as_ref().map(|error| match error {
            QualificationError::Refused(reason) => *reason,
            QualificationError::Contract(_) => "funded preparation schema validation failed",
            QualificationError::Evidence(_) => "funded preparation evidence validation failed",
        })
    }

    pub(super) fn poll_derivation(&mut self) -> Result<(), NodeObservedError> {
        if self.retired {
            return Ok(());
        }
        if self.attempted && !self.started {
            // A preparation refusal remains observable in this same capsule.
            // It must not become a derivation failure or force shutdown before
            // the actual first failure can be published by the actor.
            let _ = self.prepare_requested();
            return Ok(());
        }
        if self.failure.is_some() && !self.templates_authenticated {
            return Ok(());
        }
        let Some(prepared) = &mut self.prepared else {
            return Ok(());
        };
        if let Err(error) = prepared.poll_funded_derivation_data(false) {
            if self.failure.is_none() {
                let _ = error; // the original typed cause remains in Prepared or its Job
                self.failure = Some(QualificationError::Refused("funded derivation failed"));
            }
            // A contained logical failure spends this occurrence, not the
            // daemon's lifetime. Keep polling the same failed Prepared so its
            // supervisor cancels and waits for every actual child. World credit
            // remains retained until explicit retirement proves reclamation.
            return Ok(());
        }
        Ok(())
    }

    pub(super) fn retire(&mut self) -> Result<(), NodeObservedError> {
        if self.retired {
            return Ok(());
        }
        // Revoke acceptance first. Every original job drains through the same
        // physical cleanup before receiver closure, namespace cleanup or refund.
        self.deployment.revoke();
        if let Some(prepared) = &mut self.prepared {
            if !prepared
                .poll_funded_derivation_data(true)
                .map_err(|_| refused("funded worker cleanup remains unresolved"))?
            {
                return Err(refused("funded worker cleanup remains unresolved"));
            }
        }
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
        // namespace and Source preparation run on the poll requested by the
        // later original command, after ordinary startup and signal polling
        // are live.
        Ok(())
    }
}
