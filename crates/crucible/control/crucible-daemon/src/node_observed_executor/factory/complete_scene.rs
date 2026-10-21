//! Keeps the installed unqualified complete scene on the catalog's owning actor.
//!
//! This slot is separate from ordinary Accepted provider selection. Its lifetime
//! debits one actor world credit even before preparation and survives every
//! refused or unwound lifecycle until the original supervisor proves release.

use super::*;
use crate::node_qualification::{InstalledCompleteScene, InstalledCompleteSceneManifest};

#[path = "complete_scene/deployment.rs"]
mod deployment;
pub(super) use deployment::FundedTemplateCapsule;

impl InstalledNodeCatalog {
    /// Installs one concrete collecting source package before endpoint admission.
    ///
    /// # Errors
    /// Refuses replacement, invalid pinned source/Host scope, changed measured
    /// files or occupied private namespace. This creates no native child.
    pub fn install_complete_scene(
        &mut self,
        manifest: InstalledCompleteSceneManifest,
    ) -> Result<(), NodeObservedError> {
        if self.complete_scene.is_some() || self.funded_templates.is_some() {
            return Err(refused("complete scene already installed"));
        }
        let original =
            InstalledCompleteScene::install(manifest, self.socket_parent.join("complete-scene"))
                .map_err(native)?;
        self.complete_scene = Some(original);
        Ok(())
    }

    pub(crate) fn prepare_complete_scene(&mut self) -> Result<(), NodeObservedError> {
        if let Some(original) = self.funded_templates.as_mut() {
            original.prepare()?;
            return Err(refused(
                "funded templates remain unavailable for complete-scene preparation",
            ));
        }
        let original = self
            .complete_scene
            .as_mut()
            .ok_or_else(|| refused("complete scene is not installed"))?;
        original.prepare().map_err(native)
    }

    pub(crate) fn complete_scene_world_count(&self) -> usize {
        self.complete_scene
            .as_ref()
            .map_or(0, |original| usize::from(!original.is_reclaimed()))
            + self
                .funded_templates
                .as_ref()
                .map_or(0, |original| usize::from(!original.is_reclaimed()))
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn funded_template_observation_data(
        &self,
    ) -> crate::node_observed_executor::FundedTemplateObservation {
        use crate::node_observed_executor::{FundedTemplateObservation, FundedTemplatePhase};
        let phase = self
            .funded_templates
            .as_ref()
            .map_or(FundedTemplatePhase::Absent, |original| {
                original.observed_phase()
            });
        let failure_reason = self
            .funded_templates
            .as_ref()
            .and_then(|original| original.observed_failure_reason());
        FundedTemplateObservation::from_actor(
            phase,
            self.complete_scene_world_count(),
            failure_reason,
        )
    }

    pub(crate) fn poll_complete_scene_reclamation(
        &mut self,
        stopping: bool,
    ) -> Result<(), NodeObservedError> {
        if let Some(original) = self.funded_templates.as_mut() {
            if stopping {
                original.retire()?;
            } else {
                original.poll_derivation()?;
            }
        }
        if let Some(original) = self.complete_scene.as_mut() {
            if stopping {
                original.retire().map_err(native)?;
            }
            original.poll_reclamation().map_err(native)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_prepare_refusal_preserves_spent_capsule_and_world_credit() {
        InstalledCompleteScene::with_spent_prepare_entry_for_test(|original| {
            let executable = std::env::current_exe().unwrap();
            let expected = measure_executable(&executable).unwrap();
            let directory = tempfile::tempdir().unwrap();
            let mut catalog = InstalledNodeCatalog::new(
                executable,
                expected,
                directory.path().to_path_buf(),
                Duration::from_secs(1),
                1,
            )
            .unwrap();
            catalog.complete_scene = Some(original);

            assert!(catalog.prepare_complete_scene().is_err());
            assert_eq!(catalog.complete_scene_world_count(), 1);
            assert!(!catalog.complete_scene.as_ref().unwrap().is_reclaimed());

            catalog.poll_complete_scene_reclamation(true).unwrap();
            assert_eq!(catalog.complete_scene_world_count(), 0);
        });
    }
}
