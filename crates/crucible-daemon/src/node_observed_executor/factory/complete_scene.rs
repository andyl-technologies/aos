//! Keeps the installed unqualified complete scene on the catalog's owning actor.
//!
//! This slot is separate from ordinary Accepted provider selection. Its lifetime
//! debits one actor world credit even before preparation and survives every
//! refused or unwound lifecycle until the original supervisor proves release.

use super::*;
use crate::node_qualification::{InstalledCompleteScene, InstalledCompleteSceneManifest};

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
        if self.complete_scene.is_some() {
            return Err(refused("complete scene already installed"));
        }
        let original =
            InstalledCompleteScene::install(manifest, self.socket_parent.join("complete-scene"))
                .map_err(native)?;
        self.complete_scene = Some(original);
        Ok(())
    }

    pub(crate) fn prepare_complete_scene(&mut self) -> Result<(), NodeObservedError> {
        let original = self
            .complete_scene
            .as_mut()
            .ok_or_else(|| refused("complete scene is not installed"))?;
        let result = original.prepare().map_err(native);
        if result.is_err() {
            let _ = original.retire();
        }
        result
    }

    pub(crate) fn complete_scene_world_count(&self) -> usize {
        self.complete_scene
            .as_ref()
            .map_or(0, |original| usize::from(!original.is_reclaimed()))
    }

    pub(crate) fn poll_complete_scene_reclamation(
        &mut self,
        stopping: bool,
    ) -> Result<(), NodeObservedError> {
        if let Some(original) = self.complete_scene.as_mut() {
            if stopping {
                original.retire().map_err(native)?;
            }
            original.poll_reclamation().map_err(native)?;
        }
        Ok(())
    }
}
