//! Copies the authenticated guest tuple into its retained lifecycle owner.
//!
//! The same artifact owner keeps every file pin and external input account
//! through configuration use. This stage creates no executor or native role.

use std::path::Path;
use std::sync::Arc;

use crucible::model::VmArchitecture;
use crucible_api::ProductionVmLifecycleConfig;
use crucible_api::vm_lifecycle::ProductionVmGuestAssetPaths;
use crucible_qemu::QemuRootImageFormat;

use super::*;

impl OriginalWorkflowArtifactsOwner {
    /// Publishes the admitted guest tuple with the same original catalog provider.
    ///
    /// # Errors
    /// Refuses missing or foreign assets, repeated publication, original
    /// admission, actual state or quota custody, or lifecycle construction.
    pub(in crate::private_measurement_runtime::workflow) fn prepare_lifecycle(
        &mut self,
        state: &crate::campaign_bootstrap::OriginalCampaignStateBootstrap,
        service: &OriginalPreparedCampaignServiceOwner,
        catalog: &crate::private_measurement_runtime::catalog::OriginalRamCatalogBinding,
    ) -> Result<(), OriginalWorkflowArtifactsError> {
        let original = || service.verify_original();
        let mut failure = ArtifactFailurePurpose::prepare(&self.budget, &original)?;
        let result = {
            let check = failure.work(&original);
            let work = (|| {
                check.verify_original()?;
                self.budget.verify_live()?;
                if self.closed || self.lifecycle.is_some() {
                    return Err(ArtifactCause::Identity);
                }
                let projection = self.projection.as_ref().ok_or(ArtifactCause::Identity)?;
                let guest = &projection.guest_assets;
                if guest.architecture != "x86_64" || guest.boot_mode != "directKernel" {
                    return Err(ArtifactCause::Identity);
                }
                let root_image_format = match guest.root_image_format {
                    projection::RootImageFormat::Raw => QemuRootImageFormat::Raw,
                    projection::RootImageFormat::Qcow2 => QemuRootImageFormat::Qcow2,
                };
                state.run_state_root()?;
                catalog.verify()?;
                let configuration =
                    ProductionVmLifecycleConfig::try_from_guest_asset_paths_admitted(
                        ProductionVmGuestAssetPaths {
                            executable: Path::new(&projection.executable.path),
                            plugin: Path::new(&projection.plugin.path),
                            architecture: VmArchitecture::X86_64,
                            kernel: Path::new(&guest.kernel.path),
                            root_image: Path::new(&guest.root_image.path),
                            initrd: guest
                                .initrd
                                .as_ref()
                                .map(|artifact| Path::new(&artifact.path)),
                            root_image_format,
                            run_state_root: catalog.root(),
                        },
                        &self.budget,
                    )?
                    .with_ram_catalog_provider(catalog.provider());
                // The constructor admitted this immediate Arc header and body.
                // Publication precedes the independent sticky and raw postcuts.
                self.lifecycle = Some(Arc::new(configuration));
                Ok(())
            })();
            checked(&check, work)
        };
        failure.finish(result)
    }
}

/// Frees a unique lifecycle body while pins and original credit stay held.
///
/// # Errors
/// Retains the same body after any strong/weak alias or original refusal.
pub(super) fn close_configuration(
    owner: &mut OriginalWorkflowArtifactsOwner,
    check: &ArtifactWork<'_, '_>,
) -> Result<(), ArtifactRefusal> {
    if let Some(configuration) = owner.lifecycle.as_mut()
        && Arc::get_mut(configuration).is_none()
    {
        return checked(check, Err(ArtifactCause::LifecycleAliases));
    }
    // The configuration body, paths and Arc allocation close while all actual
    // file pins and this owner's external original custody remain retained.
    drop(owner.lifecycle.take());
    checked(check, Ok(()))
}
