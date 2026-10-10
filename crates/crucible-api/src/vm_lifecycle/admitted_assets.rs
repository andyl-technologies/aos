//! Admits owning lifecycle paths and the architecture-specific guest asset map.
//!
//! This constructor copies authenticated input selected by its caller. It does
//! not authenticate artifacts, issue a native role, or authorize a launch.

use std::path::{Path, PathBuf};

use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeCustody};

use super::{
    ProductionVmGuestAssets, ProductionVmLifecycleConfig, RootImageFormat, VmArchitecture,
};

/// Borrows the concrete paths for one lifecycle configuration.
pub struct ProductionVmGuestAssetPaths<'input> {
    /// Selects the already authenticated emulator executable.
    pub executable: &'input Path,
    /// Selects its matching installed plugin.
    pub plugin: &'input Path,
    /// Selects the architecture supported by the authenticated guest tuple.
    pub architecture: VmArchitecture,
    /// Selects the guest kernel.
    pub kernel: &'input Path,
    /// Selects the guest root image.
    pub root_image: &'input Path,
    /// Selects an optional guest initrd.
    pub initrd: Option<&'input Path>,
    /// Selects the authenticated root image format.
    pub root_image_format: RootImageFormat,
    /// Selects durable recovery storage owned by the enclosing service.
    pub run_state_root: &'input Path,
}

/// Retains a lifecycle construction refusal with its original allocation custody.
#[derive(Debug, thiserror::Error)]
#[error("lifecycle asset construction refused: {source}")]
pub struct ProductionVmGuestAssetAdmissionError {
    #[source]
    source: AssetAdmissionCause,
    // The actual typed refusal is destroyed before its allocation custody.
    _custody: DecodeCustody,
}

#[derive(Debug, thiserror::Error)]
enum AssetAdmissionCause {
    #[error("original asset admission refused: {0}")]
    Admission(#[from] DecodeAdmissionError),
    #[error("admitted path allocation refused: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
}

#[cfg(test)]
mod tests;

impl ProductionVmLifecycleConfig {
    /// Copies guest asset paths under the supplied original input account.
    ///
    /// The caller retains authenticated file pins and the account through
    /// configuration, factory and native retirement. This constructor admits
    /// its actual path capacities and guest map node before allocation, including
    /// fixed storage for an immediate shared configuration installation. It
    /// leaves the command line prefix empty; compact scenarios retain their
    /// own complete command lines. Execution bounds and service capabilities
    /// must be installed by the enclosing admitted owner before launch.
    ///
    /// # Errors
    /// Refuses an expired or exhausted account or a path allocation failure.
    pub fn try_from_guest_asset_paths_admitted(
        paths: ProductionVmGuestAssetPaths<'_>,
        budget: &DecodeBudget,
    ) -> Result<Self, ProductionVmGuestAssetAdmissionError> {
        let custody = budget.custody();
        let scope = budget.enter();
        let result = (|| {
            budget.verify_live()?;
            budget.charge_array::<Self>(1)?;
            budget.charge_array::<usize>(2)?;
            budget.charge_btree_entry::<VmArchitecture, ProductionVmGuestAssets>()?;

            let executable = copy_path(paths.executable, budget)?;
            let plugin = copy_path(paths.plugin, budget)?;
            let kernel = copy_path(paths.kernel, budget)?;
            let root_image = copy_path(paths.root_image, budget)?;
            let run_state_root = copy_path(paths.run_state_root, budget)?;
            let initrd = paths
                .initrd
                .map(|path| copy_path(path, budget))
                .transpose()?;

            let mut configuration = Self::new_for_guest_architecture(
                executable,
                plugin,
                paths.architecture,
                kernel,
                root_image,
                run_state_root,
            );
            configuration.initrd = initrd;
            configuration.root_image_format = paths.root_image_format;
            configuration.decode_custody = Some(custody.clone());
            #[cfg(test)]
            tests::after_copy(&mut configuration);
            budget.verify_live()?;
            Ok(configuration)
        })();
        drop(scope);

        result.map_err(|source| ProductionVmGuestAssetAdmissionError {
            source,
            _custody: custody,
        })
    }
}

fn copy_path(path: &Path, budget: &DecodeBudget) -> Result<PathBuf, AssetAdmissionCause> {
    let bytes = path.as_os_str().as_encoded_bytes().len();
    budget.charge_array::<u8>(bytes)?;
    let mut output = std::ffi::OsString::new();
    output.try_reserve_exact(bytes)?;
    output.push(path.as_os_str());
    Ok(output.into())
}
