//! Deployed standalone namespace custody for artifact and control input buffers.
//!
//! Inputs acquire the operator's existing catalog quota and independently
//! authored service limits before file reads or response decoding. This path
//! opens no guest process and creates no modeled execution authority.

use super::*;
use crucible_daemon::campaign_store_composition::StorePhysicalQuotaGuard;
use crucible_session::engine::owned_decode::DecodeBudget;
use std::cell::RefCell;
use std::sync::Arc;

pub(crate) use crate::cli_backend::{admit_native_command_input, take_native_owner};

thread_local! {
    // Borrowing this command owner never starts a new supervisor or namespace.
    static COMMAND_INPUT: RefCell<Option<(Option<PathBuf>, StandaloneInputResources)>> = const { RefCell::new(None) };
}

pub(crate) struct CommandInputOwner {
    previous: Option<(Option<PathBuf>, StandaloneInputResources)>,
}

impl Drop for CommandInputOwner {
    fn drop(&mut self) {
        COMMAND_INPUT.with(|current| *current.borrow_mut() = self.previous.take());
    }
}

pub(crate) fn original_budget() -> Result<DecodeBudget, CliError> {
    COMMAND_INPUT
        .with(|current| {
            current
                .borrow()
                .as_ref()
                .map(|(_, input)| input.decoding.clone())
        })
        .or_else(crucible_session::engine::owned_decode::current_budget)
        .ok_or_else(|| backend_error("command requires its original input metadata authority"))
}

#[derive(Clone)]
pub(crate) struct StandaloneInputResources {
    authority: Arc<dyn StorePhysicalQuotaGuard>,
    pub(crate) decoding: DecodeBudget,
}

impl StandaloneInputResources {
    /// Retains metadata loans from an already admitted namespace authority.
    ///
    /// # Errors
    /// Refuses an unavailable or exhausted original metadata account.
    pub(crate) fn from_authority(
        authority: Arc<dyn StorePhysicalQuotaGuard>,
    ) -> Result<Self, CliError> {
        let decoding =
            DecodeBudget::for_store(Arc::clone(&authority)).map_err(CliError::MetadataAdmission)?;
        Ok(Self {
            authority,
            decoding,
        })
    }

    /// Admits the existing deployed namespace before acquiring input buffers.
    ///
    /// # Errors
    /// Refuses unavailable deployment, mismatched operator quotas, or exhausted
    /// original service and metadata limits.
    pub(crate) fn open(deployment: Option<&Path>) -> Result<Self, CliError> {
        if let Some(resources) = COMMAND_INPUT.with(|current| {
            current
                .borrow()
                .as_ref()
                .filter(|(path, _)| path.as_deref() == deployment)
                .map(|(_, input)| input.clone())
        }) {
            resources
                .decoding
                .check()
                .map_err(CliError::MetadataAdmission)?;
            return Ok(resources);
        }
        #[cfg(test)]
        if deployment.is_none()
            && let Some(resources) = crate::tests::component_input_resources()
        {
            resources
                .decoding
                .check()
                .map_err(CliError::MetadataAdmission)?;
            return Ok(resources);
        }
        let deployment = crate::cli_verify_serve::load_guarded_campaign_deployment(deployment)?;
        let authority = deployment.input_metadata_resources()?;
        let decoding =
            DecodeBudget::for_store(Arc::clone(&authority)).map_err(CliError::MetadataAdmission)?;
        Ok(Self {
            authority,
            decoding,
        })
    }

    /// Shares one original command owner with its nested synchronous readers.
    ///
    /// # Errors
    /// Refuses the original account before copying its deployment path.
    pub(crate) fn install(&self, deployment: Option<&Path>) -> Result<CommandInputOwner, CliError> {
        if let Some(path) = deployment {
            self.decoding
                .charge_bytes(path.as_os_str().len() as u64)
                .map_err(CliError::MetadataAdmission)?;
        }
        let previous = COMMAND_INPUT.with(|current| {
            current.replace(Some((deployment.map(Path::to_path_buf), self.clone())))
        });
        Ok(CommandInputOwner { previous })
    }

    #[cfg(test)]
    pub(crate) fn from_component_scope(
        authority: Arc<dyn StorePhysicalQuotaGuard>,
        decoding: DecodeBudget,
    ) -> Self {
        Self {
            authority,
            decoding,
        }
    }

    /// Reads a stable regular-file extent after admitting its descriptor and bytes.
    ///
    /// # Errors
    /// Refuses missing original capacity, an oversized or changing extent,
    /// allocation failure, or an I/O error.
    pub(crate) fn read(&self, path: &Path) -> Result<Vec<u8>, CliError> {
        read_admitted_input(&self.authority, &self.decoding, path)
    }
}

pub(crate) fn read_admitted_input(
    authority: &Arc<dyn StorePhysicalQuotaGuard>,
    decoding: &DecodeBudget,
    path: &Path,
) -> Result<Vec<u8>, CliError> {
    use std::io::Read;

    let descriptor = authority
        .reserve_resources(1, std::mem::size_of::<std::fs::File>() as u64)
        .map_err(|source| CliError::InputAuthority(Box::new(source)))?;
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(artifact_error("input must be a regular file"));
    }
    let maximum = metadata
        .len()
        .checked_add(1)
        .ok_or_else(|| artifact_error("input size overflow"))?;
    decoding
        .charge_bytes(maximum)
        .map_err(CliError::MetadataAdmission)?;
    let capacity =
        usize::try_from(maximum).map_err(|_| artifact_error("input exceeds host address space"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|error| backend_error(format!("input allocation refused: {error}")))?;
    let mut reader = file.take(maximum);
    reader.read_to_end(&mut bytes)?;
    authority
        .verify()
        .map_err(|source| CliError::InputAuthority(Box::new(source)))?;
    decoding.check().map_err(CliError::MetadataAdmission)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(artifact_error("input changed length while being read"));
    }
    drop(reader);
    drop(descriptor);
    Ok(bytes)
}
