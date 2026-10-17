//! Explicit launch edition for the distinct native positive-work fault fixture.
//!
//! ```json
//! {"schema_version":5,"closed_ingress":false,"progress_endpoint":"/private/progress.sock",
//!  "qualification_refs":[],"bootstrap":{}}
//! ```
//! The abbreviated bootstrap retains the complete original private launch
//! authority. This edition cannot be selected by an ordinary public launch.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use crucible_node_contract::{ContentRef, ContractError, Validate};
use serde::{Deserialize, Serialize};

use super::ReferenceServiceBootstrap;
use crate::ProviderError;

/// Retains the explicit separately measured qualification fixture launch.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceProgressLaunchBootstrap {
    /// Selects exactly private launch edition five.
    pub schema_version: u16,
    /// Selects the closed source or input-capable progress consumer.
    pub closed_ingress: bool,
    /// Names the separate source-owned progress socket created before the child.
    pub progress_endpoint: PathBuf,
    /// Retains exact source-installed evidence without issuing a qualification.
    pub qualification_refs: Vec<ContentRef>,
    /// Retains original private process, world, resources and controller scope.
    pub bootstrap: ReferenceServiceBootstrap,
}

impl Validate for ReferenceProgressLaunchBootstrap {
    fn validate(&self) -> Result<(), ContractError> {
        self.bootstrap.validate()?;
        if self.schema_version != 5
            || !self.progress_endpoint.is_absolute()
            || self.qualification_refs.len() > 16
        {
            return Err(crate::bodies::invalid(
                "progress_launch",
                "invalid explicit native progress launch",
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for reference in &self.qualification_refs {
            reference.validate()?;
            if !seen.insert(reference) {
                return Err(crate::bodies::invalid(
                    "qualification_refs",
                    "duplicate progress source evidence",
                ));
            }
        }
        Ok(())
    }
}

/// Serves the distinct positive-work fixture under privately installed authority.
///
/// Profiles are regenerated from measured provider/device artifacts. The extra
/// stream must be a same-owner socket under the original private launch root;
/// it cannot silently enable behavior in an ordinary provider.
///
/// # Errors
/// Refuses another edition, nonprivate or foreign endpoints, invalid original
/// authority/evidence, profile mismatch or any native service launch failure.
pub fn serve_progress(
    socket: &Path,
    child: &Path,
    launch: ReferenceProgressLaunchBootstrap,
) -> Result<(), ProviderError> {
    launch.validate()?;
    let metadata = std::fs::symlink_metadata(&launch.progress_endpoint)?;
    if !launch.progress_endpoint.is_absolute()
        || launch.progress_endpoint.parent() != socket.parent()
        || !metadata.file_type().is_socket()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != rustix::process::getuid().as_raw()
    {
        return Err(ProviderError::Correlation(
            "progress endpoint is not original private source custody",
        ));
    }
    super::server::serve_bound(
        socket,
        child,
        launch.bootstrap,
        super::server::SourceSelection::Progress {
            closed_ingress: launch.closed_ingress,
            endpoint: launch.progress_endpoint,
        },
        &launch.qualification_refs,
    )
}
