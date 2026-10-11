//! Source-installed fixed ARM root model and private operational launch routes.
//!
//! The constructor measures a compiled installed profile. Caller-selected paths
//! name private operational storage only; they cannot choose guest or model code.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use crucible_node_contract::{ContentRef, Id, U64, canonical};
use serde_json::Value;

use super::arm_root_installed::InstalledArmRootMechanism;
use super::images::{Gem5ImageSource, sealed, validate_private_directory};
use super::{Gem5LaunchArtifact, Gem5ProcessImageTools};
use crate::ProviderError;

/// Retains the source-owned ARM root model and its measured capture machinery.
#[derive(Clone, Debug)]
pub struct ArmRootLaunch {
    pub(crate) owner: Id,
    pub(crate) incarnation: Id,
    pub(crate) generation: U64,
    pub(crate) resource_root: PathBuf,
    pub(crate) timeout: Duration,
    pub(crate) tools: Gem5ProcessImageTools,
    pub(crate) artifacts: BTreeMap<String, Gem5LaunchArtifact>,
    pub(crate) profile: ContentRef,
    pub(crate) metadata: Value,
}

impl ArmRootLaunch {
    /// Measures the compiled fixed model and binds distinct private namespaces.
    ///
    /// This binds launch resources without issuing execution or capture authority.
    /// All directories must already exist with canonical private custody.
    ///
    /// # Errors
    /// Refuses absent or changed installed source, invalid owner fencing, shared
    /// or overlapping routes, occupied namespaces, and unbounded host deadlines.
    pub fn installed(
        owner: Id,
        incarnation: Id,
        generation: U64,
        resource_root: PathBuf,
        image_root: PathBuf,
        temporary_root: PathBuf,
        timeout: Duration,
    ) -> Result<Self, ProviderError> {
        if generation.get() == 0 || timeout.is_zero() || timeout > Duration::from_secs(600) {
            return Err(ProviderError::Frame("ARM root launch fencing or deadline"));
        }
        let roots = [&resource_root, &image_root, &temporary_root];
        for (index, root) in roots.iter().enumerate() {
            validate_private_directory(root)?;
            if fs::read_dir(root)?.next().is_some() {
                return Err(ProviderError::Correlation(
                    "ARM root launch namespace occupied",
                ));
            }
            for other in roots.iter().skip(index + 1) {
                if root.starts_with(other) || other.starts_with(root) {
                    return Err(ProviderError::Correlation(
                        "ARM root launch namespaces overlap",
                    ));
                }
            }
        }
        let installed = InstalledArmRootMechanism::load()?;
        let mut artifacts = BTreeMap::new();
        for role in [
            "native_executable",
            "controller",
            "entrypoint",
            "model",
            "board_model",
            "publication_model",
            "asset_checker",
            "auditor",
            "auditor_core",
            "python",
            "kernel",
            "initramfs",
            "firmware",
            "image_guard",
            "dmtcp_launch",
            "dmtcp_restart",
            "mtcp_restart",
        ] {
            artifacts.insert(role.to_owned(), installed.artifact(role)?);
        }
        let artifact = |role: &str| {
            artifacts.get(role).cloned().ok_or(ProviderError::Frame(
                "installed ARM root capture artifact omitted",
            ))
        };
        let tools = Gem5ProcessImageTools {
            launcher: artifact("dmtcp_launch")?,
            restarter: artifact("dmtcp_restart")?,
            reconstruction_executable: artifact("mtcp_restart")?,
            resource_helper: artifact("image_guard")?,
            image_root,
            temporary_root,
        };
        Ok(Self {
            owner,
            incarnation,
            generation,
            resource_root,
            timeout,
            tools,
            artifacts,
            profile: installed.manifest_content()?,
            metadata: installed.document().clone(),
        })
    }

    /// Returns the original indivisible owner without changing its incarnation.
    pub fn owner(&self) -> &Id {
        &self.owner
    }

    /// Returns the authentic current native incarnation selected at construction.
    pub fn incarnation(&self) -> &Id {
        &self.incarnation
    }

    /// Returns the current strictly fenced native construction generation.
    pub fn generation(&self) -> U64 {
        self.generation
    }

    /// Returns the source-owned model identity; it is not guest readiness evidence.
    pub fn model_id(&self) -> &'static str {
        "arm-linux-vexpress-atomic-root-functional-v1"
    }

    /// Returns the explicit native serial dialect without SE fallback.
    pub fn native_dialect(&self) -> &'static str {
        "crucible.gem5.arm-linux-native/1"
    }

    /// Borrows the complete measured launch-role roster and its portable identities.
    ///
    /// The profile commitment additionally binds source/witness/configuration
    /// records. These inert references never create live native authority.
    pub fn bindings(&self) -> impl ExactSizeIterator<Item = (&str, &ContentRef)> {
        self.artifacts
            .iter()
            .map(|(role, artifact)| (role.as_str(), &artifact.content))
    }

    /// Borrows source-installed model metadata after immutable byte verification.
    ///
    /// Partial diagnostics and hardware/application qualification flags remain
    /// independent from a current complete opaque byte certificate.
    pub fn installed_model(&self) -> &Value {
        &self.metadata
    }

    /// Returns the source-selected immutable profile identity.
    pub fn profile(&self) -> &ContentRef {
        &self.profile
    }

    /// Returns the private modeled resource route for actual supervision.
    pub fn resource_root(&self) -> &Path {
        &self.resource_root
    }

    pub(crate) fn artifact(&self, role: &str) -> Result<&Gem5LaunchArtifact, ProviderError> {
        self.artifacts
            .get(role)
            .ok_or(ProviderError::Frame("ARM root artifact role absent"))
    }

    pub(crate) fn scope(&self) -> Result<crucible_node_contract::HashRef, ProviderError> {
        let artifacts: BTreeMap<_, _> = self
            .artifacts
            .iter()
            .map(|(role, artifact)| (role, &artifact.content))
            .collect();
        Ok(canonical::json_hash(
            "cnp.gem5-arm-root-launch.v1",
            &(
                &self.owner,
                &self.incarnation,
                self.generation,
                &self.profile,
                artifacts,
                &self.metadata["model"],
                &self.metadata["clock"],
                &self.resource_root,
                &self.tools.image_root,
                &self.tools.temporary_root,
            ),
        )?)
    }
}

impl sealed::ImageSource for ArmRootLaunch {}

impl Gem5ImageSource for ArmRootLaunch {
    fn image_tools(&self) -> Option<&Gem5ProcessImageTools> {
        Some(&self.tools)
    }

    fn managed_root(&self) -> &Path {
        &self.resource_root
    }
}
