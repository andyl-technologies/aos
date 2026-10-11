//! Inert signed source metadata for the fixed installed ARM root model.
//!
//! Historical routes are lineage data. Reconstruction never reads or recreates
//! those paths; installed assets are measured independently from the compiled
//! package. No source record is a live execution or preparation certificate.
//!
//! The historical envelope binds original identity, installed content and inert
//! route spelling. This schematic excerpt abbreviates the remaining fields:
//!
//! ```text
//! {"schema":"crucible.gem5.arm-root-historical-source.v1","owner":"owner",
//!  "incarnation":"original","generation":"1","profile":{...},
//!  "model_id":"arm-linux-vexpress-atomic-root-functional-v1",
//!  "native_dialect":"crucible.gem5.arm-linux-native/1","bindings":{...},...}
//! ```

use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use crucible_node_contract::{ContentRef, Id, U64, Validate};
use serde::{Deserialize, Serialize};

use super::arm_root_installed::InstalledArmRootMechanism;
use super::{ArmRootLaunch, Gem5LaunchArtifact, Gem5ProcessImageTools};
use crate::ProviderError;

/// Retains a complete inert original source binding beneath an authenticated archive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmRootHistoricalSource {
    /// Selects the distinct fixed ARM root historical source schema.
    pub schema: String,
    /// Retains the authentic original owner.
    pub owner: Id,
    /// Retains the original native incarnation.
    pub incarnation: Id,
    /// Retains the original native fencing generation.
    pub generation: U64,
    /// Pins the source-owned installed model and complete package closure.
    pub profile: ContentRef,
    /// Retains the exact model identity without an SE conversion.
    pub model_id: String,
    /// Retains the exact selected native serial dialect.
    pub native_dialect: String,
    /// Retains every original launch-role content binding.
    pub bindings: BTreeMap<String, ContentRef>,
    /// Retains the vanished original modeled-resource route as inert lineage.
    pub resource_root: PathBuf,
    /// Retains the original capture-image route separately from saved-file lineage.
    pub image_root: PathBuf,
    /// Retains the original private operational route.
    pub temporary_root: PathBuf,
    /// Retains the finite original host transport timeout, never guest time.
    pub timeout_nanoseconds: U64,
}

impl ArmRootLaunch {
    /// Exports source lineage without granting archive or native execution authority.
    ///
    /// # Errors
    /// Refuses an unrepresentable host timeout instead of changing original custody.
    pub fn historical_source(&self) -> Result<ArmRootHistoricalSource, ProviderError> {
        let timeout_nanoseconds = u64::try_from(self.timeout.as_nanos())
            .map_err(|_| ProviderError::Frame("ARM source timeout extent"))?;
        Ok(ArmRootHistoricalSource {
            schema: "crucible.gem5.arm-root-historical-source.v1".to_owned(),
            owner: self.owner.clone(),
            incarnation: self.incarnation.clone(),
            generation: self.generation,
            profile: self.profile.clone(),
            model_id: self.model_id().to_owned(),
            native_dialect: self.native_dialect().to_owned(),
            bindings: self
                .bindings()
                .map(|(role, content)| (role.to_owned(), content.clone()))
                .collect(),
            resource_root: self.resource_root.clone(),
            image_root: self.tools.image_root.clone(),
            temporary_root: self.tools.temporary_root.clone(),
            timeout_nanoseconds: U64::new(timeout_nanoseconds),
        })
    }
}

impl ArmRootHistoricalSource {
    pub(crate) fn installed_source(&self) -> Result<ArmRootLaunch, ProviderError> {
        self.owner.validate()?;
        self.incarnation.validate()?;
        if self.schema != "crucible.gem5.arm-root-historical-source.v1"
            || self.model_id != "arm-linux-vexpress-atomic-root-functional-v1"
            || self.native_dialect != "crucible.gem5.arm-linux-native/1"
            || self.generation.get() == 0
            || self.timeout_nanoseconds.get() == 0
            || self.timeout_nanoseconds.get() > 600_000_000_000
        {
            return Err(ProviderError::Frame("ARM historical source scope differs"));
        }
        let roots = [&self.resource_root, &self.image_root, &self.temporary_root];
        for (index, root) in roots.iter().enumerate() {
            validate_historical_route(root)?;
            for other in roots.iter().skip(index + 1) {
                if root.starts_with(other) || other.starts_with(root) {
                    return Err(ProviderError::Correlation(
                        "ARM historical namespaces overlap",
                    ));
                }
            }
        }
        let installed = InstalledArmRootMechanism::load()?;
        let profile = installed.manifest_content()?;
        if profile != self.profile || self.bindings.len() != 17 {
            return Err(ProviderError::Correlation(
                "ARM historical installed profile differs",
            ));
        }
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
            let artifact = installed.artifact(role)?;
            if self.bindings.get(role) != Some(&artifact.content) {
                return Err(ProviderError::Correlation(
                    "ARM historical artifact binding differs",
                ));
            }
            artifacts.insert(role.to_owned(), artifact);
        }
        let artifact = |role: &str| -> Result<Gem5LaunchArtifact, ProviderError> {
            artifacts
                .get(role)
                .cloned()
                .ok_or(ProviderError::Frame("ARM installed image tool omitted"))
        };
        Ok(ArmRootLaunch {
            owner: self.owner.clone(),
            incarnation: self.incarnation.clone(),
            generation: self.generation,
            resource_root: self.resource_root.clone(),
            timeout: Duration::from_nanos(self.timeout_nanoseconds.get()),
            tools: Gem5ProcessImageTools {
                launcher: artifact("dmtcp_launch")?,
                restarter: artifact("dmtcp_restart")?,
                reconstruction_executable: artifact("mtcp_restart")?,
                resource_helper: artifact("image_guard")?,
                image_root: self.image_root.clone(),
                temporary_root: self.temporary_root.clone(),
            },
            artifacts,
            profile,
            metadata: installed.document().clone(),
        })
    }
}

pub(crate) fn validate_historical_route(path: &Path) -> Result<(), ProviderError> {
    let spelling = path
        .to_str()
        .ok_or(ProviderError::Frame("ARM historical route is not UTF-8"))?;
    let normalized: PathBuf = path.components().collect();
    if normalized.as_os_str() != path.as_os_str()
        || !path.is_absolute()
        || path.parent().is_none()
        || spelling.len() > 4096
        || spelling.contains([':', '\n', '\r', '\0'])
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(ProviderError::Frame(
            "ARM historical route is not a bounded normal lineage path",
        ));
    }
    Ok(())
}

#[cfg(test)]
// crucible-lint: allow rust-allow -- Invalid inert-route fixtures must fail assertions.
// crucible-lint: allow panic-shortcut -- Route fixtures deliberately panic on unexpected admission.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn historical_route_is_inert_bounded_and_mapping_safe() {
        validate_historical_route(Path::new("/removed/original/resources")).unwrap();
        for path in [
            "relative",
            "/",
            "/double//slash",
            "/hidden/./dot",
            "/trailing/",
            "/removed/../escape",
            "/ambiguous:mapping",
            "/line\nbreak",
        ] {
            assert!(
                validate_historical_route(Path::new(path)).is_err(),
                "{path}"
            );
        }
    }
}
