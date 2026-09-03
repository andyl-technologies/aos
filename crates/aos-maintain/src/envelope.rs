//! Repository-bound envelope for pure Nix maintenance inventory.
//!
//! Pure Nix supplies only package content. The local controller wraps those
//! bytes with the Git, clone, target, and controller identities observed by
//! the maintainer invocation. Dirty content is represented explicitly and can
//! never masquerade as a clean `HEAD` suitable for a write plan.

use std::path::{Component as PathComponent, Path};

use anyhow::{Result, bail};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::MAINTENANCE_INVENTORY_ENVELOPE_V1;
use crate::inventory::MaintenanceInventoryV1;

/// Identifies one exact Git object under the repository's object format.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GitObjectId {
    /// Repository object format used by the hexadecimal value.
    pub algorithm: GitObjectFormat,
    /// Lowercase hexadecimal object identity.
    pub value: String,
}

impl GitObjectId {
    /// Validates the object's algorithm-specific external representation.
    ///
    /// # Errors
    ///
    /// Returns an error unless the value is lowercase hexadecimal with the
    /// exact length selected by the object format.
    pub fn validate(&self) -> Result<()> {
        let length = match self.algorithm {
            GitObjectFormat::Sha1 => 40,
            GitObjectFormat::Sha256 => 64,
        };
        if self.value.len() != length
            || !self
                .value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("Git object identity does not match its declared format");
        }
        Ok(())
    }
}

/// Enumerates Git object formats supported by the maintenance controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitObjectFormat {
    /// Uses the traditional 160-bit Git object format.
    Sha1,
    /// Uses the 256-bit Git object format.
    Sha256,
}

/// Distinguishes a plan-capable clean base from diagnostic dirty content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum RepositoryContent {
    /// Binds inventory to an exact committed tree and permits planning.
    Clean {
        /// Exact commit evaluated by the controller.
        commit: GitObjectId,
        /// Exact root tree referenced by the commit.
        tree: GitObjectId,
    },
    /// Binds inventory to working-tree bytes and forbids planning.
    Dirty {
        /// Current commit used only as diagnostic context.
        head: GitObjectId,
        /// Domain-separated digest of tracked and untracked content state.
        content_digest: Sha256Digest,
    },
}

impl RepositoryContent {
    /// Reports whether the envelope may serve as a write-plan base.
    #[must_use]
    pub const fn permits_write_plan(&self) -> bool {
        matches!(self, Self::Clean { .. })
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Clean { commit, tree } => {
                commit.validate()?;
                tree.validate()?;
                if commit.algorithm != tree.algorithm {
                    bail!("commit and tree use different Git object formats");
                }
            }
            Self::Dirty { head, .. } => head.validate()?,
        }
        Ok(())
    }
}

/// Freezes the local controller and policy interpreting an inventory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ControllerIdentity {
    /// Human-readable AOS CLI version.
    pub version: String,
    /// Exact executable bytes when available from the local process image.
    pub executable_digest: Sha256Digest,
    /// Exact maintenance policy implementation identity.
    pub policy_digest: Sha256Digest,
}

/// Binds one target evaluation to its canonical inventory content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TargetEvaluation {
    /// Explicit Nix platform evaluated by the controller.
    pub target: String,
    /// Digest of the canonical target-specific inventory bytes.
    pub inventory_digest: Sha256Digest,
}

/// Binds maintenance inventory to one exact local repository observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InventoryEnvelopeV1 {
    /// Selects the exact closed envelope schema.
    pub schema: String,
    /// Expected canonical remote without embedded credentials.
    pub canonical_remote: String,
    /// Canonical absolute repository worktree root.
    pub repository_root: String,
    /// Canonical absolute Git common directory distinguishing local clones.
    pub git_common_dir: String,
    /// Exact clean commit/tree or explicit dirty-content identity.
    pub content: RepositoryContent,
    /// Target evaluations in strict target order.
    pub target_evaluations: Vec<TargetEvaluation>,
    /// Canonical digest of the merged inventory value.
    pub inventory_digest: Sha256Digest,
    /// Pure Nix maintenance inventory.
    pub inventory: MaintenanceInventoryV1,
    /// Frozen local controller and policy identity.
    pub controller: ControllerIdentity,
}

impl InventoryEnvelopeV1 {
    /// Validates every repository binding and the embedded inventory digest.
    ///
    /// # Errors
    ///
    /// Returns an error for an incompatible schema, unsafe remote/path,
    /// malformed Git identity, invalid target set, invalid inventory, or
    /// inventory digest mismatch.
    pub fn validate(&self) -> Result<()> {
        if self.schema != MAINTENANCE_INVENTORY_ENVELOPE_V1 {
            bail!("unsupported maintenance inventory envelope schema");
        }
        validate_remote(&self.canonical_remote)?;
        validate_absolute_path(&self.repository_root, "repository root")?;
        validate_absolute_path(&self.git_common_dir, "Git common directory")?;
        self.content.validate()?;
        self.inventory.validate()?;

        if self.target_evaluations.is_empty() || self.target_evaluations.len() > 16 {
            bail!("inventory envelope must contain between 1 and 16 target evaluations");
        }
        for pair in self.target_evaluations.windows(2) {
            if pair[0].target >= pair[1].target {
                bail!("target evaluations must be unique and strictly ordered");
            }
        }
        if self.target_evaluations.iter().any(|evaluation| {
            evaluation.target.is_empty()
                || evaluation.target.len() > 96
                || !evaluation.target.is_ascii()
        }) {
            bail!("inventory envelope contains an invalid target");
        }
        if self.controller.version.is_empty() || self.controller.version.len() > 128 {
            bail!("controller version is empty or oversized");
        }

        let computed =
            Sha256Digest::of_canonical(crate::MAINTENANCE_INVENTORY_V1, &self.inventory)?;
        if computed != self.inventory_digest {
            bail!("maintenance inventory digest mismatch");
        }
        Ok(())
    }
}

fn validate_remote(remote: &str) -> Result<()> {
    if remote.is_empty()
        || remote.len() > 2048
        || remote.bytes().any(|byte| byte.is_ascii_control())
        || remote.contains('@')
        || !(remote.starts_with("https://") || remote.starts_with("ssh://"))
    {
        bail!("canonical remote is empty, unsafe, or unsupported");
    }
    Ok(())
}

fn validate_absolute_path(value: &str, label: &str) -> Result<()> {
    let path = Path::new(value);
    if !path.is_absolute()
        || value.len() > 4096
        || path
            .components()
            .any(|component| matches!(component, PathComponent::ParentDir | PathComponent::CurDir))
    {
        bail!("{label} is not a normalized absolute path");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::identity::{FamilyId, MemberId, UnitId};
    use crate::inventory::{
        Classification, Lifecycle, MaintenanceInventoryV1, RiskLevel, UnitPolicy, UpdateUnit,
    };

    use super::*;

    fn oid(value: char) -> GitObjectId {
        GitObjectId {
            algorithm: GitObjectFormat::Sha1,
            value: value.to_string().repeat(40),
        }
    }

    fn envelope(content: RepositoryContent) -> Result<InventoryEnvelopeV1> {
        let inventory = MaintenanceInventoryV1 {
            schema: crate::MAINTENANCE_INVENTORY_V1.to_string(),
            units: vec![UpdateUnit {
                unit_id: UnitId::parse("local-fixture")?,
                family: FamilyId::parse("local-fixture")?,
                stream: "local".to_string(),
                classification: Classification::Local,
                package: None,
                components: BTreeMap::new(),
                artifacts: BTreeMap::new(),
                owner: "pkgs/test/local-fixture.nix".to_string(),
                members: vec![MemberId::parse("local-fixture")?],
                platforms: vec!["x86_64-linux".to_string()],
                policy: UnitPolicy {
                    lifecycle: Lifecycle::Supported,
                    risk_floor: RiskLevel::Low,
                    successor_unit: None,
                },
                reason: None,
                owner_unit: None,
                owner_member: None,
                review_after: None,
            }],
        };
        let inventory_digest =
            Sha256Digest::of_canonical(crate::MAINTENANCE_INVENTORY_V1, &inventory)?;
        Ok(InventoryEnvelopeV1 {
            schema: MAINTENANCE_INVENTORY_ENVELOPE_V1.to_string(),
            canonical_remote: "https://github.com/andyl-technologies/aos.git".to_string(),
            repository_root: "/source/aos".to_string(),
            git_common_dir: "/source/aos/.git".to_string(),
            content,
            target_evaluations: vec![TargetEvaluation {
                target: "x86_64-linux".to_string(),
                inventory_digest,
            }],
            inventory_digest,
            inventory,
            controller: ControllerIdentity {
                version: "0.1.0".to_string(),
                executable_digest: Sha256Digest::of_bytes("aos"),
                policy_digest: Sha256Digest::of_bytes("policy"),
            },
        })
    }

    #[test]
    fn clean_envelope_validates_and_permits_planning() -> Result<()> {
        let envelope = envelope(RepositoryContent::Clean {
            commit: oid('a'),
            tree: oid('b'),
        })?;
        envelope.validate()?;
        assert!(envelope.content.permits_write_plan());
        Ok(())
    }

    #[test]
    fn dirty_envelope_is_valid_but_cannot_plan() -> Result<()> {
        let envelope = envelope(RepositoryContent::Dirty {
            head: oid('a'),
            content_digest: Sha256Digest::of_bytes("dirty"),
        })?;
        envelope.validate()?;
        assert!(!envelope.content.permits_write_plan());
        Ok(())
    }

    #[test]
    fn envelope_rejects_changed_inventory_and_credentialed_remote() -> Result<()> {
        let mut envelope = envelope(RepositoryContent::Clean {
            commit: oid('a'),
            tree: oid('b'),
        })?;
        envelope.inventory.units[0].stream = "changed".to_string();
        assert!(envelope.validate().is_err());

        envelope.inventory.units[0].stream = "local".to_string();
        envelope.canonical_remote = "https://token@example.invalid/aos.git".to_string();
        assert!(envelope.validate().is_err());
        Ok(())
    }

    #[test]
    fn envelope_rejects_mixed_object_formats() -> Result<()> {
        let mut tree = oid('b');
        tree.algorithm = GitObjectFormat::Sha256;
        tree.value = "b".repeat(64);
        let envelope = envelope(RepositoryContent::Clean {
            commit: oid('a'),
            tree,
        })?;
        assert!(envelope.validate().is_err());
        Ok(())
    }
}
