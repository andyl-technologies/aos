//! Pure exact-argv compilation for a future one-shot OpenZFS helper.
//!
//! This module deliberately does not spawn a process. A future fixed helper
//! must receive one authenticated [`ZfsTransaction`], close inherited descriptors, establish
//! process-tree cancellation, preserve `execve` errors, bound output, execute
//! exactly once, validate the plan's postconditions, and exit. Keeping those
//! unimplemented guarantees out of this library avoids treating an in-process
//! `pre_exec` hook or a parent-only timeout as a privilege boundary.

use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use crate::catalog::{
    CatalogBindingV1, CatalogPlanV1, HoldId, PostconditionPolicyV1, ProjectAncestorPolicyV1,
    ReservationPolicy, ResolvedCatalogCommitmentV1, WorkspaceSpacePolicyV1,
};

const MAXIMUM_EXECUTABLE_BYTES: usize = 4096;

/// Reports an invalid executable contract or unsupported catalog transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ZfsTransactionError {
    /// The configured executable is not a bounded normalized absolute path.
    #[error("one-shot ZFS helper executable path is invalid")]
    InvalidExecutable,
    /// The wire action and resolved catalog plan name different effects.
    #[error("wire storage operation does not match the resolved catalog plan")]
    OperationMismatch,
}

/// Fixes the exact AOS-built executable used by a future one-shot helper.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZfsHelperContract {
    executable: PathBuf,
}

impl ZfsHelperContract {
    /// Validates the immutable absolute path selected by AOS system configuration.
    ///
    /// Path syntax alone does not prove package provenance. The service unit
    /// must supply the exact AOS store object and the helper must verify its
    /// configured identity before `execve`.
    ///
    /// # Errors
    ///
    /// Returns [`ZfsTransactionError::InvalidExecutable`] for a relative,
    /// non-normalized, empty, or oversized path.
    pub fn new(executable: PathBuf) -> Result<Self, ZfsTransactionError> {
        let length = executable.as_os_str().as_encoded_bytes().len();
        let valid = executable.is_absolute()
            && (1..=MAXIMUM_EXECUTABLE_BYTES).contains(&length)
            && executable
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
        if valid {
            Ok(Self { executable })
        } else {
            Err(ZfsTransactionError::InvalidExecutable)
        }
    }

    /// Returns the exact executable path; no `PATH` search is permitted.
    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

/// States an observation that must hold while the catalog lock is held.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ZfsPrecondition {
    /// Requires the exact catalog generation/digest association.
    Catalog(CatalogBindingV1),
    /// Requires a named object to retain its exact nonzero GUID.
    Guid {
        /// Exact node-local ZFS name.
        name: String,
        /// Expected catalogued GUID.
        guid: u64,
    },
    /// Requires an exact durable hold on an exact snapshot GUID.
    ActiveHold {
        /// Exact node-local snapshot name.
        snapshot: String,
        /// Expected snapshot GUID.
        guid: u64,
        /// Required durable hold identity.
        hold_id: HoldId,
    },
    /// Requires a planned destination not to exist.
    Absent {
        /// Exact node-local future name.
        name: String,
    },
}

/// Describes the aggregate project-ancestor update coupled to a child mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AncestorPolicyTransaction {
    precondition: ZfsPrecondition,
    policy: ProjectAncestorPolicyV1,
}

impl AncestorPolicyTransaction {
    /// Returns the exact resolved ancestor and desired aggregate limits.
    #[must_use]
    pub const fn policy(&self) -> &ProjectAncestorPolicyV1 {
        &self.policy
    }

    /// Returns the exact GUID check immediately preceding the update.
    #[must_use]
    pub const fn precondition(&self) -> &ZfsPrecondition {
        &self.precondition
    }

    /// Returns the exact same-GUID quota/count postcondition.
    #[must_use]
    pub const fn postcondition(&self) -> &ProjectAncestorPolicyV1 {
        &self.policy
    }
}

/// Carries a non-runnable, lock-coupled storage transaction program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZfsTransaction {
    preconditions: Vec<ZfsPrecondition>,
    mutation_arguments: Vec<OsString>,
    postcondition: PostconditionPolicyV1,
    ancestor: Option<AncestorPolicyTransaction>,
}

impl ZfsTransaction {
    /// Compiles a fixed OpenZFS transaction from resolved signed semantics.
    ///
    /// This value deliberately exposes no runnable mutation argv. A future
    /// one-shot helper must acquire the protected catalog lock, revalidate all
    /// [`ZfsPrecondition`] values, apply the optional ancestor policy and the
    /// mutation, observe the typed postcondition, and durably update the
    /// catalog before releasing the lock. OpenZFS has no general atomic
    /// GUID-conditioned mutation primitive, so splitting those phases would
    /// reintroduce a name-reuse TOCTOU vulnerability.
    ///
    /// Hold and release are not assumed to be idempotent from exit status. The
    /// future helper must inventory the exact snapshot's holds by GUID and
    /// reconcile the same [`HoldId`] before retrying either operation. Clone
    /// likewise requires proof that its exact `origin_hold` is active before
    /// the mutation.
    ///
    /// # Errors
    ///
    /// Returns [`ZfsTransactionError::OperationMismatch`] when the validated
    /// wire operation does not select the same catalog plan variant or quota.
    pub fn from_catalog(
        operation: crate::StorageOperation,
        catalog: &ResolvedCatalogCommitmentV1,
    ) -> Result<Self, ZfsTransactionError> {
        validate_operation(operation, catalog.plan())?;
        let mutation_arguments = match catalog.plan() {
            CatalogPlanV1::CreateWorkspace {
                destination, space, ..
            } => {
                let mut arguments = vec!["create".into()];
                append_creation_properties(&mut arguments, *space);
                arguments.push(destination.name().into());
                arguments
            }
            CatalogPlanV1::Snapshot { destination, .. } => {
                vec!["snapshot".into(), destination.name().into()]
            }
            CatalogPlanV1::HoldSnapshot { snapshot, hold_id } => vec![
                "hold".into(),
                hold_tag(*hold_id).into(),
                snapshot.name().into(),
            ],
            CatalogPlanV1::ReleaseHold { snapshot, hold_id } => vec![
                "release".into(),
                hold_tag(*hold_id).into(),
                snapshot.name().into(),
            ],
            CatalogPlanV1::Clone {
                source,
                destination,
                space,
                ..
            } => {
                let mut arguments = vec!["clone".into()];
                append_creation_properties(&mut arguments, *space);
                arguments.push(source.name().into());
                arguments.push(destination.name().into());
                arguments
            }
            CatalogPlanV1::SetQuota { dataset, space, .. } => {
                let mut arguments = vec!["set".into()];
                append_space_assignments(&mut arguments, *space);
                arguments.push(dataset.name().into());
                arguments
            }
            CatalogPlanV1::DestroyDataset { dataset } => {
                vec!["destroy".into(), dataset.name().into()]
            }
            CatalogPlanV1::DestroySnapshot { snapshot } => {
                vec!["destroy".into(), snapshot.name().into()]
            }
        };
        let (preconditions, ancestor) = program_guards(catalog);
        Ok(Self {
            preconditions,
            mutation_arguments,
            postcondition: catalog.plan().postcondition(),
            ancestor,
        })
    }

    /// Returns all observations that must be checked under the catalog lock.
    #[must_use]
    pub fn preconditions(&self) -> &[ZfsPrecondition] {
        &self.preconditions
    }

    /// Returns the mandatory typed postcondition.
    #[must_use]
    pub const fn postcondition(&self) -> &PostconditionPolicyV1 {
        &self.postcondition
    }

    /// Returns the coupled aggregate ancestor-policy transaction, when needed.
    #[must_use]
    pub const fn ancestor_transaction(&self) -> Option<&AncestorPolicyTransaction> {
        self.ancestor.as_ref()
    }
}

fn program_guards(
    catalog: &ResolvedCatalogCommitmentV1,
) -> (Vec<ZfsPrecondition>, Option<AncestorPolicyTransaction>) {
    let mut guards = vec![ZfsPrecondition::Catalog(catalog.binding())];
    let ancestor = match catalog.plan() {
        CatalogPlanV1::CreateWorkspace {
            destination,
            ancestor,
            ..
        } => {
            guards.push(ZfsPrecondition::Absent {
                name: destination.name().to_owned(),
            });
            Some(ancestor_transaction(ancestor))
        }
        CatalogPlanV1::Snapshot {
            source,
            destination,
        } => {
            guards.push(ZfsPrecondition::Guid {
                name: source.name().to_owned(),
                guid: source.guid(),
            });
            guards.push(ZfsPrecondition::Absent {
                name: destination.name().to_owned(),
            });
            None
        }
        CatalogPlanV1::HoldSnapshot { snapshot, .. }
        | CatalogPlanV1::DestroySnapshot { snapshot } => {
            guards.push(ZfsPrecondition::Guid {
                name: snapshot.name().to_owned(),
                guid: snapshot.guid(),
            });
            None
        }
        CatalogPlanV1::ReleaseHold { snapshot, hold_id } => {
            guards.push(ZfsPrecondition::Guid {
                name: snapshot.name().to_owned(),
                guid: snapshot.guid(),
            });
            guards.push(ZfsPrecondition::ActiveHold {
                snapshot: snapshot.name().to_owned(),
                guid: snapshot.guid(),
                hold_id: *hold_id,
            });
            None
        }
        CatalogPlanV1::Clone {
            source,
            origin_hold,
            destination,
            ancestor,
            ..
        } => {
            guards.push(ZfsPrecondition::Guid {
                name: source.name().to_owned(),
                guid: source.guid(),
            });
            guards.push(ZfsPrecondition::ActiveHold {
                snapshot: source.name().to_owned(),
                guid: source.guid(),
                hold_id: origin_hold.hold_id(),
            });
            guards.push(ZfsPrecondition::Absent {
                name: destination.name().to_owned(),
            });
            Some(ancestor_transaction(ancestor))
        }
        CatalogPlanV1::SetQuota {
            dataset, ancestor, ..
        } => {
            guards.push(ZfsPrecondition::Guid {
                name: dataset.name().to_owned(),
                guid: dataset.guid(),
            });
            Some(ancestor_transaction(ancestor))
        }
        CatalogPlanV1::DestroyDataset { dataset } => {
            guards.push(ZfsPrecondition::Guid {
                name: dataset.name().to_owned(),
                guid: dataset.guid(),
            });
            None
        }
    };
    (guards, ancestor)
}

fn ancestor_transaction(policy: &ProjectAncestorPolicyV1) -> AncestorPolicyTransaction {
    AncestorPolicyTransaction {
        precondition: ZfsPrecondition::Guid {
            name: policy.dataset().name().to_owned(),
            guid: policy.dataset().guid(),
        },
        policy: policy.clone(),
    }
}

fn validate_operation(
    operation: crate::StorageOperation,
    plan: &CatalogPlanV1,
) -> Result<(), ZfsTransactionError> {
    let matches = match (operation, plan) {
        (
            crate::StorageOperation::CreateWorkspace { quota_bytes },
            CatalogPlanV1::CreateWorkspace { space, .. },
        ) => quota_bytes == space.refquota_bytes(),
        (
            crate::StorageOperation::Snapshot { storage_handle },
            CatalogPlanV1::Snapshot { source, .. },
        ) => storage_handle == source.storage_handle(),
        (
            crate::StorageOperation::HoldSnapshot {
                storage_handle,
                version_handle,
            },
            CatalogPlanV1::HoldSnapshot { snapshot, .. },
        )
        | (
            crate::StorageOperation::ReleaseHold {
                storage_handle,
                version_handle,
            },
            CatalogPlanV1::ReleaseHold { snapshot, .. },
        ) => {
            storage_handle == snapshot.dataset().storage_handle()
                && version_handle == snapshot.version_handle()
        }
        (
            crate::StorageOperation::Clone {
                storage_handle,
                version_handle,
                quota_bytes,
            },
            CatalogPlanV1::Clone { source, space, .. },
        ) => {
            storage_handle == source.dataset().storage_handle()
                && version_handle == source.version_handle()
                && quota_bytes == space.refquota_bytes()
        }
        (
            crate::StorageOperation::SetQuota {
                storage_handle,
                quota_bytes,
            },
            CatalogPlanV1::SetQuota { dataset, space, .. },
        ) => storage_handle == dataset.storage_handle() && quota_bytes == space.refquota_bytes(),
        (
            crate::StorageOperation::Destroy {
                storage_handle,
                version_handle: None,
            },
            CatalogPlanV1::DestroyDataset { dataset },
        ) => storage_handle == dataset.storage_handle(),
        (
            crate::StorageOperation::Destroy {
                storage_handle,
                version_handle,
            },
            CatalogPlanV1::DestroySnapshot { snapshot },
        ) => {
            storage_handle == snapshot.dataset().storage_handle()
                && version_handle == Some(snapshot.version_handle())
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(ZfsTransactionError::OperationMismatch)
    }
}

fn append_creation_properties(arguments: &mut Vec<OsString>, space: WorkspaceSpacePolicyV1) {
    for assignment in ["mountpoint=none".to_owned(), "canmount=off".to_owned()] {
        arguments.push("-o".into());
        arguments.push(assignment.into());
    }
    for assignment in space_assignments(space) {
        arguments.push("-o".into());
        arguments.push(assignment.into());
    }
}

fn append_space_assignments(arguments: &mut Vec<OsString>, space: WorkspaceSpacePolicyV1) {
    arguments.extend(space_assignments(space).into_iter().map(Into::into));
}

fn space_assignments(space: WorkspaceSpacePolicyV1) -> Vec<String> {
    let mut values = vec![format!("refquota={}", space.refquota_bytes())];
    match space.reservation() {
        ReservationPolicy::None => values.push("reservation=none".to_owned()),
        ReservationPolicy::Exact(bytes) => values.push(format!("reservation={bytes}")),
    }
    values
}

fn hold_tag(hold_id: HoldId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut tag = String::with_capacity(36);
    tag.push_str("aos:");
    for byte in hold_id.as_bytes() {
        tag.push(char::from(HEX[usize::from(byte >> 4)]));
        tag.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    tag
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_sandbox_core::ObjectDigest;

    use super::*;
    use crate::catalog::{
        ActiveHoldEvidence, ManagedDatasetRoot, PlannedDataset, ProjectAncestorPolicyV1,
        ResolvedDataset, ResolvedSnapshot, StorageDomainsV1,
    };

    fn root() -> ManagedDatasetRoot {
        ManagedDatasetRoot::from_catalog("tank", "tank/aos", 10).unwrap()
    }

    fn domains() -> StorageDomainsV1 {
        StorageDomainsV1::new(
            ObjectDigest::from_bytes([21; 32]),
            ObjectDigest::from_bytes([22; 32]),
            ObjectDigest::from_bytes([23; 32]),
            ObjectDigest::from_bytes([24; 32]),
        )
        .unwrap()
    }

    fn space() -> WorkspaceSpacePolicyV1 {
        WorkspaceSpacePolicyV1::new(4096, ReservationPolicy::Exact(1024)).unwrap()
    }

    fn ancestor() -> ProjectAncestorPolicyV1 {
        let dataset =
            ResolvedDataset::from_catalog(root(), "tank/aos/project", 15, [9; 32], domains())
                .unwrap();
        ProjectAncestorPolicyV1::new(dataset, 65_536, 8, 16).unwrap()
    }

    fn strings(transaction: &ZfsTransaction) -> Vec<&str> {
        transaction
            .mutation_arguments
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect()
    }

    #[test]
    fn clone_argv_is_exact_and_contains_no_recursive_or_promote_flag() {
        let dataset = ResolvedDataset::from_catalog(
            root(),
            "tank/aos/project/source",
            11,
            [1; 32],
            domains(),
        )
        .unwrap();
        let source = ResolvedSnapshot::from_catalog(dataset, "v1", 12, [2; 32]).unwrap();
        let destination =
            PlannedDataset::from_catalog(root(), "tank/aos/project/clone", domains()).unwrap();
        let catalog = ResolvedCatalogCommitmentV1::new(
            7,
            domains(),
            CatalogPlanV1::Clone {
                source: Box::new(source),
                origin_hold: ActiveHoldEvidence::from_catalog(
                    12,
                    HoldId::from_bytes([31; 16]).unwrap(),
                )
                .unwrap(),
                destination,
                space: space(),
                ancestor: ancestor(),
            },
        )
        .unwrap();
        let transaction = ZfsTransaction::from_catalog(
            crate::StorageOperation::Clone {
                storage_handle: [1; 32],
                version_handle: [2; 32],
                quota_bytes: 4096,
            },
            &catalog,
        )
        .unwrap();
        assert_eq!(
            strings(&transaction),
            [
                "clone",
                "-o",
                "mountpoint=none",
                "-o",
                "canmount=off",
                "-o",
                "refquota=4096",
                "-o",
                "reservation=1024",
                "tank/aos/project/source@v1",
                "tank/aos/project/clone",
            ]
        );
        assert!(transaction.preconditions().iter().any(|guard| matches!(
            guard,
            ZfsPrecondition::ActiveHold { guid: 12, hold_id, .. }
                if *hold_id == HoldId::from_bytes([31; 16]).unwrap()
        )));
        assert_eq!(
            transaction
                .ancestor_transaction()
                .unwrap()
                .postcondition()
                .quota_bytes(),
            65_536
        );
    }

    #[test]
    fn hold_and_release_share_durable_hold_identity_not_operation_id() {
        let dataset =
            ResolvedDataset::from_catalog(root(), "tank/aos/source", 11, [1; 32], domains())
                .unwrap();
        let snapshot = ResolvedSnapshot::from_catalog(dataset, "v1", 12, [2; 32]).unwrap();
        let hold_id = HoldId::from_bytes([0xab; 16]).unwrap();
        for plan in [
            CatalogPlanV1::HoldSnapshot {
                snapshot: snapshot.clone(),
                hold_id,
            },
            CatalogPlanV1::ReleaseHold { snapshot, hold_id },
        ] {
            let operation = match plan {
                CatalogPlanV1::HoldSnapshot { .. } => crate::StorageOperation::HoldSnapshot {
                    storage_handle: [1; 32],
                    version_handle: [2; 32],
                },
                _ => crate::StorageOperation::ReleaseHold {
                    storage_handle: [1; 32],
                    version_handle: [2; 32],
                },
            };
            let catalog = ResolvedCatalogCommitmentV1::new(7, domains(), plan).unwrap();
            let transaction = ZfsTransaction::from_catalog(operation, &catalog).unwrap();
            let arguments = strings(&transaction);
            assert_eq!(arguments[1], "aos:abababababababababababababababab");
        }
    }

    #[test]
    fn operation_and_quota_substitution_fail_closed() {
        let destination =
            PlannedDataset::from_catalog(root(), "tank/aos/project/new", domains()).unwrap();
        let catalog = ResolvedCatalogCommitmentV1::new(
            7,
            domains(),
            CatalogPlanV1::CreateWorkspace {
                destination,
                space: space(),
                ancestor: ancestor(),
            },
        )
        .unwrap();
        assert_eq!(
            ZfsTransaction::from_catalog(
                crate::StorageOperation::CreateWorkspace { quota_bytes: 4097 },
                &catalog,
            ),
            Err(ZfsTransactionError::OperationMismatch)
        );
        assert_eq!(
            ZfsTransaction::from_catalog(
                crate::StorageOperation::Snapshot {
                    storage_handle: [1; 32],
                },
                &catalog,
            ),
            Err(ZfsTransactionError::OperationMismatch)
        );
    }

    #[test]
    fn helper_contract_exposes_no_runnable_mutation() {
        let helper = ZfsHelperContract::new("/nix/store/aos-zfs/sbin/zfs".into()).unwrap();
        assert_eq!(
            helper.executable(),
            Path::new("/nix/store/aos-zfs/sbin/zfs")
        );
        assert!(ZfsHelperContract::new("zfs".into()).is_err());
    }
}
