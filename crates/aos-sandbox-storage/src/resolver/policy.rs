//! Protected naming, capacity, and assignment policy for Storage resolution.

use aos_sandbox_core::BrokerAssignment;

use crate::{
    ManagedDatasetRoot, ProjectAncestorPolicyV1, ReservationPolicy, StorageDomainsV1,
    WorkspaceSpacePolicyV1,
};

use super::StorageCatalogResolverErrorV1;

/// Fixes every node-local naming and capacity choice used by the resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedStorageResolverPolicyV1 {
    assignment: BrokerAssignment,
    root: ManagedDatasetRoot,
    domains: StorageDomainsV1,
    project_ancestor: ProjectAncestorPolicyV1,
    maximum_workspace_quota_bytes: u64,
    maximum_workspace_reservation_bytes: u64,
}

impl ProtectedStorageResolverPolicyV1 {
    pub(crate) fn new(
        assignment: BrokerAssignment,
        root: ManagedDatasetRoot,
        domains: StorageDomainsV1,
        project_ancestor: ProjectAncestorPolicyV1,
        maximum_workspace_quota_bytes: u64,
        maximum_workspace_reservation_bytes: u64,
    ) -> Result<Self, StorageCatalogResolverErrorV1> {
        if project_ancestor.dataset().root() != &root
            || project_ancestor.dataset().domains() != domains
            || maximum_workspace_quota_bytes == 0
            || maximum_workspace_quota_bytes > project_ancestor.quota_bytes()
            || maximum_workspace_reservation_bytes > maximum_workspace_quota_bytes
        {
            return Err(StorageCatalogResolverErrorV1::PolicyRejected);
        }
        Ok(Self {
            assignment,
            root,
            domains,
            project_ancestor,
            maximum_workspace_quota_bytes,
            maximum_workspace_reservation_bytes,
        })
    }

    pub(crate) const fn assignment(&self) -> BrokerAssignment {
        self.assignment
    }

    pub(crate) const fn root(&self) -> &ManagedDatasetRoot {
        &self.root
    }

    pub(crate) const fn domains(&self) -> StorageDomainsV1 {
        self.domains
    }

    pub(crate) const fn project_ancestor(&self) -> &ProjectAncestorPolicyV1 {
        &self.project_ancestor
    }

    pub(crate) fn workspace_name(
        &self,
        sandbox_id: &[u8; 16],
    ) -> Result<String, StorageCatalogResolverErrorV1> {
        derived_name(
            self.project_ancestor.dataset().name(),
            "workspace",
            sandbox_id,
        )
    }

    pub(crate) fn snapshot_component(operation_id: &[u8; 16]) -> String {
        let mut component = String::with_capacity(41);
        component.push_str("snapshot-");
        push_hex(&mut component, operation_id);
        component
    }

    pub(crate) fn space(
        &self,
        requested_quota_bytes: u64,
        requested_reservation_bytes: u64,
    ) -> Result<WorkspaceSpacePolicyV1, StorageCatalogResolverErrorV1> {
        if requested_quota_bytes == 0
            || requested_reservation_bytes > requested_quota_bytes
            || (requested_reservation_bytes != 0 && self.maximum_workspace_reservation_bytes == 0)
        {
            return Err(StorageCatalogResolverErrorV1::PolicyRejected);
        }
        let quota = requested_quota_bytes.min(self.maximum_workspace_quota_bytes);
        let reservation = if requested_reservation_bytes == 0 {
            ReservationPolicy::None
        } else {
            ReservationPolicy::Exact(
                requested_reservation_bytes.min(self.maximum_workspace_reservation_bytes),
            )
        };
        WorkspaceSpacePolicyV1::new(quota, reservation)
            .map_err(|_| StorageCatalogResolverErrorV1::PolicyRejected)
    }
}

fn derived_name(
    parent: &str,
    kind: &str,
    identifier: &[u8; 16],
) -> Result<String, StorageCatalogResolverErrorV1> {
    let mut name = String::with_capacity(parent.len() + kind.len() + 35);
    name.push_str(parent);
    name.push('/');
    name.push_str(kind);
    name.push('-');
    push_hex(&mut name, identifier);
    if name.len() > 255 {
        return Err(StorageCatalogResolverErrorV1::PolicyRejected);
    }
    Ok(name)
}

fn push_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}
