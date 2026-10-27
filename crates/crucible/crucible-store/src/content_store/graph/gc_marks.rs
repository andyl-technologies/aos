//! Original quota and allocation custody for the graph's explicit GC-only root.

use super::*;

pub(super) fn instantiate(
    node: StoreNodeId,
    nodes: &BTreeMap<StoreNodeId, StoreNodeSpec>,
    capabilities: &GraphBuildCapabilities<'_>,
    state: &mut GraphBuildState,
) -> Result<GcMarkRootAuthority, StoreError> {
    let Some(StoreNodeSpec::PhysicalQuota {
        child,
        policy,
        project_id,
        maximum_physical_bytes,
        maximum_inodes,
    }) = nodes.get(&node)
    else {
        return Err(invalid_graph(
            node.as_str(),
            GraphViolation::InvalidGcMarkRoot,
        ));
    };
    let Some(StoreNodeSpec::Directory { root }) = nodes.get(child) else {
        return Err(invalid_graph(
            node.as_str(),
            GraphViolation::InvalidGcMarkRoot,
        ));
    };

    let guard = capabilities.physical_quotas.resolve(policy)?.bind(
        root,
        *project_id,
        *maximum_physical_bytes,
        *maximum_inodes,
    )?;
    // The two new build-table entries and their retained description rows use
    // the audited pinned-toolchain B-tree extent. Ordinary graph descriptions
    // and separate GC administration share this credit, never the admin itself.
    let entry_bytes =
        crate::owned_decode::btree_entry_bytes::<StoreNodeId, Arc<dyn ImmutableBlobBackend>>()
            .map_err(|_| StoreError::Quota)?;
    let bookkeeping_bytes = entry_bytes
        .checked_mul(2)
        .and_then(|bytes| {
            bytes.checked_add((2 * std::mem::size_of::<StoreNodeDescription>()) as u64)
        })
        .and_then(|bytes| {
            bytes.checked_add((3 * (node.as_str().len() + child.as_str().len())) as u64)
        })
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<GcMarkRootAuthority>() as u64))
        .ok_or(StoreError::Quota)?;
    let resources = guard.reserve_resources(0, bookkeeping_bytes)?;
    // Borrowed graph inputs must not be copied before original admission. The
    // temporary loan covers constructor arguments and envelopes until the
    // managed pair installs its own retained child/facade credits. An error
    // unwinds the pair before this original construction loan closes.
    let input_bytes = root
        .as_os_str()
        .len()
        .checked_add(node.as_str().len())
        .and_then(|bytes| bytes.checked_mul(2))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<DirectoryBlobBackend>()))
        .and_then(|bytes| bytes.checked_add(super::super::physical_quota::facade_metadata_bytes()))
        .ok_or(StoreError::Quota)?;
    let construction = guard.reserve_resources(0, input_bytes as u64)?;
    let (backend, _admin) = DirectoryBlobBackend::new_with_physical_quota_and_admin(
        node.as_str(),
        root.clone(),
        guard,
    )?;

    // Both descriptions remain visible for deployment and physical census.
    // The quota wrapper retains its child administration internally; neither
    // node contributes campaign blob inventory or required placement roles.
    state.built.insert(child.clone(), Arc::clone(&backend));
    state.built.insert(node.clone(), Arc::clone(&backend));
    drop(construction);
    Ok(GcMarkRootAuthority {
        node,
        backend,
        resources,
    })
}

#[cfg(test)]
mod tests;
