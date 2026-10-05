//! Guarded typed inspection over closed or immutable-version External sources.
//!
//! Semantic parsers remain storage-local. Selection and source evidence never
//! grant business authority; actual reads require current independent leases.

pub(crate) mod batch;
#[cfg(target_arch = "wasm32")]
mod runtime;
pub(super) mod selection;
pub(super) mod versioned;
#[cfg(target_arch = "wasm32")]
pub(crate) use runtime::{execute, installed_inventory_mode};
#[cfg(target_arch = "wasm32")]
pub(super) mod absence;

/// Identifies an installed inventory route without granting read authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InventoryDomainMode {
    /// No related installed domain exists; the existing legacy route applies.
    Unconfigured,
    /// An installed domain requires the existing versioned executor.
    Versioned,
    /// An installed domain requires permanent guarded source evidence.
    ProtectedVersionless,
}

/// Preserves retained installed identity before any freshness decision.
///
/// # Errors
/// Refuses a missing, ambiguous or changed installed domain. Unrelated bindings
/// retain their legacy route without acquiring any new authority.
pub(in crate::external_object) fn inventory_domain_mode(
    snapshot: &aos_hub_core::storage_work::StorageBindingSnapshot,
    manages: bool,
    config: Option<&super::copy::config::Config>,
) -> anyhow::Result<InventoryDomainMode> {
    let Some(config) = config else {
        anyhow::ensure!(!manages, "protected inventory copy domain absent");
        return Ok(InventoryDomainMode::Unconfigured);
    };
    let mut candidates = config.domains.iter().filter(|domain| {
        let association = &domain.read_cohort.association;
        association.binding_id.get() == snapshot.binding_id
            || association.binding_stable_id == snapshot.binding_stable_id
    });
    let Some(domain) = candidates.next() else {
        anyhow::ensure!(!manages, "protected inventory binding domain absent");
        return Ok(InventoryDomainMode::Unconfigured);
    };
    anyhow::ensure!(
        candidates.next().is_none(),
        "installed inventory binding domain is ambiguous"
    );
    let association = &domain.read_cohort.association;
    anyhow::ensure!(
        manages
            && association.binding_id.get() == snapshot.binding_id
            && association.binding_stable_id == snapshot.binding_stable_id
            && association.binding_resource_version.get() == snapshot.binding_resource_version
            && association.binding_prefix == snapshot.object_prefix,
        "retained protected inventory domain differs from current physical binding"
    );
    Ok(
        if domain.provider_contract.protected_versionless.is_some() {
            InventoryDomainMode::ProtectedVersionless
        } else {
            InventoryDomainMode::Versioned
        },
    )
}

/// Selects operations whose decoded data outlives provider request permits.
///
/// Stored pairs acquire the same isolate graph-buffer budget themselves.
pub(super) fn needs_graph_buffer(
    operation: &aos_hub_core::storage_work::StorageWorkOperation,
) -> bool {
    use aos_hub_core::storage_work::StorageWorkOperation as Op;
    matches!(
        operation,
        Op::InspectMetadataObjects { .. }
            | Op::InspectGitObject { .. }
            | Op::InspectGitObjects { .. }
            | Op::FilterGitTreeEntries { .. }
            | Op::InspectDocumentation { .. }
            | Op::InspectDocumentationContent { .. }
    )
}

/// Retains the isolate buffer budget through source decoding and projection.
///
/// # Errors
/// Refuses a full wait queue or a failed original-window freshness check.
pub(super) async fn acquire_parser_buffer(
    operation: &aos_hub_core::storage_work::StorageWorkOperation,
    fresh: impl Fn() -> anyhow::Result<()>,
) -> anyhow::Result<Option<crate::mirror_import::buffers::Permit>> {
    if needs_graph_buffer(operation) {
        Ok(Some(
            crate::mirror_import::buffers::acquire(false, fresh).await?,
        ))
    } else {
        Ok(None)
    }
}
