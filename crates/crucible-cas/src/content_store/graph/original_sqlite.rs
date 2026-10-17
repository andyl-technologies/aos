//! Builds the genuine single-SQLite graph with external original custody.
//!
//! The supervisor prepays the graph's actual containers and shared controls.
//! The owner remains outside those controls, including the administration
//! identity. A supplied quota guard and process heap retain their independent
//! physical and native purposes; this graph constructor issues neither.

use std::alloc::Layout;
use std::path::Path;

use super::*;
use crate::owned_decode::ResourceLoan;

#[cfg(test)]
mod tests;

/// Borrows the exact single-leaf graph configuration.
pub struct OriginalSqliteGraphConfig<'input> {
    /// The validated name of the one SQLite root.
    pub name: &'input str,
    /// The already installed physical catalog namespace.
    pub root: &'input Path,
    /// The immutable object kinds accepted by this repository.
    pub admitted_kinds: &'input [ObjectKind],
    /// The authenticated catalog's native heap entitlement.
    pub maximum_sqlite_heap_bytes: u64,
}

/// Keeps graph credit outside graph, backend and administration controls.
///
/// Callers retire repository users and return the administration owner before
/// closing this owner. Uncertain closure retains its actual owners and credit.
#[must_use = "close graph users and administration before original custody"]
pub struct OriginalSqliteGraphOwner {
    graph: Option<Arc<StoreGraph>>,
    admin: Option<StoreGraphAdmin>,
    identity: Option<Arc<StoreGraphAuthorityIdentity>>,
    backend: Option<Arc<dyn ImmutableBlobBackend>>,
    supervisor: Option<Arc<dyn SqliteCatalogSupervisor>>,
    resources: Option<ResourceLoan>,
    closed: bool,
}

/// Retains graph retirement and its separate catalog completion boundary.
#[derive(Debug, thiserror::Error)]
pub enum OriginalSqliteGraphCloseError {
    /// The same original catalog boundary refused before or after retirement.
    #[error("original graph retirement boundary refused: {source}")]
    Boundary {
        /// Actual original catalog failure with its existing custody.
        #[source]
        source: StoreError,
    },
    /// A graph control remained live before completing the catalog operation.
    #[error("original graph retains a control alias; catalog completion: {completion:?}")]
    Aliases {
        /// Independently retained completion failure after the alias refusal.
        #[source]
        completion: Option<StoreError>,
    },
}

impl OriginalSqliteGraphOwner {
    /// Opens the quota-bound SQLite leaf and its genuine graph administration.
    ///
    /// The supplied guard must authenticate the installed namespace. Graph
    /// containers, canonical scratch and controls are paid before allocation;
    /// SQLite uses the same supplied process heap and catalog supervisor.
    ///
    /// # Errors
    /// Refuses invalid graph input, either original reservation, quota or heap
    /// verification, backend initialization, allocation or original completion.
    pub fn open(
        config: OriginalSqliteGraphConfig<'_>,
        quota: Arc<dyn StorePhysicalQuotaGuard>,
        supervisor: Arc<dyn SqliteCatalogSupervisor>,
        heap: &SqliteProcessHeap,
    ) -> Result<Self, StoreError> {
        let mut owner = Self {
            graph: None,
            admin: None,
            identity: None,
            backend: None,
            supervisor: Some(supervisor),
            resources: None,
            closed: false,
        };
        let supervisor = owner.supervisor.as_ref().ok_or(StoreError::Unavailable)?;
        let operation = supervisor.begin(SqliteCatalogOperationKind::Write)?;
        operation.check()?;
        quota.verify()?;
        heap.verify_live()?;
        validate_name(config.name)?;
        if config.root.as_os_str().len() > MAX_ADMINISTRATIVE_PATH_BYTES {
            return Err(StoreError::Quota);
        }

        // Three retained names belong to the graph root, description and
        // administration map. The fixed description has one allocation.
        let mut bytes = shared_bytes::<StoreGraph>()?
            .checked_add(shared_bytes::<StoreGraphAuthorityIdentity>()?)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<StoreNodeDescription>() as u64))
            .and_then(|bytes| bytes.checked_add(3 * config.name.len() as u64))
            .ok_or(StoreError::Quota)?;
        bytes = bytes
            .checked_add(tree_bytes::<StoreNodeId, StoreGraphPhysicalAuthority>()?)
            .ok_or(StoreError::Quota)?;
        for _ in config.admitted_kinds {
            bytes = bytes
                .checked_add(tree_bytes::<ObjectKind, ()>()?)
                .ok_or(StoreError::Quota)?;
        }
        owner.resources = Some(supervisor.reserve_resident_bytes(bytes)?);

        let mut kinds = BTreeSet::new();
        for kind in config.admitted_kinds {
            if !kinds.insert(*kind) {
                return Err(StoreError::InvalidComposition {
                    reason: "single SQLite graph repeats an admitted kind",
                });
            }
        }
        let configuration =
            configuration_id(config.name, config.root, &kinds, supervisor.as_ref())?;
        operation.check()?;

        let (backend, admin) = SqliteBlobBackend::open_with_physical_quota_and_admin(
            config.name,
            config.root,
            quota,
            config.maximum_sqlite_heap_bytes,
            Arc::clone(supervisor),
            heap,
        )?;
        owner.backend = Some(backend);
        operation.check()?;

        let backend = owner.backend.as_ref().ok_or(StoreError::Unavailable)?;
        owner.identity = Some(Arc::new(StoreGraphAuthorityIdentity));
        let identity = owner.identity.as_ref().ok_or(StoreError::Unavailable)?;
        let mut description = Vec::new();
        description.try_reserve_exact(1).map_err(allocation_error)?;
        description.push(StoreNodeDescription {
            id: StoreNodeId::new(config.name)?,
            kind: StoreNodeKind::Sqlite,
            capabilities: backend.capabilities(),
        });
        let physical = BTreeMap::from([(
            StoreNodeId::new(config.name)?,
            StoreGraphPhysicalAuthority {
                backend: Arc::clone(backend),
                admin,
                retention: BTreeMap::new(),
            },
        )]);
        owner.admin = Some(StoreGraphAdmin {
            configuration,
            authority_identity: Arc::clone(identity),
            physical,
            gc_mark_root: None,
            packed_repack: BTreeMap::new(),
            s3_multipart_cleanup: BTreeMap::new(),
        });
        owner.graph = Some(Arc::new(StoreGraph {
            configuration,
            authority_identity: Arc::clone(identity),
            root_id: StoreNodeId::new(config.name)?,
            admitted_kinds: kinds,
            root: Arc::clone(backend),
            description,
            metrics: BTreeMap::new(),
            write_back: BTreeMap::new(),
            namespace_authorizer: None,
            profile_validation: false,
            _gc_mark_resources: Default::default(),
        }));
        operation.complete()?;
        Ok(owner)
    }

    /// Shares the same graph with the genuine repository owner.
    ///
    /// # Errors
    /// Refuses a closed or partially retired graph owner.
    pub fn graph(&self) -> Result<Arc<StoreGraph>, StoreError> {
        self.graph.as_ref().cloned().ok_or(StoreError::Unavailable)
    }

    /// Moves the one administration capability into the service lifetime.
    ///
    /// # Errors
    /// Refuses repeated transfer or an unavailable original operation.
    pub fn take_admin(&mut self) -> Result<StoreGraphAdmin, StoreError> {
        let supervisor = self.supervisor.as_ref().ok_or(StoreError::Unavailable)?;
        let operation = supervisor.begin(SqliteCatalogOperationKind::Read)?;
        operation.complete()?;
        self.admin.take().ok_or(StoreError::Unavailable)
    }

    /// Physically frees every graph control before returning its original loan.
    ///
    /// # Errors
    /// Refuses an original boundary or any remaining strong or weak graph,
    /// administration identity or backend alias. Partial closure keeps credit.
    pub fn try_close(&mut self) -> Result<(), OriginalSqliteGraphCloseError> {
        if self.closed {
            return Ok(());
        }
        let boundary = |source| OriginalSqliteGraphCloseError::Boundary { source };
        let supervisor = self
            .supervisor
            .as_ref()
            .ok_or_else(|| boundary(StoreError::Unavailable))?;
        let operation = supervisor
            .begin(SqliteCatalogOperationKind::Write)
            .map_err(boundary)?;
        operation.check().map_err(boundary)?;

        // An alias refuses physical retirement, but it does not abandon the
        // actual catalog operation. Complete that same scope before returning
        // either the alias refusal or its independent original postcut.
        let retired = self.release_graph_controls();
        let completion = operation.complete();
        if !retired {
            return Err(OriginalSqliteGraphCloseError::Aliases {
                completion: completion.err(),
            });
        }
        completion.map_err(boundary)?;
        drop(self.resources.take());
        drop(self.supervisor.take());
        self.closed = true;
        Ok(())
    }

    fn release_graph_controls(&mut self) -> bool {
        drop(self.admin.take());
        if let Some(graph) = self.graph.as_mut()
            && Arc::get_mut(graph).is_none()
        {
            return false;
        }
        drop(self.graph.take());
        if let Some(identity) = self.identity.as_mut()
            && Arc::get_mut(identity).is_none()
        {
            return false;
        }
        if let Some(backend) = self.backend.as_mut()
            && Arc::get_mut(backend).is_none()
        {
            return false;
        }
        drop(self.backend.take());
        drop(self.identity.take());
        true
    }
}

impl Drop for OriginalSqliteGraphOwner {
    fn drop(&mut self) {
        if !self.closed {
            // A returned failure, alias or unwind is not physical retirement.
            std::mem::forget(self.admin.take());
            std::mem::forget(self.graph.take());
            std::mem::forget(self.backend.take());
            std::mem::forget(self.identity.take());
            std::mem::forget(self.resources.take());
            std::mem::forget(self.supervisor.take());
        }
    }
}

fn validate_name(name: &str) -> Result<(), StoreError> {
    if name.is_empty()
        || name.len() > MAX_NODE_ID_BYTES
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(StoreError::InvalidComposition {
            reason: "invalid single SQLite graph name",
        });
    }
    Ok(())
}

fn shared_bytes<T>() -> Result<u64, StoreError> {
    Layout::new::<(usize, usize)>()
        .extend(Layout::new::<T>())
        .map(|(layout, _)| layout.pad_to_align().size() as u64)
        .map_err(|_| StoreError::Quota)
}

fn tree_bytes<K, V>() -> Result<u64, StoreError> {
    crate::owned_decode::btree_entry_bytes::<K, V>().map_err(|source| StoreError::DecodeAdmission {
        source,
        custody: None,
    })
}

fn allocation_error(source: std::collections::TryReserveError) -> StoreError {
    StoreError::Allocation {
        source,
        custody: None,
    }
}

fn configuration_id(
    name: &str,
    root: &Path,
    kinds: &BTreeSet<ObjectKind>,
    supervisor: &dyn SqliteCatalogSupervisor,
) -> Result<StoreGraphConfigurationId, StoreError> {
    const MAGIC: &[u8] = b"crucible.content-store.graph-configuration.v13\0";
    let kind_bytes = kinds.iter().try_fold(0_usize, |total, kind| {
        total
            .checked_add(2 + kind.as_str().len())
            .ok_or(StoreError::Quota)
    })?;
    let length = MAGIC
        .len()
        .checked_add(2 + name.len() + 1 + 2 + kind_bytes + 2 + 2 + name.len() + 1 + 4)
        .and_then(|length| length.checked_add(root.as_os_str().len()))
        .ok_or(StoreError::Quota)?;
    let _scratch = supervisor.reserve_resident_bytes(length as u64)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(allocation_error)?;
    bytes.extend_from_slice(MAGIC);
    encode_string(&mut bytes, name.as_bytes())?;
    bytes.push(0);
    bytes.extend_from_slice(
        &u16::try_from(kinds.len())
            .map_err(|_| StoreError::Quota)?
            .to_be_bytes(),
    );
    // Canonical spelling order is independent of ObjectKind's enum order.
    let mut previous: Option<&str> = None;
    for _ in kinds {
        let next = kinds
            .iter()
            .map(|kind| kind.as_str())
            .filter(|name| previous.is_none_or(|previous| *name > previous))
            .min()
            .ok_or(StoreError::Quota)?;
        encode_string(&mut bytes, next.as_bytes())?;
        previous = Some(next);
    }
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    encode_string(&mut bytes, name.as_bytes())?;
    bytes.push(20);
    bytes.extend_from_slice(
        &u32::try_from(root.as_os_str().len())
            .map_err(|_| StoreError::Quota)?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(root.as_os_str().as_bytes());
    if bytes.len() != length {
        return Err(StoreError::Quota);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(GRAPH_CONFIGURATION_ID_DOMAIN.len() as u64).to_be_bytes());
    hasher.update(GRAPH_CONFIGURATION_ID_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(&bytes);
    Ok(StoreGraphConfigurationId(*hasher.finalize().as_bytes()))
}

fn encode_string(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), StoreError> {
    let length = u16::try_from(bytes.len()).map_err(|_| StoreError::Quota)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}
