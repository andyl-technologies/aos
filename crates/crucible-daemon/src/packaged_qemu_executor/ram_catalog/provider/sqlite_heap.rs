//! Transfers the catalog's original native heap to one retained process owner.

use super::*;
use crucible_cas::content_store::{SqliteHeapAuthority, SqliteHeapIssuer, SqliteProcessHeap};
use crucible_cas::owned_decode::ResourceLoan;

pub(super) struct CatalogHeapAuthority {
    resident: HostServiceAllocator,
    metadata: HostServiceAllocator,
    supervisor: HostOperationSupervisor,
    maximum: u64,
    heap: Mutex<Option<HostServiceLease>>,
    _custody: Arc<dyn Send + Sync>,
}

// The original H lease outlives its wrapper allocation and metadata credit.
struct HeapIssuerCredit {
    _leases: crucible_linux_resource::host_services::HostServiceLeasePair,
    _custody: Arc<dyn Send + Sync>,
}

struct HeapCredit {
    _heap: HostServiceLease,
    _metadata: ResourceLoan,
}

impl SqliteHeapAuthority for CatalogHeapAuthority {
    fn verify_live(&self) -> Result<(), StoreError> {
        self.supervisor
            .verify_original_live()
            .map_err(sqlite_supervision_error)
    }

    fn reserve_heap(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify_live()?;
        if bytes != self.maximum {
            return Err(StoreError::Quota);
        }
        let metadata = self.reserve_metadata(arc_allocation_bytes::<HeapCredit>()? as u64)?;
        let heap = self
            .heap
            .lock()
            .map_err(|_| StoreError::Unauthorized)?
            .take()
            .ok_or(StoreError::Unauthorized)?;
        Ok(ResourceLoan::new(HeapCredit {
            _heap: heap,
            _metadata: metadata,
        }))
    }

    fn reserve_metadata(&self, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify_live()?;
        let bytes = bytes
            .checked_add(
                u64::try_from(lease_control_bytes()?)
                    .map_err(|_| StoreError::Quota)?
                    .checked_mul(2)
                    .ok_or(StoreError::Quota)?,
            )
            .ok_or(StoreError::Quota)?;
        reserve_metadata_credit_raw(&self.resident, &self.metadata, bytes)
            .map_err(|_| StoreError::Quota)
    }
}

pub(super) fn install(
    resident: &HostServiceAllocator,
    metadata: &HostServiceAllocator,
    supervisor: &HostOperationSupervisor,
    custody: Arc<dyn Send + Sync>,
    maximum: u64,
    connections: usize,
) -> Result<SqliteProcessHeap, StoreError> {
    supervisor
        .verify_original_live()
        .map_err(sqlite_supervision_error)?;
    let purpose = SqliteHeapIssuer::control_bytes::<CatalogHeapAuthority>()
        .checked_add(
            u64::try_from(lease_control_bytes()?)
                .map_err(|_| StoreError::Quota)?
                .checked_mul(3)
                .ok_or(StoreError::Quota)?,
        )
        .ok_or(StoreError::Quota)?;
    let purpose = purpose
        .checked_add(ResourceLoan::allocation_bytes::<HeapIssuerCredit>())
        .ok_or(StoreError::Quota)?;
    let (metadata_credit, resident_credit) = metadata
        .reserve_paired_bytes(resident, purpose)
        .map_err(|_| StoreError::Quota)?;
    let constructor = ResourceLoan::new(HeapIssuerCredit {
        _leases: crucible_linux_resource::host_services::HostServiceLeasePair::new(
            resident_credit,
            metadata_credit,
        ),
        _custody: custody.clone(),
    });
    // H is a resident purpose, distinct from the metadata partition. It is
    // transferred once; neither the issuer nor its borrowers create a second H.
    let heap = resident
        .reserve_resources(0, 0, maximum)
        .map_err(|_| StoreError::Quota)?;
    let issuer = CatalogHeapAuthority {
        resident: resident.clone(),
        metadata: metadata.clone(),
        supervisor: supervisor.clone(),
        maximum,
        heap: Mutex::new(Some(heap)),
        _custody: custody,
    };
    SqliteProcessHeap::install(
        SqliteHeapIssuer::new(issuer, constructor),
        maximum,
        connections,
    )
}
