//! Original maintenance supervision and authenticated mark-storage custody.
//!
//! Mark storage belongs to the caller's admitted catalog namespace. Shared GC
//! traversal polls the same original operation before reading, marking,
//! inventorying, and deleting objects; it never restarts that deadline.

use std::cell::RefCell;
use std::sync::Arc;

use crucible_cas::content_store::{BlobHandle, ImmutableBlobBackend, StoreError, StoreGraphAdmin};
use crucible_cas::owned_decode::{DecodeAdmissionError, DecodeBudget};

/// Original supervision and quota-backed scratch for one GC maintenance scope.
pub struct CampaignGcOperationContext<'a> {
    marks: Arc<dyn ImmutableBlobBackend>,
    original: &'a DecodeBudget,
    boundary: RefCell<&'a mut dyn FnMut() -> Result<(), StoreError>>,
    _resources: crucible_cas::owned_decode::ResourceLoan,
}

impl<'a> CampaignGcOperationContext<'a> {
    /// Binds admitted mark storage and the original finite operation boundary.
    ///
    /// The backend must be isolated scratch opened by the actual catalog owner.
    /// The caller retains its physical namespace and the same unspent decode
    /// account through planning and apply. Account refusal is checked before
    /// invoking the operation boundary or reserving context storage.
    ///
    /// # Errors
    /// Refuses expired supervision, missing original metadata authority, or
    /// insufficient resources for the retained operation context.
    pub fn new(
        marks: Arc<dyn ImmutableBlobBackend>,
        original: &'a DecodeBudget,
        boundary: &'a mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<Self, StoreError> {
        original
            .verify_live()
            .map_err(|error| admission(original, error))?;
        boundary()?;
        original
            .verify_live()
            .map_err(|error| admission(original, error))?;
        let resources = marks.metadata_resources()?.reserve_resources(
            0,
            std::mem::size_of::<Self>() as u64 + 2 * std::mem::size_of::<usize>() as u64,
        )?;
        Ok(Self {
            marks,
            original,
            boundary: RefCell::new(boundary),
            _resources: resources,
        })
    }

    pub(super) fn check(&self) -> Result<(), StoreError> {
        self.original
            .verify_live()
            .map_err(|error| admission(self.original, error))?;
        let mut boundary =
            self.boundary
                .try_borrow_mut()
                .map_err(|_| StoreError::InvalidComposition {
                    reason: "GC operation boundary was reentered",
                })?;
        boundary()?;
        self.original
            .verify_live()
            .map_err(|error| admission(self.original, error))
    }

    pub(super) fn reserve_array<T>(
        &self,
        count: usize,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        let bytes = count
            .checked_mul(std::mem::size_of::<T>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Vec<T>>()))
            .ok_or(StoreError::Quota)?;
        self.reserve_bytes(u64::try_from(bytes).map_err(|_| StoreError::Quota)?)
    }

    pub(super) fn reserve_bytes(
        &self,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        self.reserve_resources(0, bytes)
    }

    pub(super) fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        self.check()?;
        self.marks
            .metadata_resources()?
            .reserve_resources(descriptors, bytes)
    }

    pub(super) fn reserve_root_accumulator(
        &self,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        // Every root can occupy each of four sets. Three complete key/link
        // slots per entry conservatively cover the standard B-tree's partially
        // occupied leaf/internal nodes and allocation headers. Manifest-owned
        // output storage has an independent retained loan.
        let slot = std::mem::size_of::<crucible_cas::content_store::ContentId>()
            + 4 * std::mem::size_of::<usize>();
        let bytes = super::MAX_CAMPAIGN_GC_MANIFEST_ENTRIES
            .checked_mul(4)
            .and_then(|entries| entries.checked_mul(3))
            .and_then(|entries| entries.checked_mul(slot))
            .ok_or(StoreError::Quota)?;
        self.reserve_bytes(u64::try_from(bytes).map_err(|_| StoreError::Quota)?)
    }

    pub(super) fn original(&self) -> &DecodeBudget {
        self.original
    }

    pub(super) fn marks(&self) -> Arc<dyn ImmutableBlobBackend> {
        self.marks.clone()
    }

    pub(super) fn authenticate_handle(&self, handle: &BlobHandle) -> Result<(), StoreError> {
        use std::io::Read;

        let _scratch = self.reserve_bytes(64 * 1024)?;
        let mut reader = handle.open()?;
        let mut bytes = [0_u8; 64 * 1024];
        let mut observed = 0_u64;
        loop {
            self.check()?;
            let count = reader
                .read(&mut bytes)
                .map_err(|source| StoreError::StreamIo {
                    operation: "authenticate GC required placement",
                    source,
                })?;
            if count == 0 {
                self.check()?;
                break;
            }
            observed = observed
                .checked_add(count as u64)
                .ok_or(StoreError::Quota)?;
            if observed > handle.logical_length() {
                return Err(StoreError::InvalidComposition {
                    reason: "GC required placement exceeds its declared length",
                });
            }
        }
        if observed != handle.logical_length() {
            return Err(StoreError::InvalidComposition {
                reason: "GC required placement differs from its declared length",
            });
        }
        Ok(())
    }
}

fn admission(original: &DecodeBudget, source: DecodeAdmissionError) -> StoreError {
    StoreError::DecodeAdmission {
        source,
        custody: Some(original.custody()),
    }
}

/// Physical graph and original operation authority used by production GC.
#[derive(Clone, Copy)]
pub struct CampaignGcMaintenance<'graph, 'operation, 'boundary> {
    pub(super) graph: &'graph StoreGraphAdmin,
    pub(super) operation: &'operation CampaignGcOperationContext<'boundary>,
}

impl<'graph, 'operation, 'boundary> CampaignGcMaintenance<'graph, 'operation, 'boundary> {
    /// Binds the selected physical graph to its original maintenance scope.
    #[must_use]
    pub const fn new(
        graph: &'graph StoreGraphAdmin,
        operation: &'operation CampaignGcOperationContext<'boundary>,
    ) -> Self {
        Self { graph, operation }
    }
}
