//! Checked administration of encoded placements in a directory namespace.
//!
//! The actual child fence owns the lock, generation and deletion outcomes.
//! Representation headers replace only logical lengths; they cannot manufacture
//! an inventory namespace or detach the child's original-account receipts.

use super::*;
use crate::owned_decode::DecodeBudget;

pub(super) trait EncodedDirectory {
    fn directory(&self) -> &directory::DirectoryBlobBackend;

    fn initialize(
        &self,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<(), StoreError>;

    fn logical_length(
        &self,
        path: &std::path::Path,
        id: ContentId,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<u64, StoreError>;
}

pub(super) fn acquire<'a, T: EncodedDirectory>(
    backend: &'a T,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<CheckedInventoryFence<'a>, StoreError> {
    let original = batch::account()?;
    checked_reader::check(&original, boundary)?;
    // Admit the wrapper allocation before the child can create or lock files.
    // The external credit survives physical destruction of both fence Boxes.
    let credit = original
        .reserve_scratch_array::<Fence<'_, T>>(1)
        .map_err(|error| batch::admission_under(&original, error))?;
    let operation = original
        .reserve_scratch_bytes(
            directory::DirectoryBlobBackend::quota_resource_costs(backend.directory().root())?
                .operation_bytes,
        )
        .map_err(|error| batch::admission_under(&original, error))?;
    let descriptor = original
        .reserve_descriptors(1)
        .map_err(|error| batch::admission_under(&original, error))?;
    let child = backend.directory().acquire_inventory_fence_initialized(
        original.clone(),
        boundary,
        &mut |check| backend.initialize(check),
    )?;
    // Initialization paths/files close before these temporary credits return.
    drop(descriptor);
    drop(operation);
    Ok(CheckedInventoryFence::new(
        Box::new(Fence {
            child,
            backend,
            original,
            terminal: false,
        }),
        credit,
    ))
}

struct Fence<'a, T> {
    child: CheckedInventoryFence<'a>,
    backend: &'a T,
    original: DecodeBudget,
    terminal: bool,
}

impl<T: EncodedDirectory> Fence<'_, T> {
    fn account(&self) -> Result<DecodeBudget, StoreError> {
        let caller = batch::account()?;
        if !self.original.same_account(&caller) {
            return Err(StoreError::InvalidComposition {
                reason: "encoded inventory fence belongs to another original account",
            });
        }
        if self.terminal {
            return Err(StoreError::Unsupported {
                capability: "failed-encoded-inventory-fence",
            });
        }
        Ok(caller)
    }
}

impl<T: EncodedDirectory> BlobInventoryFence for Fence<'_, T> {
    fn visit_inventory(
        &mut self,
        _visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
    ) -> Result<BlobInventorySummary, StoreError> {
        Err(StoreError::Unsupported {
            capability: "checked-encoded-summary-requires-owning-receipt",
        })
    }

    fn delete_candidate(&mut self, id: ContentId) -> Result<PlannedDeleteDisposition, StoreError> {
        let _entered = self.original.enter();
        let receipt = self.delete_candidates_with_boundary(&[id], &mut || Ok(()))?;
        receipt
            .first()
            .copied()
            .ok_or(StoreError::InvalidComposition {
                reason: "encoded delete returned no disposition",
            })
    }

    fn retain_checked_failure(&mut self, error: StoreError) -> StoreError {
        self.terminal = true;
        self.child.retain_checked_failure(error)
    }

    fn visit_inventory_with_boundary(
        &mut self,
        visitor: &mut dyn FnMut(BlobInventoryRecord) -> Result<(), StoreError>,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<InventorySummaryReceipt, StoreError> {
        let original = self.account()?;
        // Work is terminal unless it reaches a complete normal success. This
        // also seals a panic in our boundary before the child is entered.
        self.terminal = true;
        let result = (|| {
            checked_reader::check(&original, boundary)?;
            // Covers the bounded object path, error path copies and Arc<File>
            // control while the child still retains its own directory cursors.
            let _operation = original
                .reserve_scratch_bytes(
                    directory::DirectoryBlobBackend::quota_resource_costs(
                        self.backend.directory().root(),
                    )?
                    .operation_bytes,
                )
                .map_err(|error| batch::admission_under(&original, error))?;
            let _descriptor = original
                .reserve_descriptors(1)
                .map_err(|error| batch::admission_under(&original, error))?;
            let mut logical_bytes = 0_u64;
            let backend = self.backend;
            let boundary = std::cell::RefCell::new(boundary);
            let receipt = self.child.visit_inventory_with_boundary(
                &mut |record| {
                    let mut check = || checked_reader::check(&original, *boundary.borrow_mut());
                    check()?;
                    let id = record.id();
                    let path = object_path(backend.directory().root(), &original, id)?;
                    let length = backend.logical_length(&path, id, &mut check)?;
                    check()?;
                    logical_bytes = logical_bytes.checked_add(length).ok_or(StoreError::Quota)?;
                    visitor(BlobInventoryRecord::new(id, length))
                },
                &mut || checked_reader::check(&original, *boundary.borrow_mut()),
            )?;
            receipt.with_logical_bytes(logical_bytes)
        })();
        match result {
            Ok(receipt) => {
                self.terminal = false;
                Ok(receipt)
            }
            Err(error) => Err(self.child.retain_checked_failure(error)),
        }
    }

    fn delete_candidates_with_boundary(
        &mut self,
        ids: &[ContentId],
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<DeleteBatchReceipt, StoreError> {
        self.account()?;
        self.terminal = true;
        match self.child.delete_candidates_with_boundary(ids, boundary) {
            Ok(receipt) => {
                self.terminal = false;
                Ok(receipt)
            }
            Err(error) => Err(error),
        }
    }
}

fn object_path(
    root: &std::path::Path,
    original: &DecodeBudget,
    id: ContentId,
) -> Result<std::path::PathBuf, StoreError> {
    let capacity = root
        .as_os_str()
        .len()
        .checked_add(128)
        .ok_or(StoreError::Quota)?;
    let mut path = std::path::PathBuf::new();
    path.try_reserve_exact(capacity)
        .map_err(|error| batch::allocation_under(original, error))?;
    path.push(root);
    path.push("objects");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let first = id.digest()[0];
    let prefix = [HEX[(first >> 4) as usize], HEX[(first & 15) as usize]];
    path.push(std::str::from_utf8(&prefix).map_err(|_| StoreError::InvalidId)?);
    batch::with_id_text(id, |text| {
        path.push(text);
        Ok(path)
    })
}

// Every interrupted header read revisits the original boundary. Header parsing
// remains identical to ordinary inventory, including its corruption result.
pub(super) fn read_header(
    file: &std::fs::File,
    mut bytes: &mut [u8],
    id: ContentId,
    boundary: &mut dyn FnMut() -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    use std::os::unix::fs::FileExt;
    let mut offset = 0_u64;
    while !bytes.is_empty() {
        boundary()?;
        match file.read_at(bytes, offset) {
            Ok(0) => return Err(StoreError::Corrupt { id }),
            Ok(count) => {
                offset += count as u64;
                bytes = &mut bytes[count..];
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(StoreError::Corrupt { id }),
        }
    }
    boundary()
}

#[cfg(test)]
mod tests;
