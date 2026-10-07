//! Prepaid monotone allocation partitions for closed page and tree codecs.
//!
//! One genuine original-child scratch loan funds the exact bounded codec phase.
//! Partition receipts share that loan; they do not request another grant. Root
//! records, generic decoders and backend I/O retain their original accounting.

use std::alloc::Layout;
use std::sync::{Arc, Mutex};

use crate::content_envelope::ContentChild;
use crate::content_store::StoreError;
use crate::owned_decode::{
    DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority, DecodeScratch,
};

use super::RamStoreError;
use super::codec_ownership::{admission, encoded_source_bytes};

/// Bounds allocations before the first owned page/tree codec value is created.
pub(super) struct RecordAllocationPlan {
    partition: u64,
}

impl RecordAllocationPlan {
    pub(super) fn input(
        body_capacity: usize,
        schema: &str,
        child_roles: &[&str],
    ) -> Result<Self, RamStoreError> {
        if child_roles.len() > 2 || body_capacity > 8192 {
            return Err(RamStoreError::Limit("prepaid RAM record"));
        }
        let mut extent = DecodeBudget::allocation_bytes();
        add(&mut extent, body_capacity as u64)?;
        add(&mut extent, schema.len() as u64)?;
        add(
            &mut extent,
            shared_extent::<super::codec_ownership::OwnedEnvelope>()?,
        )?;
        for role in child_roles {
            // This includes the first pinned B-tree leaf, even for one child.
            add(&mut extent, child_node_bytes())?;
            add(&mut extent, role.len() as u64)?;
        }
        add(
            &mut extent,
            receipt_bytes() * (3 + 2 * child_roles.len()) as u64,
        )?;
        Ok(Self { partition: extent })
    }

    pub(super) fn canonical(length: usize) -> Result<Self, RamStoreError> {
        if length > 8192 {
            return Err(RamStoreError::Limit("prepaid RAM record"));
        }
        let mut extent = DecodeBudget::allocation_bytes();
        add(&mut extent, length as u64)?;
        add(&mut extent, encoded_source_bytes())?;
        add(&mut extent, receipt_bytes() * 2)?;
        Ok(Self { partition: extent })
    }

    pub(super) fn read(length: usize, maximum_children: usize) -> Result<Self, RamStoreError> {
        if maximum_children > 2 || length > 8192 {
            return Err(RamStoreError::Limit("prepaid RAM record"));
        }
        let mut extent = DecodeBudget::allocation_bytes();
        // The input has its own temporary original loan. Only the copied body,
        // schema/roles/IDs and decoder's previous child belong to this retained
        // partition; canonical comparison streams without another Vec.
        add(&mut extent, length as u64 + 128)?;
        add(
            &mut extent,
            maximum_children as u64 * (child_node_bytes() + 2 * 256 + 160),
        )?;
        add(
            &mut extent,
            receipt_bytes() * (2 + 4 * maximum_children) as u64,
        )?;
        Ok(Self { partition: extent })
    }
}

// Rust 1.98's B-tree first leaf holds eleven keys, a parent pointer and
// scalar headers. Sixteen full ContentChild slots plus 512 header/alignment
// bytes conservatively cover that allocation, including the first insertion.
// At most two children cannot split a leaf; each insertion is billed separately.
pub(super) fn child_node_bytes() -> u64 {
    (16 * std::mem::size_of::<ContentChild>() + 512) as u64
}

fn receipt_bytes() -> u64 {
    (4 * std::mem::size_of::<Arc<dyn Send + Sync>>()) as u64
}

fn add(total: &mut u64, bytes: u64) -> Result<(), RamStoreError> {
    *total = total
        .checked_add(bytes)
        .ok_or(RamStoreError::Limit("prepaid RAM allocation extent"))?;
    Ok(())
}

pub(super) fn shared_extent<T>() -> Result<u64, RamStoreError> {
    let (layout, _) = Layout::new::<[usize; 2]>()
        .extend(Layout::new::<T>())
        .map_err(|_| RamStoreError::Limit("prepaid RAM control layout"))?;
    Ok(layout.pad_to_align().size() as u64)
}

struct ReservoirOwner {
    original: DecodeBudget,
    // The sole physical loan closes after all original provenance and shared
    // partition borrowers. It never owns the local account, avoiding a cycle.
    _loan: DecodeScratch,
}

struct RecordAuthority {
    issued: Mutex<u64>,
    maximum: u64,
    owner: Arc<ReservoirOwner>,
}

impl DecodeResourceAuthority for RecordAuthority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        self.owner.original.verify_live()
    }

    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.verify_live()?;
        let mut issued = self
            .issued
            .lock()
            .map_err(|_| DecodeAdmissionError::new(StoreError::Quota))?;
        *issued = issued
            .checked_add(bytes)
            .filter(|next| *next <= self.maximum)
            .ok_or_else(|| DecodeAdmissionError::new(StoreError::Quota))?;
        Ok(self.owner.clone())
    }
}

pub(super) struct RecordAccount {
    pub(super) codec: DecodeBudget,
    pub(super) original: DecodeBudget,
}

impl RecordAccount {
    pub(super) fn new(
        original: &DecodeBudget,
        plan: RecordAllocationPlan,
    ) -> Result<Self, RamStoreError> {
        // A newly refused record poisons only this disposable original child.
        // Preexisting parent failure/max still propagate through child().
        let original = original.child().map_err(admission)?;
        Self::phase(&original, plan)
    }

    // Input and canonical phases borrow the same genuine disposable child.
    // Each phase owns a separate whole receipt, so canonical readers cannot
    // extend the input body's lifetime after the final input borrower closes.
    pub(super) fn phase(
        original: &DecodeBudget,
        plan: RecordAllocationPlan,
    ) -> Result<Self, RamStoreError> {
        let control = shared_extent::<ReservoirOwner>()? + shared_extent::<RecordAuthority>()?;
        let total = plan
            .partition
            .checked_add(control)
            .ok_or(RamStoreError::Limit("prepaid RAM allocation extent"))?;
        let loan = original.reserve_scratch_bytes(total).map_err(admission)?;
        let owner = Arc::new(ReservoirOwner {
            original: original.clone(),
            _loan: loan,
        });
        let authority = Arc::new(RecordAuthority {
            issued: Mutex::new(0),
            maximum: plan.partition,
            owner,
        });
        let codec = DecodeBudget::new(authority, plan.partition).map_err(admission)?;
        Ok(Self {
            codec,
            original: original.clone(),
        })
    }
}
