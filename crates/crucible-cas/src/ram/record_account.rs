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
    (4 * std::mem::size_of::<crate::owned_decode::ResourceLoan>()) as u64
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

struct RecordAuthority {
    issued: Mutex<u64>,
    maximum: u64,
    original: DecodeBudget,
    owner: crate::owned_decode::ResourceLoan,
}

impl RecordAuthority {
    fn new(original: &DecodeBudget, partition: u64) -> Result<Arc<Self>, RamStoreError> {
        let control = crate::owned_decode::ResourceLoan::allocation_bytes::<DecodeScratch>()
            + shared_extent::<Self>()?;
        let total = partition
            .checked_add(control)
            .ok_or(RamStoreError::Limit("prepaid RAM allocation extent"))?;
        let loan = original.reserve_scratch_bytes(total).map_err(admission)?;
        let owner = crate::owned_decode::ResourceLoan::new(loan);

        Ok(Arc::new(Self {
            issued: Mutex::new(0),
            maximum: partition,
            original: original.clone(),
            owner,
        }))
    }
}

impl DecodeResourceAuthority for RecordAuthority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        self.original.verify_live()
    }

    fn reserve(
        &self,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, DecodeAdmissionError> {
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
        let authority = RecordAuthority::new(original, plan.partition)?;
        let codec = DecodeBudget::new(authority, plan.partition).map_err(admission)?;
        Ok(Self {
            codec,
            original: original.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- finite component tests localize original-account ownership failures.
    #![allow(clippy::unwrap_used)]

    use std::error::Error;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;
    use crate::content_store::test_resources::FixtureResourceBudget;
    use crate::owned_decode::{ResourceLoan, ResourceLoanSlot};

    const MAXIMUM: u64 = 1024 * 1024;

    #[derive(Debug, thiserror::Error)]
    #[error("original record authority is closed")]
    struct OriginalClosed;

    struct Original {
        resources: FixtureResourceBudget,
        calls: AtomicUsize,
        verifications: AtomicUsize,
        closed: AtomicBool,
    }

    impl Original {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                resources: FixtureResourceBudget::new(1, MAXIMUM),
                calls: AtomicUsize::new(0),
                verifications: AtomicUsize::new(0),
                closed: AtomicBool::new(false),
            })
        }

        fn used(&self) -> u64 {
            self.resources.usage().unwrap().1
        }
    }

    impl DecodeResourceAuthority for Original {
        fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
            self.verifications.fetch_add(1, Ordering::SeqCst);
            if self.closed.load(Ordering::SeqCst) {
                return Err(DecodeAdmissionError::new(OriginalClosed));
            }
            Ok(())
        }

        fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
            self.verify_live()?;
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.resources
                .reserve(0, bytes)
                .map_err(DecodeAdmissionError::new)
        }
    }

    #[test]
    fn partition_borrower_keeps_actual_original_account_after_authority_closes() {
        let original = Original::new();
        let budget = DecodeBudget::new(original.clone(), MAXIMUM).unwrap();
        let baseline = original.used();
        let calls = original.calls.load(Ordering::SeqCst);
        let authority = RecordAuthority::new(&budget, 4096).unwrap();
        let control = ResourceLoan::allocation_bytes::<DecodeScratch>()
            + shared_extent::<RecordAuthority>().unwrap();
        assert_eq!(original.used(), baseline + 4096 + control);
        assert_eq!(original.calls.load(Ordering::SeqCst), calls + 1);

        let borrower = authority.reserve(64).unwrap();
        let alias = borrower.clone();
        assert_eq!(original.calls.load(Ordering::SeqCst), calls + 1);
        drop(authority);
        drop(budget);
        assert_eq!(original.used(), baseline + 4096 + control);
        drop(borrower);
        assert_eq!(original.used(), baseline + 4096 + control);
        drop(alias);
        assert_eq!(original.used(), 0);

        assert_eq!(std::mem::size_of::<ResourceLoan>(), 16);
        assert_eq!(std::mem::size_of::<ResourceLoanSlot>(), 16);
        // crucible-lint: allow direct-diagnostic -- records actual target layouts and admitted extents, without a native physical accounting claim.
        eprintln!(
            "record control: scratch={} scratch_arc={} authority={} authority_arc={} combined={control}",
            std::mem::size_of::<DecodeScratch>(),
            ResourceLoan::allocation_bytes::<DecodeScratch>(),
            std::mem::size_of::<RecordAuthority>(),
            shared_extent::<RecordAuthority>().unwrap(),
        );
    }

    #[test]
    fn canceled_original_under_unrelated_scope_refuses_before_partition_issue() {
        let original = Original::new();
        let budget = DecodeBudget::new(original.clone(), MAXIMUM).unwrap();
        let authority = RecordAuthority::new(&budget, 4096).unwrap();
        let unrelated = Original::new();
        let unrelated_budget = DecodeBudget::new(unrelated.clone(), MAXIMUM).unwrap();
        let unrelated_calls = unrelated.calls.load(Ordering::SeqCst);
        let unrelated_checks = unrelated.verifications.load(Ordering::SeqCst);
        let original_calls = original.calls.load(Ordering::SeqCst);
        let original_checks = original.verifications.load(Ordering::SeqCst);
        original.closed.store(true, Ordering::SeqCst);

        let scope = unrelated_budget.enter();
        let error = authority.reserve(64).unwrap_err();
        assert!(
            error
                .source()
                .unwrap()
                .downcast_ref::<OriginalClosed>()
                .is_some()
        );
        assert_eq!(*authority.issued.lock().unwrap(), 0);
        assert_eq!(original.calls.load(Ordering::SeqCst), original_calls);
        assert_eq!(
            original.verifications.load(Ordering::SeqCst),
            original_checks + 1
        );
        assert_eq!(unrelated.calls.load(Ordering::SeqCst), unrelated_calls);
        assert_eq!(
            unrelated.verifications.load(Ordering::SeqCst),
            unrelated_checks
        );
        drop(scope);
        drop(error);
        drop(authority);
        drop(budget);
        assert_eq!(original.used(), 0);
    }
}
