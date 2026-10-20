//! Parks an unfinished selected append in its same prepaid original allocation.
//!
//! This crate-private storage mechanism owns no writer, role, bank, permit or
//! success predicate. Closed C/R owners retain those checks and decide the exact
//! positive disposal frontier. Their explicit Drop parks before role fields are
//! released; the nested guard's Drop also protects unfinished construction.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// Holds one parked body and the original sticky append entry state.
pub(crate) struct SelectedAppendCustodyV1<Body> {
    body: OnceLock<Body>,
    active: AtomicBool,
    closed: AtomicBool,
}

impl<Body> SelectedAppendCustodyV1<Body> {
    /// Constructs empty storage before the actual owner pays for append growth.
    pub(crate) fn new() -> Self {
        Self {
            body: OnceLock::new(),
            active: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    /// Borrows the actual permanently parked body and its stable first cause.
    pub(crate) fn parked_body(&self) -> Option<&Body> {
        self.body.get()
    }

    /// Reports only the original local storage state, without granting entry.
    pub(crate) fn is_idle(&self) -> bool {
        !self.active.load(Ordering::SeqCst) && !self.closed.load(Ordering::SeqCst)
    }

    /// Claims the original once-active slot without resetting sticky refusal.
    pub(crate) fn enter(&self) -> bool {
        if self.closed.load(Ordering::SeqCst)
            || self.active.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err()
        {
            return false;
        }
        true
    }

    /// Records the owner's actual admission failure before any append growth.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    /// Clears activity only at the genuine owner's checked positive boundary.
    pub(crate) fn release_active(&self) {
        self.active.store(false, Ordering::SeqCst);
    }
}

/// Keeps the actual body and its original sink together until disposition.
pub(crate) struct SelectedAppendGuardV1<Body> {
    custody: Arc<SelectedAppendCustodyV1<Body>>,
    body: Option<Body>,
}

impl<Body> SelectedAppendGuardV1<Body> {
    /// Moves the actual body into its already-paid guard without allocation.
    pub(crate) fn new(custody: Arc<SelectedAppendCustodyV1<Body>>, body: Body) -> Self {
        Self { custody, body: Some(body) }
    }

    pub(crate) fn custody(&self) -> &Arc<SelectedAppendCustodyV1<Body>> {
        &self.custody
    }

    pub(crate) fn body(&self) -> Option<&Body> {
        self.body.as_ref()
    }

    pub(crate) fn body_mut(&mut self) -> Option<&mut Body> {
        self.body.as_mut()
    }

    /// Moves positive scratch only after the role owner has checked its posts.
    pub(crate) fn take_body(&mut self) -> Option<Body> {
        self.body.take()
    }

    /// Parks before the enclosing role's fields drop, without allocation or IO.
    pub(crate) fn park_unfinished(&mut self) {
        if let Some(body) = self.body.take() {
            self.custody.closed.store(true, Ordering::SeqCst);
            // Failure is sticky, so this sink never needs healthy clearing.
            // Keep a rejected actual Body resident in its Result until abort.
            let parked = self.custody.body.set(body);
            if parked.is_err() {
                std::process::abort();
            }
        }
    }
}

impl<Body> Drop for SelectedAppendGuardV1<Body> {
    fn drop(&mut self) {
        self.park_unfinished();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct ActualBody {
        bytes: Vec<u8>,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for ActualBody {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn unfinished_drop_parks_actual_backing_and_permanently_refuses_entry() {
        let drops = Arc::new(AtomicUsize::new(0));
        let sink = Arc::new(SelectedAppendCustodyV1::new());
        assert!(sink.enter());
        let bytes = vec![1, 2, 3, 4];
        let pointer = bytes.as_ptr();
        let guard = SelectedAppendGuardV1::new(Arc::clone(&sink), ActualBody {
            bytes, drops: Arc::clone(&drops),
        });

        drop(guard);

        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(sink.is_active());
        assert!(sink.is_closed());
        assert!(!sink.enter());
        assert!(!sink.is_idle());
        assert_eq!(sink.parked_body().unwrap().bytes.as_ptr(), pointer);
        drop(sink);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn explicit_parent_drop_parks_before_its_identity_field_releases() {
        struct IdentityDropProbe {
            sink: Arc<SelectedAppendCustodyV1<Vec<u8>>>,
        }
        impl Drop for IdentityDropProbe {
            fn drop(&mut self) {
                assert!(self.sink.is_closed());
                assert!(self.sink.parked_body().is_some());
            }
        }
        struct RoleCarrier {
            _identity: IdentityDropProbe,
            storage: SelectedAppendGuardV1<Vec<u8>>,
        }
        impl Drop for RoleCarrier {
            fn drop(&mut self) {
                self.storage.park_unfinished();
            }
        }
        let sink = Arc::new(SelectedAppendCustodyV1::new());
        assert!(sink.enter());
        let carrier = RoleCarrier {
            _identity: IdentityDropProbe { sink: Arc::clone(&sink) },
            storage: SelectedAppendGuardV1::new(Arc::clone(&sink), vec![5, 6]),
        };

        drop(carrier);

        assert_eq!(sink.parked_body().map(Vec::as_slice), Some([5, 6].as_slice()));
    }

    #[test]
    fn completed_body_disposes_before_activity_releases_without_parking() {
        let drops = Arc::new(AtomicUsize::new(0));
        let sink = Arc::new(SelectedAppendCustodyV1::new());
        assert!(sink.enter());
        let mut guard = SelectedAppendGuardV1::new(Arc::clone(&sink), ActualBody {
            bytes: vec![7], drops: Arc::clone(&drops),
        });

        let completed = guard.take_body().unwrap();
        drop(completed);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(sink.is_active());
        sink.release_active();
        drop(guard);

        assert!(sink.is_idle());
        assert!(!sink.is_closed());
        assert!(sink.parked_body().is_none());
        assert!(sink.enter());
    }

    #[test]
    fn parked_native_error_has_a_stable_source_after_stage_and_error_arcs_drop() {
        struct NativeFailureBody {
            error: std::io::Error,
            bytes: Vec<u8>,
        }
        let native = std::io::Error::other(std::io::Error::from_raw_os_error(9));
        let source = native.get_ref().unwrap() as *const _;
        let bytes = vec![8, 9];
        let pointer = bytes.as_ptr();
        let sink = Arc::new(SelectedAppendCustodyV1::new());
        assert!(sink.enter());
        let mut stage = SelectedAppendGuardV1::new(Arc::clone(&sink), NativeFailureBody {
            error: native, bytes,
        });
        let returned_error_owner = Arc::clone(&sink);

        stage.park_unfinished();
        drop(stage);
        drop(returned_error_owner);

        let original = sink.parked_body().unwrap();
        assert!(std::ptr::eq(source, original.error.get_ref().unwrap() as *const _));
        assert_eq!(original.bytes.as_ptr(), pointer);
        assert_eq!(original.error.get_ref().unwrap().downcast_ref::<std::io::Error>()
            .unwrap().raw_os_error(), Some(9));
        assert!(!sink.enter());
    }

}

/// Bounds the same selected canonical request, encoder and stage carrier peak.
///
/// Compiled carrier widths describe the actual closed owner; these byte DATA
/// supply no payer, grant, currentness, native constructor or disposition.
pub(crate) fn selected_append_stage_bytes_v1(
    transaction: &aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction,
    appended: u64,
    stage_bytes: usize,
    failure_bytes: usize,
    body_bytes: usize,
    receipt_bytes: usize,
) -> Option<usize> {
    let count = transaction.records().len();
    let records = count.checked_mul(std::mem::size_of::<aos_sandbox_protocol::domain_ledger::transaction::JournalRecord>())?;
    let payload = transaction.records().iter().try_fold(0usize, |sum, record| {
        sum.checked_add(record.key().len())?.checked_add(record.value().map_or(0, <[u8]>::len))
    })?;
    // Retained request copies, live/reallocated encoder buffers, actual stage
    // and negative-return carriers coexist; Arc controls remain byte storage.
    records.checked_add(payload).and_then(|value| value.checked_mul(3))
        .and_then(|value| value.checked_add(usize::try_from(appended).ok()?.checked_mul(3)?))
        .and_then(|value| value.checked_add(stage_bytes.checked_mul(4)?))
        .and_then(|value| value.checked_add(failure_bytes.checked_mul(3)?))
        .and_then(|value| value.checked_add(body_bytes.checked_mul(3)?))
        .and_then(|value| value.checked_add(receipt_bytes.checked_mul(2)?))
        .and_then(|value| value.checked_add(16 * std::mem::size_of::<usize>()))
}

#[cfg(test)]
mod stage_demand_tests {
    use super::*;
    use aos_sandbox_model::RecordNamespace;
    use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};

    #[test]
    fn selected_stage_bound_refuses_overflow_before_any_native_entry() {
        let transaction = JournalTransaction::new([1; 16], vec![JournalRecord::put(
            RecordNamespace::DesiredState, vec![1], vec![2],
        )]).unwrap();
        let encoded = aos_sandbox_protocol::domain_ledger::transaction::encoded_transaction_append_bytes(
            &transaction,
        ).unwrap();

        assert!(selected_append_stage_bytes_v1(&transaction, encoded, 1, 1, 1, 0).is_some());
        assert_eq!(selected_append_stage_bytes_v1(&transaction, encoded, usize::MAX, 1, 1, 0), None);
        assert_eq!(selected_append_stage_bytes_v1(&transaction, encoded, 1, usize::MAX, 1, 0), None);
        assert_eq!(selected_append_stage_bytes_v1(&transaction, encoded, 1, 1, usize::MAX, 0), None);
    }
}
