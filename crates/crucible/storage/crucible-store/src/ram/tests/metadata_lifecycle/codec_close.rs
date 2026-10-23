//! Physical shared-codec control closure before its original component refund.
//!
//! Actual allocator samples surround System deallocation. Finite model credit
//! supplies no Main, Source or native execution authority.

use super::*;
use crate::content_envelope::ContentEnvelope;
use crate::owned_decode::{
    DecodeAdmissionError, DecodeResourceAuthority, ResourceLoan, ResourceLoanSlot,
};
use crate::ram::codec::PAGE_SCHEMA;
use crate::ram::codec_ownership::{OwnedBytes, OwnedEnvelope, SharedEnvelope, encoded_source};
use crate::ram::record_account::{RecordAccount, RecordAllocationPlan, RecordAuthority, shared_extent};
use crucible_host_resources::test_support::{
    OriginalControlSelection, OriginalControlSlot, OriginalControlSnapshot,
    OriginalControlsOutcome, OriginalStaticCounters, TestAllocationObserver,
};
use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;

static SELECTED_OUTSTANDING: AtomicU64 = AtomicU64::new(0);
static SELECTED_ISSUED: AtomicU64 = AtomicU64::new(0);
const CEILING: u64 = 64 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("the actual original codec authority is closed")]
struct Closed;

struct Original {
    resources: FixtureResourceBudget,
    closed: AtomicBool,
    revoke_after_whole_loan: bool,
}

struct Credit {
    actual: ResourceLoanSlot,
    bytes: u64,
}

impl Drop for Credit {
    fn drop(&mut self) {
        drop(self.actual.take());
        if self.bytes >= 4096 {
            assert_eq!(SELECTED_OUTSTANDING.swap(0, Ordering::SeqCst), self.bytes);
        }
    }
}

impl DecodeResourceAuthority for Original {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(DecodeAdmissionError::new(Closed));
        }
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify_live()?;
        let actual = self
            .resources
            .reserve(0, bytes)
            .map_err(DecodeAdmissionError::new)?;
        if bytes >= 4096 {
            // Each control owns exactly one whole partition. Initial account
            // grants are smaller; partition receipts clone this same loan.
            assert_eq!(SELECTED_OUTSTANDING.swap(bytes, Ordering::SeqCst), 0);
            assert_eq!(SELECTED_ISSUED.swap(bytes, Ordering::SeqCst), 0);
            self.closed
                .store(self.revoke_after_whole_loan, Ordering::SeqCst);
        }
        Ok(ResourceLoan::new(Credit {
            actual: actual.into(),
            bytes,
        }))
    }
}

fn original(revoke: bool) -> (Arc<Original>, DecodeBudget) {
    SELECTED_OUTSTANDING.store(0, Ordering::SeqCst);
    SELECTED_ISSUED.store(0, Ordering::SeqCst);
    let original = Arc::new(Original {
        resources: FixtureResourceBudget::new(1, CEILING),
        closed: AtomicBool::new(false),
        revoke_after_whole_loan: revoke,
    });
    let budget = DecodeBudget::new(original.clone(), CEILING).unwrap();
    (original, budget)
}

fn assert_paid_close(report: crucible_host_resources::test_support::OriginalControlReport) {
    assert_eq!(report.outcome, OriginalControlsOutcome::Complete);
    let observation = report.controls[0].unwrap();
    let issued = SELECTED_ISSUED.load(Ordering::SeqCst);
    assert!(issued >= 4096);
    assert_eq!(observation.before, OriginalControlSnapshot::U64(issued));
    assert_eq!(
        observation.after,
        Some(OriginalControlSnapshot::U64(issued))
    );
    assert_eq!(SELECTED_OUTSTANDING.load(Ordering::SeqCst), 0);
}

#[test]
fn shared_input_envelope_frees_before_its_original_partition_refund() {
    if sqlite_process::isolated() {
        return;
    }
    let (original, budget) = original(false);
    let baseline = original.resources.usage().unwrap();
    let account = RecordAccount::new(
        &budget,
        RecordAllocationPlan::input(4132, PAGE_SCHEMA, &[]).unwrap(),
    )
    .unwrap();
    account.codec.charge_array::<u8>(4132).unwrap();
    account.codec.charge_array::<u8>(PAGE_SCHEMA.len()).unwrap();
    account
        .codec
        .charge_bytes(shared_extent::<OwnedEnvelope>().unwrap())
        .unwrap();
    let envelope =
        ContentEnvelope::new(PAGE_SCHEMA.to_owned(), 1, BTreeSet::new(), vec![7; 4132]).unwrap();
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::FirstThreadExtent(
                    NonZeroUsize::new(shared_extent::<OwnedEnvelope>().unwrap() as usize).unwrap(),
                ),
                OriginalStaticCounters::U64(&SELECTED_OUTSTANDING),
                true,
            )
            .unwrap();
        let input = SharedEnvelope::new(OwnedEnvelope::new(envelope, &account.codec));
        let alias = input.clone();
        drop(account);
        drop(input);
        assert!(SELECTED_OUTSTANDING.load(Ordering::SeqCst) > 0);
        drop(alias);
    })
    .unwrap();

    assert_paid_close(report);
    assert_eq!(original.resources.usage().unwrap(), baseline);
    drop(budget);
    assert_eq!(original.resources.usage().unwrap(), (0, 0));
}

#[test]
fn shared_canonical_body_frees_before_refund_after_final_checked_reader() {
    if sqlite_process::isolated() {
        return;
    }
    let (original, budget) = original(false);
    let baseline = original.resources.usage().unwrap();
    let account =
        RecordAccount::new(&budget, RecordAllocationPlan::canonical(4179).unwrap()).unwrap();
    account.codec.charge_array::<u8>(4179).unwrap();
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::FirstThreadExtent(
                    NonZeroUsize::new(shared_extent::<OwnedBytes>().unwrap() as usize).unwrap(),
                ),
                OriginalStaticCounters::U64(&SELECTED_OUTSTANDING),
                true,
            )
            .unwrap();
        let source = encoded_source(vec![7; 4179], &account.codec, &account.original).unwrap();
        let alias = source.clone();
        let mut reader =
            crate::content_store::BlobSource::open_with_boundary(&source, &budget, &mut || Ok(()))
                .unwrap();
        drop(account);
        drop(source);
        drop(alias);
        assert!(SELECTED_OUTSTANDING.load(Ordering::SeqCst) > 0);
        let mut bytes = [0; 4179];
        assert_eq!(
            reader
                .read_with_boundary(&mut bytes, &mut || Ok(()))
                .unwrap(),
            bytes.len()
        );
        assert_eq!(bytes, [7; 4179]);
        drop(reader);
    })
    .unwrap();

    assert_paid_close(report);
    assert_eq!(original.resources.usage().unwrap(), baseline);
    drop(budget);
    assert_eq!(original.resources.usage().unwrap(), (0, 0));
}

#[test]
fn refused_codec_constructor_closes_authority_control_before_original_refund() {
    if sqlite_process::isolated() {
        return;
    }
    let (original, budget) = original(true);
    let baseline = original.resources.usage().unwrap();
    let (_, report) = TestAllocationObserver::observe_original_controls(|session| {
        session
            .arm(
                OriginalControlSlot::First,
                OriginalControlSelection::FirstThreadExtent(
                    NonZeroUsize::new(shared_extent::<RecordAuthority>().unwrap() as usize)
                        .unwrap(),
                ),
                OriginalStaticCounters::U64(&SELECTED_OUTSTANDING),
                true,
            )
            .unwrap();
        let error = RecordAccount::new(
            &budget,
            RecordAllocationPlan::input(4132, PAGE_SCHEMA, &[]).unwrap(),
        )
        .err()
        .unwrap();
        let mut source: &(dyn Error + 'static) = &error;
        while !source.is::<Closed>() {
            source = source.source().unwrap();
        }
        assert!(source.is::<Closed>());
        assert!(original.closed.load(Ordering::SeqCst));
    })
    .unwrap();

    assert_paid_close(report);
    assert_eq!(original.resources.usage().unwrap(), baseline);
    drop(budget);
    assert_eq!(original.resources.usage().unwrap(), (0, 0));
}
