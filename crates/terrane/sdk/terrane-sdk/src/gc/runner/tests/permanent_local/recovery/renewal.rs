//! Checks genuine same-holder renewal ACKs against the actual selected chain.

use crate::bucket::held::SingleHeld;
use crate::gc::runner::copied_retirement_tests::support::CopiedFixture;
use std::path::PathBuf;
use terrane_format::gc::GcLease;
use terrane_format::gc::publication::{
    PublicationCommit, PublicationProof, PublicationTransaction,
};
use tokio::sync::mpsc::{UnboundedReceiver, error::TryRecvError};

/// Checks multiple acknowledged lease-only transitions without replacing ownership.
///
/// # Panics
/// Panics on unavailable genuine records, missing ACKs, an unselected slot,
/// changed non-lease state, wrong whole lease or absent same-holder renewal.
pub(super) async fn assert_selected_renewals(
    fixture: &CopiedFixture,
    initial: &GcLease,
    current: &GcLease,
    acknowledgments: &mut UnboundedReceiver<PathBuf>,
) {
    let holder = SingleHeld::acquire(fixture.guard().store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication_unrepaired().await.unwrap();
    let control = fixture.source.parent.join("copied-publication");
    let mut previous = initial.clone();
    let mut count = 0;

    loop {
        let path = match acknowledgments.try_recv() {
            Ok(path) => path,
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => panic!("native lease ACK observer disconnected"),
        };
        let bytes = std::fs::read(&path).unwrap();
        let slot = PublicationCommit::decode(&bytes).unwrap();
        assert!(slot.revision <= observed.stamp().0);
        let selected = observed
            .physical_reads()
            .iter()
            .find(|read| read.path() == path)
            .unwrap();
        assert_eq!(selected.bytes(), Some(bytes.as_slice()));
        let transaction_bytes = std::fs::read(control.join(&slot.transaction_key)).unwrap();
        slot.check_transaction(
            path.strip_prefix(&control).unwrap().to_str().unwrap(),
            &transaction_bytes,
        )
        .unwrap();
        let transaction = PublicationTransaction::decode(&transaction_bytes).unwrap();
        assert_eq!(transaction.proof, PublicationProof::Raw);
        assert_eq!(transaction.changes.len(), 1);
        let change = &transaction.changes[0];
        assert_eq!(change.key, "gc/lease");
        assert_eq!(
            GcLease::decode(change.expected.as_deref().unwrap()).unwrap(),
            previous
        );
        let renewed = GcLease::decode(change.new.as_deref().unwrap()).unwrap();
        assert_eq!(renewed.holder, initial.holder);
        assert_eq!(renewed.epoch, initial.epoch);
        assert!(renewed.expiry > previous.expiry);

        let mut unchanged = transaction.old.clone().unwrap();
        unchanged.revision = transaction.new.revision;
        assert_eq!(transaction.new, unchanged);
        previous = renewed;
        count += 1;
    }

    assert!(
        count > 1,
        "bounded handoffs must renew beyond the entry lease"
    );
    assert_eq!(&previous, current);
    assert_eq!(
        GcLease::decode(observed.logical()["gc/lease"].as_deref().unwrap()).unwrap(),
        *current
    );
}
