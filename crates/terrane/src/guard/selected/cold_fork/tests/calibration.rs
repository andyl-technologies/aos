//! Checks exact native probe publications before the measured operation begins.
//!
//! All values are observations from actual held selection or the forwarded native
//! executor. These comparisons neither create lineage nor grant publication rights.

use super::{BucketBinding, Clock, Fixture, RecordRead, TestResult, assert_read_unchanged};
use std::collections::BTreeMap;
use terrane_core::{
    bucket::BucketCapabilities,
    gc::publication::{
        PortableCurrent, PortableSnapshot, PredecessorSlot, PublicationCommit, PublicationProof,
        PublicationState,
    },
    identity::Digest,
};

/// Retains a complete independently held selection for a calibration boundary.
pub(super) struct Selection {
    state: PublicationState,
    logical: BTreeMap<String, Option<Vec<u8>>>,
    stamp: (u64, Digest),
    snapshot: PortableCurrent,
    control_identity: (u64, u64),
    reads: Vec<RecordRead>,
}

impl Selection {
    /// Captures actual backend selection and completes its unchanged-read check.
    ///
    /// # Errors
    /// Propagates unavailable or contradictory held publication observations.
    pub(super) async fn capture<C: Clock + BucketBinding + Clone + Sync + 'static>(
        fixture: &Fixture<C>,
    ) -> TestResult<Self> {
        let holder = crate::bucket::held::SingleHeld::acquire(fixture.bucket()).await?;
        let held = holder.destination();
        let observed = held.observe_publication().await?;
        let selection = Self {
            state: observed.state().clone(),
            logical: observed.logical().clone(),
            stamp: observed.stamp(),
            snapshot: observed.snapshot().clone(),
            control_identity: observed.control_identity(),
            reads: observed.physical_reads().to_vec(),
        };
        observed.revalidate().await?;
        Ok(selection)
    }

    /// Checks zero publication or exactly one bound Raw probe timestamp update.
    ///
    /// # Errors
    /// Propagates malformed canonical records or unavailable exact retained reads.
    ///
    /// # Panics
    /// Panics on any additional publication, changed non-probe state or broken
    /// native slot, transaction, snapshot, predecessor or ACK association.
    pub(super) async fn assert_probe_successor<
        C: Clock + BucketBinding + Clone + Sync + 'static,
    >(
        &self,
        fixture: &Fixture<C>,
        after: &Self,
        mutation_start: usize,
    ) -> TestResult {
        assert_eq!(self.control_identity, after.control_identity);
        assert_eq!(self.stamp.0, self.state.revision);
        assert_eq!(after.stamp.0, after.state.revision);
        // Selected slots, transactions, snapshots, registration and ref logs are
        // immutable. The previous observed absent next slot may become present.
        for read in self.reads.iter().filter(|read| read.bytes().is_some()) {
            assert_read_unchanged(&fixture.fs, read).await?;
        }

        let mutations = fixture.fs.mutations();
        let observed = mutations
            .get(mutation_start..)
            .ok_or("calibration mutation observer was reset")?;
        let old_cap = self.capabilities()?;
        let new_cap = after.capabilities()?;
        if old_cap == new_cap {
            assert!(
                observed.is_empty(),
                "unchanged probe published a transaction"
            );
            assert_eq!(after.state, self.state);
            assert_eq!(after.logical, self.logical);
            assert_eq!(after.stamp, self.stamp);
            assert_eq!(after.snapshot, self.snapshot);
            return Ok(());
        }

        let [row] = observed else {
            panic!("changed probe requires exactly one observed native publication");
        };
        assert!(row.acknowledged, "probe successor lacks actual native ACK");
        let transaction = &row.transaction;
        assert_eq!(transaction.encode()?, row.transaction_bytes);
        assert!(matches!(transaction.proof, PublicationProof::Raw));
        assert_eq!(transaction.old.as_ref(), Some(&self.state));
        assert_eq!(transaction.new, after.state);
        assert_eq!(
            transaction.predecessor,
            Some(PredecessorSlot {
                revision: self.stamp.0,
                digest: self.stamp.1,
            })
        );

        let mut expected_state = self.state.clone();
        expected_state.revision = expected_state
            .revision
            .checked_add(1)
            .ok_or("probe revision overflow")?;
        assert_eq!(after.state, expected_state);
        let mut expected_cap = BucketCapabilities::decode(old_cap)?;
        let next_cap = BucketCapabilities::decode(new_cap)?;
        assert_eq!(expected_cap.encode()?.as_slice(), old_cap);
        assert_eq!(next_cap.encode()?.as_slice(), new_cap);
        assert_ne!(expected_cap.probed_at, next_cap.probed_at);
        expected_cap.probed_at = next_cap.probed_at;
        assert_eq!(next_cap, expected_cap);
        let [change] = transaction.changes.as_slice() else {
            panic!("probe successor requires exactly one logical change");
        };
        assert_eq!(change.key, "CAPABILITIES");
        assert_eq!(change.expected.as_deref(), Some(old_cap));
        assert_eq!(change.new.as_deref(), Some(new_cap));
        let mut expected_logical = self.logical.clone();
        expected_logical.insert("CAPABILITIES".into(), Some(new_cap.to_vec()));
        assert_eq!(after.logical, expected_logical);

        let slot = PublicationCommit::decode(&row.slot_bytes)?;
        assert_eq!(slot.encode()?, row.slot_bytes);
        assert_eq!(slot.revision, after.stamp.0);
        assert_eq!(slot.predecessor, Some(self.stamp.1));
        assert_eq!(*blake3::hash(&row.slot_bytes).as_bytes(), after.stamp.1);
        slot.check_transaction(
            &format!("publication/commits/{}", slot.revision),
            &row.transaction_bytes,
        )?;
        transaction.check_key(&slot.transaction_key)?;
        let control = row
            .path
            .ancestors()
            .nth(3)
            .ok_or("actual native slot control")?;
        assert_eq!(
            row.path,
            control.join(format!("publication/commits/{}", after.stamp.0))
        );
        for (path, expected_bytes) in [
            (row.path.clone(), row.slot_bytes.as_slice()),
            (
                control.join(&slot.transaction_key),
                row.transaction_bytes.as_slice(),
            ),
        ] {
            let read = after
                .reads
                .iter()
                .find(|read| read.path() == path)
                .ok_or("actual selected native slot or transaction read")?;
            assert_eq!(read.bytes(), Some(expected_bytes));
            assert_read_unchanged(&fixture.fs, read).await?;
        }
        let old_slot = self
            .reads
            .iter()
            .find(|read| {
                read.path() == control.join(format!("publication/commits/{}", self.stamp.0))
            })
            .and_then(RecordRead::bytes)
            .ok_or("actual prior selected native slot")?;
        assert_eq!(*blake3::hash(old_slot).as_bytes(), self.stamp.1);
        assert_eq!(transaction.snapshot, after.snapshot);
        let snapshot_read = after
            .reads
            .iter()
            .find(|read| read.path() == fixture.bucket().root().join(&after.snapshot.key))
            .ok_or("actual selected portable snapshot read")?;
        let snapshot_bytes = snapshot_read.bytes().ok_or("selected snapshot bytes")?;
        transaction.check_snapshot(snapshot_bytes)?;
        let snapshot = PortableSnapshot::decode(snapshot_bytes)?;
        assert_eq!(snapshot.encode()?.as_slice(), snapshot_bytes);
        if let Some(predecessor) = snapshot.predecessor {
            assert_eq!(predecessor, self.snapshot);
        }
        assert_read_unchanged(&fixture.fs, snapshot_read).await?;
        Ok(())
    }

    fn capabilities(&self) -> TestResult<&[u8]> {
        self.logical
            .get("CAPABILITIES")
            .and_then(Option::as_deref)
            .ok_or_else(|| "actual selected capabilities".into())
    }
}
