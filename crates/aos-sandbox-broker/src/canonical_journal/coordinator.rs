//! Names mechanical operations for the trusted semantic Journal coordinator.
//!
//! Only crate-owned ordinary DATA adapters and genuine closed C/R writers
//! implement these sealed interfaces. Role borrowers never receive this port.
//! The coordinator retains every semantic, financial, fence, final-crossing and
//! postcommit gate at its actual frontier. A mechanical stage proves none of
//! those gates, and there is no native, mutable prefix or raw file projection.

pub(crate) mod selected_append;

/// Owns retained append DATA without a role or mutable native projection.
pub mod retained_data;
mod native_operations;
pub use native_operations::CanonicalWriterNativeOperationsV1;

pub mod indexed_replay;

/// Shares actual ordinary and selected physical replacement mechanics.
pub mod replacement;


mod ordinary;
pub use ordinary::{OrdinaryCoordinatorAppendV1, OrdinaryCoordinatorReadV1};

mod invocation_cursor;
pub use invocation_cursor::CanonicalCoordinatorReadCursorV1;

mod read_view;
pub use read_view::{CanonicalWriterReadViewV1, CanonicalProtectedReadViewV1, CanonicalDirectoryComparisonDataV1};

use std::error::Error;

use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use super::append_stages::CanonicalAppendPublishedDataV1;

// Marker traits have no methods: a hidden supertrait cannot accidentally lend
// a raw mutable prefix through public method resolution.
pub(crate) mod sealed {
    pub trait ReadOwner {}
    pub trait AppendOwner {}
    pub trait AppendData {}
    pub trait NativeOwner {}
}

/// Lends only safe immutable mechanics from the same actual native owner.
///
/// The returned view retains no new grant, budget or semantic admission. It
/// cannot replace the owner's native/index/location fields or expose a file.
/// External types cannot implement this owner interface:
///
/// ```compile_fail
/// use aos_sandbox_broker::canonical_journal::coordinator::{
///     CanonicalCoordinatorReadV1, CanonicalWriterReadViewV1,
/// };
/// struct Forged;
/// impl CanonicalCoordinatorReadV1<()> for Forged {
///     fn coordinator_read_view(&self) -> CanonicalWriterReadViewV1<'_, ()> {
///         panic!("no genuine native owner")
///     }
/// }
/// ```
pub trait CanonicalCoordinatorReadV1<P>: sealed::ReadOwner {
    /// Borrows the actual native/index/location as an opaque readonly view.
    fn coordinator_read_view(&self) -> CanonicalWriterReadViewV1<'_, P>;

    /// Borrows the actual complete materialized map without authenticating it.
    fn state<'owner>(&'owner self) -> &'owner std::collections::BTreeMap<
        (aos_sandbox_core::RecordNamespace, Vec<u8>), Vec<u8>,
    >
    where
        P: 'owner,
    {
        self.coordinator_read_view().state()
    }

    /// Returns the actual native limits as comparison DATA.
    fn limits(&self) -> aos_sandbox_protocol::domain_ledger::transaction::JournalLimits {
        self.coordinator_read_view().limits()
    }

    /// Returns the actual next native sequence as comparison DATA.
    fn next_sequence(&self) -> u64 {
        self.coordinator_read_view().next_sequence()
    }

    /// Reports recorded native uncertainty without asserting positive health.
    fn is_poisoned(&self) -> bool {
        self.coordinator_read_view().is_poisoned()
    }

    /// Borrows the actual native/index historical DATA without a role grant.
    fn historical_view<'owner>(&'owner self)
        -> aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1<'owner>
    where
        P: 'owner,
    {
        self.coordinator_read_view().historical_view()
    }

    /// Observes the original data file at its established metadata frontier.
    ///
    /// # Errors
    /// Returns the actual native IO error without a new health check.
    fn metadata(&self) -> std::io::Result<std::fs::Metadata> {
        self.coordinator_read_view().metadata()
    }

    /// Lends a bounded positional reader over the same actual file.
    fn captured_reader<'owner>(&'owner self, length: u64)
        -> CanonicalCoordinatorReadCursorV1<'owner>
    where
        P: 'owner,
    {
        self.coordinator_read_view().captured_reader(length)
    }
}

/// Borrows reached native stage DATA without constructing or completing a stage.
pub trait CanonicalCoordinatorAppendDataV1: sealed::AppendData {
    /// Borrows the actual transaction retained by this stage, if still resident.
    fn transaction(&self) -> Option<&JournalTransaction>;

    /// Borrows the actual encoder backing without transferring ownership.
    fn encoded_frames(&self) -> Option<&[Vec<u8>]>;

    /// Copies the actual completed native projection as comparison DATA.
    fn projected_materialized_bytes(&self) -> Option<usize>;

    /// Borrows the last record with both native and index application complete.
    fn last_applied_record(&self) -> Option<&JournalRecord>;

    /// Copies actual native publication DATA without issuing a role receipt.
    fn published_coordinates(&self) -> Option<CanonicalAppendPublishedDataV1>;

    /// Borrows the first actual retained native/index/ordering refusal.
    fn failure(&self) -> Option<&(dyn Error + 'static)>;
}

/// Drives native stages around the upper coordinator's sole semantic engine.
///
/// A selected implementation owns its already-paid original copy and parks
/// unfinished stages in that SAME owner's precharged sink. The ordinary DATA
/// adapter borrows the actual input without cloning. The associated lifetime
/// describes only that ordinary input; it never borrows a new payer or writer.
pub trait CanonicalCoordinatorAppendV1<P>:
    CanonicalCoordinatorReadV1<P> + sealed::AppendOwner
{
    /// Keeps the actual closed owner's existing error and native source types.
    type Error: Error + 'static;

    /// Owns or borrows the actual transaction with the same stage disposition.
    type Prepared<'transaction>: CanonicalCoordinatorAppendDataV1;

    /// Permanently records uncertainty in this actual native original.
    ///
    /// This negative-only operation admits no role or new stage and cannot
    /// reset the genuine owner's sticky closure, parked stages or native poison.
    fn poison(&mut self);

    /// Projects then encodes the actual transaction at the existing frontier.
    ///
    /// # Errors
    /// Preserves actual entry/payment failure in the same original. A returned
    /// negative preparation remains resident and must be inspected and retained.
    fn prepare_append_once<'transaction>(
        &mut self,
        transaction: &'transaction JournalTransaction,
    ) -> Result<Self::Prepared<'transaction>, Self::Error>;

    /// Checks frame-count/head arithmetic before expected-length metadata IO.
    ///
    /// # Errors
    /// Retains original arithmetic or foreign/repeated-stage refusal.
    fn append_coordinates_once(
        &self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<(u64, u64), Self::Error>;

    /// Samples expected append length at the original metadata frontier.
    ///
    /// # Errors
    /// Retains actual native metadata/bounds or stage-association refusal.
    fn expected_append_length_once(
        &self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<u64, Self::Error>;

    /// Executes exact append only after the actual upper final crossings.
    ///
    /// # Errors
    /// Retains write/sync/length uncertainty with the same selected original.
    fn append_prepared_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<u64, Self::Error>;

    /// Applies one actual record then its resident index before the next record.
    ///
    /// # Errors
    /// Retains actual native/index or stage-association refusal. Returns false
    /// only after every original record has completed both steps.
    fn apply_next_record_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<bool, Self::Error>;

    /// Publishes actual native bookkeeping and the closed owner's private receipt.
    ///
    /// # Errors
    /// Rejects incomplete/foreign/repeated stages; no supplied coordinates or
    /// successful scalar can construct the owner's private durable receipt.
    fn publish_append_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<CanonicalAppendPublishedDataV1, Self::Error>;

    /// Disposes positive scratch only after the actual upper interval completes.
    ///
    /// # Errors
    /// Refuses a negative, foreign or incomplete stage. Unfinished selected Drop
    /// parks the entire actual stage in its same precharged original sink.
    fn finish_append_after_posts_once(
        &mut self,
        stage: &mut Self::Prepared<'_>,
    ) -> Result<(), Self::Error>;
}

/// Lends legacy native operations only from actual sealed coordinator owners.
///
/// Trusted callers keep their original complete financial, confined-child and
/// semantic gates. Passive read views and role borrowers do not implement it.
pub trait CanonicalCoordinatorNativeV1<P>: CanonicalCoordinatorReadV1<P> + sealed::NativeOwner {
    /// Borrows the SAME native operation port without a raw File/FD projection.
    fn native_operations(&self) -> CanonicalWriterNativeOperationsV1<'_, P>;
}
