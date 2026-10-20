//! Shares immutable Commit and Node DATA during one direct immutable history walk.
//!
//! Every occurrence still validates its own canonical identity and context. The
//! actual original DATA recipes close separately from protected authority inputs;
//! no history or ACL decision can consume this reader before genuine closure.

use super::*;
use crate::bucket::held::HeldBucket;
use crate::bucket::publication::{SelectedObservation, receipts::RecordRead};

pub(super) mod sealed {
    /// Prevents arbitrary data stores from supplying a successful closing check.
    pub trait Sealed {}
}

/// Supplies operation-local Commit and Node DATA with genuine closing checks.
///
/// Only an actual held backend reader implements this sealed private interface.
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
pub(crate) trait DirectNodeReads: ContentStore + BucketBinding + sealed::Sealed {
    /// Binds the data reader to the actual holder used by owning history checks.
    ///
    /// # Errors
    /// Rejects a missing, foreign or substituted physical namespace.
    fn check_holder(
        &self,
        held: &crate::bucket::held::HeldIdentity<'_>,
    ) -> Result<(), StoreFailure>;

    /// Requires the same actual selected observation borrowed by this reader.
    ///
    /// # Errors
    /// Rejects a separately captured, foreign or substituted selection.
    fn check_selection(&self, selected: &SelectedObservation<'_>) -> Result<(), StoreFailure>;

    /// Requires the same genuine direct verification invocation retained by this reader.
    ///
    /// # Errors
    /// Rejects another capture even when its immutable inputs match.
    fn check_direct(
        &self,
        direct: &crate::guard::direct_history::DirectReadCheck,
    ) -> Result<(), StoreFailure>;

    /// Freezes new data reads and returns every actual original payload recipe.
    ///
    /// # Errors
    /// Rejects incomplete, failed, repeated or unavailable closing attempts.
    fn begin_closing(&self) -> Result<Vec<RecordRead>, StoreFailure>;

    /// Completes only the same direct scope after its native physical close.
    ///
    /// # Errors
    /// Refuses substituted scopes, incomplete or repeated closing.
    fn complete_direct_closing(
        &self,
        checked: &crate::guard::direct_history::CheckedDirectHistoryInputs<'_, '_, '_>,
    ) -> Result<(), StoreFailure>;
}

impl<'held, F, C, V, const WRITABLE: bool> HeldBucket<'held, F, C, V, WRITABLE>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Starts data sharing beneath the actual freshly checked held selection.
    ///
    /// # Errors
    /// Refuses unsupported retention, mismatched actual holders, changed selected
    /// authority and every ordinary complete catalog or physical read failure.
    pub(crate) async fn direct_node_reads<'read, 'selection>(
        &'read self,
        selected: &'read SelectedObservation<'selection>,
        direct_check: &crate::guard::direct_history::DirectReadCheck,
    ) -> Result<
        super::immutable_node_reads::HeldImmutableNodeReads<'read, 'selection, F, C, V>,
        StoreFailure,
    > {
        self.immutable_node_reads(
            selected,
            super::immutable_node_reads::ImmutableReadCheck::Direct(direct_check.clone()),
        )
        .await
    }
}
