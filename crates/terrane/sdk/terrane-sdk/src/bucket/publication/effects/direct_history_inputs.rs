//! Closes one exact direct immutable invocation through shared physical mechanics.

use super::{BucketBinding, LocalFs, SelectedObservation, StoreFailure};
use crate::bucket::held::ImmutableReadCheck;
use crate::bucket::publication::receipts::RecordRead;
use crate::guard::{RetainedControls, direct_history::DirectReadCheck};

/// Retains physical closing for one distinct direct invocation.
pub(crate) struct DirectHistoryPhysicalInputs<'scope, 'held> {
    physical: super::immutable_history_inputs::ImmutableHistoryPhysicalInputs<'scope, 'held>,
}

impl<'scope, 'held> DirectHistoryPhysicalInputs<'scope, 'held> {
    /// Borrows the exact initial selected observation closed by this invocation.
    pub(crate) fn observed(&self) -> &'scope SelectedObservation<'held> {
        self.physical.observed()
    }

    /// Closes every original selected, administrative and DATA recipe.
    ///
    /// # Errors
    /// Refuses changed inputs, missing genuine holds or failed native closure.
    pub(crate) async fn close<F: LocalFs + BucketBinding>(
        fs: &F,
        observed: &'scope SelectedObservation<'held>,
        controls: &[RetainedControls],
        original_reads: &[RecordRead],
        payload_reads: Vec<RecordRead>,
        check: &DirectReadCheck,
    ) -> Result<Self, StoreFailure> {
        let check = ImmutableReadCheck::Direct(check.clone());
        let physical = super::immutable_history_inputs::ImmutableHistoryPhysicalInputs::close(
            fs,
            observed,
            controls,
            original_reads,
            payload_reads,
            &check,
        )
        .await?;
        Ok(Self { physical })
    }
}
