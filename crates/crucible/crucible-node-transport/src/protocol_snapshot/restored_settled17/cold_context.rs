//! Joins framed native history with the separately decoded normalization DATA.
//!
//! These exact full-reference comparisons preserve the distinction between
//! historical correspondence and authenticated archive/native model ownership.

use super::*;
use crate::protocol_snapshot::owned11::OriginalOwned11Fields as Fields;
use std::mem::size_of;

impl RestoredSettledNative17Plan<'_> {
    /// Checks the before capacity/fullref and Journal's semantic/Runtime references.
    ///
    /// The caller supplies the actual strictly decoded normalization operands.
    /// This join allocates no replacement body and establishes no signed
    /// Controller/Source lineage, complete native graph or fresh authority.
    ///
    /// # Errors
    /// Refuses malformed or changed full references, or a changed Journal roster.
    pub fn authenticate_semantic_context_data(
        &self,
        native_before: &ContentRef,
        semantic: &ContentRef,
        runtime: &ContentRef,
        maximum_before_capacity: usize,
    ) -> Result<(), ProviderError> {
        if self.snapshot.before().original_capacity() > maximum_before_capacity {
            return Err(invalid());
        }
        restored_settled_native17_reference_matches_data(
            native_before,
            self.snapshot.before().reference_bytes(),
        )?;

        let mut fields = Fields::object(self.journal.objects_bytes())?;
        fields.named("after")?;
        fields.named("anchor")?;
        fields.named("before")?;
        fields.named("control")?;
        fields.named("coordinator_checkpoint")?;
        fields.named("host_protocol")?;
        restored_settled_native17_reference_matches_data(runtime, fields.named("runtime_object")?)?;
        restored_settled_native17_reference_matches_data(semantic, fields.named("semantic")?)?;
        fields.named("snapshot")?;
        fields.finish()?;
        Ok(())
    }

    /// Names the separate fixed context-comparison controls before entry.
    ///
    /// The enclosing original owner funds its guarded loan and framing reader
    /// independently. The defining native counter supplies the complete closed
    /// field/full-reference walkers used by this smaller nonowning join.
    pub fn semantic_context_counter_scratch_data() -> usize {
        restored_settled_native17_counter_scratch_data()
            + size_of::<&Self>()
            + size_of::<&ContentRef>() * 3
            + size_of::<usize>() * 2
            + size_of::<Fields<'static>>()
            + size_of::<Result<Fields<'static>, ProviderError>>()
            + size_of::<&[u8]>()
            + size_of::<Result<&[u8], ProviderError>>()
            + size_of::<Result<(), ProviderError>>() * 4
    }
}
