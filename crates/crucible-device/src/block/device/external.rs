//! External storage-array mutations and rebuild coordination.

use super::*;

impl BlockDevice {
    /// Applies one exact logical write from a multi-device storage frontend.
    ///
    /// The destination uses its own geometry, cache, persistence graph, and
    /// completion-durability policy. This method does not schedule a guest
    /// response; the logical frontend remains the sole response owner.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the range or request geometry is invalid,
    /// the destination cannot admit the bytes, or durability mutation fails.
    pub fn apply_storage_external_write(
        &mut self,
        request_id: u32,
        request_sequence: u64,
        admitted_nanos: u64,
        destination_offset: u64,
        bytes: Vec<u8>,
    ) -> Result<(BlockCompletionDurability, u64), DeviceError> {
        self.storage_faults.apply_external_write(
            &self.base,
            &mut self.overlay,
            request_id,
            request_sequence,
            admitted_nanos,
            destination_offset,
            bytes,
        )
    }

    /// Applies one exact write, discard, or flush from a multi-device frontend.
    ///
    /// The request executes against this device's real cache and durability
    /// continuation but creates no guest completion. The returned dependency
    /// frontier lets the logical frontend delay its sole completion until this
    /// member reaches the required durability stage.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the request is a read or length query, its
    /// range is invalid, or the member cannot admit the requested mutation.
    pub fn apply_storage_external_mutation(
        &mut self,
        request_sequence: u64,
        admitted_nanos: u64,
        request: BlockRequest,
    ) -> Result<(BlockCompletionDurability, u64), DeviceError> {
        self.storage_faults.apply_external_mutation(
            &self.base,
            &mut self.overlay,
            request_sequence,
            admitted_nanos,
            request,
        )
    }

    /// Records logical ranges that an array write could not place on members.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the range is invalid or bounded dirty-range
    /// continuation is exhausted.
    pub fn record_storage_array_dirty_range(
        &mut self,
        member: u16,
        start_byte: u64,
        bytes: Vec<u8>,
        dirty_nanos: u64,
    ) -> Result<(), DeviceError> {
        let mut next = self.storage_faults.clone();
        next.record_array_dirty_range(member, start_byte, bytes, dirty_nanos)?;
        self.storage_faults = next;
        Ok(())
    }

    /// Schedules or returns the next exact array rebuild chunk.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for invalid service parameters or overflow.
    pub fn next_storage_array_rebuild_opportunity(
        &mut self,
        now_nanos: u64,
        chunk_bytes: u64,
        bytes_per_second: u64,
        operations_per_second: Option<u64>,
    ) -> Result<Option<super::super::fault::BlockArrayRebuildOpportunity>, DeviceError> {
        let mut next = self.storage_faults.clone();
        let opportunity = next.next_array_rebuild_opportunity(
            now_nanos,
            chunk_bytes,
            bytes_per_second,
            operations_per_second,
        )?;
        self.storage_faults = next;
        Ok(opportunity)
    }

    /// Acknowledges one exact array rebuild chunk after member commit.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale or no longer
    /// matches the checkpointed dirty bytes.
    pub fn complete_storage_array_rebuild(
        &mut self,
        opportunity: &super::super::fault::BlockArrayRebuildOpportunity,
    ) -> Result<(), DeviceError> {
        self.storage_faults.complete_array_rebuild(opportunity)
    }

    /// Retires a failed rebuild attempt while retaining its exact dirty bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale or no longer
    /// matches the checkpointed scheduler continuation.
    pub fn defer_storage_array_rebuild(
        &mut self,
        opportunity: &super::super::fault::BlockArrayRebuildOpportunity,
    ) -> Result<(), DeviceError> {
        self.storage_faults.defer_array_rebuild(opportunity)
    }

    /// Pauses a rebuild whose member or path is currently unavailable.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the opportunity is stale or no longer
    /// matches the checkpointed scheduler continuation.
    pub fn pause_storage_array_rebuild(
        &mut self,
        now_nanos: u64,
        opportunity: &super::super::fault::BlockArrayRebuildOpportunity,
    ) -> Result<(), DeviceError> {
        self.storage_faults
            .pause_array_rebuild(now_nanos, opportunity)
    }

    /// Resolves the logical bytes produced by a successful external discard.
    ///
    /// `None` means the declared discard semantics preserve the old data.
    /// Undefined data is deterministic and keyed exactly like a local discard.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] unless `request` is a valid, aligned discard in
    /// this device's declared capacity.
    pub fn storage_array_discard_replacement(
        &self,
        request: &BlockRequest,
    ) -> Result<Option<Vec<u8>>, DeviceError> {
        let granularity = u64::from(self.storage_faults.config().discard_granularity_bytes);
        if request.op != BlockOp::Discard
            || granularity == 0
            || request.count == 0
            || !request.offset.is_multiple_of(granularity)
            || !u64::from(request.count).is_multiple_of(granularity)
            || !super::super::fault::request_in_capacity(request, self.length())
        {
            return Err(DeviceError::InvalidBlockFaultDirective {
                reason: "external array discard is unsupported, unaligned, or out of range",
            });
        }
        let count = usize::try_from(request.count).map_err(|_| {
            DeviceError::InvalidBlockFaultDirective {
                reason: "external array discard range does not fit memory",
            }
        })?;
        Ok(match self.storage_faults.config().discard_semantics {
            BlockDiscardSemantics::DeterministicZero => Some(vec![0; count]),
            BlockDiscardSemantics::ReadsOldData => None,
            BlockDiscardSemantics::UndefinedKeyed => {
                Some(keyed_discard_bytes(self.base.hash(), request, count))
            }
        })
    }

    /// Inspects exact currently visible bytes for an externally misdirected read.
    ///
    /// This controller-side inspection does not alter cache replacement state.
    /// The guest request remains owned by its attached device; this method only
    /// supplies the explicitly selected replacement bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the range exceeds the device or cannot be
    /// represented by its admitted storage geometry.
    pub fn inspect_storage_visible(
        &mut self,
        offset: u64,
        count: u32,
    ) -> Result<Vec<u8>, DeviceError> {
        self.storage_faults
            .read_visible(&self.base, &self.overlay, offset, count, false)
    }
}
