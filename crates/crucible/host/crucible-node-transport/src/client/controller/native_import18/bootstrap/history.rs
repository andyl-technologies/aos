//! Borrows the same constructor row and failed typed fields without effects.
//!
//! These views do not serialize a checkpoint or reconstruct a live owner. The
//! prepared Source Once18 writer independently funds its actual output codec.

use super::*;

/// Borrows the complete saved row, including its actual optional owner relation.
pub struct OriginalNativeImport18BootstrapRowHistoryData<'a> {
    /// Preserves the entire original literal-bank frontier.
    pub frontier: &'a OriginalProtocolStorageFacts,
    /// Preserves both actual original Hello frame commitments.
    pub hello: &'a OriginalHelloFrameDigests,
    /// Borrows the complete opaque producer recipe as inert DATA.
    pub recipe: &'a PacketNativeImport18PrebirthRecipeData,
    /// Borrows all eight original Initial operands, including the actual row.
    pub initial: PacketNativeImport18InitialFundingHistoryData<'a>,
    /// Preserves the exact typed request and request-ID commitment.
    pub input_identity: &'a [u8; 32],
    /// Preserves this constructor's separate retained/transient/fixed axes.
    pub axes: [usize; 3],
    /// Reports absent, same or different actual Controller association.
    pub same_owner_controller: Option<bool>,
}

/// Borrows every actually retained constructor field, including failed inputs.
pub struct OriginalNativeImport18BootstrapHistoryData<'a> {
    /// Names the dedicated bootstrap method independently of old Admit or Begin.
    pub method: Method,
    /// Borrows the exact retained private row as passive DATA.
    pub row: OriginalNativeImport18BootstrapRowHistoryData<'a>,
    /// Borrows the moved request ID without allocating another ID.
    pub request_id: Option<&'a Id>,
    /// Borrows the moved closed request, even when its validation failed.
    pub request: Option<&'a PacketNativeImport18BootstrapRequest>,
    /// Borrows all actual unsigned assignment prefixes after either outcome.
    pub assignment: Option<crate::reference_packet::service::complete_restore::import18::bootstrap_ack::PacketNativeImport18BootstrapAssignmentHistoryData<'a>>,
    /// Reports whether the original operational cut has been retained.
    pub original_cut_retained: bool,
    /// Borrows the exact saved reservation component row, including after refusal.
    pub reservation_row: Option<&'a PacketNativeImport18BootstrapReservationRowData>,
    /// Reports spent reservation entry independently of successful slot creation.
    pub reservation_started: bool,
    /// Preserves an initialized literal slot even when later checks failed.
    pub literal_slot: Option<usize>,
    /// Reports successful reservation without claiming publication or completion.
    pub reserved: bool,
    /// Borrows the exact materialization quote, including after a refused entry.
    pub materialization_row: Option<&'a PacketNativeImport18BootstrapMaterializationRowData>,
    /// Reports spent materialization entry independently of its surviving outputs.
    pub materialization_started: bool,
    /// Borrows the moved assignment, proof, DOM and literal after either outcome.
    pub sealing: Option<crate::reference_packet::service::complete_restore::import18::bootstrap_ack::PacketNativeImport18BootstrapSealingHistoryData<'a>>,
    /// Reports only successful typed-owner retention, never bootstrap completion.
    pub retained: bool,
    /// Preserves a spent/refused constructor independently of retained inputs.
    pub failed: bool,
}

impl OriginalNativeImport18BootstrapConstructionData {
    /// Lends this actual row and its relation to the same bank's optional owner.
    ///
    /// # Errors
    /// Refuses foreign creator origin or preserves the passive callback refusal.
    pub fn with_row_history_data<R>(
        &self,
        owner: Option<&OriginalNativeImport18Bootstrap>,
        inspect: impl for<'view> FnOnce(
            OriginalNativeImport18BootstrapRowHistoryData<'view>,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.controller.ensure_current()?;
        let result = inspect(row_history_data(self, owner));
        self.controller.ensure_current()?;
        result
    }

    /// Names actual passive row views and both callback result controls.
    pub fn row_history_counter_scratch_data<R>() -> usize {
        size_of::<&Self>()
            + size_of::<Option<&OriginalNativeImport18Bootstrap>>()
            + size_of::<OriginalNativeImport18BootstrapRowHistoryData<'static>>()
            + size_of::<PacketNativeImport18InitialFundingHistoryData<'static>>()
            + size_of::<Option<bool>>()
            + size_of::<R>()
            + size_of::<Result<R, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<std::thread::Thread>()
            + size_of::<std::thread::ThreadId>()
            + size_of::<u32>()
    }
}

impl OriginalNativeImport18Bootstrap {
    /// Lends the same actual owner without a mutable or effect-bearing handle.
    ///
    /// Origin checks bracket either callback result. Failed downstream outputs
    /// belong to the caller's already retained attempt before it returns error.
    ///
    /// # Errors
    /// Refuses foreign creator origin or preserves the passive callback refusal.
    pub fn with_partial_history_data<R>(
        &self,
        inspect: impl for<'view> FnOnce(
            OriginalNativeImport18BootstrapHistoryData<'view>,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.row.controller.ensure_current()?;
        let result = inspect(OriginalNativeImport18BootstrapHistoryData {
            method: self.method_data(),
            row: row_history_data(&self.row, Some(self)),
            request_id: self.request_id.as_ref(),
            request: self.request.as_ref(),
            assignment: self
                .assignment
                .as_ref()
                .map(PacketNativeImport18BootstrapAssignmentData::borrowed_history_data),
            original_cut_retained: self.cut.is_some(),
            reservation_row: self.reservation_row.as_ref(),
            reservation_started: self.reservation_started,
            literal_slot: self.literal_slot,
            reserved: self.reserved,
            materialization_row: self.materialization_row.as_ref(),
            materialization_started: self.materialization_started,
            sealing: self
                .sealing
                .as_ref()
                .map(PacketNativeImport18BootstrapSealingData::borrowed_history_data),
            retained: self.retained,
            failed: self.failed,
        });
        self.row.controller.ensure_current()?;
        result
    }

    /// Names actual fixed passive owner/row/callback controls before lookup.
    pub fn partial_history_counter_scratch_data<R>() -> usize {
        OriginalNativeImport18BootstrapConstructionData::row_history_counter_scratch_data::<R>()
            + size_of::<&Self>()
            + size_of::<OriginalNativeImport18BootstrapHistoryData<'static>>()
    }
}

fn row_history_data<'a>(
    row: &'a OriginalNativeImport18BootstrapConstructionData,
    owner: Option<&OriginalNativeImport18Bootstrap>,
) -> OriginalNativeImport18BootstrapRowHistoryData<'a> {
    OriginalNativeImport18BootstrapRowHistoryData {
        frontier: &row.frontier,
        hello: &row.hello,
        recipe: &row.recipe,
        initial: row.initial.borrowed_history_data(),
        input_identity: &row.input_identity,
        axes: row.axes,
        same_owner_controller: owner
            .map(|owner| Rc::ptr_eq(&row.controller, &owner.row.controller)),
    }
}
