//! Quotes original common/native comparisons from genuine historical owners.
//!
//! This leaf only describes disposable constructor storage. The defining group
//! runs every Runtime, protocol, native-model and full custody predicate after
//! the enclosing terminal ledger admits the independently derived row.

use super::*;

impl OriginalInitial15ArchivedGroup {
    /// Quotes all independent sequential common and native comparison windows.
    ///
    /// # Errors
    /// Refuses incomplete historical components or any defining prospective ceiling.
    pub(in super::super) fn semantic_join_terminal_transient_data(
        &self,
        scope: &ParentArchive17ReadScope<'_, '_>,
        index: usize,
    ) -> Result<(usize, usize), OperationFailure> {
        let protocol = self
            .protocols
            .get(index)
            .ok_or_else(|| refused("initial15 semantic protocol slot absent"))?;
        let semantics = self
            .semantics
            .get(index)
            .ok_or_else(|| refused("initial15 semantic slot absent"))?
            .read_data_ref()?;
        let launch = self
            .launches
            .get(index)
            .and_then(Option::as_ref)
            .ok_or_else(|| refused("initial15 semantic launch absent"))?;
        let selection = OriginalInitial15ArchivedSelection {
            scope,
            launch,
            storage: self
                .storage
                .get(index)
                .and_then(Option::as_ref)
                .ok_or_else(|| refused("initial15 semantic storage absent"))?,
            caps: self
                .caps
                .get(index)
                .copied()
                .flatten()
                .ok_or_else(|| refused("initial15 semantic caps absent"))?,
        };
        let host = protocol.host_data()?.historical().map_err(unknown)?;
        let native = protocol
            .native_after_data()?
            .historical()
            .map_err(unknown)?;
        let (runtime, protocol_work) = semantics.runtime_protocol_terminal_transient_data(
            host,
            ArchivedContentData::Parent(scope),
            self.maximum,
        )?;
        let native_data = NativeInputData {
            selection: NativeInputSelection::Archived(&selection),
            host,
            native,
            content: ArchivedContentData::Parent(scope),
            retained: 0,
            maximum: self.maximum,
            scratch: Cell::new(0),
            construction: None,
        };
        let (native_work, native_scratch) = native_data
            .original_semantic_validation_construction_data(semantics, protocol.journal_data()?)?;
        // Each validator returns no owner: all constructor temporaries drop
        // before the next predicate. Existing group/cache roots are outside
        // this T axis and remain independently counted by the caller.
        let launch_expected =
            NodeRuntime::capture_serialization_storage(launch, self.maximum).map_err(unknown)?;
        let transient = runtime
            .max(protocol_work)
            .max(native_work)
            .max(launch_expected);
        let scratch = Self::semantic_join_terminal_counter_scratch_data()
            .checked_add(native_scratch)
            .ok_or_else(|| refused("initial15 semantic quote workspace overflow"))?;
        Ok((transient, scratch))
    }

    /// Names the actual borrowed selection, native view and quote workspaces.
    pub(in super::super) fn semantic_join_terminal_counter_scratch_data() -> usize {
        PacketCompleteArchivedSemantics::runtime_protocol_terminal_counter_scratch_data()
            + NativeInputData::semantic_validation_construction_counter_scratch_data()
            + size_of::<OriginalInitial15ArchivedSelection<'static>>()
            + size_of::<NativeInputData<'static>>()
            + size_of::<[usize; 4]>()
            + size_of::<Result<(usize, usize), OperationFailure>>()
    }
}
