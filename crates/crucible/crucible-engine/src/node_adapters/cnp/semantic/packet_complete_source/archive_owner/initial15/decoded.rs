//! Moves private shared decoder owners into a nonborrowing inert result.
//!
//! Drop performs only fixed field moves. The final type contains no parent loan,
//! live Source, archive record, current key or future-restoration constructor.

use super::*;

pub(super) struct Initial15DecodedOwner {
    pub(super) snapshot_class: CompleteNativeSnapshotClass,
    pub(super) journal: Option<PacketCompleteSettledJournal>,
    pub(super) host_limits: OwnedProtocol11DataLimits,
    pub(super) native_limits: OwnedProtocol11DataLimits,
    pub(super) before_limits: OwnedProtocol11DataLimits,
    pub(super) registry_limits: OwnedProtocol11DataLimits,
    pub(super) maximum: usize,
    pub(super) journal_storage: usize,
    pub(super) host_aliases: Vec<HistoricalAliasSummary>,
    pub(super) native_aliases: Vec<HistoricalAliasSummary>,
    pub(super) before_aliases: Vec<HistoricalAliasSummary>,
    pub(super) registry_aliases: Vec<HistoricalAliasSummary>,
    pub(super) before_reference: Option<ContentRef>,
    pub(super) before_raw: Vec<u8>,
    pub(super) before_encoded: Option<Vec<u8>>,
    pub(super) before: Option<SealedHistoricalNativeState>,
    pub(super) host_encoded: Option<Vec<u8>>,
    pub(super) native_encoded: Option<Vec<u8>>,
    pub(super) registry_encoded: Option<Vec<u8>>,
    pub(super) registry: Option<SealedHistoricalHostExtensionRegistry>,
    pub(super) host: Option<SealedHistoricalControllerState>,
    pub(super) native: Option<SealedHistoricalNativeState>,
    pub(super) known_requested: Option<usize>,
    pub(super) native_restoration_demand: Option<crucible_node_transport::protocol_snapshot::owned11::native::outer::NativeOwnedProtocol11AllocationDemand>,
    pub(super) attempted: bool,
    pub(super) failed: bool,
}

pub(super) struct Initial15DecodeStaging<'out, 'input> {
    output: &'out mut [Initial15DecodedOwner; 3],
    pub(super) slots: [Option<PacketCompleteArchivedOwnerData<'input>>; 3],
}

impl<'out, 'input> Initial15DecodeStaging<'out, 'input> {
    pub(super) fn new_data(output: &'out mut [Initial15DecodedOwner; 3]) -> Self {
        Self {
            output,
            slots: std::array::from_fn(|_| None),
        }
    }
}

impl Drop for Initial15DecodeStaging<'_, '_> {
    fn drop(&mut self) {
        for index in 0..3 {
            if let Some(owner) = self.slots[index].take() {
                self.output[index] = Initial15DecodedOwner::retain_data(owner);
            }
        }
    }
}

impl Initial15DecodedOwner {
    pub(super) fn new_data() -> Self {
        // No empty sealed/native owner is synthesized: all actual typed outputs
        // remain None until the defining shared decoder initializes that field.
        Self {
            snapshot_class: CompleteNativeSnapshotClass::InvocationCapture15,
            journal: None,
            host_limits: empty_limits_data(),
            native_limits: empty_limits_data(),
            before_limits: empty_limits_data(),
            registry_limits: empty_limits_data(),
            maximum: 0,
            journal_storage: 0,
            host_aliases: Vec::new(),
            native_aliases: Vec::new(),
            before_aliases: Vec::new(),
            registry_aliases: Vec::new(),
            before_reference: None,
            before_raw: Vec::new(),
            before_encoded: None,
            before: None,
            host_encoded: None,
            native_encoded: None,
            registry_encoded: None,
            registry: None,
            host: None,
            native: None,
            known_requested: None,
            native_restoration_demand: None,
            attempted: false,
            failed: false,
        }
    }

    fn retain_data(owner: PacketCompleteArchivedOwnerData<'_>) -> Self {
        let PacketCompleteArchivedOwnerData {
            process: _,
            thread: _,
            source: _,
            owner: _,
            content: _,
            journal_reference: _,
            snapshot_class,
            journal,
            host_limits,
            native_limits,
            before_limits,
            registry_limits,
            maximum,
            journal_storage,
            host_aliases,
            native_aliases,
            before_aliases,
            registry_aliases,
            before_reference,
            before_raw,
            before_encoded,
            before,
            host_encoded,
            native_encoded,
            registry_encoded,
            registry,
            host,
            native,
            known_requested,
            native_restoration_demand,
            attempted,
            failed,
        } = owner;
        Self {
            snapshot_class,
            journal,
            host_limits,
            native_limits,
            before_limits,
            registry_limits,
            maximum,
            journal_storage,
            host_aliases,
            native_aliases,
            before_aliases,
            registry_aliases,
            before_reference,
            before_raw,
            before_encoded,
            before,
            host_encoded,
            native_encoded,
            registry_encoded,
            registry,
            host,
            native,
            known_requested,
            native_restoration_demand,
            attempted,
            failed,
        }
    }

    fn authenticate_complete_data(&self) -> Result<(), OperationFailure> {
        if self.snapshot_class != CompleteNativeSnapshotClass::InvocationCapture15
            || !self.attempted
            || self.failed
            || self.known_requested.is_none()
            || self.host.is_none()
            || self.native.is_none()
            || self.before.is_none()
            || self.registry.is_none()
        {
            return Err(refused("initial15 protocol decode incomplete"));
        }
        Ok(())
    }

    pub(super) fn journal_data(&self) -> Result<&PacketCompleteSettledJournal, OperationFailure> {
        self.authenticate_complete_data()?;
        self.journal
            .as_ref()
            .ok_or_else(|| refused("initial15 journal absent"))
    }

    pub(super) fn host_data(&self) -> Result<&SealedHistoricalControllerState, OperationFailure> {
        self.authenticate_complete_data()?;
        self.host
            .as_ref()
            .ok_or_else(|| refused("initial15 host absent"))
    }

    pub(super) fn native_before_data(
        &self,
    ) -> Result<&SealedHistoricalNativeState, OperationFailure> {
        self.authenticate_complete_data()?;
        self.before
            .as_ref()
            .ok_or_else(|| refused("initial15 native before absent"))
    }

    pub(super) fn native_after_data(
        &self,
    ) -> Result<&SealedHistoricalNativeState, OperationFailure> {
        self.authenticate_complete_data()?;
        self.native
            .as_ref()
            .ok_or_else(|| refused("initial15 native after absent"))
    }

    pub(super) fn registry_data(
        &self,
    ) -> Result<&SealedHistoricalHostExtensionRegistry, OperationFailure> {
        self.authenticate_complete_data()?;
        self.registry
            .as_ref()
            .ok_or_else(|| refused("initial15 Registry absent"))
    }
}

fn empty_limits_data() -> OwnedProtocol11DataLimits {
    // This never admits a parser: the actual prepare call installs all limits
    // from authenticated raw5 policy and actual archived metadata rows.
    OwnedProtocol11DataLimits {
        json: HistoricalJsonLimits {
            maximum_input_bytes: 0,
            maximum_nodes: 0,
            maximum_depth: 0,
            maximum_owned_backing_bytes: 0,
            maximum_tree_entries: 0,
        },
        content: CompactMetadata8Limits {
            content: CompactContentLimits {
                max_input_bytes: 0,
                max_rows: 0,
                max_groups: 0,
                max_first_group_capacity_bytes: 0,
            },
            maximum_metadata_capacity_bytes: 0,
        },
        maximum_metadata_rows: 0,
        maximum_literal_backing_bytes: 0,
    }
}
