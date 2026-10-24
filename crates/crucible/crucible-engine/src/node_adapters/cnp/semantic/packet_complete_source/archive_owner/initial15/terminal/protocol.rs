//! Quotes the actual initial15 protocol constructors and counts their live banks.
//!
//! Prepared journal bounds remain admission DATA. Finishes walk initialized
//! fields and actual capacities, including all partial sealed owners.

use super::*;
use super::super::storage;
use crate::node_adapters::cnp::semantic::packet_complete_source::archive_semantics::decoded_storage::Census;

impl PacketCompleteArchivedOwnerData<'_> {
    fn charge_initial15_terminal_data(&self, census: &mut Census) -> Result<(), OperationFailure> {
        let Self {
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
        } = self;
        storage::require_copy(snapshot_class);
        storage::require_copy(host_limits);
        storage::require_copy(native_limits);
        storage::require_copy(before_limits);
        storage::require_copy(registry_limits);
        storage::require_copy(maximum);
        storage::require_copy(journal_storage);
        storage::require_copy(known_requested);
        storage::require_copy(native_restoration_demand);
        storage::require_copy(attempted);
        storage::require_copy(failed);
        if let Some(journal) = journal {
            storage::charge_journal_data(census, journal)?;
        }
        for aliases in [
            host_aliases,
            native_aliases,
            before_aliases,
            registry_aliases,
        ] {
            census
                .add(
                    aliases
                        .capacity()
                        .checked_mul(size_of::<HistoricalAliasSummary>())
                        .ok_or_else(|| refused("initial15 alias bank capacity overflow"))?,
                )
                .map_err(unknown)?;
        }
        census.charge(before_reference).map_err(unknown)?;
        census.add(before_raw.capacity()).map_err(unknown)?;
        for bytes in [
            before_encoded,
            host_encoded,
            native_encoded,
            registry_encoded,
        ]
        .into_iter()
        .flatten()
        {
            census.add(bytes.capacity()).map_err(unknown)?;
        }
        if let Some(host) = host {
            storage::add_metadata(
                census,
                &host.original_retained_metadata_facts().map_err(unknown)?,
            )?;
        }
        for native in [before, native].into_iter().flatten() {
            storage::add_metadata(
                census,
                &native.original_retained_metadata_facts().map_err(unknown)?,
            )?;
        }
        if let Some(registry) = registry {
            storage::add_metadata(
                census,
                &registry
                    .original_retained_metadata_facts()
                    .map_err(unknown)?,
            )?;
        }
        Ok(())
    }
}

impl Initial15Terminal17<'_, '_> {
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source::archive_owner) fn finish_protocol_data(
        &self,
        base_backing: usize,
        slots: &[Option<PacketCompleteArchivedOwnerData<'_>>; 3],
        temporary_journal: Option<&PacketCompleteSettledJournal>,
        maximum: usize,
    ) -> Result<(), OperationFailure> {
        let mut census = Census::new(maximum);
        census.add(base_backing).map_err(unknown)?;
        for owner in slots.iter().flatten() {
            owner.charge_initial15_terminal_data(&mut census)?;
        }
        if let Some(journal) = temporary_journal {
            storage::charge_journal_data(&mut census, journal)?;
        }
        self.finish_requested_data(census.bytes())
    }
}

pub(super) fn counter_scratch_data() -> usize {
    let parser = CompleteNativeSnapshotClass::InvocationCapture15.parser_layouts();
    // These are the defining selected parser's concrete plans and fixed arrays,
    // not a byte ceiling or an estimate of the thread stack.
    let parser_scratch = parser.plan_header_bytes
        + parser.field_cursor_bytes * parser.maximum_simultaneous_field_cursors
        + parser.field_scan_declared_array_bytes
        + parser.raw_chunk_array_bytes
        + parser.streaming_hash_header_bytes
        + parser.streaming_hash_output_bytes;
    size_of::<Census>()
        + size_of::<PacketCompleteSettledJournal>()
        + size_of::<Result<PacketCompleteSettledJournal, OperationFailure>>()
        + size_of::<std::slice::Iter<'static, Option<PacketCompleteArchivedOwnerData<'static>>>>()
        + size_of::<Option<&PacketCompleteSettledJournal>>()
        + size_of::<std::iter::Flatten<std::slice::Iter<'static, Option<PacketCompleteArchivedOwnerData<'static>>>>>()
        + size_of::<std::array::IntoIter<&'static Vec<HistoricalAliasSummary>, 4>>()
        + size_of::<std::iter::Flatten<std::array::IntoIter<&'static Option<Vec<u8>>, 4>>>()
        + size_of::<std::iter::Flatten<std::array::IntoIter<&'static Option<SealedHistoricalNativeState>, 2>>>()
        + size_of::<Result<CompleteSnapshotPlan<'static>, crucible_node_transport::ProviderError>>()
        + size_of::<[usize; 6]>()
        + size_of::<std::array::IntoIter<usize, 6>>()
        + size_of::<[usize; 5]>()
        + size_of::<std::array::IntoIter<usize, 5>>()
        + size_of::<[usize; 12]>()
        + size_of::<(usize, usize, usize)>()
        + size_of::<Result<(usize, usize, usize), OperationFailure>>()
        + size_of::<ValidatedOwnedProtocol11<'static, 'static>>()
        + size_of::<ValidatedNativeOwnedProtocol11<'static, 'static>>()
        + size_of::<crucible_node_transport::protocol_snapshot::owned11::host_registry::ValidatedHostExtensionRegistry<'static, 'static>>()
        + size_of::<OwnedProtocol11AllocationDemand>()
        + size_of::<crucible_node_transport::protocol_snapshot::owned11::native::outer::NativeOwnedProtocol11AllocationDemand>()
        + size_of::<blake3::Hasher>()
        + size_of::<blake3::Hash>()
        + size_of::<[u8; 64]>()
        + size_of::<[u8; 20]>()
        + size_of::<HashRef>()
        + size_of::<Result<HashRef, crucible_node_format::ContractError>>()
        + size_of::<&CompleteSnapshotPlan<'static>>()
        + size_of::<CompleteNativeSnapshotClass>()
        + size_of::<&[u8]>()
        + size_of::<Option<&[u8]>>()
        + size_of::<Result<&[u8], OperationFailure>>()
        + PacketCompleteSettledJournal::backend_registry_identity_counter_scratch_data()
        + parser_scratch
}

/// Borrows the actual snapshot plan before admitting independent owned banks.
/// The temporary selection journal is already retained by the preceding row.
pub(in crate::node_adapters::cnp::semantic::packet_complete_source::archive_owner::initial15) fn protocol_prepare_terminal_storage_data(
    scope: &ParentArchive17ReadScope<'_, '_>,
    journal: &PacketCompleteSettledJournal,
    journal_bytes: &[u8],
    launch: &PacketNative5SourceLaunch,
    owner: &NativeOwnerState,
    host: OwnedProtocol11DataLimits,
    native: OwnedProtocol11DataLimits,
    before: OwnedProtocol11DataLimits,
    registry: OwnedProtocol11DataLimits,
    maximum: usize,
) -> Result<(usize, usize, usize), OperationFailure> {
    let limits = scope.limits_data().map_err(unknown)?;
    let class = CompleteNativeSnapshotClass::InvocationCapture15;
    let snapshot = class
        .validate_snapshot(
            scope.body_data(&journal.native_snapshot).map_err(unknown)?,
            limits.state.maximum_content_bytes,
            before.json.maximum_input_bytes,
        )
        .map_err(unknown)?;
    let before_plan = snapshot.before();
    let journal_decode = NodeRuntime::capture_selected_json_decode_storage(
        journal_bytes,
        size_of::<PacketCompleteSettledJournal>(),
        NodeRuntime::capture_map_node_storage::<String, Value>(),
        maximum,
    )
    .map_err(unknown)?
    .checked_mul(3)
    .ok_or_else(|| refused("initial15 retained journal quote overflow"))?;
    let reference_decode = NodeRuntime::capture_selected_json_decode_storage(
        before_plan.reference_bytes(),
        size_of::<ContentRef>(),
        NodeRuntime::capture_map_node_storage::<String, Value>(),
        maximum,
    )
    .map_err(unknown)?;
    let aliases = host
        .maximum_metadata_rows
        .checked_add(native.maximum_metadata_rows)
        .and_then(|n| n.checked_add(before.maximum_metadata_rows))
        .and_then(|n| n.checked_add(registry.maximum_metadata_rows))
        .and_then(|n| n.checked_mul(size_of::<HistoricalAliasSummary>()))
        .ok_or_else(|| refused("initial15 protocol alias quote overflow"))?;
    let banks = checked_sum(
        [
            aliases,
            scope
                .body_data(&journal.host_protocol)
                .map_err(unknown)?
                .len(),
            scope
                .body_data(&journal.native_after_protocol)
                .map_err(unknown)?
                .len(),
            scope
                .body_data(journal.require_complete_registry_data()?)
                .map_err(unknown)?
                .len(),
            before_plan.original_capacity(),
            before_plan.encoded_length(),
        ],
        maximum,
    )?;
    let backend = PacketCompleteSettledJournal::backend_registry_identity_view_for_class_data(
        &launch.selection.provider.implementation,
        &owner.key,
        class,
    );
    let backend_dom =
        NodeRuntime::capture_serialization_storage(&backend, maximum).map_err(unknown)?;
    let backend_encoded =
        NodeRuntime::capture_encoded_output_storage(&backend, maximum).map_err(unknown)?;
    let retained = checked_sum([journal_decode, reference_decode, banks], maximum)?;
    let transient = checked_sum(
        [
            journal_decode,
            reference_decode,
            backend_dom,
            backend_encoded,
            "blake3-256".len() + "cnp.blob.v1".len() + 64,
        ],
        maximum,
    )?;
    let scratch = snapshot_parser_known_storage_for_class(class, maximum)?;
    Ok((retained, transient, scratch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_protocol_census_ignores_prospective_decoder_ceiling() {
        let mut owner = Initial15DecodedOwner::new_data();
        let mut before = Census::new(1 << 20);
        owner.charge_data(&mut before).unwrap();

        owner.journal_storage = usize::MAX;
        owner.known_requested = Some(usize::MAX);
        owner.failed = true;
        let mut after = Census::new(1 << 20);
        owner.charge_data(&mut after).unwrap();

        assert_eq!(before.bytes(), after.bytes());
    }

    #[test]
    fn actual_protocol_census_keeps_failed_spare_banks() {
        let mut owner = Initial15DecodedOwner::new_data();
        owner.before_raw.try_reserve_exact(73).unwrap();
        owner.before_encoded = Some(Vec::with_capacity(41));
        owner.registry_encoded = Some(Vec::with_capacity(29));
        owner.failed = true;
        let expected = owner.before_raw.capacity()
            + owner.before_encoded.as_ref().unwrap().capacity()
            + owner.registry_encoded.as_ref().unwrap().capacity();

        let mut exact = Census::new(expected);
        owner.charge_data(&mut exact).unwrap();
        let mut short = Census::new(expected - 1);

        assert_eq!(exact.bytes(), expected);
        assert!(owner.charge_data(&mut short).is_err());
    }
}
