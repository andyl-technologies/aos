//! Prices construction before allocation and counts the actual retained result.
//!
//! The census follows initialized owned fields and their actual capacities even
//! after refusal. Old parser bounds and allocation-demand rows are numeric DATA;
//! none is substituted for the independently decoded typed graph's live heaps.

use super::super::super::archive_semantics::decoded_storage::{Census, Owned};
use super::*;
use crucible_node_provider::retained_metadata::{
    RetainedCaptureProtocolData, RetainedProtocolMetadataFacts, observe_retained_native_launch,
    original_metadata_observer_layout_bytes,
};

impl OriginalInitial15ArchivedGroup {
    /// Counts this actual root and all initialized retained heaps after any phase.
    ///
    /// Includes the root header once. An enclosing inline collector slot must
    /// account for that header consistently when adding this defining census.
    ///
    /// # Errors
    /// Refuses a foreign actor, unsupported layout, overflow or the bound.
    pub(crate) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, OperationFailure> {
        self.authenticate_origin_data()?;
        // An added root field must be classified by this actual census.
        let Self {
            process: _,
            thread: _,
            parent_index: _,
            parent_manifest: _,
            values: _,
            collecting: _,
            coordinator: _,
            runtime: _,
            scheduling: _,
            administrative: _,
            launches: _,
            storage: _,
            caps: _,
            protocols: _,
            semantics: _,
            maximum: _,
            verified: _,
        } = self;

        let mut census = Census::new(maximum);
        census.add(size_of::<Self>()).map_err(unknown)?;
        census.charge(&self.parent_index).map_err(unknown)?;
        census.charge(&self.parent_manifest).map_err(unknown)?;
        for value in &self.values {
            census.charge(value).map_err(unknown)?;
        }
        if let Some(collecting) = &self.collecting {
            let crate::node_state::CollectingCompleteCaptureProvenance {
                schema,
                plan,
                refused,
                sources,
                world,
                ordinary_acceptance,
            } = collecting;
            census.charge(schema).map_err(unknown)?;
            census.charge(plan).map_err(unknown)?;
            census.charge(refused).map_err(unknown)?;
            census.charge(sources).map_err(unknown)?;
            census
                .add(NodeRuntime::capture_hash_storage(world).map_err(unknown)?)
                .map_err(unknown)?;
            require_copy(ordinary_acceptance);
        }
        if let Some(coordinator) = &self.coordinator {
            let declaration::Initial15Coordinator {
                schema_version,
                runtime,
                scheduler,
                world_repeatability,
            } = coordinator;
            require_copy(schema_version);
            require_copy(world_repeatability);
            census.charge(runtime).map_err(unknown)?;
            census.charge(scheduler).map_err(unknown)?;
        }
        if let Some(runtime) = &self.runtime {
            let nested = NodeRuntime::capture_runtime_record_storage(runtime)
                .map_err(unknown)?
                .checked_sub(size_of::<OriginalLineageRuntimeRecord>())
                .ok_or_else(|| refused("initial15 runtime header census differs"))?;
            census.add(nested).map_err(unknown)?;
        }
        if let Some(scheduling) = &self.scheduling {
            let nested = NodeRuntime::capture_scheduling_record_storage(scheduling)
                .map_err(unknown)?
                .checked_sub(size_of::<SchedulingSnapshot>())
                .ok_or_else(|| refused("initial15 scheduler header census differs"))?;
            census.add(nested).map_err(unknown)?;
        }
        if let Some(administrative) = &self.administrative {
            census
                .add(NodeRuntime::capture_admin_storage(administrative).map_err(unknown)?)
                .map_err(unknown)?;
        }
        for launch in self.launches.iter().flatten() {
            add_metadata(
                &mut census,
                &observe_retained_native_launch(launch).map_err(unknown)?,
            )?;
        }
        for storage in self.storage.iter().flatten() {
            scalar_storage_data(storage);
        }
        for caps in self.caps.iter().flatten() {
            let OriginalSemanticCaps {
                operations,
                result,
                authorization,
                semantic,
            } = caps;
            require_copy(operations);
            require_copy(result);
            require_copy(authorization);
            require_copy(semantic);
        }
        for protocol in &self.protocols {
            protocol.charge_data(&mut census)?;
        }
        for semantics in &self.semantics {
            let nested = semantics
                .retained_requested_storage_data(census.remaining())
                .map_err(unknown)?
                .checked_sub(size_of::<Initial15SemanticAttempt>())
                .ok_or_else(|| refused("initial15 semantic attempt header census differs"))?;
            census.add(nested).map_err(unknown)?;
        }
        Ok(census.bytes())
    }

    fn transient_reference_storage_data(&self) -> Result<usize, OperationFailure> {
        let mut total = 0usize;
        if let Some(collecting) = &self.collecting {
            for reference in std::iter::once(&collecting.plan)
                .chain(std::iter::once(&collecting.refused))
                .chain(&collecting.sources)
            {
                total = total
                    .checked_add(
                        NodeRuntime::capture_reference_storage(reference).map_err(unknown)?,
                    )
                    .ok_or_else(|| refused("initial15 reference counter overflow"))?;
            }
        }
        if let Some(coordinator) = &self.coordinator {
            for reference in [&coordinator.runtime, &coordinator.scheduler] {
                total = total
                    .checked_add(
                        NodeRuntime::capture_reference_storage(reference).map_err(unknown)?,
                    )
                    .ok_or_else(|| refused("initial15 reference counter overflow"))?;
            }
        }
        Ok(total)
    }

    pub(super) fn admit_data(
        &self,
        scope: &ParentArchive17ReadScope<'_, '_>,
        additional: usize,
        transient: usize,
    ) -> Result<(), OperationFailure> {
        scope.manifest_data().map_err(unknown)?;
        checked_sum(
            [
                additional,
                scope
                    .retained_content_requested_storage_data()
                    .map_err(unknown)?,
                self.retained_requested_storage_data(self.maximum)?,
                self.transient_reference_storage_data()?,
                transient,
                Self::counter_scratch_data(),
            ],
            self.maximum,
        )?;
        Ok(())
    }

    pub(super) fn admit_typed_data(
        &self,
        scope: &ParentArchive17ReadScope<'_, '_>,
        additional: usize,
        value: &Value,
    ) -> Result<(), OperationFailure> {
        // Prospective construction prices typed+serde temporaries before decode;
        // it is never used as the retained-result census above.
        let extent = NodeRuntime::capture_future_decode_storage(value, self.maximum)
            .map_err(unknown)?
            .checked_mul(3)
            .ok_or_else(|| refused("initial15 typed construction row overflow"))?;
        self.admit_data(scope, additional, extent)
    }

    pub(super) fn admit_serialization_data(
        &self,
        scope: &ParentArchive17ReadScope<'_, '_>,
        additional: usize,
        value: &impl serde::Serialize,
    ) -> Result<(), OperationFailure> {
        let values =
            NodeRuntime::capture_serialization_storage(value, self.maximum).map_err(unknown)?;
        let encoded = super::super::super::super::budget::serialized_size(value, self.maximum)?;
        let encoded = encoded
            .checked_mul(4)
            .and_then(|n| n.checked_add(8))
            .ok_or_else(|| refused("initial15 serialization bank extent overflow"))?;
        self.admit_data(
            scope,
            additional,
            checked_sum([values, encoded], self.maximum)?,
        )
    }

    pub(super) fn parse_role_data(
        &mut self,
        scope: &ParentArchive17ReadScope<'_, '_>,
        reference: &ContentRef,
        slot: usize,
        additional: usize,
        terminal: Option<&Initial15Terminal17<'_, '_>>,
        temporary_references: usize,
    ) -> Result<(), OperationFailure> {
        if let Some(cursor) = terminal {
            use crate::node_state::{
                RestoredArchive17Initial15Role as Role, RestoredArchive17Initial15Work as Work,
            };
            let role = match slot {
                0 => Role::Provenance,
                1 => Role::Plan,
                2 => Role::Descriptors,
                3 => Role::Contracts,
                4 => Role::Fixtures,
                5 => Role::Coordinator,
                6 => Role::Runtime,
                7 => Role::Scheduling,
                8 => Role::Administrative,
                _ => return Err(refused("initial15 original role is outside closed grammar")),
            };
            cursor.begin_data(Work::RoleDecode(role), 0)?;
        }
        if slot >= self.values.len() || self.values[slot].is_some() {
            return Err(refused("initial15 original role slot spent"));
        }
        let bytes = scope.body_data(reference).map_err(unknown)?;
        let limits = scope.limits_data().map_err(unknown)?;
        if bytes.is_empty() || bytes.len() > limits.state.maximum_record_bytes {
            return Err(refused(
                "initial15 original role exceeds finite record ceiling",
            ));
        }
        let decoder = NodeRuntime::capture_selected_json_decode_storage(
            bytes,
            size_of::<Value>(),
            NodeRuntime::capture_map_node_storage::<String, Value>(),
            self.maximum,
        )
        .map_err(unknown)?;
        let encoded = bytes
            .len()
            .checked_mul(4)
            .and_then(|n| n.checked_add(8))
            .ok_or_else(|| refused("initial15 canonical row overflow"))?;
        self.admit_data(
            scope,
            additional,
            checked_sum([decoder, encoded], self.maximum)?,
        )?;
        if let Some(cursor) = terminal {
            cursor.construct_data(decoder, encoded)?;
        }
        self.values[slot] =
            Some(canonical::parse_json(bytes, limits.state.maximum_record_bytes).map_err(unknown)?);
        let value = self.values[slot]
            .as_ref()
            .ok_or_else(|| refused("initial15 original role DOM absent"))?;
        if canonical::canonical_json(value)
            .map_err(unknown)?
            .as_slice()
            != bytes
        {
            return Err(refused("initial15 original role is not canonical"));
        }
        self.admit_data(scope, additional, 0)?;
        if let Some(cursor) = terminal {
            cursor.finish_data(self, temporary_references)?;
        }
        Ok(())
    }

    /// Reports the defining fixed observers, serializer views and borrowed plans.
    pub(crate) fn counter_scratch_data() -> usize {
        size_of::<Census>()
            + size_of::<SchemaRef>()
            + size_of::<FacetSelection>()
            + 2 * size_of::<Value>()
            + size_of::<
                crucible_node_provider::protocol_snapshot::borrowed_json::BorrowedJsonFields<
                    'static,
                >,
            >()
            + size_of::<
                crucible_node_provider::retained_metadata::records::ValidatedMetadataRecords<
                    'static,
                >,
            >()
            + size_of::<OriginalInitial15ArchivedSelection<'static>>()
            + size_of::<NativeInputData<'static>>()
            + size_of::<ParentArchive17ReadScope<'static, 'static>>()
            + size_of::<Initial15DecodeStaging<'static, 'static>>()
            + size_of::<[Option<PacketCompleteArchivedOwnerData<'static>>; 3]>()
            + crucible_node_provider::protocol_snapshot::borrowed_json::counter_scratch_data()
            + size_of::<Result<(), OperationFailure>>()
            + size_of::<RetainedProtocolMetadataFacts>()
            + size_of::<RetainedCaptureProtocolData<'static>>()
            + original_metadata_observer_layout_bytes()
            + crucible_node_provider::retained_metadata::retained_native_launch_counter_scratch_data(
            )
            + SealedHistoricalControllerState::original_retained_metadata_counter_scratch_data()
            + SealedHistoricalNativeState::original_retained_metadata_counter_scratch_data()
            + SealedHistoricalHostExtensionRegistry::original_retained_metadata_counter_scratch_data(
            )
            + NativeInputData::counter_scratch_data()
            + PacketCompleteArchivedSemantics::retained_counter_scratch_data()
            + NodeRuntime::capture_selected_json_decode_counter_scratch_data()
            + NodeRuntime::capture_serialization_counter_scratch_data()
            + crucible_node_provider::reference_packet::service::native_snapshot::native_owned14_snapshot_schema_counter_scratch_data()
    }
}

impl Initial15DecodedOwner {
    pub(super) fn charge_data(&self, census: &mut Census) -> Result<(), OperationFailure> {
        let Self {
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
        require_copy(snapshot_class);
        require_copy(host_limits);
        require_copy(native_limits);
        require_copy(before_limits);
        require_copy(registry_limits);
        require_copy(maximum);
        require_copy(journal_storage);
        require_copy(known_requested);
        require_copy(native_restoration_demand);
        require_copy(attempted);
        require_copy(failed);
        if let Some(journal) = journal {
            charge_journal_data(census, journal)?;
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
            add_metadata(
                census,
                &host.original_retained_metadata_facts().map_err(unknown)?,
            )?;
        }
        for native in [before, native].into_iter().flatten() {
            add_metadata(
                census,
                &native.original_retained_metadata_facts().map_err(unknown)?,
            )?;
        }
        if let Some(registry) = registry {
            add_metadata(
                census,
                &registry
                    .original_retained_metadata_facts()
                    .map_err(unknown)?,
            )?;
        }
        Ok(())
    }
}

pub(super) fn charge_journal_data(
    census: &mut Census,
    journal: &PacketCompleteSettledJournal,
) -> Result<(), OperationFailure> {
    let PacketCompleteSettledJournal {
        schema,
        owner,
        participants,
        cut,
        ordinal,
        runtime,
        backend_implementation,
        semantic,
        ancestry,
        native_snapshot,
        native_control,
        native_anchor,
        native_after_protocol,
        host_protocol,
        host_extension_registry,
        confirmation_request,
        confirmation,
    } = journal;
    census.charge(schema).map_err(unknown)?;
    census.charge(owner).map_err(unknown)?;
    census.charge(participants).map_err(unknown)?;
    require_copy(cut);
    require_copy(ordinal);
    for reference in [
        runtime,
        backend_implementation,
        semantic,
        ancestry,
        native_snapshot,
        native_control,
        native_anchor,
        native_after_protocol,
        host_protocol,
    ] {
        census.charge(reference).map_err(unknown)?;
    }
    census.charge(host_extension_registry).map_err(unknown)?;
    census.charge(confirmation_request).map_err(unknown)?;
    add_metadata(
        census,
        &RetainedCaptureProtocolData::AfterConfirmation(confirmation)
            .observe_retained_metadata()
            .map_err(unknown)?,
    )
}

pub(super) fn add_metadata(
    census: &mut Census,
    facts: &RetainedProtocolMetadataFacts,
) -> Result<(), OperationFailure> {
    census
        .add(
            PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
                facts,
                census.remaining(),
            )
            .map_err(unknown)?,
        )
        .map_err(unknown)
}

fn scalar_storage_data(value: &PacketNative5StorageSelection) {
    let PacketNative5StorageSelection { storage, limits } = value;
    let crucible_node_provider::reference_packet::service::PacketNative5StorageLimits {
        snapshot_bytes,
        control_snapshot_bytes,
        protocol_snapshot_bytes,
        frame_bank_bytes,
        frames_per_direction,
        hello_bytes,
        settlement_bytes,
    } = storage;
    require_copy(snapshot_bytes);
    require_copy(control_snapshot_bytes);
    require_copy(protocol_snapshot_bytes);
    require_copy(frame_bank_bytes);
    require_copy(frames_per_direction);
    require_copy(hello_bytes);
    require_copy(settlement_bytes);
    require_copy(limits);
}

pub(super) fn require_copy<T: Copy>(_: &T) {}
