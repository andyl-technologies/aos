//! Reads the defining native DTO fields in their actual emitted order.

use super::*;

impl CurrentContract17 for PacketNativeRestoredCommitHold {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let native_pid_raw = fields.named("native_pid")?;
        let target_world_raw = fields.named("target_world")?;
        let target_owner_raw = fields.named("target_owner")?;
        let target_owner_binding_raw = fields.named("target_owner_binding")?;
        let target_activation_raw = fields.named("target_activation")?;
        let target_generation_raw = fields.named("target_generation")?;
        let captured_owner_state_raw = fields.named("captured_owner_state")?;
        let captured_control_raw = fields.named("captured_control")?;
        let captured_journal_raw = fields.named("captured_journal")?;
        let mapping_raw = fields.named("mapping")?;
        let restore_commit_raw = fields.named("restore_commit")?;
        let context_digest_raw = fields.named("context_digest")?;
        let local_cursor_raw = fields.named("local_cursor")?;
        let inventory_hash_raw = fields.named("inventory_hash")?;
        let physical_gate_held_raw = fields.named("physical_gate_held")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let native_pid = <Plain17<U64> as CurrentField17>::read(native_pid_raw, ledger, build)?;
        let target_world = <Plain17<crucible_node_format::HashRef> as CurrentField17>::read(
            target_world_raw,
            ledger,
            build,
        )?;
        let target_owner = <Plain17<Id> as CurrentField17>::read(target_owner_raw, ledger, build)?;
        let target_owner_binding =
            <Plain17<crucible_node_format::HashRef> as CurrentField17>::read(
                target_owner_binding_raw,
                ledger,
                build,
            )?;
        let target_activation =
            <Plain17<Id> as CurrentField17>::read(target_activation_raw, ledger, build)?;
        let target_generation =
            <Plain17<U64> as CurrentField17>::read(target_generation_raw, ledger, build)?;
        let captured_owner_state =
            <Plain17<ContentRef> as CurrentField17>::read(captured_owner_state_raw, ledger, build)?;
        let captured_control =
            <Plain17<ContentRef> as CurrentField17>::read(captured_control_raw, ledger, build)?;
        let captured_journal =
            <Plain17<ContentRef> as CurrentField17>::read(captured_journal_raw, ledger, build)?;
        let mapping = <Plain17<ContentRef> as CurrentField17>::read(mapping_raw, ledger, build)?;
        let restore_commit =
            <Plain17<ContentRef> as CurrentField17>::read(restore_commit_raw, ledger, build)?;
        let context_digest =
            <Plain17<Bytes> as CurrentField17>::read(context_digest_raw, ledger, build)?;
        let local_cursor =
            <Plain17<Position> as CurrentField17>::read(local_cursor_raw, ledger, build)?;
        let inventory_hash = <Plain17<crucible_node_format::HashRef> as CurrentField17>::read(
            inventory_hash_raw,
            ledger,
            build,
        )?;
        let physical_gate_held =
            <Plain17<bool> as CurrentField17>::read(physical_gate_held_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            native_pid: native_pid.ok_or_else(invalid)?,
            target_world: target_world.ok_or_else(invalid)?,
            target_owner: target_owner.ok_or_else(invalid)?,
            target_owner_binding: target_owner_binding.ok_or_else(invalid)?,
            target_activation: target_activation.ok_or_else(invalid)?,
            target_generation: target_generation.ok_or_else(invalid)?,
            captured_owner_state: captured_owner_state.ok_or_else(invalid)?,
            captured_control: captured_control.ok_or_else(invalid)?,
            captured_journal: captured_journal.ok_or_else(invalid)?,
            mapping: mapping.ok_or_else(invalid)?,
            restore_commit: restore_commit.ok_or_else(invalid)?,
            context_digest: context_digest.ok_or_else(invalid)?,
            local_cursor: local_cursor.ok_or_else(invalid)?,
            inventory_hash: inventory_hash.ok_or_else(invalid)?,
            physical_gate_held: physical_gate_held.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            native_pid,
            target_world,
            target_owner,
            target_owner_binding,
            target_activation,
            target_generation,
            captured_owner_state,
            captured_control,
            captured_journal,
            mapping,
            restore_commit,
            context_digest,
            local_cursor,
            inventory_hash,
            physical_gate_held,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <Plain17<U64> as CurrentField17>::observe(native_pid, observer)?;
        <Plain17<crucible_node_format::HashRef> as CurrentField17>::observe(
            target_world,
            observer,
        )?;
        <Plain17<Id> as CurrentField17>::observe(target_owner, observer)?;
        <Plain17<crucible_node_format::HashRef> as CurrentField17>::observe(
            target_owner_binding,
            observer,
        )?;
        <Plain17<Id> as CurrentField17>::observe(target_activation, observer)?;
        <Plain17<U64> as CurrentField17>::observe(target_generation, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(captured_owner_state, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(captured_control, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(captured_journal, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(mapping, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(restore_commit, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(context_digest, observer)?;
        <Plain17<Position> as CurrentField17>::observe(local_cursor, observer)?;
        <Plain17<crucible_node_format::HashRef> as CurrentField17>::observe(
            inventory_hash,
            observer,
        )?;
        <Plain17<bool> as CurrentField17>::observe(physical_gate_held, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for InstalledContent {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let reference_raw = fields.named("reference")?;
        let bytes_raw = fields.named("bytes")?;
        fields.finish()?;

        let reference =
            <Plain17<ContentRef> as CurrentField17>::read(reference_raw, ledger, build)?;
        let bytes = <Plain17<Bytes> as CurrentField17>::read(bytes_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            reference: reference.ok_or_else(invalid)?,
            bytes: bytes.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self { reference, bytes } = self;
        <Plain17<ContentRef> as CurrentField17>::observe(reference, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(bytes, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredSuffixReservationData {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let maximum_originals_raw = fields.named("maximum_originals")?;
        let ingress_raw = fields.named("ingress")?;
        let actions_raw = fields.named("actions")?;
        fields.finish()?;

        let maximum_originals =
            <Plain17<U64> as CurrentField17>::read(maximum_originals_raw, ledger, build)?;
        let ingress = <ScalarRow17 as CurrentField17>::read(ingress_raw, ledger, build)?;
        let actions = <ScalarRow17 as CurrentField17>::read(actions_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            maximum_originals: maximum_originals.ok_or_else(invalid)?,
            ingress: ingress.ok_or_else(invalid)?,
            actions: actions.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            maximum_originals,
            ingress,
            actions,
        } = self;
        <Plain17<U64> as CurrentField17>::observe(maximum_originals, observer)?;
        <ScalarRow17 as CurrentField17>::observe(ingress, observer)?;
        <ScalarRow17 as CurrentField17>::observe(actions, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredSettledNativeCarrierData {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let version_raw = fields.named("version")?;
        let launch_identity_raw = fields.named("launch_identity")?;
        let import_identity_raw = fields.named("import_identity")?;
        let normalization_maximum_raw = fields.named("normalization_maximum")?;
        let maximum_originals_raw = fields.named("maximum_originals")?;
        let ingress_raw = fields.named("ingress")?;
        let actions_raw = fields.named("actions")?;
        let output_limits_raw = fields.named("output_limits")?;
        fields.finish()?;

        let version = <Plain17<U64> as CurrentField17>::read(version_raw, ledger, build)?;
        let launch_identity =
            <FixedArray32Field17 as CurrentField17>::read(launch_identity_raw, ledger, build)?;
        let import_identity =
            <FixedArray32Field17 as CurrentField17>::read(import_identity_raw, ledger, build)?;
        let normalization_maximum =
            <Plain17<U64> as CurrentField17>::read(normalization_maximum_raw, ledger, build)?;
        let maximum_originals =
            <Plain17<U64> as CurrentField17>::read(maximum_originals_raw, ledger, build)?;
        let ingress = <ScalarRow17 as CurrentField17>::read(ingress_raw, ledger, build)?;
        let actions = <ScalarRow17 as CurrentField17>::read(actions_raw, ledger, build)?;
        let output_limits =
            <CurrentDto17<PacketRestoredSettledCaptureOutputLimits> as CurrentField17>::read(
                output_limits_raw,
                ledger,
                build,
            )?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            version: version.ok_or_else(invalid)?,
            launch_identity: launch_identity.ok_or_else(invalid)?,
            import_identity: import_identity.ok_or_else(invalid)?,
            normalization_maximum: normalization_maximum.ok_or_else(invalid)?,
            maximum_originals: maximum_originals.ok_or_else(invalid)?,
            ingress: ingress.ok_or_else(invalid)?,
            actions: actions.ok_or_else(invalid)?,
            output_limits: output_limits.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            version,
            launch_identity,
            import_identity,
            normalization_maximum,
            maximum_originals,
            ingress,
            actions,
            output_limits,
        } = self;
        <Plain17<U64> as CurrentField17>::observe(version, observer)?;
        <FixedArray32Field17 as CurrentField17>::observe(launch_identity, observer)?;
        <FixedArray32Field17 as CurrentField17>::observe(import_identity, observer)?;
        <Plain17<U64> as CurrentField17>::observe(normalization_maximum, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_originals, observer)?;
        <ScalarRow17 as CurrentField17>::observe(ingress, observer)?;
        <ScalarRow17 as CurrentField17>::observe(actions, observer)?;
        <CurrentDto17<PacketRestoredSettledCaptureOutputLimits> as CurrentField17>::observe(
            output_limits,
            observer,
        )?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredSettledNativeExistingRowsData {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let native_birth_raw = fields.named("native_birth")?;
        let restore_prepare_raw = fields.named("restore_prepare")?;
        let suffix_raw = fields.named("suffix")?;
        fields.finish()?;

        let native_birth = <ScalarRow17 as CurrentField17>::read(native_birth_raw, ledger, build)?;
        let restore_prepare =
            <Optional17<ScalarRow17> as CurrentField17>::read(restore_prepare_raw, ledger, build)?;
        let suffix = <CurrentDto17<PacketRestoredSuffixReservationData> as CurrentField17>::read(
            suffix_raw, ledger, build,
        )?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            native_birth: native_birth.ok_or_else(invalid)?,
            restore_prepare: restore_prepare.ok_or_else(invalid)?,
            suffix: suffix.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            native_birth,
            restore_prepare,
            suffix,
        } = self;
        <ScalarRow17 as CurrentField17>::observe(native_birth, observer)?;
        <Optional17<ScalarRow17> as CurrentField17>::observe(restore_prepare, observer)?;
        <CurrentDto17<PacketRestoredSuffixReservationData> as CurrentField17>::observe(
            suffix, observer,
        )?;
        Ok(())
    }
}

impl CurrentContract17 for PacketNative5StorageSelection {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let storage_raw = fields.named("storage")?;
        let limits_raw = fields.named("limits")?;
        fields.finish()?;

        let storage = <CurrentDto17<PacketNative5StorageLimits> as CurrentField17>::read(
            storage_raw,
            ledger,
            build,
        )?;
        let limits = <Plain17<Limits> as CurrentField17>::read(limits_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            storage: storage.ok_or_else(invalid)?,
            limits: limits.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self { storage, limits } = self;
        <CurrentDto17<PacketNative5StorageLimits> as CurrentField17>::observe(storage, observer)?;
        <Plain17<Limits> as CurrentField17>::observe(limits, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketConnectedNativeRecord {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let native_pid_raw = fields.named("native_pid")?;
        let original_raw = fields.named("original")?;
        let inventory_raw = fields.named("inventory")?;
        let grant_raw = fields.named("grant")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let native_pid = <Plain17<U64> as CurrentField17>::read(native_pid_raw, ledger, build)?;
        let original = <Plain17<Envelope> as CurrentField17>::read(original_raw, ledger, build)?;
        let inventory = <Plain17<PacketConnectedInventory> as CurrentField17>::read(
            inventory_raw,
            ledger,
            build,
        )?;
        let grant = <Plain17<Option<PacketConnectedGrant>> as CurrentField17>::read(
            grant_raw, ledger, build,
        )?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            native_pid: native_pid.ok_or_else(invalid)?,
            original: original.ok_or_else(invalid)?,
            inventory: inventory.ok_or_else(invalid)?,
            grant: grant.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            native_pid,
            original,
            inventory,
            grant,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <Plain17<U64> as CurrentField17>::observe(native_pid, observer)?;
        <Plain17<Envelope> as CurrentField17>::observe(original, observer)?;
        <Plain17<PacketConnectedInventory> as CurrentField17>::observe(inventory, observer)?;
        <Plain17<Option<PacketConnectedGrant>> as CurrentField17>::observe(grant, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketNativeRestoredRecord {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let native_receipt_raw = fields.named("native_receipt")?;
        let captured_owner_state_raw = fields.named("captured_owner_state")?;
        let captured_journal_raw = fields.named("captured_journal")?;
        let mapping_raw = fields.named("mapping")?;
        let restore_commit_raw = fields.named("restore_commit")?;
        let restore_response_raw = fields.named("restore_response")?;
        let context_digest_raw = fields.named("context_digest")?;
        let physical_gate_held_raw = fields.named("physical_gate_held")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let native_receipt = <CurrentDto17<PacketNative5Record> as CurrentField17>::read(
            native_receipt_raw,
            ledger,
            build,
        )?;
        let captured_owner_state =
            <Plain17<ContentRef> as CurrentField17>::read(captured_owner_state_raw, ledger, build)?;
        let captured_journal =
            <Plain17<ContentRef> as CurrentField17>::read(captured_journal_raw, ledger, build)?;
        let mapping = <Plain17<ContentRef> as CurrentField17>::read(mapping_raw, ledger, build)?;
        let restore_commit =
            <Plain17<ContentRef> as CurrentField17>::read(restore_commit_raw, ledger, build)?;
        let restore_response =
            <Plain17<ContentRef> as CurrentField17>::read(restore_response_raw, ledger, build)?;
        let context_digest =
            <Plain17<Bytes> as CurrentField17>::read(context_digest_raw, ledger, build)?;
        let physical_gate_held =
            <Plain17<bool> as CurrentField17>::read(physical_gate_held_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            native_receipt: native_receipt.ok_or_else(invalid)?,
            captured_owner_state: captured_owner_state.ok_or_else(invalid)?,
            captured_journal: captured_journal.ok_or_else(invalid)?,
            mapping: mapping.ok_or_else(invalid)?,
            restore_commit: restore_commit.ok_or_else(invalid)?,
            restore_response: restore_response.ok_or_else(invalid)?,
            context_digest: context_digest.ok_or_else(invalid)?,
            physical_gate_held: physical_gate_held.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            native_receipt,
            captured_owner_state,
            captured_journal,
            mapping,
            restore_commit,
            restore_response,
            context_digest,
            physical_gate_held,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <CurrentDto17<PacketNative5Record> as CurrentField17>::observe(native_receipt, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(captured_owner_state, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(captured_journal, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(mapping, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(restore_commit, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(restore_response, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(context_digest, observer)?;
        <Plain17<bool> as CurrentField17>::observe(physical_gate_held, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketProgramDefinition {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let events_raw = fields.named("events")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let events =
            <Plain17<Vec<PacketEvent>> as CurrentField17>::read(events_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            events: events.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self { schema, events } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <Plain17<Vec<PacketEvent>> as CurrentField17>::observe(events, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketNative5StorageLimits {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let snapshot_bytes_raw = fields.named("snapshot_bytes")?;
        let control_snapshot_bytes_raw = fields.named("control_snapshot_bytes")?;
        let protocol_snapshot_bytes_raw = fields.named("protocol_snapshot_bytes")?;
        let frame_bank_bytes_raw = fields.named("frame_bank_bytes")?;
        let frames_per_direction_raw = fields.named("frames_per_direction")?;
        let hello_bytes_raw = fields.named("hello_bytes")?;
        let settlement_bytes_raw = fields.named("settlement_bytes")?;
        fields.finish()?;

        let snapshot_bytes =
            <Plain17<U64> as CurrentField17>::read(snapshot_bytes_raw, ledger, build)?;
        let control_snapshot_bytes =
            <Plain17<U64> as CurrentField17>::read(control_snapshot_bytes_raw, ledger, build)?;
        let protocol_snapshot_bytes =
            <Plain17<U64> as CurrentField17>::read(protocol_snapshot_bytes_raw, ledger, build)?;
        let frame_bank_bytes =
            <Plain17<U64> as CurrentField17>::read(frame_bank_bytes_raw, ledger, build)?;
        let frames_per_direction =
            <Plain17<U64> as CurrentField17>::read(frames_per_direction_raw, ledger, build)?;
        let hello_bytes = <Plain17<U64> as CurrentField17>::read(hello_bytes_raw, ledger, build)?;
        let settlement_bytes =
            <Plain17<U64> as CurrentField17>::read(settlement_bytes_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            snapshot_bytes: snapshot_bytes.ok_or_else(invalid)?,
            control_snapshot_bytes: control_snapshot_bytes.ok_or_else(invalid)?,
            protocol_snapshot_bytes: protocol_snapshot_bytes.ok_or_else(invalid)?,
            frame_bank_bytes: frame_bank_bytes.ok_or_else(invalid)?,
            frames_per_direction: frames_per_direction.ok_or_else(invalid)?,
            hello_bytes: hello_bytes.ok_or_else(invalid)?,
            settlement_bytes: settlement_bytes.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            snapshot_bytes,
            control_snapshot_bytes,
            protocol_snapshot_bytes,
            frame_bank_bytes,
            frames_per_direction,
            hello_bytes,
            settlement_bytes,
        } = self;
        <Plain17<U64> as CurrentField17>::observe(snapshot_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(control_snapshot_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(protocol_snapshot_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(frame_bank_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(frames_per_direction, observer)?;
        <Plain17<U64> as CurrentField17>::observe(hello_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(settlement_bytes, observer)?;
        Ok(())
    }
}
