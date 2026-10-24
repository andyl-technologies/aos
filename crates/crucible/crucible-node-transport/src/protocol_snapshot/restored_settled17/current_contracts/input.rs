//! Reads the defining input DTO fields in their actual emitted order.

use super::*;

impl CurrentContract17 for PacketInputCut {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_version_raw = fields.named("schema_version")?;
        let session_id_raw = fields.named("session_id")?;
        let incarnation_id_raw = fields.named("incarnation_id")?;
        let node_id_raw = fields.named("node_id")?;
        let execution_owner_id_raw = fields.named("execution_owner_id")?;
        let owner_generation_raw = fields.named("owner_generation")?;
        let activation_id_raw = fields.named("activation_id")?;
        let world_generation_raw = fields.named("world_generation")?;
        let world_binding_hash_raw = fields.named("world_binding_hash")?;
        let stage_operation_id_raw = fields.named("stage_operation_id")?;
        let batch_id_raw = fields.named("batch_id")?;
        let batch_sequence_raw = fields.named("batch_sequence")?;
        let input_epoch_raw = fields.named("input_epoch")?;
        let batch_hash_raw = fields.named("batch_hash")?;
        let delivery_inventory_raw = fields.named("delivery_inventory")?;
        let cutoff_raw = fields.named("cutoff")?;
        fields.finish()?;

        let schema_version =
            <Plain17<u16> as CurrentField17>::read(schema_version_raw, ledger, build)?;
        let session_id = <Plain17<Id> as CurrentField17>::read(session_id_raw, ledger, build)?;
        let incarnation_id =
            <Plain17<Id> as CurrentField17>::read(incarnation_id_raw, ledger, build)?;
        let node_id = <Plain17<Id> as CurrentField17>::read(node_id_raw, ledger, build)?;
        let execution_owner_id =
            <Plain17<Id> as CurrentField17>::read(execution_owner_id_raw, ledger, build)?;
        let owner_generation =
            <Plain17<U64> as CurrentField17>::read(owner_generation_raw, ledger, build)?;
        let activation_id =
            <Plain17<Id> as CurrentField17>::read(activation_id_raw, ledger, build)?;
        let world_generation =
            <Plain17<U64> as CurrentField17>::read(world_generation_raw, ledger, build)?;
        let world_binding_hash =
            <Plain17<HashRef> as CurrentField17>::read(world_binding_hash_raw, ledger, build)?;
        let stage_operation_id =
            <Plain17<Id> as CurrentField17>::read(stage_operation_id_raw, ledger, build)?;
        let batch_id = <Plain17<Id> as CurrentField17>::read(batch_id_raw, ledger, build)?;
        let batch_sequence =
            <Plain17<U64> as CurrentField17>::read(batch_sequence_raw, ledger, build)?;
        let input_epoch = <Plain17<Id> as CurrentField17>::read(input_epoch_raw, ledger, build)?;
        let batch_hash = <Plain17<HashRef> as CurrentField17>::read(batch_hash_raw, ledger, build)?;
        let delivery_inventory =
            <Plain17<ContentRef> as CurrentField17>::read(delivery_inventory_raw, ledger, build)?;
        let cutoff = <Plain17<Position> as CurrentField17>::read(cutoff_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema_version: schema_version.ok_or_else(invalid)?,
            session_id: session_id.ok_or_else(invalid)?,
            incarnation_id: incarnation_id.ok_or_else(invalid)?,
            node_id: node_id.ok_or_else(invalid)?,
            execution_owner_id: execution_owner_id.ok_or_else(invalid)?,
            owner_generation: owner_generation.ok_or_else(invalid)?,
            activation_id: activation_id.ok_or_else(invalid)?,
            world_generation: world_generation.ok_or_else(invalid)?,
            world_binding_hash: world_binding_hash.ok_or_else(invalid)?,
            stage_operation_id: stage_operation_id.ok_or_else(invalid)?,
            batch_id: batch_id.ok_or_else(invalid)?,
            batch_sequence: batch_sequence.ok_or_else(invalid)?,
            input_epoch: input_epoch.ok_or_else(invalid)?,
            batch_hash: batch_hash.ok_or_else(invalid)?,
            delivery_inventory: delivery_inventory.ok_or_else(invalid)?,
            cutoff: cutoff.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema_version,
            session_id,
            incarnation_id,
            node_id,
            execution_owner_id,
            owner_generation,
            activation_id,
            world_generation,
            world_binding_hash,
            stage_operation_id,
            batch_id,
            batch_sequence,
            input_epoch,
            batch_hash,
            delivery_inventory,
            cutoff,
        } = self;
        <Plain17<u16> as CurrentField17>::observe(schema_version, observer)?;
        <Plain17<Id> as CurrentField17>::observe(session_id, observer)?;
        <Plain17<Id> as CurrentField17>::observe(incarnation_id, observer)?;
        <Plain17<Id> as CurrentField17>::observe(node_id, observer)?;
        <Plain17<Id> as CurrentField17>::observe(execution_owner_id, observer)?;
        <Plain17<U64> as CurrentField17>::observe(owner_generation, observer)?;
        <Plain17<Id> as CurrentField17>::observe(activation_id, observer)?;
        <Plain17<U64> as CurrentField17>::observe(world_generation, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(world_binding_hash, observer)?;
        <Plain17<Id> as CurrentField17>::observe(stage_operation_id, observer)?;
        <Plain17<Id> as CurrentField17>::observe(batch_id, observer)?;
        <Plain17<U64> as CurrentField17>::observe(batch_sequence, observer)?;
        <Plain17<Id> as CurrentField17>::observe(input_epoch, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(batch_hash, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(delivery_inventory, observer)?;
        <Plain17<Position> as CurrentField17>::observe(cutoff, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredInputReactive17Request {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let command_raw = fields.named("command")?;
        let scope_raw = fields.named("scope")?;
        let first_observation_raw = fields.named("first_observation")?;
        let current_record_raw = fields.named("current_record")?;
        let current_model_raw = fields.named("current_model")?;
        let history_prefix_raw = fields.named("history_prefix")?;
        let history_next_sequence_raw = fields.named("history_next_sequence")?;
        let native_allocation_raw = fields.named("native_allocation")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let command = <CurrentInputCommand17 as CurrentField17>::read(command_raw, ledger, build)?;
        let scope = <CurrentDto17<PacketRestorationActivationScope> as CurrentField17>::read(
            scope_raw, ledger, build,
        )?;
        let first_observation =
            <Plain17<ContentRef> as CurrentField17>::read(first_observation_raw, ledger, build)?;
        let current_record =
            <Plain17<ContentRef> as CurrentField17>::read(current_record_raw, ledger, build)?;
        let current_model =
            <Plain17<ContentRef> as CurrentField17>::read(current_model_raw, ledger, build)?;
        let history_prefix =
            <Plain17<ContentRef> as CurrentField17>::read(history_prefix_raw, ledger, build)?;
        let history_next_sequence =
            <Plain17<U64> as CurrentField17>::read(history_next_sequence_raw, ledger, build)?;
        let native_allocation =
            <ScalarRow17 as CurrentField17>::read(native_allocation_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            command: command.ok_or_else(invalid)?,
            scope: scope.ok_or_else(invalid)?,
            first_observation: first_observation.ok_or_else(invalid)?,
            current_record: current_record.ok_or_else(invalid)?,
            current_model: current_model.ok_or_else(invalid)?,
            history_prefix: history_prefix.ok_or_else(invalid)?,
            history_next_sequence: history_next_sequence.ok_or_else(invalid)?,
            native_allocation: native_allocation.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            command,
            scope,
            first_observation,
            current_record,
            current_model,
            history_prefix,
            history_next_sequence,
            native_allocation,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <CurrentInputCommand17 as CurrentField17>::observe(command, observer)?;
        <CurrentDto17<PacketRestorationActivationScope> as CurrentField17>::observe(
            scope, observer,
        )?;
        <Plain17<ContentRef> as CurrentField17>::observe(first_observation, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(current_record, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(current_model, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(history_prefix, observer)?;
        <Plain17<U64> as CurrentField17>::observe(history_next_sequence, observer)?;
        <ScalarRow17 as CurrentField17>::observe(native_allocation, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredInputReactive17Context {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let request_raw = fields.named("request")?;
        let assigned_request_raw = fields.named("assigned_request")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let request = <CurrentDto17<PacketRestoredInputReactive17Request> as CurrentField17>::read(
            request_raw,
            ledger,
            build,
        )?;
        let assigned_request =
            <Plain17<Bytes> as CurrentField17>::read(assigned_request_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            request: request.ok_or_else(invalid)?,
            assigned_request: assigned_request.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            request,
            assigned_request,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <CurrentDto17<PacketRestoredInputReactive17Request> as CurrentField17>::observe(
            request, observer,
        )?;
        <Plain17<Bytes> as CurrentField17>::observe(assigned_request, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredInputReactive17Artifact {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let request_raw = fields.named("request")?;
        let proof_raw = fields.named("proof")?;
        fields.finish()?;

        let request = <CurrentDto17<PacketRestoredInputReactive17Request> as CurrentField17>::read(
            request_raw,
            ledger,
            build,
        )?;
        let proof = <CurrentDto17<PacketRestorationActivationProof> as CurrentField17>::read(
            proof_raw, ledger, build,
        )?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            request: request.ok_or_else(invalid)?,
            proof: proof.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self { request, proof } = self;
        <CurrentDto17<PacketRestoredInputReactive17Request> as CurrentField17>::observe(
            request, observer,
        )?;
        <CurrentDto17<PacketRestorationActivationProof> as CurrentField17>::observe(
            proof, observer,
        )?;
        Ok(())
    }
}
