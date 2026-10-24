//! Reads the defining restore DTO fields in their actual emitted order.

use super::*;

impl CurrentContract17 for PacketCompleteRestoreRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let archive_index_raw = fields.named("archive_index")?;
        let capture_manifest_raw = fields.named("capture_manifest")?;
        let owner_state_raw = fields.named("owner_state")?;
        let journal_raw = fields.named("journal")?;
        let source_runtime_raw = fields.named("source_runtime")?;
        let backend_implementation_raw = fields.named("backend_implementation")?;
        let backend_schema_raw = fields.named("backend_schema")?;
        let archived_cut_raw = fields.named("archived_cut")?;
        let archived_ordinal_raw = fields.named("archived_ordinal")?;
        let target_world_raw = fields.named("target_world")?;
        let target_owner_raw = fields.named("target_owner")?;
        let target_owner_binding_raw = fields.named("target_owner_binding")?;
        let target_activation_raw = fields.named("target_activation")?;
        let target_generation_raw = fields.named("target_generation")?;
        let target_owner_generation_raw = fields.named("target_owner_generation")?;
        let mapping_raw = fields.named("mapping")?;
        let nonce_raw = fields.named("nonce")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let archive_index =
            <Plain17<ContentRef> as CurrentField17>::read(archive_index_raw, ledger, build)?;
        let capture_manifest =
            <Plain17<ContentRef> as CurrentField17>::read(capture_manifest_raw, ledger, build)?;
        let owner_state =
            <Plain17<ContentRef> as CurrentField17>::read(owner_state_raw, ledger, build)?;
        let journal = <Plain17<ContentRef> as CurrentField17>::read(journal_raw, ledger, build)?;
        let source_runtime =
            <Plain17<ContentRef> as CurrentField17>::read(source_runtime_raw, ledger, build)?;
        let backend_implementation = <Plain17<ContentRef> as CurrentField17>::read(
            backend_implementation_raw,
            ledger,
            build,
        )?;
        let backend_schema =
            <Plain17<SchemaRef> as CurrentField17>::read(backend_schema_raw, ledger, build)?;
        let archived_cut =
            <Plain17<Position> as CurrentField17>::read(archived_cut_raw, ledger, build)?;
        let archived_ordinal =
            <Plain17<U64> as CurrentField17>::read(archived_ordinal_raw, ledger, build)?;
        let target_world =
            <Plain17<HashRef> as CurrentField17>::read(target_world_raw, ledger, build)?;
        let target_owner = <Plain17<Id> as CurrentField17>::read(target_owner_raw, ledger, build)?;
        let target_owner_binding =
            <Plain17<HashRef> as CurrentField17>::read(target_owner_binding_raw, ledger, build)?;
        let target_activation =
            <Plain17<Id> as CurrentField17>::read(target_activation_raw, ledger, build)?;
        let target_generation =
            <Plain17<U64> as CurrentField17>::read(target_generation_raw, ledger, build)?;
        let target_owner_generation =
            <Plain17<U64> as CurrentField17>::read(target_owner_generation_raw, ledger, build)?;
        let mapping = <Plain17<ContentRef> as CurrentField17>::read(mapping_raw, ledger, build)?;
        let nonce = <Plain17<Bytes> as CurrentField17>::read(nonce_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            archive_index: archive_index.ok_or_else(invalid)?,
            capture_manifest: capture_manifest.ok_or_else(invalid)?,
            owner_state: owner_state.ok_or_else(invalid)?,
            journal: journal.ok_or_else(invalid)?,
            source_runtime: source_runtime.ok_or_else(invalid)?,
            backend_implementation: backend_implementation.ok_or_else(invalid)?,
            backend_schema: backend_schema.ok_or_else(invalid)?,
            archived_cut: archived_cut.ok_or_else(invalid)?,
            archived_ordinal: archived_ordinal.ok_or_else(invalid)?,
            target_world: target_world.ok_or_else(invalid)?,
            target_owner: target_owner.ok_or_else(invalid)?,
            target_owner_binding: target_owner_binding.ok_or_else(invalid)?,
            target_activation: target_activation.ok_or_else(invalid)?,
            target_generation: target_generation.ok_or_else(invalid)?,
            target_owner_generation: target_owner_generation.ok_or_else(invalid)?,
            mapping: mapping.ok_or_else(invalid)?,
            nonce: nonce.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            archive_index,
            capture_manifest,
            owner_state,
            journal,
            source_runtime,
            backend_implementation,
            backend_schema,
            archived_cut,
            archived_ordinal,
            target_world,
            target_owner,
            target_owner_binding,
            target_activation,
            target_generation,
            target_owner_generation,
            mapping,
            nonce,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(archive_index, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(capture_manifest, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(owner_state, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(journal, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(source_runtime, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(backend_implementation, observer)?;
        <Plain17<SchemaRef> as CurrentField17>::observe(backend_schema, observer)?;
        <Plain17<Position> as CurrentField17>::observe(archived_cut, observer)?;
        <Plain17<U64> as CurrentField17>::observe(archived_ordinal, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(target_world, observer)?;
        <Plain17<Id> as CurrentField17>::observe(target_owner, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(target_owner_binding, observer)?;
        <Plain17<Id> as CurrentField17>::observe(target_activation, observer)?;
        <Plain17<U64> as CurrentField17>::observe(target_generation, observer)?;
        <Plain17<U64> as CurrentField17>::observe(target_owner_generation, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(mapping, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(nonce, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketCompleteRestoreContext {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let algorithm_raw = fields.named("algorithm")?;
        let source_birth_raw = fields.named("source_birth")?;
        let kernel_binding_raw = fields.named("kernel_binding")?;
        let policy_binding_raw = fields.named("policy_binding")?;
        let host_registration_raw = fields.named("host_registration")?;
        let native_registration_raw = fields.named("native_registration")?;
        let hello_request_raw = fields.named("hello_request")?;
        let hello_response_raw = fields.named("hello_response")?;
        let assigned_restore_raw = fields.named("assigned_restore")?;
        let archive_binding_raw = fields.named("archive_binding")?;
        let target_binding_raw = fields.named("target_binding")?;
        let mapping_binding_raw = fields.named("mapping_binding")?;
        let request_binding_raw = fields.named("request_binding")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let algorithm = <Plain17<String> as CurrentField17>::read(algorithm_raw, ledger, build)?;
        let source_birth =
            <Plain17<Bytes> as CurrentField17>::read(source_birth_raw, ledger, build)?;
        let kernel_binding =
            <Plain17<Bytes> as CurrentField17>::read(kernel_binding_raw, ledger, build)?;
        let policy_binding =
            <Plain17<Bytes> as CurrentField17>::read(policy_binding_raw, ledger, build)?;
        let host_registration =
            <Plain17<Bytes> as CurrentField17>::read(host_registration_raw, ledger, build)?;
        let native_registration =
            <Plain17<Bytes> as CurrentField17>::read(native_registration_raw, ledger, build)?;
        let hello_request =
            <Plain17<Bytes> as CurrentField17>::read(hello_request_raw, ledger, build)?;
        let hello_response =
            <Plain17<Bytes> as CurrentField17>::read(hello_response_raw, ledger, build)?;
        let assigned_restore =
            <Plain17<Bytes> as CurrentField17>::read(assigned_restore_raw, ledger, build)?;
        let archive_binding =
            <Plain17<Bytes> as CurrentField17>::read(archive_binding_raw, ledger, build)?;
        let target_binding =
            <Plain17<Bytes> as CurrentField17>::read(target_binding_raw, ledger, build)?;
        let mapping_binding =
            <Plain17<Bytes> as CurrentField17>::read(mapping_binding_raw, ledger, build)?;
        let request_binding =
            <Plain17<Bytes> as CurrentField17>::read(request_binding_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            algorithm: algorithm.ok_or_else(invalid)?,
            source_birth: source_birth.ok_or_else(invalid)?,
            kernel_binding: kernel_binding.ok_or_else(invalid)?,
            policy_binding: policy_binding.ok_or_else(invalid)?,
            host_registration: host_registration.ok_or_else(invalid)?,
            native_registration: native_registration.ok_or_else(invalid)?,
            hello_request: hello_request.ok_or_else(invalid)?,
            hello_response: hello_response.ok_or_else(invalid)?,
            assigned_restore: assigned_restore.ok_or_else(invalid)?,
            archive_binding: archive_binding.ok_or_else(invalid)?,
            target_binding: target_binding.ok_or_else(invalid)?,
            mapping_binding: mapping_binding.ok_or_else(invalid)?,
            request_binding: request_binding.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            algorithm,
            source_birth,
            kernel_binding,
            policy_binding,
            host_registration,
            native_registration,
            hello_request,
            hello_response,
            assigned_restore,
            archive_binding,
            target_binding,
            mapping_binding,
            request_binding,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <Plain17<String> as CurrentField17>::observe(algorithm, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(source_birth, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(kernel_binding, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(policy_binding, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(host_registration, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(native_registration, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(hello_request, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(hello_response, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(assigned_restore, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(archive_binding, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(target_binding, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(mapping_binding, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(request_binding, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketCompleteRestoreInputAllocation {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let maximum_known_requested_bytes_raw = fields.named("maximum_known_requested_bytes")?;
        let maximum_input_bytes_raw = fields.named("maximum_input_bytes")?;
        let maximum_nodes_raw = fields.named("maximum_nodes")?;
        let maximum_depth_raw = fields.named("maximum_depth")?;
        let maximum_owned_backing_bytes_raw = fields.named("maximum_owned_backing_bytes")?;
        let maximum_tree_entries_raw = fields.named("maximum_tree_entries")?;
        let maximum_metadata_rows_raw = fields.named("maximum_metadata_rows")?;
        let maximum_literal_backing_bytes_raw = fields.named("maximum_literal_backing_bytes")?;
        let maximum_content_transfers_raw = fields.named("maximum_content_transfers")?;
        let maximum_content_objects_raw = fields.named("maximum_content_objects")?;
        let maximum_content_groups_raw = fields.named("maximum_content_groups")?;
        let maximum_content_bytes_raw = fields.named("maximum_content_bytes")?;
        let maximum_content_metadata_bytes_raw = fields.named("maximum_content_metadata_bytes")?;
        let maximum_model_bytes_raw = fields.named("maximum_model_bytes")?;
        fields.finish()?;

        let maximum_known_requested_bytes = <Plain17<U64> as CurrentField17>::read(
            maximum_known_requested_bytes_raw,
            ledger,
            build,
        )?;
        let maximum_input_bytes =
            <Plain17<U64> as CurrentField17>::read(maximum_input_bytes_raw, ledger, build)?;
        let maximum_nodes =
            <Plain17<U64> as CurrentField17>::read(maximum_nodes_raw, ledger, build)?;
        let maximum_depth =
            <Plain17<U64> as CurrentField17>::read(maximum_depth_raw, ledger, build)?;
        let maximum_owned_backing_bytes =
            <Plain17<U64> as CurrentField17>::read(maximum_owned_backing_bytes_raw, ledger, build)?;
        let maximum_tree_entries =
            <Plain17<U64> as CurrentField17>::read(maximum_tree_entries_raw, ledger, build)?;
        let maximum_metadata_rows =
            <Plain17<U64> as CurrentField17>::read(maximum_metadata_rows_raw, ledger, build)?;
        let maximum_literal_backing_bytes = <Plain17<U64> as CurrentField17>::read(
            maximum_literal_backing_bytes_raw,
            ledger,
            build,
        )?;
        let maximum_content_transfers =
            <Plain17<U64> as CurrentField17>::read(maximum_content_transfers_raw, ledger, build)?;
        let maximum_content_objects =
            <Plain17<U64> as CurrentField17>::read(maximum_content_objects_raw, ledger, build)?;
        let maximum_content_groups =
            <Plain17<U64> as CurrentField17>::read(maximum_content_groups_raw, ledger, build)?;
        let maximum_content_bytes =
            <Plain17<U64> as CurrentField17>::read(maximum_content_bytes_raw, ledger, build)?;
        let maximum_content_metadata_bytes = <Plain17<U64> as CurrentField17>::read(
            maximum_content_metadata_bytes_raw,
            ledger,
            build,
        )?;
        let maximum_model_bytes =
            <Plain17<U64> as CurrentField17>::read(maximum_model_bytes_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            maximum_known_requested_bytes: maximum_known_requested_bytes.ok_or_else(invalid)?,
            maximum_input_bytes: maximum_input_bytes.ok_or_else(invalid)?,
            maximum_nodes: maximum_nodes.ok_or_else(invalid)?,
            maximum_depth: maximum_depth.ok_or_else(invalid)?,
            maximum_owned_backing_bytes: maximum_owned_backing_bytes.ok_or_else(invalid)?,
            maximum_tree_entries: maximum_tree_entries.ok_or_else(invalid)?,
            maximum_metadata_rows: maximum_metadata_rows.ok_or_else(invalid)?,
            maximum_literal_backing_bytes: maximum_literal_backing_bytes.ok_or_else(invalid)?,
            maximum_content_transfers: maximum_content_transfers.ok_or_else(invalid)?,
            maximum_content_objects: maximum_content_objects.ok_or_else(invalid)?,
            maximum_content_groups: maximum_content_groups.ok_or_else(invalid)?,
            maximum_content_bytes: maximum_content_bytes.ok_or_else(invalid)?,
            maximum_content_metadata_bytes: maximum_content_metadata_bytes.ok_or_else(invalid)?,
            maximum_model_bytes: maximum_model_bytes.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            maximum_known_requested_bytes,
            maximum_input_bytes,
            maximum_nodes,
            maximum_depth,
            maximum_owned_backing_bytes,
            maximum_tree_entries,
            maximum_metadata_rows,
            maximum_literal_backing_bytes,
            maximum_content_transfers,
            maximum_content_objects,
            maximum_content_groups,
            maximum_content_bytes,
            maximum_content_metadata_bytes,
            maximum_model_bytes,
        } = self;
        <Plain17<U64> as CurrentField17>::observe(maximum_known_requested_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_input_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_nodes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_depth, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_owned_backing_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_tree_entries, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_metadata_rows, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_literal_backing_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_content_transfers, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_content_objects, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_content_groups, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_content_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_content_metadata_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_model_bytes, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketCompleteRestorePrepareRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let restoration_raw = fields.named("restoration")?;
        let host_protocol_raw = fields.named("host_protocol")?;
        let native_protocol_raw = fields.named("native_protocol")?;
        let native_control_raw = fields.named("native_control")?;
        let native_anchor_raw = fields.named("native_anchor")?;
        let transaction_id_raw = fields.named("transaction_id")?;
        let generation_raw = fields.named("generation")?;
        let allocation_raw = fields.named("allocation")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let restoration = <CurrentDto17<PacketCompleteRestoreRequest> as CurrentField17>::read(
            restoration_raw,
            ledger,
            build,
        )?;
        let host_protocol =
            <Plain17<ContentRef> as CurrentField17>::read(host_protocol_raw, ledger, build)?;
        let native_protocol =
            <Plain17<ContentRef> as CurrentField17>::read(native_protocol_raw, ledger, build)?;
        let native_control =
            <Plain17<ContentRef> as CurrentField17>::read(native_control_raw, ledger, build)?;
        let native_anchor =
            <Plain17<ContentRef> as CurrentField17>::read(native_anchor_raw, ledger, build)?;
        let transaction_id =
            <Plain17<Id> as CurrentField17>::read(transaction_id_raw, ledger, build)?;
        let generation = <Plain17<U64> as CurrentField17>::read(generation_raw, ledger, build)?;
        let allocation =
            <CurrentDto17<PacketCompleteRestoreInputAllocation> as CurrentField17>::read(
                allocation_raw,
                ledger,
                build,
            )?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            restoration: restoration.ok_or_else(invalid)?,
            host_protocol: host_protocol.ok_or_else(invalid)?,
            native_protocol: native_protocol.ok_or_else(invalid)?,
            native_control: native_control.ok_or_else(invalid)?,
            native_anchor: native_anchor.ok_or_else(invalid)?,
            transaction_id: transaction_id.ok_or_else(invalid)?,
            generation: generation.ok_or_else(invalid)?,
            allocation: allocation.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            restoration,
            host_protocol,
            native_protocol,
            native_control,
            native_anchor,
            transaction_id,
            generation,
            allocation,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <CurrentDto17<PacketCompleteRestoreRequest> as CurrentField17>::observe(
            restoration,
            observer,
        )?;
        <Plain17<ContentRef> as CurrentField17>::observe(host_protocol, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(native_protocol, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(native_control, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(native_anchor, observer)?;
        <Plain17<Id> as CurrentField17>::observe(transaction_id, observer)?;
        <Plain17<U64> as CurrentField17>::observe(generation, observer)?;
        <CurrentDto17<PacketCompleteRestoreInputAllocation> as CurrentField17>::observe(
            allocation, observer,
        )?;
        Ok(())
    }
}

impl CurrentContract17 for PacketCompleteRestorePrepareContext {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let algorithm_raw = fields.named("algorithm")?;
        let source_birth_raw = fields.named("source_birth")?;
        let kernel_binding_raw = fields.named("kernel_binding")?;
        let policy_binding_raw = fields.named("policy_binding")?;
        let host_registration_raw = fields.named("host_registration")?;
        let native_registration_raw = fields.named("native_registration")?;
        let hello_request_raw = fields.named("hello_request")?;
        let hello_response_raw = fields.named("hello_response")?;
        let assigned_prepare_raw = fields.named("assigned_prepare")?;
        let prepare_request_raw = fields.named("prepare_request")?;
        let input_roster_raw = fields.named("input_roster")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let algorithm = <Plain17<String> as CurrentField17>::read(algorithm_raw, ledger, build)?;
        let source_birth =
            <Plain17<Bytes> as CurrentField17>::read(source_birth_raw, ledger, build)?;
        let kernel_binding =
            <Plain17<Bytes> as CurrentField17>::read(kernel_binding_raw, ledger, build)?;
        let policy_binding =
            <Plain17<Bytes> as CurrentField17>::read(policy_binding_raw, ledger, build)?;
        let host_registration =
            <Plain17<Bytes> as CurrentField17>::read(host_registration_raw, ledger, build)?;
        let native_registration =
            <Plain17<Bytes> as CurrentField17>::read(native_registration_raw, ledger, build)?;
        let hello_request =
            <Plain17<Bytes> as CurrentField17>::read(hello_request_raw, ledger, build)?;
        let hello_response =
            <Plain17<Bytes> as CurrentField17>::read(hello_response_raw, ledger, build)?;
        let assigned_prepare =
            <Plain17<Bytes> as CurrentField17>::read(assigned_prepare_raw, ledger, build)?;
        let prepare_request =
            <Plain17<Bytes> as CurrentField17>::read(prepare_request_raw, ledger, build)?;
        let input_roster =
            <Plain17<Bytes> as CurrentField17>::read(input_roster_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            algorithm: algorithm.ok_or_else(invalid)?,
            source_birth: source_birth.ok_or_else(invalid)?,
            kernel_binding: kernel_binding.ok_or_else(invalid)?,
            policy_binding: policy_binding.ok_or_else(invalid)?,
            host_registration: host_registration.ok_or_else(invalid)?,
            native_registration: native_registration.ok_or_else(invalid)?,
            hello_request: hello_request.ok_or_else(invalid)?,
            hello_response: hello_response.ok_or_else(invalid)?,
            assigned_prepare: assigned_prepare.ok_or_else(invalid)?,
            prepare_request: prepare_request.ok_or_else(invalid)?,
            input_roster: input_roster.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            algorithm,
            source_birth,
            kernel_binding,
            policy_binding,
            host_registration,
            native_registration,
            hello_request,
            hello_response,
            assigned_prepare,
            prepare_request,
            input_roster,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <Plain17<String> as CurrentField17>::observe(algorithm, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(source_birth, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(kernel_binding, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(policy_binding, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(host_registration, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(native_registration, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(hello_request, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(hello_response, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(assigned_prepare, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(prepare_request, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(input_roster, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketCompleteRestoreTransferProof {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let algorithm_raw = fields.named("algorithm")?;
        let context_digest_raw = fields.named("context_digest")?;
        let mac_raw = fields.named("mac")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let algorithm = <Plain17<String> as CurrentField17>::read(algorithm_raw, ledger, build)?;
        let context_digest =
            <Plain17<Bytes> as CurrentField17>::read(context_digest_raw, ledger, build)?;
        let mac = <Plain17<Bytes> as CurrentField17>::read(mac_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            algorithm: algorithm.ok_or_else(invalid)?,
            context_digest: context_digest.ok_or_else(invalid)?,
            mac: mac.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            algorithm,
            context_digest,
            mac,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <Plain17<String> as CurrentField17>::observe(algorithm, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(context_digest, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(mac, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketCompleteRestoreCommitRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let prepare_raw = fields.named("prepare")?;
        let capture_terminal_raw = fields.named("capture_terminal")?;
        let prepare_request_id_raw = fields.named("prepare_request_id")?;
        let prepare_request_sequence_raw = fields.named("prepare_request_sequence")?;
        let prepare_request_digest_raw = fields.named("prepare_request_digest")?;
        let prepare_response_sequence_raw = fields.named("prepare_response_sequence")?;
        let prepare_response_digest_raw = fields.named("prepare_response_digest")?;
        let transfer_token_raw = fields.named("transfer_token")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let prepare = <CurrentDto17<PacketCompleteRestorePrepareRequest> as CurrentField17>::read(
            prepare_raw,
            ledger,
            build,
        )?;
        let capture_terminal =
            <Plain17<Envelope> as CurrentField17>::read(capture_terminal_raw, ledger, build)?;
        let prepare_request_id =
            <Plain17<Id> as CurrentField17>::read(prepare_request_id_raw, ledger, build)?;
        let prepare_request_sequence =
            <Plain17<U64> as CurrentField17>::read(prepare_request_sequence_raw, ledger, build)?;
        let prepare_request_digest =
            <Plain17<Bytes> as CurrentField17>::read(prepare_request_digest_raw, ledger, build)?;
        let prepare_response_sequence =
            <Plain17<U64> as CurrentField17>::read(prepare_response_sequence_raw, ledger, build)?;
        let prepare_response_digest =
            <Plain17<Bytes> as CurrentField17>::read(prepare_response_digest_raw, ledger, build)?;
        let transfer_token =
            <Plain17<Bytes> as CurrentField17>::read(transfer_token_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            prepare: prepare.ok_or_else(invalid)?,
            capture_terminal: capture_terminal.ok_or_else(invalid)?,
            prepare_request_id: prepare_request_id.ok_or_else(invalid)?,
            prepare_request_sequence: prepare_request_sequence.ok_or_else(invalid)?,
            prepare_request_digest: prepare_request_digest.ok_or_else(invalid)?,
            prepare_response_sequence: prepare_response_sequence.ok_or_else(invalid)?,
            prepare_response_digest: prepare_response_digest.ok_or_else(invalid)?,
            transfer_token: transfer_token.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            prepare,
            capture_terminal,
            prepare_request_id,
            prepare_request_sequence,
            prepare_request_digest,
            prepare_response_sequence,
            prepare_response_digest,
            transfer_token,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <CurrentDto17<PacketCompleteRestorePrepareRequest> as CurrentField17>::observe(
            prepare, observer,
        )?;
        <Plain17<Envelope> as CurrentField17>::observe(capture_terminal, observer)?;
        <Plain17<Id> as CurrentField17>::observe(prepare_request_id, observer)?;
        <Plain17<U64> as CurrentField17>::observe(prepare_request_sequence, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(prepare_request_digest, observer)?;
        <Plain17<U64> as CurrentField17>::observe(prepare_response_sequence, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(prepare_response_digest, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(transfer_token, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketCompleteRestoreCommitContext {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let algorithm_raw = fields.named("algorithm")?;
        let restoration_raw = fields.named("restoration")?;
        let commit_request_raw = fields.named("commit_request")?;
        let prepare_request_raw = fields.named("prepare_request")?;
        let prepare_response_raw = fields.named("prepare_response")?;
        let transfer_token_raw = fields.named("transfer_token")?;
        let input_roster_raw = fields.named("input_roster")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let algorithm = <Plain17<String> as CurrentField17>::read(algorithm_raw, ledger, build)?;
        let restoration = <CurrentDto17<PacketCompleteRestoreContext> as CurrentField17>::read(
            restoration_raw,
            ledger,
            build,
        )?;
        let commit_request =
            <Plain17<Bytes> as CurrentField17>::read(commit_request_raw, ledger, build)?;
        let prepare_request =
            <Plain17<Bytes> as CurrentField17>::read(prepare_request_raw, ledger, build)?;
        let prepare_response =
            <Plain17<Bytes> as CurrentField17>::read(prepare_response_raw, ledger, build)?;
        let transfer_token =
            <Plain17<Bytes> as CurrentField17>::read(transfer_token_raw, ledger, build)?;
        let input_roster =
            <Plain17<Bytes> as CurrentField17>::read(input_roster_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            algorithm: algorithm.ok_or_else(invalid)?,
            restoration: restoration.ok_or_else(invalid)?,
            commit_request: commit_request.ok_or_else(invalid)?,
            prepare_request: prepare_request.ok_or_else(invalid)?,
            prepare_response: prepare_response.ok_or_else(invalid)?,
            transfer_token: transfer_token.ok_or_else(invalid)?,
            input_roster: input_roster.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            algorithm,
            restoration,
            commit_request,
            prepare_request,
            prepare_response,
            transfer_token,
            input_roster,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <Plain17<String> as CurrentField17>::observe(algorithm, observer)?;
        <CurrentDto17<PacketCompleteRestoreContext> as CurrentField17>::observe(
            restoration,
            observer,
        )?;
        <Plain17<Bytes> as CurrentField17>::observe(commit_request, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(prepare_request, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(prepare_response, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(transfer_token, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(input_roster, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketCanonicalAckAdmissionContext {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let algorithm_raw = fields.named("algorithm")?;
        let source_birth_raw = fields.named("source_birth")?;
        let kernel_binding_raw = fields.named("kernel_binding")?;
        let policy_binding_raw = fields.named("policy_binding")?;
        let host_registration_raw = fields.named("host_registration")?;
        let native_registration_raw = fields.named("native_registration")?;
        let hello_request_raw = fields.named("hello_request")?;
        let hello_response_raw = fields.named("hello_response")?;
        let assigned_admit_raw = fields.named("assigned_admit")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let algorithm = <Plain17<String> as CurrentField17>::read(algorithm_raw, ledger, build)?;
        let source_birth =
            <Plain17<Bytes> as CurrentField17>::read(source_birth_raw, ledger, build)?;
        let kernel_binding =
            <Plain17<Bytes> as CurrentField17>::read(kernel_binding_raw, ledger, build)?;
        let policy_binding =
            <Plain17<Bytes> as CurrentField17>::read(policy_binding_raw, ledger, build)?;
        let host_registration =
            <Plain17<Bytes> as CurrentField17>::read(host_registration_raw, ledger, build)?;
        let native_registration =
            <Plain17<Bytes> as CurrentField17>::read(native_registration_raw, ledger, build)?;
        let hello_request =
            <Plain17<Bytes> as CurrentField17>::read(hello_request_raw, ledger, build)?;
        let hello_response =
            <Plain17<Bytes> as CurrentField17>::read(hello_response_raw, ledger, build)?;
        let assigned_admit =
            <Plain17<Bytes> as CurrentField17>::read(assigned_admit_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            algorithm: algorithm.ok_or_else(invalid)?,
            source_birth: source_birth.ok_or_else(invalid)?,
            kernel_binding: kernel_binding.ok_or_else(invalid)?,
            policy_binding: policy_binding.ok_or_else(invalid)?,
            host_registration: host_registration.ok_or_else(invalid)?,
            native_registration: native_registration.ok_or_else(invalid)?,
            hello_request: hello_request.ok_or_else(invalid)?,
            hello_response: hello_response.ok_or_else(invalid)?,
            assigned_admit: assigned_admit.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            algorithm,
            source_birth,
            kernel_binding,
            policy_binding,
            host_registration,
            native_registration,
            hello_request,
            hello_response,
            assigned_admit,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <Plain17<String> as CurrentField17>::observe(algorithm, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(source_birth, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(kernel_binding, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(policy_binding, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(host_registration, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(native_registration, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(hello_request, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(hello_response, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(assigned_admit, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketCanonicalAckAdmissionProof {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let algorithm_raw = fields.named("algorithm")?;
        let context_digest_raw = fields.named("context_digest")?;
        let mac_raw = fields.named("mac")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let algorithm = <Plain17<String> as CurrentField17>::read(algorithm_raw, ledger, build)?;
        let context_digest =
            <Plain17<Bytes> as CurrentField17>::read(context_digest_raw, ledger, build)?;
        let mac = <Plain17<Bytes> as CurrentField17>::read(mac_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            algorithm: algorithm.ok_or_else(invalid)?,
            context_digest: context_digest.ok_or_else(invalid)?,
            mac: mac.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            algorithm,
            context_digest,
            mac,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <Plain17<String> as CurrentField17>::observe(algorithm, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(context_digest, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(mac, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PrepareRestoreResult {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let transaction_id_raw = fields.named("transaction_id")?;
        let prepared_token_raw = fields.named("prepared_token")?;
        let world_binding_hash_raw = fields.named("world_binding_hash")?;
        let owner_binding_hash_raw = fields.named("owner_binding_hash")?;
        let staged_owner_ids_raw = fields.named("staged_owner_ids")?;
        let closed_gate_receipt_raw = fields.named("closed_gate_receipt")?;
        let validated_manifest_raw = fields.named("validated_manifest")?;
        fields.finish()?;

        let transaction_id =
            <Plain17<Id> as CurrentField17>::read(transaction_id_raw, ledger, build)?;
        let prepared_token =
            <Plain17<Id> as CurrentField17>::read(prepared_token_raw, ledger, build)?;
        let world_binding_hash =
            <Plain17<HashRef> as CurrentField17>::read(world_binding_hash_raw, ledger, build)?;
        let owner_binding_hash =
            <Plain17<HashRef> as CurrentField17>::read(owner_binding_hash_raw, ledger, build)?;
        let staged_owner_ids =
            <Plain17<IdSet> as CurrentField17>::read(staged_owner_ids_raw, ledger, build)?;
        let closed_gate_receipt =
            <Plain17<ContentRef> as CurrentField17>::read(closed_gate_receipt_raw, ledger, build)?;
        let validated_manifest =
            <Plain17<ContentRef> as CurrentField17>::read(validated_manifest_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            transaction_id: transaction_id.ok_or_else(invalid)?,
            prepared_token: prepared_token.ok_or_else(invalid)?,
            world_binding_hash: world_binding_hash.ok_or_else(invalid)?,
            owner_binding_hash: owner_binding_hash.ok_or_else(invalid)?,
            staged_owner_ids: staged_owner_ids.ok_or_else(invalid)?,
            closed_gate_receipt: closed_gate_receipt.ok_or_else(invalid)?,
            validated_manifest: validated_manifest.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            transaction_id,
            prepared_token,
            world_binding_hash,
            owner_binding_hash,
            staged_owner_ids,
            closed_gate_receipt,
            validated_manifest,
        } = self;
        <Plain17<Id> as CurrentField17>::observe(transaction_id, observer)?;
        <Plain17<Id> as CurrentField17>::observe(prepared_token, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(world_binding_hash, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(owner_binding_hash, observer)?;
        <Plain17<IdSet> as CurrentField17>::observe(staged_owner_ids, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(closed_gate_receipt, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(validated_manifest, observer)?;
        Ok(())
    }
}
