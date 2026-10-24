//! Reads the defining capture DTO fields in their actual emitted order.

use super::*;

impl CurrentContract17 for PacketRestoredSettledCaptureOutputLimits {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let native_snapshot_bytes_raw = fields.named("native_snapshot_bytes")?;
        let current_control_bytes_raw = fields.named("current_control_bytes")?;
        let native_before_bytes_raw = fields.named("native_before_bytes")?;
        let anchor_bytes_raw = fields.named("anchor_bytes")?;
        let native_after_bytes_raw = fields.named("native_after_bytes")?;
        fields.finish()?;

        let native_snapshot_bytes =
            <Plain17<U64> as CurrentField17>::read(native_snapshot_bytes_raw, ledger, build)?;
        let current_control_bytes =
            <Plain17<U64> as CurrentField17>::read(current_control_bytes_raw, ledger, build)?;
        let native_before_bytes =
            <Plain17<U64> as CurrentField17>::read(native_before_bytes_raw, ledger, build)?;
        let anchor_bytes = <Plain17<U64> as CurrentField17>::read(anchor_bytes_raw, ledger, build)?;
        let native_after_bytes =
            <Plain17<U64> as CurrentField17>::read(native_after_bytes_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            native_snapshot_bytes: native_snapshot_bytes.ok_or_else(invalid)?,
            current_control_bytes: current_control_bytes.ok_or_else(invalid)?,
            native_before_bytes: native_before_bytes.ok_or_else(invalid)?,
            anchor_bytes: anchor_bytes.ok_or_else(invalid)?,
            native_after_bytes: native_after_bytes.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            native_snapshot_bytes,
            current_control_bytes,
            native_before_bytes,
            anchor_bytes,
            native_after_bytes,
        } = self;
        <Plain17<U64> as CurrentField17>::observe(native_snapshot_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(current_control_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(native_before_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(anchor_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(native_after_bytes, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredSettledCaptureRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let scope_raw = fields.named("scope")?;
        let capture_raw = fields.named("capture")?;
        let capture_owner_raw = fields.named("capture_owner")?;
        let capture_operation_raw = fields.named("capture_operation")?;
        let runtime_object_raw = fields.named("runtime_object")?;
        let coordinator_checkpoint_raw = fields.named("coordinator_checkpoint")?;
        let parent_archive_raw = fields.named("parent_archive")?;
        let first_observation_raw = fields.named("first_observation")?;
        let current_record_raw = fields.named("current_record")?;
        let current_model_raw = fields.named("current_model")?;
        let history_prefix_raw = fields.named("history_prefix")?;
        let history_next_sequence_raw = fields.named("history_next_sequence")?;
        let native_schema_raw = fields.named("native_schema")?;
        let native_allocation_raw = fields.named("native_allocation")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let scope = <CurrentDto17<PacketRestorationActivationScope> as CurrentField17>::read(
            scope_raw, ledger, build,
        )?;
        let capture =
            <CurrentDto17<CaptureArguments> as CurrentField17>::read(capture_raw, ledger, build)?;
        let capture_owner =
            <Plain17<Id> as CurrentField17>::read(capture_owner_raw, ledger, build)?;
        let capture_operation =
            <Plain17<Id> as CurrentField17>::read(capture_operation_raw, ledger, build)?;
        let runtime_object =
            <Plain17<ContentRef> as CurrentField17>::read(runtime_object_raw, ledger, build)?;
        let coordinator_checkpoint = <Plain17<ContentRef> as CurrentField17>::read(
            coordinator_checkpoint_raw,
            ledger,
            build,
        )?;
        let parent_archive =
            <Plain17<ContentRef> as CurrentField17>::read(parent_archive_raw, ledger, build)?;
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
        let native_schema =
            <Plain17<ContentRef> as CurrentField17>::read(native_schema_raw, ledger, build)?;
        let native_allocation =
            <ScalarRow17 as CurrentField17>::read(native_allocation_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            scope: scope.ok_or_else(invalid)?,
            capture: capture.ok_or_else(invalid)?,
            capture_owner: capture_owner.ok_or_else(invalid)?,
            capture_operation: capture_operation.ok_or_else(invalid)?,
            runtime_object: runtime_object.ok_or_else(invalid)?,
            coordinator_checkpoint: coordinator_checkpoint.ok_or_else(invalid)?,
            parent_archive: parent_archive.ok_or_else(invalid)?,
            first_observation: first_observation.ok_or_else(invalid)?,
            current_record: current_record.ok_or_else(invalid)?,
            current_model: current_model.ok_or_else(invalid)?,
            history_prefix: history_prefix.ok_or_else(invalid)?,
            history_next_sequence: history_next_sequence.ok_or_else(invalid)?,
            native_schema: native_schema.ok_or_else(invalid)?,
            native_allocation: native_allocation.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            scope,
            capture,
            capture_owner,
            capture_operation,
            runtime_object,
            coordinator_checkpoint,
            parent_archive,
            first_observation,
            current_record,
            current_model,
            history_prefix,
            history_next_sequence,
            native_schema,
            native_allocation,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <CurrentDto17<PacketRestorationActivationScope> as CurrentField17>::observe(
            scope, observer,
        )?;
        <CurrentDto17<CaptureArguments> as CurrentField17>::observe(capture, observer)?;
        <Plain17<Id> as CurrentField17>::observe(capture_owner, observer)?;
        <Plain17<Id> as CurrentField17>::observe(capture_operation, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(runtime_object, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(coordinator_checkpoint, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(parent_archive, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(first_observation, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(current_record, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(current_model, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(history_prefix, observer)?;
        <Plain17<U64> as CurrentField17>::observe(history_next_sequence, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(native_schema, observer)?;
        <ScalarRow17 as CurrentField17>::observe(native_allocation, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredSettledCaptureContext {
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
        let request = <CurrentDto17<PacketRestoredSettledCaptureRequest> as CurrentField17>::read(
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
        <CurrentDto17<PacketRestoredSettledCaptureRequest> as CurrentField17>::observe(
            request, observer,
        )?;
        <Plain17<Bytes> as CurrentField17>::observe(assigned_request, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredSettledCaptureArtifact {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let request_raw = fields.named("request")?;
        let proof_raw = fields.named("proof")?;
        fields.finish()?;

        let request = <CurrentDto17<PacketRestoredSettledCaptureRequest> as CurrentField17>::read(
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
        <CurrentDto17<PacketRestoredSettledCaptureRequest> as CurrentField17>::observe(
            request, observer,
        )?;
        <CurrentDto17<PacketRestorationActivationProof> as CurrentField17>::observe(
            proof, observer,
        )?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredSettledCaptureUploadRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let capture_raw = fields.named("capture")?;
        let ordinal_raw = fields.named("ordinal")?;
        let transfer_id_raw = fields.named("transfer_id")?;
        let content_raw = fields.named("content")?;
        let native_allocation_raw = fields.named("native_allocation")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let capture = <CurrentDto17<PacketRestoredSettledCaptureRequest> as CurrentField17>::read(
            capture_raw,
            ledger,
            build,
        )?;
        let ordinal =
            <Inline17<PacketRestoredSettledCaptureUploadOrdinal> as CurrentField17>::read(
                ordinal_raw,
                ledger,
                build,
            )?;
        let transfer_id = <Plain17<Id> as CurrentField17>::read(transfer_id_raw, ledger, build)?;
        let content = <Plain17<ContentRef> as CurrentField17>::read(content_raw, ledger, build)?;
        let native_allocation =
            <ScalarRow17 as CurrentField17>::read(native_allocation_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            capture: capture.ok_or_else(invalid)?,
            ordinal: ordinal.ok_or_else(invalid)?,
            transfer_id: transfer_id.ok_or_else(invalid)?,
            content: content.ok_or_else(invalid)?,
            native_allocation: native_allocation.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            capture,
            ordinal,
            transfer_id,
            content,
            native_allocation,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <CurrentDto17<PacketRestoredSettledCaptureRequest> as CurrentField17>::observe(
            capture, observer,
        )?;
        <Inline17<PacketRestoredSettledCaptureUploadOrdinal> as CurrentField17>::observe(
            ordinal, observer,
        )?;
        <Plain17<Id> as CurrentField17>::observe(transfer_id, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(content, observer)?;
        <ScalarRow17 as CurrentField17>::observe(native_allocation, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredSettledCaptureUploadContext {
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
        let request =
            <CurrentDto17<PacketRestoredSettledCaptureUploadRequest> as CurrentField17>::read(
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
        <CurrentDto17<PacketRestoredSettledCaptureUploadRequest> as CurrentField17>::observe(
            request, observer,
        )?;
        <Plain17<Bytes> as CurrentField17>::observe(assigned_request, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredSettledCaptureUploadArtifact {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let request_raw = fields.named("request")?;
        let proof_raw = fields.named("proof")?;
        fields.finish()?;

        let request =
            <CurrentDto17<PacketRestoredSettledCaptureUploadRequest> as CurrentField17>::read(
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
        <CurrentDto17<PacketRestoredSettledCaptureUploadRequest> as CurrentField17>::observe(
            request, observer,
        )?;
        <CurrentDto17<PacketRestorationActivationProof> as CurrentField17>::observe(
            proof, observer,
        )?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredSettledCaptureUploadContinuation {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let context_digest_raw = fields.named("context_digest")?;
        let capture_operation_raw = fields.named("capture_operation")?;
        let transfer_id_raw = fields.named("transfer_id")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let context_digest =
            <Plain17<Bytes> as CurrentField17>::read(context_digest_raw, ledger, build)?;
        let capture_operation =
            <Plain17<Id> as CurrentField17>::read(capture_operation_raw, ledger, build)?;
        let transfer_id = <Plain17<Id> as CurrentField17>::read(transfer_id_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            context_digest: context_digest.ok_or_else(invalid)?,
            capture_operation: capture_operation.ok_or_else(invalid)?,
            transfer_id: transfer_id.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            context_digest,
            capture_operation,
            transfer_id,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(context_digest, observer)?;
        <Plain17<Id> as CurrentField17>::observe(capture_operation, observer)?;
        <Plain17<Id> as CurrentField17>::observe(transfer_id, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestoredSettledAfterConfirmationRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let capture_request_id_raw = fields.named("capture_request_id")?;
        let capture_request_hash_raw = fields.named("capture_request_hash")?;
        let capture_operation_id_raw = fields.named("capture_operation_id")?;
        let capture_terminal_hash_raw = fields.named("capture_terminal_hash")?;
        let capture_terminal_sequence_raw = fields.named("capture_terminal_sequence")?;
        let settled_capture_request_raw = fields.named("settled_capture_request")?;
        let native_snapshot_ref_raw = fields.named("native_snapshot_ref")?;
        let native_control_ref_raw = fields.named("native_control_ref")?;
        let native_anchor_ref_raw = fields.named("native_anchor_ref")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let capture_request_id =
            <Plain17<Id> as CurrentField17>::read(capture_request_id_raw, ledger, build)?;
        let capture_request_hash =
            <Plain17<HashRef> as CurrentField17>::read(capture_request_hash_raw, ledger, build)?;
        let capture_operation_id =
            <Plain17<Id> as CurrentField17>::read(capture_operation_id_raw, ledger, build)?;
        let capture_terminal_hash =
            <Plain17<HashRef> as CurrentField17>::read(capture_terminal_hash_raw, ledger, build)?;
        let capture_terminal_sequence =
            <Plain17<U64> as CurrentField17>::read(capture_terminal_sequence_raw, ledger, build)?;
        let settled_capture_request = <Plain17<ContentRef> as CurrentField17>::read(
            settled_capture_request_raw,
            ledger,
            build,
        )?;
        let native_snapshot_ref =
            <Plain17<ContentRef> as CurrentField17>::read(native_snapshot_ref_raw, ledger, build)?;
        let native_control_ref =
            <Plain17<ContentRef> as CurrentField17>::read(native_control_ref_raw, ledger, build)?;
        let native_anchor_ref =
            <Plain17<ContentRef> as CurrentField17>::read(native_anchor_ref_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            capture_request_id: capture_request_id.ok_or_else(invalid)?,
            capture_request_hash: capture_request_hash.ok_or_else(invalid)?,
            capture_operation_id: capture_operation_id.ok_or_else(invalid)?,
            capture_terminal_hash: capture_terminal_hash.ok_or_else(invalid)?,
            capture_terminal_sequence: capture_terminal_sequence.ok_or_else(invalid)?,
            settled_capture_request: settled_capture_request.ok_or_else(invalid)?,
            native_snapshot_ref: native_snapshot_ref.ok_or_else(invalid)?,
            native_control_ref: native_control_ref.ok_or_else(invalid)?,
            native_anchor_ref: native_anchor_ref.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            capture_request_id,
            capture_request_hash,
            capture_operation_id,
            capture_terminal_hash,
            capture_terminal_sequence,
            settled_capture_request,
            native_snapshot_ref,
            native_control_ref,
            native_anchor_ref,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <Plain17<Id> as CurrentField17>::observe(capture_request_id, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(capture_request_hash, observer)?;
        <Plain17<Id> as CurrentField17>::observe(capture_operation_id, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(capture_terminal_hash, observer)?;
        <Plain17<U64> as CurrentField17>::observe(capture_terminal_sequence, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(settled_capture_request, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(native_snapshot_ref, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(native_control_ref, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(native_anchor_ref, observer)?;
        Ok(())
    }
}
