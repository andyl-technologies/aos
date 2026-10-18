//! Reads the defining activation DTO fields in their actual emitted order.

use super::*;

impl CurrentContract17 for PacketRestorationActivationAllocationRow {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let retained_requested_bytes_raw = fields.named("retained_requested_bytes")?;
        let maximum_simultaneous_transient_bytes_raw =
            fields.named("maximum_simultaneous_transient_bytes")?;
        let declared_counter_scratch_bytes_raw = fields.named("declared_counter_scratch_bytes")?;
        fields.finish()?;

        let retained_requested_bytes =
            <Plain17<U64> as CurrentField17>::read(retained_requested_bytes_raw, ledger, build)?;
        let maximum_simultaneous_transient_bytes = <Plain17<U64> as CurrentField17>::read(
            maximum_simultaneous_transient_bytes_raw,
            ledger,
            build,
        )?;
        let declared_counter_scratch_bytes = <Plain17<U64> as CurrentField17>::read(
            declared_counter_scratch_bytes_raw,
            ledger,
            build,
        )?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            retained_requested_bytes: retained_requested_bytes.ok_or_else(invalid)?,
            maximum_simultaneous_transient_bytes: maximum_simultaneous_transient_bytes
                .ok_or_else(invalid)?,
            declared_counter_scratch_bytes: declared_counter_scratch_bytes.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            retained_requested_bytes,
            maximum_simultaneous_transient_bytes,
            declared_counter_scratch_bytes,
        } = self;
        <Plain17<U64> as CurrentField17>::observe(retained_requested_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_simultaneous_transient_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(declared_counter_scratch_bytes, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestorationActivationTarget {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let native_pid_raw = fields.named("native_pid")?;
        let session_raw = fields.named("session")?;
        let incarnation_raw = fields.named("incarnation")?;
        let node_raw = fields.named("node")?;
        let owner_raw = fields.named("owner")?;
        let owner_generation_raw = fields.named("owner_generation")?;
        let binding_hash_raw = fields.named("binding_hash")?;
        let world_raw = fields.named("world")?;
        let activation_raw = fields.named("activation")?;
        let generation_raw = fields.named("generation")?;
        let prepared_token_raw = fields.named("prepared_token")?;
        let gate_raw = fields.named("gate")?;
        let admission_raw = fields.named("admission")?;
        let transaction_raw = fields.named("transaction")?;
        fields.finish()?;

        let native_pid = <Plain17<U64> as CurrentField17>::read(native_pid_raw, ledger, build)?;
        let session = <Plain17<Id> as CurrentField17>::read(session_raw, ledger, build)?;
        let incarnation = <Plain17<Id> as CurrentField17>::read(incarnation_raw, ledger, build)?;
        let node = <Plain17<Id> as CurrentField17>::read(node_raw, ledger, build)?;
        let owner = <Plain17<Id> as CurrentField17>::read(owner_raw, ledger, build)?;
        let owner_generation =
            <Plain17<U64> as CurrentField17>::read(owner_generation_raw, ledger, build)?;
        let binding_hash =
            <Plain17<HashRef> as CurrentField17>::read(binding_hash_raw, ledger, build)?;
        let world = <Plain17<HashRef> as CurrentField17>::read(world_raw, ledger, build)?;
        let activation = <Plain17<Id> as CurrentField17>::read(activation_raw, ledger, build)?;
        let generation = <Plain17<U64> as CurrentField17>::read(generation_raw, ledger, build)?;
        let prepared_token =
            <Plain17<Id> as CurrentField17>::read(prepared_token_raw, ledger, build)?;
        let gate = <Plain17<Id> as CurrentField17>::read(gate_raw, ledger, build)?;
        let admission = <Plain17<Id> as CurrentField17>::read(admission_raw, ledger, build)?;
        let transaction = <Plain17<Id> as CurrentField17>::read(transaction_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            native_pid: native_pid.ok_or_else(invalid)?,
            session: session.ok_or_else(invalid)?,
            incarnation: incarnation.ok_or_else(invalid)?,
            node: node.ok_or_else(invalid)?,
            owner: owner.ok_or_else(invalid)?,
            owner_generation: owner_generation.ok_or_else(invalid)?,
            binding_hash: binding_hash.ok_or_else(invalid)?,
            world: world.ok_or_else(invalid)?,
            activation: activation.ok_or_else(invalid)?,
            generation: generation.ok_or_else(invalid)?,
            prepared_token: prepared_token.ok_or_else(invalid)?,
            gate: gate.ok_or_else(invalid)?,
            admission: admission.ok_or_else(invalid)?,
            transaction: transaction.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            native_pid,
            session,
            incarnation,
            node,
            owner,
            owner_generation,
            binding_hash,
            world,
            activation,
            generation,
            prepared_token,
            gate,
            admission,
            transaction,
        } = self;
        <Plain17<U64> as CurrentField17>::observe(native_pid, observer)?;
        <Plain17<Id> as CurrentField17>::observe(session, observer)?;
        <Plain17<Id> as CurrentField17>::observe(incarnation, observer)?;
        <Plain17<Id> as CurrentField17>::observe(node, observer)?;
        <Plain17<Id> as CurrentField17>::observe(owner, observer)?;
        <Plain17<U64> as CurrentField17>::observe(owner_generation, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(binding_hash, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(world, observer)?;
        <Plain17<Id> as CurrentField17>::observe(activation, observer)?;
        <Plain17<U64> as CurrentField17>::observe(generation, observer)?;
        <Plain17<Id> as CurrentField17>::observe(prepared_token, observer)?;
        <Plain17<Id> as CurrentField17>::observe(gate, observer)?;
        <Plain17<Id> as CurrentField17>::observe(admission, observer)?;
        <Plain17<Id> as CurrentField17>::observe(transaction, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestorationActivationOriginals {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let captured_owner_state_raw = fields.named("captured_owner_state")?;
        let captured_control_raw = fields.named("captured_control")?;
        let captured_journal_raw = fields.named("captured_journal")?;
        let mapping_raw = fields.named("mapping")?;
        let commit_request_raw = fields.named("commit_request")?;
        let commit_response_raw = fields.named("commit_response")?;
        let context_digest_raw = fields.named("context_digest")?;
        fields.finish()?;

        let captured_owner_state =
            <Plain17<ContentRef> as CurrentField17>::read(captured_owner_state_raw, ledger, build)?;
        let captured_control =
            <Plain17<ContentRef> as CurrentField17>::read(captured_control_raw, ledger, build)?;
        let captured_journal =
            <Plain17<ContentRef> as CurrentField17>::read(captured_journal_raw, ledger, build)?;
        let mapping = <Plain17<ContentRef> as CurrentField17>::read(mapping_raw, ledger, build)?;
        let commit_request =
            <Plain17<ContentRef> as CurrentField17>::read(commit_request_raw, ledger, build)?;
        let commit_response =
            <Plain17<ContentRef> as CurrentField17>::read(commit_response_raw, ledger, build)?;
        let context_digest =
            <Plain17<Bytes> as CurrentField17>::read(context_digest_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            captured_owner_state: captured_owner_state.ok_or_else(invalid)?,
            captured_control: captured_control.ok_or_else(invalid)?,
            captured_journal: captured_journal.ok_or_else(invalid)?,
            mapping: mapping.ok_or_else(invalid)?,
            commit_request: commit_request.ok_or_else(invalid)?,
            commit_response: commit_response.ok_or_else(invalid)?,
            context_digest: context_digest.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            captured_owner_state,
            captured_control,
            captured_journal,
            mapping,
            commit_request,
            commit_response,
            context_digest,
        } = self;
        <Plain17<ContentRef> as CurrentField17>::observe(captured_owner_state, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(captured_control, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(captured_journal, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(mapping, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(commit_request, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(commit_response, observer)?;
        <Plain17<Bytes> as CurrentField17>::observe(context_digest, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestorationActivationScope {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let source_birth_raw = fields.named("source_birth")?;
        let source_runtime_raw = fields.named("source_runtime")?;
        let scope_proof_raw = fields.named("scope_proof")?;
        let target_raw = fields.named("target")?;
        let restoration_raw = fields.named("restoration")?;
        fields.finish()?;

        let source_birth =
            <Plain17<ContentRef> as CurrentField17>::read(source_birth_raw, ledger, build)?;
        let source_runtime =
            <Plain17<ContentRef> as CurrentField17>::read(source_runtime_raw, ledger, build)?;
        let scope_proof =
            <Plain17<ContentRef> as CurrentField17>::read(scope_proof_raw, ledger, build)?;
        let target = <CurrentDto17<PacketRestorationActivationTarget> as CurrentField17>::read(
            target_raw, ledger, build,
        )?;
        let restoration =
            <CurrentDto17<PacketRestorationActivationOriginals> as CurrentField17>::read(
                restoration_raw,
                ledger,
                build,
            )?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            source_birth: source_birth.ok_or_else(invalid)?,
            source_runtime: source_runtime.ok_or_else(invalid)?,
            scope_proof: scope_proof.ok_or_else(invalid)?,
            target: target.ok_or_else(invalid)?,
            restoration: restoration.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            source_birth,
            source_runtime,
            scope_proof,
            target,
            restoration,
        } = self;
        <Plain17<ContentRef> as CurrentField17>::observe(source_birth, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(source_runtime, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(scope_proof, observer)?;
        <CurrentDto17<PacketRestorationActivationTarget> as CurrentField17>::observe(
            target, observer,
        )?;
        <CurrentDto17<PacketRestorationActivationOriginals> as CurrentField17>::observe(
            restoration,
            observer,
        )?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestorationActivationRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let phase_raw = fields.named("phase")?;
        let scope_raw = fields.named("scope")?;
        let native_allocation_raw = fields.named("native_allocation")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let phase = <Inline17<PacketRestorationActivationPhase> as CurrentField17>::read(
            phase_raw, ledger, build,
        )?;
        let scope = <CurrentDto17<PacketRestorationActivationScope> as CurrentField17>::read(
            scope_raw, ledger, build,
        )?;
        let native_allocation =
            <CurrentDto17<PacketRestorationActivationAllocationRow> as CurrentField17>::read(
                native_allocation_raw,
                ledger,
                build,
            )?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            phase: phase.ok_or_else(invalid)?,
            scope: scope.ok_or_else(invalid)?,
            native_allocation: native_allocation.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            phase,
            scope,
            native_allocation,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <Inline17<PacketRestorationActivationPhase> as CurrentField17>::observe(phase, observer)?;
        <CurrentDto17<PacketRestorationActivationScope> as CurrentField17>::observe(
            scope, observer,
        )?;
        <CurrentDto17<PacketRestorationActivationAllocationRow> as CurrentField17>::observe(
            native_allocation,
            observer,
        )?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestorationActivationContext {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let request_raw = fields.named("request")?;
        let assigned_request_raw = fields.named("assigned_request")?;
        fields.finish()?;

        let request = <CurrentDto17<PacketRestorationActivationRequest> as CurrentField17>::read(
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
            request: request.ok_or_else(invalid)?,
            assigned_request: assigned_request.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            request,
            assigned_request,
        } = self;
        <CurrentDto17<PacketRestorationActivationRequest> as CurrentField17>::observe(
            request, observer,
        )?;
        <Plain17<Bytes> as CurrentField17>::observe(assigned_request, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestorationActivationProof {
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

impl CurrentContract17 for PacketRestorationActivationArtifact {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let request_raw = fields.named("request")?;
        let proof_raw = fields.named("proof")?;
        fields.finish()?;

        let request = <CurrentDto17<PacketRestorationActivationRequest> as CurrentField17>::read(
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
        <CurrentDto17<PacketRestorationActivationRequest> as CurrentField17>::observe(
            request, observer,
        )?;
        <CurrentDto17<PacketRestorationActivationProof> as CurrentField17>::observe(
            proof, observer,
        )?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestorationActivationUploadRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let scope_raw = fields.named("scope")?;
        let role_raw = fields.named("role")?;
        let coordinator_raw = fields.named("coordinator")?;
        let manifest_raw = fields.named("manifest")?;
        let maximum_frame_bytes_raw = fields.named("maximum_frame_bytes")?;
        let chunk_bytes_raw = fields.named("chunk_bytes")?;
        let maximum_requests_raw = fields.named("maximum_requests")?;
        let native_allocation_raw = fields.named("native_allocation")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let scope = <CurrentDto17<PacketRestorationActivationScope> as CurrentField17>::read(
            scope_raw, ledger, build,
        )?;
        let role = <Inline17<PacketRestorationActivationUploadRole> as CurrentField17>::read(
            role_raw, ledger, build,
        )?;
        let coordinator =
            <Plain17<ContentRef> as CurrentField17>::read(coordinator_raw, ledger, build)?;
        let manifest = <Plain17<ContentRef> as CurrentField17>::read(manifest_raw, ledger, build)?;
        let maximum_frame_bytes =
            <Plain17<U64> as CurrentField17>::read(maximum_frame_bytes_raw, ledger, build)?;
        let chunk_bytes = <Plain17<U64> as CurrentField17>::read(chunk_bytes_raw, ledger, build)?;
        let maximum_requests =
            <Plain17<U64> as CurrentField17>::read(maximum_requests_raw, ledger, build)?;
        let native_allocation =
            <CurrentDto17<PacketRestorationActivationAllocationRow> as CurrentField17>::read(
                native_allocation_raw,
                ledger,
                build,
            )?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema: schema.ok_or_else(invalid)?,
            scope: scope.ok_or_else(invalid)?,
            role: role.ok_or_else(invalid)?,
            coordinator: coordinator.ok_or_else(invalid)?,
            manifest: manifest.ok_or_else(invalid)?,
            maximum_frame_bytes: maximum_frame_bytes.ok_or_else(invalid)?,
            chunk_bytes: chunk_bytes.ok_or_else(invalid)?,
            maximum_requests: maximum_requests.ok_or_else(invalid)?,
            native_allocation: native_allocation.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            scope,
            role,
            coordinator,
            manifest,
            maximum_frame_bytes,
            chunk_bytes,
            maximum_requests,
            native_allocation,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <CurrentDto17<PacketRestorationActivationScope> as CurrentField17>::observe(
            scope, observer,
        )?;
        <Inline17<PacketRestorationActivationUploadRole> as CurrentField17>::observe(
            role, observer,
        )?;
        <Plain17<ContentRef> as CurrentField17>::observe(coordinator, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(manifest, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_frame_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(chunk_bytes, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_requests, observer)?;
        <CurrentDto17<PacketRestorationActivationAllocationRow> as CurrentField17>::observe(
            native_allocation,
            observer,
        )?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestorationActivationUploadContext {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let request_raw = fields.named("request")?;
        let assigned_request_raw = fields.named("assigned_request")?;
        fields.finish()?;

        let request =
            <CurrentDto17<PacketRestorationActivationUploadRequest> as CurrentField17>::read(
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
            request: request.ok_or_else(invalid)?,
            assigned_request: assigned_request.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            request,
            assigned_request,
        } = self;
        <CurrentDto17<PacketRestorationActivationUploadRequest> as CurrentField17>::observe(
            request, observer,
        )?;
        <Plain17<Bytes> as CurrentField17>::observe(assigned_request, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestorationActivationUploadArtifact {
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
            <CurrentDto17<PacketRestorationActivationUploadRequest> as CurrentField17>::read(
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
        <CurrentDto17<PacketRestorationActivationUploadRequest> as CurrentField17>::observe(
            request, observer,
        )?;
        <CurrentDto17<PacketRestorationActivationProof> as CurrentField17>::observe(
            proof, observer,
        )?;
        Ok(())
    }
}
