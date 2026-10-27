//! Reads the defining observation DTO fields in their actual emitted order.

use super::*;

impl CurrentContract17 for PacketRestorationObservationRequest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_raw = fields.named("schema")?;
        let scope_raw = fields.named("scope")?;
        let world_original_raw = fields.named("world_original")?;
        let world_terminal_raw = fields.named("world_terminal")?;
        let maximum_items_raw = fields.named("maximum_items")?;
        let native_allocation_raw = fields.named("native_allocation")?;
        fields.finish()?;

        let schema = <Plain17<String> as CurrentField17>::read(schema_raw, ledger, build)?;
        let scope = <CurrentDto17<PacketRestorationActivationScope> as CurrentField17>::read(
            scope_raw, ledger, build,
        )?;
        let world_original =
            <Plain17<ContentRef> as CurrentField17>::read(world_original_raw, ledger, build)?;
        let world_terminal =
            <Plain17<ContentRef> as CurrentField17>::read(world_terminal_raw, ledger, build)?;
        let maximum_items =
            <Plain17<U64> as CurrentField17>::read(maximum_items_raw, ledger, build)?;
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
            world_original: world_original.ok_or_else(invalid)?,
            world_terminal: world_terminal.ok_or_else(invalid)?,
            maximum_items: maximum_items.ok_or_else(invalid)?,
            native_allocation: native_allocation.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            scope,
            world_original,
            world_terminal,
            maximum_items,
            native_allocation,
        } = self;
        <Plain17<String> as CurrentField17>::observe(schema, observer)?;
        <CurrentDto17<PacketRestorationActivationScope> as CurrentField17>::observe(
            scope, observer,
        )?;
        <Plain17<ContentRef> as CurrentField17>::observe(world_original, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(world_terminal, observer)?;
        <Plain17<U64> as CurrentField17>::observe(maximum_items, observer)?;
        <CurrentDto17<PacketRestorationActivationAllocationRow> as CurrentField17>::observe(
            native_allocation,
            observer,
        )?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestorationObservationContext {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let request_raw = fields.named("request")?;
        let assigned_request_raw = fields.named("assigned_request")?;
        fields.finish()?;

        let request = <CurrentDto17<PacketRestorationObservationRequest> as CurrentField17>::read(
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
        <CurrentDto17<PacketRestorationObservationRequest> as CurrentField17>::observe(
            request, observer,
        )?;
        <Plain17<Bytes> as CurrentField17>::observe(assigned_request, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PacketRestorationObservationProof {
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

impl CurrentContract17 for PacketRestorationObservationArtifact {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let request_raw = fields.named("request")?;
        let proof_raw = fields.named("proof")?;
        fields.finish()?;

        let request = <CurrentDto17<PacketRestorationObservationRequest> as CurrentField17>::read(
            request_raw,
            ledger,
            build,
        )?;
        let proof = <CurrentDto17<PacketRestorationObservationProof> as CurrentField17>::read(
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
        <CurrentDto17<PacketRestorationObservationRequest> as CurrentField17>::observe(
            request, observer,
        )?;
        <CurrentDto17<PacketRestorationObservationProof> as CurrentField17>::observe(
            proof, observer,
        )?;
        Ok(())
    }
}
