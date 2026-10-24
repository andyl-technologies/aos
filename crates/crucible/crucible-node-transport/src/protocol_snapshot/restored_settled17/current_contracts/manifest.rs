//! Reads the defining manifest DTO fields in their actual emitted order.

use super::*;

impl CurrentContract17 for ActivationManifest {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let schema_version_raw = fields.named("schema_version")?;
        let transaction_id_raw = fields.named("transaction_id")?;
        let activation_id_raw = fields.named("activation_id")?;
        let world_generation_raw = fields.named("world_generation")?;
        let gate_id_raw = fields.named("gate_id")?;
        let world_binding_hash_raw = fields.named("world_binding_hash")?;
        let owners_raw = fields.named("owners")?;
        let coordinator_state_ref_raw = fields.named("coordinator_state_ref")?;
        let extensions_raw = fields.named("extensions")?;
        fields.finish()?;

        let schema_version =
            <Plain17<Version> as CurrentField17>::read(schema_version_raw, ledger, build)?;
        let transaction_id =
            <Plain17<Id> as CurrentField17>::read(transaction_id_raw, ledger, build)?;
        let activation_id =
            <Plain17<Id> as CurrentField17>::read(activation_id_raw, ledger, build)?;
        let world_generation =
            <Plain17<U64> as CurrentField17>::read(world_generation_raw, ledger, build)?;
        let world_binding_hash =
            <Plain17<HashRef> as CurrentField17>::read(world_binding_hash_raw, ledger, build)?;
        let gate_id = <Plain17<Id> as CurrentField17>::read(gate_id_raw, ledger, build)?;
        let owners = <Vector17<CurrentDto17<PreparedOwner>> as CurrentField17>::read(
            owners_raw, ledger, build,
        )?;
        let coordinator_state_ref = <Plain17<ContentRef> as CurrentField17>::read(
            coordinator_state_ref_raw,
            ledger,
            build,
        )?;
        let extensions =
            <Plain17<Extensions> as CurrentField17>::read(extensions_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            schema_version: schema_version.ok_or_else(invalid)?,
            transaction_id: transaction_id.ok_or_else(invalid)?,
            activation_id: activation_id.ok_or_else(invalid)?,
            world_generation: world_generation.ok_or_else(invalid)?,
            gate_id: gate_id.ok_or_else(invalid)?,
            world_binding_hash: world_binding_hash.ok_or_else(invalid)?,
            owners: owners.ok_or_else(invalid)?,
            coordinator_state_ref: coordinator_state_ref.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema_version,
            transaction_id,
            activation_id,
            world_generation,
            gate_id,
            world_binding_hash,
            owners,
            coordinator_state_ref,
            extensions,
        } = self;
        <Plain17<Version> as CurrentField17>::observe(schema_version, observer)?;
        <Plain17<Id> as CurrentField17>::observe(transaction_id, observer)?;
        <Plain17<Id> as CurrentField17>::observe(activation_id, observer)?;
        <Plain17<U64> as CurrentField17>::observe(world_generation, observer)?;
        <Plain17<HashRef> as CurrentField17>::observe(world_binding_hash, observer)?;
        <Plain17<Id> as CurrentField17>::observe(gate_id, observer)?;
        <Vector17<CurrentDto17<PreparedOwner>> as CurrentField17>::observe(owners, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(coordinator_state_ref, observer)?;
        <Plain17<Extensions> as CurrentField17>::observe(extensions, observer)?;
        Ok(())
    }
}

impl CurrentContract17 for PreparedOwner {
    fn read_current(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        let mut fields = Fields::object(input)?;
        let owner_id_raw = fields.named("owner_id")?;
        let incarnation_id_raw = fields.named("incarnation_id")?;
        let owner_generation_raw = fields.named("owner_generation")?;
        let prepared_token_raw = fields.named("prepared_token")?;
        let binding_hashes_raw = fields.named("binding_hashes")?;
        let ready_receipt_raw = fields.named("ready_receipt")?;
        let extensions_raw = fields.named("extensions")?;
        fields.finish()?;

        let owner_id = <Plain17<Id> as CurrentField17>::read(owner_id_raw, ledger, build)?;
        let incarnation_id =
            <Plain17<Id> as CurrentField17>::read(incarnation_id_raw, ledger, build)?;
        let owner_generation =
            <Plain17<U64> as CurrentField17>::read(owner_generation_raw, ledger, build)?;
        let binding_hashes =
            <Plain17<Vec<HashRef>> as CurrentField17>::read(binding_hashes_raw, ledger, build)?;
        let prepared_token =
            <Plain17<Id> as CurrentField17>::read(prepared_token_raw, ledger, build)?;
        let ready_receipt =
            <Plain17<ContentRef> as CurrentField17>::read(ready_receipt_raw, ledger, build)?;
        let extensions =
            <Plain17<Extensions> as CurrentField17>::read(extensions_raw, ledger, build)?;
        if !build {
            return Ok(None);
        }
        Ok(Some(Self {
            owner_id: owner_id.ok_or_else(invalid)?,
            incarnation_id: incarnation_id.ok_or_else(invalid)?,
            owner_generation: owner_generation.ok_or_else(invalid)?,
            prepared_token: prepared_token.ok_or_else(invalid)?,
            binding_hashes: binding_hashes.ok_or_else(invalid)?,
            ready_receipt: ready_receipt.ok_or_else(invalid)?,
            extensions: extensions.ok_or_else(invalid)?,
        }))
    }

    fn observe_current(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            owner_id,
            incarnation_id,
            owner_generation,
            prepared_token,
            binding_hashes,
            ready_receipt,
            extensions,
        } = self;
        <Plain17<Id> as CurrentField17>::observe(owner_id, observer)?;
        <Plain17<Id> as CurrentField17>::observe(incarnation_id, observer)?;
        <Plain17<U64> as CurrentField17>::observe(owner_generation, observer)?;
        <Plain17<Vec<HashRef>> as CurrentField17>::observe(binding_hashes, observer)?;
        <Plain17<Id> as CurrentField17>::observe(prepared_token, observer)?;
        <Plain17<ContentRef> as CurrentField17>::observe(ready_receipt, observer)?;
        <Plain17<Extensions> as CurrentField17>::observe(extensions, observer)?;
        Ok(())
    }
}
