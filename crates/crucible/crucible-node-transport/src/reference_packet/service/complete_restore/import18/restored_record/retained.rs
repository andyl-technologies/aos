//! Observes complete typed record18 backing, including invalid retained DATA.
//!
//! Fixed headers belong to the enclosing owner. Every allocated child is walked
//! without validation, so a later correspondence refusal cannot erase its charge.

use super::*;
use crate::retained_metadata::{MetadataObserver, ObserveMetadata};

impl ObserveMetadata for PacketNativeImport18RecordPairData {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self { original, terminal } = self;
        observer.observe(original)?;
        observer.observe(terminal)
    }
}

impl ObserveMetadata for PacketNativeImport18RecordScopeData {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            target,
            source_birth,
            bootstrap,
            recipe_identity,
            import_binding,
            inputs,
            prepare,
        } = self;
        observe_target(target, observer)?;
        observer.observe(source_birth)?;
        observer.observe(bootstrap)?;
        observer.observe(recipe_identity)?;
        observer.observe(import_binding)?;
        observer.observe(inputs)?;
        observer.observe(prepare)
    }
}

impl ObserveMetadata for PacketNativeImport18RestoredRecordData {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        match self {
            Self::CommitHeld(PacketNativeImport18CommitHeldRecordData {
                schema,
                scope,
                commit,
                context_digest,
                local_cursor,
                inventory_hash,
                physical_gate_held,
            }) => {
                observer.observe(schema)?;
                observer.observe(scope)?;
                observer.observe(commit)?;
                observer.observe(context_digest)?;
                observer.observe(local_cursor)?;
                observer.observe(inventory_hash)?;
                observer.observe(physical_gate_held)
            }
            Self::FirstObserved(PacketNativeImport18FirstObservedRecordData {
                schema,
                scope,
                commit,
                arm,
                world,
                observe,
                native_record,
                physical_gate_held,
            }) => {
                observer.observe(schema)?;
                observer.observe(scope)?;
                observer.observe(commit)?;
                observer.observe(arm)?;
                observer.observe(world)?;
                observer.observe(observe)?;
                observer.observe(native_record)?;
                observer.observe(physical_gate_held)
            }
        }
    }
}

fn observe_target(
    target: &PacketRestorationActivationTarget,
    observer: &mut MetadataObserver<'_>,
) -> Result<(), ProviderError> {
    let PacketRestorationActivationTarget {
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
    } = target;
    observer.observe(native_pid)?;
    observer.observe(session)?;
    observer.observe(incarnation)?;
    observer.observe(node)?;
    observer.observe(owner)?;
    observer.observe(owner_generation)?;
    observer.observe(binding_hash)?;
    observer.observe(world)?;
    observer.observe(activation)?;
    observer.observe(generation)?;
    observer.observe(prepared_token)?;
    observer.observe(gate)?;
    observer.observe(admission)?;
    observer.observe(transaction)
}
