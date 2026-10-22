//! Observes every retained stage field without requiring successful validation.
//!
//! Fixed headers belong to enclosing owners. Exhaustive patterns keep failed
//! partial receipts, invalid targets and every dynamic child in the real census.

use super::super::PacketNativeImport17CommitReceipt;
use super::*;
use crate::reference_packet::service::native_startup::PacketNativeStartupAllocationRow;
use crate::retained_metadata::{MetadataObserver, ObserveMetadata};

impl ObserveMetadata for PacketNativeImport17Stage {
    fn observe_metadata(&self, _observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        Ok(())
    }
}

impl ObserveMetadata for PacketNativeImport17StagePairData {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self { original, terminal } = self;
        observer.observe(original)?;
        observer.observe(terminal)
    }
}

impl ObserveMetadata for PacketNativeImport17StagePrepareData {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self { pair, receipt } = self;
        observer.observe(pair)?;
        observer.observe(receipt)
    }
}

impl ObserveMetadata for PacketNativeImport17StageCommitData {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self { pair, receipt } = self;
        observer.observe(pair)?;
        observer.observe(receipt)
    }
}

impl ObserveMetadata for PacketNativeImport17StageBinding {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            phase,
            import_binding_digest,
            source_birth,
            source_runtime,
            scope_proof,
            target,
            prepare,
            commit,
            hold,
            arm,
            world,
            native_allocation,
        } = self;
        observer.observe(schema)?;
        observer.observe(phase)?;
        observer.observe(import_binding_digest)?;
        observer.observe(source_birth)?;
        observer.observe(source_runtime)?;
        observer.observe(scope_proof)?;
        observer.observe(target)?;
        observer.observe(prepare)?;
        observer.observe(commit)?;
        observer.observe(hold)?;
        observer.observe(arm)?;
        observer.observe(world)?;
        observer.observe(native_allocation)
    }
}

impl ObserveMetadata for PacketNativeImport17StageContext {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            algorithm,
            phase,
            birth_context_digest,
            stage_binding_digest,
            assigned_original_digest,
        } = self;
        observer.observe(schema)?;
        observer.observe(algorithm)?;
        observer.observe(phase)?;
        observer.observe(birth_context_digest)?;
        observer.observe(stage_binding_digest)?;
        observer.observe(assigned_original_digest)
    }
}

impl ObserveMetadata for PacketNativeImport17StageProof {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            algorithm,
            context_digest,
            mac,
        } = self;
        observer.observe(schema)?;
        observer.observe(algorithm)?;
        observer.observe(context_digest)?;
        observer.observe(mac)
    }
}

impl ObserveMetadata for PacketNativeImport17StageReceipt {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            algorithm,
            phase,
            context_digest,
            assigned_response,
            physical_gate_held,
            mac,
        } = self;
        observer.observe(schema)?;
        observer.observe(algorithm)?;
        observer.observe(phase)?;
        observer.observe(context_digest)?;
        observer.observe(assigned_response)?;
        observer.observe(physical_gate_held)?;
        observer.observe(mac)
    }
}

impl ObserveMetadata for PacketNativeImport17CommitReceipt {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            schema,
            algorithm,
            import_binding_digest,
            context_digest,
            commit_digest,
            installed_mapping,
            transfer_token,
            native_sequence,
            assigned_response,
            mac,
        } = self;
        observer.observe(schema)?;
        observer.observe(algorithm)?;
        observer.observe(import_binding_digest)?;
        observer.observe(context_digest)?;
        observer.observe(commit_digest)?;
        observer.observe(installed_mapping)?;
        observer.observe(transfer_token)?;
        observer.observe(native_sequence)?;
        observer.observe(assigned_response)?;
        observer.observe(mac)
    }
}

impl ObserveMetadata for PacketNativeStartupAllocationRow {
    fn observe_metadata(&self, observer: &mut MetadataObserver<'_>) -> Result<(), ProviderError> {
        let Self {
            retained_requested_bytes,
            maximum_simultaneous_transient_bytes,
            declared_counter_scratch_bytes,
        } = self;
        observer.observe(retained_requested_bytes)?;
        observer.observe(maximum_simultaneous_transient_bytes)?;
        observer.observe(declared_counter_scratch_bytes)
    }
}
