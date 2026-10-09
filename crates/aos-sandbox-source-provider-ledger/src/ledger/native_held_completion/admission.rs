//! Admission comparison fields derived only from the exact original row graph.

use super::{
    SourceNativeHeldCompletionRecordV1 as Record, corrupt,
    graph::{Companions, Records},
};
use crate::ledger::LedgerFormatErrorV1;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    SourceProviderAuthorityV1, native_held_completion::NativeHeldControlKindV1 as Kind,
};

/// Retains the actual original binding for the separate atomic capacity reducer.
///
/// This pure result describes the exact original Applying/Attempt/Session and
/// Requested checkpoint. It is not the protected admission, purpose-3 floor,
/// original clock guard or permission to dispatch. Neither this result nor a
/// capacity DATA result alone establishes the jointly required original owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceNativeHeldAdmissionBindingV1 {
    provider: SourceProviderAuthorityV1,
    holder: SourceProviderAuthorityV1,
    acquisition: ObjectDigest,
    operation: [u8; 16],
    original_reservation: ObjectDigest,
    attempt: ObjectDigest,
    root_request: ObjectDigest,
    session: ObjectDigest,
    native_request: ObjectDigest,
    root_prepared: ObjectDigest,
    catalog: (u64, ObjectDigest),
    namespace: ObjectDigest,
    backend: [u8; 32],
    lineage: ObjectDigest,
    normalized_intent: ObjectDigest,
}

impl SourceNativeHeldAdmissionBindingV1 {
    pub(super) fn derive(before: &Records, record: &Record) -> Result<Self, LedgerFormatErrorV1> {
        let rows = Companions::read(before, record)?;
        let root_prepared = record
            .suffix
            .control(Kind::RootPrepared)
            .ok_or(corrupt("held admission Root preparation"))?
            .digest();
        Ok(Self {
            provider: rows.acquisition.provider,
            holder: rows.acquisition.holder,
            acquisition: rows.acquisition.acquisition_id,
            operation: rows.acquisition.effect_id,
            original_reservation: record
                .original
                .reservation_acquisition_digest
                .ok_or(corrupt("held admission reservation"))?,
            attempt: rows.attempt.attempt_digest,
            root_request: rows.attempt.signed_request_digest,
            session: rows.holder.session_binding,
            native_request: record.original.native_request_digest,
            root_prepared,
            catalog: (
                rows.acquisition.catalog_generation,
                rows.acquisition.catalog_digest,
            ),
            namespace: rows.acquisition.resource_namespace_digest,
            backend: rows.acquisition.backend_id,
            lineage: rows.acquisition.backend_lineage_digest,
            normalized_intent: rows.acquisition.normalized_intent.digest(),
        })
    }

    /// Borrows the original complete Provider authority, not decoded trust.
    #[must_use]
    pub const fn provider(&self) -> &SourceProviderAuthorityV1 {
        &self.provider
    }

    /// Borrows the original complete holder authority, not a successor.
    #[must_use]
    pub const fn holder(&self) -> &SourceProviderAuthorityV1 {
        &self.holder
    }

    /// Returns the exact original acquisition identifier.
    #[must_use]
    pub const fn acquisition_id(&self) -> ObjectDigest {
        self.acquisition
    }

    /// Returns the immutable original operation/effect identifier.
    #[must_use]
    pub const fn operation_id(&self) -> [u8; 16] {
        self.operation
    }

    /// Returns the digest of the actual original Applying acquisition bytes.
    #[must_use]
    pub const fn reservation_acquisition_digest(&self) -> ObjectDigest {
        self.original_reservation
    }

    /// Returns the original artifact field of the legacy dispatch purpose-3 floor.
    #[must_use]
    pub const fn attempt_digest(&self) -> ObjectDigest {
        self.attempt
    }

    /// Returns the exact signed Root request commitment of that legacy floor.
    #[must_use]
    pub const fn root_request_digest(&self) -> ObjectDigest {
        self.root_request
    }

    /// Returns the original chain field of the legacy dispatch purpose-3 floor.
    #[must_use]
    pub const fn session_binding(&self) -> ObjectDigest {
        self.session
    }

    /// Returns the exact original signed native request for the new purpose-9 floor.
    #[must_use]
    pub const fn native_request_digest(&self) -> ObjectDigest {
        self.native_request
    }

    /// Returns the unchanged signed RootPrepared1 checkpoint for the new floor.
    #[must_use]
    pub const fn root_prepared_digest(&self) -> ObjectDigest {
        self.root_prepared
    }

    /// Returns the original namespace-41 catalog generation and head digest.
    #[must_use]
    pub const fn catalog_head(&self) -> (u64, ObjectDigest) {
        self.catalog
    }

    /// Returns the actual original native resource namespace.
    #[must_use]
    pub const fn resource_namespace_digest(&self) -> ObjectDigest {
        self.namespace
    }

    /// Returns the independently derived dispatch backend, never no-dispatch.
    #[must_use]
    pub const fn backend_id(&self) -> [u8; 32] {
        self.backend
    }

    /// Returns the immutable original AcquirePlan lineage commitment.
    #[must_use]
    pub const fn backend_lineage_digest(&self) -> ObjectDigest {
        self.lineage
    }

    /// Returns the unchanged normalized intent used in the dispatch derivation.
    #[must_use]
    pub const fn normalized_intent_digest(&self) -> ObjectDigest {
        self.normalized_intent
    }
}
