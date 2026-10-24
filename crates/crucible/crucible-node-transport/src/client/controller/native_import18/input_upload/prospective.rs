//! Prices the same seven bodies before the genuine Fresh query is spent.
//!
//! This independent DATA row includes one actual future Prepare pair in original
//! cache/frame/history geometry. It cannot create a completed pair or token and
//! cannot be substituted for the capsule's post-Prepare row or Source admission.

use super::*;

/// Retains exact input correspondence and prospective whole-upload storage.
pub struct OriginalNativeImport18InputUploadProspectiveStorageData {
    controller: Rc<ProtocolCaptureOwner>,
    identity: [u8; 32],
    chunk: usize,
    maximum_chunk: usize,
    requests: usize,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl OriginalNativeImport18InputUploadProspectiveStorageData {
    /// Returns additional whole-upload requested storage before any effects.
    pub const fn retained_growth_bytes(&self) -> usize {
        self.retained
    }

    /// Returns independent simultaneous protocol construction work.
    pub const fn maximum_simultaneous_transient_bytes(&self) -> usize {
        self.transient
    }

    /// Returns the defining fixed prewalk/guard controls.
    pub const fn declared_counter_scratch_bytes(&self) -> usize {
        self.scratch
    }

    /// Observes actual retained Controller association backing.
    ///
    /// # Errors
    /// Refuses foreign creator or metadata traversal exhaustion.
    pub fn retained_metadata_data(&self) -> Result<RetainedProtocolMetadataFacts, ProviderError> {
        self.controller.ensure_current()?;
        let mut observer = MetadataObserver::new();
        observer.shared_value(self.controller.as_ref())?;
        Ok(observer.finish())
    }

    /// Conjoins the actual completed-Prepare row with this original prefunding.
    ///
    /// This compares DATA only and does not confer native or Window permission.
    ///
    /// # Errors
    /// Refuses another actor, role/body/Prepare identity or increased any axis.
    pub fn authenticate_actual_data(
        &self,
        row: &OriginalNativeImport18InputUploadStorageData,
    ) -> Result<(), ProviderError> {
        self.controller.ensure_current()?;
        if !Rc::ptr_eq(&self.controller, &row.controller)
            || self.identity != row.identity
            || self.maximum_chunk != row.maximum_chunk
            || self.chunk != row.chunk
            || self.requests != row.requests
            || row.retained > self.retained
            || row.transient > self.transient
            || row.scratch > self.scratch
        {
            return Err(invalid());
        }
        Ok(())
    }
}

impl CnpController {
    /// Quotes exact seven-bank work while the original Fresh query is current.
    ///
    /// Independently admit the upload prewalk before this quote, then retain and
    /// admit these axes with all real Source/native rows before Prepare effects.
    /// The predetermined Prepare ID and exact typed inputs are borrowed DATA;
    /// no assigned original, native lease, token or Source claim is constructed.
    ///
    /// # Errors
    /// Refuses foreign/stale Fresh query, changed role bodies, exhausted actual
    /// input ceilings, reused planned IDs or original cache/history/storage bounds.
    pub fn quote_original_native_import18_input_upload_before_prepare_data(
        &self,
        emitter: &OriginalCanonicalBlobAckEmitter,
        query: &OriginalFreshRestoreQuery,
        prepare_id: &Id,
        request: &PacketCompleteRestorePrepareRequest,
        binding: &PacketNativeImport18Binding,
        bodies: [&[u8]; 7],
        maximum: usize,
    ) -> Result<OriginalNativeImport18InputUploadProspectiveStorageData, ProviderError> {
        query.authenticate_current(self, emitter)?;
        self.session.native_import18_selection_data()?;
        if self.original(prepare_id).is_some() {
            return Err(invalid());
        }
        let references =
            PacketNativeImport18InputRole::ALL.map(|role| role.reference_data(request, binding));
        for role in PacketNativeImport18InputRole::ALL {
            let index = role.ordinal_data();
            if references[index].length.get() > role.maximum_bytes_data(binding).get() {
                return Err(invalid());
            }
            verify_reference(references[index], bodies[index])?;
        }
        let prefix = blake3::hash(prepare_id.as_str().as_bytes());
        let parts =
            storage::quote_references(self, &references, prefix, &request.allocation, 1, maximum)?;
        let row = OriginalNativeImport18InputUploadProspectiveStorageData {
            controller: Rc::clone(&self.protocol_owner),
            identity: input_identity(request, binding, prefix),
            chunk: parts.chunk,
            maximum_chunk: parts.maximum_chunk,
            requests: parts.requests,
            retained: parts.retained,
            transient: parts.transient,
            scratch: storage::counter_scratch_data(),
        };
        query.authenticate_current(self, emitter)?;
        Ok(row)
    }
}
