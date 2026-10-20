//! Joins the binding and literal phase payload to independently derived peer fields.

use super::*;

impl PacketNativeImport17PeerContext {
    /// Returns the exact typed phase, without inferring it from optional fields.
    pub const fn phase_data(&self) -> PacketNativeImport17Phase {
        match self {
            Self::Prepare(_) => PacketNativeImport17Phase::Prepare,
            Self::Commit(_) => PacketNativeImport17Phase::Commit,
        }
    }

    fn validate_data(&self) -> Result<(), ProviderError> {
        match self {
            Self::Prepare(peer) => peer.validate_data(),
            Self::Commit(peer) => peer.validate_data(),
        }
    }

    fn assigned_digest_data(&self) -> &Bytes {
        match self {
            Self::Prepare(peer) => &peer.assigned_prepare,
            Self::Commit(peer) => &peer.restoration.assigned_restore,
        }
    }
}

impl PacketNativeImport17Context {
    /// Checks complete fixed-width context DATA without authenticating a live peer.
    ///
    /// # Errors
    /// Refuses another grammar/construction, invalid peer context, malformed
    /// digests or an unequal independently retained assigned-original digest.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if self.schema != "source-owned.packet-native-import-context/17"
            || self.algorithm != PACKET_COMPLETE_RESTORE_ALGORITHM
        {
            return Err(invalid());
        }
        self.peer.validate_data()?;
        digest32(&self.import_binding_digest)?;
        digest32(&self.assigned_original_digest)?;
        same_digest(
            self.peer.assigned_digest_data().as_slice(),
            self.assigned_original_digest.as_slice(),
        )?;
        crate::connection::serialized_credit(self, MAXIMUM_NATIVE_IMPORT17_CONTEXT_BYTES)?;
        Ok(())
    }

    /// Checks complete Prepare payload, import binding and the same actual assignment.
    ///
    /// Both native and Source independently construct their peer context from
    /// actual birth/kernel/registration/Hello owners. This check cannot establish
    /// those owners or replace native storage admission and lease issuance.
    ///
    /// # Errors
    /// Refuses phase, request, binding, roster, schema or assigned-envelope changes.
    pub fn authenticate_prepare_data(
        &self,
        binding: &PacketNativeImport17Binding,
        request: &PacketCompleteRestorePrepareRequest,
        original: &Envelope,
        maximum_frame_bytes: usize,
    ) -> Result<(), ProviderError> {
        let PacketNativeImport17PeerContext::Prepare(peer) = &self.peer else {
            return Err(invalid());
        };
        self.authenticate_common_data(binding, original, maximum_frame_bytes)?;
        binding.authenticate_prepare_data(request)?;
        let phase = PacketNativeImport17Phase::Prepare;
        payload_matches(request, original, phase.request_extension())?;
        peer.authenticate_request_data(request)
    }

    /// Checks complete Commit, the same Prepare and unchanged normalization bytes.
    ///
    /// The actual completed Prepare token, six full input banks and same fresh
    /// actor remain separate mandatory native/SDK requirements before installing.
    ///
    /// # Errors
    /// Refuses any phase, assignment, request, lease, binding or mapping difference.
    pub fn authenticate_commit_data(
        &self,
        binding: &PacketNativeImport17Binding,
        request: &PacketCompleteRestoreCommitRequest,
        original: &Envelope,
        normalization: &[u8],
        maximum_frame_bytes: usize,
    ) -> Result<(), ProviderError> {
        let PacketNativeImport17PeerContext::Commit(peer) = &self.peer else {
            return Err(invalid());
        };
        self.authenticate_common_data(binding, original, maximum_frame_bytes)?;
        binding.authenticate_prepare_data(&request.prepare)?;
        payload_matches(
            request,
            original,
            PacketNativeImport17Phase::Commit.request_extension(),
        )?;
        binding.normalization.verify(normalization)?;
        peer.authenticate_request_data(request, normalization)
    }

    fn authenticate_common_data(
        &self,
        binding: &PacketNativeImport17Binding,
        original: &Envelope,
        maximum_frame_bytes: usize,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        payload_matches(binding, original, NATIVE_IMPORT17_EXTENSION)?;
        same_digest(
            self.import_binding_digest.as_slice(),
            &binding.digest_data()?,
        )?;
        same_digest(
            self.assigned_original_digest.as_slice(),
            &native_import17_assigned_request_digest(
                original,
                self.peer.phase_data(),
                maximum_frame_bytes,
            )?,
        )
    }
}

fn payload_matches(
    expected: &impl Serialize,
    original: &Envelope,
    extension: &str,
) -> Result<(), ProviderError> {
    let actual = original.extensions.get(extension).ok_or_else(invalid)?;
    let expected = bounded(
        expected,
        super::super::transfer::MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
    )?;
    let actual = bounded(
        actual,
        super::super::transfer::MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
    )?;
    if expected != actual {
        return Err(invalid());
    }
    Ok(())
}
