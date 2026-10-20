//! Authenticates binding18 and assignment18 using unchanged inner context17 DATA.
//!
//! Context17 validation checks only its exact fixed inner grammar. These
//! explicitly named adapters additionally bind every successor field and the
//! distinct proof18 Envelope key. No older assignment guard accepts import18.

use super::*;

impl PacketNativeImport17Context {
    /// Checks complete Prepare payload, import binding and the same actual assignment.
    ///
    /// Both native and Source independently construct their peer context from
    /// actual birth/kernel/registration/Hello owners. This check cannot establish
    /// those owners or replace native storage admission and lease issuance.
    ///
    /// # Errors
    /// Refuses phase, request, binding, roster, schema or assigned-envelope changes.
    pub fn authenticate_import18_prepare_data(
        &self,
        binding: &PacketNativeImport18Binding,
        request: &PacketCompleteRestorePrepareRequest,
        expected_backend_schema: &SchemaRef,
        original: &Envelope,
        maximum_frame_bytes: usize,
    ) -> Result<(), ProviderError> {
        let PacketNativeImport17PeerContext::Prepare(peer) = &self.peer else {
            return Err(invalid());
        };
        self.authenticate_import18_common_data(binding, original, maximum_frame_bytes)?;
        binding.authenticate_prepare_data(request, expected_backend_schema)?;
        let phase = PacketNativeImport18Phase::Prepare;
        payload_matches(request, original, phase.request_extension())?;
        // The inner12 fixed context remains unchanged DATA. Its old helper
        // hashes a six-bank roster, so import18 compares the complete request
        // and its defining seven-bank roster explicitly instead.
        peer.validate_data()?;
        let bytes = bounded(
            request,
            super::super::transfer::MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        )?;
        same_digest(
            peer.prepare_request.as_slice(),
            blake3::hash(&bytes).as_bytes(),
        )?;
        same_digest(
            peer.input_roster.as_slice(),
            native_import18_input_roster_digest_data(request, binding)?.as_slice(),
        )
    }

    /// Checks complete Commit, the same Prepare and unchanged normalization bytes.
    ///
    /// The actual completed Prepare token, seven full input banks and same fresh
    /// actor remain separate mandatory native/SDK requirements before installing.
    ///
    /// # Errors
    /// Refuses any phase, assignment, request, lease, binding or mapping difference.
    pub fn authenticate_import18_commit_data(
        &self,
        binding: &PacketNativeImport18Binding,
        request: &PacketCompleteRestoreCommitRequest,
        expected_backend_schema: &SchemaRef,
        original: &Envelope,
        normalization: &[u8],
        maximum_frame_bytes: usize,
    ) -> Result<(), ProviderError> {
        let PacketNativeImport17PeerContext::Commit(peer) = &self.peer else {
            return Err(invalid());
        };
        self.authenticate_import18_common_data(binding, original, maximum_frame_bytes)?;
        binding.authenticate_prepare_data(&request.prepare, expected_backend_schema)?;
        payload_matches(
            request,
            original,
            PacketNativeImport18Phase::Commit.request_extension(),
        )?;
        binding.normalization.verify(normalization)?;
        peer.validate_data()?;
        request.validate_data()?;
        peer.restoration
            .authenticate_request_bindings_data(&request.prepare.restoration, normalization)?;
        let bytes = bounded(
            request,
            super::super::transfer::MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        )?;
        same_digest(
            peer.commit_request.as_slice(),
            blake3::hash(&bytes).as_bytes(),
        )?;
        for (actual, expected) in [
            (&peer.prepare_request, &request.prepare_request_digest),
            (&peer.prepare_response, &request.prepare_response_digest),
            (&peer.transfer_token, &request.transfer_token),
        ] {
            same_digest(actual.as_slice(), expected.as_slice())?;
        }
        same_digest(
            peer.input_roster.as_slice(),
            native_import18_input_roster_digest_data(&request.prepare, binding)?.as_slice(),
        )
    }

    fn authenticate_import18_common_data(
        &self,
        binding: &PacketNativeImport18Binding,
        original: &Envelope,
        maximum_frame_bytes: usize,
    ) -> Result<(), ProviderError> {
        self.validate_data()?;
        payload_matches(binding, original, NATIVE_IMPORT18_EXTENSION)?;
        same_digest(
            self.import_binding_digest.as_slice(),
            &binding.digest_data()?,
        )?;
        same_digest(
            self.assigned_original_digest.as_slice(),
            &native_import18_assigned_request_digest(
                original,
                match self.peer.phase_data() {
                    super::super::import17::PacketNativeImport17Phase::Prepare => {
                        PacketNativeImport18Phase::Prepare
                    }
                    super::super::import17::PacketNativeImport17Phase::Commit => {
                        PacketNativeImport18Phase::Commit
                    }
                },
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
    let maximum = super::super::transfer::MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES;
    let expected = bounded(expected, maximum)?;
    let actual = bounded(actual, maximum)?;
    if expected != actual {
        return Err(invalid());
    }
    Ok(())
}
