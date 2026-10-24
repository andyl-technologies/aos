//! Non-authorizing session DATA for the installed native recovery crash fixture.
//!
//! The handshake retains a live Session but creates no durable holder row.
//! The debug-only VM seeder needs its exact authenticated projection to build
//! the simulated pre-cut journal. This module performs no journal mutation,
//! request admission, backend effect, or response signing.

use aos_sandbox_source_provider_protocol::{
    ProviderRequestSequenceExpectationV1, SignedSourceProviderRequestV1, VerifiedProviderRequestV1,
};
use sha2::{Digest as _, Sha256};

use crate::{FixedProviderOwnerV1, ProviderLedgerError};

impl FixedProviderOwnerV1 {
    /// Returns the actual durable catalog commitment for the debug VM seeder.
    ///
    /// # Errors
    ///
    /// Rejects a missing, stale, or unavailable fixed ledger claim.
    pub fn native_recovery_vm_catalog_head(&mut self) -> Result<[u8; 32], ProviderLedgerError> {
        self.with_ledger(|ledger| {
            let mut hash = Sha256::new();
            hash.update(b"aos.sandbox.source-provider.current-catalog-publication-head.v1\0");
            hash.update(crate::format::encode_catalog(&ledger.recovered.catalog));
            Ok(hash.finalize().into())
        })
    }

    /// Returns canonical session DATA for a verified first Acquire in a VM fixture.
    ///
    /// This debug-only observation does not admit the request or persist the
    /// session. The external crash seeder remains responsible for constructing
    /// and validating its simulated journal cut.
    ///
    /// # Errors
    ///
    /// Rejects existing holder history, a missing or stale live session, an
    /// invalid first request, or a method other than Acquire.
    pub fn native_recovery_vm_session_record(
        &mut self,
        signed: &SignedSourceProviderRequestV1,
    ) -> Result<Vec<u8>, ProviderLedgerError> {
        self.with_ledger(|ledger| {
            if !ledger.recovered.sessions.is_empty() || !ledger.recovered.attempts.is_empty() {
                return Err(ProviderLedgerError::InvalidTransition(
                    "native recovery VM fixture requires fresh holder history",
                ));
            }

            let installed = ledger
                .current_sessions
                .get_mut(&signed.signer().authority_id())
                .ok_or(ProviderLedgerError::Unavailable)?;
            let current = installed.session.verify_current_request(
                signed,
                ProviderRequestSequenceExpectationV1::fresh(1)?,
                &[],
            )?;
            let VerifiedProviderRequestV1::Acquire(acquire) = current.verified() else {
                return Err(ProviderLedgerError::Equivocation);
            };
            let session = crate::transaction::new_session_from_projection(
                acquire.ingress_projection(),
                current.provider_execution_identity(),
                None,
                None,
                1,
            )?;

            Ok(crate::format::encode_session(&session))
        })
    }
}
