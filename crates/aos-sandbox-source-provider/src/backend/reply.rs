//! Durable reply routing and the owner-retained native handoff.
//!
//! Generic fresh and replay replies keep their existing move-only security
//! authorities. Native wire replies contain only a duplicate original OFD and
//! a comparison identity; their original observation and sealed outcome remain
//! in the fixed owner's one-slot custody after its single send attempt.

use aos_sandbox::ProtectedJournalSnapshot;
use aos_sandbox_core::ObjectDigest;

use super::{ObservedBackendAcquisitionV1, ProviderPhysicalSourceRootV1};

/// Owns a response and optional source-root descriptor after completion sync.
#[derive(Debug)]
pub struct DurableProviderReplyV1 {
    pub(crate) response: Vec<u8>,
    pub(crate) source_root: Option<ProviderPhysicalSourceRootV1>,
    pub(crate) durability: DurableReplyAuthorityV1,
}

pub(crate) enum DurableReplyAuthorityV1 {
    Fresh(aos_sandbox_source_provider_security::CommittedProviderOutcomeV1),
    RetainedNative {
        identity: crate::native_completion::NativeReplyIdentity,
        session_binding: ObjectDigest,
    },
    RevalidatedReplay {
        snapshot: ProtectedJournalSnapshot,
        attempt_key: Vec<u8>,
    },
}

impl core::fmt::Debug for DurableReplyAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DurableReplyAuthorityV1([protected durability])")
    }
}

impl DurableProviderReplyV1 {
    pub(crate) fn native_identity(&self) -> Option<crate::native_completion::NativeReplyIdentity> {
        match &self.durability {
            DurableReplyAuthorityV1::RetainedNative { identity, .. } => Some(*identity),
            _ => None,
        }
    }

    pub(crate) fn send_retained_native(
        self,
        session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        observed: &ObservedBackendAcquisitionV1,
        committed: &aos_sandbox_source_provider_security::CommittedProviderOutcomeV1,
    ) -> Result<(), crate::ProviderLedgerError> {
        let identity = self
            .native_identity()
            .ok_or(crate::ProviderLedgerError::Unavailable)?;
        if Some(identity)
            != observed
                .native
                .as_ref()
                .map(|native| native.reply_identity())
        {
            return Err(crate::ProviderLedgerError::Equivocation);
        }
        let root = self
            .source_root
            .ok_or(crate::ProviderLedgerError::Unavailable)?;
        if root.observation() != &observed.descriptor_observation {
            return Err(crate::ProviderLedgerError::BackendConflict);
        }
        let handoff = root.into_security_handoff()?;
        session.send_committed_reply_checked(journal, committed, Some(&handoff), || {
            observed.revalidate_physical().map_err(|_| {
                aos_sandbox_source_provider_security::SourceProviderSecurityError::SessionContinuity
            })
        })?;
        Ok(())
    }

    /// Consumes this reply into the authenticated session carrier.
    ///
    /// The security boundary revalidates the exact journal witness, canonical
    /// response/session identity, and the zero-or-one `SourceRoot` descriptor
    /// role immediately before the SCM_RIGHTS handoff.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProviderLedgerError`] for journal/session drift,
    /// response substitution, descriptor-shape mismatch, or carrier failure.
    pub(crate) fn send(
        self,
        session: &mut aos_sandbox_source_provider_security::CurrentProviderIngressSessionV1,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    ) -> Result<(), crate::ProviderLedgerError> {
        if self.native_identity().is_some() {
            return Err(crate::ProviderLedgerError::Unavailable);
        }
        let source_root = self
            .source_root
            .map(ProviderPhysicalSourceRootV1::into_security_handoff)
            .transpose()?;
        match self.durability {
            DurableReplyAuthorityV1::RetainedNative { .. } => {
                return Err(crate::ProviderLedgerError::Unavailable);
            }
            DurableReplyAuthorityV1::Fresh(committed) => {
                session.send_committed_reply(journal, committed, source_root)?
            }
            DurableReplyAuthorityV1::RevalidatedReplay {
                snapshot,
                attempt_key,
            } => {
                let replay = session.authorize_recovered_reply(
                    journal,
                    snapshot,
                    &attempt_key,
                    self.response,
                    source_root.is_some(),
                )?;
                session.send_revalidated_reply(journal, replay, source_root)?;
            }
        }
        Ok(())
    }

    pub(crate) fn session_binding(&self) -> Result<ObjectDigest, crate::ProviderLedgerError> {
        match &self.durability {
            DurableReplyAuthorityV1::Fresh(committed) => return Ok(committed.session_binding()),
            DurableReplyAuthorityV1::RetainedNative {
                session_binding, ..
            } => {
                return Ok(*session_binding);
            }
            DurableReplyAuthorityV1::RevalidatedReplay { .. } => {}
        }
        use aos_sandbox_source_provider_protocol::{
            ReleaseSourceResponseProfileV2, decode_acquire_response, decode_inventory_response,
        };

        if let Ok(response) = decode_acquire_response(&self.response) {
            return Ok(response.signed_status().subject().session_binding());
        }
        if let Ok(response) = ReleaseSourceResponseProfileV2::from_canonical_bytes(&self.response) {
            return Ok(response.signed_status().subject().session_binding());
        }
        if let Ok(response) = decode_inventory_response(&self.response) {
            return Ok(response.signed_status().subject().session_binding());
        }
        Err(crate::ProviderLedgerError::Corrupt(
            "durable reply response framing",
        ))
    }
}
