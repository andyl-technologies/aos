//! Root's protected consumed-Release acceptance of native export fences.
//!
//! This seals only the exact nonterminal Pending result after whole-graph
//! validation and byte-for-byte readback. It has no descriptor/absence effects.

use super::*;

impl CurrentRootMountSourceProviderSessionV1 {
    /// Seals a native fence only after its exact Root disposition is durable.
    ///
    /// Legacy outcomes are unchanged. A native result must match the verified
    /// response, immutable consumed Release, original Acquire/lease evidence,
    /// current acquisition lineage and protected canonical bytes. The receipt
    /// cannot be manufactured from a signed fence or raw proof alone.
    ///
    /// # Errors
    ///
    /// Poisons custody on an invalid protected graph, changed response/attempt,
    /// missing readback, non-Releasing owner or stale protected snapshot.
    pub fn seal_committed_native_export_fence_v1(
        &mut self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        attempt_id: [u8; 32],
        outcome: &mut VerifiedMountProviderOutcomeV2,
    ) -> Result<(), SourceProviderSecurityError> {
        use aos_sandbox_protocol::mount_source_acquisition_state::{
            ProviderAttemptStateV2, ProviderQueryOwnerV2, ProviderStatusV2,
            SourceAcquisitionPhaseV2, StoredRecordV2, encode_mount_source_state_record_v2,
            native_export_fence::validate_native_export_fence_v1,
        };
        use aos_sandbox_source_provider_protocol::ReleaseSourceResponseProfileV2;

        if outcome.method != SourceProviderMethod::Release {
            return Ok(());
        }
        let profile =
            ReleaseSourceResponseProfileV2::from_canonical_bytes(&outcome.canonical_response)
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        if profile.native_fence().is_none() {
            return Ok(());
        }

        self.revalidate()?;
        let snapshot = journal
            .snapshot()
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let graph = validated_mount_state(journal).map_err(|error| self.poison(error))?;
        let current_time = super::current_unix_seconds()?;
        let current_projection =
            capture_session_projection(self, current_time).map_err(|error| self.poison(error))?;
        let attempt = graph
            .provider_attempts
            .get(&attempt_id)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let ProviderQueryOwnerV2::Release { acquisition_id } = attempt.owner else {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        };
        let row = graph
            .acquisitions
            .get(&acquisition_id)
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        // Retained result verification may name a historical Release session.
        // The accepting Root owner must nevertheless be the exact current head,
        // not another valid live session holding an unrelated verified outcome.
        let current_session = graph
            .provider_sessions
            .values()
            .find(|session| {
                stored_mount_session_matches_projection(session, &current_projection)
                    && session.scope == row.scope
            })
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        if graph
            .provider_heads
            .get(&(
                row.scope.holder_authority_id,
                row.scope.provider_authority_id,
            ))
            .is_none_or(|head| head.current_session_id != current_session.session_id)
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        let ProviderAttemptStateV2::DispositionConsumed {
            status: ProviderStatusV2::Pending,
            signed_status,
            signed_result,
            response_sequence,
            verification_anchor,
            ..
        } = &attempt.state
        else {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        };
        let status = SignedSourceProviderStatusV1::from_canonical_bytes(signed_status)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let retained =
            ReleaseSourceResponseProfileV2::from_parts(status, Some(signed_result.clone()))
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let fence = validate_native_export_fence_v1(row, attempt, &graph)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?
            .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        if row.phase != SourceAcquisitionPhaseV2::Releasing
            || *verification_anchor != outcome.verification_anchor
            || *response_sequence != outcome.response_sequence
            || outcome.status != SourceProviderStatus::Pending
            || outcome.canonical_response != retained.to_canonical_bytes()
            || outcome.session_binding.as_bytes()
                != &graph
                    .provider_sessions
                    .get(&attempt.session_id)
                    .ok_or_else(|| self.poison(SourceProviderSecurityError::SessionContinuity))?
                    .session_binding
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }

        for record in [
            StoredRecordV2::ProviderQueryAttempt {
                value: attempt.clone(),
            },
            StoredRecordV2::Acquisition { value: row.clone() },
        ] {
            let (key, bytes) = encode_mount_source_state_record_v2(&record)
                .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
            if journal.get(&key).ok().flatten() != Some(bytes.as_slice()) {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
        }
        journal
            .validate_mount_source_acquisition_snapshot(&snapshot)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        self.revalidate()?;
        outcome.native_export_fence_acceptance = Some(RootAcceptedNativeExportFenceV1 {
            acquisition_id: ObjectDigest::from_bytes(acquisition_id),
            attempt: outcome::helpers::attempt_reference(attempt),
            fence,
        });
        Ok(())
    }
}
