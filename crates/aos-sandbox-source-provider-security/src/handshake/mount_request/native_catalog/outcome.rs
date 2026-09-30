//! Original native selection custody across Mount outcome verification and commit.
//!
//! The retained response proves the original bounded catalog observation, not
//! a writer-held remote head at outcome time. The positive Provider owner must
//! independently rejoin its protected head and floor around signing and
//! completion; that owner path remains a separate activation prerequisite.

use super::*;
use aos_sandbox_source_provider_protocol::native_held_completion::witness::{
    NativeHeldByteWitnessV1, RootNativeHeldWitnessV1,
};

// Shares an existing owner rather than duplicating its non-Clone guard. A DATA
// marker can exercise this retention seam without constructing session custody.
pub(in crate::handshake::mount_request) fn retain_original_outcome_owner<T>(
    original: &Option<std::sync::Arc<T>>,
) -> Option<std::sync::Arc<T>> {
    original.as_ref().map(std::sync::Arc::clone)
}

pub(in crate::handshake::mount_request) fn require_native_completion_barrier(
    native_positive: bool,
) -> Result<(), SourceProviderSecurityError> {
    // RFC-0021 section 17 requires a held cross-owner cut through the Mount
    // CAS and handoff. The earlier remote observation is not that authority.
    // No original Provider completion/FD-acceptance barrier reaches this owner.
    if native_positive {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}

/// Keeps the same opaque guard and exact request after successful carrier send.
pub(in crate::handshake::mount_request) struct NativeAcquireOutcomeCustodyV3 {
    guard: Option<NativeAcquireCurrentnessGuardV3>,
    signed_request: SignedSourceProviderRequestV1,
}

impl NativeAcquireOutcomeCustodyV3 {
    pub(in crate::handshake::mount_request) fn original_root_witness(
        &self,
        records: [NativeHeldByteWitnessV1; 4],
        sequence: u64,
    ) -> Result<RootNativeHeldWitnessV1, SourceProviderSecurityError> {
        self.guard()?.original_root_witness(records, sequence)
    }

    /// Allocates no authority: the actual Guard must subsequently be moved in.
    pub(in crate::handshake::mount_request) fn empty_shell(
        signed_request: SignedSourceProviderRequestV1,
    ) -> Self {
        Self {
            guard: None,
            signed_request,
        }
    }

    pub(in crate::handshake::mount_request) fn guard(
        &self,
    ) -> Result<&NativeAcquireCurrentnessGuardV3, SourceProviderSecurityError> {
        self.guard
            .as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)
    }

    /// Moves only an already borrowed actual guard slot into the unique shell.
    pub(in crate::handshake::mount_request) fn park_guard(
        &mut self,
        guard: &mut Option<NativeAcquireCurrentnessGuardV3>,
    ) {
        self.guard = guard.take();
    }

    fn validate_request(&self) -> Result<AcquireSourceRequestV1, SourceProviderSecurityError> {
        let guard = self.guard()?;
        let preparation = &guard.preparation;
        let proof = guard.proof()?;
        let request = decode_acquire_request(self.signed_request.subject())
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let catalog = join_current_catalog_claims(
            &proof.signed,
            &proof.query,
            &preparation.publication,
            preparation.mount_head_minimum,
        )?;
        if self.signed_request.method() != SourceProviderMethod::Acquire {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        require_native_request_selection(
            &request,
            &catalog,
            guard.binding_digest,
            proof.query.session_binding(),
            preparation.deadline.initial.paired.host_boot_id(),
            preparation.deadline.expires_seconds,
        )?;
        Ok(request)
    }

    fn validate_response(
        &self,
        canonical_response: &[u8],
    ) -> Result<Option<i64>, SourceProviderSecurityError> {
        let guard = self.guard()?;
        let request = self.validate_request()?;
        let response = decode_acquire_response(canonical_response)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let status = response.signed_status().subject();
        if status.signed_request_digest() != digest_signed_request(&self.signed_request) {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        if response.status() != SourceProviderStatus::Complete {
            return Ok(None);
        }
        let receipt = response
            .signed_receipt()
            .and_then(|bytes| SignedSourceProviderReceiptV1::from_canonical_bytes(bytes).ok())
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let lease = SignedSourceExportLeaseV1::from_canonical_bytes(
            receipt.subject().signed_export_lease(),
        )
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        let request_identity = (request.request_id(), digest_acquire_request(&request));
        if receipt.subject().request_identity() != request_identity
            || lease.subject().request_identity() != request_identity
            || receipt.subject().acquisition_id() != request.acquisition_id()
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        require_exact_native_selection(
            &guard.resource,
            &guard.snapshot,
            lease.subject().resource(),
            lease.subject().proof(),
        )?;
        Ok(Some(lease.subject().expires_seconds()))
    }
}

impl CurrentRootMountSourceProviderSessionV1 {
    pub(in crate::handshake::mount_request) fn require_native_outcome_authorization_v3(
        &mut self,
        authorization: &AuthorizedMountProviderOutcomeV2,
    ) -> Result<(), SourceProviderSecurityError> {
        let Some(original) = &authorization.native_outcome else {
            return Ok(());
        };
        let guard = original.guard().map_err(|error| self.poison(error))?;
        let preparation = &guard.preparation;
        let proof = guard.proof().map_err(|error| self.poison(error))?;
        if authorization.method != SourceProviderMethod::Acquire
            || authorization.deadline_policy != OutcomeDeadlinePolicyV2::Fresh
            || authorization.historical_session.is_some()
            || authorization.signed_request != original.signed_request
            || authorization.current_catalog_head_commitment
                != Some(proof.signed.head_commitment())
            || authorization.catalog_floor.as_ref().is_none_or(|floor| {
                floor.provider_authority_id()
                    != preparation.publication.provider().authority_id()
                    || floor.resource_namespace_digest()
                        != preparation.publication.resource_namespace_digest()
                    || (
                        floor.minimum_catalog_generation(),
                        floor.minimum_catalog_digest(),
                    ) != proof.signed.floor()
            })
            || original.validate_request().is_err()
        {
            return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
        }
        self.require_native_acquire_currentness_v3(guard)
    }

    pub(in crate::handshake::mount_request) fn require_native_outcome_response_v3(
        &mut self,
        authorization: &AuthorizedMountProviderOutcomeV2,
        canonical_response: &[u8],
        positive: bool,
    ) -> Result<(), SourceProviderSecurityError> {
        self.require_native_outcome_authorization_v3(authorization)?;
        if authorization.method != SourceProviderMethod::Acquire {
            return Ok(());
        }
        let request = decode_acquire_request(authorization.signed_request.subject())
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        require_original_native_outcome(
            request.native_catalog().is_some(),
            positive,
            authorization.native_outcome.is_some(),
        )
        .map_err(|error| self.poison(error))?;
        if let Some(original) = &authorization.native_outcome {
            self.require_native_response_custody_v3(original, canonical_response)?;
        }
        Ok(())
    }

    pub(in crate::handshake::mount_request) fn require_verified_native_outcome_v3(
        &mut self,
        outcome: &VerifiedMountProviderOutcomeV2,
        signed_request: &[u8],
    ) -> Result<(), SourceProviderSecurityError> {
        let request = SignedSourceProviderRequestV1::from_canonical_bytes(signed_request)
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        let acquire = decode_acquire_request(request.subject())
            .map_err(|_| self.poison(SourceProviderSecurityError::SessionContinuity))?;
        require_original_native_outcome(
            acquire.native_catalog().is_some(),
            outcome.status == SourceProviderStatus::Complete,
            outcome.native_outcome.is_some(),
        )
        .map_err(|error| self.poison(error))?;
        if let Some(original) = &outcome.native_outcome {
            if request != original.signed_request || outcome.method != SourceProviderMethod::Acquire
            {
                return Err(self.poison(SourceProviderSecurityError::SessionContinuity));
            }
            self.require_native_response_custody_v3(original, &outcome.canonical_response)?;
        }
        require_native_completion_barrier(
            acquire.native_catalog().is_some() && outcome.status == SourceProviderStatus::Complete,
        )
        .map_err(|error| self.poison(error))?;
        Ok(())
    }

    fn require_native_response_custody_v3(
        &mut self,
        original: &NativeAcquireOutcomeCustodyV3,
        canonical_response: &[u8],
    ) -> Result<(), SourceProviderSecurityError> {
        let guard = original.guard().map_err(|error| self.poison(error))?;
        let lease_expiry = original
            .validate_response(canonical_response)
            .map_err(|error| self.poison(error))?;
        self.require_native_acquire_currentness_v3(guard)?;
        if let Some(expires) = lease_expiry {
            let now = kernel_clock().map_err(|error| self.poison(error))?;
            guard
                .preparation
                .deadline
                .require_current_until(now, expires)
                .map_err(|error| self.poison(error))?;
        }
        Ok(())
    }
}

impl OriginalNativeDeadlineV3 {
    fn require_current_until(
        &self,
        later: RawPairedClockSample,
        lease_expires: i64,
    ) -> Result<(), SourceProviderSecurityError> {
        self.require_current(later)?;
        let expires = lease_expires.min(self.expires_seconds);
        // A shorter lease uses the same original before-read and paired sample.
        // Outcome latency cannot renew or rebase the retained BOOTTIME fence.
        let deadline =
            conservative_boot_ceiling(&self.initial, expires)?.min(self.boottime_deadline);
        if later.wall_seconds() >= expires || later.boottime_nanoseconds() >= deadline {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        Ok(())
    }
}

fn require_native_request_selection(
    request: &AcquireSourceRequestV1,
    catalog: &NativeAcquireCatalogBindingV3,
    binding: ObjectDigest,
    session: ObjectDigest,
    boot: [u8; 16],
    deadline: i64,
) -> Result<(), SourceProviderSecurityError> {
    if request.native_catalog() != Some(catalog)
        || request.binding_digest() != binding
        || request.session_binding() != session
        || request.boot_id() != boot
        || request.deadline_seconds() != deadline
        || request.kernel_coupled()
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}

fn require_original_native_outcome(
    native_request: bool,
    positive: bool,
    original_retained: bool,
) -> Result<(), SourceProviderSecurityError> {
    if original_retained != native_request && (original_retained || positive) {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}

fn require_exact_native_selection(
    resource: &SourceResourceV1,
    snapshot: &ZfsHeldSnapshotProofV1,
    returned_resource: &SourceResourceV1,
    returned_proof: &aos_sandbox_source_provider_protocol::SourceProviderProofV1,
) -> Result<(), SourceProviderSecurityError> {
    let aos_sandbox_source_provider_protocol::SourceProviderProofV1::ZfsHeldSnapshot {
        proof, ..
    } = returned_proof
    else {
        return Err(SourceProviderSecurityError::SessionContinuity);
    };
    if resource != returned_resource || snapshot != proof {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{clock, native_deadline_draft};
    use super::*;
    use aos_sandbox_source_provider_protocol::{RecursiveTopologyProofV1, SourceProviderProofV1};
    use std::sync::Arc;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    fn catalog_binding() -> NativeAcquireCatalogBindingV3 {
        NativeAcquireCatalogBindingV3::new(
            digest(9),
            5,
            digest(5),
            4,
            digest(4),
            digest(6),
            digest(7),
        )
        .unwrap()
    }

    fn resource(change: Option<&str>) -> SourceResourceV1 {
        SourceResourceV1::new(
            digest(if change == Some("namespace") { 19 } else { 9 }),
            [if change == Some("resource ID") { 13 } else { 3 }; 32],
            if change == Some("resource generation") {
                14
            } else {
                4
            },
            digest(if change == Some("resource digest") {
                15
            } else {
                5
            }),
            if change == Some("catalog generation") {
                18
            } else {
                8
            },
            digest(if change == Some("catalog digest") {
                16
            } else {
                6
            }),
            if change == Some("selection generation") {
                16
            } else {
                6
            },
            digest(if change == Some("selection digest") {
                17
            } else {
                7
            }),
        )
        .unwrap()
    }

    fn snapshot(change: Option<&str>) -> ZfsHeldSnapshotProofV1 {
        ZfsHeldSnapshotProofV1::new(
            [if change == Some("storage handle") {
                11
            } else {
                1
            }; 32],
            if change == Some("storage version") {
                11
            } else {
                1
            },
            if change == Some("pool GUID") { 12 } else { 2 },
            if change == Some("dataset GUID") {
                13
            } else {
                3
            },
            if change == Some("snapshot GUID") {
                14
            } else {
                4
            },
            [if change == Some("hold ID") { 15 } else { 5 }; 16],
            if change == Some("hold generation") {
                16
            } else {
                6
            },
            digest(if change == Some("active hold") { 17 } else { 7 }),
            digest(if change == Some("root policy") { 18 } else { 8 }),
            digest(if change == Some("content") { 19 } else { 9 }),
        )
        .unwrap()
    }

    fn proof(snapshot: ZfsHeldSnapshotProofV1) -> SourceProviderProofV1 {
        SourceProviderProofV1::ZfsHeldSnapshot {
            proof: snapshot,
            topology: RecursiveTopologyProofV1::new([1; 16], 1, digest(2), 1, 0, 1, 0).unwrap(),
        }
    }

    #[test]
    fn native_positive_without_a_completion_barrier_stays_closed_and_v2_is_unchanged() {
        assert!(require_original_native_outcome(false, true, false).is_ok());
        assert!(require_original_native_outcome(false, false, false).is_ok());
        assert!(require_original_native_outcome(true, false, false).is_ok());
        assert!(require_original_native_outcome(true, true, true).is_ok());
        assert!(require_original_native_outcome(true, true, false).is_err());
        assert!(require_original_native_outcome(false, true, true).is_err());

        assert!(require_native_completion_barrier(false).is_ok());
        assert!(require_native_completion_barrier(true).is_err());
    }

    #[test]
    fn verified_and_recovery_retention_share_the_same_nonclone_original_owner() {
        // DATA only: this marker has no received proof, session or FD authority.
        struct OriginalMarker(u8);

        let sent = Some(Arc::new(OriginalMarker(7)));
        let original = Arc::downgrade(sent.as_ref().unwrap());
        let verified = retain_original_outcome_owner(&sent);
        assert!(Arc::ptr_eq(
            sent.as_ref().unwrap(),
            verified.as_ref().unwrap()
        ));

        let recovery = verified;
        drop(sent);
        assert_eq!(original.upgrade().unwrap().0, 7);
        assert!(Arc::ptr_eq(
            &original.upgrade().unwrap(),
            recovery.as_ref().unwrap()
        ));

        drop(recovery);
        assert!(original.upgrade().is_none());
    }

    #[test]
    fn every_native_catalog_claim_must_match_the_original_request() {
        let original = catalog_binding();
        let request =
            AcquireSourceRequestV1::new_native_v3(native_deadline_draft(110), original.clone())
                .unwrap();
        let validate = |catalog: &NativeAcquireCatalogBindingV3| {
            require_native_request_selection(
                &request,
                catalog,
                request.binding_digest(),
                digest(1),
                [5; 16],
                110,
            )
        };
        assert!(validate(&original).is_ok());

        for (field, namespace, head, floor, commitment, publication) in [
            (
                "namespace",
                digest(19),
                (5, digest(5)),
                (4, digest(4)),
                digest(6),
                digest(7),
            ),
            (
                "head generation",
                digest(9),
                (6, digest(5)),
                (4, digest(4)),
                digest(6),
                digest(7),
            ),
            (
                "head digest",
                digest(9),
                (5, digest(15)),
                (4, digest(4)),
                digest(6),
                digest(7),
            ),
            (
                "floor generation",
                digest(9),
                (5, digest(5)),
                (3, digest(4)),
                digest(6),
                digest(7),
            ),
            (
                "floor digest",
                digest(9),
                (5, digest(5)),
                (4, digest(14)),
                digest(6),
                digest(7),
            ),
            (
                "head commitment",
                digest(9),
                (5, digest(5)),
                (4, digest(4)),
                digest(16),
                digest(7),
            ),
            (
                "publication",
                digest(9),
                (5, digest(5)),
                (4, digest(4)),
                digest(6),
                digest(17),
            ),
        ] {
            let changed = NativeAcquireCatalogBindingV3::new(
                namespace,
                head.0,
                head.1,
                floor.0,
                floor.1,
                commitment,
                publication,
            )
            .unwrap();
            assert!(validate(&changed).is_err(), "{field}");
        }
        for (binding, session, boot, deadline) in [
            (digest(20), digest(1), [5; 16], 110),
            (request.binding_digest(), digest(21), [5; 16], 110),
            (request.binding_digest(), digest(1), [22; 16], 110),
            (request.binding_digest(), digest(1), [5; 16], 111),
        ] {
            assert!(
                require_native_request_selection(
                    &request, &original, binding, session, boot, deadline,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn complete_native_selection_compares_every_resource_and_snapshot_field() {
        let original_resource = resource(None);
        let original_snapshot = snapshot(None);
        assert!(
            require_exact_native_selection(
                &original_resource,
                &original_snapshot,
                &original_resource,
                &proof(original_snapshot.clone()),
            )
            .is_ok()
        );

        for field in [
            "namespace",
            "resource ID",
            "resource generation",
            "resource digest",
            "catalog generation",
            "catalog digest",
            "selection generation",
            "selection digest",
        ] {
            assert!(
                require_exact_native_selection(
                    &original_resource,
                    &original_snapshot,
                    &resource(Some(field)),
                    &proof(original_snapshot.clone()),
                )
                .is_err(),
                "{field}"
            );
        }
        for field in [
            "storage handle",
            "storage version",
            "pool GUID",
            "dataset GUID",
            "snapshot GUID",
            "hold ID",
            "hold generation",
            "active hold",
            "root policy",
            "content",
        ] {
            assert!(
                require_exact_native_selection(
                    &original_resource,
                    &original_snapshot,
                    &original_resource,
                    &proof(snapshot(Some(field))),
                )
                .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn shorter_lease_retains_original_clock_and_rejects_expiry_boot_and_drift() {
        let original = clock(100, 200, 5);
        let deadline = OriginalNativeDeadlineV3::from_sample(original, 110, u64::MAX).unwrap();
        assert!(
            deadline
                .require_current_until(clock(103, 203, 5), 105)
                .is_ok()
        );

        for later in [
            clock(104, 204, 5),
            clock(105, 203, 5),
            clock(103, 203, 6),
            clock(99, 201, 5),
            clock(101, 199, 5),
            clock(104, 201, 5),
        ] {
            assert!(deadline.require_current_until(later, 105).is_err());
        }
        assert_eq!(deadline.initial.paired, original);
        assert_eq!(deadline.expires_seconds, 110);
        assert_eq!(deadline.boottime_deadline, 209_000_000_000);
    }
}
