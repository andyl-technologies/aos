//! One owned Root1-first original Acquire pair, before any Source reservation.
//!
//! This lane borrows shared ledger/configuration data and the sole real Session,
//! never a mutable ProviderLedger or an effect closure. Pending and closed state
//! cannot fall back to an old backend, signing, capacity or migration path.

use aos_sandbox::{ProtectedJournalAuthority, ProtectedJournalSnapshot};
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_source_provider_protocol::{
    ACQUIRE_SOURCE_REQUEST_VERSION_V3, AcquireSourceRequestV1, SignedSourceProviderRequestV1,
    SourceProviderMethod, VerifiedProviderRequestSequenceV1, VerifiedProviderRequestV1,
    digest_signed_request, native_held_completion::NativeHeldScopeV1,
    held_snapshot_catalog::MAXIMUM_HELD_SNAPSHOT_CATALOG_BYTES_V1,
};
use aos_sandbox_source_provider_security::{
    CurrentProviderIngressSessionV1, CurrentProviderOriginalCarrierPacketV1,
    CurrentProviderRequestV1, CurrentRootPreparedCarrierV1,
};

use super::{
    FixedProviderIngressProgressV1, FixedProviderOwnerStateV1, FixedProviderOwnerV1,
    claim_fixed_provider_authority, configured_ledger,
};
use crate::{
    ProviderLedgerError, model::RecoveredProviderLedgerV1, state::ProtectedProviderConfigurationV1,
};

#[derive(Default)]
pub(super) struct OriginalIngressV1 {
    pending: Option<RetainedOriginalPairV1>,
    rejected_packet: Option<Vec<u8>>,
    producer_failure: Option<super::original_journal::producer::OriginalProducerErrorV5>,
    closed: bool,
}

struct RetainedOriginalPairV1 {
    root: CurrentRootPreparedCarrierV1,
    cut: OriginalIngressCutV1,
    acquire_packet: Option<Vec<u8>>,
    acquire: Option<CurrentProviderRequestV1>,
    selection: Option<crate::acquire::CurrentSelection>,
    clock: Option<crate::native_completion::NativeAcquireClockGuardV1>,
    catalog: RetainedOriginalCatalogV1,
}

// The original pair owns one bounded public catalog preimage. Inline storage
// parks the bytes before authentication without a fallible retention allocation.
struct RetainedOriginalCatalogV1 {
    bytes: [u8; MAXIMUM_HELD_SNAPSHOT_CATALOG_BYTES_V1],
    length: Option<usize>,
}

impl Default for RetainedOriginalCatalogV1 {
    fn default() -> Self {
        Self {
            bytes: [0; MAXIMUM_HELD_SNAPSHOT_CATALOG_BYTES_V1],
            length: None,
        }
    }
}

impl RetainedOriginalCatalogV1 {
    fn retain(&mut self, bytes: &[u8]) -> Result<(), ProviderLedgerError> {
        if bytes.len() > self.bytes.len() {
            return Err(ProviderLedgerError::LimitExceeded(
                "original held catalog bytes",
            ));
        }
        if let Some(length) = self.length {
            if self.bytes[..length] != *bytes {
                return Err(ProviderLedgerError::Equivocation);
            }
            return Ok(());
        }

        self.bytes[..bytes.len()].copy_from_slice(bytes);
        self.length = Some(bytes.len());
        Ok(())
    }

    fn bytes(&self) -> Result<&[u8], ProviderLedgerError> {
        let length = self.length.ok_or(ProviderLedgerError::Unavailable)?;
        Ok(&self.bytes[..length])
    }
}

struct OriginalIngressCutV1 {
    snapshot: ProtectedJournalSnapshot,
    configuration: ObjectDigest,
    session: ObjectDigest,
}

pub(super) enum ReceivedOriginalIngressV1 {
    Ordinary(Vec<u8>),
    Progress(FixedProviderIngressProgressV1),
}

impl OriginalIngressV1 {
    /// Borrows the exact catalog parked before the original pair authentication.
    pub(super) fn borrowed_catalog_v1(&self) -> Result<&[u8], ProviderLedgerError> {
        self.borrowed_pair_v5()?;
        self.pending
            .as_ref()
            .ok_or(ProviderLedgerError::Unavailable)?
            .catalog
            .bytes()
    }

    pub(super) fn retain_producer_failure_v5(
        &mut self,
        cause: super::original_journal::producer::OriginalProducerErrorV5,
    ) {
        if self.producer_failure.is_none() {
            self.producer_failure = Some(cause);
        }
        self.close_if_retained();
    }

    pub(super) fn producer_failure_v5(
        &self,
    ) -> Option<&super::original_journal::producer::OriginalProducerErrorV5> {
        self.producer_failure.as_ref()
    }

    pub(super) fn producer_closed_v5(&self) -> bool {
        self.closed
    }

    /// Borrows the selected owner retained by the sole original pairing engine.
    pub(super) fn borrowed_selection_v5(
        &self,
    ) -> Result<&crate::acquire::CurrentSelection, ProviderLedgerError> {
        self.borrowed_pair_v5()?;
        self.pending.as_ref().and_then(|pair| pair.selection.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)
    }

    /// Captures one original clock only while the genuine fresh pair is resident.
    pub(super) fn retain_original_clock_v5(&mut self) -> Result<(), ProviderLedgerError> {
        self.borrowed_pair_v5()?;
        let pending = self.pending.as_mut().ok_or(ProviderLedgerError::Unavailable)?;
        let acquire = pending.acquire.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let VerifiedProviderRequestV1::Acquire(verified) = acquire.verified() else {
            return Err(ProviderLedgerError::Equivocation);
        };
        let signed = SignedSourceProviderRequestV1::from_canonical_bytes(
            verified.attempt().canonical_signed_request(),
        ).map_err(|_| ProviderLedgerError::Equivocation)?;
        if pending.clock.is_none() {
            pending.clock = Some(
                crate::native_completion::NativeAcquireClockGuardV1::before_challenge(
                    &signed,
                    verified.attempt().attempt_digest(),
                    verified.ingress_projection().verified_at_seconds(),
                    verified.ingress_projection().current_valid_until_seconds(),
                )?,
            );
        }
        pending.clock.as_ref().ok_or(ProviderLedgerError::Unavailable)?
            .require_original(&signed, verified.attempt().attempt_digest())
    }

    pub(super) fn borrowed_clock_v5(
        &self,
    ) -> Result<&crate::native_completion::NativeAcquireClockGuardV1, ProviderLedgerError> {
        self.borrowed_pair_v5()?;
        self.pending.as_ref().and_then(|pair| pair.clock.as_ref())
            .ok_or(ProviderLedgerError::Unavailable)
    }

    /// Borrows the already authenticated full pair without moving its custody.
    pub(super) fn borrowed_pair_v5(
        &self,
    ) -> Result<(&CurrentRootPreparedCarrierV1, &CurrentProviderRequestV1), ProviderLedgerError> {
        self.require_open()?;
        let pending = self.pending.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let acquire = pending.acquire.as_ref().ok_or(ProviderLedgerError::Unavailable)?;
        let VerifiedProviderRequestV1::Acquire(verified) = acquire.verified() else {
            return Err(ProviderLedgerError::Equivocation);
        };
        if pending.acquire_packet.as_deref() != Some(verified.attempt().canonical_signed_request()) {
            return Err(ProviderLedgerError::Equivocation);
        }

        Ok((&pending.root, acquire))
    }

    /// Requires the original real preappend cut, not a later reconstructed cut.
    pub(super) fn require_borrowed_cut_v5(
        &self,
        journal: &ProtectedJournalAuthority<'_>,
        configuration: ObjectDigest,
        session: ObjectDigest,
    ) -> Result<(), ProviderLedgerError> {
        self.borrowed_pair_v5()?;
        let cut = &self.pending.as_ref().ok_or(ProviderLedgerError::Unavailable)?.cut;
        journal.validate_fixed_source_provider_storage()?;
        journal.validate_source_provider_authority_snapshot(&cut.snapshot)?;
        if cut.configuration != configuration || cut.session != session {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }

        Ok(())
    }

    pub(super) fn close_original_writer_v5(&mut self) {
        self.close_if_retained();
    }

    fn require_idle(&self) -> Result<(), ProviderLedgerError> {
        if self.closed || self.pending.is_some() {
            return Err(ProviderLedgerError::InvalidTransition(
                "original native ingress retains exclusive carrier custody",
            ));
        }
        Ok(())
    }

    fn require_open(&self) -> Result<(), ProviderLedgerError> {
        if self.closed {
            return Err(ProviderLedgerError::InvalidTransition(
                "original native ingress is closed",
            ));
        }
        Ok(())
    }

    fn close_if_retained(&mut self) {
        if self.pending.is_some() || self.rejected_packet.is_some() {
            self.closed = true;
        }
    }
}

impl FixedProviderOwnerV1 {
    pub(crate) fn require_original_ingress_idle(&self) -> Result<(), ProviderLedgerError> {
        self.original_ingress.require_idle()
    }

    /// Reports retained original carrier custody, never an admission grant.
    #[must_use]
    pub fn original_native_pair_pending(&self) -> bool {
        self.original_ingress.pending.is_some() || self.original_ingress.closed
    }

    /// Reports irreversible failed carrier custody without exposing its bytes.
    #[must_use]
    pub fn original_native_ingress_closed(&self) -> bool {
        self.original_ingress.closed
    }

    /// Closes retained original custody after an outer ingress failure.
    ///
    /// All original packets, cut and owning objects remain in this owner. This
    /// only refuses progress; it cannot clear custody or authorize a fallback.
    pub fn close_original_native_ingress_after_failure(&mut self) {
        self.original_ingress.close_if_retained();
    }

    /// Advances only the retained Root1-to-original-Acquire carrier pair.
    ///
    /// The fixed caller supplies current protected publication/row bytes. No
    /// Source reservation, sequence advance, clock, nonce or effect is created.
    ///
    /// # Errors
    ///
    /// Rejects absent/closed custody, changed physical/current cut, interleaved
    /// packets, or a nonfresh or unjoined Acquire. All owning state is retained.
    pub fn advance_original_native_pair(
        &mut self,
        publication: &[u8],
        rows: &[u8],
    ) -> Result<FixedProviderIngressProgressV1, ProviderLedgerError> {
        if self.original_ingress.pending.is_none() {
            self.original_ingress.require_open()?;
            return Err(ProviderLedgerError::InvalidTransition(
                "original Root1 is not retained",
            ));
        }
        match self.receive_original_ingress(publication, Some(rows))? {
            ReceivedOriginalIngressV1::Progress(progress) => Ok(progress),
            ReceivedOriginalIngressV1::Ordinary(_) => {
                self.original_ingress.closed = true;
                Err(ProviderLedgerError::Equivocation)
            }
        }
    }

    pub(super) fn receive_original_ingress(
        &mut self,
        publication: &[u8],
        rows: Option<&[u8]>,
    ) -> Result<ReceivedOriginalIngressV1, ProviderLedgerError> {
        self.original_ingress.require_open()?;
        // These old containers already own this carrier; never overwrite them.
        let carrier_idle = self.recovery_handshake.is_none()
            && self.ingress_reopen.is_none()
            && self.pending_backend_recovery.is_empty()
            && self.priority_mount_retry_digest.is_none()
            && self.priority_mount_retry_rearm_digest.is_none()
            && self.pending_catalog_currentness.is_none()
            && self.pending_recovery_query_digest.is_none()
            && self.pending_inventory_readback_digest.is_none();
        let Some(FixedProviderOwnerStateV1::Ready(detached)) = self.state.as_mut() else {
            return Err(ProviderLedgerError::InvalidTransition(
                "original ingress requires Ready",
            ));
        };

        let pair = &mut self.original_ingress;
        let result = (|| {
            let journal = claim_fixed_provider_authority(self.journal.as_mut())?;
            let original_idle = carrier_idle && detached.original_ingress_is_idle().is_ok();
            let (configuration, recovered, session) = detached.original_ingress_parts()?;
            if let Some(pending) = &mut pair.pending {
                if !original_idle {
                    return Err(ProviderLedgerError::Unavailable);
                }
                let before = OriginalIngressCutV1::capture(
                    &journal,
                    configuration,
                    recovered,
                    session,
                    publication,
                )?;
                pending.cut.require_current(&journal, &before)?;
                session.revalidate_root_prepared_carrier_v1(&pending.root)?;
                if pending.acquire.is_some() {
                    // Do not consume another transport packet after pairing.
                    if let Some(rows) = rows {
                        pending.catalog.retain(rows)?;
                    }
                    let after = OriginalIngressCutV1::capture(
                        &journal,
                        configuration,
                        recovered,
                        session,
                        publication,
                    )?;
                    pending.cut.require_current(&journal, &after)?;
                    session.revalidate_root_prepared_carrier_v1(&pending.root)?;
                    return Ok(ReceivedOriginalIngressV1::Progress(
                        FixedProviderIngressProgressV1::OriginalPairRetained,
                    ));
                }
            }

            let before_snapshot = journal.snapshot()?;
            let Some(packet) = session.receive_current_original_packet_v1()? else {
                if let Some(pending) = &pair.pending {
                    let after = OriginalIngressCutV1::capture(
                        &journal,
                        configuration,
                        recovered,
                        session,
                        publication,
                    )?;
                    pending.cut.require_current(&journal, &after)?;
                    session.revalidate_root_prepared_carrier_v1(&pending.root)?;
                }
                return Ok(ReceivedOriginalIngressV1::Progress(
                    FixedProviderIngressProgressV1::Pending,
                ));
            };
            let received = match packet {
                CurrentProviderOriginalCarrierPacketV1::RootPrepared(root) => {
                    if let Some(pending) = &pair.pending {
                        if pending.root.control().to_canonical_bytes()
                            != root.control().to_canonical_bytes()
                        {
                            pair.rejected_packet = Some(root.control().to_canonical_bytes());
                            return Err(ProviderLedgerError::Equivocation);
                        }
                    } else {
                        // Retain the owning Root1 BEFORE every post-receive check.
                        let cut = OriginalIngressCutV1 {
                            snapshot: before_snapshot,
                            configuration: configuration.deployment_digest(),
                            session: root.control().scope().original_source_session,
                        };
                        pair.pending = Some(RetainedOriginalPairV1 {
                            root,
                            cut,
                            acquire_packet: None,
                            acquire: None,
                            selection: None,
                            clock: None,
                            catalog: RetainedOriginalCatalogV1::default(),
                        });
                    }
                    if !original_idle {
                        return Err(ProviderLedgerError::Unavailable);
                    }
                    ReceivedOriginalIngressV1::Progress(
                        FixedProviderIngressProgressV1::OriginalRootPreparedRetained,
                    )
                }
                CurrentProviderOriginalCarrierPacketV1::Source(packet) => {
                    if let Some(pending) = pair.pending.as_mut() {
                        pending.acquire_packet = Some(packet);
                        let rows = rows.ok_or(ProviderLedgerError::Unavailable)?;
                        pending.catalog.retain(rows)?;
                        authenticate_original_pair(
                            &journal,
                            configuration,
                            recovered,
                            session,
                            pending,
                            publication,
                            rows,
                        )?;
                        ReceivedOriginalIngressV1::Progress(
                            FixedProviderIngressProgressV1::OriginalPairRetained,
                        )
                    } else {
                        // Preserve every old ordinary/debt/replay precondition.
                        return Ok(ReceivedOriginalIngressV1::Ordinary(packet));
                    }
                }
                CurrentProviderOriginalCarrierPacketV1::Rejected { packet, error } => {
                    if pair.pending.is_some() || packet.starts_with(b"AOSNHC01") {
                        pair.rejected_packet = Some(packet);
                    }
                    return Err(error.into());
                }
            };

            let after = OriginalIngressCutV1::capture(
                &journal,
                configuration,
                recovered,
                session,
                publication,
            )?;
            if let Some(pending) = &pair.pending {
                pending.cut.require_current(&journal, &after)?;
                session.revalidate_root_prepared_carrier_v1(&pending.root)?;
            }
            Ok(received)
        })();
        if result.is_err() {
            // Keep the SAME Session, Journal, original Root1 and any raw packet.
            // Poisoned custody is retained, never restored as a usable owner.
            pair.close_if_retained();
        }
        result
    }
}

impl OriginalIngressCutV1 {
    fn capture(
        journal: &ProtectedJournalAuthority<'_>,
        configuration: &ProtectedProviderConfigurationV1,
        recovered: &RecoveredProviderLedgerV1,
        session: &mut CurrentProviderIngressSessionV1,
        publication: &[u8],
    ) -> Result<Self, ProviderLedgerError> {
        journal.validate_fixed_source_provider_storage()?;
        let snapshot = journal.snapshot()?;
        journal.validate_source_provider_authority_snapshot(&snapshot)?;
        let current = configured_ledger(session, publication)?;
        if current.deployment_digest() != configuration.deployment_digest()
            || !current.matches_authority_and_catalog(&recovered.authority, &recovered.catalog)
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        let projection = session.current_projection()?;
        journal.validate_source_provider_authority_snapshot(&snapshot)?;
        Ok(Self {
            snapshot,
            configuration: current.deployment_digest(),
            session: projection.session_binding(),
        })
    }

    fn require_current(
        &self,
        journal: &ProtectedJournalAuthority<'_>,
        current: &Self,
    ) -> Result<(), ProviderLedgerError> {
        journal.validate_fixed_source_provider_storage()?;
        journal.validate_source_provider_authority_snapshot(&self.snapshot)?;
        journal.validate_source_provider_authority_snapshot(&current.snapshot)?;
        if self.configuration != current.configuration || self.session != current.session {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        Ok(())
    }
}

fn authenticate_original_pair(
    journal: &ProtectedJournalAuthority<'_>,
    configuration: &ProtectedProviderConfigurationV1,
    recovered: &RecoveredProviderLedgerV1,
    session: &mut CurrentProviderIngressSessionV1,
    pending: &mut RetainedOriginalPairV1,
    publication: &[u8],
    rows: &[u8],
) -> Result<(), ProviderLedgerError> {
    let signed = SignedSourceProviderRequestV1::from_canonical_bytes(
        pending
            .acquire_packet
            .as_deref()
            .ok_or(ProviderLedgerError::Unavailable)?,
    )
    .map_err(|_| ProviderLedgerError::Equivocation)?;
    if signed.method() != SourceProviderMethod::Acquire {
        return Err(ProviderLedgerError::Equivocation);
    }
    let expectation =
        crate::transaction::request_sequence_expectation_at(journal, recovered, &signed)?;
    let current = session.verify_current_request(&signed, expectation, &[])?;
    pending.acquire = Some(current);
    let VerifiedProviderRequestV1::Acquire(verified) = pending.acquire.as_ref()
        .ok_or(ProviderLedgerError::Unavailable)?.verified() else {
        return Err(ProviderLedgerError::Equivocation);
    };
    require_original_pair_scope(
        pending.root.control().scope(),
        verified.request(),
        digest_signed_request(&signed),
    )?;
    if !matches!(
        verified.sequence(),
        VerifiedProviderRequestSequenceV1::Fresh(_)
    ) || recovered
        .acquisitions
        .values()
        .any(|row| row.acquisition_id == verified.request().acquisition_id())
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    let (holder, same_session) = crate::transaction::projection_session_at(
        configuration,
        recovered,
        verified.ingress_projection(),
    )?;
    if !same_session || verified.ingress_projection().proof_class_capabilities() & 1 == 0 {
        return Err(ProviderLedgerError::ConfigurationMismatch);
    }
    // A first-ever genuine Session has no durable head yet. Bind that exact
    // absence, or the existing canonical head, without bootstrapping a write.
    let projection = verified.ingress_projection();
    let holder_key = crate::format::session_key(
        projection.provider_authority().authority_id(),
        projection.root_mount_authority().authority_id(),
    );
    let expected_holder = holder.as_ref().map(crate::format::encode_session);
    if journal.get(&holder_key)? != expected_holder.as_deref() {
        return Err(ProviderLedgerError::Equivocation);
    }

    let normalized = crate::acquire::normalized_intent(verified)?;
    pending.selection = Some(crate::acquire::select_current_resource_at(
        journal,
        &recovered.catalog,
        session,
        &normalized,
        verified.ingress_projection().resource_namespace_digest(),
        publication,
        rows,
    )?);
    pending.selection.as_ref().ok_or(ProviderLedgerError::Unavailable)?.require_native_claims(
        journal,
        verified
            .request()
            .native_catalog()
            .ok_or(ProviderLedgerError::Equivocation)?,
        verified.ingress_projection().resource_namespace_digest(),
    )?;

    // verify_current_request is PRE-only; close the complete comparison cut.
    session.revalidate_root_prepared_carrier_v1(&pending.root)?;
    let after = OriginalIngressCutV1::capture(
        journal,
        configuration,
        recovered,
        session,
        &recovered.catalog.canonical_publication,
    )?;
    pending.cut.require_current(journal, &after)?;
    session.revalidate_root_prepared_carrier_v1(&pending.root)?;
    Ok(())
}

fn require_original_pair_scope(
    scope: &NativeHeldScopeV1,
    request: &AcquireSourceRequestV1,
    signed_digest: ObjectDigest,
) -> Result<(), ProviderLedgerError> {
    scope
        .validate_root_only()
        .map_err(|_| ProviderLedgerError::Equivocation)?;
    if request.acquisition_version() != ACQUIRE_SOURCE_REQUEST_VERSION_V3
        || request.kernel_coupled()
        || scope.original_source_session != request.session_binding()
        || scope.provider_acquisition != request.acquisition_id()
        || scope.original_root_request != signed_digest
    {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_source_provider_protocol::{
        NativeAcquireCatalogBindingV3, decode_acquire_request, encode_acquire_request,
        native_held_completion::native_held_flight_digest_v1, sign_request,
    };
    use ed25519_dalek::SigningKey;

    #[test]
    fn bounded_catalog_retention_preserves_the_first_bytes() {
        let mut retained = RetainedOriginalCatalogV1::default();
        assert!(retained.bytes().is_err());
        let original = vec![31; retained.bytes.len()];
        retained.retain(&original).unwrap();

        retained.retain(&original).unwrap();
        assert!(retained.retain(&original[..original.len() - 1]).is_err());
        let mut changed = original.clone();
        changed[original.len() - 1] ^= 1;
        assert!(retained.retain(&changed).is_err());
        assert_eq!(retained.bytes().unwrap(), original);
    }

    #[test]
    fn oversized_catalog_is_refused_before_parking_and_retention_is_not_validation() {
        let mut retained = RetainedOriginalCatalogV1::default();
        let oversized = vec![31; retained.bytes.len() + 1];
        assert!(retained.retain(&oversized).is_err());
        assert!(retained.length.is_none());

        // The slot owns raw DATA before authentication; it cannot certify it.
        retained.retain(b"not-a-canonical-catalog").unwrap();
        assert!(
            aos_sandbox_source_provider_protocol::ProviderHeldSnapshotCatalogV1::from_canonical_bytes(
                retained.bytes().unwrap(),
            )
            .is_err()
        );
    }

    fn original() -> (AcquireSourceRequestV1, ObjectDigest, NativeHeldScopeV1) {
        let retained = crate::native_completion::fixture_requested(
            [1; 32],
            500,
            ObjectDigest::from_bytes([2; 32]),
        );
        let signed = retained
            .canonical_request
            .as_ref()
            .unwrap()
            .request()
            .signed_root_request();
        let request = decode_acquire_request(signed.subject()).unwrap();
        let catalog = NativeAcquireCatalogBindingV3::new(
            ObjectDigest::from_bytes([3; 32]),
            2,
            ObjectDigest::from_bytes([4; 32]),
            1,
            ObjectDigest::from_bytes([5; 32]),
            ObjectDigest::from_bytes([6; 32]),
            ObjectDigest::from_bytes([7; 32]),
        )
        .unwrap();
        let request = AcquireSourceRequestV1::new_native_v3(request, catalog).unwrap();
        let signed = sign_request(
            SourceProviderMethod::Acquire,
            encode_acquire_request(&request),
            signed.signer().clone(),
            &SigningKey::from_bytes(&[51; 32]),
        )
        .unwrap();
        let signed_digest = digest_signed_request(&signed);
        let mount_attempt = ObjectDigest::from_bytes([8; 32]);
        let scope = NativeHeldScopeV1 {
            flight: native_held_flight_digest_v1(
                signed_digest,
                mount_attempt,
                request.session_binding(),
            ),
            original_source_session: request.session_binding(),
            mount_attempt,
            provider_attempt: ObjectDigest::from_bytes([0; 32]),
            provider_acquisition: request.acquisition_id(),
            original_root_request: signed_digest,
            original_native_request: ObjectDigest::from_bytes([0; 32]),
        };
        (request, signed_digest, scope)
    }

    #[test]
    fn comparison_joins_only_the_exact_original_v3_request() {
        let (request, signed_digest, scope) = original();
        require_original_pair_scope(&scope, &request, signed_digest).unwrap();

        for changed in [
            NativeHeldScopeV1 {
                provider_acquisition: ObjectDigest::from_bytes([9; 32]),
                ..scope
            },
            NativeHeldScopeV1 {
                provider_attempt: ObjectDigest::from_bytes([9; 32]),
                ..scope
            },
            NativeHeldScopeV1 {
                original_native_request: ObjectDigest::from_bytes([9; 32]),
                ..scope
            },
            NativeHeldScopeV1 {
                flight: ObjectDigest::from_bytes([9; 32]),
                ..scope
            },
        ] {
            assert!(require_original_pair_scope(&changed, &request, signed_digest).is_err());
        }
        assert!(
            require_original_pair_scope(&scope, &request, ObjectDigest::from_bytes([9; 32]))
                .is_err()
        );

        let changed_session = ObjectDigest::from_bytes([9; 32]);
        let changed = NativeHeldScopeV1 {
            original_source_session: changed_session,
            flight: native_held_flight_digest_v1(
                signed_digest,
                scope.mount_attempt,
                changed_session,
            ),
            ..scope
        };
        assert!(require_original_pair_scope(&changed, &request, signed_digest).is_err());
    }

    #[test]
    fn comparison_cannot_retag_an_old_original_v2_packet() {
        let retained = crate::native_completion::fixture_requested(
            [1; 32],
            500,
            ObjectDigest::from_bytes([2; 32]),
        );
        let signed = retained
            .canonical_request
            .as_ref()
            .unwrap()
            .request()
            .signed_root_request();
        let legacy = decode_acquire_request(signed.subject()).unwrap();
        let (_, _, scope) = original();

        assert!(
            require_original_pair_scope(&scope, &legacy, digest_signed_request(signed)).is_err()
        );
        assert_eq!(encode_acquire_request(&legacy), signed.subject());
    }

    #[test]
    fn ordinary_failure_does_not_latch_empty_pair_custody() {
        let mut ingress = OriginalIngressV1::default();
        ingress.close_if_retained();

        ingress.require_idle().unwrap();
        ingress.require_open().unwrap();
        assert!(!ingress.closed);
        assert!(ingress.pending.is_none());
        assert!(ingress.rejected_packet.is_none());
    }

    #[test]
    fn rejected_root_bytes_are_retained_across_repeated_effect_refusals() {
        let original = b"AOSNHC01-rejected-original".to_vec();
        let mut ingress = OriginalIngressV1 {
            pending: None,
            rejected_packet: Some(original.clone()),
            producer_failure: None,
            closed: false,
        };
        ingress.close_if_retained();

        for _ in 0..3 {
            assert!(ingress.require_idle().is_err());
            assert!(ingress.require_open().is_err());
            ingress.close_if_retained();
            assert_eq!(ingress.rejected_packet.as_ref(), Some(&original));
        }
        assert!(ingress.pending.is_none());
    }
}
