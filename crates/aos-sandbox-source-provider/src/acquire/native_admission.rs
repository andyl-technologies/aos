//! Original-carrier native admission and exact protected catalog joins.
//!
//! This owner-local cut admits only a no-dispatch reservation. Catalog claims
//! are not Storage observations, and neither this cut nor its retained clock
//! can construct a native bridge, SourceRoot, or positive lease.

use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::Arc;

use aos_sandbox_source_provider_protocol::{
    NativeAcquireCatalogBindingV3, SignedSourceProviderRequestV1, SourceResourceV1,
    ZfsHeldSnapshotProofV1,
};
use aos_sandbox_source_provider_security::{
    CurrentCatalogPublicationProjectionV1, ProtectedCurrentCatalogPublicationV1,
};
use sha2::{Digest, Sha256};

use super::*;

/// Holds the actual current-row owner alongside its selected comparison data.
pub(crate) struct CurrentSelection {
    current: ProtectedCurrentCatalogPublicationV1,
    projection: CurrentCatalogPublicationProjectionV1,
    publication_digest: ObjectDigest,
    resource: SourceResourceV1,
    snapshot: Option<ZfsHeldSnapshotProofV1>,
}

impl CurrentSelection {
    /// Borrows the already-selected tuple without selecting again or authorizing an effect.
    pub(crate) fn original_selected_tuple(
        &self,
    ) -> (&SourceResourceV1, Option<&ZfsHeldSnapshotProofV1>) {
        (&self.resource, self.snapshot.as_ref())
    }

    /// Borrows the exact publication projection retained at original pairing.
    pub(crate) fn original_publication_projection(
        &self,
    ) -> (&CurrentCatalogPublicationProjectionV1, ObjectDigest) {
        (&self.projection, self.publication_digest)
    }

    pub(crate) fn require_native_claims(
        &self,
        journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
        claims: &NativeAcquireCatalogBindingV3,
        namespace: ObjectDigest,
    ) -> Result<(), ProviderLedgerError> {
        self.current
            .require_native_catalog_binding_v3(journal, claims)?;
        if claims.resource_namespace_digest() != namespace || self.snapshot.is_none() {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        Ok(())
    }

    pub(super) fn resource(&self) -> &SourceResourceV1 {
        &self.resource
    }

    fn require_original(
        &self,
        ledger: &ProviderLedgerV1<'_>,
        normalized: &NormalizedAcquisitionIntentV1,
        rows: &[u8],
    ) -> Result<(), ProviderLedgerError> {
        let selected = self.current.select_held_snapshot_row(
            &ledger.journal,
            rows,
            normalized.binding_digest(),
        )?;
        if !selected.is_current(&ledger.journal)
            || selected.selected()
                != (
                    &self.resource,
                    self.snapshot
                        .as_ref()
                        .ok_or(ProviderLedgerError::Unavailable)?,
                )
        {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        Ok(())
    }

    fn same_selection(&self, other: &Self) -> bool {
        self.projection == other.projection
            && self.publication_digest == other.publication_digest
            && self.resource == other.resource
            && self.snapshot == other.snapshot
    }
}

/// Shares the existing manifest/native row join without weakening its owner.
pub(super) fn select_current_resource(
    ledger: &ProviderLedgerV1<'_>,
    session: &mut CurrentProviderIngressSessionV1,
    normalized: &NormalizedAcquisitionIntentV1,
    namespace: ObjectDigest,
    publication_bytes: &[u8],
    rows: &[u8],
) -> Result<CurrentSelection, ProviderLedgerError> {
    select_current_resource_at(
        &ledger.journal,
        &ledger.recovered.catalog,
        session,
        normalized,
        namespace,
        publication_bytes,
        rows,
    )
}

/// Shares the original row-selection engine with the immutable pairing view.
pub(crate) fn select_current_resource_at(
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    catalog: &crate::model::CatalogHeadRecordV1,
    session: &mut CurrentProviderIngressSessionV1,
    normalized: &NormalizedAcquisitionIntentV1,
    namespace: ObjectDigest,
    publication_bytes: &[u8],
    rows: &[u8],
) -> Result<CurrentSelection, ProviderLedgerError> {
    let configuration = session.revalidated_provider_configuration()?;
    let publication = aos_sandbox_source_provider_security::verify_catalog_publication(
        &configuration,
        publication_bytes,
    )?;
    // The receipt digest is a different domain. V3 commits to ALL signed bytes.
    let publication_digest =
        ObjectDigest::from_bytes(Sha256::digest(publication.canonical_publication()).into());
    let current = session.authorize_fixed_current_catalog_publication_v1(
        journal,
        journal.snapshot()?,
        publication,
    )?;
    let projection = current.projection().clone();
    let (resource, snapshot, is_current) = if normalized.kernel_coupled() {
        let selected = current.select_manifest_row(journal, rows, normalized.binding_digest())?;
        (
            selected.selected().0.clone(),
            None,
            selected.is_current(journal),
        )
    } else {
        let selected =
            current.select_held_snapshot_row(journal, rows, normalized.binding_digest())?;
        (
            selected.selected().0.clone(),
            Some(selected.selected().1.clone()),
            selected.is_current(journal),
        )
    };
    if !is_current
        || resource.resource_namespace_digest() != namespace
        || resource.catalog_generation() != catalog.catalog_generation
        || resource.catalog_digest() != catalog.catalog_digest
    {
        return Err(ProviderLedgerError::ConfigurationMismatch);
    }
    Ok(CurrentSelection {
        current,
        projection,
        publication_digest,
        resource,
        snapshot,
    })
}

fn require_catalog_claims(
    ledger: &ProviderLedgerV1<'_>,
    claims: &NativeAcquireCatalogBindingV3,
    selection: &CurrentSelection,
    namespace: ObjectDigest,
) -> Result<(), ProviderLedgerError> {
    selection.require_native_claims(&ledger.journal, claims, namespace)
}

/// Retains original packet, clock, and selected row until reservation readback.
pub(super) struct OriginalNativeAdmission {
    original: SignedSourceProviderRequestV1,
    acquisition_id: ObjectDigest,
    attempt: ObjectDigest,
    session_binding: ObjectDigest,
    namespace: ObjectDigest,
    normalized: NormalizedAcquisitionIntentV1,
    selection: CurrentSelection,
    clock: Arc<crate::native_completion::NativeAcquireClockGuardV1>,
}

impl OriginalNativeAdmission {
    pub(super) fn prepare(
        ledger: &ProviderLedgerV1<'_>,
        packet: &crate::FixedProviderAuthenticatedSourceRequestV1,
        verified: &VerifiedProviderAcquireRequestV1,
        selection: CurrentSelection,
    ) -> Result<Self, ProviderLedgerError> {
        let request = verified.request();
        let projection = verified.ingress_projection();
        let attempt = verified.attempt();
        let normalized = normalized_intent(verified)?;
        if request.kernel_coupled()
            || projection.proof_class_capabilities() & 1 == 0
            || packet.signed().to_canonical_bytes() != attempt.canonical_signed_request()
        {
            return Err(ProviderLedgerError::Equivocation);
        }
        require_catalog_claims(
            ledger,
            request
                .native_catalog()
                .ok_or(ProviderLedgerError::Equivocation)?,
            &selection,
            projection.resource_namespace_digest(),
        )?;

        // V3 cannot supersede an Applying attempt. Its no-dispatch terminal
        // proof must name the SAME effect/current attempt and holder session.
        if let Some(existing) = ledger
            .recovered
            .acquisitions
            .values()
            .find(|record| record.acquisition_id == request.acquisition_id())
        {
            if !matches!(
                verified.sequence(),
                VerifiedProviderRequestSequenceV1::ExactReplay(_)
            ) || !matches_original_acquisition(
                existing,
                &normalized,
                selection.resource(),
                attempt.attempt_digest(),
            ) {
                return Err(ProviderLedgerError::Equivocation);
            }
        }

        let clock =
            if let Some(retained) = ledger.native_acquire_custody.get(&request.acquisition_id()) {
                Arc::clone(&retained.clock)
            } else {
                if !matches!(
                    verified.sequence(),
                    VerifiedProviderRequestSequenceV1::Fresh(_)
                ) || ledger
                    .recovered
                    .acquisitions
                    .values()
                    .any(|record| record.acquisition_id == request.acquisition_id())
                {
                    // A historical wall interval cannot recreate live authority.
                    return Err(ProviderLedgerError::Unavailable);
                }
                // A fresh pre-append refusal owns only this local sample. It
                // cannot accumulate clock-only entries in the retained owner.
                // A new carrier receive must still verify Fresh and the same
                // signed expiry; existing rows/ExactReplay cannot recapture.
                Arc::new(
                    crate::native_completion::NativeAcquireClockGuardV1::before_challenge(
                        packet.signed(),
                        attempt.attempt_digest(),
                        projection.verified_at_seconds(),
                        projection.current_valid_until_seconds(),
                    )?,
                )
            };
        clock.require_original(packet.signed(), attempt.attempt_digest())?;
        Ok(Self {
            original: packet.signed().clone(),
            acquisition_id: request.acquisition_id(),
            attempt: attempt.attempt_digest(),
            session_binding: request.session_binding(),
            namespace: projection.resource_namespace_digest(),
            normalized,
            selection,
            clock,
        })
    }

    pub(super) fn resource(&self) -> &SourceResourceV1 {
        self.selection.resource()
    }

    pub(super) fn before_commit(
        &self,
        ledger: &ProviderLedgerV1<'_>,
        session: &mut CurrentProviderIngressSessionV1,
        rows: &[u8],
    ) -> Result<(), ProviderLedgerError> {
        self.require_live(session)?;
        ledger.journal.validate_fixed_source_provider_storage()?;
        self.selection
            .require_original(ledger, &self.normalized, rows)?;
        self.require_live(session)
    }

    /// Retains the same anchor only at the final possible-append boundary.
    pub(super) fn retain_before_append(
        &self,
        ledger: &mut ProviderLedgerV1<'_>,
        session: &mut CurrentProviderIngressSessionV1,
        rows: &[u8],
    ) -> Result<(), ProviderLedgerError> {
        self.before_commit(ledger, session, rows)?;
        // No fallible preflight remains after this retention. Any commit
        // failure may have appended, so poisoning must retain this SAME Arc.
        retain_original_clock(
            &mut ledger.native_acquire_custody,
            self.acquisition_id,
            &self.clock,
        )
    }

    pub(super) fn after_commit(
        &self,
        ledger: &ProviderLedgerV1<'_>,
        session: &mut CurrentProviderIngressSessionV1,
        publication: &[u8],
        rows: &[u8],
    ) -> Result<(), ProviderLedgerError> {
        self.require_live(session)?;
        ledger.journal.validate_fixed_source_provider_storage()?;
        // Our own append invalidates the old whole-journal snapshot. Rejoin
        // the real new snapshot, requiring every ORIGINAL claim and tuple.
        let current = select_current_resource(
            ledger,
            session,
            &self.normalized,
            self.namespace,
            publication,
            rows,
        )?;
        if !self.selection.same_selection(&current) {
            return Err(ProviderLedgerError::ConfigurationMismatch);
        }
        ledger.journal.validate_fixed_source_provider_storage()?;
        self.require_live(session)
    }

    pub(super) fn require_live(
        &self,
        session: &mut CurrentProviderIngressSessionV1,
    ) -> Result<(), ProviderLedgerError> {
        if session.current_projection()?.session_binding() != self.session_binding {
            return Err(ProviderLedgerError::Equivocation);
        }
        self.clock.require_original(&self.original, self.attempt)
    }
}

/// Adds original hot custody without replacing an already retained anchor.
pub(crate) fn retain_original_clock(
    custody: &mut BTreeMap<ObjectDigest, crate::native_completion::NativeAcquireHotCustodyV3>,
    acquisition_id: ObjectDigest,
    clock: &Arc<crate::native_completion::NativeAcquireClockGuardV1>,
) -> Result<(), ProviderLedgerError> {
    match custody.entry(acquisition_id) {
        Entry::Vacant(entry) => {
            entry.insert(crate::native_completion::NativeAcquireHotCustodyV3 {
                clock: Arc::clone(clock),
                source_root: None,
            });
            Ok(())
        }
        Entry::Occupied(entry) if Arc::ptr_eq(&entry.get().clock, clock) => Ok(()),
        Entry::Occupied(_) => Err(ProviderLedgerError::Equivocation),
    }
}

fn resource_matches_acquisition(
    resource: &SourceResourceV1,
    acquisition: &AcquisitionRecordV1,
) -> bool {
    resource.resource_namespace_digest() == acquisition.resource_namespace_digest
        && resource.resource_id() == acquisition.resource_id
        && resource.resource_generation() == acquisition.resource_generation
        && resource.resource_digest() == acquisition.resource_digest
        && resource.catalog_generation() == acquisition.catalog_generation
        && resource.catalog_digest() == acquisition.catalog_digest
        && resource.selection_generation() == acquisition.selection_generation
        && resource.selection_digest() == acquisition.selection_digest
}

pub(crate) fn matches_original_acquisition(
    existing: &AcquisitionRecordV1,
    normalized: &NormalizedAcquisitionIntentV1,
    selected: &SourceResourceV1,
    original_attempt: ObjectDigest,
) -> bool {
    existing.effect_attempt_digest == original_attempt
        && existing.current_attempt_digest == original_attempt
        && existing.normalized_intent == *normalized
        && is_native_no_dispatch_acquisition(existing)
        && resource_matches_acquisition(selected, existing)
}

pub(crate) fn require_original_packet_profile(
    request: &aos_sandbox_source_provider_protocol::AcquireSourceRequestV1,
    packet: Option<&crate::FixedProviderAuthenticatedSourceRequestV1>,
) -> Result<bool, ProviderLedgerError> {
    let native = request.acquisition_version()
        == aos_sandbox_source_provider_protocol::ACQUIRE_SOURCE_REQUEST_VERSION_V3;
    if native && packet.is_none() {
        return Err(ProviderLedgerError::Equivocation);
    }
    Ok(native)
}

pub(super) fn permits_native_dispatch(
    selected_native: bool,
    original_native: bool,
    bridge: Option<&crate::native_completion::QualifiedNativeBridgeV2>,
) -> bool {
    selected_native && !original_native && bridge.is_some()
}

/// Narrows slot allocation to the existing qualified V2 held-row profile.
pub(super) fn permits_native_reply_reservation(
    has_catalog: bool,
    version: u16,
    kernel_coupled: bool,
    bridge: Option<&crate::native_completion::QualifiedNativeBridgeV2>,
) -> bool {
    version == aos_sandbox_source_provider_protocol::ACQUIRE_SOURCE_REQUEST_VERSION_V2
        && permits_native_dispatch(has_catalog && !kernel_coupled, false, bridge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occupied_reply_slot_closes_only_the_qualified_v2_native_candidate() {
        use crate::native_completion::{NativeReplyCustody, NativeReplyIdentity};
        use aos_sandbox_source_provider_protocol::{
            ACQUIRE_SOURCE_REQUEST_VERSION_V2, ACQUIRE_SOURCE_REQUEST_VERSION_V3,
        };

        let bridge = crate::native_completion::QualifiedNativeBridgeV2::for_test();
        let mut slot = NativeReplyCustody::default();
        slot.reserve(NativeReplyIdentity {
            acquisition: ObjectDigest::from_bytes([1; 32]),
            attempt: ObjectDigest::from_bytes([2; 32]),
            session: ObjectDigest::from_bytes([3; 32]),
            signed_request: ObjectDigest::from_bytes([4; 32]),
        })
        .unwrap();

        let available = |catalog, version, kernel, bridge| {
            slot.require_candidate_available(permits_native_reply_reservation(
                catalog, version, kernel, bridge,
            ))
        };
        assert!(
            available(
                true,
                ACQUIRE_SOURCE_REQUEST_VERSION_V2,
                false,
                Some(&bridge)
            )
            .is_err()
        );
        assert!(
            available(
                true,
                ACQUIRE_SOURCE_REQUEST_VERSION_V3,
                false,
                Some(&bridge)
            )
            .is_ok()
        );
        assert!(
            available(
                false,
                ACQUIRE_SOURCE_REQUEST_VERSION_V2,
                false,
                Some(&bridge)
            )
            .is_ok()
        );
        assert!(available(true, ACQUIRE_SOURCE_REQUEST_VERSION_V2, true, Some(&bridge)).is_ok());
        assert!(available(true, ACQUIRE_SOURCE_REQUEST_VERSION_V2, false, None).is_ok());
    }

    #[test]
    fn raw_native_v3_is_closed_and_a_v2_test_bridge_cannot_enable_dispatch() {
        let retained = crate::native_completion::fixture_requested(
            [1; 32],
            500,
            ObjectDigest::from_bytes([2; 32]),
        );
        let original = retained
            .canonical_request
            .as_ref()
            .unwrap()
            .request()
            .signed_root_request();
        let legacy =
            aos_sandbox_source_provider_protocol::decode_acquire_request(original.subject())
                .unwrap();
        assert!(!require_original_packet_profile(&legacy, None).unwrap());
        let catalog = NativeAcquireCatalogBindingV3::new(
            ObjectDigest::from_bytes([24; 32]),
            2,
            ObjectDigest::from_bytes([25; 32]),
            1,
            ObjectDigest::from_bytes([26; 32]),
            ObjectDigest::from_bytes([27; 32]),
            ObjectDigest::from_bytes([28; 32]),
        )
        .unwrap();
        let native = aos_sandbox_source_provider_protocol::AcquireSourceRequestV1::new_native_v3(
            legacy, catalog,
        )
        .unwrap();
        assert!(require_original_packet_profile(&native, None).is_err());
        let bridge = crate::native_completion::QualifiedNativeBridgeV2::for_test();
        assert!(permits_native_dispatch(true, false, Some(&bridge)));
        assert!(!permits_native_dispatch(true, true, Some(&bridge)));
        assert!(!permits_native_dispatch(false, false, Some(&bridge)));
    }
}
