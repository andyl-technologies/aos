//! Protected Mount catalog floors shared by local and remote planning.

use super::*;
use aos_sandbox_protocol::mount_source_acquisition_state::{
    MountSourceAcquisitionStateV2, ProviderMethodV2, StoredRecordV2,
    decode_mount_source_state_record_v2, protocol_selection_floor_v2,
};

pub(super) fn validate_mount_floor(
    journal: &aos_sandbox::ProtectedJournalAuthority<'_>,
    graph: &MountSourceAcquisitionStateV2,
    session: &MountProviderSessionProjectionV2,
    catalog: &ProviderCatalogFloorV1,
    selection_key: Option<&[u8]>,
) -> Result<Option<SourceSelectionFloorV1>, SourceProviderSecurityError> {
    let scope = (
        session.authority_trust[0].authority.authority_id(),
        session.authority_trust[1].authority.authority_id(),
    );
    let minimum = (
        catalog.minimum_catalog_generation(),
        catalog.minimum_catalog_digest(),
    );
    if graph.provider_attempts.values().any(|attempt| {
        if attempt.method != ProviderMethodV2::Acquire
            || (
                attempt.scope.holder_authority_id,
                attempt.scope.provider_authority_id,
            ) != scope
        {
            return false;
        }
        attempt
            .acquire_verification_floor
            .as_ref()
            .is_none_or(|floor| {
                !floor_at_least(
                    minimum,
                    (
                        floor.catalog.minimum_catalog_generation,
                        ObjectDigest::from_bytes(floor.catalog.minimum_catalog_digest),
                    ),
                )
            })
    }) {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }

    let Some(key) = selection_key else {
        return Ok(None);
    };
    let record = journal
        .get(key)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?
        .ok_or(SourceProviderSecurityError::SessionContinuity)?;
    let row = match decode_mount_source_state_record_v2(key, record) {
        Ok(StoredRecordV2::Acquisition { value }) => value,
        _ => return Err(SourceProviderSecurityError::SessionContinuity),
    };
    let historical = &row
        .evidence
        .as_ref()
        .ok_or(SourceProviderSecurityError::SessionContinuity)?
        .historical_lease_signer;
    let selection = protocol_selection_floor_v2(&historical.selection_floor)
        .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    if graph.acquisitions.get(&row.acquisition_id) != Some(&row)
        || row.scope.holder_authority_id != scope.0
        || row.scope.provider_authority_id != scope.1
        || historical.selection_floor_digest != *selection.digest().as_bytes()
        || selection.acquisition_id().as_bytes() != &row.provider_acquisition.acquisition_id
        || !floor_at_least(
            (
                selection.resource().catalog_generation(),
                selection.resource().catalog_digest(),
            ),
            minimum,
        )
    {
        return Err(SourceProviderSecurityError::SessionContinuity);
    }
    Ok(Some(selection))
}

/// Keeps the existing wire minimum distinct from retained Mount head history.
pub(super) struct RemoteMountCatalogBoundsV3 {
    pub(super) query_floor: ProviderCatalogFloorV1,
    pub(super) head_minimum: (u64, ObjectDigest),
}

/// Derives challenge bounds, not fresh authorization, from protected history.
pub(super) fn remote_catalog_bounds(
    graph: &MountSourceAcquisitionStateV2,
    session: &MountProviderSessionProjectionV2,
    publication_floor: (u64, ObjectDigest),
) -> Result<RemoteMountCatalogBoundsV3, SourceProviderSecurityError> {
    let scope = (
        session.authority_trust[0].authority.authority_id(),
        session.authority_trust[1].authority.authority_id(),
    );
    let mut minimum = CatalogLowerBoundV3::new(publication_floor)?;
    let mut head_minimum = CatalogLowerBoundV3::new(publication_floor)?;
    for attempt in graph.provider_attempts.values().filter(|attempt| {
        attempt.method == ProviderMethodV2::Acquire
            && (
                attempt.scope.holder_authority_id,
                attempt.scope.provider_authority_id,
            ) == scope
    }) {
        if attempt.scope.resource_namespace_digest != *session.resource_namespace_digest.as_bytes()
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        let floor = &attempt
            .acquire_verification_floor
            .as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?
            .catalog;
        let minimum_claim = (
            floor.minimum_catalog_generation,
            ObjectDigest::from_bytes(floor.minimum_catalog_digest),
        );
        minimum.include(minimum_claim)?;
        head_minimum.include(minimum_claim)?;
        let normalized = attempt
            .normalized_acquire_intent
            .as_ref()
            .ok_or(SourceProviderSecurityError::SessionContinuity)?;
        let normalized = NormalizedAcquisitionIntentV2::from_canonical_bytes(&normalized.bytes)
            .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
        if let Some(native) = normalized.native_catalog() {
            if native.resource_namespace_digest() != session.resource_namespace_digest {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            head_minimum.include(native.head())?;
        }
    }
    if let Some(floor) = graph
        .provider_heads
        .get(&scope)
        .and_then(|head| head.inventory_floor.as_ref())
    {
        let minimum_claim = (
            floor.catalog_generation,
            ObjectDigest::from_bytes(floor.catalog_digest),
        );
        minimum.include(minimum_claim)?;
        head_minimum.include(minimum_claim)?;
    }
    for row in graph.acquisitions.values().filter(|row| {
        (
            row.scope.holder_authority_id,
            row.scope.provider_authority_id,
        ) == scope
    }) {
        if row.scope.resource_namespace_digest != *session.resource_namespace_digest.as_bytes() {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        if let Some(evidence) = &row.evidence {
            let floor = &evidence.historical_lease_signer;
            let minimum_claim = (
                floor.minimum_catalog_generation,
                ObjectDigest::from_bytes(floor.minimum_catalog_digest),
            );
            minimum.include(minimum_claim)?;
            head_minimum.include(minimum_claim)?;
            let selection = protocol_selection_floor_v2(&floor.selection_floor)
                .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
            if selection.resource().resource_namespace_digest() != session.resource_namespace_digest
            {
                return Err(SourceProviderSecurityError::SessionContinuity);
            }
            head_minimum.include((
                selection.resource().catalog_generation(),
                selection.resource().catalog_digest(),
            ))?;
        }
    }
    let query_floor = ProviderCatalogFloorV1::new(
        scope.1,
        session.resource_namespace_digest,
        minimum.minimum.0,
        minimum.minimum.1,
    )
    .map_err(|_| SourceProviderSecurityError::SessionContinuity)?;
    Ok(RemoteMountCatalogBoundsV3 {
        query_floor,
        head_minimum: head_minimum.minimum,
    })
}

pub(super) fn floor_at_least(value: (u64, ObjectDigest), minimum: (u64, ObjectDigest)) -> bool {
    value.0 > minimum.0 || (value.0 == minimum.0 && value.1 == minimum.1)
}

// History may be visited in key order rather than catalog-generation order.
// Remember every observed generation so a lower historical fork cannot hide
// behind a previously encountered higher bound.
struct CatalogLowerBoundV3 {
    minimum: (u64, ObjectDigest),
    generations: std::collections::BTreeMap<u64, ObjectDigest>,
}

impl CatalogLowerBoundV3 {
    fn new(seed: (u64, ObjectDigest)) -> Result<Self, SourceProviderSecurityError> {
        let mut bound = Self {
            minimum: seed,
            generations: std::collections::BTreeMap::new(),
        };
        bound.include(seed)?;
        Ok(bound)
    }

    fn include(
        &mut self,
        candidate: (u64, ObjectDigest),
    ) -> Result<(), SourceProviderSecurityError> {
        if candidate.0 == 0
            || candidate.1.as_bytes() == &[0; 32]
            || self
                .generations
                .get(&candidate.0)
                .is_some_and(|digest| *digest != candidate.1)
        {
            return Err(SourceProviderSecurityError::SessionContinuity);
        }
        self.generations.insert(candidate.0, candidate.1);
        if candidate.0 > self.minimum.0 {
            self.minimum = candidate;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> ObjectDigest {
        ObjectDigest::from_bytes([byte; 32])
    }

    #[test]
    fn shared_floor_comparison_preserves_strict_same_generation_digest() {
        assert!(floor_at_least((4, digest(4)), (4, digest(4))));
        assert!(floor_at_least((5, digest(5)), (4, digest(4))));
        assert!(!floor_at_least((4, digest(5)), (4, digest(4))));
        assert!(!floor_at_least((3, digest(3)), (4, digest(4))));
    }

    #[test]
    fn challenge_floor_join_retains_maximum_and_refuses_sentinels_or_fork() {
        let mut floor = CatalogLowerBoundV3::new((4, digest(4))).unwrap();
        floor.include((3, digest(3))).unwrap();
        assert_eq!(floor.minimum, (4, digest(4)));
        floor.include((5, digest(5))).unwrap();
        assert_eq!(floor.minimum, (5, digest(5)));
        assert!(floor.include((5, digest(6))).is_err());
        assert!(floor.include((3, digest(6))).is_err());
        assert!(floor.include((0, digest(6))).is_err());
        assert!(floor.include((6, digest(0))).is_err());
        assert_eq!(floor.minimum, (5, digest(5)));
    }
}
