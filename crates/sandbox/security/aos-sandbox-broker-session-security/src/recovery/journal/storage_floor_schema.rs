//! Retains the existing Storage floor schema walk's actual negative prefixes.
//!
//! This inert lane owns no Journal, endpoint, floor, payer or replay authority.
//! The genuine main owner installs it only while running its ordinary schema
//! recipe. Completed pure archive scratch can retire at its existing complete
//! comparison boundary; failed native/codec prefixes remain in this lane.

use std::collections::TryReserveError;
use std::mem::size_of;

use aos_sandbox_controller_domain::journal::{ProtectedJournalAuthority, ProtectedJournalPreopenReplayExtentV1};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_protocol::authenticated_session::stored_history::StoredBrokerSessionHistoryDecodeCaptureV1;
use aos_sandbox_protocol::domain_ledger::capacity_family::family::CanonicalCapacityReadCaptureV1;

use super::*;

// The existing recursive inventory validator is bounded by sixteen archives.
// Four retained read/model destinations per level and sixteen fixed lanes
// cover that stack without growing a capture index after entry.
const SLOTS: usize = MAXIMUM_STORAGE_INVENTORY_ARCHIVES * 4 + 16;

struct SchemaClaimOriginalV3 {
    capacity: [CanonicalCapacityReadCaptureV1; 2],
    native: Option<aos_sandbox_controller_domain::JournalError>,
    claimed: bool,
}

impl SchemaClaimOriginalV3 {
    fn new() -> Self {
        Self {
            capacity: std::array::from_fn(|_| CanonicalCapacityReadCaptureV1::new()),
            native: None,
            claimed: false,
        }
    }

    fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native.as_ref().map(|cause| cause as _)
    }
}

/// Owns one complete schema attempt without supplying a native capability.
#[derive(Default)]
pub(crate) struct StorageFloorSchemaOriginalV3 {
    traffic: Vec<StoredReadOriginalsV1>,
    codecs: Vec<StoredBrokerSessionHistoryDecodeCaptureV1>,
    values: Vec<Vec<u8>>,
    entries: Vec<Vec<(Vec<u8>, Vec<u8>)>>,
    ids: Vec<Vec<[u8; 16]>>,
    claim: Option<SchemaClaimOriginalV3>,
    overflow_value: Option<Vec<u8>>,
    overflow_entries: Option<Vec<(Vec<u8>, Vec<u8>)>>,
    overflow_ids: Option<Vec<[u8; 16]>>,
    allocation: Option<TryReserveError>,
    returned: Option<Result<(), BrokerSessionSecurityError>>,
    attempted: bool,
    closed: Option<BrokerSessionSecurityError>,
}

impl StorageFloorSchemaOriginalV3 {
    /// Constructs empty passive storage without opening or decoding anything.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Prices the shared schema recipe and this actual retained destination.
    ///
    /// # Errors
    /// Refuses an invalid actual held extent or checked representation overflow.
    pub(crate) fn receiving_demand_v3(
        extent: &ProtectedJournalPreopenReplayExtentV1,
    ) -> Result<ResourceVector, BrokerSessionSecurityError> {
        let invalid = || BrokerSessionSecurityError::Currentness;
        let schema = storage_session_schema_demand::schema_demand(extent)?;
        let rows = usize::try_from(extent.native_bytes)
            .map_err(|_| invalid())?
            .checked_div(aos_sandbox_journal::framing::HEADER_BYTES)
            .ok_or_else(invalid)?
            .min(extent.limits.maximum_materialized_records);
        let (capacity, _) =
            CanonicalCapacityReadCaptureV1::receiving_obligations_v1(rows).ok_or_else(invalid)?;
        let names = CanonicalCapacityReadCaptureV1::receiving_named_entries_v2(rows)
            .and_then(|count| count.checked_mul(2))
            .ok_or_else(invalid)?;
        let slots = size_of::<StoredReadOriginalsV1>()
            .checked_add(size_of::<StoredBrokerSessionHistoryDecodeCaptureV1>())
            .and_then(|bytes| bytes.checked_add(size_of::<Vec<u8>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<Vec<(Vec<u8>, Vec<u8>)>>()))
            .and_then(|bytes| bytes.checked_add(size_of::<Vec<[u8; 16]>>()))
            .and_then(|bytes| bytes.checked_mul(SLOTS))
            .ok_or_else(invalid)?;
        let fixed = size_of::<Self>()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(slots))
            .and_then(|bytes| bytes.checked_add(size_of::<SchemaClaimOriginalV3>()))
            .and_then(|bytes| bytes.checked_add(capacity.checked_mul(2)?))
            .ok_or_else(invalid)?;
        let native = crate::endpoint::RetainedEndpointRevalidationOriginalV1::receiving_demand_v1()
            .ok_or_else(invalid)?;

        // The second copy covers the retained sole-codec original beside the
        // same pure comparison value. No native state or authority is cloned.
        let backing = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(fixed).map_err(|_| invalid())?)
            .with(
                D::MetadataEntries,
                u64::try_from(names).map_err(|_| invalid())?,
            );
        schema
            .checked_add(schema)
            .and_then(|demand| demand.checked_add(native))
            .and_then(|demand| demand.checked_add(backing))
            .map_err(|_| invalid())
    }

    /// Borrows an actual retained native/codec/allocation cause before projection.
    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.claim
            .as_ref()
            .and_then(SchemaClaimOriginalV3::failure)
            .or_else(|| self.traffic.iter().find_map(StoredReadOriginalsV1::failure))
            .or_else(|| {
                self.codecs
                    .iter()
                    .find_map(|capture| capture.failure())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.allocation.as_ref().map(|cause| cause as _))
            .or_else(|| {
                self.returned
                    .as_ref()
                    .and_then(|result| result.as_ref().err())
                    .map(|cause| cause as _)
            })
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    fn prepare(&mut self) -> Result<(), BrokerSessionSecurityError> {
        if self.attempted || self.closed.is_some() {
            self.closed
                .get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.attempted = true;
        macro_rules! reserve {
            ($field:ident) => {
                if let Err(cause) = self.$field.try_reserve_exact(SLOTS) {
                    self.allocation = Some(cause);
                    return Err(BrokerSessionSecurityError::Currentness);
                }
            };
        }
        reserve!(traffic);
        reserve!(codecs);
        reserve!(values);
        reserve!(entries);
        reserve!(ids);
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(super) struct SchemaScopeV3 {
    traffic: usize,
    codecs: usize,
    values: usize,
    entries: usize,
    ids: usize,
}

/// Borrows only the original namespace guard while recording its returned errors.
pub(super) struct SchemaAuthorityV3<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
    original: Option<&'journal mut SchemaClaimOriginalV3>,
}

impl SchemaAuthorityV3<'_> {
    pub(super) fn get(&mut self, key: &[u8]) -> Result<Option<&[u8]>, BrokerSessionSecurityError> {
        match self.authority.get(key) {
            Ok(value) => Ok(value),
            Err(cause) => {
                if let Some(original) = self.original.as_deref_mut() {
                    original.native.get_or_insert(cause);
                }
                Err(BrokerSessionSecurityError::Currentness)
            }
        }
    }

    pub(super) fn records(
        &mut self,
    ) -> Result<impl Iterator<Item = (&[u8], &[u8])>, BrokerSessionSecurityError> {
        match self.authority.records() {
            Ok(records) => Ok(records),
            Err(cause) => {
                if let Some(original) = self.original.as_deref_mut() {
                    original.native.get_or_insert(cause);
                }
                Err(BrokerSessionSecurityError::Currentness)
            }
        }
    }
}

impl ProtectedBrokerSessionJournalV1 {
    /// Runs the same complete schema recipe with a once-owned passive sink.
    ///
    /// # Errors
    /// Returns the original schema refusal, or refuses reentry and a non-Storage
    /// endpoint before installing a selected floor-schema lane.
    pub(crate) fn validate_schema_only_retaining_v3(
        &mut self,
        original: &mut StorageFloorSchemaOriginalV3,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.schema_original.is_some()
            || self.endpoint.protected_protocol_and_node().0 != BrokerSessionProtocolV1::Storage
        {
            original
                .closed
                .get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        original.prepare()?;
        self.schema_original = Some(std::mem::take(original));
        let returned = self.validate_schema_only();
        let Some(mut retained) = self.schema_original.take() else {
            std::process::abort();
        };
        retained.returned = Some(returned);
        let result = match retained.returned.as_ref() {
            Some(Ok(())) => Ok(()),
            Some(Err(cause)) => Err(cause.clone()),
            None => std::process::abort(),
        };
        *original = retained;
        result
    }

    pub(super) fn schema_scope_v3(&self) -> Option<SchemaScopeV3> {
        self.schema_original.as_ref().map(|original| SchemaScopeV3 {
            traffic: original.traffic.len(),
            codecs: original.codecs.len(),
            values: original.values.len(),
            entries: original.entries.len(),
            ids: original.ids.len(),
        })
    }

    pub(super) fn schema_complete_scope_v3<T>(
        &mut self,
        scope: Option<SchemaScopeV3>,
        result: &Result<T, BrokerSessionSecurityError>,
    ) {
        if result.is_err() {
            return;
        }
        if let (Some(original), Some(scope)) = (self.schema_original.as_mut(), scope) {
            // The complete canonical archive comparison has no remaining pure
            // borrower. Native Journal/endpoint custody and charged F stay held.
            original.traffic.truncate(scope.traffic);
            original.codecs.truncate(scope.codecs);
            original.values.truncate(scope.values);
            original.entries.truncate(scope.entries);
            original.ids.truncate(scope.ids);
        }
    }

    pub(super) fn schema_authority_v3(
        &mut self,
    ) -> Result<SchemaAuthorityV3<'_>, BrokerSessionSecurityError> {
        let journal = self
            .journal
            .as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let mut original = match self.schema_original.as_mut() {
            Some(schema) => {
                if schema
                    .claim
                    .as_ref()
                    .is_some_and(|claim| claim.failure().is_some() || !claim.claimed)
                {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                // A successful capacity scan is pure DATA. Its exact returned
                // guard has ended before another exclusive claim can enter.
                schema.claim = Some(SchemaClaimOriginalV3::new());
                schema.claim.as_mut()
            }
            None => None,
        };
        let result = match original.as_deref_mut() {
            Some(original) => journal.claim_protected_authority_retaining_v1(
                RecordNamespace::BrokerSessionTraffic,
                &mut original.capacity,
            ),
            None => journal.claim_protected_authority(RecordNamespace::BrokerSessionTraffic),
        };
        match result {
            Ok(authority) => {
                if let Some(original) = original.as_deref_mut() {
                    original.claimed = true;
                }
                Ok(SchemaAuthorityV3 {
                    authority,
                    original,
                })
            }
            Err(cause) => {
                if let Some(original) = original {
                    original.native = Some(cause);
                }
                Err(BrokerSessionSecurityError::Currentness)
            }
        }
    }

    pub(super) fn read_optional_schema_retaining_v3(
        &mut self,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<Option<StoredProtocolHistoryV1>, BrokerSessionSecurityError> {
        if self
            .schema_original
            .as_ref()
            .is_none_or(|original| original.traffic.len() == SLOTS)
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut work = StoredReadOriginalsV1::new();
        let result = self.read_optional_schema_captured(protocol, &mut work, true);
        let selected = if result.is_ok() {
            work.schema_selected_clone_v3()
        } else {
            None
        };
        self.schema_original
            .as_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?
            .traffic
            .push(work);
        result.map(|_| selected)
    }

    pub(super) fn schema_decode_stored_v3(
        &mut self,
        key: &[u8],
        value: &[u8],
    ) -> Result<StoredProtocolHistoryV1, BrokerSessionSecurityError> {
        let Some(original) = self.schema_original.as_mut() else {
            return StoredProtocolHistoryV1::decode(key, value);
        };
        if original.codecs.len() == SLOTS {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        original
            .codecs
            .push(StoredBrokerSessionHistoryDecodeCaptureV1::new());
        let capture = original
            .codecs
            .last_mut()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        CanonicalStoredHistoryV1::decode_retaining(key, value, capture)
            .map_err(|_| BrokerSessionSecurityError::Currentness)?;
        let stored = capture
            .stored()
            .cloned()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        StoredProtocolHistoryV1::from_canonical_for_key_v2(stored, key)
    }

    pub(super) fn schema_retain_value_v3(
        &mut self,
        value: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, BrokerSessionSecurityError> {
        let Some(original) = self.schema_original.as_mut() else {
            return Ok(value);
        };
        let Some(value) = value else {
            return Ok(None);
        };
        if original.values.len() == SLOTS {
            original.overflow_value = Some(value);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        original.values.push(value);
        let value = original
            .values
            .last()
            .ok_or(BrokerSessionSecurityError::Currentness)?;
        let mut copy = Vec::new();
        if let Err(cause) = copy.try_reserve_exact(value.len()) {
            original.allocation.get_or_insert(cause);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        copy.extend_from_slice(value);
        Ok(Some(copy))
    }

    pub(super) fn schema_retain_entries_v3(
        &mut self,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
        result: Result<(), BrokerSessionSecurityError>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BrokerSessionSecurityError> {
        let Some(original) = self.schema_original.as_mut() else {
            result?;
            return Ok(entries);
        };
        if original.entries.len() == SLOTS {
            original.overflow_entries = Some(entries);
            return result.and(Err(BrokerSessionSecurityError::Currentness));
        }
        original.entries.push(entries);
        result?;
        Ok(original
            .entries
            .last()
            .ok_or(BrokerSessionSecurityError::Currentness)?
            .clone())
    }

    pub(super) fn schema_retain_ids_v3(
        &mut self,
        ids: Vec<[u8; 16]>,
        result: Result<(), BrokerSessionSecurityError>,
    ) -> Result<Vec<[u8; 16]>, BrokerSessionSecurityError> {
        let Some(original) = self.schema_original.as_mut() else {
            result?;
            return Ok(ids);
        };
        if original.ids.len() == SLOTS {
            original.overflow_ids = Some(ids);
            return result.and(Err(BrokerSessionSecurityError::Currentness));
        }
        original.ids.push(ids);
        result?;
        Ok(original
            .ids
            .last()
            .ok_or(BrokerSessionSecurityError::Currentness)?
            .clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reentry_keeps_the_actual_first_codec_error_and_original_sink() {
        let mut original = StorageFloorSchemaOriginalV3::new();
        original.prepare().unwrap();
        original
            .codecs
            .push(StoredBrokerSessionHistoryDecodeCaptureV1::new());
        let returned = CanonicalStoredHistoryV1::decode_retaining(
            &protocol_key(BrokerSessionProtocolV1::Storage),
            b"invalid stored history",
            &mut original.codecs[0],
        );
        assert!(returned.is_err());
        let before = original.failure().unwrap() as *const dyn std::error::Error;

        assert!(original.prepare().is_err());

        assert!(std::ptr::eq(
            before,
            original.failure().unwrap() as *const dyn std::error::Error
        ));
        assert_eq!(original.codecs.len(), 1);
    }

    #[test]
    fn non_storage_entry_refuses_before_installing_or_growing_the_schema_lane() {
        let mut fixture = super::super::lifecycle_test_fixture::LifecycleTerminalFixture::new();
        let mut original = StorageFloorSchemaOriginalV3::new();

        assert!(
            fixture
                .journal
                .validate_schema_only_retaining_v3(&mut original)
                .is_err()
        );

        assert!(!original.attempted);
        assert!(original.traffic.is_empty());
        assert!(original.codecs.is_empty());
        assert!(fixture.journal.schema_original.is_none());
        assert!(original.failure().is_some());
    }
}
