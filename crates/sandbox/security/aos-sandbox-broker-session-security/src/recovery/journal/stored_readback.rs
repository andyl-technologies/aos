//! Owns selected stored-history read prefixes through their actual posts.
//!
//! The ordinary reader and selected Client use one schema walk. Selected rows
//! remain under the same held Journal; these passive owners confer no access,
//! currentness, Session, funding, or replay authority.

use super::*;
use std::ops::Deref;
use aos_sandbox_protocol::authenticated_session::stored_history::StoredBrokerSessionHistoryDecodeCaptureV1;

pub(crate) struct StoredReadOriginalsV1 {
    current: Option<StoredBrokerSessionHistoryDecodeCaptureV1>,
    snapshot_bytes: Option<Vec<u8>>,
    snapshot: Option<ProtectedBrokerSessionJournalSnapshotV1>,
    selected: Option<StoredProtocolHistoryV1>,
    rows: Vec<StoredProtocolHistoryV1>,
    selected_index: Option<usize>,
    floor_before: Option<Result<(), BrokerSessionSecurityError>>,
    before_identity: Option<Result<[u8; 32], BrokerSessionSecurityError>>,
    after_identity: Option<Result<[u8; 32], BrokerSessionSecurityError>>,
    row_identities: [Option<Result<[u8; 32], BrokerSessionSecurityError>>; MAXIMUM_PROTOCOL_RECORDS],
    schema: Option<Result<(), BrokerSessionSecurityError>>,
    floor_after: Option<Result<(), BrokerSessionSecurityError>>,
    returned: Option<Result<(), BrokerSessionSecurityError>>,
    attempted: bool,
    closed: Option<BrokerSessionSecurityError>,
}

impl Default for StoredReadOriginalsV1 {
    fn default() -> Self {
        Self {
            current: None, snapshot_bytes: None, snapshot: None, selected: None,
            rows: Vec::new(), selected_index: None, floor_before: None,
            before_identity: None, after_identity: None,
            row_identities: std::array::from_fn(|_| None),
            schema: None, floor_after: None, returned: None, attempted: false, closed: None,
        }
    }
}

impl StoredReadOriginalsV1 {
    pub(crate) fn new() -> Self { Self::default() }

    pub(crate) fn receiving_metadata_cells_v1() -> Option<usize> {
        // Five reached representation/selection destinations, ten stage cells
        // (including four fixed per-row identities), and two refusal controls.
        17_usize.checked_add(StoredBrokerSessionHistoryDecodeCaptureV1::receiving_metadata_cells_v1()?)
    }

    pub(crate) fn receiving_fixed_backing_bytes_v1() -> Option<usize> {
        let row_slots = MAXIMUM_PROTOCOL_RECORDS.checked_mul(3)?.checked_add(4)?;
        std::mem::size_of::<StoredProtocolHistoryV1>().checked_mul(row_slots)
    }

    pub(crate) fn construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>()
            .checked_add(StoredBrokerSessionHistoryDecodeCaptureV1::construction_bytes_v1())?
            .checked_add(std::mem::size_of::<ProtectedBrokerSessionJournalSnapshotV1>())?
            .checked_add(std::mem::size_of::<SchemaRow<'static>>())?
            .checked_add(std::mem::size_of::<SchemaRows<'static>>())?
            .checked_add(std::mem::size_of::<BrokerSessionProtocolV1>().checked_mul(3)?)
    }

    pub(crate) fn observe_optional_once(&mut self, journal: &mut ProtectedBrokerSessionJournalV1)
        -> Result<(), BrokerSessionSecurityError>
    {
        self.observe_once(journal, false)
    }

    pub(crate) fn observe_current_once(&mut self, journal: &mut ProtectedBrokerSessionJournalV1)
        -> Result<(), BrokerSessionSecurityError>
    {
        self.observe_once(journal, true)
    }

    pub(in crate::recovery) fn observe_delete_current_once_v1(&mut self,
        journal: &mut ProtectedBrokerSessionJournalV1,
        protocol: BrokerSessionProtocolV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        let entry = journal.delete_inventory_client_method_v1().and_then(|_| {
            if journal.endpoint.protected_protocol_and_node().0 == protocol { Ok(()) }
            else { Err(BrokerSessionSecurityError::Currentness) }
        });
        if let Err(cause) = entry {
            self.closed.get_or_insert(cause);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.observe_protocol_once_v1(journal, true, protocol)
    }

    fn observe_once(&mut self, journal: &mut ProtectedBrokerSessionJournalV1, require_current: bool)
        -> Result<(), BrokerSessionSecurityError>
    {
        self.observe_protocol_once_v1(journal, require_current, BrokerSessionProtocolV1::Storage)
    }

    fn observe_protocol_once_v1(&mut self, journal: &mut ProtectedBrokerSessionJournalV1,
        require_current: bool, protocol: BrokerSessionProtocolV1,
    ) -> Result<(), BrokerSessionSecurityError> {
        if self.attempted || self.closed.is_some() {
            self.closed.get_or_insert(BrokerSessionSecurityError::Currentness);
            return Err(BrokerSessionSecurityError::Currentness);
        }
        self.attempted = true;
        let result = self.observe(journal, require_current, protocol);
        let returned = result.as_ref().map(|_| ()).map_err(|_| BrokerSessionSecurityError::Currentness);
        self.returned = Some(result);
        returned
    }

    fn observe(&mut self, journal: &mut ProtectedBrokerSessionJournalV1, require_current: bool,
        protocol: BrokerSessionProtocolV1)
        -> Result<(), BrokerSessionSecurityError>
    {
        stage(journal.require_floor_current(), Some(&mut self.floor_before))?;
        self.schema = Some(journal.read_optional_schema_captured(protocol, self, true));
        if matches!(self.schema, Some(Err(_))) { return Err(BrokerSessionSecurityError::Currentness); }
        stage(journal.require_floor_current(), Some(&mut self.floor_after))?;
        if require_current {
            let current = self.selected_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
            // Clone at the same original snapshot frontier, then retain it before
            // the ordinary snapshot field checks can refuse it.
            self.snapshot_bytes = Some(current.history.clone());
            let current = self.selected_ref().ok_or(BrokerSessionSecurityError::Currentness)?;
            let (generation, publication, catalog, head) = (current.generation,
                current.endpoint_publication, current.current_catalog, current.current_head);
            self.snapshot = Some(ProtectedBrokerSessionJournalSnapshotV1::new_retaining(
                generation, publication, catalog, head, &mut self.snapshot_bytes,
            )?);
        }
        Ok(())
    }

    pub(super) fn take_ordinary(&mut self) -> Option<StoredProtocolHistoryV1> {
        self.selected.take()
    }

    pub(super) fn schema_selected_clone_v3(&self) -> Option<StoredProtocolHistoryV1> {
        self.selected_ref().cloned()
    }

    pub(super) fn selected_optional_v1(&self) -> Option<&StoredProtocolHistoryV1> {
        if self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) { return None; }
        self.selected_ref()
    }

    fn selected_ref(&self) -> Option<&StoredProtocolHistoryV1> {
        self.selected_index.and_then(|index| self.rows.get(index)).or(self.selected.as_ref())
    }

    pub(crate) fn snapshot(&self) -> Option<&ProtectedBrokerSessionJournalSnapshotV1> {
        if self.closed.is_some() || !matches!(self.returned, Some(Ok(()))) { return None; }
        self.snapshot.as_ref()
    }

    pub(in crate::recovery) fn negotiated_checkpoint_data_v2(&self) -> Option<&HistoricalSessionCheckpointV1> {
        self.snapshot()?;
        self.selected_ref()?.checkpoint.as_ref()
    }

    pub(crate) fn is_absent(&self) -> bool {
        self.closed.is_none() && matches!(self.returned, Some(Ok(()))) && self.selected_ref().is_none()
    }

    pub(crate) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        fn error<T>(value: &Option<Result<T, BrokerSessionSecurityError>>)
            -> Option<&(dyn std::error::Error + 'static)>
        { value.as_ref().and_then(|value| value.as_ref().err()).map(|e| e as _) }
        error(&self.floor_before)
            .or_else(|| error(&self.before_identity))
            .or_else(|| self.current.as_ref().and_then(|v| v.failure()).map(|e| e as _))
            .or_else(|| error(&self.after_identity))
            .or_else(|| self.row_identities.iter().find_map(error))
            .or_else(|| error(&self.schema))
            .or_else(|| error(&self.floor_after))
            .or_else(|| error(&self.returned))
            .or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }
}

fn stage<T: Copy>(result: Result<T, BrokerSessionSecurityError>,
    destination: Option<&mut Option<Result<T, BrokerSessionSecurityError>>>)
    -> Result<T, BrokerSessionSecurityError>
{
    let Some(destination) = destination else { return result; };
    if destination.is_some() { std::process::abort(); }
    *destination = Some(result);
    match destination.as_ref() {
        Some(Ok(value)) => Ok(*value),
        _ => Err(BrokerSessionSecurityError::Currentness),
    }
}

enum SchemaRow<'rows> {
    Ordinary(StoredProtocolHistoryV1),
    Retained(usize, &'rows StoredProtocolHistoryV1),
}

impl Deref for SchemaRow<'_> {
    type Target = StoredProtocolHistoryV1;
    fn deref(&self) -> &Self::Target {
        match self { Self::Ordinary(value) => value, Self::Retained(_, value) => value }
    }
}

enum SchemaRows<'rows> {
    Ordinary(std::vec::IntoIter<StoredProtocolHistoryV1>),
    Retained(std::iter::Enumerate<std::slice::Iter<'rows, StoredProtocolHistoryV1>>),
}

impl<'rows> Iterator for SchemaRows<'rows> {
    type Item = SchemaRow<'rows>;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Ordinary(rows) => rows.next().map(SchemaRow::Ordinary),
            Self::Retained(rows) => rows.next().map(|(index, row)| SchemaRow::Retained(index, row)),
        }
    }
}

impl ProtectedBrokerSessionJournalV1 {
    pub(super) fn read_optional_schema_captured(&mut self, protocol: BrokerSessionProtocolV1,
        work: &mut StoredReadOriginalsV1, retaining: bool) -> Result<(), BrokerSessionSecurityError>
    {
        let fixed_protocol = self.endpoint.protected_protocol_and_node().0;
        let before_identity = stage(self.stable_endpoint_identity(protocol),
            retaining.then_some(&mut work.before_identity))?;
        #[cfg(feature = "online-nix")]
        let online = self.online_schema.as_ref().map(|schema| (schema.key, schema.seed));
        {
            let mut authority = self.schema_authority_v3()?;

            for (key, value) in authority
                .records()
                .map_err(|_| BrokerSessionSecurityError::Currentness)?
            {
                #[cfg(feature = "online-nix")]
                if online.as_ref().is_some_and(|(seed_key, seed)| {
                    key == seed_key && value == seed
                }) || online.is_some() && is_online_nix_authorization_key(key)
                {
                    continue;
                }
                match classified_broker_session_key(key)?.0 {
                    BrokerSessionJournalKeyKind::Traffic => {}
                    // Archive values are checked by their separate strict
                    // validators during cold replay before this owner opens.
                    _ => continue,
                }
                let (_, row_protocol) = classify_protocol_key_v2(key)
                    .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                if row_protocol != fixed_protocol {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                if work.rows.len() == MAXIMUM_PROTOCOL_RECORDS {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
                if retaining {
                    work.current = Some(StoredBrokerSessionHistoryDecodeCaptureV1::new());
                    let current = work.current.as_mut().ok_or(BrokerSessionSecurityError::Currentness)?;
                    CanonicalStoredHistoryV1::decode_retaining(key, value, current)
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                    work.rows.push(StoredProtocolHistoryV1::from_canonical_for_key_v2(
                        current.take_stored_once().map_err(|_| BrokerSessionSecurityError::Currentness)?, key,
                    )?);
                    // The private wrapper owns the actual complete lower value first.
                    drop(work.current.take());
                } else {
                    work.rows.push(StoredProtocolHistoryV1::decode(key, value)?);
                }
            }
        }
        let after_identity = stage(self.stable_endpoint_identity(protocol),
            retaining.then_some(&mut work.after_identity))?;
        if before_identity != after_identity
            || work.rows
                .iter()
                .any(|record| record.endpoint != self.endpoint.role())
        {
            return Err(BrokerSessionSecurityError::Currentness);
        }
        let mut selected = None;
        let rows = if retaining {
            SchemaRows::Retained(work.rows.iter().enumerate())
        } else {
            SchemaRows::Ordinary(std::mem::take(&mut work.rows).into_iter())
        };
        for (index, record) in rows.enumerate() {
            let observed = self.stable_endpoint_identity(record.protocol);
            let identity = stage(observed, if retaining {
                Some(work.row_identities.get_mut(index).ok_or(BrokerSessionSecurityError::Currentness)?)
            } else { None })?;
            if record.stable_endpoint_identity != identity {
                return Err(BrokerSessionSecurityError::Currentness);
            }
            if record.protocol == protocol && record.purpose == self.purpose {
                if selected.replace(record).is_some() {
                    return Err(BrokerSessionSecurityError::Currentness);
                }
            }
        }
        if let Some(current) = &selected {
            if protocol == BrokerSessionProtocolV1::Host
                && self.endpoint.role() == BrokerSessionDurableEndpointV1::Client
            {
                for record in current.history_model()?.records() {
                    if super::original_host_argument_method_v2(record.method())
                        && record.phase() == BrokerSessionDurablePhaseV1::RequestPrepared
                    {
                        let archived = self
                            .read_host_argument_archive(record.request_id())?
                            .ok_or(BrokerSessionSecurityError::Currentness)?;
                        let archived_head = archived
                            .history_model()?
                            .head()
                            .map_err(|_| BrokerSessionSecurityError::Currentness)?
                            .clone();
                        if archived_head.request_packet() != record.request_packet() {
                            return Err(BrokerSessionSecurityError::Currentness);
                        }
                    }
                    if record.method() == BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY
                        && record.phase() == BrokerSessionDurablePhaseV1::Terminal
                        && successful_terminal(record)?
                    {
                        let body = aos_sandbox_api::aos::sandbox::local::v1::TerminalHostExecutionArgumentNoApplyRequestV1::decode_from_slice(
                            decode_canonical_request_v1(record.request_packet())
                                .map_err(|_| BrokerSessionSecurityError::Currentness)?
                                .message()
                                .body
                                .as_slice(),
                        )
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                        let source = ControllerExecutionArgumentAttemptV1::decode_canonical(
                            &body.canonical_attempt,
                        )
                        .map_err(|_| BrokerSessionSecurityError::Currentness)?;
                        let retained = self
                            .read_host_terminal_archive(source.request_id())?
                            .ok_or(BrokerSessionSecurityError::Currentness)?;
                        if retained.no_apply_outcome().request().canonical_packet()
                            != record.request_packet()
                            || Some(retained.no_apply_outcome().canonical_packet())
                                != record.outcome_packet()
                        {
                            return Err(BrokerSessionSecurityError::Currentness);
                        }
                    }
                }
            }
        }
        match selected {
            Some(SchemaRow::Ordinary(record)) => work.selected = Some(record),
            Some(SchemaRow::Retained(index, _)) => work.selected_index = Some(index),
            None => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod delete_protocol_tests {
    use super::*;

    #[test]
    fn fixed_delete_entry_refusal_prevents_later_native_read_entry() {
        // This genuine native Host fixture intentionally lives outside the
        // production fixed directory, so the real D predicate must refuse it.
        let mut fixture = super::super::lifecycle_test_fixture::LifecycleTerminalFixture::new();
        let mut read = StoredReadOriginalsV1::new();

        assert!(read.observe_delete_current_once_v1(&mut fixture.journal,
            BrokerSessionProtocolV1::Host).is_err());
        assert!(read.observe_protocol_once_v1(&mut fixture.journal, true,
            BrokerSessionProtocolV1::Host).is_err());

        assert!(read.floor_before.is_none());
        assert!(read.current.is_none());
        assert!(read.snapshot().is_none());
        assert!(read.failure().is_some());
    }

    #[test]
    fn same_native_stored_reader_keeps_the_actual_host_checkpoint_in_its_selected_destination() {
        // Genuine signed/native Host fixture with the established test-only
        // unscoped floor. This tests the shared reader, not production D minting.
        let mut fixture = super::super::lifecycle_test_fixture::LifecycleTerminalFixture::new();
        let expected = fixture.journal.read_current(BrokerSessionProtocolV1::Host).unwrap();
        let mut read = StoredReadOriginalsV1::new();

        read.observe_protocol_once_v1(&mut fixture.journal, true, BrokerSessionProtocolV1::Host).unwrap();

        assert_eq!(read.snapshot().unwrap(), &expected);
        let checkpoint = read.negotiated_checkpoint_data_v2().unwrap();
        assert!(!checkpoint.client_hello_bytes().is_empty());
        assert!(!checkpoint.broker_hello_bytes().is_empty());
        assert_eq!(read.selected_ref().unwrap().protocol, BrokerSessionProtocolV1::Host);
        assert!(read.failure().is_none());
    }
}
