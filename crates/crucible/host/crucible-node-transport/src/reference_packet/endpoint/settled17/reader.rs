//! Reads the actual Endpoint17 component as inert retained DATA.
//!
//! The physical writer emits schema-first fields. The reader first captures
//! those exact spans, then consumes capacities and aliases in the distinct
//! owning metadata walk order. Every child uses this same caller-owned Ledger;
//! no complete field is represented by a validity assertion about raw bytes.

use super::*;
use crate::connection::{
    HistoricalAckToken17, HistoricalCurrentNativeConnection17, HistoricalExchangeRecord17,
    HistoricalNativeBlobReceiver17, HistoricalOperationPin17, HistoricalPrepareToken17,
    NativeBlobReceiver17GroupIds, NativeConnection17GroupIds, read_native17_blob_receiver_data,
    read_native17_operation_pin_data,
};
use crate::handshake::HistoricalAuthority17;
use crate::protocol_snapshot::owned11::typed::{
    Fields, HistoricalType, Ledger, invalid, plain_string, unsigned,
};
use crate::reference_packet::endpoint::{
    complete::settled17::{CompleteEndpoint17Groups, HistoricalCompleteEndpoint17},
    fresh_restore::{HistoricalFreshRestoreAttempt17, NativeFreshRestoreAttempt},
    restore_commit::settled17::{HistoricalRestoreCommitFlight17, RestoreCommitFlight17Groups},
};
use crate::reference_packet::service::report_startup::PacketNativeReportStartupPurpose;
use crate::retained_metadata::records::MetadataRecordKind;
use std::mem::{align_of, size_of};

/// Names the original Fresh Rc group and both independent startup root pairs.
#[derive(Clone, Copy)]
pub(crate) struct FreshEndpoint17GroupIds {
    pub(crate) owner: usize,
    pub(crate) startup: (usize, usize),
    pub(crate) prepare: (usize, usize),
}

/// Retains independently checked role coordinates from the same Endpoint pass.
#[derive(Clone, Copy)]
pub(crate) struct CurrentEndpoint17GroupIds {
    pub(crate) authority: (usize, usize),
    pub(crate) policy: usize,
    pub(crate) uploads: NativeBlobReceiver17GroupIds,
    pub(crate) pins: usize,
    pub(crate) records: usize,
    pub(crate) records_with_actor: usize,
    pub(crate) record_actor_frames: Option<(usize, usize)>,
    pub(crate) complete: CompleteEndpoint17Groups,
    pub(crate) fresh: Option<FreshEndpoint17GroupIds>,
    pub(crate) boot: usize,
    pub(crate) ack: Option<(usize, usize, usize, usize)>,
    pub(crate) flight: Option<RestoreCommitFlight17Groups>,
    pub(crate) prepare: Option<(usize, usize, usize, usize, usize)>,
}

/// Owns every eligible current Endpoint field without creating a live endpoint.
///
/// The connected transport, Control and immutable policy remain independently
/// defined outer graph roles. The four explicit legacy transaction slots are
/// absent in this class; the writer checks their actual absence before encoding.
pub(crate) struct CurrentEndpoint17Data {
    pub(crate) authority: HistoricalAuthority17,
    pub(crate) uploads: HistoricalNativeBlobReceiver17,
    pub(crate) pins: Vec<HistoricalOperationPin17>,
    pub(crate) pins_capacity: usize,
    pub(crate) records: Vec<HistoricalExchangeRecord17>,
    pub(crate) records_capacity: usize,
    pub(crate) next_sequence: u64,
    pub(crate) transport_credit: usize,
    pub(crate) held: bool,
    pub(crate) complete: HistoricalCompleteEndpoint17,
    pub(crate) fresh_restore_attempt: Option<Rc<HistoricalFreshRestoreAttempt17>>,
    pub(crate) canonical_ack_admission: Option<HistoricalAckToken17>,
    pub(crate) restore_commit: Option<HistoricalRestoreCommitFlight17>,
    pub(crate) restore_protocol_attempted: bool,
    pub(crate) restore_prepare_admission: Option<HistoricalPrepareToken17>,
    groups: CurrentEndpoint17GroupIds,
}

/// Reads complete current Endpoint fields using the caller's single Ledger.
///
/// # Errors
/// Refuses another edition, unsupported active legacy slots, changed capacities
/// or aliases, unavailable exact backing, or unconsumed component fields.
pub(crate) fn read_endpoint17_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<Option<CurrentEndpoint17Data>, ProviderError> {
    read_endpoint17_fields_data(input, ledger, build).map(|result| result.0)
}

/// Returns actual shared-role coordinates during both native17 reader passes.
///
/// # Errors
/// Refuses malformed source framing, unsupported active legacy slots, incomplete
/// prior root definitions or any disagreement with the actual capacity roster.
pub(crate) fn read_endpoint17_fields_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<CurrentEndpoint17Data>, CurrentEndpoint17GroupIds), ProviderError> {
    read_endpoint17_inner_data(input, ledger, build, None)
}

/// Reads the distinct root-linked Endpoint using only enclosing grammar spans.
///
/// # Errors
/// Refuses changed closed roles, parent roots, exact rows or child history.
pub(crate) fn read_rooted_endpoint17_fields_data(
    roots: &crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans<'_>,
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<(Option<CurrentEndpoint17Data>, CurrentEndpoint17GroupIds), ProviderError> {
    read_endpoint17_inner_data(roots.endpoint_data(), ledger, build, Some(roots))
}

fn read_endpoint17_inner_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
    roots: Option<
        &crate::protocol_snapshot::native_wholegraph17::NativeCurrentGraph17RootSpans<'_>,
    >,
) -> Result<(Option<CurrentEndpoint17Data>, CurrentEndpoint17GroupIds), ProviderError> {
    if ledger.settled_aliases.is_none() || ledger.aliases.is_some() {
        return Err(invalid());
    }
    let mut spans = EndpointSpans17::read(input, roots.is_some())?;
    if let Some(roots) = roots {
        if plain_string(spans.uploads)? != "native-blob-receiver" {
            return Err(invalid());
        }
        spans.uploads = roots.receiver_data();
    }

    let (authority, authority_groups) =
        crate::handshake::read_settled17_authority_fields_data(spans.authority, ledger, build)?;
    let policy = reference::<Native5Policy>(ledger, MetadataSharedKind::NativePolicy)?;
    let (uploads, upload_groups) = read_native17_blob_receiver_data(spans.uploads, ledger, build)?;

    exact_vector::<OperationContentPin>(ledger, spans.pins_capacity)?;
    ledger.native17_target_vector_data::<HistoricalOperationPin17>(spans.pins_capacity)?;
    let mut pins = reserve::<HistoricalOperationPin17>(spans.pins_capacity, build)?;
    let mut cursor = Fields::array(spans.pins)?;
    let mut pin_count = 0usize;
    while let Some(pin) = cursor.next_value()? {
        pin_count = next_count(pin_count, spans.pins_capacity)?;
        let (pin, group) = read_native17_operation_pin_data(pin, spans.uploads, ledger, build)?;
        if group != upload_groups.ledger {
            return Err(invalid());
        }
        if let Some(pin) = pin {
            pins.push(pin);
        }
    }
    cursor.finish()?;
    if pin_count > EXCHANGES {
        return Err(invalid());
    }

    exact_vector::<ExchangeRecord>(ledger, spans.records_capacity)?;
    ledger.native17_target_vector_data::<HistoricalExchangeRecord17>(spans.records_capacity)?;
    let mut records = reserve::<HistoricalExchangeRecord17>(spans.records_capacity, build)?;
    let mut cursor = Fields::array(spans.records)?;
    let mut record_count = 0usize;
    let mut records_with_actor = 0usize;
    let mut record_actor_frames = None;
    while let Some(record) = cursor.next_value()? {
        record_count = next_count(record_count, spans.records_capacity)?;
        let (record, groups) =
            HistoricalExchangeRecord17::read_settled17_fields_data(record, ledger, build)?;
        if let Some(groups) = groups {
            if record_actor_frames.is_some_and(|prior| prior != groups) {
                return Err(invalid());
            }
            record_actor_frames = Some(groups);
            records_with_actor = records_with_actor.checked_add(1).ok_or_else(invalid)?;
        }
        if let Some(record) = record {
            records.push(record);
        }
    }
    cursor.finish()?;
    if record_count > EXCHANGES {
        return Err(invalid());
    }

    let next_sequence = ledger
        .read::<u64>(spans.next_sequence, true)?
        .ok_or_else(invalid)?;
    let transport_credit = ledger
        .read::<usize>(spans.transport_credit, true)?
        .ok_or_else(invalid)?;
    let held = ledger.read::<bool>(spans.held, true)?.ok_or_else(invalid)?;
    if next_sequence < 2 || transport_credit > MAXIMUM_PACKET_TRANSPORT_BYTES {
        return Err(invalid());
    }
    let (complete, complete_groups) =
        HistoricalCompleteEndpoint17::read_settled17_fields_data(spans.complete, ledger, build)?;
    let (fresh_restore_attempt, fresh_groups) =
        read_fresh(spans.fresh_restore_attempt, ledger, build)?;
    let boot = reference::<RefCell<NativeAckBoot>>(ledger, MetadataSharedKind::NativeBoot)?;
    let (canonical_ack_admission, ack_groups) = if spans.canonical_ack_admission == b"null" {
        (None, None)
    } else {
        let (token, groups) = HistoricalAckToken17::read_settled17_fields_data(
            spans.canonical_ack_admission,
            ledger,
            build,
        )?;
        (token, Some(groups))
    };
    let (restore_commit, flight_groups) = if spans.restore_commit == b"null" {
        (None, None)
    } else {
        let (flight, groups) = HistoricalRestoreCommitFlight17::read_settled17_fields_data(
            spans.restore_commit,
            ledger,
            build,
        )?;
        (flight, Some(groups))
    };
    let restore_protocol_attempted = ledger
        .read::<bool>(spans.restore_protocol_attempted, true)?
        .ok_or_else(invalid)?;
    let (restore_prepare_admission, prepare_groups) = if spans.restore_prepare_admission == b"null"
    {
        (None, None)
    } else {
        let (token, groups) = HistoricalPrepareToken17::read_settled17_fields_data(
            spans.restore_prepare_admission,
            ledger,
            build,
        )?;
        (token, Some(groups))
    };

    let groups = CurrentEndpoint17GroupIds {
        authority: authority_groups,
        policy,
        uploads: upload_groups,
        pins: pin_count,
        records: record_count,
        records_with_actor,
        record_actor_frames,
        complete: complete_groups,
        fresh: fresh_groups,
        boot,
        ack: ack_groups,
        flight: flight_groups,
        prepare: prepare_groups,
    };
    groups.authenticate_local_role_groups_data()?;
    if !build {
        return Ok((None, groups));
    }
    Ok((
        Some(CurrentEndpoint17Data {
            authority: authority.ok_or_else(invalid)?,
            uploads: uploads.ok_or_else(invalid)?,
            pins,
            pins_capacity: spans.pins_capacity,
            records,
            records_capacity: spans.records_capacity,
            next_sequence,
            transport_credit,
            held,
            complete: complete.ok_or_else(invalid)?,
            fresh_restore_attempt,
            canonical_ack_admission,
            restore_commit,
            restore_protocol_attempted,
            restore_prepare_admission,
            groups,
        }),
        groups,
    ))
}

impl CurrentEndpoint17Data {
    /// Returns actual same-pass group facts for independent whole-graph joins.
    pub(crate) const fn group_ids_data(&self) -> CurrentEndpoint17GroupIds {
        self.groups
    }

    /// Checks retained Endpoint children against the independent current Connection.
    ///
    /// The enclosing graph additionally conjoins Boot, Prepare, Commit, mapping,
    /// physical Hold and startup facts with their independently defined owners.
    /// This method constructs no registrar, transport, model or capture grant.
    ///
    /// # Errors
    /// Refuses a changed registration, different real group, invalid pin/ledger,
    /// inconsistent literal history or a mismatched selected complete profile.
    pub(crate) fn authenticate_local_groups_data(
        &self,
        connection: &HistoricalCurrentNativeConnection17,
    ) -> Result<(), ProviderError> {
        let current = connection.group_ids_data();
        self.groups.authenticate_connection_groups_data(current)?;
        if !self.authority.same_registration_data(&connection.authority)
            || self.uploads.data.session != self.authority.data.session
            || self.uploads.data.incarnation != self.authority.data.incarnation
            || self.complete.profile.as_ref() != Some(&connection.policy.data.capture_profile)
            || self.complete.metadata_limits != connection.policy.data.protocol_metadata_limits
        {
            return Err(invalid());
        }
        self.complete
            .storage
            .validate(&self.authority.data.limits)?;
        match (
            self.complete.metadata_limits,
            self.complete.metadata_birth_facts,
        ) {
            (Some(limits), Some(facts)) => facts.validate_data(&limits)?,
            (None, None) => {}
            _ => return Err(invalid()),
        }
        for reservation in [&self.complete.before, &self.complete.after]
            .into_iter()
            .flatten()
        {
            reservation.authenticate_issuer_authority_data(&self.authority)?;
        }
        self.uploads.authenticate_state_data()?;
        for pin in &self.pins {
            pin.authenticate_receiver_data(&self.uploads)?;
        }
        for record in &self.records {
            record.authenticate_connection17_data(connection)?;
        }
        if let Some(fresh) = &self.fresh_restore_attempt {
            if fresh.startup.purpose != PacketNativeReportStartupPurpose::FreshCompletedAdmit13
                || fresh.startup.source_digest.0 != fresh.prepare.source_digest.0
                || fresh.creator != self.complete.creator
            {
                return Err(invalid());
            }
        }
        if let Some(token) = &self.canonical_ack_admission {
            if !token.authority.same_registration_data(&self.authority) {
                return Err(invalid());
            }
        }
        if let Some(token) = &self.restore_prepare_admission {
            if !token.authority.same_registration_data(&self.authority) {
                return Err(invalid());
            }
        }
        if let Some(flight) = &self.restore_commit {
            if let Some(token) = &flight.admission {
                if !token.authority.same_registration_data(&self.authority) {
                    return Err(invalid());
                }
            }
            if let Some(recovered) = &flight.recovered_connection {
                recovered.authenticate_child_groups_data()?;
                if !recovered.authority.same_registration_data(&self.authority) {
                    return Err(invalid());
                }
            }
            if let Some(record) = &flight.completed {
                record.authenticate_connection17_data(connection)?;
            }
        }
        if let Some(token) = &connection.canonical_ack_admission {
            if token.group_ids_data().2 != self.groups.boot {
                return Err(invalid());
            }
        }
        if let Some(inputs) = &connection.restore_inputs {
            let (_, _, boot, _, prepare) = inputs.token.group_ids_data();
            if boot != self.groups.boot
                || self
                    .groups
                    .prepare
                    .is_some_and(|groups| groups.4 != prepare)
            {
                return Err(invalid());
            }
        }
        if let Some(installed) = &connection.complete_restoration {
            let (_, _, boot, _, commit) = installed.token.group_ids_data();
            if boot != self.groups.boot {
                return Err(invalid());
            }
            if let Some(flight) = self.groups.flight {
                if flight
                    .mapping
                    .is_some_and(|mapping| mapping != installed.mapping_group)
                    || flight.admission.is_some_and(|groups| groups.4 != commit)
                    || flight.held.is_some_and(|groups| groups.2 != commit)
                {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }

    /// Reports requested typed container/header bytes distinct from source rows.
    ///
    /// Nested String, byte, tree and decoded cache backing remains separately
    /// charged by the owning whole17 geometry. This DATA supplies no admission.
    ///
    /// # Errors
    /// Refuses checked layout overflow.
    pub(crate) fn historical_container_requested_bytes_data(&self) -> Result<usize, ProviderError> {
        let pins = self
            .pins
            .capacity()
            .checked_mul(size_of::<HistoricalOperationPin17>())
            .ok_or_else(invalid)?;
        let records = self
            .records
            .capacity()
            .checked_mul(size_of::<HistoricalExchangeRecord17>())
            .ok_or_else(invalid)?;
        let fresh = if self.fresh_restore_attempt.is_some() {
            let header = crate::retained_metadata::requested_storage::shared_header_storage_data(
                1,
                align_of::<HistoricalFreshRestoreAttempt17>(),
            )?;
            size_of::<HistoricalFreshRestoreAttempt17>()
                .checked_add(header)
                .ok_or_else(invalid)?
        } else {
            0
        };
        size_of::<Self>()
            .checked_add(pins)
            .and_then(|bytes| bytes.checked_add(records))
            .and_then(|bytes| bytes.checked_add(fresh))
            .ok_or_else(invalid)
    }
}

impl CurrentEndpoint17GroupIds {
    /// Checks actual Endpoint references against independent Connection roots.
    ///
    /// # Errors
    /// Refuses another policy, ledger, supervisor, actor, frame bank or codec.
    pub(crate) fn authenticate_connection_groups_data(
        &self,
        current: NativeConnection17GroupIds,
    ) -> Result<(), ProviderError> {
        self.authenticate_local_role_groups_data()?;
        if self.policy != current.policy
            || current.blobs != Some(self.uploads.ledger)
            || self.uploads.supervisor != current.supervisor
            || self
                .record_actor_frames
                .is_some_and(|groups| groups != (current.actor, current.frames))
        {
            return Err(invalid());
        }
        for groups in [self.complete.before, self.complete.after]
            .into_iter()
            .flatten()
        {
            if groups.1.is_some_and(|codec| codec != current.codec)
                || groups.2.is_some_and(|actor| actor != current.actor)
            {
                return Err(invalid());
            }
        }
        if self
            .ack
            .is_some_and(|groups| (groups.0, groups.1) != (current.actor, current.frames))
            || self
                .prepare
                .is_some_and(|groups| (groups.0, groups.1) != (current.actor, current.frames))
        {
            return Err(invalid());
        }
        if let Some(flight) = self.flight {
            if flight
                .admission
                .is_some_and(|groups| (groups.0, groups.1) != (current.actor, current.frames))
                || flight
                    .completed
                    .is_some_and(|groups| groups != (current.actor, current.frames))
                || flight
                    .proof_allocation
                    .is_some_and(|groups| groups != (current.actor, current.codec, current.frames))
                || flight.recovered.is_some_and(|groups| groups != current)
            {
                return Err(invalid());
            }
        }
        Ok(())
    }

    fn authenticate_local_role_groups_data(&self) -> Result<(), ProviderError> {
        for registrar in [
            self.complete.before_authority,
            self.complete.after_authority,
        ]
        .into_iter()
        .flatten()
        {
            if registrar != self.authority {
                return Err(invalid());
            }
        }
        if self
            .ack
            .is_some_and(|groups| (groups.2, groups.3) != (self.boot, self.policy))
            || self
                .prepare
                .is_some_and(|groups| (groups.2, groups.3) != (self.boot, self.policy))
        {
            return Err(invalid());
        }
        if let Some(fresh) = self.fresh {
            if fresh.startup != (self.boot, self.policy)
                || fresh.prepare != (self.boot, self.policy)
            {
                return Err(invalid());
            }
        }
        if let Some(flight) = self.flight {
            if flight
                .admission
                .is_some_and(|groups| (groups.2, groups.3) != (self.boot, self.policy))
                || flight.held.is_some_and(|groups| groups.0 != self.boot)
            {
                return Err(invalid());
            }
            if let (Some(admission), Some(held)) = (flight.admission, flight.held) {
                if admission.4 != held.2 {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}

fn read_fresh(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
    build: bool,
) -> Result<
    (
        Option<Rc<HistoricalFreshRestoreAttempt17>>,
        Option<FreshEndpoint17GroupIds>,
    ),
    ProviderError,
> {
    if input == b"null" {
        return Ok((None, None));
    }
    type Payload = RefCell<NativeFreshRestoreAttempt>;
    let start = ledger.rows.encoded_position();
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, align_of::<Payload>())?
        != size_of::<Payload>()
    {
        return Err(invalid());
    }
    let owner = ledger.shared_begin(MetadataSharedKind::NativeFreshReportAttempt)?;
    ledger.native17_target_shared_data::<HistoricalFreshRestoreAttempt17>()?;
    let (data, (startup, prepare)) =
        HistoricalFreshRestoreAttempt17::read_settled17_fields_data(input, ledger, build)?;
    let rows = ledger.rows.encoded_between(start)?;
    ledger.shared_finish(owner, size_of::<Payload>(), input, rows)?;
    Ok((
        data.map(Rc::new),
        Some(FreshEndpoint17GroupIds {
            owner,
            startup,
            prepare,
        }),
    ))
}

struct EndpointSpans17<'a> {
    authority: &'a [u8],
    uploads: &'a [u8],
    pins: &'a [u8],
    pins_capacity: usize,
    records: &'a [u8],
    records_capacity: usize,
    next_sequence: &'a [u8],
    transport_credit: &'a [u8],
    held: &'a [u8],
    complete: &'a [u8],
    fresh_restore_attempt: &'a [u8],
    canonical_ack_admission: &'a [u8],
    restore_commit: &'a [u8],
    restore_protocol_attempted: &'a [u8],
    restore_prepare_admission: &'a [u8],
}

impl<'a> EndpointSpans17<'a> {
    fn read(input: &'a [u8], rooted: bool) -> Result<Self, ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            if rooted {
                "source-private.native-rooted-endpoint/17"
            } else {
                "source-private.native-current-endpoint/17"
            },
        )?;
        let mut transport = Fields::array(fields.named("transport")?)?;
        exact(next(&mut transport)?, "connected")?;
        exact(next(&mut transport)?, "current-native-connection")?;
        transport.finish()?;
        exact(fields.named("native_role")?, "current-native-control")?;
        let authority = fields.named("authority")?;
        exact(fields.named("policy_role")?, "native-policy")?;
        let uploads = fields.named("uploads")?;
        let pins = fields.named("pins")?;
        let pins_capacity = quantity(fields.named("pins_capacity")?)?;
        let records = fields.named("records")?;
        let records_capacity = quantity(fields.named("records_capacity")?)?;
        let next_sequence = fields.named("next_sequence")?;
        let transport_credit = fields.named("transport_credit")?;
        let held = fields.named("held")?;
        let complete = fields.named("complete")?;
        if complete == b"null" {
            return Err(invalid());
        }
        require_null(fields.named("capture")?)?;
        require_null(fields.named("capture_allocation_attempt")?)?;
        let fresh_restore_attempt = fields.named("fresh_restore_attempt")?;
        require_null(fields.named("pending_capture")?)?;
        require_null(fields.named("after_confirmation")?)?;
        exact(fields.named("canonical_ack_boot_role")?, "native-boot")?;
        let canonical_ack_admission = fields.named("canonical_ack_admission")?;
        let restore_commit = fields.named("restore_commit")?;
        let restore_protocol_attempted = fields.named("restore_protocol_attempted")?;
        let restore_prepare_admission = fields.named("restore_prepare_admission")?;
        fields.finish()?;
        Ok(Self {
            authority,
            uploads,
            pins,
            pins_capacity,
            records,
            records_capacity,
            next_sequence,
            transport_credit,
            held,
            complete,
            fresh_restore_attempt,
            canonical_ack_admission,
            restore_commit,
            restore_protocol_attempted,
            restore_prepare_admission,
        })
    }
}

impl HistoricalType for CurrentEndpoint17Data {
    fn read(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Option<Self>, ProviderError> {
        read_endpoint17_data(input, ledger, build)
    }
}

fn next<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    fields.next_value()?.ok_or_else(invalid)
}
fn exact(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}
fn quantity(input: &[u8]) -> Result<usize, ProviderError> {
    usize::try_from(unsigned(input)?).map_err(|_| invalid())
}
fn require_null(input: &[u8]) -> Result<(), ProviderError> {
    if input != b"null" {
        return Err(invalid());
    }
    Ok(())
}
fn next_count(count: usize, capacity: usize) -> Result<usize, ProviderError> {
    count
        .checked_add(1)
        .filter(|next| *next <= capacity)
        .ok_or_else(invalid)
}

fn reference<T>(
    ledger: &mut Ledger<'_, '_, '_>,
    kind: MetadataSharedKind,
) -> Result<usize, ProviderError> {
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, align_of::<T>())? != size_of::<T>() {
        return Err(invalid());
    }
    ledger.shared_reference(kind, size_of::<T>())
}

fn exact_vector<T>(ledger: &mut Ledger<'_, '_, '_>, capacity: usize) -> Result<(), ProviderError> {
    if ledger.row_aligned(MetadataRecordKind::Vector, size_of::<T>(), align_of::<T>())? != capacity
    {
        return Err(invalid());
    }
    Ok(())
}

fn reserve<T>(capacity: usize, build: bool) -> Result<Vec<T>, ProviderError> {
    let mut values = Vec::new();
    if build {
        values.try_reserve_exact(capacity).map_err(|_| invalid())?;
        if values.capacity() != capacity {
            return Err(invalid());
        }
    }
    Ok(values)
}
