//! Preserves each current reservation field without reconstructing an issuer.
//!
//! ```text
//! {schema,bytes,maximum,compact,records,aliases,assigned_cut_role,
//!  restore_cut_role,hello_role,complete,literal,codec_role,issuer}
//! ```
//!
//! The complete outer owner retains these exact raw bytes. The strict reader
//! returns scalar and alias facts only; saved deadlines and issuers never become
//! current host clocks, capture permissions or protocol reservations.

use super::*;
use crate::native_hello::OriginalNativeHelloJournal;
use crate::protocol_snapshot::compact_bytes::{BorrowedCompactBytes, ValidatedCompactBytes};
use crate::protocol_snapshot::owned11::typed::{Fields, Ledger, invalid, plain_string, unsigned};
use crate::retained_metadata::{
    MetadataObserver, aliases::MetadataSharedKind, records::MetadataRecordKind,
};
use serde::{Serialize, Serializer, ser::SerializeStruct};

struct ReservationHistory<'a> {
    reservation: &'a ProtocolSnapshotReservation,
    hello: &'a OriginalNativeHelloJournal,
}

impl ProtocolSnapshotReservation {
    fn authenticate_settled17_associations_data(
        &self,
        hello: &OriginalNativeHelloJournal,
    ) -> Result<(), ProviderError> {
        if let Some((_, owner, _, _)) = &self.issuer {
            owner.ensure_current()?;
        }
        if let Some(bank) = &self.original_hello {
            hello.authenticate_settled17_bank_data(bank)?;
        }
        Ok(())
    }

    /// Borrows every present current reservation field as historical DATA.
    ///
    /// # Errors
    /// Refuses a foreign issuer or another actual retained Hello-bank allocation.
    pub(crate) fn borrowed_settled17_data<'a>(
        &'a self,
        hello: &'a OriginalNativeHelloJournal,
    ) -> Result<impl Serialize + 'a, ProviderError> {
        self.authenticate_settled17_associations_data(hello)?;
        Ok(ReservationHistory {
            reservation: self,
            hello,
        })
    }

    /// Records every retained current allocation and repeated real shared edge.
    ///
    /// # Errors
    /// Refuses changed original associations, metadata exhaustion or overflow.
    pub(crate) fn observe_settled17_metadata_data(
        &self,
        hello: &OriginalNativeHelloJournal,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        self.authenticate_settled17_associations_data(hello)?;
        let Self {
            bytes,
            maximum,
            compact,
            owned11_records,
            owned11_aliases,
            original_assigned_cut,
            original_restore_cut,
            original_hello,
            complete,
            literal,
            codec,
            issuer,
        } = self;
        observer.vector::<u8>(bytes.capacity())?;
        observer.observe(maximum)?;
        observer.observe(compact)?;
        observer.observe(&owned11_records.is_some())?;
        if let Some(records) = owned11_records {
            observer.vector::<MetadataCapacityRecord>(records.capacity_rows())?;
            observer.observe(&records.maximum_rows())?;
            observer.observe(&records.rows().len())?;
        }
        observer.observe(&owned11_aliases.is_some())?;
        if let Some(aliases) = owned11_aliases {
            aliases.observe_settled17_bank_metadata_data(observer)?;
        }
        observer.observe(&original_assigned_cut.is_some())?;
        observer.observe(&original_restore_cut.is_some())?;
        observer.observe(&original_hello.is_some())?;
        if let Some(hello) = original_hello {
            observer.shared_original(MetadataSharedKind::FrameBank, hello.as_ref())?;
        }
        observer.observe(complete)?;
        observer.observe(&literal.is_some())?;
        if let Some(literal) = literal {
            literal.observe_owned11_metadata(observer)?;
        }
        observer.observe(&codec.is_some())?;
        if let Some(codec) = codec {
            observer.shared_original(MetadataSharedKind::Codec, codec.as_ref())?;
        }
        observer.observe(&issuer.is_some())?;
        if let Some((authority, actor, cut, _)) = issuer {
            observer.observe(&matches!(cut, ProtocolCaptureCut::NativeIncomingCapture))?;
            authority.observe_retained_metadata(observer)?;
            observer.shared_original(MetadataSharedKind::ProtocolOwner, actor.as_ref())?;
        }
        Ok(())
    }
}

impl Serialize for ReservationHistory<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.reservation
            .authenticate_settled17_associations_data(self.hello)
            .map_err(serde::ser::Error::custom)?;
        let ProtocolSnapshotReservation {
            bytes,
            maximum,
            compact,
            owned11_records,
            owned11_aliases,
            original_assigned_cut,
            original_restore_cut,
            original_hello,
            complete,
            literal,
            codec,
            issuer,
        } = self.reservation;
        let mut fields = serializer.serialize_struct("CurrentProtocolReservation17", 13)?;
        fields.serialize_field(
            "schema",
            "source-private.current-protocol-reservation-history/17",
        )?;
        fields.serialize_field(
            "bytes",
            &(bytes.capacity(), BorrowedCompactBytes::new(bytes)),
        )?;
        fields.serialize_field("maximum", maximum)?;
        fields.serialize_field("compact", compact)?;
        fields.serialize_field(
            "records",
            &owned11_records
                .as_ref()
                .map(|records| (records.maximum_rows(), records.capacity_rows(), records)),
        )?;
        fields.serialize_field(
            "aliases",
            &owned11_aliases
                .as_ref()
                .map(MetadataAliasBank::borrowed_settled17_bank_data),
        )?;
        fields.serialize_field(
            "assigned_cut_role",
            &original_assigned_cut
                .as_ref()
                .map(|_| "historical-assigned-cut"),
        )?;
        fields.serialize_field(
            "restore_cut_role",
            &original_restore_cut
                .as_ref()
                .map(|_| "historical-restore-cut"),
        )?;
        fields.serialize_field(
            "hello_role",
            &original_hello
                .as_ref()
                .map(|_| "native-original-Hello-frames"),
        )?;
        fields.serialize_field("complete", complete)?;
        fields.serialize_field(
            "literal",
            &literal
                .as_ref()
                .map(|bank| bank.protocol_view_with_encoding(true)),
        )?;
        fields.serialize_field(
            "codec_role",
            &codec.as_ref().map(|_| "native-connection-codec"),
        )?;
        fields.serialize_field(
            "issuer",
            &issuer.as_ref().map(|(authority, _, cut, _)| {
                (
                    authority.borrowed_settled_history_data(),
                    "native-connection-actor",
                    match cut {
                        ProtocolCaptureCut::HostSettled => "host-settled",
                        ProtocolCaptureCut::NativeIncomingCapture => "native-incoming-capture",
                    },
                    "historical-issuer-cut",
                )
            }),
        )?;
        fields.end()
    }
}

/// Keeps checked current reservation scalars beside the parent's complete raw body.
pub(crate) struct HistoricalReservation17 {
    pub(crate) maximum: usize,
    pub(crate) compact: bool,
    pub(crate) encoded_capacity: usize,
    pub(crate) encoded_length: usize,
    pub(crate) complete: bool,
    pub(crate) assigned_cut: bool,
    pub(crate) restore_cut: bool,
    hello_group: Option<usize>,
    codec_group: Option<usize>,
    issuer_actor_group: Option<usize>,
    issuer_authority: Option<crate::handshake::HistoricalAuthority17>,
    issuer_authority_groups: Option<(usize, usize)>,
    raw_digest: [u8; 32],
}

impl HistoricalReservation17 {
    /// Validates all raw fields and consumes their exact retained capacity rows.
    ///
    /// # Errors
    /// Refuses unsupported schema, incomplete fields or changed real alias roots.
    pub(crate) fn read_settled17_data(
        input: &[u8],
        ledger: &mut Ledger<'_, '_, '_>,
        build: bool,
    ) -> Result<Self, ProviderError> {
        let mut fields = Fields::object(input)?;
        exact(
            fields.named("schema")?,
            "source-private.current-protocol-reservation-history/17",
        )?;
        let bytes = fields.named("bytes")?;
        let maximum = quantity(fields.named("maximum")?)?;
        let compact = boolean(fields.named("compact")?)?;
        let records = fields.named("records")?;
        let aliases = fields.named("aliases")?;
        let assigned_cut = optional_role(
            fields.named("assigned_cut_role")?,
            "historical-assigned-cut",
        )?;
        let restore_cut =
            optional_role(fields.named("restore_cut_role")?, "historical-restore-cut")?;
        let has_hello = optional_role(fields.named("hello_role")?, "native-original-Hello-frames")?;
        let complete = boolean(fields.named("complete")?)?;
        let literal = fields.named("literal")?;
        let has_codec = optional_role(fields.named("codec_role")?, "native-connection-codec")?;
        let issuer = fields.named("issuer")?;
        fields.finish()?;

        let mut bank = Fields::array(bytes)?;
        let encoded_capacity = quantity(next(&mut bank)?)?;
        let encoded = next(&mut bank)?;
        bank.finish()?;
        let encoded_length = ValidatedCompactBytes::validate(
            encoded,
            ledger.limits.maximum_input_bytes,
            encoded_capacity,
        )?
        .decoded_length();
        if maximum == 0
            || encoded_length > maximum
            || encoded_capacity < maximum
            || ledger.row_aligned(MetadataRecordKind::Vector, 1, 1)? != encoded_capacity
        {
            return Err(invalid());
        }
        if records != b"null" {
            read_record_bank_data(records, ledger)?;
        }
        if aliases != b"null" {
            read_alias_bank_data(aliases, ledger)?;
        }
        let hello_group = if has_hello {
            Some(shared_reference_data::<
                std::cell::RefCell<crate::transport::original_frames::OriginalFrameReservation>,
            >(ledger, MetadataSharedKind::FrameBank)?)
        } else {
            None
        };
        if literal != b"null" {
            crate::native_hello::settled17::read_literal_data(literal, ledger)?;
        }
        let codec_group = if has_codec {
            Some(
                shared_reference_data::<crate::connection::Native5CodecOwner>(
                    ledger,
                    MetadataSharedKind::Codec,
                )?,
            )
        } else {
            None
        };
        let (issuer_authority, issuer_actor_group, issuer_authority_groups) = if issuer == b"null" {
            (None, None, None)
        } else {
            let mut fields = Fields::array(issuer)?;
            let (authority, authority_groups) =
                crate::handshake::read_settled17_authority_fields_data(
                    next(&mut fields)?,
                    ledger,
                    build,
                )?;
            exact(next(&mut fields)?, "native-connection-actor")?;
            match plain_string(next(&mut fields)?)? {
                "host-settled" | "native-incoming-capture" => {}
                _ => return Err(invalid()),
            }
            exact(next(&mut fields)?, "historical-issuer-cut")?;
            fields.finish()?;
            (
                authority,
                Some(shared_reference_data::<ProtocolCaptureOwner>(
                    ledger,
                    MetadataSharedKind::ProtocolOwner,
                )?),
                Some(authority_groups),
            )
        };
        Ok(Self {
            maximum,
            compact,
            encoded_capacity,
            encoded_length,
            complete,
            assigned_cut,
            restore_cut,
            hello_group,
            codec_group,
            issuer_actor_group,
            issuer_authority,
            issuer_authority_groups,
            raw_digest: *blake3::hash(input).as_bytes(),
        })
    }

    /// Returns the independently present Hello, codec and issuer-actor groups.
    pub(crate) const fn group_ids_data(&self) -> (Option<usize>, Option<usize>, Option<usize>) {
        (self.hello_group, self.codec_group, self.issuer_actor_group)
    }

    /// Returns a present issuer's actual registrar groups in either pass.
    pub(crate) const fn issuer_registration_groups_data(&self) -> Option<(usize, usize)> {
        self.issuer_authority_groups
    }

    /// Checks a retained issuer's full registration against the current owner.
    ///
    /// # Errors
    /// Refuses an incomplete historical issuer or different registration DATA.
    pub(crate) fn authenticate_issuer_authority_data(
        &self,
        authority: &crate::handshake::HistoricalAuthority17,
    ) -> Result<(), ProviderError> {
        match (&self.issuer_authority, self.issuer_actor_group) {
            (None, None) => Ok(()),
            (Some(issuer), Some(_)) if issuer.same_registration_data(authority) => Ok(()),
            _ => Err(invalid()),
        }
    }

    /// Returns the commitment to all independently retained raw fields.
    pub(crate) const fn raw_digest_data(&self) -> &[u8; 32] {
        &self.raw_digest
    }
}

fn read_record_bank_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<(), ProviderError> {
    let mut fields = Fields::array(input)?;
    let maximum = quantity(next(&mut fields)?)?;
    let capacity = quantity(next(&mut fields)?)?;
    let rows = next(&mut fields)?;
    fields.finish()?;
    if maximum == 0
        || capacity < maximum
        || capacity > 131072
        || ledger.row_aligned(
            MetadataRecordKind::Vector,
            std::mem::size_of::<MetadataCapacityRecord>(),
            std::mem::align_of::<MetadataCapacityRecord>(),
        )? != capacity
    {
        return Err(invalid());
    }
    let plan = ValidatedMetadataRecords::validate(
        rows,
        maximum,
        ledger.limits.maximum_owned_backing_bytes,
    )?;
    if plan.row_count() > capacity {
        return Err(invalid());
    }
    Ok(())
}

fn read_alias_bank_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<(), ProviderError> {
    let mut fields = Fields::array(input)?;
    let maximum = quantity(next(&mut fields)?)?;
    let capacity = quantity(next(&mut fields)?)?;
    let lookup_capacity = quantity(next(&mut fields)?)?;
    let rows = next(&mut fields)?;
    let lookup = next(&mut fields)?;
    let comparisons = quantity(next(&mut fields)?)?;
    fields.finish()?;
    if maximum == 0
        || maximum > 131072
        || capacity < maximum
        || lookup_capacity < maximum
        || comparisons > 64 * 1024 * 1024
    {
        return Err(invalid());
    }
    for ((size, alignment), expected) in
        crate::retained_metadata::aliases::settled17_alias_bank_layouts_data()
            .into_iter()
            .zip([capacity, lookup_capacity])
    {
        if ledger.row_aligned(MetadataRecordKind::Vector, size, alignment)? != expected {
            return Err(invalid());
        }
    }
    let mut cursor = Fields::array(rows)?;
    let mut count = 0usize;
    let mut groups = 0usize;
    let mut work = 0usize;
    while let Some(row) = cursor.next()? {
        if count >= maximum || count >= capacity {
            return Err(invalid());
        }
        let mut fields = Fields::array(row)?;
        let kind = next(&mut fields)?;
        alias_kind(kind)?;
        let group = quantity(next(&mut fields)?)?;
        fields.finish()?;
        if group > groups {
            return Err(invalid());
        }
        if group == groups {
            groups = groups.checked_add(1).ok_or_else(invalid)?;
        } else if first_group_kind_data(rows, group, &mut work)? != plain_string(kind)? {
            return Err(invalid());
        }
        count += 1;
    }
    cursor.finish()?;
    let mut cursor = Fields::array(lookup)?;
    let mut count = 0usize;
    while let Some(kind) = cursor.next()? {
        alias_kind(kind)?;
        if count >= groups || first_group_kind_data(rows, count, &mut work)? != plain_string(kind)?
        {
            return Err(invalid());
        }
        count = count.checked_add(1).ok_or_else(invalid)?;
        if count > maximum || count > lookup_capacity {
            return Err(invalid());
        }
    }
    cursor.finish()?;
    // A completed source walk clears only its private lookup keys. Otherwise
    // every retained first group has its corresponding ordered lookup entry.
    if count != 0 && count != groups {
        return Err(invalid());
    }
    Ok(())
}

fn first_group_kind_data<'a>(
    input: &'a [u8],
    target: usize,
    work: &mut usize,
) -> Result<&'a str, ProviderError> {
    let mut rows = Fields::array(input)?;
    while let Some(row) = rows.next()? {
        *work = work.checked_add(1).ok_or_else(invalid)?;
        if *work > 64 * 1024 * 1024 {
            return Err(invalid());
        }
        let mut fields = Fields::array(row)?;
        let kind = next(&mut fields)?;
        let group = quantity(next(&mut fields)?)?;
        fields.finish()?;
        if group == target {
            return plain_string(kind);
        }
    }
    Err(invalid())
}

fn alias_kind(input: &[u8]) -> Result<(), ProviderError> {
    match plain_string(input)? {
        "native-restored-physical-hold"
        | "native-restore-commit-attempt"
        | "native-restore-input-custody"
        | "native-restoration-observation-attempt"
        | "native-restored-suffix-observe-attempt"
        | "native-restored-producer-attempt"
        | "protocol-owner"
        | "registrar-epoch"
        | "registrar-gate"
        | "selected-extensions"
        | "codec"
        | "native-policy"
        | "hello-bank"
        | "content-bytes"
        | "frame-bank"
        | "native-boot"
        | "private-bootstrap-bank"
        | "installed-registry"
        | "native-supervisor"
        | "blob-ledger"
        | "host-supervisor"
        | "operational-deadline"
        | "archived-mapping"
        | "native-control-identity"
        | "native-fresh-report-attempt"
        | "native-restore-prepare-attempt"
        | "native-restoration-activation-attempt"
        | "native-restoration-upload-attempt" => Ok(()),
        _ => Err(invalid()),
    }
}

fn shared_reference_data<T>(
    ledger: &mut Ledger<'_, '_, '_>,
    kind: MetadataSharedKind,
) -> Result<usize, ProviderError> {
    if ledger.row_aligned(MetadataRecordKind::Shared, 1, std::mem::align_of::<T>())?
        != std::mem::size_of::<T>()
    {
        return Err(invalid());
    }
    ledger.shared_reference(kind, std::mem::size_of::<T>())
}

fn exact(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    if plain_string(input)? != expected {
        return Err(invalid());
    }
    Ok(())
}
fn optional_role(input: &[u8], role: &str) -> Result<bool, ProviderError> {
    if input == b"null" {
        return Ok(false);
    }
    exact(input, role)?;
    Ok(true)
}
fn quantity(input: &[u8]) -> Result<usize, ProviderError> {
    usize::try_from(unsigned(input)?).map_err(|_| invalid())
}
fn boolean(input: &[u8]) -> Result<bool, ProviderError> {
    match input {
        b"true" => Ok(true),
        b"false" => Ok(false),
        _ => Err(invalid()),
    }
}
fn next<'a>(fields: &mut Fields<'a>) -> Result<&'a [u8], ProviderError> {
    fields.next()?.ok_or_else(invalid)
}
