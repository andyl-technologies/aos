//! Borrows logical endpoint custody and one-shot lineage at the settled cut.
//!
//! Every source cache remains in the immutable outer wire. The projection keeps
//! exact identities, counts, debits and spent facts; it cannot create a receiver,
//! startup scope, transport, released-world witness or native admission.

mod fresh;
mod records;
mod retained;

pub(crate) use retained::authenticate_native17_retained_terminal_data;

pub(crate) use fresh::BorrowedSpentFresh17;

use crate::ProviderError;
use crate::connection::native17_borrowed_custody::{
    BorrowedBlobCustody17, authenticate_borrowed_settled_capture17_custody_data,
};
use crate::connection::{
    BorrowedAdmission17Lineage, BorrowedAuthority17Lineage,
    borrow_native17_connection_logical_data, native17_borrowed_bytes::*,
};
use crate::protocol_snapshot::{
    native_wholegraph17::BorrowedNativeCurrentGraph17Plan,
    owned11::typed::{Fields, invalid},
};

#[derive(Clone, Copy)]
pub(crate) struct BorrowedHello17Lineage<'a> {
    pub(crate) encoded: &'a [u8],
    pub(crate) maximum_bytes: usize,
    pub(crate) maximum_nesting: usize,
    pub(crate) attempted: bool,
    pub(crate) received: bool,
    pub(crate) write_started: bool,
    pub(crate) failed: bool,
    pub(crate) frames: Frames17<'a>,
}

impl<'a> BorrowedHello17Lineage<'a> {
    /// Borrows the complete actual incoming literal, including its frame header.
    pub(crate) fn request_literal_data(self) -> Result<Bytes17<'a>, ProviderError> {
        self.frames.single_literal(true)
    }

    /// Borrows the complete actual outgoing literal, including its frame header.
    pub(crate) fn response_literal_data(self) -> Result<Bytes17<'a>, ProviderError> {
        self.frames.single_literal(false)
    }

    pub(crate) fn request_frame_data(self) -> Result<Bytes17<'a>, ProviderError> {
        self.frames.single_body(true)
    }

    pub(crate) fn response_frame_data(self) -> Result<Bytes17<'a>, ProviderError> {
        self.frames.single_body(false)
    }

    fn read(encoded: &'a [u8]) -> Result<Self, ProviderError> {
        let maximum_bytes = quantity(item(encoded, 1)?)?;
        let maximum_nesting = quantity(item(encoded, 2)?)?;
        let attempted = boolean(item(encoded, 3)?)?;
        let received = boolean(item(encoded, 4)?)?;
        let write_started = boolean(item(encoded, 5)?)?;
        let failed = boolean(item(encoded, 6)?)?;
        let frames = Frames17::read(item(encoded, 7)?)?;
        frames.require_complete()?;
        Ok(Self {
            encoded,
            maximum_bytes,
            maximum_nesting,
            attempted,
            received,
            write_started,
            failed,
            frames,
        })
    }
}

/// Keeps the exact retained capsule rather than inferring release from Some.
#[derive(Clone, Copy)]
pub(crate) struct BorrowedCommitFlight17Lineage<'a> {
    pub(crate) held: &'a [u8],
    pub(crate) proof_allocation: &'a [u8],
    pub(crate) proof_charge: usize,
    pub(crate) commit_original: &'a [u8],
    pub(crate) completed_response: &'a [u8],
}

pub(crate) struct BorrowedNativeEndpoint17LogicalData<'a> {
    pub(crate) authority: BorrowedAuthority17Lineage<'a>,
    pub(crate) uploads: BorrowedBlobCustody17<'a>,
    pub(crate) pins: &'a [u8],
    pub(crate) records: &'a [u8],
    pub(crate) record_count: usize,
    pub(crate) next_sequence: u64,
    pub(crate) transport_credit: usize,
    pub(crate) held: bool,
    pub(crate) hello: BorrowedHello17Lineage<'a>,
    pub(crate) complete: &'a [u8],
    pub(crate) before: Option<&'a [u8]>,
    pub(crate) after: Option<&'a [u8]>,
    pub(crate) fresh: Option<BorrowedSpentFresh17<'a>>,
    pub(crate) canonical_ack_admission: Option<BorrowedAdmission17Lineage<'a>>,
    pub(crate) restore_prepare_admission: Option<BorrowedAdmission17Lineage<'a>>,
    pub(crate) restore_protocol_attempted: bool,
    pub(crate) commit_flight: Option<BorrowedCommitFlight17Lineage<'a>>,
    assigned_responses: [&'a [u8]; 2],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BorrowedTerminal17Location {
    Record { record: usize, original: usize },
    Assigned { slot: usize },
}

#[derive(Clone, Copy)]
pub(crate) struct BorrowedTerminal17<'a> {
    pub(crate) encoded: &'a [u8],
    pub(crate) location: BorrowedTerminal17Location,
    pub(crate) literal_slot: usize,
}

impl<'a> BorrowedNativeEndpoint17LogicalData<'a> {
    /// Finds the one actual completed terminal without copying old record heaps.
    ///
    /// # Errors
    /// Refuses absent or ambiguous terminals; every candidate must echo the
    /// original full scope and belong to its previously checked send frontier.
    pub(crate) fn completed_terminal_for_data(
        &self,
        original: &[u8],
    ) -> Result<BorrowedTerminal17<'a>, ProviderError> {
        let mut found = None;
        for record_index in 0..self.record_count {
            let record = item(self.records, record_index)?;
            let originals = field(record, "originals")?;
            for original_index in 0..quantity(field(record, "sent")?)? {
                let candidate = item(originals, original_index)?;
                if completed_matches(original, candidate)? {
                    retain_terminal(
                        &mut found,
                        BorrowedTerminal17 {
                            encoded: candidate,
                            location: BorrowedTerminal17Location::Record {
                                record: record_index,
                                original: original_index,
                            },
                            literal_slot: quantity(item(
                                field(record, "original_slots")?,
                                original_index,
                            )?)?,
                        },
                    )?;
                }
            }
        }
        for (slot, response) in self.assigned_responses.iter().enumerate() {
            if *response == b"null" {
                continue;
            }
            let candidate = field(response, "original")?;
            if completed_matches(original, candidate)? {
                retain_terminal(
                    &mut found,
                    BorrowedTerminal17 {
                        encoded: candidate,
                        location: BorrowedTerminal17Location::Assigned { slot },
                        literal_slot: quantity(field(response, "literal_slot")?)?,
                    },
                )?;
            }
        }
        found.ok_or_else(invalid)
    }
}

fn retain_terminal<'a>(
    found: &mut Option<BorrowedTerminal17<'a>>,
    candidate: BorrowedTerminal17<'a>,
) -> Result<(), ProviderError> {
    if let Some(prior) = found {
        // Two cache views may name one real outgoing occurrence. Their exact
        // original and actual literal slot must both agree before reuse.
        if prior.encoded != candidate.encoded || prior.literal_slot != candidate.literal_slot {
            return Err(invalid());
        }
    } else {
        *found = Some(candidate);
    }
    Ok(())
}

fn completed_matches(request: &[u8], candidate: &[u8]) -> Result<bool, ProviderError> {
    if field(candidate, "message")? != b"\"response\""
        || field(field(candidate, "body")?, "status")? != b"\"completed\""
    {
        return Ok(false);
    }
    for name in [
        "method",
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "request_id",
        "operation_id",
    ] {
        if field(request, name)? != field(candidate, name)? {
            return Ok(false);
        }
    }
    Ok(field(request, "message")? == b"\"request\"")
}

/// Checks complete borrowed endpoint correspondence and active-host refusals.
///
/// # Errors
/// Refuses unfinished Fresh/Prepare/Commit work, unresolved content custody,
/// changed journal literals/ACKs, differing independent registrations or policy,
/// invalid fixed storage/metadata facts or inconsistent exact debit frontiers.
pub(crate) fn borrow_native17_endpoint_logical_data<'a>(
    plan: &BorrowedNativeCurrentGraph17Plan<'a, '_>,
) -> Result<BorrowedNativeEndpoint17LogicalData<'a>, ProviderError> {
    let roots = plan.root_spans_data();
    let connection = borrow_native17_connection_logical_data(plan)?;
    let input = roots.endpoint_data();
    let authority = BorrowedAuthority17Lineage::read(field(input, "authority")?)?;
    authority.same_registration(connection.authority)?;
    for name in [
        "capture",
        "capture_allocation_attempt",
        "pending_capture",
        "after_confirmation",
    ] {
        if field(input, name)? != b"null" {
            return Err(invalid());
        }
    }
    let groups = plan.endpoint_groups_data();
    groups.authenticate_connection_groups_data(plan.connection_groups_data())?;
    if groups.boot != plan.boot_group_data() {
        return Err(invalid());
    }
    let pins = field(input, "pins")?;
    let uploads = authenticate_borrowed_settled_capture17_custody_data(
        roots.receiver_data(),
        pins,
        authority,
    )?;
    let records = field(input, "records")?;
    let record_count = count(records)?;
    let mut journal = Fields::array(records)?;
    while let Some(record) = journal.next_value()? {
        records::BorrowedExchange17::read(record, connection.frames)?;
    }
    journal.finish()?;
    let next_sequence =
        crate::protocol_snapshot::owned11::typed::unsigned(field(input, "next_sequence")?)?;
    let transport_credit = quantity(field(input, "transport_credit")?)?;
    let held = boolean(field(input, "held")?)?;
    if next_sequence != connection.correlations.next_sent {
        return Err(invalid());
    }
    let complete = field(input, "complete")?;
    let hello = BorrowedHello17Lineage::read(field(complete, "hello")?)?;
    let policy = field(roots.codec_data(), "data")?;
    if field(complete, "profile")? != field(policy, "capture_profile")?
        || field(complete, "metadata_limits")? != field(policy, "protocol_metadata_limits")?
    {
        return Err(invalid());
    }
    // These actual deny-unknown-fields contracts contain only fixed U64 rows.
    let storage: crate::reference_packet::service::PacketNative5StorageLimits =
        serde_json::from_slice(field(complete, "storage")?).map_err(|_| invalid())?;
    let limits: crate::handshake::Limits =
        serde_json::from_slice(authority.limits).map_err(|_| invalid())?;
    storage.validate(&limits)?;
    match (
        field(complete, "metadata_limits")?,
        field(complete, "metadata_birth_facts")?,
    ) {
        (b"null", b"null") => {}
        (limits, facts) if limits != b"null" && facts != b"null" => {
            let limits: crate::reference_packet::service::PacketNative5ProtocolMetadataLimits =
                serde_json::from_slice(limits).map_err(|_| invalid())?;
            let facts: crate::reference_packet::service::PacketNative5ProtocolMetadataBirthFacts =
                serde_json::from_slice(facts).map_err(|_| invalid())?;
            facts.validate_data(&limits)?;
        }
        _ => return Err(invalid()),
    }
    let before = reservation(field(complete, "before")?, authority)?;
    let after = reservation(field(complete, "after")?, authority)?;
    let canonical_ack_admission = token(
        field(input, "canonical_ack_admission")?,
        authority,
        connection.frames,
    )?;
    let restore_prepare_admission = token(
        field(input, "restore_prepare_admission")?,
        authority,
        connection.frames,
    )?;
    let restore_protocol_attempted = boolean(field(input, "restore_protocol_attempted")?)?;
    let flight = field(input, "restore_commit")?;
    let commit_flight = if flight == b"null" {
        if restore_protocol_attempted || restore_prepare_admission.is_some() {
            return Err(invalid());
        }
        None
    } else {
        for name in ["admission", "proof", "recovered_connection", "completed"] {
            if field(flight, name)? != b"null" {
                return Err(invalid());
            }
        }
        for name in ["mapping_role", "held", "proof_allocation"] {
            if field(flight, name)? == b"null" {
                return Err(invalid());
            }
        }
        let commit = plan
            .boot_lineage_data()
            .commit
            .as_ref()
            .ok_or_else(invalid)?;
        if !restore_protocol_attempted
            || !commit.verified
            || !commit.installation_started
            || !commit.receipt_started
            || commit.completed_response.raw_data() == b"null"
            || commit.gate_data.raw_data() == b"null"
            || connection.complete_restoration.is_none()
        {
            return Err(invalid());
        }
        let proof_charge = quantity(field(flight, "proof_charge")?)?;
        if proof_charge > transport_credit {
            return Err(invalid());
        }
        Some(BorrowedCommitFlight17Lineage {
            held: field(flight, "held")?,
            proof_allocation: field(flight, "proof_allocation")?,
            proof_charge,
            commit_original: commit.original.raw_data(),
            completed_response: commit.completed_response.raw_data(),
        })
    };
    let fresh_input = field(input, "fresh_restore_attempt")?;
    let fresh = if fresh_input == b"null" {
        None
    } else {
        if commit_flight.is_none() || !restore_protocol_attempted {
            return Err(invalid());
        }
        let prepare = plan
            .boot_lineage_data()
            .prepare
            .as_ref()
            .ok_or_else(invalid)?;
        Some(fresh::spent_fresh(
            fresh_input,
            records,
            complete,
            prepare.original.raw_data(),
            connection.frames,
        )?)
    };
    if let Some(token) = canonical_ack_admission {
        token.authenticate_original(
            plan.boot_lineage_data().ack_original.raw_data(),
            connection.frames,
        )?;
    }
    if let Some(token) = restore_prepare_admission {
        token.authenticate_original(
            plan.boot_lineage_data()
                .prepare
                .as_ref()
                .ok_or_else(invalid)?
                .original
                .raw_data(),
            connection.frames,
        )?;
    }
    Ok(BorrowedNativeEndpoint17LogicalData {
        authority,
        uploads,
        pins,
        records,
        record_count,
        next_sequence,
        transport_credit,
        held,
        hello,
        complete,
        before,
        after,
        fresh,
        canonical_ack_admission,
        restore_prepare_admission,
        restore_protocol_attempted,
        commit_flight,
        assigned_responses: [
            item(field(roots.connection_data(), "restore_responses")?, 0)?,
            item(field(roots.connection_data(), "restore_responses")?, 1)?,
        ],
    })
}

fn token<'a>(
    input: &'a [u8],
    authority: BorrowedAuthority17Lineage<'a>,
    frames: Frames17<'a>,
) -> Result<Option<BorrowedAdmission17Lineage<'a>>, ProviderError> {
    if input == b"null" {
        return Ok(None);
    }
    Ok(Some(BorrowedAdmission17Lineage::read(
        input, authority, frames,
    )?))
}

fn reservation<'a>(
    input: &'a [u8],
    authority: BorrowedAuthority17Lineage<'_>,
) -> Result<Option<&'a [u8]>, ProviderError> {
    if input == b"null" {
        return Ok(None);
    }
    let issuer = field(input, "issuer")?;
    if issuer != b"null" {
        BorrowedAuthority17Lineage::read(item(issuer, 0)?)?.same_registration(authority)?;
    }
    Ok(Some(input))
}
