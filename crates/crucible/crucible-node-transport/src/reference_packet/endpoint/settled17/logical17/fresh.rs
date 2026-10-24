//! Checks the genuinely spent Fresh frontier without rebuilding report caches.

use super::records::BorrowedExchange17;
use crate::ProviderError;
use crate::connection::native17_borrowed_bytes::*;
use crate::protocol_snapshot::owned11::typed::invalid;

/// Keeps concrete Query/Prepare and publication commitments needed by lineage.
#[derive(Clone, Copy)]
pub(crate) struct BorrowedSpentFresh17<'a> {
    pub(crate) input: &'a [u8],
    pub(crate) query: &'a [u8],
    pub(crate) prepare_input: &'a [u8],
    pub(crate) commitments: [[u8; 32]; 5],
    pub(crate) allocation: &'a [u8],
    pub(crate) completed_response: [u8; 32],
    pub(crate) completed_record: usize,
    pub(crate) source_digest: [u8; 32],
    pub(crate) launch_digest: [u8; 32],
    pub(crate) prepare_started: bool,
}

pub(crate) fn spent_fresh<'a>(
    input: &'a [u8],
    records: &'a [u8],
    complete: &[u8],
    prepare_original: &[u8],
    frames: Frames17<'a>,
) -> Result<BorrowedSpentFresh17<'a>, ProviderError> {
    let startup = field(input, "startup")?;
    let prepare = field(input, "prepare")?;
    if field(startup, "purpose")? != b"\"fresh_completed_admit13\""
        || field(input, "creator")? != field(complete, "creator")?
        || field(startup, "source_digest")? != field(prepare, "source_digest")?
    {
        return Err(invalid());
    }
    let query_input = field(input, "input")?;
    let query_frame = field(query_input, "frame")?;
    let query = item(query_frame, 0)?;
    frames.authenticate_incoming(query)?;
    if field(query, "message")? != b"\"request\"" || field(query, "method")? != b"\"observe\"" {
        return Err(invalid());
    }
    let mut commitments = [[0; 32]; 5];
    let raw_commitments = field(query_input, "commitments")?;
    if count(raw_commitments)? != commitments.len() {
        return Err(invalid());
    }
    for (index, value) in commitments.iter_mut().enumerate() {
        *value = digest(item(raw_commitments, index)?)?;
    }
    if canonical_domain_digest(query, "source-owned.packet-fresh-restore-query-original/13")?
        != commitments[2]
    {
        return Err(invalid());
    }
    let prepare_input = field(input, "prepare_input")?;
    let prepare_envelope = item(prepare_input, 0)?;
    if prepare_envelope != prepare_original {
        return Err(invalid());
    }
    let publication = field(input, "publication")?;
    for name in ["schema", "data", "proof"] {
        if field(publication, name)? != b"null" {
            return Err(invalid());
        }
    }
    for name in [
        "report",
        "reference",
        "result",
        "receipt",
        "reply",
        "completed_response",
        "completed_record",
    ] {
        if field(publication, name)? == b"null" {
            return Err(invalid());
        }
    }
    let (raw, capacity) = Bytes17::bank(field(publication, "raw")?, false)?;
    let allocation = field(publication, "reference")?;
    if raw.len() == 0 || capacity != crate::reference_packet::service::report_startup::PACKET_NATIVE_REPORT_STARTUP_RAW_CAPACITY
        || field(field(publication, "receipt")?, "allocation")? != allocation
    { return Err(invalid()); }
    authenticate_content(allocation, raw)?;
    raw.canonical(field(publication, "report")?)?;
    let completed_response = digest(field(publication, "completed_response")?)?;
    let completed_record = quantity(field(publication, "completed_record")?)?;
    let record = BorrowedExchange17::read(item(records, completed_record)?, frames)?;
    let terminal = record.terminal()?;
    matches_response(query, terminal)?;
    if canonical_domain_digest(
        terminal,
        "source-owned.packet-fresh-restore-query-response/13",
    )? != completed_response
    {
        return Err(invalid());
    }
    let previous = record.require_completed_proof()?;
    if quoted(field(previous, "sequence")?)?.checked_add(1)
        != Some(quoted(field(prepare_envelope, "sequence")?)?)
    {
        return Err(invalid());
    }
    let binding = field(field(prepare_envelope, "extensions")?, crate::reference_packet::service::fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)?;
    if field(binding, "schema")?
        != b"\"source-owned.packet-fresh-restore-allocation-prepare-binding/13\""
        || base64_digest(field(binding, "assigned_query")?)? != commitments[2]
        || base64_digest(field(binding, "completed_query_response")?)? != completed_response
        || field(binding, "allocation")? != allocation
    {
        return Err(invalid());
    }
    Ok(BorrowedSpentFresh17 {
        input,
        query,
        prepare_input,
        commitments,
        allocation,
        completed_response,
        completed_record,
        source_digest: digest(field(prepare, "source_digest")?)?,
        launch_digest: digest(field(prepare, "launch_digest")?)?,
        prepare_started: boolean(field(prepare, "started")?)?,
    })
}
