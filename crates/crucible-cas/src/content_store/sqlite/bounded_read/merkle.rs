//! Fresh, bounded Merkle-node bodies without deferred source allocations.
//!
//! Native metadata admits the body before its buffer is reserved. Its BLOB,
//! cursor and statement close before a fresh current-row EOF projection. Only
//! that projection followed by complete digest authentication can expose bytes.

use super::*;
use crate::content_store::{MAX_MERKLE_NODE_ENVELOPE_BYTES, OwnedBlobBytes};
use crate::owned_decode::DecodeScratch;

impl SqliteBlobBackend {
    pub(in crate::content_store::sqlite) fn consume_merkle_record(
        &self,
        original: &DecodeBudget,
        id: ContentId,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<OwnedBlobBytes, StoreError> {
        if id.kind() != ObjectKind::MerkleNode {
            return Err(StoreError::Corrupt { id });
        }
        super::super::super::checked_reader::check(original, boundary)?;
        let diagnostic = diagnostic::admit_for_merkle_record(original, &self.connection)?;
        diagnostic::retain_failure(diagnostic, || {
            let mut check = || {
                super::super::super::checked_reader::check(original, boundary)?;
                busy::healthy(&self.quarantined)
            };
            let staging = catalog::read_gate_with_boundary(&mut check)?;
            let mut connection = loop {
                check()?;
                match self
                    .read_connection
                    .try_lock_for("lock-merkle-sqlite-record")?
                {
                    Some(connection) => break connection,
                    None => std::thread::yield_now(),
                }
            };
            let mut output_credit: Option<DecodeScratch> = None;
            let bytes = busy::single_record::consume_merkle(
                original,
                &connection,
                &self.quarantined,
                &mut check,
                id,
                |length| {
                    if length > MAX_MERKLE_NODE_ENVELOPE_BYTES as u64 {
                        return Err(StoreError::Quota);
                    }
                    let capacity = usize::try_from(length).map_err(|_| StoreError::Quota)?;
                    let extent = length
                        .checked_add(std::mem::size_of::<OwnedBlobBytes>() as u64)
                        .ok_or(StoreError::Quota)?;
                    let credit = original.reserve_scratch_bytes(extent).map_err(|error| {
                        crate::content_store::batch::admission_under(original, error)
                    })?;
                    let mut bytes = Vec::new();
                    bytes.try_reserve_exact(capacity).map_err(|error| {
                        crate::content_store::batch::allocation_under(original, error)
                    })?;
                    output_credit = Some(credit);
                    Ok(bytes)
                },
            )?
            .finish(|bytes| bytes.ok_or(StoreError::NotFound { id }))?;

            // No metadata snapshot remains active here. A separate exact row
            // projection observes growth, deletion and type changes after body
            // consumption, including an originally empty object.
            let length = bytes.len() as u64;
            let accepted = busy::with_zero(
                original,
                &mut connection,
                &self.quarantined,
                &mut check,
                |connection, _, check| {
                    batch::reader::current_chunk(
                        connection,
                        &self.quarantined,
                        check,
                        id,
                        1,
                        0,
                        length,
                    )
                },
            )?;
            accepted.finish(|eof| {
                check()?;
                if eof.as_ref().is_none_or(|bytes| !bytes.is_empty()) {
                    return Err(StoreError::Corrupt { id });
                }
                Ok(())
            })?;
            if !id.authenticates(&bytes) {
                return Err(StoreError::Corrupt { id });
            }
            drop(connection);
            drop(staging);
            check()?;
            let credit = output_credit.ok_or(StoreError::InvalidComposition {
                reason: "Merkle body has no original output credit",
            })?;
            Ok(OwnedBlobBytes::prepared(bytes, credit))
        })
    }
}
