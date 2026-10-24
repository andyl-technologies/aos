//! Prices and retains the seven exact reference and byte-bank allocations.
//!
//! The enclosing native Prepare must authenticate and admit this DATA demand
//! under its original escrow before reservation. This module supplies no token,
//! phase issuer or conversion from an announced row into memory authority.

use super::*;

/// Quotes exact future seven-reference copies and input byte-bank reservations.
///
/// Inputs follow `PacketNativeImport18InputRole::ALL` in its exact receive order.
/// The shared native constructor uses this same formula. Lengths derive actual
/// allocations; supplied maxima only restrict them. Borrowed input spare
/// capacity is independently retained and never copied into the new banks.
///
/// Admit the fixed counter before this nonallocating DATA walk. Existing empty
/// headers, original owners, signed Prepare validation, token/escrow custody,
/// frame decoding and whole-phase construction remain separately funded. This
/// function creates no bank, Prepare token, opaque Recipe, Initial or grant.
///
/// # Errors
/// Refuses malformed references, empty or over-bound bodies, checked overflow
/// or a complete returned row above the independent supplied restriction.
pub fn native_import18_receiving_bank_backing_construction_data(
    references: [&ContentRef; 7],
    maximums: [usize; 7],
    maximum: usize,
) -> Result<[usize; 3], ProviderError> {
    let mut retained = 0usize;
    for (reference, ceiling) in references.into_iter().zip(maximums) {
        validate_reference(reference)?;
        let length = usize::try_from(reference.length.get()).map_err(|_| exhausted())?;
        if length == 0 || length > ceiling {
            return Err(exhausted());
        }
        retained = retained.checked_add(length).ok_or_else(exhausted)?;
        for string in reference_strings(reference) {
            retained = retained.checked_add(string.len()).ok_or_else(exhausted)?;
        }
    }

    let transient = size_of::<ContentRef>()
        + size_of::<Option<ContentRef>>()
        + size_of::<HashRef>()
        + size_of::<[String; 4]>();
    // Later reservation/upload work has its own controls. The initial
    // bootstrap charges only empty headers and the actual retained census.
    let scratch = native_import18_receiving_bank_backing_counter_scratch_data();
    if retained
        .checked_add(transient)
        .and_then(|sum| sum.checked_add(scratch))
        .is_none_or(|sum| sum > maximum)
    {
        return Err(exhausted());
    }
    Ok([retained, transient, scratch])
}

/// Names actual quote, reference-copy, bank-reservation and transfer controls.
///
/// The extra forwarding views remain charged on the native primitive path;
/// public DATA callers receive the identical conservative construction row.
pub fn native_import18_receiving_bank_backing_counter_scratch_data() -> usize {
    OriginalImport18ReceivingBanks::counter_scratch_data()
        + counter_scratch_data()
        + transfer::counter_scratch_data()
        + size_of::<[&ContentRef; 7]>()
        + size_of::<[usize; 7]>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<usize>()
}

impl OriginalImport18ReceivingBanks {
    /// Prices additional backing before any reference copy or bank reservation.
    ///
    /// Existing bank headers remain charged by their enclosing original owner.
    /// The independent restriction is not an escrow or a grant.
    ///
    /// # Errors
    /// Refuses invalid references, role extents, overflow or excessive demand.
    pub(in super::super) fn backing_construction_data(
        references: [&ContentRef; 7],
        maximums: [usize; 7],
        maximum: usize,
    ) -> Result<[usize; 3], ProviderError> {
        native_import18_receiving_bank_backing_construction_data(references, maximums, maximum)
    }

    /// Reserves the already-admitted exact seven-reference DATA population.
    ///
    /// The genuine Prepare caller separately authenticates its current token,
    /// borrows these exact references and admits the independent row before
    /// entry. This primitive cannot create or authenticate that token. It spends
    /// reservation before validation and retains every partial output on error.
    ///
    /// # Errors
    /// Refuses re-entry, invalid extents, insufficient independent restriction,
    /// reservation failure or allocator capacity beyond the admitted request.
    pub(in super::super) fn reserve_data(
        &mut self,
        references: [&ContentRef; 7],
        maximums: [usize; 7],
        maximum: usize,
    ) -> Result<(), ProviderError> {
        if self.phase != ReceivePhase::Empty {
            return Err(unavailable());
        }
        self.phase = ReceivePhase::Reserving;
        let result = self.reserve_current(references, maximums, maximum);
        self.phase = if result.is_ok() {
            ReceivePhase::Receiving
        } else {
            ReceivePhase::Failed
        };
        result
    }

    fn reserve_current(
        &mut self,
        references: [&ContentRef; 7],
        maximums: [usize; 7],
        maximum: usize,
    ) -> Result<(), ProviderError> {
        Self::backing_construction_data(references, maximums, maximum)?;
        for (bank, reference) in self.banks.iter_mut().zip(references) {
            // Install the full empty reference before the first String reserve.
            // A later allocation failure leaves all earlier leaves counted.
            bank.reference = Some(ContentRef {
                hash: HashRef {
                    algorithm: String::new(),
                    domain: String::new(),
                    digest: String::new(),
                },
                length: reference.length,
                media_type: String::new(),
            });
            let retained = bank.reference.as_mut().ok_or_else(unavailable)?;
            let ContentRef {
                hash:
                    HashRef {
                        algorithm,
                        domain,
                        digest,
                    },
                length: _,
                media_type,
            } = retained;
            let targets = [algorithm, domain, digest, media_type];
            for (target, source) in targets.into_iter().zip(reference_strings(reference)) {
                target
                    .try_reserve_exact(source.len())
                    .map_err(|_| exhausted())?;
                if target.capacity() != source.len() {
                    return Err(exhausted());
                }
                target.push_str(source);
            }

            let length = usize::try_from(reference.length.get()).map_err(|_| exhausted())?;
            bank.bytes
                .try_reserve_exact(length)
                .map_err(|_| exhausted())?;
            if bank.bytes.capacity() != length {
                return Err(exhausted());
            }
        }
        Ok(())
    }
}

/// Borrows every owned String leaf through the exhaustive full-reference roster.
pub(super) fn reference_strings(reference: &ContentRef) -> [&String; 4] {
    let ContentRef {
        hash: HashRef {
            algorithm,
            domain,
            digest,
        },
        length: _,
        media_type,
    } = reference;
    [algorithm, domain, digest, media_type]
}

fn validate_reference(reference: &ContentRef) -> Result<(), ProviderError> {
    // Keep this nonallocating closed check ahead of all allocation. The generic
    // schema validator constructs an owned diagnostic on malformed input.
    if reference.hash.algorithm != "blake3-256"
        || reference.hash.domain != "cnp.blob.v1"
        || reference.hash.digest.len() != 64
        || !reference
            .hash
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || reference.media_type.is_empty()
        || reference.media_type.len() > 128
        || !reference
            .media_type
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte))
    {
        return Err(unavailable());
    }
    Ok(())
}

/// Names actual quote, partial-reference copy and exact-reservation controls.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<[&ContentRef; 7]>() * 3
        + size_of::<[usize; 7]>() * 3
        + size_of::<[usize; 3]>()
        + size_of::<Result<[usize; 3], ProviderError>>()
        + size_of::<
            std::iter::Zip<std::array::IntoIter<&ContentRef, 7>, std::array::IntoIter<usize, 7>>,
        >()
        + size_of::<
            std::iter::Zip<
                std::slice::IterMut<'static, InputBank>,
                std::array::IntoIter<&ContentRef, 7>,
            >,
        >()
        + size_of::<
            std::iter::Zip<std::array::IntoIter<&mut String, 4>, std::array::IntoIter<&String, 4>>,
        >()
        + size_of::<[&String; 4]>() * 2
        + size_of::<[&mut String; 4]>()
        + size_of::<std::array::IntoIter<&String, 4>>()
        + size_of::<std::str::Bytes<'static>>() * 2
        + size_of::<std::ops::RangeInclusive<u8>>() * 2
        + size_of::<&mut ContentRef>()
        + size_of::<&mut OriginalImport18ReceivingBanks>() * 2
        + size_of::<&mut Vec<u8>>()
        + size_of::<&ContentRef>()
        + size_of::<&mut InputBank>()
        + size_of::<&mut String>() * 4
        + size_of::<&String>() * 4
        + size_of::<&str>() * 2
        + size_of::<Option<u8>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
        + size_of::<Result<(), std::collections::TryReserveError>>()
        + size_of::<Result<(), ProviderError>>() * 3
        + size_of::<ReceivePhase>() * 2
        + size_of::<usize>() * 5
        + size_of::<bool>() * 2
}
