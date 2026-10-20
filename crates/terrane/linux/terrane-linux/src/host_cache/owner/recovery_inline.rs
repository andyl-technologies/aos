//! Reconciles only canonical sealed inline chunks under real publisher custody.
//!
//! Candidate names supply no authority. Adoption independently verifies actual
//! plaintext and kernel sealing; the physical executor retains every receipt
//! before further fallible work. Mixed recovery selects inline candidates only
//! after classifying the complete inventory; manifest adoption remains separate.
//! No cold policy record is discarded.

use crate::{
    host_cache::{
        NativeHostLayout, NativeRecoveryCandidate, NativeRecoveryInspection, RecoveryIssue,
    },
    publisher_local::{client::PeerPublishedObject, wire::BodyKind},
};
use std::{io, sync::Arc};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_sdk::host::{
    cache::{HostDomainLocation, ResidenceRecord},
    publication::{PublicationClaim, PublicationRecipe},
};

/// Retains adopted immutable bodies independently of embedded state and waiters.
pub(super) type AdoptedInline = Arc<PeerPublishedObject<HostDomainLocation>>;

/// Classifies the entire bounded inventory before any inline adoption effect.
///
/// # Errors
/// Refuses all failures, pending observations, nonsealed/nonchunk descriptors
/// and issue categories other than the intentionally unresolved sealed witness.
pub(super) fn claims(
    inventory: &NativeRecoveryInspection,
    layout: &Arc<NativeHostLayout<HostDomainLocation>>,
) -> io::Result<Vec<PublicationClaim>> {
    if inventory.inventory_failure().is_some() || inventory.namespace_failure().is_some() {
        return Err(unresolved("inventory failed before inline reconciliation"));
    }
    let mut claims = Vec::with_capacity(inventory.candidates().len());
    for candidate in inventory.candidates() {
        claims.push(claim(candidate, layout)?);
    }
    Ok(claims)
}

/// Selects inline claims after validating every mixed-inventory candidate.
///
/// # Errors
/// Refuses global failures, unsupported candidates and invalid inline claims.
pub(super) fn selected_claims(
    inventory: &NativeRecoveryInspection,
    layout: &Arc<NativeHostLayout<HostDomainLocation>>,
) -> io::Result<Vec<PublicationClaim>> {
    super::recovery_candidates::preflight(inventory)?;
    let mut claims = Vec::new();
    for candidate in inventory.candidates() {
        if matches!(
            super::recovery_candidates::classify(candidate)?,
            super::recovery_candidates::RecoveryCase::Inline
        ) {
            claims.push(claim(candidate, layout)?);
        }
    }
    Ok(claims)
}

fn claim(
    candidate: &NativeRecoveryCandidate,
    layout: &Arc<NativeHostLayout<HostDomainLocation>>,
) -> io::Result<PublicationClaim> {
    if candidate.key().kind != BodyKind::Sealed as i32
        || candidate.pending_observation().is_some()
        || !matches!(candidate.issues(), [RecoveryIssue::SealedWitnessRequired])
    {
        return Err(unresolved("unsupported recovery candidate or pending body"));
    }
    let descriptor =
        Descriptor::decode(&TERRANE_V1, &candidate.key().descriptor).map_err(io::Error::other)?;
    if descriptor.domain()
        != TERRANE_V1
            .domain(IdentityKind::Chunk)
            .map_err(io::Error::other)?
    {
        return Err(unresolved("manifest-backed sealed recovery is unsupported"));
    }
    let location = layout.layout();
    PublicationClaim::new(
        location.domain().to_owned(),
        PublicationRecipe::Inline { chunk: descriptor },
        location.chunk_profile(),
    )
    .map_err(io::Error::other)
}

/// Derives exact reconstructible ranges without assigning consumer pin promises.
pub(super) fn residences(claims: &[PublicationClaim]) -> Vec<ResidenceRecord> {
    claims
        .iter()
        .map(|claim| {
            let digest: String = claim
                .descriptor()
                .digest()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            ResidenceRecord {
                chunk: digest.clone(),
                object: digest,
                offset: 0,
                length: claim.plaintext_size(),
            }
        })
        .collect()
}

/// Checks final inventory against the exact independently adopted handles.
///
/// # Errors
/// Refuses changed candidate sets, root custody or immutable handle size/type.
/// This rechecks no embedded state and performs no serving read callbacks.
pub(super) fn check(
    inventory: &NativeRecoveryInspection,
    layout: &Arc<NativeHostLayout<HostDomainLocation>>,
    adopted: &[AdoptedInline],
) -> io::Result<()> {
    let claims = claims(inventory, layout)?;
    check_claims(&claims, layout, adopted)
}

/// Checks the exact adopted inline subset without ignoring other candidate issues.
///
/// # Errors
/// Refuses invalid mixed inventory, changed inline sets or native custody.
pub(super) fn check_subset(
    inventory: &NativeRecoveryInspection,
    layout: &Arc<NativeHostLayout<HostDomainLocation>>,
    adopted: &[AdoptedInline],
) -> io::Result<()> {
    let claims = selected_claims(inventory, layout)?;
    check_claims(&claims, layout, adopted)
}

fn check_claims(
    claims: &[PublicationClaim],
    layout: &Arc<NativeHostLayout<HostDomainLocation>>,
    adopted: &[AdoptedInline],
) -> io::Result<()> {
    if claims.len() != adopted.len() {
        return Err(unresolved("inline candidate set changed during recovery"));
    }
    for (claim, body) in claims.iter().zip(adopted) {
        if claim.descriptor() != body.claim().descriptor()
            || claim.domain() != body.claim().domain()
            || !std::ptr::eq(layout.as_ref(), body.layout().as_ref())
        {
            return Err(unresolved("inline backing differs from final candidate"));
        }
        body.layout().recheck()?;
        let metadata = body.handle().metadata()?;
        if !metadata.is_file() || metadata.len() != claim.plaintext_size() {
            return Err(unresolved("adopted inline backing changed"));
        }
    }
    Ok(())
}

fn unresolved(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, message)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use terrane_format::chunking::ChunkProfile;

    #[test]
    fn inline_reconstruction_keeps_each_exact_whole_chunk_range() {
        // Canonical claims exercise derived policy only; this creates no
        // native root, adopted handle, durable pin or completion authority.
        let claims: Vec<_> = [b"a".as_slice(), b"different".as_slice()]
            .into_iter()
            .map(|bytes| {
                let identity = TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap();
                let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, bytes).unwrap();
                PublicationClaim::new(
                    "public".into(),
                    PublicationRecipe::Inline { chunk: descriptor },
                    &ChunkProfile::cdc_1m([0; 32]),
                )
                .unwrap()
            })
            .collect();
        let ranges = residences(&claims);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].length, 1);
        assert_eq!(ranges[1].length, 9);
        for range in &ranges {
            assert_eq!(range.chunk, range.object);
            assert_eq!(range.offset, 0);
            assert_eq!(range.chunk.len(), 64);
        }
        assert_ne!(ranges[0].object, ranges[1].object);
        assert!(residences(&[]).is_empty());
    }
}
