//! Checks the independently signed native17 roles and immutable ancestor DAG.
//!
//! These borrowed readers own no live registrar, model, Capture claim or native
//! credit. The complete selected reader must conjoin current Control, Endpoint,
//! Connection and service semantics before returning a validated native owner.
//! Old native11/15/16 readers and their accepted vocabulary remain independent.

use crate::ProviderError;
use crucible_node_contract::ContentRef;

/// Borrows the five independently signed bodies of a native17 archive member.
///
/// Each pair comes from retained verified archive content. Snapshot and journal
/// bind the same separately supplied Control, protocol and anchor references.
/// Nothing in this DATA loan authenticates the enclosing archive signature.
pub struct RestoredSettledNative17Input<'a> {
    /// Borrows the current native continuation snapshot and exact fullref.
    pub snapshot: (&'a ContentRef, &'a [u8]),
    /// Borrows the full current Connection/service/Endpoint protocol graph.
    pub current_protocol: (&'a ContentRef, &'a [u8]),
    /// Borrows the separate complete current Control17/model object.
    pub control: (&'a ContentRef, &'a [u8]),
    /// Borrows the current native observation anchor.
    pub anchor: (&'a ContentRef, &'a [u8]),
    /// Borrows the signed Source member journal binding all four other roles.
    pub journal: (&'a ContentRef, &'a [u8]),
}

impl<'a> RestoredSettledNative17Input<'a> {
    /// Checks all original fullrefs and independent finite raw-input ceilings.
    ///
    /// This validates byte ownership only. It is deliberately not a constructor
    /// for the complete semantic native17 validator or any live state.
    ///
    /// # Errors
    /// Refuses a malformed reference, non-JSON role, wrong body/hash/length,
    /// independent role excess, or checked aggregate input excess.
    pub fn authenticate_role_bytes_data(
        &self,
        limits: &RestoredSettledNative17Limits,
    ) -> Result<(), ProviderError> {
        let mut total = 0usize;
        for ((reference, body), maximum) in self.roles_data().into_iter().zip(limits.input_roles) {
            if body.is_empty() || body.len() > maximum {
                return Err(invalid());
            }
            verify_role_body_data(reference, body)?;
            total = total.checked_add(body.len()).ok_or_else(invalid)?;
            if total > limits.maximum_requested_bytes {
                return Err(invalid());
            }
        }
        Ok(())
    }

    /// Returns role order for exact cache, geometry and fullref correspondence.
    pub const fn roles_data(&self) -> [(&'a ContentRef, &'a [u8]); 5] {
        [
            self.snapshot,
            self.current_protocol,
            self.control,
            self.anchor,
            self.journal,
        ]
    }
}

/// Retains independent admitted input, immutable-DAG and work ceilings as DATA.
///
/// The caller derives these from its actual signed archive and preadmitted row.
/// Values cannot supply native credit or expand the existing launch ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoredSettledNative17Limits {
    input_roles: [usize; 5],
    immutable_bytes: usize,
    immutable_objects: usize,
    immutable_depth: usize,
    nodes: usize,
    maximum_requested_bytes: usize,
}

impl RestoredSettledNative17Limits {
    /// Checks finite separately funded role, DAG and parser-work bounds.
    ///
    /// `input_roles` follows [`RestoredSettledNative17Input::roles_data`]. The
    /// requested ceiling is a bound to compare, not an allocation or grant.
    ///
    /// # Errors
    /// Refuses zero bounds, arithmetic overflow, role/immutable byte credit
    /// beyond the explicit requested ceiling, or unsupported parser/DAG depth.
    pub fn new(
        input_roles: [usize; 5],
        immutable_bytes: usize,
        immutable_objects: usize,
        immutable_depth: usize,
        nodes: usize,
        maximum_requested_bytes: usize,
    ) -> Result<Self, ProviderError> {
        let input = input_roles
            .iter()
            .try_fold(0usize, |sum, next| sum.checked_add(*next))
            .ok_or_else(invalid)?;
        if input_roles.contains(&0)
            || immutable_bytes == 0
            || immutable_objects == 0
            || immutable_depth == 0
            || immutable_depth > 64
            || nodes == 0
            || input > maximum_requested_bytes
            || immutable_bytes > maximum_requested_bytes
        {
            return Err(invalid());
        }
        Ok(Self {
            input_roles,
            immutable_bytes,
            immutable_objects,
            immutable_depth,
            nodes,
            maximum_requested_bytes,
        })
    }

    /// Returns the exact five independent signed-role ceilings.
    pub const fn input_role_limits_data(&self) -> [usize; 5] {
        self.input_roles
    }

    /// Returns the distinct immutable objects and aggregate verified-byte bound.
    pub const fn immutable_limits_data(&self) -> (usize, usize, usize) {
        (
            self.immutable_objects,
            self.immutable_bytes,
            self.immutable_depth,
        )
    }

    /// Returns the finite parser-node ceiling admitted by the same owner.
    pub const fn maximum_nodes_data(&self) -> usize {
        self.nodes
    }
}

/// Lends an immutable fullref/body pair from actual retained verified content.
///
/// The input is the complete canonical JSON ContentRef object from the native
/// DAG. The implementation must search only its separately bounded retained
/// archive content. Returned references are checked again by the native reader;
/// neither this lookup nor a successful hash establishes signed provenance.
pub trait RestoredSettledNative17Content {
    /// Lends an existing object without loading mutable paths or creating it.
    ///
    /// # Errors
    /// Refuses invalid reference syntax or exhaustion of the implementation's
    /// independently admitted lookup work. Missing content returns `None`.
    fn immutable_content_data(
        &self,
        canonical_reference: &[u8],
    ) -> Result<Option<(&ContentRef, &[u8])>, ProviderError>;
}

/// Compares one canonical borrowed fullref without allocating a replacement.
///
/// The comparison includes hash algorithm/domain/digest, length and media type.
/// It deliberately performs no content lookup and grants no archive identity.
///
/// # Errors
/// Refuses malformed, reordered, missing, additional or changed fullref fields.
pub fn restored_settled_native17_reference_matches_data(
    reference: &ContentRef,
    canonical_reference: &[u8],
) -> Result<(), ProviderError> {
    super::owned11::correspondence::content_reference(reference, canonical_reference)
}

/// Retains one caller-preallocated immutable graph visitation slot.
///
/// Only the borrowed validator writes its private reference and active state.
/// The role records neither a current owner identity nor reconstructed rights.
#[derive(Default)]
pub struct RestoredSettledNative17ObjectVisit<'a> {
    reference: Option<&'a ContentRef>,
    active: bool,
}

/// Borrows the actual fixed visitation bank before any native17 traversal.
pub struct RestoredSettledNative17ValidationScratch<'bank, 'data> {
    objects: &'bank mut [RestoredSettledNative17ObjectVisit<'data>],
    used: usize,
    bytes: usize,
}

impl<'bank, 'data> RestoredSettledNative17ValidationScratch<'bank, 'data> {
    /// Borrows an empty preallocated visitation bank without growing it.
    ///
    /// # Errors
    /// Refuses an empty bank or leftover in-progress/populated slots. A failed
    /// validation never silently resets the same borrowed attempt's history.
    pub fn new(
        objects: &'bank mut [RestoredSettledNative17ObjectVisit<'data>],
    ) -> Result<Self, ProviderError> {
        if objects.is_empty()
            || objects
                .iter()
                .any(|slot| slot.reference.is_some() || slot.active)
        {
            return Err(invalid());
        }
        Ok(Self {
            objects,
            used: 0,
            bytes: 0,
        })
    }

    /// Reports visited object count and aggregate distinct verified byte extent.
    pub const fn observed_immutable_extent_data(&self) -> (usize, usize) {
        (self.used, self.bytes)
    }

    fn begin(
        &mut self,
        reference: &'data ContentRef,
        body: &[u8],
        depth: usize,
        limits: &RestoredSettledNative17Limits,
    ) -> Result<(usize, bool), ProviderError> {
        if depth >= limits.immutable_depth {
            return Err(invalid());
        }
        for (index, slot) in self.objects[..self.used].iter().enumerate() {
            if slot.reference == Some(reference) {
                if slot.active {
                    return Err(invalid());
                }
                return Ok((index, false));
            }
        }
        if self.used >= limits.immutable_objects {
            return Err(invalid());
        }
        let next_bytes = self.bytes.checked_add(body.len()).ok_or_else(invalid)?;
        if next_bytes > limits.immutable_bytes {
            return Err(invalid());
        }
        let index = self.used;
        let slot = self.objects.get_mut(index).ok_or_else(invalid)?;
        slot.reference = Some(reference);
        slot.active = true;
        self.used += 1;
        self.bytes = next_bytes;
        Ok((index, true))
    }

    fn complete(&mut self, index: usize) -> Result<(), ProviderError> {
        let slot = self.objects.get_mut(index).ok_or_else(invalid)?;
        if slot.reference.is_none() || !slot.active {
            return Err(invalid());
        }
        slot.active = false;
        Ok(())
    }
}

fn invalid() -> ProviderError {
    ProviderError::Correlation("restored settled native17 input or immutable graph differs")
}

// Same normative CNP/1 content hash as ContentRef::verify, compared against its
// borrowed hexadecimal string. Pure preadmission geometry must not allocate a
// temporary HashRef's three Strings merely to authenticate an existing body.
fn verify_role_body_data(reference: &ContentRef, body: &[u8]) -> Result<(), ProviderError> {
    if reference.media_type != "application/json"
        || reference.hash.algorithm != "blake3-256"
        || reference.hash.domain != "cnp.blob.v1"
        || reference.hash.digest.len() != 64
        || u64::try_from(body.len()).map_err(|_| invalid())? != reference.length.get()
    {
        return Err(invalid());
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&11u32.to_be_bytes());
    hash.update(b"cnp.blob.v1");
    hash.update(&reference.length.get().to_be_bytes());
    hash.update(body);
    if hash.finalize().to_hex().as_str() != reference.hash.digest {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_node_contract::canonical;

    #[test]
    fn changed_signed_role_and_independent_short_role_refuse() {
        let body = br#"{"native":"actual-content-bound-state"}"#;
        let reference = canonical::content_ref(body, "application/json").unwrap();
        let input = RestoredSettledNative17Input {
            snapshot: (&reference, body),
            current_protocol: (&reference, body),
            control: (&reference, body),
            anchor: (&reference, body),
            journal: (&reference, body),
        };
        let maximum = body.len() * 6;
        let limits =
            RestoredSettledNative17Limits::new([body.len(); 5], body.len(), 1, 1, 64, maximum)
                .unwrap();
        input.authenticate_role_bytes_data(&limits).unwrap();

        let changed = RestoredSettledNative17Input {
            anchor: (&reference, b"{}"),
            ..input
        };
        assert!(changed.authenticate_role_bytes_data(&limits).is_err());
        for role in 0..5 {
            let mut independent = [body.len(); 5];
            independent[role] -= 1;
            let limits =
                RestoredSettledNative17Limits::new(independent, body.len(), 1, 1, 64, maximum)
                    .unwrap();
            assert!(input.authenticate_role_bytes_data(&limits).is_err());
        }
    }

    #[test]
    fn immutable_cycle_and_one_short_bank_fail_without_reset_or_growth() {
        let first = canonical::content_ref(b"{}", "application/json").unwrap();
        let second = canonical::content_ref(b"[]", "application/json").unwrap();
        let limits = RestoredSettledNative17Limits::new([2; 5], 4, 2, 2, 64, 16).unwrap();
        let mut objects = [RestoredSettledNative17ObjectVisit::default()];
        let mut scratch = RestoredSettledNative17ValidationScratch::new(&mut objects).unwrap();
        let (slot, fresh) = scratch.begin(&first, b"{}", 0, &limits).unwrap();
        assert!(fresh);
        assert!(scratch.begin(&first, b"{}", 1, &limits).is_err());
        assert!(scratch.begin(&second, b"[]", 1, &limits).is_err());
        assert_eq!(scratch.observed_immutable_extent_data(), (1, 2));
        scratch.complete(slot).unwrap();
        assert_eq!(
            scratch.begin(&first, b"{}", 0, &limits).unwrap(),
            (slot, false)
        );
        drop(scratch);

        // Re-borrowing cannot erase a failed traversal's installed reference.
        assert!(RestoredSettledNative17ValidationScratch::new(&mut objects).is_err());
    }
}

mod import_geometry;
pub use import_geometry::{
    RestoredSettledNative17AllocationDemand, RestoredSettledNativeImportClass,
    RestoredSettledNativeImportGeometryData,
};

mod connection_children;

mod capture_outputs;
mod sealed;
pub use capture_outputs::{
    RestoredSettledNative17CaptureOutputPlan, ValidatedRestoredSettledNative17CaptureOutputs,
};
pub use sealed::{
    RestoredSettledHistoryVerifierData, RestoredSettledNative17DecodeAttempt,
    SealedHistoricalRestoredSettledNative17,
    restored_settled_native17_decode_construction_transient_bytes_data,
};

pub mod aliases;

/// Names the actual native17 input, partial-owner and strict borrowed view layouts.
///
/// Raw, typed, Value, immutable closure, alias-bank and tree allocations remain
/// independent dynamic terms. This getter supplies neither those allocations
/// nor any validation, fit, native reservation or accepted historical owner.
pub fn restored_settled_native17_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<RestoredSettledNative17Input<'static>>()
        + size_of::<RestoredSettledNative17Limits>()
        + size_of::<RestoredSettledNative17ObjectVisit<'static>>()
        + size_of::<RestoredSettledNative17ValidationScratch<'static, 'static>>()
        + size_of::<[(&'static ContentRef, &'static [u8]); 5]>()
        + size_of::<std::array::IntoIter<(&'static ContentRef, &'static [u8]), 5>>()
        + size_of::<[usize; 5]>() + size_of::<std::array::IntoIter<usize, 5>>()
        + size_of::<std::iter::Zip<
            std::array::IntoIter<(&'static ContentRef, &'static [u8]), 5>,
            std::array::IntoIter<usize, 5>,
        >>()
        + size_of::<Option<((&'static ContentRef, &'static [u8]), usize)>>()
        + size_of::<Result<(usize, bool), ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<blake3::Hasher>() + size_of::<blake3::Hash>()
        + sealed::counter_scratch_data() + capture_outputs::counter_scratch_data()
        + cold::counter_scratch_data()
        + crate::protocol_snapshot::native_wholegraph17::native_current_graph17_counter_scratch_data()
        + output_pair::counter_scratch_data()
        + RestoredSettledNativeImportGeometryData::counter_scratch_data()
        + aliases::restored_settled_native17_alias_counter_scratch_data()
        + historical_auth::historical_auth17_counter_scratch_data()
        + current_boot::current_boot17_counter_scratch_data()
        + crate::reference_packet::continuation_models::settled_reader::settled_model17_counter_scratch_data()
}

pub(crate) mod historical_auth;
pub use historical_auth::{HistoricalCompletedPair17, HistoricalRestoredObservation17Data};
pub use historical_auth::construction::{
    RestoredSettledSourceHistory17AuthGeometryData,
    source_history17_authentication_counter_scratch_data,
};

pub(crate) mod current_actions;

pub(crate) mod current_boot;

pub(crate) mod current_command;

pub(crate) mod current_commit;

pub(crate) mod current_contracts;

pub(crate) mod current_facts;

pub(crate) mod current_fixed;

pub(crate) mod current_inline;

pub(crate) mod current_launch;

pub(crate) mod current_ordinary;

pub(crate) mod current_pending;

pub(crate) mod current_prepare;

pub(crate) mod current_purpose;

pub(crate) mod current_quotes;

pub(crate) mod current_receipt;

pub(crate) mod current_reserve;

pub(crate) mod current_shared;

pub(crate) mod current_stages;

pub(crate) mod current_suffix;

pub(crate) mod current_import17;

mod cold;
pub use cold::RestoredSettledNative17Plan;

mod output_pair;
mod reader;

pub(crate) mod current_lineage17;

pub(crate) mod current_capture17_borrowed;

pub(crate) mod current_build17;

pub(crate) mod current_custody;
