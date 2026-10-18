//! Authenticated bounded content closure and closed-record reference enumeration.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Write};

use crucible_node_contract::{ContentRef, HashRef};
use serde::Serialize;

use super::{CaptureEvidence, StateError, StateErrorCode, StateLimits, schema};

#[path = "closure/retained.rs"]
pub(crate) mod retained;

#[path = "closure/settled_history.rs"]
mod settled_history;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ContentInventoryEdition {
    Legacy,
    Typed,
}

/// Retains verified immutable bytes without granting access to native resources.
///
/// Construction is private. Every object passed to a native verifier has already
/// satisfied exact content identity, length and aggregate allocation limits.
#[derive(Debug)]
pub struct VerifiedStateContent {
    objects: BTreeMap<HashRef, (ContentRef, Vec<u8>)>,
    total_bytes: usize,
    references: BTreeSet<ContentRef>,
    edition: ContentInventoryEdition,
}

impl VerifiedStateContent {
    /// Borrows bytes only when the complete reference metadata matches admission.
    pub fn get(&self, reference: &ContentRef) -> Option<&[u8]> {
        self.objects
            .get(&reference.hash)
            .filter(|(stored, _)| {
                stored == reference
                    || (self.edition == ContentInventoryEdition::Typed
                        && self.references.contains(reference))
            })
            .map(|(_, bytes)| bytes.as_slice())
    }

    /// Returns total distinct authenticated content bytes retained by this closure.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Returns the number of independently authenticated typed references.
    pub fn object_count(&self) -> usize {
        self.references.len()
    }

    pub(super) fn entries(&self) -> impl Iterator<Item = (&ContentRef, &[u8])> {
        self.references.iter().filter_map(|reference| {
            self.objects
                .get(&reference.hash)
                .map(|(_, bytes)| (reference, bytes.as_slice()))
        })
    }

    /// Adds original bounded runtime payload bytes without issuing lineage authority.
    pub(super) fn include_payload(
        &mut self,
        reference: &ContentRef,
        bytes: &[u8],
        limits: StateLimits,
    ) -> Result<(), StateError> {
        reference.verify(bytes).map_err(|error| {
            StateError::new(
                StateErrorCode::Content,
                reference.hash.digest.clone(),
                error.to_string(),
            )
        })?;
        if let Some((stored, original)) = self.objects.get(&reference.hash) {
            if (self.edition == ContentInventoryEdition::Legacy && stored != reference)
                || stored.length != reference.length
                || original.as_slice() != bytes
            {
                return Err(StateError::new(
                    StateErrorCode::Content,
                    reference.hash.digest.clone(),
                    "original payload reference conflicts with verified closure",
                ));
            }
            if !self.references.contains(reference)
                && self.references.len() >= limits.maximum_content_objects
            {
                return Err(limit("typed runtime payload inventory"));
            }
            self.references.insert(reference.clone());
            return Ok(());
        }

        let total = self
            .total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| limit("runtime payload byte count"))?;
        if bytes.len() > limits.maximum_content_bytes
            || total > limits.maximum_total_content_bytes
            || self.references.len() >= limits.maximum_content_objects
        {
            return Err(limit("runtime payload allocation"));
        }
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(bytes.len())
            .map_err(|_| limit("runtime payload allocation"))?;
        retained.extend_from_slice(bytes);
        self.objects
            .insert(reference.hash.clone(), (reference.clone(), retained));
        self.references.insert(reference.clone());
        self.total_bytes = total;
        Ok(())
    }
}

pub(super) fn verify_closure(
    roots: Vec<ContentRef>,
    evidence: &dyn CaptureEvidence,
    limits: StateLimits,
) -> Result<VerifiedStateContent, StateError> {
    verify_closure_with_edition(roots, evidence, limits, ContentInventoryEdition::Legacy)
}

pub(super) fn verify_closure_with_edition(
    roots: Vec<ContentRef>,
    evidence: &dyn CaptureEvidence,
    limits: StateLimits,
    edition: ContentInventoryEdition,
) -> Result<VerifiedStateContent, StateError> {
    verify_closure_admitted(roots, evidence, limits, edition, false)
}

/// Adds actual returned-bank admission for the complete index-three route.
/// Legacy and transcript closures retain their original logical-byte policy.
pub(super) fn verify_complete_closure(
    roots: Vec<ContentRef>,
    evidence: &dyn CaptureEvidence,
    limits: StateLimits,
) -> Result<VerifiedStateContent, StateError> {
    verify_closure_admitted(
        roots,
        evidence,
        limits,
        ContentInventoryEdition::Typed,
        true,
    )
}

fn verify_closure_admitted(
    roots: Vec<ContentRef>,
    evidence: &dyn CaptureEvidence,
    limits: StateLimits,
    edition: ContentInventoryEdition,
    allocated: bool,
) -> Result<VerifiedStateContent, StateError> {
    let mut returned_storage = 0usize;

    if roots.len() > limits.maximum_content_objects {
        return Err(limit("closure roots"));
    }
    let mut content = VerifiedStateContent {
        objects: BTreeMap::new(),
        total_bytes: 0,
        references: BTreeSet::new(),
        edition,
    };
    let mut queued = BTreeSet::new();
    let mut pending = VecDeque::new();
    let mut references = BTreeMap::new();
    let mut dependency_edges = 0usize;
    for reference in roots {
        enqueue(
            reference,
            0,
            &mut pending,
            &mut queued,
            &mut references,
            limits,
            edition,
        )?;
    }

    while let Some((reference, depth)) = pending.pop_front() {
        let length =
            usize::try_from(reference.length.get()).map_err(|_| limit("content length"))?;
        let remaining = limits
            .maximum_total_content_bytes
            .checked_sub(content.total_bytes)
            .ok_or_else(|| limit("total content"))?;
        let shared = content.objects.get(&reference.hash);
        if length > limits.maximum_content_bytes || (shared.is_none() && length > remaining) {
            return Err(limit("content allocation"));
        }
        let bytes = evidence.content(&reference, length)?;
        if allocated {
            // Even an equal-hash duplicate returns an independent bank while
            // retained content still exists. Admit it before digest work.
            let peak = returned_storage
                .checked_add(bytes.capacity())
                .ok_or_else(|| limit("returned content capacity"))?;
            if bytes.capacity() > limits.maximum_content_bytes
                || peak > limits.maximum_total_content_bytes
            {
                return Err(limit("returned content capacity"));
            }
        }
        reference.verify(&bytes).map_err(|error| {
            StateError::new(
                StateErrorCode::Content,
                reference.hash.digest.clone(),
                error.to_string(),
            )
        })?;
        let dependencies =
            evidence.dependencies(&reference, &bytes, limits.maximum_content_objects)?;
        if allocated {
            let mut adjacency = dependencies
                .capacity()
                .checked_mul(std::mem::size_of::<ContentRef>())
                .ok_or_else(|| limit("returned dependency capacity"))?;
            for child in &dependencies {
                adjacency = adjacency
                    .checked_add(
                        crate::node_contract::NodeRuntime::capture_reference_storage(child)
                            .map_err(schema)?,
                    )
                    .ok_or_else(|| limit("returned dependency capacity"))?;
            }
            let peak = returned_storage
                .checked_add(bytes.capacity())
                .and_then(|bytes| bytes.checked_add(adjacency))
                .ok_or_else(|| limit("returned dependency capacity"))?;
            if peak > limits.maximum_total_content_bytes {
                return Err(limit("returned dependency capacity"));
            }
        }
        if dependencies.len() > limits.maximum_content_objects {
            return Err(limit("dependency fanout"));
        }
        dependency_edges = dependency_edges
            .checked_add(dependencies.len())
            .ok_or_else(|| limit("dependency edge count"))?;
        if dependency_edges > limits.maximum_dependency_edges {
            return Err(limit("dependency edge count"));
        }
        for child in dependencies {
            enqueue(
                child,
                depth
                    .checked_add(1)
                    .ok_or_else(|| limit("dependency depth"))?,
                &mut pending,
                &mut queued,
                &mut references,
                limits,
                edition,
            )?;
        }
        if let Some((_, original)) = content.objects.get(&reference.hash) {
            if original != &bytes {
                return Err(StateError::new(
                    StateErrorCode::Content,
                    "typed reference",
                    "same hash has different authenticated octets",
                ));
            }
        } else {
            if allocated {
                returned_storage = returned_storage
                    .checked_add(bytes.capacity())
                    .ok_or_else(|| limit("retained content capacity"))?;
            }
            content.total_bytes = content
                .total_bytes
                .checked_add(bytes.len())
                .ok_or_else(|| limit("total content"))?;
            content
                .objects
                .insert(reference.hash.clone(), (reference.clone(), bytes));
        }
        content.references.insert(reference);
    }
    Ok(content)
}

fn enqueue(
    reference: ContentRef,
    depth: usize,
    pending: &mut VecDeque<(ContentRef, usize)>,
    queued: &mut BTreeSet<ContentRef>,
    references: &mut BTreeMap<HashRef, ContentRef>,
    limits: StateLimits,
    edition: ContentInventoryEdition,
) -> Result<(), StateError> {
    use crucible_node_contract::Validate;
    reference.validate().map_err(schema)?;
    if let Some(previous) = references.get(&reference.hash)
        && ((edition == ContentInventoryEdition::Legacy && previous != &reference)
            || previous.length != reference.length)
    {
        return Err(StateError::new(
            StateErrorCode::Content,
            "reference",
            "same digest has inconsistent length or media type",
        ));
    }
    if queued.contains(&reference) {
        return Ok(());
    }
    if depth > limits.maximum_dependency_depth || queued.len() >= limits.maximum_content_objects {
        return Err(limit("content dependency closure"));
    }
    references.insert(reference.hash.clone(), reference.clone());
    queued.insert(reference.clone());
    pending.push_back((reference, depth));
    Ok(())
}

/// Enumerates references in closed host-supported core records, not opaque state.
pub(super) fn core_references(
    value: &impl Serialize,
    maximum: usize,
) -> Result<Vec<ContentRef>, StateError> {
    bounded_record(value, maximum)?;
    let value = serde_json::to_value(value).map_err(schema)?;
    let mut output = Vec::new();
    let mut stack = vec![&value];
    while let Some(value) = stack.pop() {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(extensions) = object.get("extensions")
                    && !extensions.as_object().is_some_and(|value| value.is_empty())
                {
                    return Err(StateError::new(
                        StateErrorCode::Schema,
                        "extensions",
                        "capture extension semantics are not registered",
                    ));
                }
                if object.contains_key("hash")
                    && object.contains_key("length")
                    && object.contains_key("media_type")
                {
                    output.push(serde_json::from_value(value.clone()).map_err(schema)?);
                } else {
                    stack.extend(object.values());
                }
            }
            serde_json::Value::Array(array) => stack.extend(array),
            _ => {}
        }
    }
    Ok(output)
}

pub(super) fn bounded_record(value: &impl Serialize, maximum: usize) -> Result<(), StateError> {
    struct Counter {
        remaining: usize,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.remaining = self
                .remaining
                .checked_sub(bytes.len())
                .ok_or_else(|| io::Error::other("state record ceiling exceeded"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Counter { remaining: maximum }, value)
        .map_err(|_| limit("core record bytes"))
}

pub(super) fn limit(component: &str) -> StateError {
    StateError::new(
        StateErrorCode::ResourceLimit,
        component,
        "finite state operation ceiling exceeded",
    )
}

/// Forms only test-local typed content; it attests byte geometry, never native state.
#[cfg(test)]
pub(crate) fn synthetic_typed_content(
    objects: &[crate::node_scheduling::InputPayload],
) -> Result<VerifiedStateContent, StateError> {
    let mut result = VerifiedStateContent {
        objects: BTreeMap::new(),
        total_bytes: 0,
        references: BTreeSet::new(),
        edition: ContentInventoryEdition::Typed,
    };
    for object in objects {
        result.include_payload(&object.reference, &object.bytes, StateLimits::default())?;
    }
    Ok(result)
}

#[cfg(test)]
mod payload_tests {
    // Panics identify a regression in authenticated object or byte-budget bounds.
    // crucible-lint: allow panic-shortcut -- These closure tests deliberately panic on invalid fixtures or failed invariants.
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crucible_node_contract::canonical;

    #[test]
    fn original_runtime_payloads_respect_shared_closure_bounds_and_metadata() {
        let bytes = b"original future publication";
        let reference = canonical::content_ref(bytes, "application/octet-stream").unwrap();
        let limits = StateLimits {
            maximum_content_bytes: bytes.len(),
            maximum_total_content_bytes: bytes.len(),
            maximum_content_objects: 1,
            ..StateLimits::default()
        };
        let mut content = VerifiedStateContent {
            objects: BTreeMap::new(),
            total_bytes: 0,
            references: BTreeSet::new(),
            edition: ContentInventoryEdition::Legacy,
        };

        content.include_payload(&reference, bytes, limits).unwrap();
        content.include_payload(&reference, bytes, limits).unwrap();
        assert_eq!(content.get(&reference), Some(bytes.as_slice()));
        assert_eq!(content.total_bytes(), bytes.len());
        assert_eq!(content.object_count(), 1);

        let second = canonical::content_ref(b"next", "application/octet-stream").unwrap();
        assert_eq!(
            content
                .include_payload(&second, b"next", limits)
                .unwrap_err()
                .code,
            StateErrorCode::ResourceLimit
        );
        let mut foreign = reference.clone();
        foreign.media_type = "text/plain".into();
        assert_eq!(
            content
                .include_payload(&foreign, bytes, limits)
                .unwrap_err()
                .code,
            StateErrorCode::Content
        );
        assert_eq!(
            content
                .include_payload(&reference, b"substitution", limits)
                .unwrap_err()
                .code,
            StateErrorCode::Content
        );
        assert_eq!(content.get(&reference), Some(bytes.as_slice()));
        assert_eq!(content.total_bytes(), bytes.len());
        assert_eq!(content.object_count(), 1);
    }
}

impl VerifiedStateContent {
    /// Names the actual immutable-content owning iterator and child views.
    ///
    /// Requested map-node layouts are constants; no JSON decode, hash or
    /// descriptor operation is performed by the owning census itself.
    pub(crate) fn capture_owned_counter_scratch_data() -> usize {
        use crate::node_contract::RuntimeError;
        use std::mem::size_of;
        size_of::<&Self>()
            + size_of::<usize>()
            + size_of::<std::collections::btree_map::Iter<
                'static,
                HashRef,
                (ContentRef, Vec<u8>),
            >>()
            + size_of::<(&HashRef, &(ContentRef, Vec<u8>))>()
            + size_of::<&Vec<u8>>()
            + size_of::<std::collections::btree_set::Iter<'static, ContentRef>>()
            + size_of::<&ContentRef>()
            + size_of::<&HashRef>()
            // ContentRef and HashRef owned_fields each retain their accumulator.
            + size_of::<[usize; 2]>()
            + size_of::<Result<usize, RuntimeError>>()
            + size_of::<Option<usize>>()
    }

    pub(crate) fn capture_owned_storage(
        &self,
    ) -> Result<usize, crate::node_contract::RuntimeError> {
        use crate::node_contract::{NodeRuntime, RuntimeError};
        let add = |a: usize, b: usize| a.checked_add(b).ok_or(RuntimeError::ResourceLimit);
        let mut bytes = self
            .objects
            .len()
            .max(1)
            .checked_mul(NodeRuntime::capture_map_node_storage::<
                HashRef,
                (ContentRef, Vec<u8>),
            >())
            .ok_or(RuntimeError::ResourceLimit)?;
        bytes = add(
            bytes,
            self.references
                .len()
                .max(1)
                .checked_mul(NodeRuntime::capture_map_node_storage::<ContentRef, ()>())
                .ok_or(RuntimeError::ResourceLimit)?,
        )?;
        for (hash, (reference, body)) in &self.objects {
            bytes = add(bytes, NodeRuntime::capture_hash_storage(hash)?)?;
            bytes = add(bytes, NodeRuntime::capture_reference_storage(reference)?)?;
            bytes = add(bytes, body.capacity())?;
        }
        for reference in &self.references {
            bytes = add(bytes, NodeRuntime::capture_reference_storage(reference)?)?;
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod capture_owned_storage_tests {
    use crucible_node_contract::canonical;
    // These controls construct inert verified-content storage internally to
    // test requested extents. They issue no source, native or restore authority.
    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn retained_verified_content_charges_spare_body_capacity() {
        let body = b"original";
        let reference = canonical::content_ref(body, "application/octet-stream").unwrap();
        let mut retained = Vec::with_capacity(16384);
        retained.extend_from_slice(body);
        let capacity = retained.capacity();
        let content = VerifiedStateContent {
            objects: BTreeMap::from([(reference.hash.clone(), (reference.clone(), retained))]),
            total_bytes: body.len(),
            references: BTreeSet::from([reference]),
            edition: ContentInventoryEdition::Typed,
        };
        assert_eq!(content.total_bytes(), body.len());
        assert!(content.capture_owned_storage().unwrap() >= capacity);
        assert!(content.capture_owned_storage().unwrap() > content.total_bytes());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn retained_verified_content_charges_independent_equal_reference_storage() {
        let body = b"original";
        let mut reference = canonical::content_ref(body, "application/octet-stream").unwrap();
        let mut oversized = String::with_capacity(8192);
        oversized.push_str(&reference.media_type);
        reference.media_type = oversized;
        let capacity = reference.media_type.capacity();
        let content = VerifiedStateContent {
            objects: BTreeMap::from([(reference.hash.clone(), (reference.clone(), body.to_vec()))]),
            total_bytes: body.len(),
            references: BTreeSet::from([reference]),
            edition: ContentInventoryEdition::Typed,
        };
        // Content equality does not make the owning set key's spare bank free.
        assert!(content.capture_owned_storage().unwrap() >= capacity);
    }
}

#[cfg(test)]
mod complete_capacity_controls {
    // These controls exercise immutable content banks, not native issuers.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::cell::Cell;

    struct Evidence {
        body_capacity: usize,
        dependency_capacity: usize,
        bad_reference: bool,
        dependencies_called: Cell<usize>,
    }

    impl CaptureEvidence for Evidence {
        fn content(&self, _: &ContentRef, _: usize) -> Result<Vec<u8>, StateError> {
            let mut body = Vec::with_capacity(self.body_capacity);
            body.extend_from_slice(b"body");
            Ok(body)
        }

        fn dependencies(
            &self,
            _: &ContentRef,
            _: &[u8],
            _: usize,
        ) -> Result<Vec<ContentRef>, StateError> {
            self.dependencies_called
                .set(self.dependencies_called.get() + 1);
            let mut result = Vec::with_capacity(self.dependency_capacity);
            if self.bad_reference {
                let mut child = crucible_node_contract::canonical::content_ref(
                    b"child",
                    "application/octet-stream",
                )
                .map_err(schema)?;
                child.hash.digest = "invalid".into();
                result.push(child);
            }
            Ok(result)
        }

        fn verify_owner_capture(
            &self,
            _: &crate::node_admission::AdmittedGraph,
            _: &crucible_node_contract::CaptureManifest,
            _: &crucible_node_contract::CapturedOwner,
            _: &super::super::StateRequirements,
            _: &VerifiedStateContent,
        ) -> Result<super::super::NativeOwnerCaptureProof, StateError> {
            Err(limit("no native fixture authority"))
        }

        fn verify_coordinator_capture(
            &self,
            _: &crate::node_admission::AdmittedGraph,
            _: &crucible_node_contract::CaptureManifest,
            _: &VerifiedStateContent,
        ) -> Result<super::super::NativeCoordinatorCaptureProof, StateError> {
            Err(limit("no native fixture authority"))
        }
    }

    fn limits() -> StateLimits {
        StateLimits {
            maximum_content_bytes: 4096,
            maximum_total_content_bytes: 8192,
            maximum_content_objects: 8,
            ..StateLimits::default()
        }
    }

    #[test]
    fn complete_bank_refusal_precedes_digest_and_legacy_policy_stays_logical() {
        let reference =
            crucible_node_contract::canonical::content_ref(b"else", "application/octet-stream")
                .unwrap();
        let evidence = Evidence {
            body_capacity: 16384,
            dependency_capacity: 0,
            bad_reference: false,
            dependencies_called: Cell::new(0),
        };
        // Invalid digest must not displace the earlier allocation refusal.
        assert_eq!(
            verify_complete_closure(vec![reference], &evidence, limits())
                .unwrap_err()
                .code,
            StateErrorCode::ResourceLimit
        );
        assert_eq!(evidence.dependencies_called.get(), 0);
        let reference =
            crucible_node_contract::canonical::content_ref(b"body", "application/octet-stream")
                .unwrap();
        assert!(
            verify_closure_with_edition(
                vec![reference],
                &evidence,
                limits(),
                ContentInventoryEdition::Typed
            )
            .is_ok()
        );
    }

    #[test]
    fn complete_empty_adjacency_spare_capacity_refuses_before_enqueue() {
        let reference =
            crucible_node_contract::canonical::content_ref(b"body", "application/octet-stream")
                .unwrap();
        let evidence = Evidence {
            body_capacity: 4,
            dependency_capacity: 4096,
            bad_reference: true,
            dependencies_called: Cell::new(0),
        };
        assert_eq!(
            verify_complete_closure(vec![reference], &evidence, limits())
                .unwrap_err()
                .code,
            StateErrorCode::ResourceLimit
        );
        assert_eq!(evidence.dependencies_called.get(), 1);
    }

    #[test]
    fn complete_exact_small_banks_retain_original_bytes() {
        let reference =
            crucible_node_contract::canonical::content_ref(b"body", "application/octet-stream")
                .unwrap();
        let evidence = Evidence {
            body_capacity: 4,
            dependency_capacity: 0,
            bad_reference: false,
            dependencies_called: Cell::new(0),
        };
        let content =
            verify_complete_closure(vec![reference.clone()], &evidence, limits()).unwrap();
        assert_eq!(content.get(&reference), Some(b"body".as_slice()));
    }
}

impl VerifiedStateContent {
    pub(super) fn charge_original_storage_data(
        &self,
        counter: &mut crate::node_contract::runtime_owned_counter::RetainedRuntimeCounter,
    ) -> Result<(), crate::node_contract::RuntimeError> {
        let Self {
            objects,
            total_bytes: _,
            references,
            edition: _,
        } = self;
        counter.map(objects)?;
        for (hash, (reference, bytes)) in objects {
            counter.owned(hash)?;
            counter.owned(reference)?;
            counter.owned(bytes)?;
        }
        counter.set(references)?;
        for reference in references {
            counter.owned(reference)?;
        }
        Ok(())
    }
}
