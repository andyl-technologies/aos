//! Authenticated bounded content closure and closed-record reference enumeration.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Write};

use crucible_node_contract::{ContentRef, HashRef};
use serde::Serialize;

use super::{CaptureEvidence, StateError, StateErrorCode, StateLimits, schema};

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
        reference.verify(&bytes).map_err(|error| {
            StateError::new(
                StateErrorCode::Content,
                reference.hash.digest.clone(),
                error.to_string(),
            )
        })?;
        let dependencies =
            evidence.dependencies(&reference, &bytes, limits.maximum_content_objects)?;
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
