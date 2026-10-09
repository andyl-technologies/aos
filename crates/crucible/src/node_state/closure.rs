//! Authenticated bounded content closure and closed-record reference enumeration.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Write};

use crucible_node_contract::{ContentRef, HashRef};
use serde::Serialize;

use super::{CaptureEvidence, StateError, StateErrorCode, StateLimits, schema};

/// Retains verified immutable bytes without granting access to native resources.
///
/// Construction is private. Every object passed to a native verifier has already
/// satisfied exact content identity, length and aggregate allocation limits.
#[derive(Debug)]
pub struct VerifiedStateContent {
    objects: BTreeMap<HashRef, (ContentRef, Vec<u8>)>,
    total_bytes: usize,
}

impl VerifiedStateContent {
    /// Borrows bytes only when the complete reference metadata matches admission.
    pub fn get(&self, reference: &ContentRef) -> Option<&[u8]> {
        self.objects
            .get(&reference.hash)
            .filter(|(stored, _)| stored == reference)
            .map(|(_, bytes)| bytes.as_slice())
    }

    /// Returns total distinct authenticated content bytes retained by this closure.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Returns the number of distinct authenticated content objects.
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub(super) fn entries(&self) -> impl Iterator<Item = (&ContentRef, &[u8])> {
        self.objects
            .values()
            .map(|(reference, bytes)| (reference, bytes.as_slice()))
    }
}

pub(super) fn verify_closure(
    roots: Vec<ContentRef>,
    evidence: &dyn CaptureEvidence,
    limits: StateLimits,
) -> Result<VerifiedStateContent, StateError> {
    if roots.len() > limits.maximum_content_objects {
        return Err(limit("closure roots"));
    }
    let mut content = VerifiedStateContent {
        objects: BTreeMap::new(),
        total_bytes: 0,
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
        )?;
    }

    while let Some((reference, depth)) = pending.pop_front() {
        let length =
            usize::try_from(reference.length.get()).map_err(|_| limit("content length"))?;
        let remaining = limits
            .maximum_total_content_bytes
            .checked_sub(content.total_bytes)
            .ok_or_else(|| limit("total content"))?;
        if length > limits.maximum_content_bytes || length > remaining {
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
            )?;
        }
        content.total_bytes = content
            .total_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| limit("total content"))?;
        content
            .objects
            .insert(reference.hash.clone(), (reference, bytes));
    }
    Ok(content)
}

fn enqueue(
    reference: ContentRef,
    depth: usize,
    pending: &mut VecDeque<(ContentRef, usize)>,
    queued: &mut BTreeSet<HashRef>,
    references: &mut BTreeMap<HashRef, ContentRef>,
    limits: StateLimits,
) -> Result<(), StateError> {
    use crucible_node_contract::Validate;
    reference.validate().map_err(schema)?;
    if let Some(previous) = references.get(&reference.hash) {
        if previous != &reference {
            return Err(StateError::new(
                StateErrorCode::Content,
                "reference",
                "same digest has inconsistent length or media type",
            ));
        }
    }
    if queued.contains(&reference.hash) {
        return Ok(());
    }
    if depth > limits.maximum_dependency_depth || queued.len() >= limits.maximum_content_objects {
        return Err(limit("content dependency closure"));
    }
    references.insert(reference.hash.clone(), reference.clone());
    queued.insert(reference.hash.clone());
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
                if let Some(extensions) = object.get("extensions") {
                    if !extensions.as_object().is_some_and(|value| value.is_empty()) {
                        return Err(StateError::new(
                            StateErrorCode::Schema,
                            "extensions",
                            "capture extension semantics are not registered",
                        ));
                    }
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
