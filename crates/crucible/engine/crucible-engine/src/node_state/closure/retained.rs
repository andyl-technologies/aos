//! Retains successful immutable reads and in-progress closure work on refusal.
//!
//! This owner is used only by the separately admitted current17 loader. Partial
//! content is inaccessible as verified content until the entire walk succeeds.

use super::*;
use crate::node_contract::{NodeRuntime, RuntimeError};

pub(crate) struct RetainedClosureVerification {
    content: Option<VerifiedStateContent>,
    queued: BTreeSet<ContentRef>,
    pending: VecDeque<(ContentRef, usize)>,
    references: BTreeMap<HashRef, ContentRef>,
    current: Option<(ContentRef, usize)>,
    bytes: Option<Vec<u8>>,
    dependencies: Vec<ContentRef>,
    edges: usize,
    complete: bool,
    started: bool,
}

impl RetainedClosureVerification {
    pub(crate) fn new() -> Self {
        Self {
            content: Some(VerifiedStateContent {
                objects: BTreeMap::new(),
                total_bytes: 0,
                references: BTreeSet::new(),
                edition: ContentInventoryEdition::Typed,
            }),
            queued: BTreeSet::new(),
            pending: VecDeque::new(),
            references: BTreeMap::new(),
            current: None,
            bytes: None,
            dependencies: Vec::new(),
            edges: 0,
            complete: false,
            started: false,
        }
    }

    pub(crate) fn retained_requested_storage_data(&self) -> Result<usize, RuntimeError> {
        let mut total = std::mem::size_of::<Self>();
        let mut add = |next| -> Result<(), RuntimeError> {
            total = total.checked_add(next).ok_or(RuntimeError::ResourceLimit)?;
            Ok(())
        };
        if let Some(content) = &self.content {
            add(content.capture_owned_storage()?)?;
        }
        add(self
            .dependencies
            .capacity()
            .checked_mul(std::mem::size_of::<ContentRef>())
            .ok_or(RuntimeError::ResourceLimit)?)?;
        add(self
            .pending
            .capacity()
            .checked_mul(std::mem::size_of::<(ContentRef, usize)>())
            .ok_or(RuntimeError::ResourceLimit)?)?;
        add(self
            .queued
            .len()
            .max(1)
            .checked_mul(NodeRuntime::capture_map_node_storage::<ContentRef, ()>())
            .ok_or(RuntimeError::ResourceLimit)?)?;
        add(self
            .references
            .len()
            .max(1)
            .checked_mul(NodeRuntime::capture_map_node_storage::<HashRef, ContentRef>())
            .ok_or(RuntimeError::ResourceLimit)?)?;
        for reference in self.dependencies.iter().chain(&self.queued) {
            add(NodeRuntime::capture_reference_storage(reference)?)?;
        }
        for (reference, _) in self.pending.iter().chain(self.current.iter()) {
            add(NodeRuntime::capture_reference_storage(reference)?)?;
        }
        for (hash, reference) in &self.references {
            add(NodeRuntime::capture_hash_storage(hash)?)?;
            add(NodeRuntime::capture_reference_storage(reference)?)?;
        }
        if let Some(bytes) = &self.bytes {
            add(bytes.capacity())?;
        }
        Ok(total)
    }

    fn admit(
        &self,
        additional: usize,
        future: usize,
        limits: StateLimits,
    ) -> Result<(), StateError> {
        let peak = self
            .retained_requested_storage_data()
            .map_err(schema)?
            .checked_add(additional)
            .and_then(|value| value.checked_add(future))
            .ok_or_else(|| limit("retained immutable closure work"))?;
        if peak > limits.maximum_total_content_bytes {
            return Err(limit("retained immutable closure work"));
        }
        Ok(())
    }

    fn enqueue_admitted(
        &mut self,
        reference: &ContentRef,
        depth: usize,
        additional: usize,
        limits: StateLimits,
    ) -> Result<(), StateError> {
        // The ordinary closed enqueue keeps its full-reference consistency,
        // depth, fanout and no-duplicate rules. Price all three retained copies.
        let reference_bytes = NodeRuntime::capture_reference_storage(reference).map_err(schema)?;
        let hash_bytes = NodeRuntime::capture_hash_storage(&reference.hash).map_err(schema)?;
        let future = reference_bytes
            .checked_mul(4)
            .and_then(|value| value.checked_add(hash_bytes))
            .and_then(|value| {
                value.checked_add(NodeRuntime::capture_map_node_storage::<HashRef, ContentRef>())
            })
            .and_then(|value| {
                value.checked_add(NodeRuntime::capture_map_node_storage::<ContentRef, ()>())
            })
            .and_then(|value| {
                value.checked_add(
                    self.pending
                        .capacity()
                        .max(2)
                        .checked_mul(2)?
                        .checked_mul(std::mem::size_of::<(ContentRef, usize)>())?,
                )
            })
            .ok_or_else(|| limit("retained closure enqueue work"))?;
        self.admit(additional, future, limits)?;
        enqueue(
            reference.clone(),
            depth,
            &mut self.pending,
            &mut self.queued,
            &mut self.references,
            limits,
            ContentInventoryEdition::Typed,
        )
    }

    pub(crate) fn verify_into(
        &mut self,
        root: &ContentRef,
        evidence: &dyn CaptureEvidence,
        limits: StateLimits,
        additional: usize,
        maximum_dependency_allocation: usize,
    ) -> Result<(), StateError> {
        if self.started {
            return Err(limit("immutable closure attempt already spent"));
        }
        self.started = true;
        self.enqueue_admitted(root, 0, additional, limits)?;
        while let Some(current) = self.pending.pop_front() {
            self.current = Some(current);
            let (reference, depth) = self
                .current
                .as_ref()
                .ok_or_else(|| limit("closure current owner"))?;
            let length =
                usize::try_from(reference.length.get()).map_err(|_| limit("content length"))?;
            let content = self
                .content
                .as_ref()
                .ok_or_else(|| limit("closure content owner"))?;
            let remaining = limits
                .maximum_total_content_bytes
                .checked_sub(content.total_bytes)
                .ok_or_else(|| limit("total content"))?;
            if length > limits.maximum_content_bytes
                || (!content.objects.contains_key(&reference.hash) && length > remaining)
            {
                return Err(limit("content allocation"));
            }
            self.admit(additional, length, limits)?;
            self.bytes = Some(evidence.content(reference, length)?);
            self.admit(additional, 0, limits)?;
            let bytes = self
                .bytes
                .as_ref()
                .ok_or_else(|| limit("closure returned owner"))?;
            if bytes.capacity() > limits.maximum_content_bytes {
                return Err(limit("returned content capacity"));
            }
            reference.verify(bytes).map_err(schema)?;
            self.admit(additional, maximum_dependency_allocation, limits)?;
            self.dependencies =
                evidence.dependencies(reference, bytes, limits.maximum_content_objects)?;
            self.admit(additional, 0, limits)?;
            if self.dependencies.len() > limits.maximum_content_objects {
                return Err(limit("dependency fanout"));
            }
            self.edges = self
                .edges
                .checked_add(self.dependencies.len())
                .ok_or_else(|| limit("dependency edges"))?;
            if self.edges > limits.maximum_dependency_edges {
                return Err(limit("dependency edges"));
            }
            let next_depth = depth
                .checked_add(1)
                .ok_or_else(|| limit("dependency depth"))?;
            for index in 0..self.dependencies.len() {
                self.admit(
                    additional,
                    NodeRuntime::capture_reference_storage(&self.dependencies[index])
                        .map_err(schema)?,
                    limits,
                )?;
                let child = self.dependencies[index].clone();
                self.enqueue_admitted(&child, next_depth, additional, limits)?;
            }
            let (reference, _) = self
                .current
                .as_ref()
                .ok_or_else(|| limit("closure current owner"))?;
            let finish = NodeRuntime::capture_reference_storage(reference)
                .map_err(schema)?
                .checked_mul(2)
                .and_then(|value| {
                    value.checked_add(NodeRuntime::capture_hash_storage(&reference.hash).ok()?)
                })
                .and_then(|value| {
                    value.checked_add(NodeRuntime::capture_map_node_storage::<
                        HashRef,
                        (ContentRef, Vec<u8>),
                    >())
                })
                .and_then(|value| {
                    value.checked_add(NodeRuntime::capture_map_node_storage::<ContentRef, ()>())
                })
                .ok_or_else(|| limit("retained closure completed row work"))?;
            self.admit(additional, finish, limits)?;
            let content = self
                .content
                .as_mut()
                .ok_or_else(|| limit("closure content owner"))?;
            let bytes = self
                .bytes
                .as_ref()
                .ok_or_else(|| limit("closure returned owner"))?;
            if let Some((_, original)) = content.objects.get(&reference.hash) {
                if original != bytes {
                    return Err(limit("same hash has different authenticated octets"));
                }
            } else {
                content.total_bytes = content
                    .total_bytes
                    .checked_add(bytes.len())
                    .ok_or_else(|| limit("total content"))?;
                let bytes = self
                    .bytes
                    .take()
                    .ok_or_else(|| limit("closure returned owner"))?;
                content
                    .objects
                    .insert(reference.hash.clone(), (reference.clone(), bytes));
            }
            content.references.insert(reference.clone());
            self.current = None;
            self.bytes = None;
            self.dependencies.clear();
        }
        self.complete = true;
        Ok(())
    }

    pub(crate) fn take_verified_data(&mut self) -> Result<VerifiedStateContent, StateError> {
        if !self.complete {
            return Err(limit("immutable closure is incomplete"));
        }
        self.content
            .take()
            .ok_or_else(|| limit("immutable closure was already taken"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::node_state::{
        NativeCoordinatorCaptureProof, NativeOwnerCaptureProof, StateRequirements,
    };
    use crucible_node_format::{CaptureManifest, CapturedOwner, canonical};

    struct Evidence {
        root: ContentRef,
        child: ContentRef,
        corrupt_child: bool,
    }

    impl CaptureEvidence for Evidence {
        fn content(&self, reference: &ContentRef, maximum: usize) -> Result<Vec<u8>, StateError> {
            let bytes: &[u8] = if reference == &self.root {
                b"root"
            } else if reference == &self.child && self.corrupt_child {
                b"fail"
            } else if reference == &self.child {
                b"leaf"
            } else {
                return Err(limit("unknown test content"));
            };
            if bytes.len() > maximum {
                return Err(limit("test read extent"));
            }
            Ok(bytes.to_vec())
        }

        fn dependencies(
            &self,
            reference: &ContentRef,
            _: &[u8],
            maximum: usize,
        ) -> Result<Vec<ContentRef>, StateError> {
            if reference == &self.root {
                if maximum == 0 {
                    return Err(limit("test adjacency extent"));
                }
                Ok(vec![self.child.clone()])
            } else if reference == &self.child {
                Ok(Vec::new())
            } else {
                Err(limit("unknown test dependency"))
            }
        }

        fn verify_owner_capture(
            &self,
            _: &crate::node_admission::AdmittedGraph,
            _: &CaptureManifest,
            _: &CapturedOwner,
            _: &StateRequirements,
            _: &VerifiedStateContent,
        ) -> Result<NativeOwnerCaptureProof, StateError> {
            Err(limit("inert closure control has no native authority"))
        }

        fn verify_coordinator_capture(
            &self,
            _: &crate::node_admission::AdmittedGraph,
            _: &CaptureManifest,
            _: &VerifiedStateContent,
        ) -> Result<NativeCoordinatorCaptureProof, StateError> {
            Err(limit("inert closure control has no coordinator authority"))
        }
    }

    fn evidence(corrupt_child: bool) -> Evidence {
        Evidence {
            root: canonical::content_ref(b"root", "application/octet-stream").unwrap(),
            child: canonical::content_ref(b"leaf", "application/octet-stream").unwrap(),
            corrupt_child,
        }
    }

    #[test]
    fn failed_closure_keeps_verified_prefix_and_actual_bad_return_without_replay() {
        let evidence = evidence(true);
        let mut attempt = RetainedClosureVerification::new();
        let maximum_adjacency = std::mem::size_of::<ContentRef>()
            + NodeRuntime::capture_reference_storage(&evidence.child).unwrap();

        assert!(
            attempt
                .verify_into(
                    &evidence.root,
                    &evidence,
                    StateLimits::default(),
                    0,
                    maximum_adjacency
                )
                .is_err()
        );
        assert_eq!(
            attempt.content.as_ref().unwrap().get(&evidence.root),
            Some(b"root".as_slice())
        );
        assert_eq!(attempt.current.as_ref().unwrap().0, evidence.child);
        assert_eq!(attempt.bytes.as_deref(), Some(b"fail".as_slice()));
        assert!(attempt.take_verified_data().is_err());
        assert!(
            attempt
                .verify_into(
                    &evidence.root,
                    &evidence,
                    StateLimits::default(),
                    0,
                    maximum_adjacency
                )
                .is_err()
        );
        assert_eq!(attempt.bytes.as_deref(), Some(b"fail".as_slice()));
    }

    #[test]
    fn complete_closure_moves_exact_verified_bodies_once() {
        let evidence = evidence(false);
        let mut attempt = RetainedClosureVerification::new();
        let maximum_adjacency = std::mem::size_of::<ContentRef>()
            + NodeRuntime::capture_reference_storage(&evidence.child).unwrap();

        attempt
            .verify_into(
                &evidence.root,
                &evidence,
                StateLimits::default(),
                0,
                maximum_adjacency,
            )
            .unwrap();
        let verified = attempt.take_verified_data().unwrap();

        assert_eq!(verified.object_count(), 2);
        assert_eq!(verified.get(&evidence.root), Some(b"root".as_slice()));
        assert_eq!(verified.get(&evidence.child), Some(b"leaf".as_slice()));
        assert!(attempt.take_verified_data().is_err());
    }
}
