//! Accounts actual shared native Capture roots once while retaining every edge.
//!
//! This private, fixed stack roster is used only by the separate allocation
//! report walk. It does not alter repeated-view wire metadata or serialize
//! addresses. Exhaustion refuses before report publication; identity data grants
//! no source/native permission and is never accepted from portable fields.

use super::*;
use aliases::MetadataSharedKind;

const MAXIMUM_CAPTURE_SHARED_ROOTS: usize = 64;

#[derive(Clone, Copy)]
struct SharedRoot {
    kind: MetadataSharedKind,
    address: *const (),
    bytes: usize,
    alignment: usize,
    child_walked: bool,
}

/// Retains only actual borrowed allocation identities during one closed walk.
pub(crate) struct NativeCaptureMetadataRoots {
    entries: [Option<SharedRoot>; MAXIMUM_CAPTURE_SHARED_ROOTS],
    initialized: usize,
    strong_edges: usize,
}

impl NativeCaptureMetadataRoots {
    pub(crate) const fn new() -> Self {
        Self {
            entries: [None; MAXIMUM_CAPTURE_SHARED_ROOTS],
            initialized: 0,
            strong_edges: 0,
        }
    }

    /// Records a real edge and starts its child walk exactly once.
    pub(crate) fn observe_shared<T: ?Sized>(
        &mut self,
        observer: &mut MetadataObserver,
        kind: MetadataSharedKind,
        backing: &T,
    ) -> Result<bool, ProviderError> {
        let index = self.observe_edge_inner(observer, kind, backing)?;
        let root = self.entries[index].as_mut().ok_or_else(refused)?;
        if root.child_walked {
            return Ok(false);
        }
        root.child_walked = true;
        Ok(true)
    }

    /// Records a real edge whose actual typed child is walked elsewhere.
    pub(crate) fn observe_shared_edge<T: ?Sized>(
        &mut self,
        observer: &mut MetadataObserver,
        kind: MetadataSharedKind,
        backing: &T,
    ) -> Result<(), ProviderError> {
        self.observe_edge_inner(observer, kind, backing).map(|_| ())
    }

    fn observe_edge_inner<T: ?Sized>(
        &mut self,
        observer: &mut MetadataObserver,
        kind: MetadataSharedKind,
        backing: &T,
    ) -> Result<usize, ProviderError> {
        self.strong_edges = self.strong_edges.checked_add(1).ok_or_else(refused)?;
        let address = std::ptr::from_ref(backing).cast::<()>();
        let bytes = size_of_val(backing);
        let alignment = align_of_val(backing);
        for (index, root) in self.entries[..self.initialized].iter().enumerate() {
            let root = root.as_ref().ok_or_else(refused)?;
            if root.kind == kind && root.address == address {
                if root.bytes != bytes || root.alignment != alignment {
                    return Err(refused());
                }
                return Ok(index);
            }
        }
        if self.initialized == self.entries.len() {
            return Err(refused());
        }
        observer.shared_original(kind, backing)?;
        let index = self.initialized;
        self.entries[index] = Some(SharedRoot {
            kind,
            address,
            bytes,
            alignment,
            child_walked: false,
        });
        self.initialized += 1;
        Ok(index)
    }

    /// Requires every recorded header to have its real typed payload accounted.
    pub(crate) fn finish(&self) -> Result<(usize, usize), ProviderError> {
        if self.entries[..self.initialized]
            .iter()
            .any(|root| root.as_ref().is_none_or(|root| !root.child_walked))
        {
            return Err(refused());
        }
        Ok((self.strong_edges, self.initialized))
    }
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("native Capture actual shared-root roster")
}

// crucible-lint: allow panic-shortcut -- fixture assertions preserve actual alias/layout/refusal observations.
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "actual Rc allocation identities and checked roster refusal are the test observations"
)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[test]
    fn actual_alias_edges_share_one_payload_but_equal_distinct_roots_do_not() {
        let first = Rc::new(Vec::<u8>::with_capacity(19));
        let alias = Rc::clone(&first);
        let distinct = Rc::new(Vec::<u8>::with_capacity(19));
        let mut roots = NativeCaptureMetadataRoots::new();
        let mut observer = MetadataObserver::new();

        for owner in [&first, &alias, &distinct] {
            if roots
                .observe_shared(
                    &mut observer,
                    MetadataSharedKind::ContentBytes,
                    owner.as_ref(),
                )
                .unwrap()
            {
                observer.vector::<u8>(owner.capacity()).unwrap();
            }
        }

        assert_eq!(roots.finish().unwrap(), (3, 2));
        let facts = observer.finish();
        assert_eq!(facts.shared_backing_views, 2);
        assert_eq!(facts.shared_value_bytes, 2 * size_of::<Vec<u8>>());
        assert_eq!(
            facts.vector_capacity_bytes,
            first.capacity() + distinct.capacity()
        );
    }

    #[test]
    fn deferred_real_edge_requires_its_actual_child_and_consistent_layout() {
        let backing = Rc::new([1u8, 2]);
        let mut roots = NativeCaptureMetadataRoots::new();
        let mut observer = MetadataObserver::new();

        roots
            .observe_shared_edge(
                &mut observer,
                MetadataSharedKind::ContentBytes,
                backing.as_ref(),
            )
            .unwrap();
        assert!(roots.finish().is_err());
        assert!(
            roots
                .observe_shared(
                    &mut observer,
                    MetadataSharedKind::ContentBytes,
                    backing.as_ref()
                )
                .unwrap()
        );
        assert_eq!(roots.finish().unwrap(), (2, 1));

        let mut slices = NativeCaptureMetadataRoots::new();
        slices
            .observe_shared(
                &mut observer,
                MetadataSharedKind::ContentBytes,
                &backing[..1],
            )
            .unwrap();
        assert!(
            slices
                .observe_shared(
                    &mut observer,
                    MetadataSharedKind::ContentBytes,
                    &backing[..2]
                )
                .is_err()
        );
    }

    #[test]
    fn fixed_roster_exhaustion_and_edge_overflow_refuse_without_heap_fallback() {
        let backings: Vec<_> = (0..=MAXIMUM_CAPTURE_SHARED_ROOTS)
            .map(|_| Rc::new(0u8))
            .collect();
        let mut roots = NativeCaptureMetadataRoots::new();
        let mut observer = MetadataObserver::new();
        for backing in &backings[..MAXIMUM_CAPTURE_SHARED_ROOTS] {
            assert!(
                roots
                    .observe_shared(
                        &mut observer,
                        MetadataSharedKind::ContentBytes,
                        backing.as_ref()
                    )
                    .unwrap()
            );
        }
        assert_eq!(
            roots.finish().unwrap(),
            (MAXIMUM_CAPTURE_SHARED_ROOTS, MAXIMUM_CAPTURE_SHARED_ROOTS)
        );
        assert!(
            roots
                .observe_shared(
                    &mut observer,
                    MetadataSharedKind::ContentBytes,
                    backings[MAXIMUM_CAPTURE_SHARED_ROOTS].as_ref()
                )
                .is_err()
        );

        roots.strong_edges = usize::MAX;
        assert!(
            roots
                .observe_shared_edge(
                    &mut observer,
                    MetadataSharedKind::ContentBytes,
                    backings[0].as_ref()
                )
                .is_err()
        );
    }
}
