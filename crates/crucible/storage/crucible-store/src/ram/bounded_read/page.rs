//! Authenticates one lazy page path through a single owning read request.
//!
//! Packed leaves borrow one pinned index and a paid active manifest across the
//! bounded binary path. Graph and physical admission still apply to every
//! selected object; all pins close before the final acceptance observation.

use super::*;
use crate::content_store::{ContentId, PackedBlobBackend};
use crate::owned_decode::DecodeBudget;
use crate::ram::codec::{PreparedEnvelopeRead, read_envelope_using, validate_page_envelope};
use crate::ram::{RamPageBytes, RamPageRead};
use crucible_ram::{PageDigest, PageProof};

/// Borrows the leased root and one validated lazy-page coordinate.
#[derive(Clone, Copy)]
pub(super) struct Readback<'read> {
    root: &'read LeasedRamRoot,
    region_id: &'read str,
    page_index: u64,
    reference: TreeRef,
    expected_length: usize,
}

trait Access {
    fn tree(&mut self, reference: TreeRef, work: &mut Work<'_>) -> Result<TreeNode, RamStoreError>;

    fn page(
        &mut self,
        id: ContentId,
        digest: PageDigest,
        work: &mut Work<'_>,
    ) -> Result<RamPageBytes, RamStoreError>;
}

struct ExistingAccess<'read, B: ?Sized>(&'read B);

impl<B: ImmutableBlobBackend + ?Sized> Access for ExistingAccess<'_, B> {
    fn tree(&mut self, reference: TreeRef, work: &mut Work<'_>) -> Result<TreeNode, RamStoreError> {
        if reference.id.kind() != crate::content_store::ObjectKind::RamTree {
            return Err(RamStoreError::Invalid("tree object kind"));
        }
        let envelope = read_envelope_from(self.0, reference.id, work, true)?;
        validate_tree(&envelope, reference)
    }

    fn page(
        &mut self,
        id: ContentId,
        digest: PageDigest,
        work: &mut Work<'_>,
    ) -> Result<RamPageBytes, RamStoreError> {
        if id.kind() != crate::content_store::ObjectKind::RamExtent {
            return Err(RamStoreError::Invalid("page object kind"));
        }
        let envelope = read_envelope_from(self.0, id, work, false)?;
        validate_page_envelope(&envelope, digest)?;
        Ok(RamPageBytes::new(envelope))
    }
}

struct CheckedAccess<'read, F, V> {
    source: &'read mut F,
    verify: &'read mut V,
}

impl<F, V> Access for CheckedAccess<'_, F, V>
where
    F: FnMut(
        &DecodeBudget,
        ContentId,
        &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<crate::content_store::BlobHandle, StoreError>,
    V: FnMut(&DecodeBudget) -> Result<(), StoreError>,
{
    fn tree(&mut self, reference: TreeRef, work: &mut Work<'_>) -> Result<TreeNode, RamStoreError> {
        if reference.id.kind() != crate::content_store::ObjectKind::RamTree {
            return Err(RamStoreError::Invalid("tree object kind"));
        }
        let envelope = read_envelope_using(reference.id, work, true, self.source, self.verify)?;
        validate_tree(&envelope, reference)
    }

    fn page(
        &mut self,
        id: ContentId,
        digest: PageDigest,
        work: &mut Work<'_>,
    ) -> Result<RamPageBytes, RamStoreError> {
        if id.kind() != crate::content_store::ObjectKind::RamExtent {
            return Err(RamStoreError::Invalid("page object kind"));
        }
        let envelope = read_envelope_using(id, work, false, self.source, self.verify)?;
        validate_page_envelope(&envelope, digest)?;
        Ok(RamPageBytes::new(envelope))
    }
}

impl Readback<'_> {
    /// Reads the complete path through the existing checked backend.
    ///
    /// # Errors
    /// Preserves original, backend, codec, geometry and membership refusals.
    pub(super) fn execute_existing<B: ImmutableBlobBackend + ?Sized>(
        &self,
        backend: &B,
        work: &mut Work<'_>,
    ) -> Result<ReadValue, RamStoreError> {
        self.walk(work, &mut ExistingAccess(backend))
            .map(ReadValue::Page)
    }

    fn walk(
        &self,
        work: &mut Work<'_>,
        access: &mut impl Access,
    ) -> Result<RamPageRead, RamStoreError> {
        let mut reference = self.reference;
        let mut page = self.page_index;
        let proof_credit = crate::ram::page_read::proof_credit(
            work.original(),
            self.region_id,
            reference.height as usize,
        )?;
        let mut siblings = Vec::with_capacity(reference.height as usize);

        loop {
            match access.tree(reference, work)? {
                TreeNode::Padding => {
                    return Err(RamStoreError::Invalid("real page resolves to padding"));
                }
                TreeNode::Leaf {
                    page: object,
                    digest,
                } => {
                    let bytes = access.page(object, digest, work)?;
                    if bytes.len() != self.expected_length {
                        return Err(RamStoreError::Invalid("logical page valid length"));
                    }
                    siblings.reverse();
                    let proof = PageProof::new(
                        self.region_id,
                        self.page_index,
                        self.expected_length as u32,
                        digest,
                        siblings,
                    )
                    .map_err(crate::ram::logical)?;
                    proof
                        .verify(&bytes, &self.root.record, self.root.logical_digest())
                        .map_err(crate::ram::logical)?;
                    return Ok(RamPageRead::new(bytes, proof, proof_credit));
                }
                TreeNode::Branch { left, right } => {
                    let width = 1_u64 << (reference.height - 1);
                    if page < width {
                        siblings.push(right.digest);
                        reference = left;
                    } else {
                        siblings.push(left.digest);
                        page -= width;
                        reference = right;
                    }
                }
            }
        }
    }
}

/// Admits one complete page path before selecting its physical implementation.
///
/// # Errors
/// Returns invalid coordinates, resource refusal, lost custody or corrupt bytes.
pub(in crate::ram) fn read(
    store: &crate::ram::RamStore,
    root: &LeasedRamRoot,
    region_id: &str,
    page_index: u64,
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
) -> Result<RamPageRead, RamStoreError> {
    let (index, region) = crate::ram::tree::selected_region(&root.record, region_id)?;
    let readback = Readback {
        root,
        region_id,
        page_index,
        reference: root.regions[index],
        expected_length: crate::ram::valid_length(region, page_index)?,
    };
    let mut work = Work::new(store.limits, original, boundary)?;
    let control_bytes = std::mem::size_of::<ReadState>()
        .checked_add(std::mem::size_of::<BoundedReadRequest<'_, '_>>())
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Readback<'_>>()))
        .and_then(|bytes| {
            bytes.checked_add(std::mem::size_of::<PreparedEnvelopeRead>().checked_mul(2)?)
        })
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(RamStoreError::Limit("RAM page read control"))?;
    let _credit = original
        .reserve_scratch_bytes(control_bytes)
        .map_err(crate::ram::codec_ownership::admission)?;
    let mut state = ReadState {
        phase: ReadPhase::Ready,
        pending: Cell::new(None),
    };
    let mut request = BoundedReadRequest {
        work: &mut work,
        task: ReadTask::Page(readback),
        state: &mut state,
        physical: None,
        inventory_admission: None,
    };
    let provider = store.backend.read_bounded_with_boundary(&mut request);
    match request.finish(provider).map_err(RamStoreError::from)? {
        ReadValue::Page(page) => Ok(page),
        _ => unreachable!("a lazy page request retains its own authenticated response"),
    }
}

impl BoundedReadRequest<'_, '_> {
    /// Reads a complete page path with one authenticated Packed view.
    ///
    /// # Errors
    /// Refuses reuse, graph admission, physical or original expiry and corruption.
    pub(super) fn execute_packed_page(
        &mut self,
        backend: &PackedBlobBackend,
    ) -> Result<(), StoreError> {
        match self.state.phase {
            ReadPhase::Ready => {}
            ReadPhase::Failed => return Err(self.first_failure()),
            _ => {
                return Err(StoreError::Unsupported {
                    capability: "bounded-read-request-already-used",
                });
            }
        }
        if let Some(first) = self.work.account.read_failure() {
            self.state.phase = ReadPhase::Failed;
            return Err(first);
        }
        let ReadTask::Page(readback) = self.task else {
            return Err(StoreError::Unsupported {
                capability: "not-page-readback",
            });
        };
        self.state.phase = ReadPhase::Active;
        let physical = self.physical;
        let admission = self.inventory_admission;
        let result = (|| {
            // Validate the first selected object before opening the shared view.
            self.work.checked(|original, boundary| {
                if let Some(admit) = admission {
                    admit(readback.reference.id)?;
                }
                crate::content_store::checked_reader::check(original, boundary)?;
                verify_physical(original, physical)
            })?;
            let view = self.work.checked(|original, boundary| {
                let mut checked = || {
                    crate::content_store::checked_reader::check(original, boundary)?;
                    verify_physical(original, physical)
                };
                crate::content_store::PackedReadView::begin(backend, original, &mut checked)
            })?;
            let mut reader = self.work.checked(|original, boundary| {
                let mut checked = || {
                    crate::content_store::checked_reader::check(original, boundary)?;
                    verify_physical(original, physical)
                };
                view.reader(backend, original, &mut checked)
            })?;
            let selected = Cell::new(None);
            let mut source =
                |original: &DecodeBudget,
                 id,
                 boundary: &mut dyn FnMut() -> Result<(), StoreError>| {
                    selected.set(Some(id));
                    if let Some(admit) = admission {
                        admit(id)?;
                    }
                    reader.lookup(backend, original, id, selected_physical(physical), boundary)
                };
            let mut verify = |original: &DecodeBudget| {
                if let (Some(admit), Some(id)) = (admission, selected.get()) {
                    admit(id)?;
                }
                verify_physical(original, physical)
            };
            readback.walk(
                self.work,
                &mut CheckedAccess {
                    source: &mut source,
                    verify: &mut verify,
                },
            )
        })();
        // The returned page owns decoded bytes, never a pack descriptor. The
        // view and its active manifest are physically closed before acceptance.
        let result = result.and_then(|page| {
            self.work.checked(|original, boundary| {
                crate::content_store::checked_reader::check(original, boundary)?;
                verify_physical(original, physical)
            })?;
            Ok::<_, RamStoreError>(page)
        });
        match result {
            Ok(page) => {
                self.state.pending.set(Some(Ok(ReadValue::Page(page))));
                self.state.phase = ReadPhase::Completed;
                Ok(())
            }
            Err(error) => {
                self.state.phase = ReadPhase::Failed;
                Err(self.work.account.fail_read(error))
            }
        }
    }
}
