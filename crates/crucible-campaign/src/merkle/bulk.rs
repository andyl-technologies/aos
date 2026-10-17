//! Canonical streaming construction of complete Merkle maps.
//!
//! Ordinary and controlled construction share one traversal. Each retains one
//! pending item and at most one 16-way node per digest level; their publication
//! sinks retain the appropriate ordinary or original-account storage contract.

use crucible_cas::owned_decode::DecodeBudget;

use super::*;

mod checked;

impl MerkleMap {
    /// Builds the canonical map for an ascending stream of unique entries.
    ///
    /// The result is byte-identical to inserting the same key/value set into an
    /// empty map. Input chunking does not affect the root. Construction retains
    /// at most one pending entry and one bounded node per digest level; the
    /// supplied iterator may impose its own buffering policy. Referenced values
    /// must already be available before using the root as a storage closure.
    ///
    /// # Errors
    /// Returns storage/encoding errors or an integrity error for duplicate or
    /// descending keys. Ordinary construction retains its existing store API.
    pub fn build_from_sorted<I>(&self, entries: I) -> Result<MerkleMapRoot, CampaignStoreError>
    where
        I: IntoIterator<Item = (CampaignHash, ContentId)>,
    {
        let mut entries = SortedEntries::new(entries.into_iter().map(Ok::<_, CampaignStoreError>));
        let Some(first) = entries.next()? else {
            return self.empty();
        };
        let mut sink = OrdinarySink(self);
        let root = build_node(0, first, &mut entries, &mut sink)?;
        if entries.peek()?.is_some() {
            return Err(invalid("sorted-builder-left-unconsumed-entry"));
        }
        Ok(root)
    }
}

trait NodeSink {
    fn begin_node(&mut self) -> Result<Option<DecodeBudget>, CampaignStoreError>;

    fn emit(
        &mut self,
        node: &MerkleNode,
        account: Option<&DecodeBudget>,
    ) -> Result<MerkleMapRoot, CampaignStoreError>;
}

struct OrdinarySink<'a>(&'a MerkleMap);

impl NodeSink for OrdinarySink<'_> {
    fn begin_node(&mut self) -> Result<Option<DecodeBudget>, CampaignStoreError> {
        Ok(None)
    }

    fn emit(
        &mut self,
        node: &MerkleNode,
        _account: Option<&DecodeBudget>,
    ) -> Result<MerkleMapRoot, CampaignStoreError> {
        Ok(MerkleMapRoot {
            content_id: self.0.persist_node(node)?,
            entry_count: node.entry_count,
        })
    }
}

fn build_node<I, E, S>(
    depth: u8,
    first: (CampaignHash, ContentId),
    entries: &mut SortedEntries<I>,
    sink: &mut S,
) -> Result<MerkleMapRoot, CampaignStoreError>
where
    I: Iterator<Item = Result<(CampaignHash, ContentId), E>>,
    E: Into<CampaignStoreError>,
    S: NodeSink,
{
    if depth >= DIGEST_NIBBLES {
        return Err(invalid("duplicate-sorted-builder-key"));
    }
    let account = sink.begin_node()?;
    let _scope = account.as_ref().map(DecodeBudget::enter);
    let prefix_key = first.0;
    let mut pending = Some(first);
    let mut node = MerkleNode {
        schema_version: MERKLE_NODE_SCHEMA_VERSION,
        depth,
        entry_count: 0,
        entries: BTreeMap::new(),
    };

    while let Some((key, value)) = pending.take() {
        if !keys_share_prefix(prefix_key, key, depth) {
            return Err(invalid("sorted-builder-prefix-mismatch"));
        }
        let slot = digest_nibble(key, depth);
        let entry = if entries
            .peek()?
            .is_some_and(|(next, _)| keys_share_prefix(key, next, depth + 1))
        {
            let child = build_node(depth + 1, (key, value), entries, sink)?;
            MerkleEntry::Node {
                content_id: child.content_id(),
                entry_count: child.entry_count(),
            }
        } else {
            MerkleEntry::Leaf { key, value }
        };
        if let Some(account) = &account {
            account
                .charge_btree_entry::<u8, MerkleEntry>()
                .map_err(CampaignCodecError::from)?;
        }
        if node.entries.insert(slot, entry).is_some() {
            return Err(invalid("duplicate-sorted-builder-slot"));
        }

        let Some((next, _)) = entries.peek()? else {
            break;
        };
        if !keys_share_prefix(prefix_key, next, depth) {
            break;
        }
        pending = entries.next()?;
    }
    node.recompute_count()?;
    sink.emit(&node, account.as_ref())
}

struct SortedEntries<I> {
    inner: I,
    pending: Option<(CampaignHash, ContentId)>,
    previous: Option<CampaignHash>,
    complete: bool,
}

impl<I, E> SortedEntries<I>
where
    I: Iterator<Item = Result<(CampaignHash, ContentId), E>>,
    E: Into<CampaignStoreError>,
{
    fn new(inner: I) -> Self {
        Self {
            inner,
            pending: None,
            previous: None,
            complete: false,
        }
    }

    fn peek(&mut self) -> Result<Option<(CampaignHash, ContentId)>, CampaignStoreError> {
        if self.pending.is_none() && !self.complete {
            self.pending = self.inner.next().transpose().map_err(Into::into)?;
            self.complete = self.pending.is_none();
        }
        Ok(self.pending)
    }

    fn next(&mut self) -> Result<Option<(CampaignHash, ContentId)>, CampaignStoreError> {
        let Some(entry) = self.peek()? else {
            return Ok(None);
        };
        self.pending = None;
        if self.previous.is_some_and(|previous| previous >= entry.0) {
            return Err(invalid("sorted-builder-keys-not-strictly-ascending"));
        }
        self.previous = Some(entry.0);
        Ok(Some(entry))
    }
}

fn keys_share_prefix(left: CampaignHash, right: CampaignHash, prefix_nibbles: u8) -> bool {
    (0..prefix_nibbles).all(|depth| digest_nibble(left, depth) == digest_nibble(right, depth))
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- exact failures identify malformed test fixtures.
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::CampaignRepository;
    use crate::repository::{frontier_index_anchor_key, frontier_index_order_key};
    use crucible_cas::content_store::{
        BlobHandle, ImmutableBlobBackend, MemoryBlobBackend, MemoryRefBackend, ObjectKind,
    };

    fn entry(bytes: [u8; 32], value: u8) -> (CampaignHash, ContentId) {
        (
            CampaignHash::from_bytes(bytes),
            ContentId::for_bytes(ObjectKind::Trace, 1, &[value]),
        )
    }

    fn mixed_entries() -> Vec<(CampaignHash, ContentId)> {
        vec![
            entry([0x00; 32], 0),
            entry(
                [
                    0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                1,
            ),
            entry(
                [
                    0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0,
                ],
                2,
            ),
            entry(
                [
                    0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0,
                ],
                3,
            ),
            entry([0xff; 32], 4),
        ]
    }

    #[test]
    fn sorted_builder_matches_point_insertion_across_chunking() {
        let entries = mixed_entries();
        let point_backend = Arc::new(MemoryBlobBackend::new("merkle-point", 4 * 1024 * 1024));
        let point_map = MerkleMap::new(point_backend);
        let mut point_root = point_map.empty().expect("empty point map");
        for (key, value) in &entries {
            point_root = point_map
                .insert(point_root.content_id(), *key, *value)
                .expect("point insert");
        }

        let stream_backend = Arc::new(MemoryBlobBackend::new("merkle-stream", 4 * 1024 * 1024));
        let stream_map = MerkleMap::new(stream_backend);
        let stream_root = stream_map
            .build_from_sorted(entries.iter().copied())
            .expect("single stream build");
        let chunked_root = stream_map
            .build_from_sorted(entries.chunks(2).flat_map(|chunk| chunk.iter().copied()))
            .expect("chunked stream build");

        assert_eq!(stream_root, point_root);
        assert_eq!(chunked_root, point_root);
        assert_eq!(
            stream_map
                .build_from_sorted(std::iter::empty())
                .expect("empty stream"),
            point_map.empty().expect("canonical empty point map")
        );
        assert_eq!(
            stream_map
                .build_from_sorted(entries.iter().copied().take(1))
                .expect("singleton stream"),
            point_map
                .insert(
                    point_map.empty().expect("empty singleton map").content_id(),
                    entries[0].0,
                    entries[0].1,
                )
                .expect("point singleton")
        );
    }

    #[test]
    fn sorted_builder_rejects_duplicate_and_descending_keys() {
        let backend = Arc::new(MemoryBlobBackend::new(
            "merkle-invalid-stream",
            4 * 1024 * 1024,
        ));
        let map = MerkleMap::new(backend);
        let entries = mixed_entries();

        let duplicate = [entries[0], entries[0]];
        assert!(matches!(
            map.build_from_sorted(duplicate),
            Err(CampaignStoreError::InvalidMerkle {
                reason: "sorted-builder-keys-not-strictly-ascending"
                    | "duplicate-sorted-builder-key"
            })
        ));

        let descending = [entries[1], entries[0]];
        assert!(matches!(
            map.build_from_sorted(descending),
            Err(CampaignStoreError::InvalidMerkle {
                reason: "sorted-builder-keys-not-strictly-ascending"
            })
        ));
    }

    #[test]
    fn sorted_builder_preserves_the_final_nibble_and_publishes_only_final_nodes() {
        let stream_backend = Arc::new(MemoryBlobBackend::new(
            "merkle-final-nibble-stream",
            4 * 1024 * 1024,
        ));
        let stream_map = MerkleMap::new(stream_backend.clone());
        let mut adjacent = [[0_u8; 32]; 2];
        adjacent[1][31] = 1;
        let entries = [entry(adjacent[0], 0), entry(adjacent[1], 1)];

        let stream_root = stream_map
            .build_from_sorted(entries)
            .expect("final-nibble stream build");
        assert_eq!(stream_root.entry_count(), 2);
        assert_eq!(
            stream_backend
                .object_count()
                .expect("final-node object count"),
            usize::from(DIGEST_NIBBLES),
            "one node at every occupied depth is the complete final trie"
        );

        let point_backend = Arc::new(MemoryBlobBackend::new(
            "merkle-final-nibble-point",
            4 * 1024 * 1024,
        ));
        let point_map = MerkleMap::new(point_backend);
        let mut point_root = point_map.empty().expect("empty point map");
        for (key, value) in entries {
            point_root = point_map
                .insert(point_root.content_id(), key, value)
                .expect("final-nibble point insert");
        }
        assert_eq!(stream_root, point_root);
    }

    #[test]
    fn million_dormant_continuations_use_bounded_production_frontier_pages() {
        const CONTINUATIONS: usize = 1_000_000;
        const PAGE_SIZE: usize = 137;

        // Fixture publication constructs real typed projection envelopes. The
        // traversal assertions below bound production page and proof size;
        // CPERF-6 allocation instrumentation lives in the huge-domain gate
        // fixture, whose contract specifically covers integral cardinality.
        let blobs = Arc::new(MemoryBlobBackend::new(
            "million-dormant-frontier",
            768 * 1024 * 1024,
        ));
        let map = MerkleMap::new(blobs.clone());
        let entries = (0..CONTINUATIONS).map(|index| {
            let request_content = ContentId::parse(&format!("campaign-fact.10.{index:064x}"))
                .expect("ordered synthetic request identity");
            let request = crate::BranchRequestId::from_content_id(request_content)
                .expect("typed synthetic request identity");
            let branch_point = crate::BranchPointId::from_hash(CampaignHash::derive(
                "gate.lazy-frontier.dormant-branch-point.v1",
                &index.to_be_bytes(),
            ));
            let projection = crate::ContinuationProjection::new(
                request,
                branch_point,
                crate::ContinuationState::Open,
            );
            let envelope = ObjectEnvelope::for_record(
                CampaignRecordKind::ContinuationProjection,
                crate::object::content_children(projection.content_children())
                    .expect("projection children"),
                projection.canonical_bytes(),
            )
            .expect("projection envelope");
            let projection_content = envelope.content_id();
            let receipt = blobs
                .put_if_absent(
                    projection_content,
                    &BlobHandle::from_bytes(envelope.canonical_bytes()),
                )
                .expect("publish dormant continuation projection");
            assert_eq!(receipt.id, projection_content);

            (frontier_index_order_key(request), projection_content)
        });
        let frontier = map
            .build_from_sorted(entries)
            .expect("build million-entry frontier index");
        assert_eq!(frontier.entry_count(), CONTINUATIONS as u64);

        let empty = map.empty().expect("empty exploration root");
        let exploration = map
            .insert(
                empty.content_id(),
                frontier_index_anchor_key(),
                frontier.content_id(),
            )
            .expect("attach frontier index to exploration root");
        let repository = CampaignRepository::new(
            blobs.clone(),
            Arc::new(MemoryRefBackend::new()),
            crate::CampaignRamAdmission::Unavailable,
        );

        let (first, _, first_proof) = repository
            .scan_frontier_page(exploration.content_id(), None, PAGE_SIZE)
            .expect("scan first bounded frontier page");
        assert_eq!(first.entries().len(), PAGE_SIZE);
        assert!(first_proof.node_count() <= (PAGE_SIZE + 2) * usize::from(DIGEST_NIBBLES) + 1);
        let first_cursor = first.next_after().expect("first page cursor");
        assert_eq!(first_cursor, first.entries()[PAGE_SIZE - 1].0);
        for (key, content) in first.entries() {
            let projection = read_projection_envelope(blobs.as_ref(), *content);
            assert_eq!(projection.state(), crate::ContinuationState::Open);
            assert_eq!(frontier_index_order_key(projection.request()), *key);
        }

        let after = synthetic_request(CONTINUATIONS - PAGE_SIZE - 1);
        let (last, _, last_proof) = repository
            .scan_frontier_page(exploration.content_id(), Some(after), PAGE_SIZE)
            .expect("scan final bounded frontier page");
        assert_eq!(last.entries().len(), PAGE_SIZE);
        assert_eq!(last.next_after(), None);
        assert!(last_proof.node_count() <= (PAGE_SIZE + 2) * usize::from(DIGEST_NIBBLES) + 1);

        // A new repository has no process-local projection or validation cache.
        // It must reproduce the same page and typed projection bodies solely
        // from the immutable exploration/frontier roots.
        let restarted = CampaignRepository::new(
            blobs.clone(),
            Arc::new(MemoryRefBackend::new()),
            crate::CampaignRamAdmission::Unavailable,
        );
        let (reopened, _, _) = restarted
            .scan_frontier_page(exploration.content_id(), Some(after), PAGE_SIZE)
            .expect("cold-reopen final frontier page");
        assert_eq!(reopened, last);
        for (_, content) in reopened.entries() {
            let projection = read_projection_envelope(blobs.as_ref(), *content);
            assert_eq!(projection.state(), crate::ContinuationState::Open);
        }
    }

    fn synthetic_request(index: usize) -> crate::BranchRequestId {
        let content = ContentId::parse(&format!("campaign-fact.10.{index:064x}"))
            .expect("synthetic request content identity");
        crate::BranchRequestId::from_content_id(content).expect("synthetic request identity")
    }

    fn read_projection_envelope(
        blobs: &dyn ImmutableBlobBackend,
        content: ContentId,
    ) -> crate::ContinuationProjection {
        let source = blobs.read(content, None).expect("read projection envelope");
        let bytes = source
            .read_all(source.logical_length())
            .expect("authenticate projection envelope bytes");
        let envelope =
            ObjectEnvelope::from_canonical_bytes(&bytes).expect("decode projection envelope");
        assert_eq!(envelope.content_id(), content);
        assert_eq!(
            envelope.record_kind(),
            CampaignRecordKind::ContinuationProjection
        );
        crate::ContinuationProjection::from_canonical_bytes(envelope.body())
            .expect("decode typed continuation body")
    }
}
