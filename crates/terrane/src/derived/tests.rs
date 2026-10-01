//! Exercises streaming orchestration and metadata-only side-table behavior.

#[path = "signed_tests.rs"]
mod signed_tests;

#[path = "dictionary_tests.rs"]
mod dictionary_tests;

use super::*;
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, Durability,
    IdentityPrefix, RangeCapability, RefCapability, StoreFailure,
};
use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use terrane_core::refs::Locality;
use terrane_core::{
    derived::{AttrRecord, AttributeName, AttributeValue, MAGIC_PREFIX_LIMIT, Magic},
    identity::{Digest, Identity, IdentityKind, TERRANE_V1},
};

fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("test storage completes synchronously"),
    }
}

struct Object {
    bytes: Vec<u8>,
    digest: Digest,
    reads: AtomicUsize,
    max_read: AtomicUsize,
}
impl Object {
    fn new(bytes: Vec<u8>) -> Self {
        let digest = TERRANE_V1
            .calculate(IdentityKind::Chunk, &bytes)
            .expect("fixture plaintext chunk identity")
            .terrane_v1_digest()
            .expect("fixture digest profile");

        Self {
            bytes,
            digest,
            reads: AtomicUsize::new(0),
            max_read: AtomicUsize::new(0),
        }
    }
}
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl PlaintextObject for Object {
    fn digest(&self) -> Digest {
        self.digest
    }
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }
    async fn read_range(&self, offset: u64, length: usize) -> Result<Vec<u8>, Error> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.max_read.fetch_max(length, Ordering::Relaxed);
        let start = offset as usize;
        Ok(self
            .bytes
            .get(start..start + length)
            .ok_or(Error::InvalidRead)?
            .to_vec())
    }
}

struct Untrusted;
impl ProducerVerifier for Untrusted {
    fn verify(&self, _: &AttrRecord) -> Result<Option<ProducerEvidence>, Error> {
        Ok(None)
    }
}

struct MemoryStore {
    bytes: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
    reads: AtomicUsize,
    capabilities: Capabilities,
}
impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            bytes: Mutex::new(BTreeMap::new()),
            reads: AtomicUsize::new(0),
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::Ranges,
                presign: false,
                locality: Locality::default(),
                durability: Durability::Local,
                sealed: false,
            },
        }
    }
}
impl CapabilityReport for MemoryStore {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl ContentStore for MemoryStore {
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        let ContentUpload::Meta(meta) = upload else {
            panic!("test stores metadata only");
        };
        AttrRecord::decode(meta.bytes()).expect("storage format validator");
        let identity = TERRANE_V1
            .calculate(meta.kind(), meta.bytes())
            .expect("identity");
        self.bytes
            .lock()
            .expect("test mutex")
            .insert(identity.digest().to_vec(), meta.bytes().to_vec());
        Ok(identity)
    }
    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        assert!(range.is_none());
        self.reads.fetch_add(1, Ordering::Relaxed);
        Ok(self
            .bytes
            .lock()
            .expect("test mutex")
            .get(identity.digest())
            .expect("stored bytes")
            .clone())
    }
    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        Ok(identities
            .iter()
            .map(|i| {
                self.bytes
                    .lock()
                    .expect("test mutex")
                    .contains_key(i.digest())
            })
            .collect())
    }
    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        panic!("LIST must never supply authoritative catalog membership")
    }
}
struct Catalog(Vec<Identity>);
#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl AttributeCatalog for Catalog {
    async fn attribute_identities(&self) -> Result<Vec<Identity>, Error> {
        Ok(self.0.clone())
    }
}

#[test]
fn full_plaintext_hashing_streams_beyond_magic_bound() {
    let mut bytes = vec![b'a'; MAGIC_PREFIX_LIMIT + 123];
    bytes[MAGIC_PREFIX_LIMIT] = 0;
    let object = Object::new(bytes);
    let values = ready(compute(
        &object,
        &[
            AttributeName::Sha256,
            AttributeName::Sha512,
            AttributeName::GitBlobSha1,
            AttributeName::GitBlobSha256,
            AttributeName::Magic,
        ],
    ))
    .expect("compute");
    let mut expected = terrane_core::derived::PlaintextHashes::new(object.size());
    expected.update(&object.bytes).expect("plaintext");
    let hashes = expected.finish().expect("full length");
    assert_eq!(values[0], AttributeValue::Sha256(hashes.sha256));
    assert_eq!(values[1], AttributeValue::Sha512(hashes.sha512));
    assert_eq!(values[2], AttributeValue::GitBlobSha1(hashes.git_blob_sha1));
    assert_eq!(
        values[3],
        AttributeValue::GitBlobSha256(hashes.git_blob_sha256)
    );
    assert_eq!(values[4], AttributeValue::Magic(Magic::Text));
    assert_eq!(object.max_read.load(Ordering::Relaxed), MAGIC_PREFIX_LIMIT);
}

#[test]
fn magic_only_reads_one_bounded_prefix() {
    let object = Object::new(vec![b'a'; MAGIC_PREFIX_LIMIT * 3]);
    assert_eq!(
        ready(compute(&object, &[AttributeName::Magic])).expect("magic"),
        vec![AttributeValue::Magic(Magic::Text)]
    );
    assert_eq!(object.reads.load(Ordering::Relaxed), 1);
    assert_eq!(object.max_read.load(Ordering::Relaxed), MAGIC_PREFIX_LIMIT);
}

#[test]
fn side_table_rebuild_and_lookup_need_no_object_or_list_reads() {
    let store = MemoryStore::default();
    let object = Object::new(b"payload".to_vec());
    let record = AttrRecord::new(object.digest(), AttributeValue::Magic(Magic::Text), [2; 32]);
    let mut table = SideTable::new();
    let identity = ready(table.put(&store, record.clone(), &Untrusted)).expect("put");
    let mut rebuilt = ready(SideTable::rebuild(
        &store,
        &Catalog(vec![identity.clone()]),
        &Untrusted,
    ))
    .expect("rebuild");
    let reads = store.reads.load(Ordering::Relaxed);
    assert_eq!(
        rebuilt.current(object.digest(), AttributeName::Magic, false),
        Some(&record)
    );
    assert!(
        rebuilt
            .current(object.digest(), AttributeName::Magic, true)
            .is_none()
    );
    assert_eq!(rebuilt.trust(&identity), Some(Trust::Untrusted));
    assert_eq!(store.reads.load(Ordering::Relaxed), reads);
    assert_eq!(object.reads.load(Ordering::Relaxed), 0);
    ready(rebuilt.verify(&identity, &object)).expect("recompute");
    assert_eq!(object.reads.load(Ordering::Relaxed), 1);
    assert_eq!(rebuilt.trust(&identity), Some(Trust::Untrusted));
    assert!(rebuilt.producer_evidence(&identity).is_none());
    assert!(
        rebuilt
            .current(object.digest(), AttributeName::Magic, true)
            .is_none()
    );
}

#[test]
fn corrupt_records_are_quarantined_and_versions_producers_coexist() {
    let store = MemoryStore::default();
    let object = Object::new(b"payload".to_vec());
    let mut table = SideTable::new();
    let good = AttrRecord::new(object.digest(), AttributeValue::Magic(Magic::Text), [1; 32]);
    let mut old = good.clone();
    old.function.version = "0".to_owned();
    let mut other = good.clone();
    other.producer = [2; 32];
    for record in [&good, &old, &other] {
        ready(table.put(&store, record.clone(), &Untrusted)).expect("put distinct record");
    }
    for record in [&good, &old, &other] {
        assert_eq!(
            table.lookup(
                record.object,
                record.value.name(),
                &record.function,
                record.producer,
                false
            ),
            Some(record)
        );
    }
    let bad = AttrRecord::new(
        object.digest(),
        AttributeValue::Magic(Magic::Other),
        [3; 32],
    );
    let identity = ready(table.put(&store, bad.clone(), &Untrusted)).expect("put bad");
    assert!(ready(table.verify(&identity, &object)).is_err());
    assert_eq!(table.quarantined().len(), 1);
    assert!(
        table
            .lookup(
                bad.object,
                bad.value.name(),
                &bad.function,
                bad.producer,
                false
            )
            .is_none()
    );
    assert!(
        table
            .lookup(
                good.object,
                good.value.name(),
                &good.function,
                good.producer,
                false
            )
            .is_some()
    );
}

#[test]
fn malformed_record_catalog_entry_is_quarantined() {
    let store = MemoryStore::default();
    let bytes = b"not an AttrRecord".to_vec();
    let identity = TERRANE_V1
        .calculate(IdentityKind::Attribute, &bytes)
        .expect("identity");
    store
        .bytes
        .lock()
        .expect("mutex")
        .insert(identity.digest().to_vec(), bytes);
    let table = ready(SideTable::rebuild(
        &store,
        &Catalog(vec![identity.clone()]),
        &Untrusted,
    ))
    .expect("quarantine malformed record");
    assert_eq!(table.quarantined()[0].identity, identity);
}

#[test]
fn immutable_signature_variants_coexist_and_exact_quarantine_preserves_other_variant() {
    let store = MemoryStore::default();
    let object = Object::new(b"payload".to_vec());
    let unsigned = AttrRecord::new(object.digest(), AttributeValue::Magic(Magic::Text), [1; 32]);
    let mut signed = unsigned.clone();
    signed.signature = Some([3; 64]);
    let mut table = SideTable::new();
    let unsigned_id =
        ready(table.put(&store, unsigned.clone(), &Untrusted)).expect("legacy record");
    let signed_id = ready(table.put(&store, signed.clone(), &Untrusted)).expect("signed variant");
    assert_ne!(unsigned_id, signed_id);
    let mut bad = signed;
    bad.value = AttributeValue::Magic(Magic::Other);
    let bad_id = ready(table.put(&store, bad, &Untrusted)).expect("third exact variant");
    let catalog = Catalog(vec![unsigned_id.clone(), signed_id.clone(), bad_id.clone()]);
    let mut rebuilt =
        ready(SideTable::rebuild(&store, &catalog, &Untrusted)).expect("all variants retained");
    assert_eq!(rebuilt.trust(&unsigned_id), Some(Trust::Untrusted));
    assert_eq!(rebuilt.trust(&signed_id), Some(Trust::Untrusted));
    assert!(ready(rebuilt.verify(&bad_id, &object)).is_err());
    assert_eq!(rebuilt.quarantined()[0].identity, bad_id);
    assert_eq!(rebuilt.trust(&unsigned_id), Some(Trust::Untrusted));
    assert_eq!(rebuilt.trust(&signed_id), Some(Trust::Untrusted));
    assert!(
        rebuilt
            .lookup(
                unsigned.object,
                AttributeName::Magic,
                &unsigned.function,
                unsigned.producer,
                false
            )
            .is_some()
    );
    assert!(
        rebuilt
            .lookup(
                unsigned.object,
                AttributeName::Magic,
                &unsigned.function,
                unsigned.producer,
                true
            )
            .is_none()
    );
}

#[test]
fn requirements_include_conditional_detail_and_skip_metadata_hits() {
    let store = MemoryStore::default();
    let object = Object::new(b"#!/bin/env python3 -u\nprint(1)".to_vec());
    let mut table = SideTable::new();
    let requirements = Requirements {
        hashes: vec![AttributeName::Sha256],
        classify: vec![Magic::Elf, Magic::Shebang],
    };
    let values = ready(produce_required(
        &mut table,
        &store,
        &object,
        &requirements,
        [2; 32],
        &Untrusted,
        false,
    ))
    .expect("requirements");
    assert_eq!(
        values.iter().map(|r| r.value.name()).collect::<Vec<_>>(),
        vec![
            AttributeName::Sha256,
            AttributeName::Magic,
            AttributeName::Shebang
        ]
    );
    let reads = object.reads.load(Ordering::Relaxed);
    ready(produce_required(
        &mut table,
        &store,
        &object,
        &requirements,
        [3; 32],
        &Untrusted,
        false,
    ))
    .expect("all metadata hits");
    assert_eq!(object.reads.load(Ordering::Relaxed), reads);
    assert!(
        ready(produce_required(
            &mut table,
            &store,
            &object,
            &requirements,
            [3; 32],
            &Untrusted,
            true
        ))
        .is_err()
    );
}

#[test]
fn inline_copy_disagreement_is_rejected_for_all_producers() {
    let store = MemoryStore::default();
    let object = Object::new(b"payload".to_vec());
    let mut table = SideTable::new();
    let record = AttrRecord::new(object.digest(), AttributeValue::Magic(Magic::Text), [2; 32]);
    ready(table.put(&store, record.clone(), &Untrusted)).expect("put");
    assert!(
        table
            .agree_inline(
                object.digest(),
                AttributeName::Magic,
                &record.function,
                b"\x64text"
            )
            .is_ok()
    );
    assert!(
        table
            .agree_inline(
                object.digest(),
                AttributeName::Magic,
                &record.function,
                b"\x65other"
            )
            .is_err()
    );
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn elf_dynamic_linkage_resolves_checked_file_ranges() {
    let mut bytes = vec![0; 512];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    put16(&mut bytes, 16, 3);
    put16(&mut bytes, 18, 62);
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 32, 64);
    put16(&mut bytes, 52, 64);
    put16(&mut bytes, 54, 56);
    put16(&mut bytes, 56, 3);
    // LOAD maps the string table's virtual address; INTERP and DYNAMIC name file ranges.
    for (i, kind, offset, address, size) in [
        (0, 1, 0, 0x4000, 512),
        (1, 3, 256, 0, 11),
        (2, 2, 288, 0, 80),
    ] {
        let at = 64 + i * 56;
        put32(&mut bytes, at, kind);
        put64(&mut bytes, at + 8, offset);
        put64(&mut bytes, at + 16, address);
        put64(&mut bytes, at + 32, size);
        put64(&mut bytes, at + 40, size);
    }
    bytes[256..267].copy_from_slice(b"/ld.so.1\0\0\0");
    // Replace with an exact single-NUL interpreter range.
    put64(&mut bytes, 64 + 56 + 32, 9);
    put64(&mut bytes, 64 + 56 + 40, 9);
    for (i, tag, value) in [
        (0, 5, 0x4180),
        (1, 10, 24),
        (2, 1, 1),
        (3, 1, 11),
        (4, 0, 0),
    ] {
        put64(&mut bytes, 288 + i * 16, tag);
        put64(&mut bytes, 296 + i * 16, value);
    }
    bytes[384..405].copy_from_slice(b"\0libc.so.6\0libm.so.6\0");
    let object = Object::new(bytes);
    let values = ready(compute(&object, &[AttributeName::Elf])).expect("ELF linkage");
    let AttributeValue::Elf(value) = &values[0] else {
        panic!("ELF value");
    };
    assert_eq!(value.interpreter.as_deref(), Some("/ld.so.1"));
    assert_eq!(value.needed, vec!["libc.so.6", "libm.so.6"]);
    assert!(object.max_read.load(Ordering::Relaxed) <= MAGIC_PREFIX_LIMIT);
}

#[test]
fn store_object_reassembles_verified_chunks_in_manifest_order() {
    use terrane_core::{
        chunking::ChunkProfile,
        manifest::{ChunkRef, Manifest},
        tree_format::ContentRef,
    };

    let store = MemoryStore::default();
    let profile = ChunkProfile::new(16, 64, 128, 48, 1, [3; 32]).expect("test chunk profile");
    let plaintext: Vec<u8> = (0..513).map(|index| (index % 251) as u8).collect();
    let mut chunks = Vec::new();
    for range in profile.ranges(&plaintext) {
        let bytes = &plaintext[range];
        let identity = TERRANE_V1
            .calculate(IdentityKind::Chunk, bytes)
            .expect("chunk identity");
        let encoded =
            crate::codec::encode_chunk(bytes, profile.maximum(), 3, None).expect("chunk codec");
        store
            .bytes
            .lock()
            .expect("test mutex")
            .insert(identity.digest().to_vec(), encoded);
        chunks.push(ChunkRef {
            digest: identity.terrane_v1_digest().expect("digest"),
            length: bytes.len() as u64,
        });
    }
    assert!(chunks.len() > 2);
    // Manifest hash declarations are deliberately unrelated: secondary producers
    // must consume actual verified plaintext rather than copying declarations.
    let manifest = Manifest {
        size: plaintext.len() as u64,
        chunks,
        hashes: std::collections::BTreeMap::from([
            ("blake3".to_owned(), vec![0; 32]),
            ("sha256".to_owned(), vec![0; 32]),
        ]),
        media_type: None,
    };
    let encoded = manifest.encode(&profile).expect("manifest schema");
    let identity = manifest.identity(&profile).expect("manifest identity");
    store
        .bytes
        .lock()
        .expect("test mutex")
        .insert(identity.digest().to_vec(), encoded);
    let object = ready(StoreObject::open(
        &store,
        &NoDictionaries,
        &profile,
        ContentRef::Manifest(identity.terrane_v1_digest().expect("digest")),
        plaintext.len() as u64,
    ))
    .expect("open verified manifest");

    assert_eq!(
        ready(object.read_range(7, 500)).expect("cross-chunk read"),
        plaintext[7..507]
    );
    let produced = ready(compute(
        &object,
        &[AttributeName::Sha256, AttributeName::GitBlobSha1],
    ))
    .expect("full plaintext hashes");
    let mut hashes = terrane_core::derived::PlaintextHashes::new(plaintext.len() as u64);
    hashes.update(&plaintext).expect("expected input");
    let expected = hashes.finish().expect("expected digests");
    assert_eq!(
        produced,
        vec![
            AttributeValue::Sha256(expected.sha256),
            AttributeValue::GitBlobSha1(expected.git_blob_sha1)
        ]
    );
}

#[test]
fn verification_quarantines_an_executable_record_for_non_executable_bytes() {
    let store = MemoryStore::default();
    let object = Object::new(b"text".to_vec());
    let value = AttributeValue::Elf(terrane_core::derived::ElfValue {
        class: 64,
        machine: 62,
        elf_type: 3,
        interpreter: None,
        needed: Vec::new(),
    });
    let record = AttrRecord::new(object.digest(), value, [1; 32]);
    let mut table = SideTable::new();
    let identity =
        ready(table.put(&store, record.clone(), &Untrusted)).expect("canonical supplied record");

    assert!(ready(table.verify(&identity, &object)).is_err());
    assert_eq!(table.quarantined().len(), 1);
    assert!(
        table
            .lookup(
                record.object,
                record.value.name(),
                &record.function,
                record.producer,
                false
            )
            .is_none()
    );
}

#[test]
fn effective_requirements_produce_records_accepted_by_changed_entry_validation() {
    use terrane_core::{
        cbor,
        properties::{
            Defaults, DerivedAttribute, Domain, EntryChange, RootLayer, resolve, validate_commit,
        },
        tree_format::{Attribute, ContentRef, Entry, EntryKind, Property},
    };

    let mut hashes = Vec::new();
    cbor::write_array(&mut hashes, 2);
    for name in ["sha256", "git-blob-sha1"] {
        cbor::write_text(&mut hashes, name);
    }
    let mut classifiers = Vec::new();
    cbor::write_array(&mut classifiers, 2);
    for name in ["elf", "shebang"] {
        cbor::write_text(&mut classifiers, name);
    }
    let properties = [
        Property {
            name: "hashes",
            value: &hashes,
        },
        Property {
            name: "classify",
            value: &classifiers,
        },
    ];
    let policy = resolve(
        &[RootLayer {
            properties: &properties,
            overrides: &[],
        }],
        Defaults {
            store: "local",
            private_domain: "private:root",
            home: "local",
        },
    )
    .expect("effective requirements");
    let requirements = Requirements::from_effective(&policy).expect("typed requirements");
    let object = Object::new(b"#!/bin/bash -eu\nprintf ready".to_vec());
    let store = MemoryStore::default();
    let mut table = SideTable::new();
    let records = ready(produce_required(
        &mut table,
        &store,
        &object,
        &requirements,
        [2; 32],
        &Untrusted,
        false,
    ))
    .expect("all effective requirements");
    let encoded: Vec<_> = records
        .iter()
        .map(|record| record.value.encode().expect("typed inline encoding"))
        .collect();
    let derived: Vec<_> = records
        .iter()
        .zip(&encoded)
        .map(|(record, value)| DerivedAttribute {
            object: record.object,
            attribute: Attribute {
                name: record.value.name().as_str(),
                value,
            },
        })
        .collect();
    let entry = Entry {
        kind: EntryKind::File {
            mode: 0o644,
            size: object.size(),
            content: ContentRef::Inline(object.digest()),
            link_id: None,
        },
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    };
    let change = EntryChange {
        entry: &entry,
        properties: &policy,
        reference_domains: &[Domain::Private("root")],
        graft_properties: None,
    };

    assert_eq!(validate_commit(&[change], &derived), Ok(()));
    let missing_shebang: Vec<_> = derived
        .iter()
        .filter(|attribute| attribute.attribute.name != "class.shebang")
        .cloned()
        .collect();
    assert_eq!(
        validate_commit(&[change], &missing_shebang),
        Err(terrane_core::properties::Error::MissingAttribute)
    );
}

#[test]
fn magic_classification_has_no_whole_object_size_cap() {
    struct Large;

    #[cfg_attr(feature = "send", async_trait::async_trait)]
    #[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
    impl PlaintextObject for Large {
        fn digest(&self) -> Digest {
            [9; 32]
        }
        fn size(&self) -> u64 {
            u64::MAX
        }
        async fn read_range(&self, offset: u64, length: usize) -> Result<Vec<u8>, Error> {
            assert_eq!(offset, 0);
            assert_eq!(length, MAGIC_PREFIX_LIMIT);
            Ok(vec![b'a'; length])
        }
    }

    assert_eq!(
        ready(compute(&Large, &[AttributeName::Magic])).expect("bounded prefix on large object"),
        vec![AttributeValue::Magic(Magic::Text)]
    );
}
