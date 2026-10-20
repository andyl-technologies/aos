//! Qualifies per-object attribute get/put through the public SDK alone.
#![allow(
    clippy::expect_used,
    reason = "Fixture construction and failed assertions intentionally panic."
)]

use std::{
    cmp,
    collections::BTreeMap,
    error::Error as _,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use terrane_format::{
    auth::{Authority, Grant, IssuerKey, Request, Token, Verb, Verbs},
    chunking::ChunkProfile,
    derived::{AttrRecord, AttributeName, AttributeValue, Function, Magic},
    identity::{Digest, Identity, IdentityKind, TERRANE_V1},
    provenance::{EntryLocation, VerifiedHistory, sign},
    refs::{Commit, CommitSource, Locality, PrincipalKind, ProfilePair, Provenance},
    tree_format::{ContentRef, Entry, EntryKind, LeafItem, Node, NodeItems, encode_node},
};
use terrane_sdk::{
    derived::{
        Error, PlaintextObject, ProducerEvidence, ProducerVerifier, SideTable, Trust, compute,
    },
    repository::MetadataValidator,
    store::{
        ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, ContentValidator,
        CorruptSubject, Durability, IdentityPrefix, RangeCapability, RefCapability, StoreErrorKind,
        StoreFailure,
    },
};

/// Polls the injected synchronous fixture operations without a runtime binding.
fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());

    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("fixture I/O completes synchronously"),
    }
}

struct Object {
    bytes: Vec<u8>,
    digest: Digest,
    reads: AtomicUsize,
}

impl Object {
    fn new(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            digest: TERRANE_V1
                .calculate(IdentityKind::Chunk, bytes)
                .expect("inline chunk identity")
                .terrane_v1_digest()
                .expect("v1 digest"),
            reads: AtomicUsize::new(0),
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
        let start = usize::try_from(offset).map_err(|_| Error::InvalidRead)?;
        let end = start.checked_add(length).ok_or(Error::InvalidRead)?;

        self.bytes
            .get(start..end)
            .map(<[u8]>::to_vec)
            .ok_or(Error::InvalidRead)
    }
}

/// Orders fixture keys without changing the public identity representation.
#[derive(Eq, PartialEq)]
struct OrderedIdentity(Identity);

impl Ord for OrderedIdentity {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        // Discriminants distinguish kinds only within this private in-memory
        // ordering. All public identity fields participate in equality.
        (self.0.profile(), self.0.kind() as u8, self.0.digest()).cmp(&(
            other.0.profile(),
            other.0.kind() as u8,
            other.0.digest(),
        ))
    }
}

impl PartialOrd for OrderedIdentity {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Owns opaque immutable metadata and injects a real admission failure.
struct MetadataStore {
    bytes: Mutex<BTreeMap<OrderedIdentity, Vec<u8>>>,
    validator: MetadataValidator,
    capabilities: Capabilities,
    reads: AtomicUsize,
    writes: AtomicUsize,
    unavailable: AtomicBool,
}

impl MetadataStore {
    fn new() -> Self {
        Self {
            bytes: Mutex::new(BTreeMap::new()),
            validator: MetadataValidator::new(ChunkProfile::cdc_1m([0; 32])),
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::WholeObjectOnly,
                presign: false,
                locality: Locality::default(),
                durability: Durability::Local,
                sealed: false,
            },
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            unavailable: AtomicBool::new(false),
        }
    }
}

impl CapabilityReport for MetadataStore {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl ContentStore for MetadataStore {
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        let ContentUpload::Meta(meta) = upload else {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        };
        if meta.kind() != IdentityKind::Attribute {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        self.validator.validate_meta(&meta)?;
        let identity = TERRANE_V1
            .calculate(meta.kind(), meta.bytes())
            .map_err(|error| StoreFailure::with_source(StoreErrorKind::Unsupported, error))?;

        let mut bytes = self.bytes.lock().expect("fixture mutex");
        let key = OrderedIdentity(identity.clone());
        if bytes.contains_key(&key) {
            return Ok(identity);
        }
        if self.unavailable.load(Ordering::Relaxed) {
            return Err(StoreFailure::with_source(
                StoreErrorKind::Unavailable {
                    retry_after: Some(Duration::from_secs(17)),
                },
                std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "metadata admission unavailable",
                ),
            ));
        }

        bytes.insert(key, meta.bytes().to_vec());
        Ok(identity)
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if range.is_some() {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let bytes = self
            .bytes
            .lock()
            .expect("fixture mutex")
            .get(&OrderedIdentity(identity.clone()))
            .cloned()
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Absent(identity.clone())))?;
        TERRANE_V1.verify(identity, &bytes).map_err(|error| {
            StoreFailure::with_source(
                StoreErrorKind::Corrupt(CorruptSubject::Identity(identity.clone())),
                error,
            )
        })?;

        Ok(bytes)
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        let bytes = self.bytes.lock().expect("fixture mutex");
        Ok(identities
            .iter()
            .map(|id| bytes.contains_key(&OrderedIdentity(id.clone())))
            .collect())
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        Ok(self
            .bytes
            .lock()
            .expect("fixture mutex")
            .keys()
            .map(|key| &key.0)
            .filter(|id| id.kind() == prefix.kind && id.digest().starts_with(&prefix.digest_prefix))
            .cloned()
            .collect())
    }
}

struct CheckedProducer {
    history: VerifiedHistory,
    location: EntryLocation,
}

impl ProducerVerifier for CheckedProducer {
    fn verify(&self, record: &AttrRecord) -> Result<Option<ProducerEvidence>, Error> {
        ProducerEvidence::from_history(record, &self.history, &self.location).map(Some)
    }
}

struct Untrusted;

impl ProducerVerifier for Untrusted {
    fn verify(&self, _record: &AttrRecord) -> Result<Option<ProducerEvidence>, Error> {
        Ok(None)
    }
}

// RFC 8032 vector 1 provides public fixture keys, not configured credentials.
fn vector<const N: usize>(hex: &str) -> [u8; N] {
    let mut bytes = [0; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("fixture hex");
    }
    bytes
}

/// Signs a finalized producer and retains its canonical object-tree witness.
fn signed_record(
    object: &Object,
    value: AttributeValue,
    process: &str,
) -> (AttrRecord, CheckedProducer) {
    let secret = vector("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = vector("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let node = Node {
        level: 0,
        items: NodeItems::Leaf(vec![LeafItem {
            key: b"file".to_vec(),
            entry: Entry {
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
            },
        }]),
        props: None,
    };
    let bytes = encode_node(&node, true, 262144).expect("canonical object witness");
    let root = TERRANE_V1
        .calculate(IdentityKind::Node, &bytes)
        .expect("tree identity")
        .terrane_v1_digest()
        .expect("tree digest");
    let token = Token::issue(
        Authority {
            issuer: "issuer".to_owned(),
            key_id: "key".to_owned(),
            subject: "producer".to_owned(),
            kind: PrincipalKind::Workload,
            groups: vec!["baseline".to_owned()],
            not_after: 200,
            not_before: Some(50),
            token_id: [3; 16],
            grants: vec![
                Grant::new(
                    "refs/heads/main".to_owned(),
                    Verbs::new(4).expect("commit bit"),
                )
                .expect("commit grant"),
            ],
            workload: Some("job".to_owned()),
        },
        &secret,
        public,
    )
    .expect("fixture token");
    let commit = Commit {
        tree: root,
        parents: Vec::new(),
        provenance: Provenance {
            issuer: "issuer".to_owned(),
            token_id: [3; 16],
            subject: "producer".to_owned(),
            kind: PrincipalKind::Workload,
            workload_identity: Some("job".to_owned()),
            process: process.to_owned(),
            observed_at: 100,
            writer_epoch: 4,
            source: CommitSource::Derived,
            embedded_token: Some(token.encode()),
        },
        timestamp: 100,
        message: "Compute side attributes".to_owned(),
        profile_pair: ProfilePair {
            tree_format: 1,
            chunk_profile: "default".to_owned(),
            recipe: None,
            conflicted: None,
            lease: None,
            required_properties: None,
            commit_context: None,
            entry_receipts: None,
        },
        packs: None,
        signature: None,
    };
    let locality = Locality::default();
    let request = Request {
        reference: b"refs/heads/main",
        verb: Verb::Commit,
        roots: &[],
        now: 100,
        surface: "sdk",
        locality: &locality,
        epochs: &[("refs/heads/main", 4)],
    };
    let commit = sign(
        commit,
        &secret,
        &[IssuerKey {
            issuer: "issuer".to_owned(),
            key_id: "key".to_owned(),
            public_key: public,
            retirement: None,
        }],
        &request,
        4,
    )
    .expect("verified finalized producer");
    let location = EntryLocation {
        commit: commit.identity(),
        root,
        path: b"file".to_vec(),
    };
    let mut history = VerifiedHistory::new(262144);
    history
        .insert_commit(commit.clone())
        .expect("producer history");
    history
        .insert_tree(root, &[(root, bytes)])
        .expect("tree witness");
    let mut record = AttrRecord::new(object.digest(), value, commit.identity());
    record
        .sign(&commit, &secret)
        .expect("detached record signature");

    (record, CheckedProducer { history, location })
}

#[test]
fn public_attrs_get_put_preserves_provenance_and_storage_errors() {
    let object = Object::new(b"attribute SDK plaintext\n");
    let computed =
        ready(compute(&object, &[AttributeName::Magic])).expect("plaintext classification");
    assert_eq!(computed, vec![AttributeValue::Magic(Magic::Text)]);
    let (first, first_verifier) = signed_record(&object, computed[0].clone(), "first-producer");
    let (second, second_verifier) = signed_record(&object, computed[0].clone(), "second-producer");
    let store = MetadataStore::new();
    let mut attrs = SideTable::new();

    let first_id =
        ready(attrs.put(&store, first.clone(), &first_verifier)).expect("first producer");
    let second_id =
        ready(attrs.put(&store, second.clone(), &second_verifier)).expect("second producer");
    assert_eq!(first.value, second.value);
    assert_eq!(first.function, second.function);
    assert_ne!(first.producer, second.producer);
    assert_ne!(first_id, second_id);
    assert_eq!(first_id.kind(), IdentityKind::Attribute);
    assert_eq!(
        first_id,
        first.identity().expect("canonical record identity")
    );
    let stored = ready(store.get(&first_id, None)).expect("published metadata");
    assert_eq!(stored, first.encode().expect("canonical record bytes"));
    assert_eq!(
        AttrRecord::decode(&stored).expect("public record decoder"),
        first
    );

    let mut unsigned = first.clone();
    unsigned.signature = None;
    let unsigned_id =
        ready(attrs.put(&store, unsigned.clone(), &Untrusted)).expect("untrusted record");
    let mut future = first.clone();
    future.function.version = "2".to_owned();
    future.signature = None;
    let future_id =
        ready(attrs.put(&store, future.clone(), &Untrusted)).expect("retained future version");
    assert_eq!(attrs.trust(&unsigned_id), Some(Trust::Untrusted));
    assert_eq!(attrs.trust(&future_id), Some(Trust::Untrusted));
    assert!(attrs.producer_evidence(&unsigned_id).is_none());
    assert!(attrs.producer_evidence(&future_id).is_none());

    let plaintext_reads = object.reads.load(Ordering::Relaxed);
    let storage_reads = store.reads.load(Ordering::Relaxed);
    let writes = store.writes.load(Ordering::Relaxed);
    for (record, identity, verifier) in [
        (&first, &first_id, &first_verifier),
        (&second, &second_id, &second_verifier),
    ] {
        assert_eq!(
            attrs.get(
                object.digest(),
                AttributeName::Magic,
                &record.function,
                record.producer,
                true
            ),
            Some(record)
        );
        assert_eq!(attrs.trust(identity), Some(Trust::VerifiedProducer));
        let evidence = attrs
            .producer_evidence(identity)
            .expect("independent producer witness");
        assert_eq!(evidence.record(), identity);
        assert_eq!(evidence.producer(), &record.producer);
        assert_eq!(evidence.object(), &object.digest());
        assert_eq!(evidence.function(), &record.function);
        assert_eq!(evidence.location(), &verifier.location);
        assert_eq!(
            evidence.value(),
            record.value.encode().expect("checked value")
        );
    }
    assert_eq!(
        attrs.get(
            object.digest(),
            AttributeName::Magic,
            &future.function,
            first.producer,
            false
        ),
        Some(&future)
    );
    assert!(
        attrs
            .get(
                object.digest(),
                AttributeName::Magic,
                &future.function,
                first.producer,
                true
            )
            .is_none()
    );
    for (object, name, function, producer) in [
        (
            [9; 32],
            AttributeName::Magic,
            first.function.clone(),
            first.producer,
        ),
        (
            object.digest(),
            AttributeName::Sha256,
            first.function.clone(),
            first.producer,
        ),
        (
            object.digest(),
            AttributeName::Magic,
            Function {
                name: "other".to_owned(),
                version: "1".to_owned(),
            },
            first.producer,
        ),
        (
            object.digest(),
            AttributeName::Magic,
            Function {
                name: "magic".to_owned(),
                version: "3".to_owned(),
            },
            first.producer,
        ),
        (
            object.digest(),
            AttributeName::Magic,
            first.function.clone(),
            [9; 32],
        ),
    ] {
        assert!(
            attrs
                .get(object, name, &function, producer, false)
                .is_none()
        );
    }
    assert_eq!(object.reads.load(Ordering::Relaxed), plaintext_reads);
    assert_eq!(store.reads.load(Ordering::Relaxed), storage_reads);
    assert_eq!(store.writes.load(Ordering::Relaxed), writes);

    // Successful recomputation does not authenticate an unsigned producer.
    let mut untrusted_attrs = SideTable::new();
    ready(untrusted_attrs.put(&store, unsigned.clone(), &Untrusted)).expect("unsigned publication");
    ready(untrusted_attrs.verify(&unsigned_id, &object)).expect("same computed value");
    assert_eq!(
        untrusted_attrs.get(
            object.digest(),
            AttributeName::Magic,
            &unsigned.function,
            unsigned.producer,
            false
        ),
        Some(&unsigned)
    );
    assert!(
        untrusted_attrs
            .get(
                object.digest(),
                AttributeName::Magic,
                &unsigned.function,
                unsigned.producer,
                true
            )
            .is_none()
    );
    assert_eq!(untrusted_attrs.trust(&unsigned_id), Some(Trust::Untrusted));
    assert!(untrusted_attrs.producer_evidence(&unsigned_id).is_none());

    let (failed, failed_verifier) = signed_record(&object, computed[0].clone(), "failed-producer");
    let failed_id = failed.identity().expect("failed candidate identity");
    store.unavailable.store(true, Ordering::Relaxed);
    let writes = store.writes.load(Ordering::Relaxed);
    let failure = ready(attrs.put(&store, failed.clone(), &failed_verifier))
        .expect_err("actual admission failure");
    let Error::Store(failure) = failure else {
        panic!("SDK must preserve the typed storage failure");
    };
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Unavailable {
            retry_after: Some(Duration::from_secs(17))
        }
    );
    assert_eq!(
        failure
            .source()
            .expect("backend source")
            .downcast_ref::<std::io::Error>()
            .expect("typed backend diagnostic")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(store.writes.load(Ordering::Relaxed), writes + 1);
    assert_eq!(
        ready(store.has(std::slice::from_ref(&failed_id))).expect("membership"),
        vec![false]
    );
    assert!(
        attrs
            .get(
                object.digest(),
                AttributeName::Magic,
                &failed.function,
                failed.producer,
                false
            )
            .is_none()
    );
    assert!(attrs.trust(&failed_id).is_none());
    assert!(attrs.producer_evidence(&failed_id).is_none());

    // Invalid signed evidence must fail before even attempting publication.
    store.unavailable.store(false, Ordering::Relaxed);
    let mut invalid = failed.clone();
    invalid.signature.as_mut().expect("detached signature")[0] ^= 1;
    let invalid_id = invalid
        .identity()
        .expect("invalid evidence record identity");
    let writes = store.writes.load(Ordering::Relaxed);
    assert!(matches!(
        ready(attrs.put(&store, invalid, &failed_verifier)),
        Err(Error::Derived(
            terrane_format::derived::Error::InvalidProvenance
        ))
    ));
    assert_eq!(store.writes.load(Ordering::Relaxed), writes);
    assert_eq!(
        ready(store.has(std::slice::from_ref(&invalid_id))).expect("membership"),
        vec![false]
    );
    assert!(attrs.trust(&invalid_id).is_none());
    assert!(attrs.producer_evidence(&invalid_id).is_none());
    assert_eq!(
        attrs.get(
            object.digest(),
            AttributeName::Magic,
            &first.function,
            first.producer,
            true
        ),
        Some(&first)
    );
    assert!(attrs.quarantined().is_empty());
}
