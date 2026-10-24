//! Tests portable residence composition over actual ordinary host directories.
//!
//! The residence input below is deliberately synthetic. These tests establish
//! adapter verification and routing, not adopted publisher descriptors, retained
//! canonical manifests, durable pins, recovery or native domain custody.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use super::{Fixture, access, snapshot};
use crate::host::cache::{DomainHostLayout, HostResidenceReader, ResidenceChunk};
use crate::store::shared_dir::ResidentSharedDirRoutes;
use crate::store::{
    ByteRange, ContentStore, ContentUpload, IdentityPrefix, MetaUpload, StoreErrorKind,
    StoreFailure,
};
use terrane_format::identity::{Identity, IdentityKind, TERRANE_V1};

struct PortableResidence {
    domain: String,
    identity: Identity,
    plaintext: Vec<u8>,
    reads: Arc<AtomicUsize>,
}

impl PortableResidence {
    fn new(domain: &str, plaintext: &[u8]) -> Self {
        Self {
            domain: domain.into(),
            identity: TERRANE_V1
                .calculate(IdentityKind::Chunk, plaintext)
                .unwrap(),
            plaintext: plaintext.to_vec(),
            reads: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl HostResidenceReader for PortableResidence {
    async fn read_chunk(
        &self,
        layout: &DomainHostLayout,
        identity: &Identity,
        max_plaintext_bytes: usize,
    ) -> Result<Option<ResidenceChunk>, StoreFailure> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if layout.domain_binding().domain != self.domain {
            return Err(StoreFailure::new(StoreErrorKind::Denied {
                verb: "read",
                pattern: self.domain.clone(),
            }));
        }
        if identity != &self.identity {
            return Ok(None);
        }
        if self.plaintext.len() > max_plaintext_bytes {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }

        Ok(Some(ResidenceChunk {
            plaintext: self.plaintext.clone(),
            final_chunk: true,
        }))
    }

    async fn chunk_identities(
        &self,
        _layout: &DomainHostLayout,
        max_entries: usize,
    ) -> Result<Vec<Identity>, StoreFailure> {
        if max_entries == 0 {
            return Err(StoreFailure::new(StoreErrorKind::Capacity));
        }

        Ok(vec![self.identity.clone()])
    }
}

#[tokio::test]
async fn portable_composition_recovers_encoded_chunk_after_ordinary_body_removal() {
    let fixture = Fixture::new();
    let root = fixture.domain_root("public");
    let plaintext = b"portable residence bytes";
    let (identity, encoded, path) = fixture.chunk(&root, plaintext);
    std::fs::remove_file(path).unwrap();
    let residence = PortableResidence::new("public", plaintext);
    let reads = residence.reads.clone();
    let ordinary = fixture.open(root, "public").await;
    let view = ordinary.with_residences(residence, 8).unwrap();
    let before = snapshot(&fixture.root);

    assert_eq!(view.get(&identity, None).await.unwrap(), encoded);
    assert_eq!(
        view.has(&[identity.clone(), identity.clone()])
            .await
            .unwrap(),
        [true, true]
    );
    assert_eq!(
        view.get(
            &identity,
            Some(ByteRange {
                start: 1,
                length: 8
            })
        )
        .await
        .unwrap(),
        &plaintext[..8]
    );
    assert_eq!(
        view.list(&IdentityPrefix {
            kind: IdentityKind::Chunk,
            digest_prefix: Vec::new()
        })
        .await
        .unwrap(),
        [identity]
    );
    let reads_before_put = reads.load(Ordering::Relaxed);
    let upload = MetaUpload::new(IdentityKind::Policy, b"not admitted").unwrap();
    assert_eq!(
        view.put(ContentUpload::Meta(upload))
            .await
            .unwrap_err()
            .kind(),
        &StoreErrorKind::ReadOnly
    );
    assert_eq!(reads.load(Ordering::Relaxed), reads_before_put);
    assert_eq!(snapshot(&fixture.root), before);
}

#[tokio::test]
async fn portable_resident_routes_preserve_domain_and_reachability_before_lookup() {
    let fixture = Fixture::new();
    let root = fixture.domain_root("tenant-a");
    let residence = PortableResidence::new("tenant:a", b"scoped residence");
    let identity = residence.identity.clone();
    let reads = residence.reads.clone();
    let view = fixture
        .open(root, "tenant:a")
        .await
        .with_residences(residence, 8)
        .unwrap();
    let routes = ResidentSharedDirRoutes::new(vec![view]).unwrap();

    assert_eq!(
        routes
            .has(&access("tenant:a", &[]), std::slice::from_ref(&identity))
            .await
            .unwrap(),
        [false]
    );
    assert!(matches!(
        routes
            .get(
                &access("tenant:b", std::slice::from_ref(&identity)),
                &identity,
                None
            )
            .await
            .unwrap_err()
            .kind(),
        StoreErrorKind::Denied { .. }
    ));
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    assert_eq!(
        routes
            .has(
                &access("tenant:a", std::slice::from_ref(&identity)),
                &[identity]
            )
            .await
            .unwrap(),
        [true]
    );
    assert_eq!(reads.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn portable_residence_never_masks_corruption_or_substitutes_manifest_plaintext() {
    let fixture = Fixture::new();
    let root = fixture.domain_root("public");
    let (identity, _, path) = fixture.chunk(&root, b"original chunk");
    let mut residence = PortableResidence::new("public", b"original chunk");
    residence.plaintext = b"wrong residence".to_vec();
    let reads = residence.reads.clone();
    let view = fixture
        .open(root, "public")
        .await
        .with_residences(residence, 8)
        .unwrap();
    std::fs::write(&path, b"\0corrupt ordinary body").unwrap();

    assert!(matches!(
        view.get(&identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Corrupt(_)
    ));
    assert_eq!(reads.load(Ordering::Relaxed), 0);
    std::fs::remove_file(path).unwrap();
    assert!(matches!(
        view.get(&identity, None).await.unwrap_err().kind(),
        StoreErrorKind::Corrupt(_)
    ));
    assert_eq!(reads.load(Ordering::Relaxed), 1);
    let manifest = TERRANE_V1
        .calculate(IdentityKind::Manifest, b"not a chunk")
        .unwrap();
    assert!(matches!(
        view.get(&manifest, None).await.unwrap_err().kind(),
        StoreErrorKind::Absent(_)
    ));
    assert_eq!(reads.load(Ordering::Relaxed), 1);
}
