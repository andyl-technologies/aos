//! Exercises portable ordering and identity failures independently of kernel proof.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{self, Cursor};
use std::sync::{Arc, Mutex};

use terrane_format::chunking::ChunkProfile;
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_sdk::host::publication::{
    PublicationClaim, PublicationKernel, PublicationRecipe, PublicationState, Publisher,
    VerityBinding,
};

fn run<F: std::future::Future>(future: F) -> F::Output {
    struct WakeThread(std::thread::Thread);
    impl std::task::Wake for WakeThread {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = std::task::Waker::from(std::sync::Arc::new(WakeThread(std::thread::current())));
    let mut context = std::task::Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(value) => return value,
            std::task::Poll::Pending => std::thread::park(),
        }
    }
}

type Events = Arc<Mutex<Vec<&'static str>>>;

fn claim(bytes: &[u8]) -> PublicationClaim {
    let identity = TERRANE_V1.calculate(IdentityKind::Chunk, bytes).unwrap();
    let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, bytes).unwrap();
    PublicationClaim::new(
        "public".into(),
        PublicationRecipe::Inline { chunk: descriptor },
        &ChunkProfile::cdc_1m([0; 32]),
    )
    .unwrap()
}

fn binding() -> VerityBinding {
    VerityBinding {
        algorithm: 1,
        digest: vec![1; 32],
    }
}

struct State {
    events: Events,
    fail: bool,
    recorded: Option<VerityBinding>,
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl PublicationState for State {
    async fn binding(&self, _: &PublicationClaim) -> io::Result<Option<VerityBinding>> {
        Ok(self.recorded.clone())
    }

    async fn record(&mut self, _: &PublicationClaim, value: &VerityBinding) -> io::Result<()> {
        self.events.lock().unwrap().push("state");
        if self.fail {
            return Err(io::Error::other("state fault"));
        }
        self.recorded = Some(value.clone());
        Ok(())
    }
}

struct Kernel {
    events: Events,
    bytes: Vec<u8>,
    exists: bool,
    sealed: bool,
    fail: Option<&'static str>,
}

impl Kernel {
    fn event(&self, event: &'static str) -> io::Result<()> {
        self.events.lock().unwrap().push(event);
        if self.fail == Some(event) {
            return Err(io::Error::other(event));
        }
        Ok(())
    }
}

impl PublicationKernel for Kernel {
    type Source = Vec<u8>;
    type Staged = Cursor<Vec<u8>>;
    type Handle = Cursor<Vec<u8>>;

    fn stage(&mut self, _: &PublicationClaim, bytes: Vec<u8>) -> io::Result<Self::Staged> {
        self.event("stage")?;
        self.bytes = bytes.clone();
        Ok(Cursor::new(bytes))
    }

    fn close_writers(&mut self, _: &mut Self::Staged) -> io::Result<()> {
        self.event("close")
    }

    fn seal(&mut self, _: &Self::Staged) -> io::Result<VerityBinding> {
        self.event("seal")?;
        self.sealed = true;
        Ok(binding())
    }

    fn sync_staged(&mut self, _: &Self::Staged) -> io::Result<()> {
        self.event("file-sync")
    }

    fn insert(&mut self, _: &PublicationClaim, _: &Self::Staged) -> io::Result<bool> {
        self.event("insert")?;
        let inserted = !self.exists;
        self.exists = true;
        Ok(inserted)
    }

    fn sync_parent(&mut self, _: &PublicationClaim) -> io::Result<()> {
        self.event("parent-sync")
    }

    fn rollback(&mut self, _: &PublicationClaim, _: &Self::Staged) -> io::Result<()> {
        self.event("rollback")?;
        self.exists = false;
        Ok(())
    }

    fn open(&mut self, _: &PublicationClaim) -> io::Result<Self::Handle> {
        self.event("open")?;
        Ok(Cursor::new(self.bytes.clone()))
    }

    fn measure(&mut self, _: &Self::Handle) -> io::Result<VerityBinding> {
        self.event("measure")?;
        if !self.sealed {
            return Err(io::Error::other("not sealed"));
        }
        Ok(binding())
    }

    fn retain_staged(&mut self, staged: &Self::Staged) -> io::Result<Self::Handle> {
        self.event("retain-staged")?;
        Ok(staged.clone())
    }

    fn duplicate_handle(&mut self, handle: &Self::Handle) -> io::Result<Self::Handle> {
        self.event("retain-existing")?;
        Ok(handle.clone())
    }

    fn sync_handle(&mut self, _: &Self::Handle) -> io::Result<()> {
        self.event("adopt-file-sync")
    }
}

fn publisher(fail: Option<&'static str>, state_fail: bool) -> (Publisher<Kernel, State>, Events) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let kernel = Kernel {
        events: Arc::clone(&events),
        bytes: Vec::new(),
        exists: false,
        sealed: false,
        fail,
    };
    let state = State {
        events: Arc::clone(&events),
        fail: state_fail,
        recorded: None,
    };
    (Publisher::new(kernel, state), events)
}

#[test]
fn publication_orders_close_seal_sync_link_parent_and_state() {
    let (mut publisher, events) = publisher(None, false);
    run(publisher.publish(&claim(b"hello"), b"hello".to_vec())).unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        [
            "stage",
            "close",
            "seal",
            "file-sync",
            "insert",
            "parent-sync",
            "state",
            "open",
            "measure"
        ]
    );
}

#[test]
fn invalid_plaintext_never_closes_seals_or_inserts() {
    let (mut publisher, events) = publisher(None, false);
    assert!(run(publisher.publish(&claim(b"hello"), b"wrong".to_vec())).is_err());
    assert_eq!(*events.lock().unwrap(), ["stage"]);
}

#[test]
fn prepublication_faults_leave_no_canonical_name() {
    for phase in ["stage", "close", "seal", "file-sync", "insert"] {
        let (mut publisher, _) = publisher(Some(phase), false);
        assert!(run(publisher.publish(&claim(b"hello"), b"hello".to_vec())).is_err());
        let (kernel, _) = publisher.into_parts();
        assert!(!kernel.exists, "phase {phase}");
    }
}

#[test]
fn parent_sync_failure_withholds_handle_and_rolls_back() {
    let (mut publisher, events) = publisher(Some("parent-sync"), false);
    assert!(run(publisher.publish(&claim(b"hello"), b"hello".to_vec())).is_err());
    assert_eq!(events.lock().unwrap().last(), Some(&"rollback"));
    assert!(!publisher.into_parts().0.exists);
}

#[test]
fn binding_failure_withholds_handle_and_rolls_back() {
    let (mut publisher, events) = publisher(None, true);
    assert!(run(publisher.publish(&claim(b"hello"), b"hello".to_vec())).is_err());
    assert_eq!(events.lock().unwrap().last(), Some(&"rollback"));
    assert!(!events.lock().unwrap().contains(&"open"));
}

#[test]
fn adoption_rejects_unsealed_and_conflicting_bindings() {
    let (publisher, _) = publisher(None, false);
    let (mut kernel, mut state) = publisher.into_parts();
    kernel.bytes = b"hello".to_vec();
    kernel.exists = true;
    let mut publisher = Publisher::new(kernel, state);
    assert!(run(publisher.adopt(&claim(b"hello"))).is_err());

    let (mut kernel, old_state) = publisher.into_parts();
    state = old_state;
    kernel.sealed = true;
    state.recorded = Some(VerityBinding {
        algorithm: 1,
        digest: vec![9; 32],
    });
    let mut publisher = Publisher::new(kernel, state);
    assert!(run(publisher.adopt(&claim(b"hello"))).is_err());
}

#[test]
fn lost_state_adoption_revalidates_plaintext_and_rewinds_handle() {
    let (publisher, events) = publisher(None, false);
    let (mut kernel, state) = publisher.into_parts();
    kernel.bytes = b"hello".to_vec();
    kernel.exists = true;
    kernel.sealed = true;
    let mut publisher = Publisher::new(kernel, state);
    let published = run(publisher.adopt(&claim(b"hello"))).unwrap();
    assert_eq!(published.into_handle().position(), 0);
    assert_eq!(
        *events.lock().unwrap(),
        ["open", "measure", "adopt-file-sync", "parent-sync", "state"]
    );
}

fn manifest_recipe(bytes: &[u8], lengths: &[usize]) -> (PublicationRecipe, ChunkProfile) {
    use std::collections::BTreeMap;
    use terrane_format::derived::PlaintextHashes;
    use terrane_format::manifest::{ChunkRef, Manifest};

    let profile = ChunkProfile::new(16, 32, 64, 48, 2, [0; 32]).unwrap();
    let mut secondary = PlaintextHashes::new(bytes.len() as u64);
    secondary.update(bytes).unwrap();
    let hashes = secondary.finish().unwrap();
    let mut offset = 0;
    let chunks = lengths
        .iter()
        .map(|&length| {
            let identity = TERRANE_V1
                .calculate(IdentityKind::Chunk, &bytes[offset..offset + length])
                .unwrap();
            offset += length;
            ChunkRef {
                digest: identity.terrane_v1_digest().unwrap(),
                length: length as u64,
            }
        })
        .collect();
    assert_eq!(offset, bytes.len());
    let manifest = Manifest {
        size: bytes.len() as u64,
        chunks,
        media_type: None,
        hashes: BTreeMap::from([
            ("blake3".into(), blake3::hash(bytes).as_bytes().to_vec()),
            ("sha256".into(), hashes.sha256.to_vec()),
            ("sha512".into(), hashes.sha512.to_vec()),
            ("git-blob-sha1".into(), hashes.git_blob_sha1.to_vec()),
            ("git-blob-sha256".into(), hashes.git_blob_sha256.to_vec()),
        ]),
    };
    let canonical_manifest = manifest.encode(&profile).unwrap();
    let identity = manifest.identity(&profile).unwrap();
    let object = Descriptor::from_identity(&TERRANE_V1, &identity, &canonical_manifest).unwrap();
    (
        PublicationRecipe::Manifest {
            object,
            canonical_manifest,
        },
        profile,
    )
}

#[test]
fn manifest_identity_remains_distinct_from_all_verified_plaintext_hashes() {
    let bytes: Vec<u8> = (0..70).collect();
    let (recipe, profile) = manifest_recipe(&bytes, &[40, 30]);
    let claim = PublicationClaim::new("private:root".into(), recipe, &profile).unwrap();
    assert_ne!(claim.descriptor().size(), claim.plaintext_size());
    assert_ne!(claim.descriptor().digest(), blake3::hash(&bytes).as_bytes());
    claim.verify_reader(&mut bytes.as_slice()).unwrap();
    let mut reordered = bytes[40..].to_vec();
    reordered.extend_from_slice(&bytes[..40]);
    assert!(claim.verify_reader(&mut reordered.as_slice()).is_err());
    let mut truncated = &bytes[..69];
    assert!(claim.verify_reader(&mut truncated).is_err());
}

#[test]
fn one_chunk_above_inline_threshold_retains_manifest_identity() {
    let bytes = vec![7; 40];
    let (recipe, profile) = manifest_recipe(&bytes, &[40]);
    let claim = PublicationClaim::new("public".into(), recipe, &profile).unwrap();
    assert_eq!(claim.descriptor().domain(), "terrane-manifest-v1");
    claim.verify_reader(&mut bytes.as_slice()).unwrap();
}

#[test]
fn manifest_and_claim_domain_are_checked_before_plaintext() {
    let bytes = vec![7; 40];
    let (mut recipe, profile) = manifest_recipe(&bytes, &[40]);
    if let PublicationRecipe::Manifest {
        canonical_manifest, ..
    } = &mut recipe
    {
        canonical_manifest.push(0);
    }
    assert!(PublicationClaim::new("public".into(), recipe, &profile).is_err());
    let (recipe, profile) = manifest_recipe(&bytes, &[40]);
    assert!(PublicationClaim::new("unknown".into(), recipe, &profile).is_err());
}

#[test]
fn retained_descriptor_failure_precedes_canonical_publication() {
    let (mut publisher, events) = publisher(Some("retain-staged"), false);
    assert!(run(publisher.publish_retained(&claim(b"hello"), b"hello".to_vec())).is_err());
    assert!(!events.lock().unwrap().contains(&"insert"));
    assert!(!events.lock().unwrap().contains(&"state"));
    assert!(!publisher.into_parts().0.exists);
}

#[test]
fn retained_descriptor_failure_precedes_adoption_state_effects() {
    let (publisher, events) = publisher(Some("retain-existing"), false);
    let (mut kernel, state) = publisher.into_parts();
    kernel.bytes = b"hello".to_vec();
    kernel.exists = true;
    kernel.sealed = true;
    let mut publisher = Publisher::new(kernel, state);

    assert!(run(publisher.adopt_retained(&claim(b"hello"))).is_err());
    assert!(!events.lock().unwrap().contains(&"state"));
    let (kernel, state) = publisher.into_parts();
    assert!(kernel.exists);
    assert!(state.recorded.is_none());
}
