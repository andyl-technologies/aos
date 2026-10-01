//! Checks domain ordering and observable scoped-storage behavior.

#![allow(
    clippy::unwrap_used,
    reason = "Test fixture failures intentionally panic."
)]

#[cfg(not(feature = "send"))]
use std::cell::{Cell, RefCell};
#[cfg(not(feature = "send"))]
use std::collections::BTreeMap;
#[cfg(not(feature = "send"))]
use std::task::{Context, Poll, Waker};

#[cfg(not(feature = "send"))]
use terrane_core::auth::Verb;
use terrane_core::identity::{Identity, IdentityKind, TERRANE_V1};
use terrane_core::properties::Domain;
#[cfg(not(feature = "send"))]
use terrane_core::refs::{Locality, RefRecord};

use super::*;
#[cfg(not(feature = "send"))]
use crate::store::*;

#[cfg(not(feature = "send"))]
fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let mut context = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("in-memory test backend must complete synchronously"),
    }
}

fn identity(kind: IdentityKind, bytes: &[u8]) -> Identity {
    TERRANE_V1.calculate(kind, bytes).unwrap()
}

#[cfg(not(feature = "send"))]
fn access(domain: &str, verb: Verb) -> DomainAccess {
    DomainAccess::authorized(
        DomainBinding {
            domain: domain.into(),
            reference: "refs/heads/main".into(),
            root: identity(IdentityKind::Node, b"root"),
            path: b"/".to_vec(),
        },
        verb,
        "test-principal".into(),
        [1; 16],
    )
    .unwrap()
    .with_reference_record(RefRecord {
        commit: identity(IdentityKind::Commit, b"current")
            .terrane_v1_digest()
            .unwrap(),
        seq: 1,
        writer_epoch: 1,
        home: Locality::default(),
        policy: None,
        candidate_id: None,
    })
}

#[cfg(not(feature = "send"))]
struct MemoryStore {
    capabilities: Capabilities,
    records: RefCell<BTreeMap<Vec<u8>, Vec<u8>>>,
    reads: Cell<usize>,
    writes: Cell<usize>,
}

#[cfg(not(feature = "send"))]
impl MemoryStore {
    fn new() -> Self {
        Self {
            capabilities: Capabilities {
                refs: RefCapability::None,
                ranges: RangeCapability::Ranges,
                presign: false,
                locality: Locality::default(),
                durability: Durability::Local,
                sealed: false,
            },
            records: RefCell::new(BTreeMap::new()),
            reads: Cell::new(0),
            writes: Cell::new(0),
        }
    }
}

#[cfg(not(feature = "send"))]
impl CapabilityReport for MemoryStore {
    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
}

// These tests use local bindings; send-feature tests exercise the file backend.
#[cfg(not(feature = "send"))]
#[async_trait::async_trait(?Send)]
impl ContentStore for MemoryStore {
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        let ContentUpload::Meta(upload) = upload else {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        };
        let id = identity(upload.kind(), upload.bytes());
        self.writes.set(self.writes.get() + 1);
        self.records
            .borrow_mut()
            .entry(id.digest().to_vec())
            .or_insert_with(|| upload.bytes().to_vec());
        Ok(id)
    }

    async fn get(&self, id: &Identity, _: Option<ByteRange>) -> Result<Vec<u8>, StoreFailure> {
        self.reads.set(self.reads.get() + 1);
        self.records
            .borrow()
            .get(id.digest())
            .cloned()
            .ok_or_else(|| StoreFailure::new(StoreErrorKind::Absent(id.clone())))
    }

    async fn has(&self, ids: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        self.reads.set(self.reads.get() + 1);
        Ok(ids
            .iter()
            .map(|id| self.records.borrow().contains_key(id.digest()))
            .collect())
    }

    async fn list(&self, _: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}

#[test]
fn dom_reference_order_checks_every_kind_and_incomparable_name() {
    let domains = [
        Domain::Public,
        Domain::Tenant("a"),
        Domain::Tenant("b"),
        Domain::Group("a"),
        Domain::Group("b"),
        Domain::Private("a"),
        Domain::Private("b"),
    ];
    let id = identity(IdentityKind::Node, b"referenced-root");
    for destination in domains {
        for source in domains {
            let reference = DomainReference {
                identity: &id,
                domain: source,
            };
            assert_eq!(
                DomainAdmission::new(None, destination, &[reference]).is_ok(),
                destination.permits_reference(source),
                "{destination:?} <- {source:?}"
            );
            assert_eq!(
                DomainAdmission::new(Some(source), destination, &[]).is_ok(),
                destination.permits_reference(source),
                "transition {source:?} -> {destination:?}"
            );
        }
    }
}

#[test]
fn dom_reference_order_requires_fresh_records_after_closing() {
    let id = identity(IdentityKind::Manifest, b"same-content");
    let old = DomainRecord::admitted(id.clone(), "public".into()).unwrap();
    assert!(
        DomainAdmission::from_records(Some(Domain::Public), Domain::Tenant("a"), &[old]).is_err()
    );

    let fresh = DomainRecord::admitted(id, "tenant:a".into()).unwrap();
    let admission =
        DomainAdmission::from_records(Some(Domain::Public), Domain::Tenant("a"), &[fresh]).unwrap();
    assert!(admission.requires_readmission());
    assert!(DomainAdmission::new(Some(Domain::Private("a")), Domain::Public, &[]).is_err());
}

#[test]
fn dom_default_private_is_unique_to_root_identity() {
    let first = identity(IdentityKind::Node, b"one");
    let second = identity(IdentityKind::Node, b"two");
    assert_ne!(private_default(&first), private_default(&second));
    assert!(matches!(
        Domain::parse(&private_default(&first)),
        Ok(Domain::Private(_))
    ));

    for root in [&first, &second] {
        let default = private_default(root);
        let policy = terrane_core::properties::resolve(
            &[],
            terrane_core::properties::Defaults {
                store: "authority",
                private_domain: &default,
                home: "local",
            },
        )
        .unwrap();
        assert_eq!(policy.domain().unwrap(), Domain::parse(&default).unwrap());
        assert_eq!(
            policy.get(terrane_core::properties::PropertyName::Dedup),
            Some(&terrane_core::properties::Value::Text("domain"))
        );
    }
}

#[cfg(feature = "std")]
#[test]
fn dom_dedup_scope_rejects_aliasing_namespace_configuration() {
    let namespace = |domain: &str, path: &str| DomainNamespace {
        domain: domain.into(),
        root: path.into(),
    };
    for bad in [
        namespace("tenant:b", "/tmp/domain-a"),
        namespace("tenant:b", "/tmp/domain-a/nested"),
        namespace("tenant:a", "/tmp/domain-b"),
        namespace("tenant:b", "/tmp/./domain-b"),
        namespace("tenant:b", "relative/domain"),
    ] {
        assert!(DomainNamespaces::new(vec![namespace("tenant:a", "/tmp/domain-a"), bad]).is_err());
    }
    let distinct = DomainNamespaces::new(vec![
        namespace("tenant:a", "/tmp/domain-a"),
        namespace("tenant:b", "/tmp/domain-b"),
    ])
    .unwrap();
    assert_eq!(
        distinct.root(Domain::Tenant("a")),
        Some(std::path::Path::new("/tmp/domain-a"))
    );
    assert_eq!(distinct.root(Domain::Tenant("c")), None);
}

#[cfg(not(feature = "send"))]
#[test]
fn dom_dedup_scope_creates_independent_records_without_other_domain_probe() {
    let first = DomainStore::new("tenant:a".into(), MemoryStore::new()).unwrap();
    let second = DomainStore::new("tenant:b".into(), MemoryStore::new()).unwrap();
    let upload = ContentUpload::Meta(MetaUpload::new(IdentityKind::Policy, b"same bytes").unwrap());
    let record = ready(first.put_record(&access("tenant:a", Verb::Commit), upload)).unwrap();

    assert_eq!(
        ready(second.has(
            &access("tenant:b", Verb::Read),
            &[record.identity().clone()]
        ))
        .unwrap(),
        [false]
    );
    assert_eq!(first.backend.reads.get(), 0);
    let duplicate = ready(second.put_record(&access("tenant:b", Verb::Commit), upload)).unwrap();
    assert_eq!(record.identity(), duplicate.identity());
    assert_ne!(record.domain(), duplicate.domain());
    assert_eq!(first.backend.writes.get(), 1);
    assert_eq!(second.backend.writes.get(), 1);
    assert_eq!(first.backend.records.borrow().len(), 1);
    assert_eq!(second.backend.records.borrow().len(), 1);
}

#[cfg(not(feature = "send"))]
#[test]
fn dom_existence_oracle_denies_identically_without_backend_lookup() {
    let store = DomainStore::new("private:a".into(), MemoryStore::new()).unwrap();
    let present = ready(store.put(
        &access("private:a", Verb::Commit),
        ContentUpload::Meta(MetaUpload::new(IdentityKind::Policy, b"present").unwrap()),
    ))
    .unwrap();
    let absent = identity(IdentityKind::Policy, b"absent");
    let outside = access("private:b", Verb::Read);
    for id in [&present, &absent] {
        let failure = ready(store.get(&outside, id, None)).unwrap_err();
        assert!(matches!(failure.kind(), StoreErrorKind::Denied { .. }));
        assert!(ready(store.has(&outside, std::slice::from_ref(id))).is_err());
        assert!(ready(store.filter(&outside, id)).is_err());
    }
    assert_eq!(store.backend.reads.get(), 0);
}

#[cfg(not(feature = "send"))]
#[test]
fn dom_existence_oracle_same_domain_requires_reachable_identity() {
    let store = DomainStore::new("private:a".into(), MemoryStore::new()).unwrap();
    let present = ready(store.put(
        &access("private:a", Verb::Commit),
        ContentUpload::Meta(MetaUpload::new(IdentityKind::Policy, b"present").unwrap()),
    ))
    .unwrap();
    let absent = identity(IdentityKind::Policy, b"absent");
    let denied = access("private:a", Verb::Read);

    assert!(matches!(
        ready(store.get(&denied, &present, None))
            .unwrap_err()
            .kind(),
        StoreErrorKind::Absent(_)
    ));
    assert_eq!(
        ready(store.has(&denied, &[present.clone(), absent.clone()])).unwrap(),
        vec![false, false]
    );
    assert_eq!(store.backend.reads.get(), 0);

    let permitted = denied.with_read_identities(vec![present.clone()]);
    assert_eq!(
        ready(store.has(&permitted, &[absent, present.clone(), present])).unwrap(),
        vec![false, true, true]
    );
    assert_eq!(store.backend.reads.get(), 1);
}

#[cfg(not(feature = "send"))]
#[test]
fn dom_existence_oracle_filters_and_explicit_disclosure_remain_scoped() {
    let private = DomainStore::new("private:a".into(), MemoryStore::new()).unwrap();
    let public = DomainStore::new("public".into(), MemoryStore::new()).unwrap();
    let upload =
        ContentUpload::Meta(MetaUpload::new(IdentityKind::Filter, b"private filter").unwrap());
    let record = ready(private.put_record(&access("private:a", Verb::Commit), upload)).unwrap();

    assert!(matches!(
        ready(public.filter(&access("public", Verb::Read), record.identity()))
            .unwrap_err()
            .kind(),
        StoreErrorKind::Absent(_)
    ));
    let manifest = terrane_core::manifest::Manifest {
        size: 1,
        chunks: vec![terrane_core::manifest::ChunkRef {
            digest: identity(IdentityKind::Chunk, b"a")
                .terrane_v1_digest()
                .unwrap(),
            length: 1,
        }],
        hashes: BTreeMap::from([("blake3".into(), blake3::hash(b"a").as_bytes().to_vec())]),
        media_type: None,
    };
    let encoded = manifest
        .encode(&terrane_core::chunking::ChunkProfile::cdc_1m([0; 32]))
        .unwrap();
    let upload = ContentUpload::Meta(MetaUpload::new(IdentityKind::Manifest, &encoded).unwrap());
    let record = ready(private.put_record(&access("private:a", Verb::Commit), upload)).unwrap();
    let broad_source =
        access("private:a", Verb::Read).with_read_identities(vec![record.identity().clone()]);

    // Reachability alone does not identify which authenticated file introduced
    // shared content. Disclosure needs the exact source path and ref snapshot.
    assert!(
        ready(public.disclose_from(
            &access("public", Verb::Commit),
            &private,
            &broad_source,
            record.identity(),
            upload,
        ))
        .is_err()
    );
    assert_eq!(private.backend.reads.get(), 0);
    assert_eq!(public.backend.writes.get(), 0);
    let path_only = broad_source
        .with_read_path(record.identity().clone(), b"/file".to_vec())
        .unwrap();
    assert!(
        ready(public.disclose_from(
            &access("public", Verb::Commit),
            &private,
            &path_only,
            record.identity(),
            upload,
        ))
        .is_err()
    );
    assert_eq!(private.backend.reads.get(), 0);
    assert_eq!(public.backend.writes.get(), 0);
    let selected_commit = identity(IdentityKind::Commit, b"historical")
        .terrane_v1_digest()
        .unwrap();
    let source = path_only.with_read_commit(selected_commit);
    assert!(
        source
            .clone()
            .with_read_path(record.identity().clone(), b"/alias".to_vec())
            .is_err()
    );

    let other_actor = DomainAccess::authorized(
        access("private:a", Verb::Read).binding().clone(),
        Verb::Read,
        "other-principal".into(),
        [2; 16],
    )
    .unwrap()
    .with_read_identities(vec![record.identity().clone()]);
    assert!(
        ready(public.disclose_from(
            &access("public", Verb::Commit),
            &private,
            &other_actor,
            record.identity(),
            upload,
        ))
        .is_err()
    );
    assert_eq!(private.backend.reads.get(), 0);
    assert_eq!(public.backend.writes.get(), 0);

    let disclosure = ready(public.disclose_from(
        &access("public", Verb::Commit),
        &private,
        &source,
        record.identity(),
        upload,
    ))
    .unwrap();
    assert_eq!(disclosure.record().identity(), record.identity());
    assert_eq!(disclosure.record().domain(), "public");
    assert_eq!(disclosure.source().domain, "private:a");
    assert_eq!(disclosure.destination().domain, "public");
    assert_eq!(
        disclosure.source_access().read_commit(),
        Some(&selected_commit)
    );
    assert_ne!(
        disclosure
            .source_access()
            .reference_record()
            .unwrap()
            .commit,
        selected_commit
    );
    assert_eq!(disclosure.source_path(), b"/file");
    assert_eq!(
        disclosure.source_access().reference_record(),
        source.reference_record()
    );
    assert_eq!(
        ready(public.get(
            &access("public", Verb::Read).with_read_identities(vec![record.identity().clone()]),
            record.identity(),
            None,
        ))
        .unwrap(),
        encoded
    );
    assert_eq!(public.backend.writes.get(), 1);
}

#[cfg(not(feature = "send"))]
struct DeletionFixture {
    roots: Vec<DomainBinding>,
    events: RefCell<Vec<&'static str>>,
    fail_intent: Cell<bool>,
    fail_backend: Cell<bool>,
}

#[cfg(not(feature = "send"))]
#[async_trait::async_trait(?Send)]
impl DomainDeletionBackend for DeletionFixture {
    fn domain(&self) -> &str {
        "tenant:a"
    }

    async fn domain_roots(&self) -> Result<Vec<DomainBinding>, StoreFailure> {
        Ok(self.roots.clone())
    }

    async fn delete_domain_data(&self) -> Result<(), StoreFailure> {
        self.events.borrow_mut().push("delete");
        if self.fail_backend.get() {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }
        Ok(())
    }
}

#[cfg(not(feature = "send"))]
#[async_trait::async_trait(?Send)]
impl DomainDeletionAudit for DeletionFixture {
    async fn domain_deleted(&self, domain: &str) -> Result<bool, StoreFailure> {
        assert_eq!(domain, "tenant:a");
        Ok(!self.fail_intent.get() && self.events.borrow().contains(&"intent"))
    }

    async fn record_intent(&self, event: &DomainDeletionEvent) -> Result<Identity, StoreFailure> {
        assert_eq!(event.domain, "tenant:a");
        self.events.borrow_mut().push("intent");
        if self.fail_intent.get() {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }
        Ok(identity(IdentityKind::Commit, b"intent"))
    }

    async fn record_completion(
        &self,
        _: &DomainDeletionEvent,
        intent: &Identity,
    ) -> Result<Identity, StoreFailure> {
        assert_eq!(intent, &identity(IdentityKind::Commit, b"intent"));
        self.events.borrow_mut().push("complete");
        Ok(identity(IdentityKind::Commit, b"complete"))
    }
}

#[cfg(not(feature = "send"))]
#[test]
fn dom_deletion_requires_every_root_admin_and_orders_audit_before_removal() {
    let first = access("tenant:a", Verb::Admin);
    let mut other_binding = first.binding().clone();
    other_binding.path = b"/second".to_vec();
    let second = DomainAccess::authorized(
        other_binding,
        Verb::Admin,
        first.subject().to_owned(),
        *first.token_id(),
    )
    .unwrap();
    let plan = DomainDeletionPlan::new(
        "tenant:a".into(),
        vec![first.binding().clone(), second.binding().clone()],
    )
    .unwrap();
    let fixture = DeletionFixture {
        roots: vec![first.binding().clone(), second.binding().clone()],
        events: RefCell::new(Vec::new()),
        fail_intent: Cell::new(false),
        fail_backend: Cell::new(false),
    };

    assert!(ready(plan.execute(std::slice::from_ref(&first), &fixture, &fixture)).is_err());
    assert!(fixture.events.borrow().is_empty());
    let incomplete =
        DomainDeletionPlan::new("tenant:a".into(), vec![first.binding().clone()]).unwrap();
    assert!(ready(incomplete.execute(std::slice::from_ref(&first), &fixture, &fixture)).is_err());
    assert!(fixture.events.borrow().is_empty());
    let permissions = [first, second];
    fixture.fail_intent.set(true);
    assert!(ready(plan.execute(&permissions, &fixture, &fixture)).is_err());
    assert_eq!(*fixture.events.borrow(), ["intent"]);

    fixture.events.borrow_mut().clear();
    fixture.fail_intent.set(false);
    fixture.fail_backend.set(true);
    assert!(ready(plan.execute(&permissions, &fixture, &fixture)).is_err());
    assert_eq!(*fixture.events.borrow(), ["intent", "delete"]);

    fixture.events.borrow_mut().clear();
    fixture.fail_backend.set(false);
    ready(plan.execute(&permissions, &fixture, &fixture)).unwrap();
    assert_eq!(*fixture.events.borrow(), ["intent", "delete", "complete"]);
}
