//! Exercises recorded authoring through signed disclosure, selected ACK and private erasure.
//!
//! Setup supplies exact per-view profiles independently of the inspected lineage.
//! Canonical later-property bytes remain inert only under the selected revision.

use super::*;
use crate::bucket::held::SingleHeld;
use crate::guard::{
    AuthoringNamespaceProfile, ConsumedResolver, HistoryObservation, RecordedNamespaceProfile,
    RecordedNamespaceProfiles, SelectedReadInterpretation,
};
use crate::ref_advance::{AdvanceError, DisclosureCommitRequest, DisclosureCommitSelection};
use crate::store::{InvalidReason, RefStore, StoreErrorKind};
use terrane_format::gc::publication::evidence::{
    CheckedLineage, LineageUsedInputs, ViewInterpretationMode,
};
use terrane_format::identity::Digest;
use terrane_format::properties::selected::Selection;
use terrane_format::properties::semantics::{RecordedContext, associations::RecordedAssociation};
use terrane_format::refs::{PrincipalKind, RefRecord};
use witness_support::{MINIMUM, REFERENCE, file, physical_snapshot, proposal};

const LATER: &[&str] = &["index-roots", "index-gaps"];
const INERT: &[u8] = b"\x81\x00";
const REVISION_ONE_NAMES: &[&str] = &[
    "acl",
    "baseline",
    "chunk",
    "classify",
    "compaction_threshold",
    "compression",
    "dedup",
    "degraded",
    "domain",
    "durability",
    "encryption",
    "gap_merge_bytes",
    "hashes",
    "home",
    "index",
    "merge",
    "on-release",
    "passthrough",
    "prefetch",
    "quota",
    "reassembly",
    "redundancy",
    "reflog_retain",
    "replicate",
    "retain",
    "span_max_bytes",
    "store",
    "strict-attrs",
    "trust",
    "warm",
    "whole_pack_threshold",
    "wipe",
    "writers",
];

fn authoring(revision: u64) -> AuthoringNamespaceProfile {
    AuthoringNamespaceProfile::new(revision, 3, if revision == 1 { LATER } else { &[] }, 1).unwrap()
}

async fn factory(
    domain: &str,
    revision: u64,
) -> (
    NativeFixture<TokioLocalFs>,
    crate::repository::local_authority::LocalAuthority,
    std::path::PathBuf,
) {
    independent_factory_profile(
        domain,
        PrincipalKind::Human,
        Vec::new(),
        Some(authoring(revision)),
    )
    .await
}

fn tree(private: bool, plaintext: &[u8]) -> Tree<'static> {
    let mut properties = materialization::properties(private).unwrap();
    properties.extend(LATER.iter().map(|name| Property { name, value: INERT }));
    Tree::build(
        vec![LeafItem {
            key: b"file".to_vec(),
            entry: file(plaintext),
        }],
        Some(properties),
        MINIMUM,
        TreeUse::Ordinary,
    )
    .unwrap()
}

fn selection(source: &RefRecord, token: &[u8]) -> DisclosureCommitSelection {
    DisclosureCommitSelection {
        source_reference: REFERENCE.into(),
        source_commit: source.commit,
        source_path: b"/file".to_vec(),
        source_token: token.to_vec(),
        destination_path: b"/file".to_vec(),
    }
}

fn assert_mapping(used: &LineageUsedInputs, view: Digest, root: Digest) {
    assert!(used.check_supported_view_contexts().unwrap());
    assert_eq!(used.views.len(), 1);
    assert_eq!(used.views[0].view, view);
    let contexts = used.view_interpretations.as_ref().unwrap();
    assert_eq!(contexts.len(), 1);
    let context = &contexts[0];
    assert_eq!(context.view, view);
    assert_eq!(context.original_root, root);
    assert_eq!(context.mode, ViewInterpretationMode::Recorded);
    assert_eq!(context.registries.property_revision, 1);
    assert_eq!(context.registries.attribute_revision, 1);
    assert_eq!(context.registries.selector_revision, 1);
    assert_eq!(context.registries.tree_revision, 1);
    assert_eq!(context.registries.chunk_revision, 1);
    assert_eq!(context.registries.identity_profile, "terrane-v1");
    assert_eq!(
        context.registries.later_properties,
        vec!["index-gaps", "index-roots"]
    );
    assert_eq!(
        context.registries.behavioral_properties,
        REVISION_ONE_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
    );
    let namespace = used.views[0]
        .roots
        .iter()
        .find(|root| root.path == b"/")
        .unwrap();
    assert_eq!(namespace.root, root);
}

async fn reopen(
    destination: NativeFixture<TokioLocalFs>,
    authority: &crate::repository::local_authority::LocalAuthority,
    view: Digest,
    root: Digest,
) -> NativeFixture<TokioLocalFs> {
    let location = destination.store().root().to_owned();
    let policy = destination.guard().config().clone();
    drop(destination);
    let bucket = FileBucket::open(config(location).await, TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap();
    let profile = RecordedNamespaceProfile::new(
        RecordedAssociation::new(view, root, RecordedContext::new(1, 3, LATER).unwrap()),
        1,
    )
    .unwrap();
    let guard = Guard::new_with_recorded_namespace_profiles_and_authoring(
        bucket,
        TokioClock,
        vec![authority.issuer_key().clone()],
        policy,
        RecordedNamespaceProfiles::new([profile]).unwrap(),
        authoring(1),
    );
    NativeFixture::reopen(Coordinator::new(
        guard,
        CommitTiming::new(
            Duration::from_secs(30),
            Duration::from_secs(60),
            Duration::from_secs(10),
        )
        .unwrap(),
        TokioLocalFs,
    ))
    .await
}

#[tokio::test]
async fn disclosure_recorded_authoring_survives_selected_ack_and_destination_only_reopen() {
    let (source, source_authority, source_credentials) = factory("private:writer", 1).await;
    let (destination, destination_authority, _) = factory("public", 1).await;
    let plaintext = b"recorded disclosure uses actual historical property semantics";
    let private_tree = tree(true, plaintext);
    let public_tree = tree(false, plaintext);
    let mut source_writer = source
        .begin(REFERENCE, source_authority.token(), "sdk")
        .await
        .unwrap();
    let source_head = source
        .advance(
            &mut source_writer,
            proposal(&source_authority, Vec::new(), &private_tree, &[plaintext]),
        )
        .await
        .unwrap();
    let source_snapshot = source
        .guard()
        .read_snapshot(REFERENCE, source_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    assert_eq!(
        source_snapshot
            .history
            .property_selection(source_head.commit)
            .unwrap(),
        Selection::Recorded(RecordedContext::new(1, 3, LATER).unwrap())
    );
    assert_eq!(
        source_snapshot.commit.commit().tree,
        private_tree.root_identity()
    );
    drop(source_snapshot);

    let mut writer = destination
        .begin(REFERENCE, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let published = destination
        .advance_disclosure(
            source.guard(),
            &mut writer,
            DisclosureCommitRequest {
                proposal: proposal(
                    &destination_authority,
                    Vec::new(),
                    &public_tree,
                    &[plaintext],
                ),
                selections: vec![selection(&source_head, source_authority.token())],
            },
        )
        .await
        .unwrap();
    assert_eq!(writer.record(), Some(&published));
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        Some(published.clone())
    );
    let snapshot = destination
        .guard()
        .read_snapshot(REFERENCE, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let root = snapshot.commit.commit().tree;
    let receipt = &snapshot
        .commit
        .commit()
        .profile_pair
        .entry_receipts
        .as_ref()
        .unwrap()[0];
    let proof = receipt.disclosure_proof.as_ref().unwrap();
    assert_ne!(proof.signature, [0; 64]);
    assert_eq!(proof.source_domain, "private:writer");
    assert_eq!(
        receipt.reintroduced_from.as_ref().unwrap().commit,
        source_head.commit
    );
    assert_eq!(snapshot.commit.commit().parents, vec![source_head.commit]);
    for (kind, digest) in [
        (IdentityKind::Commit, source_head.commit),
        (IdentityKind::Node, private_tree.root_identity()),
    ] {
        assert_eq!(
            destination
                .store()
                .has(&[TERRANE_V1.from_digest(kind, &digest).unwrap()])
                .await
                .unwrap(),
            vec![false]
        );
    }
    drop(snapshot);

    let holder = SingleHeld::acquire(destination.store()).await.unwrap();
    let held = holder.destination();
    let observed = held.observe_publication().await.unwrap();
    let lineage = CheckedLineage::decode(
        &held
            .selected_lineage(&observed, REFERENCE)
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(lineage.source, published);
    assert_eq!(lineage.commit_id, published.commit);
    assert_mapping(&lineage.used, published.commit, root);
    assert!(!lineage.used.disclosures.is_empty());
    observed.revalidate().await.unwrap();
    drop(observed);
    drop(held);
    drop(holder);
    drop(source_writer);
    drop(source_authority);
    witness_support::erase_source(source, source_credentials).await;
    drop(writer);

    // The selected view/root was captured from the actual signed destination,
    // never reconstructed from the ordinary lineage inspected above.
    let reopened = reopen(destination, &destination_authority, published.commit, root).await;
    let snapshot = reopened
        .guard()
        .read_snapshot(REFERENCE, destination_authority.token(), b"/file", "sdk")
        .await
        .unwrap();
    let SelectedReadInterpretation::Recorded(association) = &snapshot.interpretation else {
        panic!("destination-only read must retain its explicit recorded association");
    };
    assert_eq!(association.view(), published.commit);
    assert_eq!(association.original_root(), root);
    assert_eq!(
        association.context(),
        &RecordedContext::new(1, 3, LATER).unwrap()
    );
    assert!(snapshot.history.commit(&source_head.commit).is_none());
    let public = snapshot.evidence.tree(root, MINIMUM).unwrap();
    for name in LATER {
        assert_eq!(
            public
                .props()
                .unwrap()
                .iter()
                .find(|property| property.name == *name)
                .unwrap()
                .value,
            INERT
        );
    }
    let (location, _) = snapshot.history.locate(published.commit, b"file").unwrap();
    assert_eq!(
        snapshot.history.introducing_commit(&location).unwrap(),
        published.commit
    );
    let EntryKind::File { content, size, .. } = snapshot.history.entry(&location).unwrap().kind
    else {
        panic!("disclosed entry is a file");
    };
    assert_eq!(
        reopened
            .guard()
            .read_content(&snapshot, b"/file", content, size)
            .await
            .unwrap(),
        plaintext
    );
    drop(public);
    drop(snapshot);

    let authority = reopened.guard().configured_original_authority().unwrap();
    let holder = SingleHeld::acquire(reopened.store()).await.unwrap();
    let held = holder.destination();
    let identity = held.identity_proof();
    let guard = reopened
        .guard()
        .held_guard(holder.destination(), TokioClock)
        .unwrap();
    let consumed = ConsumedResolver::new(reopened.guard(), &authority).unwrap();
    let before = physical_snapshot(reopened.store().root()).await;
    let checked = guard
        .verified_collection_tree_observed(
            published.commit,
            HistoryObservation::held(&identity).tracked(&consumed),
        )
        .await
        .unwrap();
    let dependencies = checked.completed().dependencies(published.commit).unwrap();
    assert!(
        dependencies
            .disclosure()
            .unwrap()
            .certified_parent(published.commit, source_head.commit)
    );
    assert!(
        checked
            .completed()
            .history()
            .commit(&source_head.commit)
            .is_none()
    );
    assert_mapping(&consumed.finish().unwrap(), published.commit, root);
    assert_eq!(physical_snapshot(reopened.store().root()).await, before);
}

#[tokio::test]
async fn disclosure_active_three_refuses_malformed_later_properties_before_effects() {
    let (source, source_authority, _) = factory("private:writer", 1).await;
    let (destination, destination_authority, _) = factory("public", 3).await;
    let plaintext = b"same canonical property bytes become invalid active pointer bindings";
    let mut source_writer = source
        .begin(REFERENCE, source_authority.token(), "sdk")
        .await
        .unwrap();
    let source_head = source
        .advance(
            &mut source_writer,
            proposal(
                &source_authority,
                Vec::new(),
                &tree(true, plaintext),
                &[plaintext],
            ),
        )
        .await
        .unwrap();
    let mut writer = destination
        .begin(REFERENCE, destination_authority.token(), "sdk")
        .await
        .unwrap();
    let previous = writer.record().cloned();
    let before = physical_snapshot(destination.store().root()).await;
    let Err(AdvanceError::Store(failure)) = destination
        .advance_disclosure(
            source.guard(),
            &mut writer,
            DisclosureCommitRequest {
                proposal: proposal(
                    &destination_authority,
                    Vec::new(),
                    &tree(false, plaintext),
                    &[plaintext],
                ),
                selections: vec![selection(&source_head, source_authority.token())],
            },
        )
        .await
    else {
        panic!("active revision 3 must refuse malformed registered pointer properties");
    };
    assert_eq!(
        failure.kind(),
        &StoreErrorKind::Invalid(InvalidReason::MalformedRequest)
    );
    assert_eq!(writer.record(), previous.as_ref());
    assert_eq!(
        destination.store().ref_get(REFERENCE).await.unwrap(),
        previous
    );
    assert_eq!(physical_snapshot(destination.store().root()).await, before);
    assert_eq!(
        source.store().ref_get(REFERENCE).await.unwrap(),
        Some(source_head)
    );
}
