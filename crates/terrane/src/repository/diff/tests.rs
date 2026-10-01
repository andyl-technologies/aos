//! Exercises scoped graft policy differences through protected local factories.

use std::{collections::BTreeSet, os::unix::fs::MetadataExt, path::PathBuf, time::Duration};

use terrane_core::{
    auth::{Authority, Grant, Verbs},
    cbor,
    refs::{CommitSource, Locality, PrincipalKind},
    surface::{View, ViewTarget},
    tree_builder::Tree,
    tree_format::{Entry, EntryKind, LeafItem, Property, TreeUse},
};

use crate::{
    ref_advance::CommitTiming,
    repository::{
        CommitMetadata, LocalAuthorityParameters, LocalRepositoryLocation, LocalRepositoryPolicy,
        PreparedTree, Repository, local::proposal,
    },
    store::{LocalFs, TokioClock, TokioLocalFs},
};

/// Removes only the exclusively created fixture parent, including credentials.
struct FixtureDirectory(PathBuf);

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("Failed to remove private diff fixture: {error}");
        }
    }
}

fn entry(kind: EntryKind<'_>) -> Entry<'_> {
    Entry {
        kind,
        attrs: Vec::new(),
        attrs_present: false,
        xattrs: Vec::new(),
        xattrs_present: false,
        provenance: None,
    }
}

fn grafts(
    properties: &[(String, Vec<u8>)],
    minimum: u64,
    visible: &str,
    sibling: &str,
) -> Result<PreparedTree, super::Error> {
    let mut uploads = Vec::new();
    let mut entries = Vec::new();
    let mut staged_roots = BTreeSet::new();
    for (path, retain) in [("visible", visible), ("sibling", sibling)] {
        let mut value = Vec::new();
        cbor::write_text(&mut value, retain);
        let child = Tree::build(
            Vec::new(),
            Some(vec![Property {
                name: "retain",
                value: &value,
            }]),
            minimum,
            TreeUse::Ordinary,
        )?;
        let prepared = PreparedTree::from_tree(&child)?;
        entries.push(LeafItem {
            key: path.as_bytes().to_vec(),
            entry: entry(EntryKind::Directory { mode: 0o700 }),
        });
        entries.push(LeafItem {
            key: format!("{path}/nested").into_bytes(),
            entry: entry(EntryKind::Tree {
                root: prepared.root(),
                props: None,
            }),
        });
        if staged_roots.insert(prepared.root()) {
            uploads.extend(prepared.uploads);
        }
    }
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    let properties = properties
        .iter()
        .map(|(name, value)| Property { name, value })
        .collect();
    let tree = Tree::build(entries, Some(properties), minimum, TreeUse::Ordinary)?;
    let mut prepared = PreparedTree::from_tree(&tree)?;
    prepared.uploads.extend(uploads);
    Ok(prepared)
}

#[tokio::test]
async fn descendant_policy_only_diff_respects_authorized_scope()
-> Result<(), Box<dyn std::error::Error>> {
    let fs = TokioLocalFs;
    let entropy = fs.random_bytes(16).await?;
    let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
    let parent = std::env::temp_dir().join(format!("terrane-sdk-policy-diff-{suffix}"));
    fs.create_dir_new(&parent).await?;
    let _cleanup = FixtureDirectory(parent.clone());
    let owner_uid = fs.metadata(&parent).await?.uid();
    let reference = "refs/heads/_/main";
    let (repository, authority) = Repository::initialize_local(
        &LocalRepositoryLocation {
            bucket: parent.join("bucket"),
            authority: parent.join("authority"),
        },
        LocalAuthorityParameters {
            owner_uid,
            authority: Authority {
                issuer: "local".into(),
                key_id: "initial".into(),
                subject: "owner".into(),
                kind: PrincipalKind::Human,
                groups: Vec::new(),
                not_after: u64::MAX,
                not_before: None,
                token_id: entropy.try_into().map_err(|_| "invalid entropy")?,
                grants: vec![Grant::new("refs/**".into(), Verbs::new(31)?)?],
                workload: None,
            },
        },
        LocalRepositoryPolicy {
            store_name: "local".into(),
            domain: "private:owner".into(),
            default_private_domain: "private:owner".into(),
            acl: vec![("owner".into(), 31)],
            locality: Locality::default(),
            timing: CommitTiming::new(
                Duration::from_secs(30),
                Duration::from_secs(60),
                Duration::from_secs(10),
            )?,
            policy_authority: Some(reference.into()),
            bootstrap_properties: Vec::new(),
        },
        reference,
        fs,
        TokioClock,
    )
    .await?;
    let minimum = repository.chunk_profile().minimum() as u64;
    let snapshot = repository
        .coordinator
        .guard()
        .read_snapshot(reference, authority.token(), b"/", "sdk")
        .await?;
    let tree = snapshot.evidence.tree(snapshot.evidence.root, minimum)?;
    let properties: Vec<_> = tree
        .props()
        .ok_or("missing bootstrap policy")?
        .iter()
        .map(|property| (property.name.to_owned(), property.value.to_vec()))
        .collect();
    drop(tree);
    drop(snapshot);
    let mut session = repository
        .begin(reference, authority.token(), "sdk")
        .await?;
    let mut commits = Vec::new();
    for (visible, sibling) in [("gc", "gc"), ("forever", "gc"), ("forever", "forever")] {
        let prepared = grafts(&properties, minimum, visible, sibling)?;
        let parent = session.record().ok_or("missing initial commit")?.commit;
        let request = authority.commit_request(
            proposal(
                prepared.root(),
                vec![parent],
                CommitMetadata {
                    message: "Change graft retention declaration".into(),
                    process: "sdk-regression".into(),
                    source: CommitSource::Built,
                },
                "cdc-1m",
            ),
            "sdk".into(),
        );
        commits.push(
            repository
                .commit(&mut session, prepared, request)
                .await?
                .commit,
        );
    }
    let view = |commit, subtree: &[u8]| View {
        target: ViewTarget::Commit(commit),
        subtree: subtree.to_vec(),
        policy: None,
    };
    let visible_change = repository
        .diff(
            &view(commits[0], b"visible"),
            &view(commits[1], b"visible"),
            authority.token(),
            "sdk",
        )
        .await?;
    assert!(visible_change.policies_changed());
    assert!(visible_change.entries()?.changes.is_empty());
    let excluded_change = repository
        .diff(
            &view(commits[1], b"visible"),
            &view(commits[2], b"visible"),
            authority.token(),
            "sdk",
        )
        .await?;
    assert!(!excluded_change.policies_changed());
    assert!(excluded_change.entries()?.changes.is_empty());
    let whole_change = repository
        .diff(
            &view(commits[1], b""),
            &view(commits[2], b""),
            authority.token(),
            "sdk",
        )
        .await?;
    assert!(whole_change.policies_changed());
    assert!(whole_change.entries()?.changes.is_empty());
    Ok(())
}
