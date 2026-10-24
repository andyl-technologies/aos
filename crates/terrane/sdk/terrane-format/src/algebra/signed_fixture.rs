//! Supplies signed algebra views with separately retained original bootstrap policy.

#![allow(clippy::unwrap_used)]

use alloc::vec::Vec;

use crate::identity::Digest;
use crate::provenance::{OriginalBootstrapPolicy, VerifiedCommit, VerifiedHistory};
use crate::tree_builder::Tree;

// Protected fixture configuration is independent of candidate and current ACLs.
const ORIGINAL_AUTHORITY: &str = "algebra-original-physical-authority";
const ORIGINAL_BOOTSTRAP: OriginalBootstrapPolicy<'static> = OriginalBootstrapPolicy {
    authority: ORIGINAL_AUTHORITY,
    reference: "refs/heads/main",
    writer_epoch: 4,
    acl: &[],
};

/// Describes a newly authored side whose signing capability is verified again.
pub(super) struct SignedSide<'t, 'a> {
    /// Complete enclosing immutable view.
    pub(super) tree: &'t Tree<'a>,
    /// Optional immutable root mounted at `/mount` in that view.
    pub(super) child: Option<&'t Tree<'a>>,
    /// Whether the issued signing capability carries the fixture baseline group.
    pub(super) baseline: bool,
    /// Advisory producer timestamp authenticated by the new commit signature.
    pub(super) time: u64,
}

/// Authenticates canonical witnesses and original scope before exposing views.
pub(super) fn signed_history(
    sides: [SignedSide<'_, '_>; 2],
    domain: &str,
) -> (VerifiedHistory, [Digest; 2]) {
    let (templates, _, trusted_view, _, untrusted_view) =
        crate::provenance::tests::baseline_and_untrusted_history();
    let mut history = VerifiedHistory::new(1024);
    let mut views = [[0; 32]; 2];

    for (index, side) in sides.iter().enumerate() {
        for tree in core::iter::once(side.tree).chain(side.child) {
            let nodes = tree
                .nodes()
                .map(|node| (node.identity(), node.encoded().to_vec()))
                .collect::<Vec<_>>();
            history.insert_tree(tree.root_identity(), &nodes).unwrap();
        }
        let template = templates
            .commit(&if side.baseline {
                trusted_view
            } else {
                untrusted_view
            })
            .unwrap()
            .commit();
        let signed = signed_view(template, side, domain);
        views[index] = signed.identity();
        history.insert_commit(signed).unwrap();
    }

    for view in views {
        crate::provenance::verify_root_context_with_bootstrap(
            &mut history,
            view,
            crate::properties::Defaults {
                store: "algebra-fixture-store",
                private_domain: "private:fixture-default",
                home: "algebra-fixture-home",
            },
            ORIGINAL_AUTHORITY,
            ORIGINAL_BOOTSTRAP,
        )
        .unwrap();
    }
    (history, views)
}

fn signed_view(
    template: &crate::refs::Commit,
    side: &SignedSide<'_, '_>,
    domain: &str,
) -> VerifiedCommit {
    use crate::auth::{IssuerKey, Request, RequestRoot, Verb};
    use crate::refs::{CommitContext, EntryOrigin, EntryReceipt, Locality};
    use ed25519_dalek::SigningKey;

    let mut receipts: Vec<_> = core::iter::once(side.tree)
        .chain(side.child)
        .flat_map(|tree| {
            tree.iter().map(|item| EntryReceipt {
                root: tree.root_identity(),
                path: item.key.clone(),
                origin: EntryOrigin::Current,
                attributes: None,
                reintroduced_from: None,
                disclosure_proof: None,
            })
        })
        .collect();
    receipts.sort_by(|left, right| (left.root, &left.path).cmp(&(right.root, &right.path)));

    let mut roots = alloc::vec![RequestRoot { path: b"/", domain }];
    if side.child.is_some() {
        roots.push(RequestRoot {
            path: b"/mount",
            domain,
        });
    }
    let locality = Locality::default();
    let request = Request {
        reference: b"refs/heads/main",
        verb: Verb::Commit,
        roots: &roots,
        now: side.time,
        surface: "sdk",
        locality: &locality,
        epochs: &[("refs/heads/main", 4)],
    };
    let mut authored = template.clone();
    authored.tree = side.tree.root_identity();
    authored.parents.clear();
    authored.timestamp = side.time;
    authored.provenance.observed_at = side.time;
    authored.profile_pair.entry_receipts = Some(receipts);
    authored.profile_pair.commit_context = Some(CommitContext::from_request(&request).unwrap());
    authored.signature = None;

    let issuer = IssuerKey {
        issuer: "issuer".into(),
        key_id: "issuer-key".into(),
        public_key: SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes(),
        retirement: None,
    };
    crate::provenance::sign_authored(authored, &[9; 32], &[issuer], &request, 4).unwrap()
}
