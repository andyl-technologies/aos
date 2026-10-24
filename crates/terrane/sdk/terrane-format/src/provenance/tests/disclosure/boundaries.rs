//! Exercises complete disclosure boundaries and public provenance resolution.

use super::*;

#[test]
fn prov_history_union_preserves_completed_disclosure_boundaries() {
    let fixture = fixture(file());
    let (finished, _) = disclosed_candidate(
        &fixture.destination,
        fixture.target.commit,
        &[authority()],
        defaults(),
    )
    .unwrap()
    .finish()
    .unwrap();
    let mut merged = VerifiedHistory::new(MIN_CHUNK);
    merged.append_verified(&finished).unwrap();

    assert_eq!(merged.disclosure_boundaries, finished.disclosure_boundaries);
    assert_eq!(merged.disclosure_parents, finished.disclosure_parents);
    assert_eq!(
        merged.disclosure_verified_views,
        finished.disclosure_verified_views
    );
    assert_eq!(merged.root_scopes, finished.root_scopes);
    assert_eq!(merged.bootstrap_policies, finished.bootstrap_policies);
    assert_eq!(
        merged.introducing_commit(&fixture.target),
        Ok(fixture.target.commit)
    );
    assert!(merged.commit(&fixture.source_commit.identity()).is_none());
    assert!(
        merged
            .require_verified_context(fixture.target.commit)
            .is_ok()
    );
    let before = TrustContext::new(
        &finished,
        fixture.target.commit,
        Selector::preset(Preset::Strict),
        PUBLIC,
        Some("baseline"),
    )
    .unwrap();
    let after = TrustContext::new(
        &merged,
        fixture.target.commit,
        Selector::preset(Preset::Strict),
        PUBLIC,
        Some("baseline"),
    )
    .unwrap();

    assert_eq!(after.canonical_context(), before.canonical_context());
    assert!(!after.accepts_path(b"file"));
}

#[test]
fn prov_disclosure_history_import_rejects_unfinished_or_provisional_dependencies() {
    let fixture = fixture(file());
    let (finished, _) = disclosed_candidate(
        &fixture.destination,
        fixture.target.commit,
        &[authority()],
        defaults(),
    )
    .unwrap()
    .finish()
    .unwrap();
    let mut unfinished = finished.clone();
    unfinished.root_scopes.remove(&fixture.target.commit);
    let mut provisional = finished.clone();
    provisional.provisional_scopes.insert(fixture.target.commit);

    for dependency in [unfinished, provisional] {
        let mut candidate = disclosed_candidate(
            &fixture.destination,
            fixture.target.commit,
            &[authority()],
            defaults(),
        )
        .unwrap();
        assert!(candidate.insert_history(&dependency).is_err());
        let (history, _) = candidate.finish().unwrap();
        assert_eq!(
            history.introducing_commit(&fixture.target),
            Ok(fixture.target.commit)
        );
    }
}

#[test]
fn prov_disclosure_fresh_boundary_requires_independently_retained_bootstrap_even_empty_acl() {
    let fixture = fixture(file());
    let candidate = DisclosureCandidate::new(
        &fixture.destination,
        fixture.target.commit,
        &[authority()],
        defaults(),
    )
    .unwrap();
    assert!(candidate.required_commits().is_empty());
    assert!(candidate.finish().is_err());
    assert!(
        fixture
            .destination
            .require_verified_context(fixture.target.commit)
            .is_err()
    );

    let wrong = OriginalBootstrapPolicy {
        writer_epoch: 5,
        ..fixture_bootstrap()
    };
    assert!(
        DisclosureCandidate::new_with_bootstrap(
            &fixture.destination,
            fixture.target.commit,
            &[authority()],
            defaults(),
            fixture_bootstrap().authority,
            wrong
        )
        .is_err()
    );
    let (history, _) = disclosed_candidate(
        &fixture.destination,
        fixture.target.commit,
        &[authority()],
        defaults(),
    )
    .unwrap()
    .finish()
    .unwrap();
    assert!(
        history
            .require_verified_context(fixture.target.commit)
            .is_ok()
    );
    assert!(history.commit(&fixture.source_commit.identity()).is_none());
}

#[test]
fn prov_disclosure_destination_only_reopen_preserves_public_introduction_and_audit() {
    let fixture = fixture(file());
    assert!(
        fixture
            .destination
            .introducing_commit(&fixture.target)
            .is_err()
    );
    assert!(
        TrustContext::new(
            &fixture.destination,
            fixture.target.commit,
            Selector::preset(Preset::Any),
            PUBLIC,
            Some("baseline")
        )
        .is_err()
    );
    let candidate = disclosed_candidate(
        &fixture.destination,
        fixture.target.commit,
        &[authority()],
        defaults(),
    )
    .unwrap();
    assert!(candidate.required_commits().is_empty());
    let (history, batch) = candidate.finish().unwrap();

    assert_eq!(
        history.introducing_commit(&fixture.target),
        Ok(fixture.target.commit)
    );
    assert_eq!(
        history.attribute_producer(&fixture.target, "provenance.reintroduced-from"),
        Ok(fixture.target.commit)
    );
    assert!(history.commit(&fixture.source_commit.identity()).is_none());
    assert!(history.root_properties(fixture.source_root).is_err());
    assert_eq!(history.provenance_walk(&fixture.target).unwrap().len(), 1);
    assert!(batch.certified_parent(fixture.target.commit, fixture.source_commit.identity()));
    assert!(!batch.certified_parent([0; 32], fixture.source_commit.identity()));
    let boundary = &batch.boundaries()[0];
    assert_eq!(
        boundary.original_introducer(),
        fixture.source_commit.identity()
    );
    assert_eq!(boundary.root_occurrences(), &[b"/".to_vec()]);
    assert_eq!(boundary.authority_repository(), authority().repository);
    assert_eq!(boundary.source().commit, fixture.source_commit.identity());
    for (preset, expected) in [
        (Preset::Any, true),
        (Preset::Attested, false),
        (Preset::Strict, false),
        (Preset::SignedBaseline, false),
    ] {
        let context = TrustContext::new(
            &history,
            fixture.target.commit,
            Selector::preset(preset),
            PUBLIC,
            Some("baseline"),
        )
        .unwrap();
        assert_eq!(context.accepts_path(b"file"), expected);
    }

    let bytes = fixture.destination_commit.commit().encode().unwrap();
    let decoded = Commit::decode(&bytes).unwrap();
    let roots = [RequestRoot {
        path: b"/",
        domain: PUBLIC,
    }];
    let verified =
        verify_history(&decoded, &issuer_keys(), &roots, &[("refs/heads/main", 4)]).unwrap();
    let mut reopened = fixture.destination.clone();
    reopened.insert_commit(verified).unwrap();
    let (reopened, _) =
        disclosed_candidate(&reopened, fixture.target.commit, &[authority()], defaults())
            .unwrap()
            .finish()
            .unwrap();
    assert_eq!(
        reopened.introducing_commit(&fixture.target),
        Ok(fixture.target.commit)
    );
}

#[test]
fn prov_disclosure_private_objects_present_do_not_restore_private_acceptance() {
    let fixture = fixture(file());
    let mut with_private = fixture.destination.clone();
    with_private
        .insert_commit(fixture.source_commit.clone())
        .unwrap();
    // Supply the source tree exactly, to make availability unable to change cuts.
    with_private
        .insert_tree(
            fixture.source_root,
            &[(fixture.source_root, fixture.source_bytes.clone())],
        )
        .unwrap();
    let (history, batch) = disclosed_candidate(
        &with_private,
        fixture.target.commit,
        &[authority()],
        defaults(),
    )
    .unwrap()
    .finish()
    .unwrap();
    assert_eq!(
        history.introducing_commit(&fixture.target),
        Ok(fixture.target.commit)
    );
    assert!(
        !history
            .public_ancestor(fixture.source_commit.identity(), fixture.target.commit)
            .unwrap()
    );
    assert!(
        history
            .acceptance_commits(&fixture.target, fixture.target.commit)
            .unwrap()
            .is_empty()
    );
    assert!(batch.certified_parent(fixture.target.commit, fixture.source_commit.identity()));
    assert!(
        !TrustContext::new(
            &history,
            fixture.target.commit,
            Selector::preset(Preset::Strict),
            PUBLIC,
            Some("baseline")
        )
        .unwrap()
        .accepts_path(b"file")
    );
}

#[test]
fn prov_disclosure_directory_marker_and_symlink_bytes_grant_no_descendant_access() {
    let mut directory = entry(b"");
    directory.kind = EntryKind::Directory { mode: 0o755 };
    for value in [
        directory,
        entry(b"/private/target"),
        entry(b""),
        entry(b"../unavailable"),
    ] {
        let fixture = fixture(value);
        let (history, _) = disclosed_candidate(
            &fixture.destination,
            fixture.target.commit,
            &[authority()],
            defaults(),
        )
        .unwrap()
        .finish()
        .unwrap();
        assert_eq!(
            history.introducing_commit(&fixture.target),
            Ok(fixture.target.commit)
        );
        assert!(
            history
                .locate(fixture.target.commit, b"file/child")
                .is_err()
        );
        assert!(
            history
                .locate(fixture.target.commit, b"private/target")
                .is_err()
        );
    }
}

#[test]
fn prov_disclosure_complete_candidate_denies_uncovered_siblings_and_private_attributes() {
    let fixture = fixture(file());
    for receipt_mode in 0..3 {
        let disclosed = fixture.destination.entry(&fixture.target).unwrap();
        let (root, bytes) = root_tree(
            vec![item(b"file", disclosed), item(b"other", file())],
            PUBLIC,
        );
        let mut history = fixture.destination.clone();
        history.insert_tree(root, &[(root, bytes)]).unwrap();
        let mut commit = fixture.destination_commit.commit().clone();
        commit.tree = root;
        commit.profile_pair.entry_receipts.as_mut().unwrap()[0].root = root;
        if receipt_mode != 0 {
            let mut sibling = receipt(root, EntryOrigin::Current);
            sibling.path = b"other".to_vec();
            if receipt_mode == 2 {
                sibling.origin = EntryOrigin::Source(EntrySource {
                    commit: fixture.source_commit.identity(),
                    root: fixture.source_root,
                    path: b"file".to_vec(),
                });
            }
            commit
                .profile_pair
                .entry_receipts
                .as_mut()
                .unwrap()
                .push(sibling);
        }
        let signed = resign_certificate(&fixture, commit, &history);
        history.insert_commit(signed.clone()).unwrap();
        assert!(
            disclosed_candidate(&history, signed.identity(), &[authority()], defaults()).is_err()
        );
        // An uncovered sibling cannot resolve through ordinary current newness
        // before the commit's entire certificate batch has been admitted.
        assert!(
            history
                .introducing_commit(&EntryLocation {
                    commit: signed.identity(),
                    root,
                    path: b"other".to_vec()
                })
                .is_err()
        );
    }

    for origin in [
        None,
        Some(EntryOrigin::Source(EntrySource {
            commit: fixture.source_commit.identity(),
            root: fixture.source_root,
            path: b"file".to_vec(),
        })),
    ] {
        let mut commit = fixture.destination_commit.commit().clone();
        let receipt = &mut commit.profile_pair.entry_receipts.as_mut().unwrap()[0];
        receipt.attributes =
            origin.map(|origin| vec![("provenance.reintroduced-from".to_string(), origin)]);
        let signed = resign_certificate(&fixture, commit, &fixture.destination);
        let mut history = fixture.destination.clone();
        history.insert_commit(signed.clone()).unwrap();
        assert!(
            disclosed_candidate(&history, signed.identity(), &[authority()], defaults()).is_err()
        );
    }
}

#[test]
fn prov_disclosure_public_dependency_is_required_and_unanchored_parent_is_not_skipped() {
    let fixture = fixture(file());
    let (public_root, public_bytes) = root_tree(vec![item(b"other", file())], PUBLIC);
    let mut origin_receipt = receipt(public_root, EntryOrigin::Current);
    origin_receipt.path = b"other".to_vec();
    let mut public_commit = unsigned_commit();
    public_commit.tree = public_root;
    public_commit.profile_pair.entry_receipts = Some(vec![origin_receipt]);
    let public_commit = authored(public_commit, PUBLIC, &[12; 32], true);
    let disclosed = fixture.destination.entry(&fixture.target).unwrap();
    let (root, bytes) = root_tree(
        vec![item(b"file", disclosed), item(b"other", file())],
        PUBLIC,
    );
    let mut history = fixture.destination.clone();
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    let mut commit = fixture.destination_commit.commit().clone();
    commit.tree = root;
    commit.parents.insert(0, public_commit.identity());
    commit.profile_pair.entry_receipts.as_mut().unwrap()[0].root = root;
    let mut public_receipt = receipt(
        root,
        EntryOrigin::Source(EntrySource {
            commit: public_commit.identity(),
            root: public_root,
            path: b"other".to_vec(),
        }),
    );
    public_receipt.path = b"other".to_vec();
    commit
        .profile_pair
        .entry_receipts
        .as_mut()
        .unwrap()
        .push(public_receipt);
    let signed = resign_certificate(&fixture, commit.clone(), &history);
    history.insert_commit(signed.clone()).unwrap();
    let mut candidate =
        disclosed_candidate(&history, signed.identity(), &[authority()], defaults()).unwrap();
    assert_eq!(candidate.required_commits(), &[public_commit.identity()]);
    assert!(
        disclosed_candidate(&history, signed.identity(), &[authority()], defaults())
            .unwrap()
            .finish()
            .is_err()
    );
    candidate.insert_commit(public_commit.clone()).unwrap();
    candidate
        .insert_tree(public_root, &[(public_root, public_bytes)])
        .unwrap();
    candidate
        .validate_dependency_scope_with_bootstrap(
            public_commit.identity(),
            fixture_bootstrap().authority,
            fixture_bootstrap(),
        )
        .unwrap();
    let (verified, batch) = candidate.finish().unwrap();
    assert!(batch.certified_parent(signed.identity(), fixture.source_commit.identity()));
    assert!(!batch.certified_parent(signed.identity(), public_commit.identity()));
    assert_eq!(
        verified.introducing_commit(&EntryLocation {
            commit: signed.identity(),
            root,
            path: b"other".to_vec()
        }),
        Ok(public_commit.identity())
    );

    commit.parents.push([99; 32]);
    let unanchored = resign_certificate(&fixture, commit, &history);
    history.insert_commit(unanchored.clone()).unwrap();
    let candidate =
        disclosed_candidate(&history, unanchored.identity(), &[authority()], defaults()).unwrap();
    assert!(candidate.required_commits().contains(&[99; 32]));
    assert!(candidate.finish().is_err());
}

#[test]
fn prov_disclosure_valid_directory_certificate_cannot_cover_a_child() {
    let mut directory = entry(b"");
    directory.kind = EntryKind::Directory { mode: 0o755 };
    let fixture = fixture(directory);
    let disclosed = fixture.destination.entry(&fixture.target).unwrap();
    let (root, bytes) = root_tree(
        vec![item(b"file", disclosed), item(b"file/child", file())],
        PUBLIC,
    );
    let mut history = fixture.destination.clone();
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    let mut commit = fixture.destination_commit.commit().clone();
    commit.tree = root;
    commit.profile_pair.entry_receipts.as_mut().unwrap()[0].root = root;
    let signed = resign_certificate(&fixture, commit, &history);
    history.insert_commit(signed.clone()).unwrap();
    assert!(disclosed_candidate(&history, signed.identity(), &[authority()], defaults()).is_err());
}

#[test]
fn prov_disclosure_all_certificates_share_one_projection_and_fail_atomically() {
    let fixture = fixture(file());
    let disclosed = fixture.destination.entry(&fixture.target).unwrap();
    let (root, bytes) = root_tree(
        vec![item(b"file", disclosed.clone()), item(b"other", disclosed)],
        PUBLIC,
    );
    let mut history = fixture.destination.clone();
    history.insert_tree(root, &[(root, bytes)]).unwrap();
    let mut commit = fixture.destination_commit.commit().clone();
    commit.tree = root;
    let first = &mut commit.profile_pair.entry_receipts.as_mut().unwrap()[0];
    first.root = root;
    first.disclosure_proof.as_mut().unwrap().signature = [0; 64];
    let mut second = first.clone();
    second.path = b"other".to_vec();
    commit
        .profile_pair
        .entry_receipts
        .as_mut()
        .unwrap()
        .push(second);
    let prototype = authored(commit.clone(), PUBLIC, &[11; 32], false);
    history.insert_commit(prototype.clone()).unwrap();
    let binding = disclosure_target_binding(&commit).unwrap();
    for (position, path) in [b"file".as_slice(), b"other"].into_iter().enumerate() {
        let signature = sign_disclosure(
            DisclosureSigning {
                source_history: &fixture.source,
                source_commit: fixture.source_commit.identity(),
                source_path: b"file",
                destination_history: &history,
                destination_commit: prototype.identity(),
                destination_path: path,
                source_defaults: defaults(),
                destination_defaults: defaults(),
            },
            authority(),
            &AUTHORITY_SECRET,
        )
        .unwrap();
        commit.profile_pair.entry_receipts.as_mut().unwrap()[position]
            .disclosure_proof
            .as_mut()
            .unwrap()
            .signature = signature;
        assert_eq!(disclosure_target_binding(&commit).unwrap(), binding);
    }
    let signed = authored(commit.clone(), PUBLIC, &[11; 32], false);
    history.insert_commit(signed.clone()).unwrap();
    let (verified, batch) =
        disclosed_candidate(&history, signed.identity(), &[authority()], defaults())
            .unwrap()
            .finish()
            .unwrap();
    assert_eq!(batch.boundaries().len(), 2);
    assert_eq!(
        batch.boundaries()[0].destination_binding(),
        batch.boundaries()[1].destination_binding()
    );
    assert_eq!(
        verified.introducing_commit(&EntryLocation {
            commit: signed.identity(),
            root,
            path: b"other".to_vec()
        }),
        Ok(signed.identity())
    );

    commit.profile_pair.entry_receipts.as_mut().unwrap()[1]
        .disclosure_proof
        .as_mut()
        .unwrap()
        .signature[0] ^= 1;
    let broken = authored(commit, PUBLIC, &[11; 32], false);
    history.insert_commit(broken.clone()).unwrap();
    assert!(disclosed_candidate(&history, broken.identity(), &[authority()], defaults()).is_err());
    assert!(
        TrustContext::new(
            &history,
            broken.identity(),
            Selector::preset(Preset::Any),
            PUBLIC,
            None
        )
        .is_err()
    );
}

#[test]
fn prov_disclosure_graft_root_occurrence_is_exact_and_history_dependencies_can_be_nested() {
    let fixture = fixture(file());
    let (checked_source, _) = disclosed_candidate(
        &fixture.destination,
        fixture.target.commit,
        &[authority()],
        defaults(),
    )
    .unwrap()
    .finish()
    .unwrap();
    let mut graft = entry(b"");
    graft.kind = EntryKind::Tree {
        root: fixture.target.root,
        props: None,
    };
    let (root, bytes) = root_tree(vec![item(b"mount", graft)], PUBLIC);
    let mut parent_commit = unsigned_commit();
    parent_commit.tree = root;
    parent_commit.parents = vec![fixture.target.commit];
    let mut mount_receipt = receipt(root, EntryOrigin::Current);
    mount_receipt.path = b"mount".to_vec();
    let source = EntrySource {
        commit: fixture.target.commit,
        root: fixture.target.root,
        path: b"file".to_vec(),
    };
    let mut child_receipt = receipt(fixture.target.root, EntryOrigin::Source(source.clone()));
    child_receipt.attributes = Some(vec![(
        "provenance.reintroduced-from".to_string(),
        EntryOrigin::Source(source),
    )]);
    let mut parent_receipts = vec![mount_receipt.clone(), child_receipt];
    parent_receipts.sort_by(|left, right| (left.root, &left.path).cmp(&(right.root, &right.path)));
    parent_commit.profile_pair.entry_receipts = Some(parent_receipts);
    let parent = authored(parent_commit, PUBLIC, &[12; 32], true);
    let mut public_history = checked_source;
    public_history
        .insert_tree(root, &[(root, bytes.clone())])
        .unwrap();
    public_history.insert_commit(parent.clone()).unwrap();
    verify_fixture_scope(&mut public_history, parent.identity(), defaults()).unwrap();

    let mut commit = fixture.destination_commit.commit().clone();
    commit.tree = root;
    commit.parents = vec![parent.identity(), fixture.source_commit.identity()];
    mount_receipt.origin = EntryOrigin::Source(EntrySource {
        commit: parent.identity(),
        root,
        path: b"mount".to_vec(),
    });
    let mut receipts = vec![
        mount_receipt,
        commit.profile_pair.entry_receipts.as_ref().unwrap()[0].clone(),
    ];
    receipts.sort_by(|left, right| (left.root, &left.path).cmp(&(right.root, &right.path)));
    commit.profile_pair.entry_receipts = Some(receipts);
    let prototype = authored(commit.clone(), PUBLIC, &[11; 32], false);
    let mut seed = fixture.destination.clone();
    seed.insert_tree(root, &[(root, bytes)]).unwrap();
    seed.insert_commit(prototype.clone()).unwrap();
    let signature = sign_disclosure(
        DisclosureSigning {
            source_history: &fixture.source,
            source_commit: fixture.source_commit.identity(),
            source_path: b"file",
            destination_history: &seed,
            destination_commit: prototype.identity(),
            destination_path: b"mount/file",
            source_defaults: defaults(),
            destination_defaults: defaults(),
        },
        authority(),
        &AUTHORITY_SECRET,
    )
    .unwrap();
    commit
        .profile_pair
        .entry_receipts
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|receipt| receipt.disclosure_proof.is_some())
        .unwrap()
        .disclosure_proof
        .as_mut()
        .unwrap()
        .signature = signature;
    let signed = authored(commit, PUBLIC, &[11; 32], false);
    seed.insert_commit(signed.clone()).unwrap();
    let mut candidate =
        disclosed_candidate(&seed, signed.identity(), &[authority()], defaults()).unwrap();
    candidate.insert_history(&public_history).unwrap();
    let (verified, batch) = candidate.finish().unwrap();
    assert_eq!(
        batch.boundaries()[0].root_occurrences(),
        &[b"/mount".to_vec()]
    );
    assert_eq!(batch.boundaries()[0].target().root, fixture.target.root);
    assert!(batch.certified_parent(signed.identity(), fixture.source_commit.identity()));
    assert!(!batch.certified_parent(signed.identity(), parent.identity()));
    let location = verified.locate(signed.identity(), b"mount/file").unwrap().0;
    assert_eq!(
        verified.introducing_commit(&location),
        Ok(signed.identity())
    );

    // A certified first-parent cut is a fresh whole-root publication. A
    // legitimate child-root grant cannot authenticate its containing root.
    let mut narrow = signed.commit().clone();
    narrow.parents.swap(0, 1);
    let sign_narrow = |mut commit: Commit| {
        with_request(|request| {
            let roots = [RequestRoot {
                path: b"/mount",
                domain: PUBLIC,
            }];
            let request = Request {
                roots: &roots,
                ..*request
            };
            commit.profile_pair.commit_context =
                Some(CommitContext::from_request(&request).unwrap());
            sign_authored(commit, &[11; 32], &issuer_keys(), &request, 4).unwrap()
        })
    };
    let prototype = sign_narrow(narrow.clone());
    seed.insert_commit(prototype.clone()).unwrap();
    let signature = sign_disclosure(
        DisclosureSigning {
            source_history: &fixture.source,
            source_commit: fixture.source_commit.identity(),
            source_path: b"file",
            destination_history: &seed,
            destination_commit: prototype.identity(),
            destination_path: b"mount/file",
            source_defaults: defaults(),
            destination_defaults: defaults(),
        },
        authority(),
        &AUTHORITY_SECRET,
    )
    .unwrap();
    narrow
        .profile_pair
        .entry_receipts
        .as_mut()
        .unwrap()
        .iter_mut()
        .find(|receipt| receipt.disclosure_proof.is_some())
        .unwrap()
        .disclosure_proof
        .as_mut()
        .unwrap()
        .signature = signature;
    let narrow = sign_narrow(narrow);
    seed.insert_commit(narrow.clone()).unwrap();
    assert!(disclosed_candidate(&seed, narrow.identity(), &[authority()], defaults()).is_err());
}
