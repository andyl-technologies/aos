//! Exercises whole-commit normalization and scoped historical authority keys.

use super::*;

#[test]
fn prov_disclosure_whole_projection_rejects_resigned_destination_mutations() {
    let fixture = fixture(file());
    let commit = fixture.destination_commit.commit();
    let binding = disclosure_target_binding(commit).unwrap();
    let mut cases = Vec::new();
    let mut changed = commit.clone();
    changed.message.push_str(" changed");
    cases.push(changed);
    let mut changed = commit.clone();
    changed.parents.push([44; 32]);
    cases.push(changed);
    let mut changed = commit.clone();
    changed.profile_pair.chunk_profile = "different".to_string();
    cases.push(changed);
    let mut changed = commit.clone();
    let mut recipe = Vec::new();
    cbor::write_map(&mut recipe, 3);
    cbor::write_uint(&mut recipe, 1);
    // Generic map arguments retain opaque signature-shaped data; overlay's
    // closed argument schema rejects that metadata before normalization.
    cbor::write_text(&mut recipe, "map");
    cbor::write_uint(&mut recipe, 2);
    cbor::write_array(&mut recipe, 0);
    cbor::write_uint(&mut recipe, 3);
    cbor::write_map(&mut recipe, 1);
    cbor::write_text(&mut recipe, "signature");
    cbor::write_bytes(&mut recipe, &[0x55; 64]);
    changed.profile_pair.recipe = Some(recipe);
    cases.push(changed);
    let mut changed = commit.clone();
    changed.profile_pair.entry_receipts.as_mut().unwrap()[0]
        .disclosure_proof
        .as_mut()
        .unwrap()
        .observed_at += 1;
    cases.push(changed);
    let mut changed = commit.clone();
    changed.profile_pair.entry_receipts.as_mut().unwrap()[0]
        .reintroduced_from
        .as_mut()
        .unwrap()
        .path = b"secret".to_vec();
    cases.push(changed);
    for changed in cases {
        assert_ne!(disclosure_target_binding(&changed).unwrap(), binding);
        let (history, signed) = changed_destination(&fixture, changed);
        assert!(
            disclosed_candidate(&history, signed.identity(), &[authority()], defaults()).is_err()
        );
    }

    let mut zeroed = commit.clone();
    zeroed.signature = Some([0; 64]);
    zeroed.profile_pair.entry_receipts.as_mut().unwrap()[0]
        .disclosure_proof
        .as_mut()
        .unwrap()
        .signature = [0; 64];
    assert_eq!(disclosure_target_binding(&zeroed).unwrap(), binding);
    let (history, signed) = changed_destination(&fixture, zeroed);
    assert!(disclosed_candidate(&history, signed.identity(), &[authority()], defaults()).is_err());
    assert!(
        fixture
            .destination
            .introducing_commit(&fixture.target)
            .is_err()
    );

    let mut wrong_signature = commit.clone();
    wrong_signature.signature.as_mut().unwrap()[0] ^= 1;
    let roots = [RequestRoot {
        path: b"/",
        domain: PUBLIC,
    }];
    assert!(
        verify_history(
            &wrong_signature,
            &issuer_keys(),
            &roots,
            &[("refs/heads/main", 4)]
        )
        .is_err()
    );
}

#[test]
fn prov_disclosure_historical_authority_rotation_scope_and_issue_time() {
    let fixture = fixture(file());
    let retired = authority();
    let rotated = DisclosureAuthority {
        public_key: SigningKey::from_bytes(&[22; 32]).verifying_key().to_bytes(),
        not_before: 150,
        not_after: None,
        ..retired
    };
    assert!(
        disclosed_candidate(
            &fixture.destination,
            fixture.target.commit,
            &[retired, rotated],
            defaults()
        )
        .unwrap()
        .finish()
        .is_ok()
    );
    assert!(
        disclosed_candidate(
            &fixture.destination,
            fixture.target.commit,
            &[rotated],
            defaults()
        )
        .is_err()
    );
    for invalid in [
        DisclosureAuthority {
            domain: "private:unrelated",
            ..retired
        },
        DisclosureAuthority {
            not_before: 101,
            ..retired
        },
        DisclosureAuthority {
            not_after: Some(100),
            ..retired
        },
        DisclosureAuthority {
            repository: "",
            ..retired
        },
    ] {
        assert!(
            disclosed_candidate(
                &fixture.destination,
                fixture.target.commit,
                &[invalid],
                defaults()
            )
            .is_err()
        );
    }
    let ambiguous = DisclosureAuthority {
        repository: "different-physical-repository",
        ..retired
    };
    assert!(
        disclosed_candidate(
            &fixture.destination,
            fixture.target.commit,
            &[retired, ambiguous],
            defaults()
        )
        .is_err()
    );
    assert!(
        sign_disclosure(
            DisclosureSigning {
                source_history: &fixture.source,
                source_commit: fixture.source_commit.identity(),
                source_path: b"secret",
                destination_history: &fixture.destination,
                destination_commit: fixture.target.commit,
                destination_path: b"file",
                source_defaults: defaults(),
                destination_defaults: defaults(),
            },
            retired,
            &AUTHORITY_SECRET
        )
        .is_err()
    );
}

#[test]
fn prov_disclosure_memo_context_distinguishes_exact_signed_boundary_destination() {
    let fixture = fixture(file());
    let (first, _) = disclosed_candidate(
        &fixture.destination,
        fixture.target.commit,
        &[authority()],
        defaults(),
    )
    .unwrap()
    .finish()
    .unwrap();
    let mut commit = fixture.destination_commit.commit().clone();
    commit.message = "separate authorized publication".to_string();
    let second_commit = resign_certificate(&fixture, commit, &fixture.destination);
    let mut second = fixture.destination.clone();
    second.insert_commit(second_commit.clone()).unwrap();
    let (second, _) = disclosed_candidate(
        &second,
        second_commit.identity(),
        &[authority()],
        defaults(),
    )
    .unwrap()
    .finish()
    .unwrap();
    let first = TrustContext::new(
        &first,
        fixture.target.commit,
        Selector::preset(Preset::Any),
        PUBLIC,
        None,
    )
    .unwrap();
    let second = TrustContext::new(
        &second,
        second_commit.identity(),
        Selector::preset(Preset::Any),
        PUBLIC,
        None,
    )
    .unwrap();
    assert!(first.accepts_path(b"file"));
    assert!(second.accepts_path(b"file"));
    assert_ne!(first.canonical_context(), second.canonical_context());
}
