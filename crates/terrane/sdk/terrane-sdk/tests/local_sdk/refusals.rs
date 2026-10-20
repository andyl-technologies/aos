//! Checks exact refusal outcomes and fresh authority after earlier success.

use super::fixture::{Fixture, MAIN, OLD, TestResult, fixed, inventory, metadata};
use std::error::Error as _;
use terrane_format::{
    cbor,
    tree_builder::Tree,
    tree_format::{Property, TreeUse},
};
use terrane_sdk::{
    repository::{Error, PreparedTree},
    store::StoreErrorKind,
    surface::{EndpointKind, ReaderMode, View},
};

#[tokio::test]
async fn sdk_checkout_public_api_rejects_unavailable_registry_mode_endpoint_and_policy()
-> TestResult {
    let fixture = Fixture::new().await?;
    let commit = fixture.commit_bytes(OLD).await?;
    let view = View::parse(MAIN)?;
    let before = inventory(&fixture.parent)?;

    for case in ["surface", "follow", "endpoint", "policy"] {
        let mut hints = fixture.hints(case);
        let mut selected = view.clone();
        match case {
            "surface" => hints.surface = "x-unavailable-sdk-test".into(),
            "follow" => hints.reader = ReaderMode::Follow,
            "endpoint" => hints.endpoint.kind = EndpointKind::UnixSocket,
            "policy" => selected.policy = Some("x-unregistered-sdk-test".into()),
            _ => unreachable!(),
        }
        let result = fixture.repository.realize(selected, hints).await;
        let error = result.err().ok_or("unsupported presentation must refuse")?;
        match case {
            "surface" => assert!(
                matches!(error, Error::UnavailableSurface(ref name) if name == "x-unavailable-sdk-test"),
                "{error:?}"
            ),
            "follow" => assert!(
                matches!(error, Error::UnavailableOperation("SDK follow reader")),
                "{error:?}"
            ),
            "endpoint" => assert!(matches!(error, Error::Unrealizable), "{error:?}"),
            "policy" => assert!(
                matches!(
                    error,
                    Error::UnavailableOperation("unregistered view policy")
                ),
                "{error:?}"
            ),
            _ => unreachable!(),
        }
        assert_eq!(
            inventory(&fixture.parent)?,
            before,
            "persistent namespace changed for {case}"
        );
        assert_eq!(
            fixture
                .repository
                .read_file(&view, b"file", fixture.authority.token(), "sdk")
                .await?,
            (commit, OLD.to_vec())
        );
    }
    Ok(())
}

#[tokio::test]
async fn sdk_checkout_public_api_refuses_current_acl_and_missing_original_authority() -> TestResult
{
    let fixture = Fixture::new().await?;
    let old = fixture.commit_bytes(OLD).await?;
    let historical = fixed(old);
    assert_eq!(
        fixture
            .repository
            .read_file(&historical, b"file", fixture.authority.token(), "sdk")
            .await?,
        (old, OLD.to_vec())
    );
    let successful = fixture
        .repository
        .realize(historical.clone(), fixture.hints("authorized"))
        .await?;
    let completed = inventory(&fixture.parent.join("authorized"))?;

    // Old Admin authority admits this genuine new policy; zero verbs also
    // excludes AUTH-22's Commit-implies-Read implication.
    let mut acl = Vec::new();
    cbor::write_array(&mut acl, 1);
    cbor::write_array(&mut acl, 2);
    cbor::write_text(&mut acl, "owner");
    cbor::write_uint(&mut acl, 0);
    let mut domain = Vec::new();
    cbor::write_text(&mut domain, "private:owner");
    let tree = Tree::build(
        Vec::new(),
        Some(vec![
            Property {
                name: "acl",
                value: &acl,
            },
            Property {
                name: "domain",
                value: &domain,
            },
            Property {
                name: "durability",
                value: b"\x65local",
            },
        ]),
        fixture.repository.chunk_profile().minimum() as u64,
        TreeUse::Ordinary,
    )?;
    let prepared = PreparedTree::from_tree(&tree)?;
    let mut session = fixture
        .repository
        .begin(MAIN, fixture.authority.token(), "sdk")
        .await?;
    let mut request = fixture
        .repository
        .source_request(&fixture.authority, metadata("Revoke SDK read authority"));
    request.commit.tree = prepared.root();
    request.commit.parents = vec![old];
    fixture
        .repository
        .commit(&mut session, prepared, request)
        .await?;
    let before = inventory(&fixture.parent)?;

    let error = fixture
        .repository
        .realize(historical, fixture.hints("revoked"))
        .await
        .err()
        .ok_or("fresh checkout must honor current ACL")?;
    let Error::Store(failure) = error else {
        panic!("expected current authorization failure: {error:?}");
    };
    assert!(
        matches!(failure.kind(), StoreErrorKind::Denied { verb: "read", pattern } if pattern == MAIN),
        "{failure:?}"
    );
    assert_eq!(inventory(&fixture.parent)?, before);
    assert_eq!(successful.status().commit, old);
    assert_eq!(inventory(&fixture.parent.join("authorized"))?, completed);
    assert_eq!(std::fs::read(fixture.parent.join("authorized/file"))?, OLD);

    let original = Fixture::new().await?;
    let commit = original.commit_bytes(OLD).await?;
    let target = fixed(commit);
    assert_eq!(
        original
            .repository
            .read_file(&target, b"file", original.authority.token(), "sdk")
            .await?,
        (commit, OLD.to_vec())
    );
    original
        .repository
        .realize(target.clone(), original.hints("original-authorized"))
        .await?;
    let completed = inventory(&original.parent.join("original-authorized"))?;
    // This is loss of the actual protected record, never a replacement authority.
    let hex: String = commit.iter().map(|byte| format!("{byte:02x}")).collect();
    let association = original
        .location
        .authority
        .join(format!("commit-{hex}.cbor"));
    assert!(std::fs::symlink_metadata(&association)?.is_file());
    std::fs::remove_file(&association)?;
    let before = inventory(&original.parent)?;

    let error = original
        .repository
        .realize(target, original.hints("missing-original"))
        .await
        .err()
        .ok_or("fresh checkout must recheck protected original authority")?;
    let Error::Store(failure) = error else {
        panic!("expected original authority failure: {error:?}");
    };
    assert!(
        matches!(
            failure.kind(),
            StoreErrorKind::Unavailable { retry_after: None }
        ),
        "{failure:?}"
    );
    assert_eq!(
        failure
            .source()
            .and_then(|source| source.downcast_ref::<std::io::Error>())
            .ok_or("native cause retained")?
            .kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(inventory(&original.parent)?, before);
    assert_eq!(
        inventory(&original.parent.join("original-authorized"))?,
        completed
    );
    assert_eq!(
        std::fs::read(original.parent.join("original-authorized/file"))?,
        OLD
    );
    Ok(())
}
