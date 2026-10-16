//! Exercises actual authorized preparation and registered SDK lifecycle.
#![cfg(all(feature = "tokio", feature = "surface-sdk", unix))]

#[path = "local_sdk/fixture.rs"]
mod fixture;

use fixture::{Fixture, MAIN, NEW, OLD, TestResult};
use terrane::{
    config::Config,
    repository::Error,
    surface::{ExposureState, PreparedExposures, TokenResolver, TreeSchema, View},
};

struct Resolver {
    token: Vec<u8>,
    deny_second: bool,
}

#[async_trait::async_trait]
impl TokenResolver for Resolver {
    async fn resolve(&self, reference: &str) -> Result<Vec<u8>, Error> {
        if self.deny_second && reference.ends_with("second") {
            return Err(Error::Denied);
        }
        Ok(self.token.clone())
    }
}

fn configuration(fixture: &Fixture) -> String {
    let mut text = "store='disk(/tmp)'\n".to_string();
    for id in ["first", "second"] {
        text.push_str(&format!("[[expose]]\nid='{id}'\nview='{MAIN}'\nsurface='sdk'\nat='{}'\ntoken='file:/tokens/{id}'\nmode={{reader='pinned'}}\n", fixture.parent.join(id).display()));
    }
    text
}

#[tokio::test]
async fn preparation_refuses_entire_list_before_any_endpoint_starts() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
    let config = Config::parse(&configuration(&fixture))?;
    let resolver = Resolver {
        token: fixture.authority.token().to_vec(),
        deny_second: true,
    };
    assert!(
        PreparedExposures::prepare(&fixture.repository, config.exposures(), &resolver)
            .await
            .is_err()
    );
    assert!(!fixture.parent.join("first").exists());
    assert!(!fixture.parent.join("second").exists());
    Ok(())
}

#[tokio::test]
async fn prepared_snapshots_keep_validated_commit_and_report_complete_status() -> TestResult {
    let fixture = Fixture::new().await?;
    let first = fixture.commit_bytes(OLD).await?;
    let config = Config::parse(&configuration(&fixture))?;
    let resolver = Resolver {
        token: fixture.authority.token().to_vec(),
        deny_second: false,
    };
    let prepared =
        PreparedExposures::prepare(&fixture.repository, config.exposures(), &resolver).await?;
    fixture.commit_bytes(NEW).await?;
    let handles = prepared.start(&fixture.repository).await?;
    assert_eq!(handles.len(), 2);
    for (index, id) in ["first", "second"].iter().enumerate() {
        assert_eq!(std::fs::read(fixture.parent.join(id).join("file"))?, OLD);
        let status = handles[index].status();
        assert_eq!(status.commit, first);
        assert_eq!(status.surface, "sdk");
        assert_eq!(status.realizer, None);
        assert!(status.features.is_empty());
        assert_eq!(status.writer, None);
        assert_eq!(status.last_commit, None);
        assert_eq!(status.state, ExposureState::Serving);
        handles[index].stop()?;
    }
    Ok(())
}

#[tokio::test]
async fn schema_refusal_precedes_sdk_directory_creation() -> TestResult {
    let fixture = Fixture::new().await?;
    fixture.commit_bytes(OLD).await?;
    let schema = TreeSchema {
        forbidden_entries: vec![b"file".to_vec()],
        ..TreeSchema::default()
    };
    assert!(matches!(
        fixture
            .repository
            .validate_view_schema(
                &View::parse(MAIN)?,
                fixture.authority.token(),
                "sdk",
                &schema
            )
            .await,
        Err(Error::Schema)
    ));
    assert!(!fixture.parent.join("output").exists());
    let metadata = fixture
        .repository
        .validate_view_schema(
            &View::parse(MAIN)?,
            fixture.authority.token(),
            "sdk",
            &TreeSchema::default(),
        )
        .await?;
    assert_eq!(metadata.entries.len(), 1);
    Ok(())
}

#[tokio::test]
async fn prepared_snapshots_recheck_current_authority_before_startup() -> TestResult {
    use terrane::repository::PreparedTree;
    use terrane_core::{
        cbor,
        tree_builder::Tree,
        tree_format::{Property, TreeUse},
    };

    let fixture = Fixture::new().await?;
    let old = fixture.commit_bytes(OLD).await?;
    let config = Config::parse(&configuration(&fixture))?;
    let resolver = Resolver {
        token: fixture.authority.token().to_vec(),
        deny_second: false,
    };
    let prepared =
        PreparedExposures::prepare(&fixture.repository, config.exposures(), &resolver).await?;

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
    let replacement = PreparedTree::from_tree(&tree)?;
    let mut session = fixture
        .repository
        .begin(MAIN, fixture.authority.token(), "sdk")
        .await?;
    let mut request = fixture.repository.source_request(
        &fixture.authority,
        fixture::metadata("Revoke prepared exposure authority"),
    );
    request.commit.tree = replacement.root();
    request.commit.parents = vec![old];
    fixture
        .repository
        .commit(&mut session, replacement, request)
        .await?;

    assert!(prepared.start(&fixture.repository).await.is_err());
    assert!(!fixture.parent.join("first").exists());
    assert!(!fixture.parent.join("second").exists());
    Ok(())
}
