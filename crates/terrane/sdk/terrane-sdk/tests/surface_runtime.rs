//! Exercises actual authorized preparation and registered SDK lifecycle.
#![cfg(all(feature = "tokio", feature = "surface-sdk", unix))]

#[allow(
    dead_code,
    reason = "Shared SDK fixtures also provide reopen and inventory helpers for other integration targets."
)]
#[path = "local_sdk/fixture.rs"]
mod fixture;

use std::sync::atomic::{AtomicUsize, Ordering};

use fixture::{Fixture, MAIN, NEW, OLD, TestResult};
use terrane_sdk::{
    config::Config,
    repository::Error,
    surface::{ExposureState, PreparedExposures, TokenResolver, TreeSchema, View},
};

struct Resolver {
    token: Vec<u8>,
    deny_second: bool,
    resolutions: AtomicUsize,
}

#[async_trait::async_trait]
impl TokenResolver for Resolver {
    async fn resolve(&self, reference: &str) -> Result<Vec<u8>, Error> {
        self.resolutions.fetch_add(1, Ordering::Relaxed);
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
        resolutions: Default::default(),
    };

    let mut unknown_policy = config.exposures().to_vec();
    unknown_policy[1].view.policy = Some("unregistered".to_owned());
    assert!(matches!(
        PreparedExposures::prepare(&fixture.repository, &unknown_policy, &resolver).await,
        Err(Error::UnavailableOperation("unregistered view policy"))
    ));
    assert_eq!(
        resolver.resolutions.load(Ordering::Relaxed),
        0,
        "the whole list must reject an unknown policy before resolving any token"
    );

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
        resolutions: Default::default(),
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
    use terrane_format::{
        cbor,
        tree_builder::Tree,
        tree_format::{Property, TreeUse},
    };
    use terrane_sdk::repository::PreparedTree;

    let fixture = Fixture::new().await?;
    let old = fixture.commit_bytes(OLD).await?;
    let config = Config::parse(&configuration(&fixture))?;
    let resolver = Resolver {
        token: fixture.authority.token().to_vec(),
        deny_second: false,
        resolutions: Default::default(),
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

#[tokio::test]
#[ignore = "Requires native ext4 xattrs; executed by gate:surface-status"]
async fn sdk_presents_attribute_ownership_canonical_times_and_filtered_xattrs() -> TestResult {
    use std::os::unix::fs::MetadataExt;
    use terrane_format::{
        cbor,
        tree_builder::Tree,
        tree_format::{self, Attribute, ExtendedAttribute, LeafItem, Property, TreeUse},
    };
    use terrane_sdk::repository::PreparedTree;

    let fixture = Fixture::new().await?;
    let old = fixture.commit_bytes(OLD).await?;
    let metadata = fixture
        .repository
        .validate_view_schema(
            &View::parse(MAIN)?,
            fixture.authority.token(),
            "sdk",
            &TreeSchema::default(),
        )
        .await?;
    let source_metadata = std::fs::metadata(fixture.parent.join("source/file"))?;
    let mut uid = Vec::new();
    let mut gid = Vec::new();
    cbor::write_uint(&mut uid, u64::from(source_metadata.uid()));
    cbor::write_uint(&mut gid, u64::from(source_metadata.gid()));
    let mut entry =
        tree_format::decode_entry_bytes(&metadata.entries[0].1, metadata.minimum_chunk_size)?;
    entry.attrs.extend([
        Attribute {
            name: "gid",
            value: &gid,
        },
        Attribute {
            name: "uid",
            value: &uid,
        },
    ]);
    entry.attrs_present = true;
    entry.xattrs = vec![
        ExtendedAttribute {
            name: b"security.test",
            value: b"must stay hidden",
        },
        ExtendedAttribute {
            name: b"system.test",
            value: b"must stay hidden",
        },
        ExtendedAttribute {
            name: b"trusted.test",
            value: b"must stay hidden",
        },
        ExtendedAttribute {
            name: b"user.note",
            value: b"visible bytes",
        },
    ];
    entry.xattrs_present = true;
    let mut domain = Vec::new();
    cbor::write_text(&mut domain, "private:owner");
    let mut acl = Vec::new();
    cbor::write_array(&mut acl, 1);
    cbor::write_array(&mut acl, 2);
    cbor::write_text(&mut acl, "owner");
    cbor::write_uint(&mut acl, 31);
    let tree = Tree::build(
        vec![
            LeafItem {
                key: b"file".to_vec(),
                entry,
            },
            LeafItem {
                key: b"link".to_vec(),
                entry: tree_format::Entry {
                    kind: tree_format::EntryKind::Symlink { target: b"file" },
                    attrs: Vec::new(),
                    attrs_present: false,
                    xattrs: Vec::new(),
                    xattrs_present: false,
                    provenance: None,
                },
            },
        ],
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
        metadata.minimum_chunk_size,
        TreeUse::Ordinary,
    )?;
    let staged = PreparedTree::from_tree(&tree)?;
    let mut session = fixture
        .repository
        .begin(MAIN, fixture.authority.token(), "sdk")
        .await?;
    let mut request = fixture.repository.source_request(
        &fixture.authority,
        fixture::metadata("Publish inode presentation fixture"),
    );
    request.commit.tree = staged.root();
    request.commit.parents = vec![old];
    // The modified entry introduces this reference again. Supply real plaintext
    // admission evidence instead of bypassing the guarded domain-reference check.
    let profile = fixture.repository.chunk_profile();
    request
        .uploads
        .push(terrane_sdk::ref_advance::StagedUpload::Chunk {
            encoded: terrane_sdk::codec::encode_chunk(OLD, profile.maximum(), 3, None)?,
            identity: terrane_format::identity::TERRANE_V1
                .calculate(terrane_format::identity::IdentityKind::Chunk, OLD)?,
            declared_plaintext_len: OLD.len(),
            position: terrane_sdk::store::ChunkPosition::Final,
            profile: Box::new(profile.clone()),
        });
    fixture
        .repository
        .commit(&mut session, staged, request)
        .await?;

    let serving = fixture
        .repository
        .realize(View::parse(MAIN)?, fixture.hints("presentation"))
        .await?;
    let output = fixture.parent.join("presentation/file");
    let presented = std::fs::symlink_metadata(&output)?;
    assert_eq!(presented.uid(), source_metadata.uid());
    assert_eq!(presented.gid(), source_metadata.gid());
    assert_eq!((presented.mtime(), presented.mtime_nsec()), (0, 0));
    assert_eq!((presented.atime(), presented.atime_nsec()), (0, 0));
    let link = std::fs::symlink_metadata(fixture.parent.join("presentation/link"))?;
    assert!(link.file_type().is_symlink());
    assert_eq!((link.mtime(), link.mtime_nsec()), (0, 0));
    assert_eq!(
        std::fs::read_link(fixture.parent.join("presentation/link"))?,
        std::path::Path::new("file")
    );
    let root = std::fs::symlink_metadata(fixture.parent.join("presentation"))?;
    assert_eq!((root.mtime(), root.mtime_nsec()), (0, 0));
    let names = xattr::list(&output)?.collect::<Vec<_>>();
    assert!(names.contains(&std::ffi::OsString::from("user.note")));
    for hidden in ["security.test", "system.test", "trusted.test"] {
        assert!(!names.contains(&std::ffi::OsString::from(hidden)));
    }
    assert_eq!(
        xattr::get(&output, "user.note")?.as_deref(),
        Some(b"visible bytes".as_slice())
    );
    serving.stop()?;
    Ok(())
}

#[tokio::test]
async fn readonly_sdk_refuses_writer_mode_before_any_endpoint_or_mutation() -> TestResult {
    let fixture = Fixture::new().await?;
    let old = fixture.commit_bytes(OLD).await?;
    let config = Config::parse(&configuration(&fixture))?;
    let mut exposures = config.exposures().to_vec();
    exposures[0].writer = Some(terrane_sdk::surface::WriterMode::Sync);
    let resolver = Resolver {
        token: fixture.authority.token().to_vec(),
        deny_second: false,
        resolutions: Default::default(),
    };

    assert!(
        PreparedExposures::prepare(&fixture.repository, &exposures, &resolver)
            .await
            .is_err()
    );
    assert!(!fixture.parent.join("first").exists());
    assert_eq!(
        fixture
            .repository
            .read_file(
                &View::parse(MAIN)?,
                b"file",
                fixture.authority.token(),
                "sdk"
            )
            .await?,
        (old, OLD.to_vec())
    );
    Ok(())
}
