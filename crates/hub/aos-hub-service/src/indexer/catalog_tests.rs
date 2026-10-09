//! Signed surface fixtures for default catalog selection and draft isolation.

use std::collections::BTreeMap;

use anyhow::Result;
use aos_registry_format::object::{self, ObjectKind, Oid, TreeEntry};
use aos_registry_format::sshsig;
use aos_registry_format::tag::render_tag_payload;
use ed25519_dalek::SigningKey;

use super::index_registry;
use crate::db::{Database, RegistryRecord};
use crate::fetch::SurfaceFetch;

#[derive(Default)]
struct CatalogSurface {
    objects: BTreeMap<String, Vec<u8>>,
}

impl CatalogSurface {
    fn object(&mut self, kind: ObjectKind, body: &[u8]) -> Oid {
        let oid = object::hash_object(kind, body);
        self.objects
            .insert(oid.loose_path(), object::encode_loose(kind, body).unwrap());
        oid
    }

    fn tree(&mut self, entries: &[(&str, &str, Oid)]) -> Oid {
        let entries = entries
            .iter()
            .map(|(mode, name, oid)| TreeEntry {
                mode: (*mode).into(),
                name: (*name).into(),
                oid: *oid,
            })
            .collect::<Vec<_>>();
        self.object(ObjectKind::Tree, &object::encode_tree(&entries))
    }

    fn commit(&mut self, description: &str, when: i64, key: &SigningKey) -> Oid {
        let registry = self.object(ObjectKind::Blob, b"[registry]\nname = \"Fixture\"\n");
        let package = format!(
            r#"[package]
name = "example"
description = "{description}"
license = "MIT"
maintainer = "fixture"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-example"
closure_size = 1
source_drv = ""
source_nar_hash = ""
"#
        );
        let package = self.object(ObjectKind::Blob, package.as_bytes());
        let bucket = self.tree(&[("100644", "example.toml", package)]);
        let packages = self.tree(&[("40000", "00", bucket)]);
        let root = self.tree(&[
            ("40000", "packages", packages),
            ("100644", "registry.toml", registry),
        ]);
        let headers = format!(
            "tree {root}\nauthor Fixture <fixture@example.org> {when} +0000\ncommitter Fixture <fixture@example.org> {when} +0000\n"
        );
        let payload = format!("{headers}\nCatalog\n");
        let armor = sshsig::sign_armored(payload.as_bytes(), key);
        let signature = armor.trim_end().replace('\n', "\n ");
        let commit = format!("{headers}gpgsig-sha256 {signature}\n\nCatalog\n");
        self.object(ObjectKind::Commit, commit.as_bytes())
    }

    fn tag(&mut self, name: &str, target: Oid, target_type: &str, key: &SigningKey) -> Oid {
        let body = render_tag_payload(name, &target.to_hex(), target_type, "Fixture", 1).unwrap();
        let armor = sshsig::sign_armored(body.as_bytes(), key);
        self.object(ObjectKind::Tag, format!("{body}{armor}").as_bytes())
    }

    fn channel(&mut self, target: Oid, key: &SigningKey) {
        let body = render_tag_payload("stable", &target.to_hex(), "tag", "Fixture", 1).unwrap();
        let armor = sshsig::sign_armored(body.as_bytes(), key);
        for bucket in 0..=255 {
            self.objects.insert(
                format!("channels/stable/{bucket:02x}"),
                format!("{body}{armor}").into_bytes(),
            );
        }
    }

    fn refs(&mut self, frontier: Oid, draft: Oid, releases: &[(&str, Oid)]) {
        let mut refs =
            format!("{frontier}\trefs/heads/stable\n{draft}\trefs/heads/maintainer/candidate\n");
        for (name, oid) in releases {
            refs.push_str(&format!("{oid}\trefs/tags/{name}\n"));
        }
        self.objects.insert("info/refs".into(), refs.into_bytes());
        self.objects
            .insert("HEAD".into(), b"ref: refs/heads/stable\n".to_vec());
    }
}

#[async_trait::async_trait]
impl SurfaceFetch for CatalogSurface {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.objects.get(path).cloned())
    }

    fn describe(&self) -> String {
        "signed-catalog-fixture".into()
    }
}

async fn registry(db: &Database, key: &SigningKey) -> RegistryRecord {
    let trusted = sshsig::trusted_key_line("fixture", &key.verifying_key());
    let id = db
        .register_registry("signed-catalog-fixture", &[trusted], true)
        .await
        .unwrap();
    db.registry_by_id(id).await.unwrap().unwrap()
}

#[tokio::test]
async fn signed_draft_updates_stay_private_until_release_and_channel_selection() {
    let db = Database::open_in_memory().await.unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let registry = registry(&db, &key).await;
    let mut surface = CatalogSurface::default();
    let released = surface.commit("Released catalog", 10, &key);
    let draft = surface.commit("Newer draft catalog", 100, &key);
    let release_tag = surface.tag("1.0.0", released, "commit", &key);
    surface.refs(released, draft, &[("1.0.0", release_tag)]);
    surface.channel(release_tag, &key);

    let first = index_registry(&db, &surface, &registry, None)
        .await
        .unwrap();
    assert_eq!(first.packages, 1);
    assert_eq!(first.channels, 1);
    assert_eq!(
        db.list_packages(registry.id).await.unwrap()[0].description,
        "Released catalog"
    );
    assert_eq!(
        db.default_browse_release(registry.id)
            .await
            .unwrap()
            .as_deref(),
        Some("1.0.0")
    );

    let unchanged = index_registry(&db, &surface, &registry, None)
        .await
        .unwrap();
    assert!(unchanged.incremental);

    let revised = surface.commit("Updated newer draft", 200, &key);
    surface.refs(released, revised, &[("1.0.0", release_tag)]);
    index_registry(&db, &surface, &registry, None)
        .await
        .unwrap();
    assert_eq!(
        db.list_packages(registry.id).await.unwrap()[0].description,
        "Released catalog"
    );

    let final_tag = surface.tag("2.0.0", revised, "commit", &key);
    surface.refs(
        released,
        revised,
        &[("1.0.0", release_tag), ("2.0.0", final_tag)],
    );
    index_registry(&db, &surface, &registry, None)
        .await
        .unwrap();
    assert_eq!(db.list_releases(registry.id).await.unwrap().len(), 2);
    assert_eq!(
        db.list_packages(registry.id).await.unwrap()[0].description,
        "Released catalog"
    );
    assert_eq!(
        db.release_browse_packages(registry.id, "2.0.0")
            .await
            .unwrap()
            .unwrap()[0]
            .package
            .description,
        "Updated newer draft"
    );

    // Mutable signed partitions advance while info/refs remains unchanged.
    surface.channel(final_tag, &key);
    let advanced = index_registry(&db, &surface, &registry, None)
        .await
        .unwrap();
    assert!(!advanced.incremental);
    assert_eq!(
        db.list_packages(registry.id).await.unwrap()[0].description,
        "Updated newer draft"
    );
    assert_eq!(
        db.default_browse_release(registry.id)
            .await
            .unwrap()
            .as_deref(),
        Some("2.0.0")
    );
    assert!(
        index_registry(&db, &surface, &registry, None)
            .await
            .unwrap()
            .incremental
    );
}

#[tokio::test]
async fn released_tag_without_default_channel_has_only_historical_catalog() {
    let db = Database::open_in_memory().await.unwrap();
    let key = SigningKey::from_bytes(&[8; 32]);
    let registry = registry(&db, &key).await;
    let mut surface = CatalogSurface::default();
    let released = surface.commit("Released catalog", 10, &key);
    let tag = surface.tag("1.0.0", released, "commit", &key);
    surface.objects.insert(
        "info/refs".into(),
        format!("{tag}\trefs/tags/1.0.0\n").into_bytes(),
    );

    let outcome = index_registry(&db, &surface, &registry, None)
        .await
        .unwrap();
    assert_eq!(outcome.packages, 0);
    assert_eq!(outcome.releases, 1);
    assert!(db.list_packages(registry.id).await.unwrap().is_empty());
    assert!(db
        .default_browse_release(registry.id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        db.release_browse_packages(registry.id, "1.0.0")
            .await
            .unwrap()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn candidate_admission_authenticates_exact_release_without_advancing_distribution() {
    use aos_registry_format::staging::{
        inventory_digest, StageObject, StagePointer, StageRevision, STAGE_SCHEMA,
    };
    use sha2::{Digest as _, Sha256};

    let db = Database::open_in_memory().await.unwrap();
    let key = SigningKey::from_bytes(&[9; 32]);
    let registry = registry(&db, &key).await;
    let mut surface = CatalogSurface::default();
    let released = surface.commit("Released catalog", 10, &key);
    let candidate = surface.commit("Candidate catalog", 100, &key);
    let release_tag = surface.tag("1.0.0", released, "commit", &key);
    let candidate_tag = surface.tag("2.0.0", candidate, "commit", &key);
    surface.refs(released, candidate, &[("1.0.0", release_tag)]);
    surface.channel(release_tag, &key);
    let current_refs = surface.objects.get("info/refs").unwrap();
    let mut proposed_refs = current_refs.clone();
    proposed_refs.extend_from_slice(format!("{candidate_tag}\trefs/tags/2.0.0\n").as_bytes());
    let pack_name = format!("pack-{}.pack", "d".repeat(64));
    let inventory = vec![StageObject {
        path: format!("releases/2/0/0/objects/pack/{pack_name}"),
        sha256: format!("sha256:{}", "d".repeat(64)),
        byte_size: 1,
        kind: "git-pack".into(),
        media_type: "application/octet-stream".into(),
    }];
    let revision = StageRevision {
        schema: STAGE_SCHEMA.into(),
        id: "candidate".into(),
        registry: registry.slug.clone(),
        revision: 1,
        release_id: "2.0.0".into(),
        source_branch: "maintainer/candidate".into(),
        commit: candidate.to_hex(),
        container: None,
        inventory_digest: inventory_digest(&inventory).unwrap(),
        inventory,
        publication: vec![
            StagePointer {
                path: "info/refs".into(),
                bytes: proposed_refs,
                expected_sha256: Some(format!(
                    "sha256:{}",
                    hex::encode(Sha256::digest(current_refs))
                )),
            },
            StagePointer {
                path: "releases/2/0/0/objects/info/packs".into(),
                bytes: format!("P {pack_name}\n").into_bytes(),
                expected_sha256: None,
            },
        ],
        store_roots: vec![],
    };

    super::staging::validate_candidate(&db, &surface, &registry, &revision)
        .await
        .unwrap();
    assert!(db.list_releases(registry.id).await.unwrap().is_empty());

    let mut wrong_commit = revision.clone();
    wrong_commit.commit = released.to_hex();
    assert!(
        super::staging::validate_candidate(&db, &surface, &registry, &wrong_commit)
            .await
            .is_err()
    );

    let mut moved_channel = revision.clone();
    moved_channel.publication[0].bytes =
        String::from_utf8(moved_channel.publication[0].bytes.clone())
            .unwrap()
            .replace(
                &format!("{released}\trefs/heads/stable"),
                &format!("{candidate}\trefs/heads/stable"),
            )
            .into_bytes();
    assert!(
        super::staging::validate_candidate(&db, &surface, &registry, &moved_channel)
            .await
            .is_err()
    );

    let mut replaced_release = revision.clone();
    replaced_release.publication[0].bytes =
        String::from_utf8(replaced_release.publication[0].bytes.clone())
            .unwrap()
            .replace(
                &format!("{release_tag}\trefs/tags/1.0.0"),
                &format!("{candidate_tag}\trefs/tags/1.0.0"),
            )
            .into_bytes();
    assert!(
        super::staging::validate_candidate(&db, &surface, &registry, &replaced_release)
            .await
            .is_err()
    );

    let mut default_workspace = revision.clone();
    default_workspace.source_branch = "stable".into();
    assert!(
        super::staging::validate_candidate(&db, &surface, &registry, &default_workspace)
            .await
            .is_err()
    );

    let mut unrelated_tag = revision.clone();
    unrelated_tag.publication[0]
        .bytes
        .extend_from_slice(format!("{candidate_tag}\trefs/tags/unrelated\n").as_bytes());
    assert!(
        super::staging::validate_candidate(&db, &surface, &registry, &unrelated_tag)
            .await
            .is_err()
    );

    let mut unrelated_pointer = revision.clone();
    unrelated_pointer.publication.push(StagePointer {
        path: "web/config.json".into(),
        bytes: b"unrelated pointer".to_vec(),
        expected_sha256: None,
    });
    assert!(
        super::staging::validate_candidate(&db, &surface, &registry, &unrelated_pointer)
            .await
            .is_err()
    );

    let mut stale_pointer = revision;
    stale_pointer.publication[0].expected_sha256 = None;
    assert!(
        super::staging::validate_candidate(&db, &surface, &registry, &stale_pointer)
            .await
            .is_err()
    );
}
