//! Current upstream metadata and closed storage-local Git discovery.
//!
//! Native records exact bounded trust metadata. Encoded Git pairs and raw tree
//! framing stay beside storage; complete semantic inventories supply closure
//! rows and record the representations that actually contain each selected OID.

use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::{ensure, Context as _, Result};
use aos_hub_core::db::{Database, RegistryRecord};
use aos_hub_core::mirror_inspection::{MirrorPackProjection, MirrorPackSelection};
use aos_hub_core::mirror_work::MirrorVerification;
use aos_registry_surface::object::{self, ObjectKind, Oid, TreeEntry};
use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use tokio::sync::OnceCell;

use crate::fetch::SurfaceFetch as _;
use crate::storage_work::RemoteStorageWorkClient;

pub(super) struct MetadataDiscovery<'a> {
    upstream: crate::fetch::HttpFetch,
    db: &'a Database,
    work: &'a RemoteStorageWorkClient,
    registry: RegistryRecord,
    proofs: Mutex<BTreeMap<String, MirrorVerification>>,
    representations: Mutex<BTreeMap<Oid, Vec<String>>>,
    candidates: OnceCell<Vec<String>>,
    pair_sources: Mutex<BTreeMap<String, String>>,
}

impl<'a> MetadataDiscovery<'a> {
    #[cfg(test)]
    pub(super) async fn controlled(
        db: &'a Database,
        work: &'a RemoteStorageWorkClient,
        registry: &RegistryRecord,
        upstream: crate::fetch::HttpFetch,
    ) -> Result<Self> {
        let source = db
            .mirror_source(registry.id)
            .await?
            .context("controlled mirror upstream disappeared")?;
        aos_hub_core::url_guard::is_safe_remote_url(&source.upstream_url)?;
        ensure!(
            url::Url::parse(&source.upstream_url)?.scheme() == "https",
            "controlled mirror source requires HTTPS"
        );
        Ok(Self::from_upstream(db, work, registry, upstream))
    }

    pub(super) async fn new(
        db: &'a Database,
        work: &'a RemoteStorageWorkClient,
        registry: &RegistryRecord,
        selection: &super::selection::Selection,
    ) -> Result<Self> {
        selection.validate_current(db, work, registry).await?;
        let upstream = &selection.source.source_url;
        crate::fetch::is_safe_remote_url(upstream)?;
        ensure!(
            url::Url::parse(upstream)?.scheme() == "https",
            "hybrid mirror source requires HTTPS"
        );
        let upstream = crate::fetch::HttpFetch::new(upstream)
            .await
            .for_mirror_metadata();
        Ok(Self::from_upstream(db, work, registry, upstream))
    }

    fn from_upstream(
        db: &'a Database,
        work: &'a RemoteStorageWorkClient,
        registry: &RegistryRecord,
        upstream: crate::fetch::HttpFetch,
    ) -> Self {
        Self {
            upstream,
            db,
            work,
            registry: registry.clone(),
            proofs: Default::default(),
            representations: Default::default(),
            candidates: OnceCell::new(),
            pair_sources: Default::default(),
        }
    }

    pub(super) fn proofs(&self) -> Result<BTreeMap<String, MirrorVerification>> {
        Ok(self
            .proofs
            .lock()
            .map_err(|_| anyhow::anyhow!("mirror discovery is poisoned"))?
            .clone())
    }

    fn retain_proof(&self, path: &str, proof: MirrorVerification) -> Result<()> {
        let mut proofs = self
            .proofs
            .lock()
            .map_err(|_| anyhow::anyhow!("mirror discovery is poisoned"))?;
        if let Some(prior) = proofs.get(path) {
            ensure!(prior == &proof, "mirror metadata changed during discovery");
        }
        ensure!(
            proofs.len() < 100_000 || proofs.contains_key(path),
            "mirror discovery exceeds its object count"
        );
        proofs.insert(path.into(), proof);
        Ok(())
    }

    fn retain_pair(&self, oid: Oid, pair: &MirrorPackProjection) -> Result<()> {
        let paths = vec![pair.pack.path.clone(), pair.index.path.clone()];
        for source in [&pair.pack, &pair.index] {
            self.retain_proof(
                &source.path,
                MirrorVerification::Sha256 {
                    sha256: source.sha256.clone(),
                    size: source.size,
                },
            )?;
        }
        let mut representations = self
            .representations
            .lock()
            .map_err(|_| anyhow::anyhow!("mirror representation state is poisoned"))?;
        ensure!(
            representations.len() < 100_000 || representations.contains_key(&oid),
            "mirror Git discovery exceeds its object count"
        );
        if let Some(prior) = representations.get(&oid) {
            ensure!(
                prior == &paths,
                "mirror selected OID changed its representation"
            );
        }
        representations.insert(oid, paths);
        Ok(())
    }

    fn pair_source(&self, index: &str) -> Result<Option<String>> {
        Ok(self
            .pair_sources
            .lock()
            .map_err(|_| anyhow::anyhow!("mirror pair identity is poisoned"))?
            .get(index)
            .cloned())
    }

    fn retain_pair_source(&self, index: &str, pair: &MirrorPackProjection) -> Result<()> {
        let digest = pair.source_commitment()?;
        let mut sources = self
            .pair_sources
            .lock()
            .map_err(|_| anyhow::anyhow!("mirror pair identity is poisoned"))?;
        if let Some(prior) = sources.get(index) {
            ensure!(
                prior == &digest,
                "mirror pair source changed during closure discovery"
            );
        }
        ensure!(
            sources.len() < 128 || sources.contains_key(index),
            "mirror pair count exceeds its bound"
        );
        sources.insert(index.into(), digest);
        Ok(())
    }

    async fn read_inventory(
        &self,
        oid: Oid,
        index: Option<&str>,
    ) -> Result<Option<Vec<TreeEntry>>> {
        use aos_hub_core::mirror_tree_inventory::MirrorTreeInventoryCommitment;
        let Some(first) = self
            .work
            .inspect_mirror_tree_inventory(self.db, &self.registry, index, &oid.to_hex(), None)
            .await?
        else {
            return Ok(None);
        };
        let Some(mut page) = first.page else {
            return Ok(None);
        };
        let source = first.source;
        let commitment = source.source_commitment()?;
        let total = page.total_entries;
        let mut rows: Vec<TreeEntry> = Vec::with_capacity(total);
        loop {
            ensure!(
                page.total_entries == total
                    && page.start_index == rows.len()
                    && page.source_commitment == commitment,
                "inventory changed source or skipped rows"
            );
            for entry in page.entries {
                if let Some(prior) = rows.last() {
                    ensure!(
                        prior.name < entry.name,
                        "inventory reordered entries across pages"
                    );
                }
                rows.push(entry.tree_entry()?);
            }
            let Some(cursor) = page.next_cursor else {
                break;
            };
            let next = self
                .work
                .inspect_mirror_tree_inventory(
                    self.db,
                    &self.registry,
                    index,
                    &oid.to_hex(),
                    Some(cursor),
                )
                .await?
                .context("positive inventory continuation returned absence")?;
            ensure!(
                next.source == source && next.object_size == first.object_size,
                "inventory changed exact source or tree size"
            );
            page = next
                .page
                .context("inventory continuation lost its positive tree")?;
        }
        ensure!(
            rows.len() == total,
            "inventory ended before the complete closure"
        );
        match &source {
            MirrorTreeInventoryCommitment::Pack { pair } => self.retain_pair(oid, pair)?,
            MirrorTreeInventoryCommitment::Loose { object } => {
                self.retain_proof(
                    &object.path,
                    MirrorVerification::Sha256 {
                        sha256: object.sha256.clone(),
                        size: object.size,
                    },
                )?;
                self.representations
                    .lock()
                    .map_err(|_| anyhow::anyhow!("mirror representation state is poisoned"))?
                    .insert(oid, vec![object.path.clone()]);
            }
        }
        Ok(Some(rows))
    }

    async fn candidates(&self) -> Result<&Vec<String>> {
        self.candidates
            .get_or_try_init(|| async {
                let mut bases = vec![String::new()];
                if let Some(refs) = self.fetch("info/refs").await? {
                    let refs = crate::surface::refs::parse_info_refs(std::str::from_utf8(&refs)?)?;
                    for version in refs
                        .tags
                        .keys()
                        .filter(|version| semver::Version::parse(version).is_ok())
                    {
                        let mut parts = version.splitn(3, '.');
                        let major = parts.next().context("release major missing")?;
                        let minor = parts.next().context("release minor missing")?;
                        let rest = parts.next().context("release suffix missing")?;
                        ensure!(
                            bases.len() < 129,
                            "upstream exceeds bounded release pack discovery"
                        );
                        bases.push(format!("releases/{major}/{minor}/{rest}/"));
                    }
                }
                let mut paths = Vec::new();
                for base in bases {
                    let listing = format!("{base}objects/info/packs");
                    let Some(bytes) = self.fetch(&listing).await? else {
                        continue;
                    };
                    for line in std::str::from_utf8(&bytes)?
                        .lines()
                        .filter(|line| !line.is_empty())
                    {
                        let name = line
                            .strip_prefix("P ")
                            .context("invalid upstream pack listing row")?;
                        let stem = name
                            .strip_suffix(".pack")
                            .context("invalid upstream pack listing suffix")?;
                        let index = format!("{base}objects/pack/{stem}.idx");
                        ensure!(
                            aos_registry_surface::pack_index::companion_pack_path(&index)
                                == Some(format!("{base}objects/pack/{name}")),
                            "noncanonical upstream pack listing"
                        );
                        ensure!(
                            paths.len() < 128,
                            "upstream exceeds the bounded pack candidate count"
                        );
                        paths.push(index);
                    }
                }
                paths.sort();
                ensure!(
                    paths.windows(2).all(|paths| paths[0] != paths[1]),
                    "upstream pack listing repeats a pair"
                );
                Ok(paths)
            })
            .await
    }
}

#[async_trait::async_trait]
impl crate::fetch::SurfaceFetch for MetadataDiscovery<'_> {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let Some(bytes) = self.upstream.fetch(path).await? else {
            return Ok(None);
        };
        self.retain_proof(
            path,
            MirrorVerification::Sha256 {
                sha256: hex::encode(Sha256::digest(&bytes)),
                size: bytes.len() as u64,
            },
        )?;
        Ok(Some(bytes))
    }

    fn storage_local_git_projection(&self) -> bool {
        true
    }

    async fn inspect_git_object(&self, oid: Oid) -> Result<Option<(ObjectKind, Vec<u8>)>> {
        // A canonical loose object remains a bounded trust-metadata source.
        // Optional bundle framing is never allowed to poison that fallback.
        if let Some(bytes) = self.fetch(&oid.loose_path()).await? {
            let (kind, content) =
                object::decode_loose_with_limit(&bytes, Some(oid), 128 * 1024 + 64)?;
            ensure!(
                kind != ObjectKind::Tree,
                "raw Hybrid trees require semantic inventory"
            );
            ensure!(
                content.len() <= 128 * 1024,
                "Git content exceeds bounded projection output"
            );
            return Ok(Some((kind, content)));
        }
        for index in self.candidates().await? {
            let pair = self
                .work
                .inspect_mirror_pack(
                    self.db,
                    &self.registry,
                    index,
                    vec![MirrorPackSelection {
                        oid: oid.to_hex(),
                        range: None,
                    }],
                )
                .await?;
            if let Some(projected) = pair.objects.first() {
                let kind = ObjectKind::parse(&projected.kind)?;
                ensure!(
                    kind != ObjectKind::Tree,
                    "raw Hybrid trees require semantic inventory"
                );
                let content =
                    base64::engine::general_purpose::STANDARD.decode(&projected.content_base64)?;
                ensure!(
                    object::hash_object(kind, &content) == oid,
                    "Git projection changed OID"
                );
                self.retain_pair(oid, &pair)?;
                return Ok(Some((kind, content)));
            }
        }
        Ok(None)
    }

    async fn inspect_git_tree_inventory(&self, oid: Oid) -> Result<Vec<TreeEntry>> {
        if let Some(rows) = self.read_inventory(oid, None).await? {
            return Ok(rows);
        }
        for index in self.candidates().await? {
            if let Some(rows) = self.read_inventory(oid, Some(index)).await? {
                return Ok(rows);
            }
        }
        anyhow::bail!("upstream tree is absent from canonical loose and qualified pack sources")
    }

    fn git_object_source_paths(&self, oid: Oid) -> Result<Vec<String>> {
        Ok(self
            .representations
            .lock()
            .map_err(|_| anyhow::anyhow!("mirror representation state is poisoned"))?
            .get(&oid)
            .cloned()
            .unwrap_or_else(|| vec![oid.loose_path()]))
    }

    async fn verified_git_source_paths(&self, oid: Oid) -> Result<Vec<String>> {
        if let Some(paths) = self
            .representations
            .lock()
            .map_err(|_| anyhow::anyhow!("mirror representation state is poisoned"))?
            .get(&oid)
            .cloned()
        {
            return Ok(paths);
        }
        if self
            .proofs
            .lock()
            .map_err(|_| anyhow::anyhow!("mirror discovery is poisoned"))?
            .contains_key(&oid.loose_path())
        {
            return Ok(vec![oid.loose_path()]);
        }
        let path = oid.loose_path();
        if let Some(encoded) = self.fetch(&path).await? {
            object::decode_loose_with_limit(&encoded, Some(oid), 4 * 1024 * 1024 + 64)?;
            return Ok(vec![path]);
        }
        // Negative membership is issued only from complete verified semantic
        // coverage. The Worker retains that coverage across bounded requests.
        for index in self.candidates().await? {
            let membership = self
                .work
                .inspect_mirror_membership(
                    self.db,
                    &self.registry,
                    index,
                    vec![oid.to_hex()],
                    self.pair_source(index)?,
                )
                .await?;
            self.retain_pair_source(index, &membership.pair)?;
            if membership.objects[0].is_some() {
                self.retain_pair(oid, &membership.pair)?;
                return self.git_object_source_paths(oid);
            }
        }
        anyhow::bail!("closure OID is absent from all approved sources")
    }

    async fn verified_git_sources(&self, oids: &[Oid]) -> Result<Vec<Vec<String>>> {
        use futures_util::{stream, StreamExt as _, TryStreamExt as _};

        // Probe canonical loose representations once, preserving compatibility
        // before consulting optional pairs. The closure remains a bounded set
        // selected by the verified manifest/tree walk.
        let unresolved: Vec<_> = {
            let representations = self
                .representations
                .lock()
                .map_err(|_| anyhow::anyhow!("mirror representation state is poisoned"))?;
            oids.iter()
                .copied()
                .filter(|oid| !representations.contains_key(oid))
                .collect()
        };
        let misses: Vec<Option<Oid>> = stream::iter(unresolved)
            .map(|oid| async move {
                let path = oid.loose_path();
                if self
                    .proofs
                    .lock()
                    .map_err(|_| anyhow::anyhow!("mirror discovery is poisoned"))?
                    .contains_key(&path)
                {
                    return Ok(None);
                }
                let Some(encoded) = self.fetch(&path).await? else {
                    return Ok(Some(oid));
                };
                object::decode_loose_with_limit(&encoded, Some(oid), 4 * 1024 * 1024 + 64)?;
                Ok::<_, anyhow::Error>(None)
            })
            .buffer_unordered(8)
            .try_collect()
            .await?;
        let mut missing: std::collections::BTreeSet<_> = misses.into_iter().flatten().collect();

        if missing.is_empty() {
            return oids
                .iter()
                .map(|oid| self.git_object_source_paths(*oid))
                .collect();
        }

        for index in self.candidates().await? {
            let selections: Vec<_> = missing.iter().copied().collect();
            for batch in selections.chunks(aos_hub_core::mirror_membership::MAX_MEMBERSHIP_OBJECTS)
            {
                let membership = self
                    .work
                    .inspect_mirror_membership(
                        self.db,
                        &self.registry,
                        index,
                        batch.iter().map(|oid| oid.to_hex()).collect(),
                        self.pair_source(index)?,
                    )
                    .await?;
                self.retain_pair_source(index, &membership.pair)?;
                for (oid, answer) in batch.iter().zip(&membership.objects) {
                    if answer.is_some() {
                        self.retain_pair(*oid, &membership.pair)?;
                        missing.remove(oid);
                    }
                }
            }
            if missing.is_empty() {
                break;
            }
        }
        ensure!(
            missing.is_empty(),
            "closure OIDs are absent from all approved sources"
        );
        oids.iter()
            .map(|oid| self.git_object_source_paths(*oid))
            .collect()
    }

    fn git_auxiliary_source_paths(&self) -> Result<Vec<String>> {
        Ok(self
            .proofs
            .lock()
            .map_err(|_| anyhow::anyhow!("mirror discovery is poisoned"))?
            .keys()
            .filter(|path| *path == "objects/info/packs" || path.ends_with("/objects/info/packs"))
            .cloned()
            .collect())
    }

    fn describe(&self) -> String {
        self.upstream.describe()
    }
}
