//! Original signed graph evidence for available, potentially unrealized outputs.
//!
//! Private profile receipts preserve the authenticated release's canonical
//! `store/` records. Availability never installs or roots an output: only a
//! checked deployment input triggers transport, exact verification, and import.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::{Evidence, RegistryAdmission};
use crate::registry::store::{StoreMap, TrustContext, parse_entry, serialize_entry};
use crate::registry::{Registry, ReleaseTrustReceipt, store_path_hash};
use crate::store::temp_roots::TemporaryRoots;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AvailableCatalog {
    release: ReleaseTrustReceipt,
    roots: BTreeSet<String>,
    records: BTreeMap<String, String>,
}

impl AvailableCatalog {
    fn graph(&self) -> Result<StoreMap> {
        let entries = self
            .records
            .iter()
            .map(|(hash, text)| Ok((hash.clone(), parse_entry(text)?)))
            .collect::<Result<_>>()?;
        let graph = StoreMap::from_authenticated_entries(entries)?;
        ensure!(
            self.release.schema == "aos.registry-release-trust/v1",
            "available graph release receipt schema changed"
        );
        semver::Version::parse(&self.release.release_tag)?;
        ensure!(
            matches!(self.release.commit.len(), 40 | 64)
                && self
                    .release
                    .commit
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "available graph release commit is invalid"
        );
        for root in &self.roots {
            let (canonical, suffix) =
                crate::deployment::nix::store_root_and_suffix(Path::new(root))?;
            ensure!(
                canonical == Path::new(root) && suffix.as_os_str().is_empty(),
                "available output is not canonical"
            );
            ensure!(
                graph.get(store_path_hash(root)).is_some(),
                "available output lacks signed graph evidence"
            );
        }
        Ok(graph)
    }
}

impl RegistryAdmission {
    pub(super) fn load_available(&mut self, directory: &Path) -> Result<()> {
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_file(),
                "available receipt is not a regular file"
            );
            let bytes = crate::native_deployment::read_regular_document(&entry.path())?;
            let expected = format!("{}.json", Sha256Digest::of_bytes(&bytes).hex());
            ensure!(
                entry.file_name() == std::ffi::OsStr::new(&expected),
                "available receipt content changed"
            );
            let catalog: AvailableCatalog = aos_ability_plan::module_graph::GRAPH_LIMITS
                .decode(&bytes, "available registry inputs")?;
            catalog.graph()?;
            let key = Sha256Digest::of_bytes(&serde_json::to_vec(&catalog.release)?).hex();
            match self.available.get_mut(&key) {
                Some(previous) => merge(previous, catalog)?,
                None => {
                    self.available.insert(key, catalog);
                }
            }
        }
        Ok(())
    }

    pub(super) fn capture_available(
        &mut self,
        registry: &Registry,
        roots: impl IntoIterator<Item = String>,
    ) -> Result<()> {
        let release = registry
            .release_trust()
            .context("available outputs lack signed release authority")?
            .clone();
        let graph = registry.store_map();
        ensure!(
            graph.is_present(),
            "available outputs lack signed store graph"
        );
        let roots = roots.into_iter().collect::<BTreeSet<_>>();
        let mut records = BTreeMap::new();
        for root in &roots {
            for hash in graph.reachable(store_path_hash(root)) {
                let record = graph
                    .get(&hash)
                    .context("available output signed graph is incomplete")?;
                records.insert(hash, serialize_entry(record));
            }
        }
        let catalog = AvailableCatalog {
            release,
            roots,
            records,
        };
        catalog.graph()?;
        let key = Sha256Digest::of_bytes(&serde_json::to_vec(&catalog.release)?).hex();
        match self.available.get_mut(&key) {
            Some(previous) => merge(previous, catalog),
            None => {
                self.available.insert(key, catalog);
                Ok(())
            }
        }
    }

    pub(super) fn persist_available(&self, directory: &Path) -> Result<()> {
        std::fs::create_dir_all(directory)?;
        ensure!(
            std::fs::symlink_metadata(directory)?.is_dir(),
            "available receipts require private profile storage"
        );
        for catalog in self.available.values() {
            let bytes = serde_json::to_vec(catalog)?;
            ensure!(
                bytes.len() <= aos_ability_plan::module_graph::GRAPH_LIMITS.max_bytes,
                "available graph receipt exceeds its limit"
            );
            let path = directory.join(format!("{}.json", Sha256Digest::of_bytes(&bytes).hex()));
            crate::profile::atomic_write(&path, &bytes)?;
        }
        Ok(())
    }

    /// Checks original authority without realizing or rooting an available output.
    ///
    /// # Errors
    /// Returns an error for an invalid retained image receipt or release graph.
    pub(crate) fn has_output_authority(&self, root: &str) -> Result<bool> {
        if self.evidence.contains_key(root) || self.image.receipt_for(root)?.is_some() {
            return Ok(true);
        }
        for catalog in self
            .available
            .values()
            .filter(|catalog| catalog.roots.contains(root))
        {
            catalog.graph()?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Realizes only graph-used available outputs under their original release.
    pub(crate) fn realize_inputs(
        &mut self,
        config: &crate::config::ApmConfig,
        inputs: &[String],
        temporary_roots: &mut TemporaryRoots,
        cancellation: &aos_ability_runtime::adapter::CancellationToken,
    ) -> Result<()> {
        for root in inputs {
            if self.evidence.contains_key(root) || self.image.receipt_for(root)?.is_some() {
                self.admit_input(root)?;
                continue;
            }
            let catalog = self
                .available
                .values()
                .find(|catalog| catalog.roots.contains(root))
                .context("checked deployment input lacks original available-output authority")?
                .clone();
            let graph = catalog.graph()?;
            let evidence = std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        runtime.block_on(realize(
                            config,
                            root,
                            &catalog,
                            &graph,
                            temporary_roots,
                            cancellation,
                            &self.executable,
                        ))
                    })
                    .join()
                    .map_err(|_| anyhow::anyhow!("available output transport worker panicked"))?
            })?;
            for (path, evidence) in evidence {
                self.insert(path, evidence)?;
            }
            self.admit_input(root)?;
        }
        Ok(())
    }

    fn admit_input(&mut self, root: &str) -> Result<()> {
        crate::deployment::retention::ArtifactAdmission::admit(self, root)
    }
}

fn merge(previous: &mut AvailableCatalog, catalog: AvailableCatalog) -> Result<()> {
    ensure!(
        previous.release == catalog.release,
        "available output authority changed"
    );
    for (hash, record) in catalog.records {
        if let Some(retained) = previous.records.get(&hash) {
            ensure!(
                retained == &record,
                "original signed graph records disagree"
            );
        }
        previous.records.insert(hash, record);
    }
    previous.roots.extend(catalog.roots);
    Ok(())
}

async fn realize(
    config: &crate::config::ApmConfig,
    root: &str,
    catalog: &AvailableCatalog,
    graph: &StoreMap,
    temporary_roots: &mut TemporaryRoots,
    cancellation: &aos_ability_runtime::adapter::CancellationToken,
    executable: &Path,
) -> Result<BTreeMap<String, Evidence>> {
    let transport = config
        .enabled_registries()
        .into_iter()
        .find(|registry| registry.name == catalog.release.registry)
        .context("original input registry has no enabled transport")?;
    let chain = crate::download::resolve_mirror_chain(&config.scope.registries_path(), transport);
    ensure!(
        !chain.is_empty(),
        "original output registry has no configured transport"
    );
    let request = crate::download::DownloadRequest {
        store_path: root.into(),
        mirror_url: chain[0].clone(),
        fallback_mirrors: chain[1..].to_vec(),
    };
    let printer = aos_core::output::Printer::new(0, true, false);
    let resolved = crate::download::fetch_complete_narinfo_closure(
        std::sync::Arc::new(crate::download::default_engine()),
        &[request],
        config.settings.parallel_downloads,
        &printer,
    )
    .await?;
    let reachable = graph
        .reachable(store_path_hash(root))
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut trust = TrustContext::new();
    for item in &resolved {
        let hash = store_path_hash(&item.narinfo.store_path);
        ensure!(
            reachable.contains(hash),
            "available output escaped its original signed graph"
        );
        trust.insert(hash.to_owned(), graph);
    }
    trust.enforce_totality()?;
    validate_realisations(graph, &resolved)
        .with_context(|| format!("validating available output {root} realization dependencies"))?;
    let results = crate::download::download_nars(
        &resolved,
        &config.nar_cache_path(),
        config.settings.parallel_downloads,
        &printer,
    )
    .await?;
    crate::verify::verify_downloads(&results, &trust, &printer)?;
    temporary_roots.retain(
        results.iter().map(|result| result.store_path.clone()),
        cancellation,
    )?;
    let mut evidence = BTreeMap::new();
    for result in &results {
        crate::store::import_nar_with_compression(
            &result.local_path,
            &result.store_path,
            &result.references,
            result.deriver.as_deref(),
            &result.compression,
        )
        .await?;
        let item = resolved
            .iter()
            .find(|item| item.narinfo.store_path == result.store_path)
            .context("imported path lacks checked transport identity")?;
        let nar_hash = Sha256Digest::parse(&format!(
            "sha256:{}",
            crate::verify::sha256_digest_hex(&item.narinfo.nar_hash)?
        ))?;
        let nar_size = item.narinfo.nar_size;
        let mut expected_references = item
            .narinfo
            .references
            .iter()
            .map(|reference| store_path_hash(reference).to_owned())
            .filter(|reference| reference != store_path_hash(&result.store_path))
            .collect::<Vec<_>>();
        expected_references.sort();
        expected_references.dedup();
        crate::store::verification::verify_store_object_in(
            &result.store_path,
            nar_hash,
            nar_size,
            &expected_references,
            Some(executable),
        )?;
        let (nar_hash, nar_size) = crate::store::verification::dump_store_path_identity_in(
            &result.store_path,
            Some(executable),
        )?;
        let references = crate::store::verification::query_reference_hashes_in(
            &result.store_path,
            Some(executable),
        )?;
        evidence.insert(
            result.store_path.clone(),
            Evidence {
                nar_hash,
                nar_size,
                references,
                release: Some(catalog.release.clone()),
                source_authority: None,
            },
        );
    }
    Ok(evidence)
}

fn validate_realisations(
    graph: &StoreMap,
    resolved: &[crate::download::ResolvedDownload],
) -> Result<()> {
    let mut selected = BTreeMap::new();
    for item in resolved {
        let hash = store_path_hash(&item.narinfo.store_path);
        let mut references = item
            .narinfo
            .references
            .iter()
            .map(|path| store_path_hash(path).to_owned())
            .filter(|reference| reference != hash)
            .collect::<Vec<_>>();
        references.sort();
        references.dedup();
        let matching = graph
            .get(hash)
            .context("available path lacks original graph record")?
            .realisations
            .iter()
            .filter(|record| {
                let mut expected = record
                    .deps
                    .iter()
                    .map(|edge| edge.dep_ia.clone())
                    .filter(|reference| reference != hash)
                    .collect::<Vec<_>>();
                expected.sort();
                expected.dedup();
                record
                    .nar
                    .matches(&item.narinfo.nar_hash, item.narinfo.nar_size)
                    && expected == references
            })
            .collect::<Vec<_>>();
        ensure!(
            !matching.is_empty(),
            "available NAR or references disagree with original release"
        );
        selected.insert(hash, matching);
    }
    for candidates in selected.values() {
        ensure!(
            candidates
                .iter()
                .any(|record| record.deps.iter().all(|edge| {
                    selected
                        .get(edge.dep_ia.as_str())
                        .is_some_and(|dependency| {
                            dependency.iter().any(|candidate| {
                                edge.dep_ca.is_none() || edge.dep_ca == candidate.ca
                            })
                        })
                })),
            "available output dependency realization pin changed"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::{DownloadRequest, ResolvedDownload};
    use aos_core::nar::info::NarInfo;

    fn graph() -> StoreMap {
        let root = "0".repeat(32);
        let dependency = "1".repeat(32);
        StoreMap::from_authenticated_entries(BTreeMap::from([
            (
                root,
                parse_entry(&format!(
                    "nar:sha256:{}:1\n  ia:sha256:{dependency}/ca:sha256:{}\n",
                    crate::registry::store::normalize_digest(&format!("sha256:{}", "a".repeat(64)))
                        .unwrap(),
                    crate::registry::store::normalize_digest(&format!("sha256:{}", "b".repeat(64)))
                        .unwrap()
                ))
                .unwrap(),
            ),
            (
                dependency,
                parse_entry(&format!(
                    "ca:sha256:{} nar:sha256:{}:2\n",
                    crate::registry::store::normalize_digest(&format!("sha256:{}", "b".repeat(64)))
                        .unwrap(),
                    crate::registry::store::normalize_digest(&format!("sha256:{}", "c".repeat(64)))
                        .unwrap()
                ))
                .unwrap(),
            ),
        ]))
        .unwrap()
    }

    fn selected() -> Vec<ResolvedDownload> {
        let root = format!("/nix/store/{}-runtime", "0".repeat(32));
        let dependency = format!("/nix/store/{}-library", "1".repeat(32));
        [
            (root, "a".repeat(64), 1, vec![dependency.clone()]),
            (dependency, "c".repeat(64), 2, vec![]),
        ]
        .into_iter()
        .map(|(path, hash, size, references)| ResolvedDownload {
            req: DownloadRequest {
                store_path: path.clone(),
                mirror_url: "https://cache.example.invalid".into(),
                fallback_mirrors: vec![],
            },
            narinfo: NarInfo {
                store_path: path,
                url: "nar/example.nar".into(),
                compression: "none".into(),
                file_hash: None,
                file_size: None,
                nar_hash: format!("sha256:{hash}"),
                nar_size: size,
                references,
                deriver: None,
                signatures: vec![],
            },
        })
        .collect()
    }

    #[test]
    fn original_available_graph_accepts_exact_closure_and_rejects_changed_bytes_or_edges() {
        let graph = graph();
        let mut selected = selected();
        validate_realisations(&graph, &selected).unwrap();

        selected[1].narinfo.nar_hash = format!("sha256:{}", "d".repeat(64));
        assert!(validate_realisations(&graph, &selected).is_err());
        let mut selected = self::selected();
        selected[0].narinfo.references.clear();
        assert!(validate_realisations(&graph, &selected).is_err());
    }

    #[test]
    fn original_available_graph_rejects_a_different_blessed_dependency_realization() {
        let mut entries = graph()
            .iter()
            .map(|(hash, entry)| (hash.to_owned(), entry.clone()))
            .collect::<BTreeMap<_, _>>();
        let dependency = entries.get_mut(&"1".repeat(32)).unwrap();
        dependency.realisations[0].ca = Some(
            crate::registry::store::normalize_digest(&format!("sha256:{}", "d".repeat(64)))
                .unwrap(),
        );
        let graph = StoreMap::from_authenticated_entries(entries).unwrap();

        assert!(validate_realisations(&graph, &selected()).is_err());
    }

    #[test]
    fn retained_available_graph_requires_closed_dependency_evidence() {
        let entries = BTreeMap::from([(
            "0".repeat(32),
            graph().get(&"0".repeat(32)).unwrap().clone(),
        )]);

        assert!(StoreMap::from_authenticated_entries(entries).is_err());
    }
}
