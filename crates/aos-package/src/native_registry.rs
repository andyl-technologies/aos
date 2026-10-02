//! Authenticated registry resolution and retained admission for native profiles.
//!
//! Native envelopes remain bound to the signed registry release, exact NAR
//! contents, and live reference graph that admitted them. Private profile
//! receipts preserve that original admission evidence for old handlers during
//! removal and recovery; a transaction document never supplies its own trust.

mod available;
mod roots;
pub(crate) mod solver;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_ability_plan::module_graph::GRAPH_LIMITS;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::deployment::evaluation::PackageResolver;
use crate::deployment::model::{Envelope, ModuleDependency, ModuleSource};
use crate::deployment::retention::ArtifactAdmission;
use crate::registry::{Registry, RegistrySet, ReleaseTrustReceipt, store_path_hash};
use crate::store::verification::{
    dump_store_path_identity_in, query_reference_hashes_in, query_store_paths_in,
    verify_store_object_in,
};
use crate::types::{InstalledMeta, PackageMeta};

// Signed catalog NAR hashes use Nix encodings; private admission evidence uses
// canonical hex. Normalize the representation before comparing the exact bytes.
fn catalog_nar_hash(hash: &str, artifact: &str) -> Result<Sha256Digest> {
    let encoded = crate::verify::sha256_digest_hex(hash)
        .with_context(|| format!("invalid {artifact} catalog NAR hash"))?;
    Sha256Digest::parse(&format!("sha256:{encoded}"))
        .with_context(|| format!("invalid {artifact} catalog NAR digest"))
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    nar_hash: Sha256Digest,
    nar_size: u64,
    references: Vec<String>,
    release: Option<ReleaseTrustReceipt>,
    #[serde(default)]
    source_authority: Option<crate::native_deployment::SourceAuthorization>,
}

/// Rechecks artifacts against previously authenticated private profile receipts.
pub(crate) struct RegistryAdmission {
    executable: PathBuf,
    evidence: BTreeMap<String, Evidence>,
    image: crate::native_deployment::Admission,
    available: BTreeMap<String, available::AvailableCatalog>,
}

impl RegistryAdmission {
    /// Exports exact admitted identity and original authority for generation evidence.
    pub(crate) fn evidence(
        &mut self,
        root: &str,
    ) -> Result<crate::attestation::native::InputEvidence> {
        self.admit(root)?;
        let (nar_hash, nar_size) = dump_store_path_identity_in(root, Some(&self.executable))?;
        let references = query_reference_hashes_in(root, Some(&self.executable))?;
        let image = self
            .image
            .receipt_for(root)?
            .map(|(path, digest)| crate::attestation::native::ImageAdmission { path, digest });
        Ok(crate::attestation::native::InputEvidence {
            store_path: root.to_owned(),
            nar_hash,
            nar_size,
            references,
            release: self
                .evidence
                .get(root)
                .and_then(|evidence| evidence.release.clone()),
            image,
            source_authority: self
                .evidence
                .get(root)
                .and_then(|evidence| evidence.source_authority.clone()),
        })
    }
    pub(crate) fn new(executable: PathBuf, receipts: &Path) -> Result<Self> {
        ensure!(
            executable.is_absolute(),
            "native store executable must be absolute"
        );
        let mut result = Self {
            image: crate::native_deployment::Admission::new(executable.clone())?,
            executable,
            evidence: BTreeMap::new(),
            available: BTreeMap::new(),
        };
        result.image.load_retained(
            &receipts
                .parent()
                .context("admission storage has no parent")?
                .join("admissions"),
        )?;
        result.load_available(
            &receipts
                .parent()
                .context("admission storage has no parent")?
                .join("registry-available"),
        )?;
        let entries = match fs::read_dir(receipts) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(result),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_file(),
                "native profile receipt must be a regular file"
            );
            let bytes = crate::native_deployment::read_regular_document(&entry.path())?;
            let evidence: BTreeMap<String, Evidence> =
                GRAPH_LIMITS.decode(&bytes, "retained registry admission")?;
            for (root, evidence) in evidence {
                result.insert(root, evidence)?;
            }
        }
        Ok(result)
    }

    fn insert(&mut self, root: String, mut evidence: Evidence) -> Result<()> {
        let (canonical, suffix) = crate::deployment::nix::store_root_and_suffix(Path::new(&root))?;
        ensure!(
            canonical == Path::new(&root) && suffix.as_os_str().is_empty(),
            "admission receipt must identify a canonical root"
        );
        ensure!(evidence.nar_size > 0, "admission receipt has an empty NAR");
        if let Some(previous) = self.evidence.get(&root) {
            ensure!(
                previous.nar_hash == evidence.nar_hash
                    && previous.nar_size == evidence.nar_size
                    && previous.references == evidence.references,
                "retained registry receipts disagree about an artifact"
            );
            if let (Some(original), Some(incoming)) =
                (&previous.source_authority, &evidence.source_authority)
            {
                ensure!(original == incoming, "retained source authorities disagree");
            }
            // Re-observing a realized artifact cannot erase its original authority.
            if previous.source_authority.is_some() {
                evidence.source_authority = previous.source_authority.clone();
            }
            if previous.release.is_some() {
                evidence.release = previous.release.clone();
            }
        }
        self.evidence.insert(root, evidence);
        Ok(())
    }

    /// Captures an input authorized by the installed package runtime itself.
    pub(crate) fn trust_runtime_input(&mut self, root: &str) -> Result<()> {
        let (nar_hash, nar_size) = dump_store_path_identity_in(root, Some(&self.executable))?;
        let references = query_reference_hashes_in(root, Some(&self.executable))?;
        self.insert(
            root.to_owned(),
            Evidence {
                nar_hash,
                nar_size,
                references,
                release: None,
                source_authority: None,
            },
        )
    }

    pub(crate) fn trust_authorized_input(
        &mut self,
        root: &str,
        authority: &crate::native_deployment::SourceAuthorization,
    ) -> Result<()> {
        authority.verify_integrity()?;
        self.trust_runtime_input(root)?;
        let evidence = self
            .evidence
            .get_mut(root)
            .context("authorized root evidence missing")?;
        ensure!(
            evidence
                .source_authority
                .as_ref()
                .is_none_or(|original| original == authority),
            "authorized root has a different original source proof"
        );
        evidence.source_authority = Some(authority.clone());
        Ok(())
    }

    pub(crate) fn has_source_authority(
        &self,
        root: &Path,
        authority: &crate::native_deployment::SourceAuthorization,
    ) -> bool {
        root.to_str()
            .and_then(|root| self.evidence.get(root))
            .and_then(|evidence| evidence.source_authority.as_ref())
            == Some(authority)
    }

    fn capture_closure(&mut self, registry: &Registry, root: &str) -> Result<()> {
        let release = registry
            .release_trust()
            .context("native envelope lacks authenticated signed-release evidence")?;
        let signed = registry.store_map();
        ensure!(
            signed.is_present(),
            "native envelope requires a signed store graph"
        );
        let reachable: BTreeSet<_> = signed
            .reachable(store_path_hash(root))
            .into_iter()
            .collect();
        for path in
            query_store_paths_in(&["--query", "--requisites"], root, Some(&self.executable))?
        {
            let hash = store_path_hash(&path);
            ensure!(
                reachable.contains(hash),
                "native artifact escaped its authenticated graph"
            );
            let record = signed
                .get(hash)
                .context("native closure member lacks signed NAR evidence")?;
            let (nar_hash, nar_size) = dump_store_path_identity_in(&path, Some(&self.executable))?;
            let references = query_reference_hashes_in(&path, Some(&self.executable))?;
            let matching = record.realisations.iter().any(|realisation| {
                let mut expected: Vec<_> = realisation
                    .deps
                    .iter()
                    .map(|edge| edge.dep_ia.clone())
                    .filter(|dependency| dependency != hash)
                    .collect();
                expected.sort();
                expected.dedup();
                realisation.nar.matches(&nar_hash.to_string(), nar_size) && expected == references
            });
            ensure!(
                matching,
                "native closure contents or references differ from the signed release"
            );
            self.insert(
                path,
                Evidence {
                    nar_hash,
                    nar_size,
                    references,
                    release: Some(release.clone()),
                    source_authority: None,
                },
            )?;
        }
        Ok(())
    }

    pub(crate) fn persist(&self, directory: &Path) -> Result<()> {
        fs::create_dir_all(directory)?;
        ensure!(
            fs::symlink_metadata(directory)?.is_dir(),
            "native receipts must use private profile storage"
        );
        let bytes = serde_json::to_vec(&self.evidence)?;
        ensure!(
            bytes.len() <= GRAPH_LIMITS.max_bytes,
            "native registry receipt exceeds its size limit"
        );
        let path = directory.join(format!("{}.json", Sha256Digest::of_bytes(&bytes).hex()));
        let temporary = directory.join(format!(".registry-{}", std::process::id()));
        fs::write(&temporary, bytes)?;
        fs::File::open(&temporary)?.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(directory)?.sync_all()?;
        self.persist_available(
            &directory
                .parent()
                .context("admission storage has no parent")?
                .join("registry-available"),
        )?;
        Ok(())
    }
}

impl ArtifactAdmission for RegistryAdmission {
    fn admit(&mut self, root: &str) -> Result<()> {
        let Some(evidence) = self.evidence.get(root) else {
            return self.image.admit(root);
        };
        if let Some(authority) = &evidence.source_authority {
            authority.verify_integrity()?;
        }
        verify_store_object_in(
            root,
            evidence.nar_hash,
            evidence.nar_size,
            &evidence.references,
            Some(&self.executable),
        )
    }
}

/// Resolves exact native envelopes from the authenticated registry selection.
pub(crate) struct NativeRegistry<'a> {
    registries: &'a RegistrySet,
    admission: RegistryAdmission,
    envelopes: BTreeMap<(String, String, String), Envelope>,
    retained_inputs: BTreeSet<PathBuf>,
    module_envelopes: BTreeMap<(String, String, String), PathBuf>,
    resolution_lock: Option<solver::ResolutionLock>,
    retained_module_sources: Vec<ModuleSource>,
    retained_envelopes: Vec<Envelope>,
    candidate_priorities: BTreeMap<(String, String, String), usize>,
    companion_inputs: BTreeMap<(String, String, String), BTreeSet<PathBuf>>,
}

impl<'a> NativeRegistry<'a> {
    pub(crate) fn new(registries: &'a RegistrySet, admission: RegistryAdmission) -> Self {
        Self {
            registries,
            admission,
            envelopes: BTreeMap::new(),
            retained_inputs: BTreeSet::new(),
            module_envelopes: BTreeMap::new(),
            resolution_lock: None,
            retained_module_sources: Vec::new(),
            retained_envelopes: Vec::new(),
            candidate_priorities: BTreeMap::new(),
            companion_inputs: BTreeMap::new(),
        }
    }

    pub(crate) fn package(&mut self, registry_name: &str, meta: &PackageMeta) -> Result<Envelope> {
        let registry = self
            .registries
            .get_registry(registry_name)
            .context("native package registry is unavailable")?;
        let deployment = meta
            .deployment
            .as_ref()
            .context("selected package lacks a native deployment envelope")?;
        self.retained_inputs
            .insert(PathBuf::from(&deployment.store_path));
        for documentation in [&meta.module_documentation].into_iter().flatten() {
            self.retained_inputs
                .insert(PathBuf::from(&documentation.store_path));
        }
        ensure!(
            registry.release_trust().is_some(),
            "native package lacks signed-release authentication"
        );
        verify_store_object_in(
            &deployment.store_path,
            catalog_nar_hash(&deployment.nar_hash, "deployment envelope")?,
            deployment.nar_size,
            &deployment.references,
            Some(&self.admission.executable),
        )?;
        self.admission
            .capture_closure(registry, &deployment.store_path)?;
        for documentation in [&meta.module_documentation].into_iter().flatten() {
            verify_store_object_in(
                &documentation.store_path,
                catalog_nar_hash(&documentation.nar_hash, "module documentation")?,
                documentation.nar_size,
                &documentation.references,
                Some(&self.admission.executable),
            )?;
            self.admission
                .capture_closure(registry, &documentation.store_path)?;
        }
        let envelope = crate::native_artifact::read_envelope_in(
            deployment,
            &meta.name,
            &meta.version,
            &meta.platform,
            &self.admission.executable,
            &aos_ability_runtime::adapter::CancellationToken::default(),
        )?;
        envelope.verify_catalog_resolution(
            meta.version_requirement.as_deref(),
            meta.os_version.as_deref(),
            &meta.module_dependencies,
        )?;
        let priority = self
            .registries
            .registries()
            .iter()
            .position(|registry| registry.config.name == registry_name)
            .context("candidate registry priority is absent")?;
        self.candidate_priorities
            .entry(envelope_key(&envelope))
            .and_modify(|previous| *previous = (*previous).min(priority))
            .or_insert(priority);
        self.companion_inputs.insert(
            envelope_key(&envelope),
            std::iter::once(PathBuf::from(&deployment.store_path))
                .chain(
                    meta.module_documentation
                        .iter()
                        .map(|metadata| PathBuf::from(&metadata.store_path)),
                )
                .collect(),
        );
        ensure!(
            envelope
                .package
                .outputs
                .values()
                .any(|path| path == &meta.store_path),
            "native envelope changed its signed payload output"
        );
        self.admission
            .capture_available(registry, envelope.package.outputs.values().cloned())?;
        self.cache_envelope(envelope.clone())?;
        self.module_envelopes.insert(
            envelope_key(&envelope),
            PathBuf::from(&deployment.store_path),
        );
        Ok(envelope)
    }

    // Runtime roles may refer to different builds with identical name/version.
    // Only exact artifact catalogs share a cache entry; module lookup separately
    // requires one unambiguous package context for the pinned module source.
    fn cache_envelope(&mut self, envelope: Envelope) -> Result<()> {
        let key = envelope_key(&envelope);
        if let Some(previous) = self.envelopes.get(&key) {
            ensure!(
                same_package_context(previous, &envelope),
                "native artifact coordinate has conflicting package envelopes"
            );
        }
        self.envelopes.insert(key, envelope);
        Ok(())
    }

    fn cached_module(&self, source: &ModuleSource) -> Result<Option<Envelope>> {
        let mut matches = self
            .envelopes
            .values()
            .filter(|envelope| envelope.module.as_ref() == Some(source));
        let Some(envelope) = matches.next() else {
            return Ok(None);
        };
        ensure!(
            matches.all(|other| same_package_context(envelope, other)),
            "pinned native module source has ambiguous artifact contexts"
        );
        Ok(Some(envelope.clone()))
    }

    /// Checks whether an output has retained original admission evidence.
    ///
    /// # Errors
    /// Returns an error if a retained image or signed release receipt is invalid.
    pub(crate) fn has_output_authority(
        &self,
        artifact: &crate::deployment::model::Artifact,
    ) -> Result<bool> {
        self.admission.has_output_authority(&artifact.path)
    }

    pub(crate) fn into_admission(self) -> RegistryAdmission {
        self.admission
    }

    pub(crate) fn resolve_scope(
        &mut self,
        system: &str,
        roots: Vec<Envelope>,
        payloads: &[crate::deployment::model::Artifact],
        allow_resolution: bool,
        refresh_names: Option<&BTreeSet<String>>,
        cancellation: &aos_ability_runtime::adapter::CancellationToken,
        os_release: Option<&aos_doc_model::runtime::OsRelease>,
    ) -> Result<(
        crate::deployment::model::ResolvedPackages,
        Option<solver::ResolutionLock>,
    )> {
        if allow_resolution {
            let mut candidates = self.envelopes.values().cloned().collect::<Vec<_>>();
            candidates.retain(|candidate| candidate.system == system);
            candidates.sort_by(|left, right| {
                let priority = self
                    .candidate_priorities
                    .get(&envelope_key(left))
                    .copied()
                    .unwrap_or(usize::MAX)
                    .cmp(
                        &self
                            .candidate_priorities
                            .get(&envelope_key(right))
                            .copied()
                            .unwrap_or(usize::MAX),
                    );
                priority
                    .then_with(|| {
                        crate::registry::parse::compare_registry_versions(
                            &right.package.version,
                            &left.package.version,
                        )
                    })
                    .then_with(|| envelope_key(left).cmp(&envelope_key(right)))
            });
            let mut solution = solver::solve(
                &roots,
                &candidates,
                self.resolution_lock.as_ref(),
                &self.retained_module_sources,
                refresh_names,
                cancellation,
                os_release,
            )?;
            if let Some(lock) = &mut solution.lock {
                for edge in &lock.edges {
                    let envelope = solution
                        .envelopes
                        .iter()
                        .find(|envelope| envelope.package.canonical_catalog() == edge.requester)
                        .context("solved requester envelope is absent")?;
                    let path = self
                        .module_envelopes
                        .get(&envelope_key(envelope))
                        .context("solved requester lacks authenticated companion")?;
                    lock.requesters
                        .insert(edge.requester.path.clone(), path.clone());
                }
                lock.validate(&solution.envelopes)?;
            }
            self.resolution_lock = solution.lock;
        }
        let packages =
            crate::deployment::evaluation::resolve_packages(system, roots.clone(), self)?;
        let mut selected = BTreeMap::new();
        for mut root in roots {
            root.package = root.package.canonical_catalog();
            selected.insert(root.package.name.clone(), root);
        }
        for module in &packages.modules {
            let envelope = self
                .envelopes
                .values()
                .find(|envelope| envelope.module_record().as_ref() == Some(module))
                .context("selected module envelope is absent")?;
            selected
                .entry(envelope.package.name.clone())
                .or_insert_with(|| envelope.clone());
        }
        let selected = selected.into_values().collect::<Vec<_>>();
        for envelope in &selected {
            solver::check_os_requirement(envelope, os_release)?;
        }
        let mut lock = self.resolution_lock.clone();
        if let Some(value) = &mut lock {
            value.edges.retain(|edge| {
                selected
                    .iter()
                    .any(|envelope| envelope.package.canonical_catalog() == edge.requester)
            });
            value
                .requesters
                .retain(|path, _| value.edges.iter().any(|edge| &edge.requester.path == path));
            value.validate(&selected)?;
            if !value.edges.iter().any(|edge| edge.requirement.is_ranged()) {
                lock = None;
            }
        }
        let selected_keys: BTreeSet<_> = selected
            .iter()
            .map(envelope_key)
            .chain(
                self.envelopes
                    .values()
                    .filter(|envelope| {
                        payloads.iter().any(|payload| {
                            envelope.package.canonical_catalog() == payload.canonical_catalog()
                        })
                    })
                    .map(envelope_key),
            )
            .collect();
        let excluded: BTreeSet<_> = self
            .companion_inputs
            .iter()
            .filter(|(key, _)| !selected_keys.contains(*key))
            .flat_map(|(_, inputs)| inputs.iter().cloned())
            .collect();
        let retained: BTreeSet<_> = self
            .companion_inputs
            .iter()
            .filter(|(key, _)| selected_keys.contains(*key))
            .flat_map(|(_, inputs)| inputs.iter().cloned())
            .collect();
        self.retained_inputs
            .retain(|input| !excluded.contains(input) || retained.contains(input));
        Ok((packages, lock))
    }

    pub(crate) fn retained_inputs(&self) -> Vec<PathBuf> {
        self.retained_inputs
            .iter()
            .cloned()
            .chain(self.admission.image.receipt_roots())
            .collect()
    }

    pub(crate) fn package_envelopes(
        &self,
        packages: &crate::deployment::model::ResolvedPackages,
    ) -> Result<BTreeMap<String, PathBuf>> {
        packages
            .artifacts
            .iter()
            .map(|artifact| {
                let envelope = self
                    .envelopes
                    .values()
                    .find(|envelope| {
                        envelope.package.canonical_catalog() == artifact.canonical_catalog()
                    })
                    .context("selected payload lacks its authenticated envelope")?;
                let root = self
                    .module_envelopes
                    .get(&envelope_key(envelope))
                    .context("selected payload lacks its retained envelope")?;
                Ok((artifact.canonical_catalog().path, root.clone()))
            })
            .collect()
    }

    pub(crate) fn module_envelopes(
        &self,
        packages: &crate::deployment::model::ResolvedPackages,
    ) -> Result<BTreeMap<String, PathBuf>> {
        packages
            .modules
            .iter()
            .map(|module| {
                let envelope = self
                    .envelopes
                    .values()
                    .find(|envelope| envelope.module_record().as_ref() == Some(module))
                    .context("resolved module lacks its exact authenticated package context")?;
                let path = self
                    .module_envelopes
                    .get(&envelope_key(envelope))
                    .context("resolved module lacks its original deployment envelope")?;
                Ok((module.name.clone(), path.clone()))
            })
            .collect()
    }

    pub(crate) fn retain_modules(
        &mut self,
        descriptor: &crate::native_deployment::EvaluationInput,
        desired: &crate::deployment::model::Deployment,
    ) -> Result<()> {
        self.resolution_lock = descriptor.resolution_lock.clone();
        self.retained_module_sources = descriptor
            .packages
            .modules
            .iter()
            .map(|module| {
                Ok(ModuleSource {
                    name: module.name.clone(),
                    version: module.version.clone(),
                    source: module.config_root.clone(),
                    entrypoint: module
                        .module
                        .strip_prefix(&format!("{}/", module.config_root))
                        .context("retained module entrypoint is outside its source root")?
                        .to_owned(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        {
            let requesters = descriptor
                .resolution_lock
                .iter()
                .flat_map(|lock| lock.requesters.iter());
            for (artifact, path) in descriptor.package_envelopes.iter().chain(requesters) {
                let root = path.to_str().context("requester envelope is not UTF-8")?;
                ensure!(
                    desired.inputs().iter().any(|input| input == root),
                    "lock requester envelope is not retained"
                );
                self.admission.admit(root)?;
                let bytes = crate::native_deployment::read_regular_store_document_in(
                    &path.join("deployment.json"),
                    &self.admission.executable,
                    &Default::default(),
                )?;
                let envelope = Envelope::decode(&bytes)?;
                ensure!(
                    envelope.package.canonical_catalog().path == *artifact,
                    "lock requester identity changed"
                );
                solver::check_os_requirement(&envelope, descriptor.os_release.as_ref())?;
                self.module_envelopes
                    .insert(envelope_key(&envelope), path.clone());
                self.retained_inputs.insert(path.clone());
                self.cache_envelope(envelope)?;
            }
        }
        for module in &descriptor.packages.modules {
            let path = descriptor
                .module_envelopes
                .get(&module.name)
                .context("retained module lacks its original deployment envelope")?;
            let root = path.to_str().context("module envelope root is not UTF-8")?;
            ensure!(
                desired.inputs().iter().any(|input| input == root),
                "committed deployment does not retain its module envelope"
            );
            self.admission.admit(root)?;
            let bytes = crate::native_deployment::read_regular_store_document_in(
                &path.join("deployment.json"),
                &self.admission.executable,
                &aos_ability_runtime::adapter::CancellationToken::default(),
            )?;
            let envelope = Envelope::decode(&bytes)?;
            ensure!(
                envelope.system == descriptor.packages.system
                    && envelope.module_record().as_ref() == Some(module),
                "retained module envelope differs from its admitted module catalog"
            );
            for dependency in &envelope.module_dependencies {
                if dependency.is_ranged() {
                    continue;
                }
                let dependency = dependency.seed();
                ensure!(
                    descriptor
                        .packages
                        .modules
                        .iter()
                        .any(|record| record.name == dependency.name
                            && record.version == dependency.version
                            && record.config_root == dependency.source
                            && record.module
                                == format!("{}/{}", dependency.source, dependency.entrypoint)),
                    "retained module envelope has an unresolved dependency"
                );
            }
            let key = envelope_key(&envelope);
            self.cache_envelope(envelope)?;
            self.module_envelopes.insert(key, path.clone());
            self.retained_inputs.insert(path.clone());
        }
        if let Some(lock) = &self.resolution_lock {
            let envelopes = self
                .envelopes
                .values()
                .filter(|envelope| {
                    descriptor
                        .packages
                        .modules
                        .iter()
                        .any(|module| envelope.module_record().as_ref() == Some(module))
                        || lock
                            .requesters
                            .contains_key(&envelope.package.canonical_catalog().path)
                })
                .cloned()
                .collect::<Vec<_>>();
            lock.validate(&envelopes)?;
        }
        let retained = self
            .envelopes
            .values()
            .filter(|envelope| {
                descriptor
                    .packages
                    .modules
                    .iter()
                    .any(|module| envelope.module_record().as_ref() == Some(module))
                    || descriptor.resolution_lock.as_ref().is_some_and(|lock| {
                        lock.requesters
                            .contains_key(&envelope.package.canonical_catalog().path)
                    })
            })
            .cloned()
            .collect::<Vec<_>>();
        self.retained_envelopes = retained;
        Ok(())
    }

    pub(crate) fn retained_roots(&self, original_packages: &[Envelope]) -> Result<Vec<Envelope>> {
        let mut retained = self.retained_envelopes.clone();
        for envelope in original_packages {
            if !retained.contains(envelope) {
                retained.push(envelope.clone());
            }
        }
        let root_names = roots::root_names(&retained)?;
        Ok(retained
            .into_iter()
            .filter(|envelope| root_names.contains(&envelope.package.name))
            .collect())
    }

    pub(crate) fn metadata(&self, path: &str) -> Result<(String, PackageMeta)> {
        if let Some(selected) = self.registries.registries().iter().find_map(|registry| {
            registry
                .get_by_hash(store_path_hash(path))
                .filter(|meta| meta.store_path == path)
                .map(|meta| (registry.config.name.clone(), meta.clone()))
        }) {
            return Ok(selected);
        }
        let mut matches = self.envelopes.values().filter(|envelope| {
            envelope
                .package
                .outputs
                .values()
                .any(|output| output == path)
        });
        let envelope = matches
            .next()
            .context("native payload has no authenticated package envelope")?;
        ensure!(
            matches.all(|other| same_package_context(envelope, other)),
            "native payload has ambiguous authenticated package contexts"
        );
        let (registry, canonical) = self
            .registries
            .all_versions(&envelope.package.name)
            .into_iter()
            .find(|(_, meta)| {
                meta.version == envelope.package.version
                    && meta.store_path == envelope.package.canonical_catalog().path
            })
            .context("named native output lacks canonical signed package metadata")?;
        let output = canonical
            .named_outputs
            .values()
            .find(|output| output.store_path == path)
            .context("named native output lacks its own signed output metadata")?;
        let deployment = output
            .deployment
            .as_ref()
            .context("named native output lacks its own deployment envelope")?;
        let evidence = self
            .admission
            .evidence
            .get(path)
            .context("named native output lacks an admitted signed NAR identity")?;
        ensure!(
            evidence.release.as_ref() == registry.release_trust(),
            "named native output admission differs from its package release"
        );
        let mut selected = canonical.clone();
        selected.store_path = path.into();
        selected.deployment = Some(deployment.clone());
        selected.attestation = output.attestation.clone();
        selected.nar_hash = evidence.nar_hash.to_string();
        selected.nar_size = evidence.nar_size;
        selected.references.clone_from(&evidence.references);
        // The canonical output's closure size does not describe this selected
        // root. Resolve the exact admitted closure rather than copying it.
        selected.closure_size = query_store_paths_in(
            &["--query", "--requisites"],
            path,
            Some(&self.admission.executable),
        )?
        .iter()
        .try_fold(0_u64, |total, root| {
            let size = self
                .admission
                .evidence
                .get(root)
                .context("named native output closure lacks signed NAR evidence")?
                .nar_size;
            total
                .checked_add(size)
                .context("named native output closure size overflow")
        })?;
        Ok((registry.config.name.clone(), selected))
    }

    pub(crate) fn installed(&mut self, installed: &InstalledMeta) -> Result<Envelope> {
        let meta = installed
            .apm
            .as_ref()
            .context("installed package lacks native package identity")?;
        let artifact = meta
            .deployment
            .as_ref()
            .context("installed package lacks retained native deployment metadata")?;
        self.retained_inputs
            .insert(PathBuf::from(&artifact.store_path));
        for documentation in [&meta.module_documentation].into_iter().flatten() {
            self.retained_inputs
                .insert(PathBuf::from(&documentation.store_path));
        }
        self.admission.admit(&artifact.store_path)?;
        let envelope = crate::native_artifact::read_envelope_in(
            artifact,
            &meta.name,
            &meta.version,
            &crate::platform::native_platform(),
            &self.admission.executable,
            &aos_ability_runtime::adapter::CancellationToken::default(),
        )?;
        ensure!(
            envelope
                .package
                .outputs
                .values()
                .any(|path| path == &installed.store_path),
            "retained native envelope differs from installed payload"
        );
        self.cache_envelope(envelope.clone())?;
        self.module_envelopes
            .insert(envelope_key(&envelope), PathBuf::from(&artifact.store_path));
        Ok(envelope)
    }
}

// Selected payload outputs do not change the package-owned module context.
// Every other authenticated envelope field must remain identical.
pub(crate) fn same_package_context(left: &Envelope, right: &Envelope) -> bool {
    let mut package = left.package.clone();
    package.path.clone_from(&right.package.path);
    package == right.package
        && left.schema == right.schema
        && left.system == right.system
        && left.module == right.module
        && left.runtime_dependencies == right.runtime_dependencies
        && left.module_dependencies == right.module_dependencies
        && left.version_requirement == right.version_requirement
        && left.os_version == right.os_version
}

fn envelope_key(envelope: &Envelope) -> (String, String, String) {
    (
        envelope.package.name.clone(),
        envelope.package.version.clone(),
        envelope.package.canonical_catalog().path,
    )
}

impl PackageResolver for NativeRegistry<'_> {
    fn resolve(&mut self, dependency: &ModuleDependency) -> Result<Envelope> {
        let source = if dependency.is_ranged() {
            let lock = self
                .resolution_lock
                .as_ref()
                .context("ranged module dependency requires an exact retained resolution lock")?;
            let matches = lock
                .edges
                .iter()
                .filter(|edge| &edge.requirement == dependency)
                .collect::<Vec<_>>();
            let edge = matches
                .first()
                .context("ranged dependency is absent from retained lock")?;
            ensure!(
                matches.iter().all(|other| other.selected == edge.selected),
                "lock has conflicting dependency choices"
            );
            edge.selected.clone()
        } else {
            dependency.seed().clone()
        };
        let source = &source;
        if let Some(envelope) = self.cached_module(source)? {
            return Ok(envelope);
        }
        ensure!(
            !dependency.is_ranged(),
            "locked module companion is unavailable; replay does not discover new releases"
        );
        let candidates = self
            .registries
            .all_versions(&source.name)
            .into_iter()
            .filter(|(_, meta)| meta.version == source.version && meta.deployment.is_some())
            .map(|(registry, meta)| (registry.config.name.clone(), meta.clone()))
            .collect::<Vec<_>>();
        for (registry, meta) in candidates {
            self.package(&registry, &meta)?;
        }
        if let Some(envelope) = self.cached_module(source)? {
            return Ok(envelope);
        }
        anyhow::bail!(
            "exact native module dependency {}@{} is unavailable",
            source.name,
            source.version
        )
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;

    #[test]
    fn catalog_admission_normalizes_nix_hashes_without_changing_identity() {
        // Captured from the source-built acquired fixture's deployment NAR.
        let nix_hash = "sha256:0sl85qninq6dgnc7g3yba4i56hxwis72c1k96c4gmc47dimnwxx9";
        let expected = Sha256Digest::parse(
            "sha256:a9776e6b6c87b0fa08336906268e8ebc43532251cb8f77987dcd601b2d2e886a",
        )
        .unwrap();

        for artifact in ["deployment envelope", "module documentation"] {
            assert_eq!(catalog_nar_hash(nix_hash, artifact).unwrap(), expected);
            assert_eq!(
                catalog_nar_hash(&expected.to_string(), artifact).unwrap(),
                expected
            );
            assert_ne!(
                catalog_nar_hash(nix_hash, artifact).unwrap(),
                Sha256Digest::of_bytes(b"tampered NAR")
            );
            for invalid in [
                "sha512:deadbeef",
                "sha256:invalid",
                "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            ] {
                let error = catalog_nar_hash(invalid, artifact).unwrap_err();
                assert!(error.to_string().contains(artifact));
            }
        }
    }

    fn empty_admission() -> RegistryAdmission {
        let executable = PathBuf::from("/nix/store/pinned/bin/nix-store");
        RegistryAdmission {
            image: crate::native_deployment::Admission::new(executable.clone()).unwrap(),
            executable,
            evidence: BTreeMap::new(),
            available: BTreeMap::new(),
        }
    }

    fn envelope(payload: &str, module: Option<ModuleSource>) -> Envelope {
        let path = format!("/nix/store/{}-{payload}", "a".repeat(32));
        Envelope {
            schema: "aos.package.deployment".into(),
            system: "x86_64-linux".into(),
            package: crate::deployment::model::Artifact {
                name: "system-image".into(),
                version: "1".into(),
                path: path.clone(),
                outputs: BTreeMap::from([("out".into(), path)]),
                main_program: None,
            },
            module,
            runtime_dependencies: BTreeMap::new(),
            version_requirement: None,
            os_version: None,
            module_dependencies: Vec::new(),
        }
    }

    #[test]
    fn runtime_artifact_cache_preserves_same_coordinate_distinct_payloads() {
        let registries = RegistrySet::new(Vec::new());
        let admission = empty_admission();
        let mut resolver = NativeRegistry::new(&registries, admission);
        resolver
            .cache_envelope(envelope("predecessor", None))
            .unwrap();
        resolver
            .cache_envelope(envelope("candidate", None))
            .unwrap();
        assert_eq!(resolver.envelopes.len(), 2);
    }

    #[test]
    fn module_resolution_rejects_ambiguous_artifact_contexts() {
        let registries = RegistrySet::new(Vec::new());
        let admission = empty_admission();
        let mut resolver = NativeRegistry::new(&registries, admission);
        let source = ModuleSource {
            name: "system-image".into(),
            version: "1".into(),
            source: format!("/nix/store/{}-module", "b".repeat(32)),
            entrypoint: "module.nix".into(),
        };
        resolver
            .cache_envelope(envelope("predecessor", Some(source.clone())))
            .unwrap();
        assert_eq!(
            resolver
                .resolve(&ModuleDependency::Exact(source.clone()))
                .unwrap()
                .package
                .path,
            envelope("predecessor", None).package.path
        );
        resolver
            .cache_envelope(envelope("candidate", Some(source.clone())))
            .unwrap();
        assert!(
            resolver
                .resolve(&ModuleDependency::Exact(source.clone()))
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
    }

    #[test]
    fn companion_catalog_preserves_the_exact_selected_module_source() {
        let registries = RegistrySet::new(Vec::new());
        let mut resolver = NativeRegistry::new(&registries, empty_admission());
        let source = ModuleSource {
            name: "system-image".into(),
            version: "1".into(),
            source: format!("/nix/store/{}-first-module", "b".repeat(32)),
            entrypoint: "module.nix".into(),
        };
        let first = envelope("first", Some(source.clone()));
        let mut other_source = source.clone();
        other_source.source = format!("/nix/store/{}-second-module", "c".repeat(32));
        let second = envelope("second", Some(other_source));
        let first_companion =
            PathBuf::from(format!("/nix/store/{}-first-envelope", "d".repeat(32)));
        let second_companion =
            PathBuf::from(format!("/nix/store/{}-second-envelope", "f".repeat(32)));
        resolver
            .module_envelopes
            .insert(envelope_key(&first), first_companion.clone());
        resolver
            .module_envelopes
            .insert(envelope_key(&second), second_companion);
        resolver.cache_envelope(first.clone()).unwrap();
        resolver.cache_envelope(second).unwrap();

        let resolved = crate::deployment::evaluation::resolve_packages(
            "x86_64-linux",
            vec![first],
            &mut resolver,
        )
        .unwrap();
        let companions = resolver.module_envelopes(&resolved).unwrap();

        assert_eq!(companions["system-image"], first_companion);
        assert_eq!(
            resolver
                .resolve(&ModuleDependency::Exact(source.clone()))
                .unwrap()
                .module
                .as_ref(),
            Some(&source)
        );
    }

    #[test]
    fn repeated_observation_preserves_original_source_authority() {
        let executable = PathBuf::from("/nix/store/pinned/bin/nix-store");
        let mut admission = RegistryAdmission {
            image: crate::native_deployment::Admission::new(executable.clone()).unwrap(),
            executable,
            evidence: BTreeMap::new(),
            available: BTreeMap::new(),
        };
        let root = format!("/nix/store/{}-source", "a".repeat(32));
        let authority = crate::native_deployment::SourceAuthorization {
            kind: "aos.boot.authenticated-source".into(),
            proof: PathBuf::from(format!("/nix/store/{}-proof.json", "b".repeat(32))),
            digest: Sha256Digest::of_bytes(b"original proof"),
        };
        let mut evidence = Evidence {
            nar_hash: Sha256Digest::of_bytes(b"original NAR"),
            nar_size: 128,
            references: Vec::new(),
            release: None,
            source_authority: Some(authority.clone()),
        };
        admission.insert(root.clone(), evidence.clone()).unwrap();

        evidence.source_authority = None;
        admission.insert(root.clone(), evidence.clone()).unwrap();
        assert!(admission.has_source_authority(Path::new(&root), &authority));

        evidence.source_authority = Some(crate::native_deployment::SourceAuthorization {
            digest: Sha256Digest::of_bytes(b"different proof"),
            ..authority.clone()
        });
        assert!(admission.insert(root.clone(), evidence).is_err());
        assert!(admission.has_source_authority(Path::new(&root), &authority));
    }
}
