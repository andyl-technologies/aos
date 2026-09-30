//! Authenticated registry resolution and retained admission for native profiles.
//!
//! Native envelopes remain bound to the signed registry release, exact NAR
//! contents, and live reference graph that admitted them. Private profile
//! receipts preserve that original admission evidence for old handlers during
//! removal and recovery; a transaction document never supplies its own trust.

mod available;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use aos_ability_plan::module_graph::GRAPH_LIMITS;
use aos_contract::Sha256Digest;
use serde::{Deserialize, Serialize};

use crate::deployment::evaluation::PackageResolver;
use crate::deployment::model::{Envelope, ModuleSource};
use crate::deployment::retention::ArtifactAdmission;
use crate::registry::{Registry, RegistrySet, ReleaseTrustReceipt, store_path_hash};
use crate::store::verification::{
    dump_store_path_identity_in, query_reference_hashes_in, query_store_paths_in,
    verify_store_object_in,
};
use crate::types::{InstalledMeta, PackageMeta};

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
}

impl<'a> NativeRegistry<'a> {
    pub(crate) fn new(registries: &'a RegistrySet, admission: RegistryAdmission) -> Self {
        Self {
            registries,
            admission,
            envelopes: BTreeMap::new(),
            retained_inputs: BTreeSet::new(),
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
            Sha256Digest::parse(&deployment.nar_hash)?,
            deployment.nar_size,
            &deployment.references,
            Some(&self.admission.executable),
        )?;
        self.admission
            .capture_closure(registry, &deployment.store_path)?;
        for documentation in [&meta.module_documentation].into_iter().flatten() {
            verify_store_object_in(
                &documentation.store_path,
                Sha256Digest::parse(&documentation.nar_hash)?,
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
        Ok(envelope)
    }

    // Runtime roles may refer to different builds with identical name/version.
    // Only exact artifact catalogs share a cache entry; module lookup separately
    // requires one unambiguous package context for the pinned module source.
    fn cache_envelope(&mut self, envelope: Envelope) -> Result<()> {
        let key = (
            envelope.package.name.clone(),
            envelope.package.version.clone(),
            envelope.package.canonical_catalog().path,
        );
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

    pub(crate) fn into_admission(self) -> RegistryAdmission {
        self.admission
    }

    pub(crate) fn retained_inputs(&self) -> Vec<PathBuf> {
        self.retained_inputs
            .iter()
            .cloned()
            .chain(self.admission.image.receipt_roots())
            .collect()
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
}

impl PackageResolver for NativeRegistry<'_> {
    fn resolve(&mut self, source: &ModuleSource) -> Result<Envelope> {
        if let Some(envelope) = self.cached_module(source)? {
            return Ok(envelope);
        }
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
            resolver.resolve(&source).unwrap().package.path,
            envelope("predecessor", None).package.path
        );
        resolver
            .cache_envelope(envelope("candidate", Some(source.clone())))
            .unwrap();
        assert!(
            resolver
                .resolve(&source)
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
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
