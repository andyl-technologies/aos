//! Transfers exact staged inventories and installs withheld pointers on release.

use aos_cache::backend::{self, AuthOptions, CacheBackend, ConditionalOutcome, Expectation};
use aos_core::output::Printer;
use aos_registry_surface::{keymap, object, refs};

use super::*;
use crate::registry::transport::{
    ImmutableUpload, ImmutableUploadPhase, RegistryStorage, pointer_upload_rank,
    upload_immutable_inventory,
};

const MAX_POINTER_BYTES: usize = 256 * 1024 * 1024;

impl LocalStageStore {
    /// Materializes a frozen revision's complete private publication surface.
    ///
    /// The resulting directory contains immutable inventory and withheld pointer
    /// bytes for shared publication adapters. It is never the public origin.
    ///
    /// # Errors
    ///
    /// Returns an error for stale revisions, corrupt inventory, or failed writes.
    pub fn materialize_surface(&self, id: &str, revision: u64) -> Result<PathBuf> {
        let _lock = self.lock()?;
        let candidate = self.verify_inventory(id, revision)?;
        self.materialize_revision(&candidate)
    }

    /// Uploads exact immutable bytes to every required destination before readiness.
    ///
    /// Static container graphs use canonical blob paths and their signed catalog
    /// as version authority. Hub adapters perform dedicated Distribution admission.
    ///
    /// # Errors
    ///
    /// Returns an error for stale or frozen revisions, changed destinations,
    /// conflicting objects, incomplete Hub admission, or failed transfers.
    pub async fn upload(
        &self,
        id: &str,
        revision: u64,
        destinations: &[String],
        auth: &AuthOptions,
    ) -> Result<StageRecord> {
        crate::dry_run::refuse_mutation("upload candidate bytes")?;
        self.require_targets(id, revision, destinations)?;
        let _lock = self.lock()?;
        let candidate = self.verify_inventory(id, revision)?;
        let mut record = self.show(id)?;
        if !matches!(record.state, StageState::Draft | StageState::Ready) {
            bail!("only a mutable candidate can upload bytes");
        }
        let printer = Printer::new(0, false, false);
        let mut static_targets = Vec::new();
        let mut hubs = Vec::new();
        for destination in normalized_targets(destinations)? {
            if let Some(target) = hub::target(&destination, &candidate.registry).await? {
                if target.registry != candidate.registry {
                    bail!("Hub namespace differs from the frozen candidate identity");
                }
                hubs.push(target);
            } else {
                let backend = backend::from_url(&destination, auth).await?;
                static_targets.push((destination, backend));
            }
        }
        let objects = self.upload_inventory(&candidate)?;
        if !static_targets.is_empty() {
            let targets: Vec<_> = static_targets
                .iter()
                .map(|(name, backend)| (name.as_str(), backend.as_ref()))
                .collect();
            upload_immutable_inventory(&objects, &targets, &printer).await?;
        }
        if !hubs.is_empty() {
            let surface = self.materialize_revision(&candidate)?;
            for target in hubs {
                hub::upload(
                    &candidate,
                    &surface,
                    &target.origin,
                    auth.token.as_deref(),
                    &printer,
                )
                .await?;
            }
        }
        record.state = StageState::Ready;
        self.write_record(&record)?;
        Ok(record)
    }

    /// Publishes exact frozen pointer bytes after verifying all required destinations.
    ///
    /// Predecessor absence is a conflict when capture observed an existing pointer.
    /// A retry accepts already-installed exact bytes and preserves every authoring
    /// branch, worktree, index, and channel frontier.
    ///
    /// # Errors
    ///
    /// Returns an error for changed destinations, stale revisions, missing immutable
    /// objects, pointer conflicts, failed conditional writes, or local tag conflicts.
    pub async fn publish(
        &self,
        id: &str,
        revision: u64,
        destinations: &[String],
        auth: &AuthOptions,
    ) -> Result<StageRecord> {
        crate::dry_run::refuse_mutation("publish candidate pointers")?;
        self.require_targets(id, revision, destinations)?;
        let _lock = self.lock()?;
        let candidate = self.verify_inventory(id, revision)?;
        let mut record = self.show(id)?;
        if !matches!(
            record.state,
            StageState::Ready | StageState::Releasing | StageState::Released
        ) {
            bail!("candidate must be ready before publication");
        }
        if record.state == StageState::Released {
            // This durable receipt was written only after every destination
            // committed. Later releases may have advanced their pointers;
            // validating this identity must never replay an older snapshot.
            self.verify_local_release_identity(&candidate)?;
            return Ok(record);
        }
        if candidate
            .publication
            .iter()
            .any(|pointer| pointer.path.starts_with("channels/"))
        {
            bail!("staged publication cannot promote channel partitions");
        }
        let mut static_targets = Vec::new();
        let mut hubs = Vec::new();
        for destination in normalized_targets(destinations)? {
            if let Some(target) = hub::target(&destination, &candidate.registry).await? {
                if target.registry != candidate.registry {
                    bail!("Hub namespace differs from the frozen candidate identity");
                }
                hubs.push(target);
            } else {
                static_targets.push((
                    destination.clone(),
                    backend::from_url(&destination, auth).await?,
                ));
            }
        }
        let mut pointers: Vec<_> = candidate.publication.iter().collect();
        pointers.sort_by(|left, right| {
            pointer_upload_rank(&left.path)
                .cmp(&pointer_upload_rank(&right.path))
                .then_with(|| left.path.cmp(&right.path))
        });
        // Complete every destination preflight before freezing or exposing any
        // pointer. Deletion of an expected predecessor must not become bootstrap.
        for (_, backend) in &static_targets {
            self.verify_remote_inventory(&candidate, backend.as_ref())
                .await?;
            for pointer in &pointers {
                check_pointer_predecessor(backend.as_ref(), pointer).await?;
            }
        }
        self.verify_local_release_identity(&candidate)?;
        if record.state == StageState::Ready {
            record.state = StageState::Releasing;
            self.write_record(&record)?;
        }

        // Prepare local bytes before any destination effects. Hub publication
        // uses admitted server bytes, so Hub-only releases need no local copy.
        let surface = if static_targets.is_empty() {
            None
        } else {
            Some(self.materialize_revision(&candidate)?)
        };
        let mut hubs_released = true;
        for target in hubs {
            let remote = hub::publish(&candidate, &target.origin, auth.token.as_deref()).await?;
            if remote.revision != candidate {
                bail!("Hub returned a different frozen candidate identity");
            }
            hubs_released &= remote.state == StageState::Released;
        }
        for (_, backend) in &static_targets {
            let surface = surface
                .as_deref()
                .context("static publication surface is missing")?;
            for pointer in &pointers {
                let observed = check_pointer_predecessor(backend.as_ref(), pointer).await?;
                if observed
                    .as_ref()
                    .is_some_and(|(bytes, _)| bytes == &pointer.bytes)
                {
                    continue;
                }
                let expect = observed.map_or(Expectation::Absent, |(_, version)| {
                    Expectation::Version(version)
                });
                let outcome = backend
                    .put_static_file_conditional(
                        &pointer.path,
                        &surface.join(&pointer.path),
                        Some(keymap::content_type(&pointer.path)),
                        Some(keymap::MUTABLE_CACHE_CONTROL),
                        expect,
                    )
                    .await?;
                if matches!(outcome, ConditionalOutcome::PreconditionFailed { .. }) {
                    let installed = backend
                        .get_static_object(&pointer.path, MAX_POINTER_BYTES)
                        .await?;
                    if !installed.is_some_and(|(bytes, _)| bytes == pointer.bytes) {
                        bail!(
                            "candidate publication pointer changed concurrently: {}",
                            pointer.path
                        );
                    }
                }
            }
        }
        for (_, backend) in &static_targets {
            for pointer in &pointers {
                let installed = backend
                    .get_static_object(&pointer.path, MAX_POINTER_BYTES)
                    .await?;
                if !installed.is_some_and(|(bytes, _)| bytes == pointer.bytes) {
                    bail!("published pointer did not verify: {}", pointer.path);
                }
            }
        }
        if !hubs_released {
            return Ok(record);
        }
        self.reconcile_release(&candidate)?;
        record.state = StageState::Released;
        record.released_version = Some(candidate.release_id);
        self.write_record(&record)?;
        Ok(record)
    }

    fn materialize_revision(&self, candidate: &StageRevision) -> Result<PathBuf> {
        let root = self
            .root
            .join("surfaces")
            .join(&candidate.id)
            .join(candidate.revision.to_string());
        fs::create_dir_all(&root)?;
        for object in &candidate.inventory {
            let path = root.join(&object.path);
            if path.exists() {
                if hash_file(&path)? != (object.byte_size, object.sha256.clone()) {
                    bail!("materialized candidate object identity changed");
                }
            } else {
                let parent = path.parent().context("candidate object lacks a parent")?;
                fs::create_dir_all(parent)?;
                let source = self.object_path(&object.sha256)?;
                if fs::hard_link(&source, &path).is_err() {
                    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
                    std::io::copy(&mut File::open(&source)?, temporary.as_file_mut())?;
                    temporary.as_file().sync_all()?;
                    temporary.persist_noclobber(&path)?;
                }
                File::open(parent)?.sync_all()?;
            }
        }
        for pointer in &candidate.publication {
            self.write_new(&root.join(&pointer.path), &pointer.bytes)?;
        }
        Ok(root)
    }

    fn upload_inventory(&self, candidate: &StageRevision) -> Result<Vec<ImmutableUpload>> {
        candidate
            .inventory
            .iter()
            .map(|object| {
                Ok(ImmutableUpload {
                    path: object.path.clone(),
                    source: self.object_path(&object.sha256)?,
                    sha256: object
                        .sha256
                        .strip_prefix("sha256:")
                        .context("candidate digest is malformed")?
                        .into(),
                    byte_size: object.byte_size,
                    phase: match object.kind.as_str() {
                        "image-disk" => ImmutableUploadPhase::ImageDisk,
                        "receipt" => ImmutableUploadPhase::Receipt,
                        _ => ImmutableUploadPhase::Catalog,
                    },
                })
            })
            .collect()
    }

    async fn verify_remote_inventory(
        &self,
        candidate: &StageRevision,
        backend: &dyn CacheBackend,
    ) -> Result<()> {
        let storage = RegistryStorage::new(backend);
        for object in self.upload_inventory(candidate)? {
            if !storage
                .object_matches(&object.path, &object.sha256, object.byte_size)
                .await?
            {
                bail!(
                    "candidate immutable bytes are missing at destination: {}",
                    object.path
                );
            }
        }
        Ok(())
    }

    fn verify_local_release_identity(&self, candidate: &StageRevision) -> Result<()> {
        let repository = git2::Repository::open(&self.registry)?;
        let oid = release_tag_oid(candidate, repository.object_format())?;
        match repository.find_reference(&format!("refs/tags/{}", candidate.release_id)) {
            Ok(reference) if reference.target() != Some(oid) => {
                bail!("local release tag differs from the frozen identity")
            }
            Ok(_) => Ok(()),
            Err(error) if error.code() == git2::ErrorCode::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn reconcile_release(&self, candidate: &StageRevision) -> Result<()> {
        let repository = git2::Repository::open(&self.registry)?;
        let odb = repository.odb()?;
        let git_dir = crate::registry::objectstore::repo_git_dir(&self.registry)?;

        let import_loose = |path: &str, bytes: &[u8]| -> Result<()> {
            let hex = path.trim_start_matches("objects/").replace('/', "");
            let expected = object::Oid::from_hex(&hex)?;
            let (kind, payload) = object::decode_loose(bytes, Some(expected))?;
            let kind = match kind {
                object::ObjectKind::Blob => git2::ObjectType::Blob,
                object::ObjectKind::Tree => git2::ObjectType::Tree,
                object::ObjectKind::Commit => git2::ObjectType::Commit,
                object::ObjectKind::Tag => git2::ObjectType::Tag,
            };
            if odb.write(kind, &payload)?.to_string() != expected.to_hex() {
                bail!("candidate object imported with a different Git identity");
            }
            Ok(())
        };

        for entry in &candidate.inventory {
            if keymap::is_loose_git_object_path(&entry.path) {
                import_loose(&entry.path, &fs::read(self.object_path(&entry.sha256)?)?)?;
            } else if entry.path.starts_with("releases/") {
                let path = git_dir.join(&entry.path);
                self.write_new(&path, &fs::read(self.object_path(&entry.sha256)?)?)?;
            }
        }

        for pointer in &candidate.publication {
            if keymap::is_loose_git_object_path(&pointer.path) {
                import_loose(&pointer.path, &pointer.bytes)?;
            } else if pointer.path.starts_with("releases/") {
                // Pack indexes and per-release server metadata are canonical
                // prepared pointers. Retain their exact reviewed bytes beside
                // the imported packs for subsequent publication adapters.
                self.write_new(&git_dir.join(&pointer.path), &pointer.bytes)?;
            }
        }

        let tag = release_tag_oid(candidate, repository.object_format())?;
        let name = format!("refs/tags/{}", candidate.release_id);
        match repository.find_reference(&name) {
            Ok(reference) if reference.target() == Some(tag) => {}
            Ok(_) => bail!("local release tag differs from the frozen identity"),
            Err(error) if error.code() == git2::ErrorCode::NotFound => {
                repository.reference(&name, tag, false, "import finalized registry release")?;
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

async fn check_pointer_predecessor(
    backend: &dyn CacheBackend,
    pointer: &StagePointer,
) -> Result<Option<(Vec<u8>, backend::ObjectVersion)>> {
    let observed = backend
        .get_static_object(&pointer.path, MAX_POINTER_BYTES)
        .await?;
    let compatible = match &observed {
        Some((bytes, _)) => {
            bytes == &pointer.bytes
                || pointer.expected_sha256.as_ref() == Some(&super::capture::pointer_digest(bytes))
        }
        None => pointer.expected_sha256.is_none(),
    };
    if !compatible {
        bail!(
            "candidate publication predecessor changed or disappeared: {}",
            pointer.path
        );
    }
    Ok(observed)
}

fn release_tag_oid(candidate: &StageRevision, format: git2::ObjectFormat) -> Result<git2::Oid> {
    let listing = candidate
        .publication
        .iter()
        .find(|pointer| pointer.path == "info/refs")
        .context("candidate has no release advertisement")?;
    let parsed = refs::parse_info_refs(std::str::from_utf8(&listing.bytes)?)?;
    let oid = parsed
        .tags
        .get(&candidate.release_id)
        .context("candidate release tag is missing")?;
    if parsed
        .peeled_tags
        .get(&candidate.release_id)
        .map(|oid| oid.to_hex())
        .as_deref()
        != Some(candidate.commit.as_str())
    {
        bail!("candidate release advertisement differs from its frozen commit");
    }
    Ok(git2::Oid::from_str_ext(&oid.to_hex(), format)?)
}
