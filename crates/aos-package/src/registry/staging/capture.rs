//! Captures exact candidate bytes and their real publication predecessors.

use std::collections::BTreeMap;

use aos_cache::backend::{self, AuthOptions, CacheBackend};
use aos_registry_surface::{keymap, refs};

use super::*;
use crate::registry::static_upload::{StaticOriginClass, collect_static_origin_files};
use crate::registry::transport::{RegistryRead as _, RegistryTransport};

const MAX_POINTER_BYTES: u64 = 256 * 1024 * 1024;

enum DestinationReader {
    Static(Box<dyn CacheBackend>),
    Hub(RegistryTransport),
}

impl DestinationReader {
    async fn read(&self, path: &str) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Static(backend) => Ok(backend
                .get_static_object(path, MAX_POINTER_BYTES as usize)
                .await?
                .map(|(bytes, _)| bytes)),
            Self::Hub(reader) => reader.read_optional(path, MAX_POINTER_BYTES).await,
        }
    }
}

impl LocalStageStore {
    /// Captures a new immutable revision against its required destination snapshots.
    ///
    /// Only the candidate's version tag is added to the existing advertisement.
    /// The public default branch and channel partition files remain unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error for stale revisions, dirty preparation, missing bootstrap
    /// metadata, divergent destinations, incomplete container bytes, or unsafe paths.
    #[allow(clippy::too_many_arguments)]
    pub async fn capture(
        &self,
        id: &str,
        registry: &str,
        release_id: &str,
        source_branch: &str,
        workspace: &Path,
        expected_revision: Option<u64>,
        cache_dir: Option<&Path>,
        destinations: &[String],
        auth: &AuthOptions,
        container_graph: Option<&StageContainerGraph>,
        graph_objects: &[StageObject],
    ) -> Result<StageRecord> {
        crate::dry_run::refuse_mutation("capture a candidate revision")?;
        validate_stage_id(id)?;
        semver::Version::parse(release_id)?;
        self.require_authoring_branch(source_branch)?;
        let targets = normalized_targets(destinations)?;
        let _lock = self.lock()?;
        let current = self.optional_record(id)?;
        match (&current, expected_revision) {
            (None, None) => {}
            (Some(record), Some(expected))
                if record.revision.revision == expected
                    && matches!(record.state, StageState::Draft | StageState::Ready) => {}
            _ => bail!("candidate revision or lifecycle changed; refusing stale preparation"),
        }
        let revision = current.as_ref().map_or(Ok(1), |record| {
            record
                .revision
                .revision
                .checked_add(1)
                .context("stage revision overflow")
        })?;
        let repository = git2::Repository::open(workspace)?;
        let statuses = repository.statuses(Some(
            git2::StatusOptions::new()
                .include_untracked(true)
                .recurse_untracked_dirs(true),
        ))?;
        if !statuses.is_empty() {
            bail!("candidate workspace must be committed and clean before capture");
        }
        let source_head = repository.head()?;
        if source_head.name()? != format!("refs/heads/{source_branch}") {
            bail!("candidate workspace HEAD differs from its authoring branch");
        }
        let commit = source_head.peel_to_commit()?.id().to_string();
        let tag_ref = repository.find_reference(&format!("refs/tags/{release_id}"))?;
        let tag_oid = tag_ref
            .target()
            .context("candidate release tag must be a direct reference")?;
        let odb = repository.odb()?;
        let tag = odb.read(tag_oid)?;
        if tag.kind() != git2::ObjectType::Tag {
            bail!("candidate release must have an annotated signed tag");
        }
        let signed = aos_registry_surface::tag::parse_signed_tag(tag.data())?;
        if signed.tag.name != release_id
            || signed.tag.object != commit
            || signed.tag.target_type != aos_registry_surface::tagobject::TagTarget::Commit
        {
            bail!("signed candidate tag differs from its frozen release identity");
        }
        if workspace.join("containers/v1/index.json").exists() && container_graph.is_none() {
            bail!("container catalog requires its complete verified staged graph");
        }

        let mut readers = Vec::new();
        let mut canonical_registry = None;
        for destination in &targets {
            if let Some(target) = hub::target(destination, registry).await? {
                if canonical_registry
                    .as_ref()
                    .is_some_and(|name| name != &target.registry)
                {
                    bail!("candidate destinations identify different Hub registry namespaces");
                }
                canonical_registry = Some(target.registry);
                readers.push(DestinationReader::Hub(
                    authenticated_hub_reader(destination, &target.origin, auth).await?,
                ));
            } else {
                readers.push(DestinationReader::Static(
                    backend::from_url(destination, auth).await?,
                ));
            }
        }
        let head = common_pointer(&readers, "HEAD").await?.context(
            "stage destination has no public HEAD; bootstrap the registry before staging",
        )?;
        let default = refs::parse_head(std::str::from_utf8(&head)?)
            .context("stage destination HEAD must identify its public default branch")?;
        crate::types::validate_channel_name(&default)?;
        if default == source_branch {
            bail!("candidate authoring branch is the destination's public default branch");
        }
        let advertisement = common_pointer(&readers, "info/refs").await?.context(
            "stage destination has no public ref advertisement; bootstrap it before staging",
        )?;
        let git_dir = crate::registry::objectstore::repo_git_dir(workspace)?;
        let prepared_refs = fs::read(git_dir.join("info/refs"))?;
        let merged_refs =
            merge_release_advertisement(&advertisement, &prepared_refs, release_id, &commit)?;

        let mut inventory = BTreeMap::new();
        let mut pointers = BTreeMap::new();
        for file in collect_static_origin_files(workspace)? {
            let path = file.relative_path;
            if path.starts_with("channels/") {
                continue;
            }
            if !keymap::is_mutable_path(&path) {
                let kind = match file.class {
                    StaticOriginClass::ImageDisk => "image-disk",
                    StaticOriginClass::Receipt => "receipt",
                    _ => "catalog",
                };
                let object =
                    self.capture_object(&path, &file.source, kind, keymap::content_type(&path))?;
                inventory.insert(path, object);
            } else {
                let bytes = match path.as_str() {
                    "HEAD" => head.clone(),
                    "info/refs" => merged_refs.clone(),
                    _ => fs::read(&file.source)?,
                };
                pointers.insert(path, bytes);
            }
        }
        // A collector may omit an optional local HEAD/listing; the destination
        // snapshot is nevertheless part of every frozen publication contract.
        pointers.insert("HEAD".into(), head.clone());
        pointers.insert("info/refs".into(), merged_refs);
        if let Some(cache) = cache_dir.filter(|directory| directory.exists()) {
            for (path, source) in regular_files(cache)? {
                if keymap::is_mutable_path(&path) {
                    pointers.insert(path, fs::read(source)?);
                } else {
                    let object =
                        self.capture_object(&path, &source, "cache", keymap::content_type(&path))?;
                    if !aos_registry_surface::staging::is_immutable_stage_path(&path) {
                        bail!("candidate cache contains an unsupported object key: {path}");
                    }
                    inventory.insert(path, object);
                }
            }
        }
        for object in graph_objects {
            if hash_file(&self.object_path(&object.sha256)?)?
                != (object.byte_size, object.sha256.clone())
            {
                bail!("container graph object bytes differ from the candidate descriptor");
            }
            if inventory
                .insert(object.path.clone(), object.clone())
                .is_some()
            {
                bail!("container graph repeats a staged object path");
            }
        }
        let mut publication = Vec::new();
        for (path, mut bytes) in pointers {
            let previous = common_pointer(&readers, &path).await?;
            if (path == "HEAD" && previous.as_deref() != Some(head.as_slice()))
                || (path == "info/refs" && previous.as_deref() != Some(advertisement.as_slice()))
            {
                bail!("destination discovery pointers changed during candidate capture");
            }
            if matches!(
                path.as_str(),
                "objects/info/packs" | "objects/info/alternates"
            ) {
                let mut lines = BTreeSet::new();
                for content in [previous.as_deref().unwrap_or_default(), bytes.as_slice()] {
                    lines.extend(std::str::from_utf8(content)?.lines().map(str::to_owned));
                }
                bytes = lines
                    .into_iter()
                    .map(|line| format!("{line}\n"))
                    .collect::<String>()
                    .into_bytes();
            }
            publication.push(StagePointer {
                path,
                bytes,
                expected_sha256: previous.map(|bytes| pointer_digest(&bytes)),
            });
        }
        let inventory: Vec<_> = inventory.into_values().collect();
        let candidate = StageRevision {
            schema: STAGE_SCHEMA.into(),
            id: id.into(),
            registry: canonical_registry.unwrap_or_else(|| registry.to_owned()),
            revision,
            release_id: release_id.into(),
            source_branch: source_branch.into(),
            commit,
            inventory_digest: inventory_digest(&inventory)?,
            inventory,
            container: container_graph.cloned(),
            publication,
            store_roots: crate::registry::nixcache::collect_static_cache_roots(workspace)?,
        };
        candidate.validate()?;
        if let Some(graph) = &candidate.container {
            crate::registry::container_stage::verify_container_stage_objects(
                graph,
                &self.objects_path(),
            )?;
        }
        self.write_new(
            &self.targets_path(id, revision),
            &serde_json::to_vec(&StageTargets {
                destinations: targets,
            })?,
        )?;
        self.write_new(
            &self.revision_path(id, revision),
            &serde_json::to_vec(&candidate)?,
        )?;
        if let Some(previous) = current {
            self.retire_revision_roots(id, previous.revision.revision)?;
        }
        let record = StageRecord {
            revision: candidate,
            state: StageState::Draft,
            released_version: None,
        };
        self.write_record(&record)?;
        Ok(record)
    }

    fn capture_object(
        &self,
        path: &str,
        source: &Path,
        kind: &str,
        media_type: &str,
    ) -> Result<StageObject> {
        if !source.symlink_metadata()?.is_file() {
            bail!("candidate object must be a regular file: {path}");
        }
        let (byte_size, sha256) = hash_file(source)?;
        let destination = self.object_path(&sha256)?;
        if !destination.exists() {
            let mut temporary = tempfile::NamedTempFile::new_in(self.objects_path())?;
            std::io::copy(&mut File::open(source)?, temporary.as_file_mut())?;
            temporary.as_file().sync_all()?;
            temporary.persist_noclobber(&destination)?;
            File::open(self.objects_path())?.sync_all()?;
        }
        if hash_file(&destination)? != (byte_size, sha256.clone()) {
            bail!("candidate object changed during capture: {path}");
        }
        Ok(StageObject {
            path: path.into(),
            sha256,
            byte_size,
            kind: kind.into(),
            media_type: media_type.into(),
        })
    }
}

async fn common_pointer(readers: &[DestinationReader], path: &str) -> Result<Option<Vec<u8>>> {
    let mut result = None;
    for (index, reader) in readers.iter().enumerate() {
        let bytes = reader.read(path).await?;
        if index != 0 && result != bytes {
            bail!("candidate destinations have different predecessors for {path}");
        }
        result = bytes;
    }
    Ok(result)
}

async fn authenticated_hub_reader(
    destination: &str,
    origin: &str,
    auth: &AuthOptions,
) -> Result<RegistryTransport> {
    crate::hub_auth::authenticated_hub_client(origin, auth.token.as_deref()).await?;
    let (_, token) = crate::hub_auth::resolve_access(Some(origin), auth.token.as_deref())?;
    let token = token.context("candidate destination requires authenticated Hub credentials")?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {token}").parse()?,
    );
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let engine = std::sync::Arc::new(aos_net::TransferEngine::with_http_client(
        aos_net::TransferEngineConfig::default(),
        client,
    ));
    Ok(RegistryTransport::new(destination)?.with_engine(engine))
}

fn merge_release_advertisement(
    baseline: &[u8],
    prepared: &[u8],
    version: &str,
    commit: &str,
) -> Result<Vec<u8>> {
    let parse = |bytes: &[u8]| -> Result<BTreeMap<String, String>> {
        let text = std::str::from_utf8(bytes)?;
        refs::parse_info_refs(text)?;
        text.lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                let (oid, name) = line.split_once('\t').context("invalid ref advertisement")?;
                Ok((name.to_owned(), oid.to_owned()))
            })
            .collect()
    };
    let mut merged = parse(baseline)?;
    let prepared = parse(prepared)?;
    let tag = format!("refs/tags/{version}");
    let peeled = format!("{tag}^{{}}");
    if prepared.get(&peeled).map(String::as_str) != Some(commit) {
        bail!("candidate must advertise its annotated release tag and exact commit");
    }
    for name in [tag, peeled] {
        let oid = prepared
            .get(&name)
            .context("candidate release tag is missing")?;
        if merged.get(&name).is_some_and(|existing| existing != oid) {
            bail!("published release identity already exists with different bytes");
        }
        merged.insert(name, oid.clone());
    }
    Ok(merged
        .into_iter()
        .map(|(name, oid)| format!("{oid}\t{name}\n"))
        .collect::<String>()
        .into_bytes())
}

pub(super) fn pointer_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub(super) fn regular_files(root: &Path) -> Result<Vec<(String, PathBuf)>> {
    fn visit(root: &Path, directory: &Path, files: &mut Vec<(String, PathBuf)>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                visit(root, &path, files)?;
            } else if kind.is_file() {
                let relative = path
                    .strip_prefix(root)?
                    .to_str()
                    .context("non-UTF-8 candidate path")?
                    .to_owned();
                files.push((relative, path));
            } else {
                bail!("candidate inventory contains a symbolic link or special file");
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(root, root, &mut files)?;
    files.sort();
    Ok(files)
}
