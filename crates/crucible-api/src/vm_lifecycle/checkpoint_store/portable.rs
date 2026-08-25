//! Streaming installation of portable production exact-checkpoint closures.

use super::*;

/// Read-only source for one complete portable production checkpoint closure.
///
/// Implementations expose the canonical version-four manifest, its exact
/// sorted immutable-object inventory, and authenticated streaming reads. The
/// installer independently verifies every byte and never grants the source
/// destination-store authority.
pub trait ProductionExactCheckpointSource: Send + Sync {
    /// Returns the production closure identity claimed by this source.
    fn identity(&self) -> ContentHash;

    /// Returns the exact scenario claimed by this source.
    fn scenario(&self) -> ContentHash;

    /// Returns the exact modeled configuration claimed by this source.
    fn configuration(&self) -> ContentHash;

    /// Returns the canonical `crucible.production-exact-closure.v4` manifest.
    fn manifest(&self) -> &[u8];

    /// Returns the exact strictly sorted immutable-object inventory.
    fn objects(&self) -> &[ProductionExactCheckpointObject];

    /// Opens one named object at its first byte.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the object is unavailable, does not
    /// belong to the source, or cannot be opened for streaming.
    fn open_object(&self, identity: ContentHash)
    -> Result<Box<dyn Read + Send>, LifecycleApiError>;

    /// Streams one named object into `destination`.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the object is unavailable, does not
    /// belong to the source, changes during the read, or destination I/O
    /// fails.
    fn copy_object_to(
        &self,
        identity: ContentHash,
        destination: &mut dyn Write,
    ) -> Result<u64, LifecycleApiError> {
        let mut source = self.open_object(identity)?;
        let mut copied = 0_u64;
        let mut buffer = [0_u8; CLOSURE_EXPORT_COPY_BUFFER_BYTES];
        loop {
            let count = source.read(&mut buffer).map_err(|error| {
                loop_factory_error(format!("read portable checkpoint object: {error}"))
            })?;
            if count == 0 {
                return Ok(copied);
            }
            destination.write_all(&buffer[..count]).map_err(|error| {
                loop_factory_error(format!("write portable checkpoint object: {error}"))
            })?;
            copied = copied
                .checked_add(u64::try_from(count).map_err(|_| {
                    loop_factory_error("portable checkpoint copy length is not representable")
                })?)
                .ok_or_else(|| loop_factory_error("portable checkpoint copy length overflow"))?;
        }
    }
}

impl ProductionExactCheckpointSource for ProductionExactCheckpointClosure {
    fn identity(&self) -> ContentHash {
        ProductionExactCheckpointClosure::identity(self)
    }

    fn scenario(&self) -> ContentHash {
        ProductionExactCheckpointClosure::scenario(self)
    }

    fn configuration(&self) -> ContentHash {
        ProductionExactCheckpointClosure::configuration(self)
    }

    fn manifest(&self) -> &[u8] {
        ProductionExactCheckpointClosure::manifest(self)
    }

    fn objects(&self) -> &[ProductionExactCheckpointObject] {
        ProductionExactCheckpointClosure::objects(self)
    }

    fn open_object(
        &self,
        identity: ContentHash,
    ) -> Result<Box<dyn Read + Send>, LifecycleApiError> {
        ProductionExactCheckpointClosure::open_object(self, identity)
    }

    fn copy_object_to(
        &self,
        identity: ContentHash,
        destination: &mut dyn Write,
    ) -> Result<u64, LifecycleApiError> {
        ProductionExactCheckpointClosure::copy_object_to(self, identity, destination)
    }
}

impl ProductionExactCheckpointSource for PreparedProductionReplayOraclePromotion {
    fn identity(&self) -> ContentHash {
        self.promoted
    }

    fn scenario(&self) -> ContentHash {
        self.scenario
    }

    fn configuration(&self) -> ContentHash {
        self.configuration
    }

    fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    fn objects(&self) -> &[ProductionExactCheckpointObject] {
        &self.objects
    }

    fn open_object(
        &self,
        identity: ContentHash,
    ) -> Result<Box<dyn Read + Send>, LifecycleApiError> {
        let Some(descriptor) = self.promoted_snapshots.get(&identity).copied() else {
            return self.raw.open_object(identity);
        };
        let mut boundary = || Ok(());
        let raw = read_portable_snapshot(
            &self.raw,
            descriptor.raw_object,
            self.fat_checkpoint_bytes,
            &mut boundary,
        )?;
        let promoted = descriptor.check.promote(&raw).map_err(|error| {
            loop_factory_error(format!(
                "regenerate promoted production replay-oracle snapshot: {error}"
            ))
        })?;
        let bytes = promoted
            .to_canonical_bytes_with_limit(self.fat_checkpoint_bytes)
            .map_err(|error| {
                loop_factory_error(format!(
                    "encode regenerated production replay-oracle snapshot: {error}"
                ))
            })?;
        if u64::try_from(bytes.len()).ok() != Some(descriptor.length)
            || ContentHash::from_bytes(&bytes) != identity
        {
            return Err(loop_factory_error(
                "regenerated production replay-oracle snapshot changed identity",
            ));
        }
        Ok(Box::new(std::io::Cursor::new(bytes)))
    }
}

/// Authenticates a portable source-bound production replay-oracle promotion.
///
/// Both source closures are copied into isolated temporary stores and pass the
/// complete scenario-aware restore validator. The validator then proves that
/// every live-node snapshot changed from raw `NotRun` evidence to `Match`
/// evidence without changing any other production continuation field. It
/// publishes no destination objects or manifests.
///
/// # Errors
///
/// Returns [`LifecycleApiError`] when either portable closure is malformed,
/// incomplete, semantically invalid, over the authored bounds, belongs to a
/// different scenario, or is not an exact source-bound replay-oracle
/// promotion.
pub fn authenticate_portable_exact_checkpoint_replay_oracle_promotion(
    source: &ScenarioDefForm,
    raw: &dyn ProductionExactCheckpointSource,
    promoted: &dyn ProductionExactCheckpointSource,
) -> Result<(), LifecycleApiError> {
    authenticate_portable_exact_checkpoint_replay_oracle_promotion_with_boundary(
        source,
        raw,
        promoted,
        &mut || Ok(()),
    )
}

/// Authenticates a portable replay-oracle promotion under a boundary callback.
///
/// The callback runs before path access, between source reads and bounded
/// temporary writes, throughout complete semantic validation, and between
/// per-node snapshot comparisons.
///
/// # Errors
///
/// Returns the same errors as
/// [`authenticate_portable_exact_checkpoint_replay_oracle_promotion`],
/// including the exact [`LifecycleApiError`] returned by `boundary`.
pub fn authenticate_portable_exact_checkpoint_replay_oracle_promotion_with_boundary(
    source: &ScenarioDefForm,
    raw: &dyn ProductionExactCheckpointSource,
    promoted: &dyn ProductionExactCheckpointSource,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    boundary()?;
    if raw.identity() == promoted.identity() {
        return Err(loop_factory_error(
            "portable production replay-oracle promotion did not change the closure identity",
        ));
    }
    let raw_preflight = preflight_portable_source(source, raw, boundary)?;
    let promoted_preflight = preflight_portable_source(source, promoted, boundary)?;
    let (raw_staging, _) =
        stage_and_validate_portable_source(source, raw, &raw_preflight, boundary)?;
    drop(raw_staging);
    let (promoted_staging, _) =
        stage_and_validate_portable_source(source, promoted, &promoted_preflight, boundary)?;
    drop(promoted_staging);

    let limits = source.plan().fault_signals().resource_limits();
    let raw_manifest = decode::decode_manifest_with_limits(&raw_preflight.manifest, limits)?;
    let promoted_manifest =
        decode::decode_manifest_with_limits(&promoted_preflight.manifest, limits)?;
    let raw_fault_identity = read_portable_fault_checkpoint_identity(
        raw,
        raw_manifest.fault_checkpoint,
        source,
        boundary,
    )?;
    let promoted_fault_identity = read_portable_fault_checkpoint_identity(
        promoted,
        promoted_manifest.fault_checkpoint,
        source,
        boundary,
    )?;
    if raw_fault_identity != promoted_fault_identity {
        return Err(loop_factory_error(
            "portable production replay-oracle promotion changed the fault-runtime identity",
        ));
    }

    authenticate_replay_oracle_source_pair(raw, promoted, limits, raw_fault_identity, boundary)
}

struct PortableClosurePreflight {
    identity: ContentHash,
    manifest: Vec<u8>,
    objects: Vec<ProductionExactCheckpointObject>,
}

/// Installs one complete portable checkpoint into a production run-state store.
///
/// The operation first copies the exact source inventory into a private
/// staging store and runs the complete production restore validator there.
/// Invalid or incomplete input therefore cannot publish destination objects.
/// After validation, immutable objects are installed idempotently and the
/// closure manifest is made visible last with the existing crash-consistent
/// publication protocol.
///
/// The installer retains only fixed-size streaming authentication state while
/// large overlay and VMState chunks pass through the source; aggregate retained
/// bytes remain bounded by the scenario's `fat_checkpoint_bytes` ceiling.
///
/// # Errors
///
/// Returns [`LifecycleApiError`] when the source manifest or inventory is
/// malformed, incomplete, noncanonical, over bounds, or semantically invalid;
/// an object fails streaming authentication; destination persistence fails;
/// or manifest publication is indeterminate.
pub fn install_exact_checkpoint_closure(
    run_state_root: &Path,
    source: &ScenarioDefForm,
    portable: &dyn ProductionExactCheckpointSource,
) -> Result<ProductionExactCheckpointClosure, LifecycleApiError> {
    install_exact_checkpoint_closure_with_boundary(run_state_root, source, portable, &mut || Ok(()))
}

/// Installs one portable checkpoint while observing an operational boundary.
///
/// The callback runs before path access, between source-object reads and
/// destination writes of at most one MiB, throughout complete semantic
/// validation, and between durable publication operations. An interrupted
/// staging transaction never publishes its manifest; immutable destination
/// objects placed before a later interruption remain unreachable and
/// idempotently reusable.
///
/// # Errors
///
/// Returns the same errors as [`install_exact_checkpoint_closure`], including
/// the exact [`LifecycleApiError`] returned by `boundary`.
pub fn install_exact_checkpoint_closure_with_boundary(
    run_state_root: &Path,
    source: &ScenarioDefForm,
    portable: &dyn ProductionExactCheckpointSource,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<ProductionExactCheckpointClosure, LifecycleApiError> {
    install_exact_checkpoint_closure_with_boundary_and_admission(
        run_state_root,
        source,
        portable,
        boundary,
        &mut |_| Ok(()),
    )
}

/// Installs one portable checkpoint after modeled-basis admission.
///
/// Complete scenario-aware validation runs in an isolated staging directory.
/// `admit` then receives the authenticated modeled continuation before any
/// object or manifest is published beneath `run_state_root`. This lets an
/// attempt owner reject a semantically valid closure for the wrong attempt
/// without retaining it in the private native catalog.
///
/// # Errors
///
/// Returns the same errors as
/// [`install_exact_checkpoint_closure_with_boundary`], including the exact
/// [`LifecycleApiError`] returned by `boundary` or `admit`.
pub fn install_exact_checkpoint_closure_with_boundary_and_admission(
    run_state_root: &Path,
    source: &ScenarioDefForm,
    portable: &dyn ProductionExactCheckpointSource,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
    admit: &mut dyn FnMut(&ProductionExactCheckpointResumeBasis) -> Result<(), LifecycleApiError>,
) -> Result<ProductionExactCheckpointClosure, LifecycleApiError> {
    boundary()?;
    let preflight = preflight_portable_source(source, portable, boundary)?;
    let (staging, basis) =
        stage_and_validate_portable_source(source, portable, &preflight, boundary)?;
    boundary()?;
    admit(&basis)?;
    boundary()?;

    publish_validated_portable_source(
        run_state_root,
        source,
        &preflight,
        staging.path(),
        boundary,
    )?;
    open_exact_checkpoint_closure_with_boundary(
        run_state_root,
        source,
        preflight.identity,
        boundary,
    )
}

fn preflight_portable_source(
    source: &ScenarioDefForm,
    portable: &dyn ProductionExactCheckpointSource,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<PortableClosurePreflight, LifecycleApiError> {
    boundary()?;
    let source_manifest = portable.manifest();
    if source_manifest.len() > MAX_MANIFEST_BYTES {
        return Err(loop_factory_error(
            "portable exact checkpoint manifest exceeds its byte limit",
        ));
    }
    let mut manifest = Vec::new();
    manifest
        .try_reserve_exact(source_manifest.len())
        .map_err(|_| loop_factory_error("reserve portable exact checkpoint manifest storage"))?;
    for chunk in source_manifest.chunks(CLOSURE_EXPORT_COPY_BUFFER_BYTES) {
        boundary()?;
        manifest.extend_from_slice(chunk);
    }

    let limits = source.plan().fault_signals().resource_limits();
    let decoded = decode::decode_manifest_with_limits(&manifest, limits)?;
    let identity = closure_identity(&decoded).map_err(scheduler_api_error)?;
    if decoded.identity != identity
        || decoded.scenario != source.scenario_def().id()
        || portable.identity() != identity
        || portable.scenario() != decoded.scenario
        || portable.configuration() != decoded.configuration
    {
        return Err(loop_factory_error(
            "portable exact checkpoint failed identity, scenario, or configuration authentication",
        ));
    }

    let expected = manifest_object_identities(&decoded);
    let supplied = portable.objects();
    if supplied.len() != expected.len()
        || !supplied
            .windows(2)
            .all(|pair| pair[0].identity() < pair[1].identity())
        || !expected
            .iter()
            .zip(supplied)
            .all(|(expected, supplied)| *expected == supplied.identity())
    {
        return Err(loop_factory_error(
            "portable exact checkpoint object inventory is not exact and strictly sorted",
        ));
    }

    let mut total = u64::try_from(manifest.len()).map_err(|_| {
        loop_factory_error("portable exact checkpoint manifest length is not representable")
    })?;
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(supplied.len())
        .map_err(|_| loop_factory_error("reserve portable exact checkpoint inventory"))?;
    for object in supplied {
        boundary()?;
        total = add_checkpoint_bytes(total, object.length()).map_err(scheduler_api_error)?;
        objects.push(*object);
    }
    limits
        .reserve("fat_checkpoint_bytes", 0, total)
        .map_err(scheduler_resource_limit)
        .map_err(scheduler_api_error)?;
    Ok(PortableClosurePreflight {
        identity,
        manifest,
        objects,
    })
}

fn stage_and_validate_portable_source(
    source: &ScenarioDefForm,
    portable: &dyn ProductionExactCheckpointSource,
    preflight: &PortableClosurePreflight,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(tempfile::TempDir, ProductionExactCheckpointResumeBasis), LifecycleApiError> {
    boundary()?;
    let staging_parent = tempfile::tempdir().map_err(|error| {
        loop_factory_error(format!(
            "create portable exact checkpoint validation store: {error}"
        ))
    })?;
    let scenario = source.scenario_def().id();
    let object_directory = object_parent(staging_parent.path(), scenario);
    fs::create_dir_all(&object_directory).map_err(|error| {
        loop_factory_error(format!(
            "create portable checkpoint staging object directory: {error}"
        ))
    })?;
    for object in &preflight.objects {
        boundary()?;
        stage_portable_object(&object_directory, portable, *object, boundary)?;
    }

    let publication =
        closure_parent(staging_parent.path(), scenario).join(preflight.identity.to_hex());
    fs::create_dir_all(&publication).map_err(|error| {
        loop_factory_error(format!(
            "create portable checkpoint staging publication: {error}"
        ))
    })?;
    let mut scheduler_boundary = || boundary().map_err(lifecycle_boundary_scheduler_error);
    persist_file_bytes_with_boundary(
        &publication.join(MANIFEST_FILE),
        &preflight.manifest,
        &mut scheduler_boundary,
    )
    .map_err(scheduler_api_error)?;
    let restored = load_exact_checkpoint_set_with_boundary(
        staging_parent.path(),
        &source.scenario_def(),
        source,
        preflight.identity,
        boundary,
    )?;
    let replay_oracle_ready = restored.targets.values().all(|target| {
        matches!(
            target.snapshot.replay_oracle_validation(),
            QemuReplayOracleValidation::Match { .. }
        )
    });
    let basis = ProductionExactCheckpointResumeBasis {
        identity: restored.identity,
        configuration: restored.configuration,
        scheduler: restored.scheduler,
        replay_oracle_ready,
    };
    Ok((staging_parent, basis))
}

fn stage_portable_object(
    object_directory: &Path,
    portable: &dyn ProductionExactCheckpointSource,
    object: ProductionExactCheckpointObject,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    boundary()?;
    let destination = object_path(object_directory, object.identity());
    let parent = destination
        .parent()
        .ok_or_else(|| loop_factory_error("portable checkpoint object path has no parent"))?;
    fs::create_dir_all(parent).map_err(|error| {
        loop_factory_error(format!("create portable checkpoint object prefix: {error}"))
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .map_err(|error| {
            loop_factory_error(format!(
                "create staged portable checkpoint object {}: {error}",
                object.identity().to_hex()
            ))
        })?;
    let (observed, hash) = {
        let mut writer = BoundedObjectWriter::new(&mut file, object.length());
        let mut source = portable.open_object(object.identity())?;
        let mut buffer = [0_u8; CLOSURE_EXPORT_COPY_BUFFER_BYTES];
        loop {
            boundary()?;
            let count = match source.read(&mut buffer) {
                Ok(count) => count,
                Err(error) => {
                    boundary()?;
                    return Err(loop_factory_error(format!(
                        "read portable checkpoint object: {error}"
                    )));
                }
            };
            boundary()?;
            if count == 0 {
                break;
            }
            writer.write_all(&buffer[..count]).map_err(|error| {
                loop_factory_error(format!("write portable checkpoint object: {error}"))
            })?;
        }
        boundary()?;
        writer.flush().map_err(|error| {
            loop_factory_error(format!(
                "flush staged portable checkpoint object {}: {error}",
                object.identity().to_hex()
            ))
        })?;
        (writer.written, writer.hash())
    };
    if observed != object.length() || hash != object.identity() {
        return Err(loop_factory_error(format!(
            "portable checkpoint object {} failed independent streaming authentication",
            object.identity().to_hex()
        )));
    }
    file.sync_all().map_err(|error| {
        loop_factory_error(format!(
            "sync staged portable checkpoint object {}: {error}",
            object.identity().to_hex()
        ))
    })
}

struct BoundedObjectWriter<'a> {
    destination: &'a mut File,
    maximum: u64,
    written: u64,
    hasher: blake3::Hasher,
}

impl<'a> BoundedObjectWriter<'a> {
    fn new(destination: &'a mut File, maximum: u64) -> Self {
        Self {
            destination,
            maximum,
            written: 0,
            hasher: blake3::Hasher::new(),
        }
    }

    fn hash(&self) -> ContentHash {
        ContentHash {
            bytes: *self.hasher.clone().finalize().as_bytes(),
        }
    }
}

impl Write for BoundedObjectWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let requested = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let next = self
            .written
            .checked_add(requested)
            .ok_or_else(|| std::io::Error::other("portable checkpoint object length overflow"))?;
        if next > self.maximum {
            return Err(std::io::Error::other(
                "portable checkpoint source exceeded its declared object length",
            ));
        }
        let written = self.destination.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        self.written = self
            .written
            .checked_add(u64::try_from(written).unwrap_or(u64::MAX))
            .ok_or_else(|| std::io::Error::other("portable checkpoint object length overflow"))?;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.destination.flush()
    }
}

fn publish_validated_portable_source(
    run_state_root: &Path,
    source: &ScenarioDefForm,
    preflight: &PortableClosurePreflight,
    staging_root: &Path,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    boundary()?;
    let scenario = source.scenario_def().id();
    let limits = source.plan().fault_signals().resource_limits();
    let closure_directory = closure_parent(run_state_root, scenario);
    let destination = closure_directory.join(preflight.identity.to_hex());
    admit_new_publication(&closure_directory, &destination, limits, boundary)?;

    if destination.exists() {
        return authenticate_existing_import(run_state_root, source, preflight, boundary);
    }

    let scenario_directory = run_state_root.join(scenario.to_hex());
    fs::create_dir_all(&scenario_directory).map_err(|error| {
        loop_factory_error(format!(
            "create imported checkpoint scenario directory: {error}"
        ))
    })?;
    sync_directory(run_state_root).map_err(scheduler_api_error)?;
    let object_directory = object_parent(run_state_root, scenario);
    fs::create_dir_all(&closure_directory).map_err(|error| {
        loop_factory_error(format!(
            "create imported checkpoint closure directory: {error}"
        ))
    })?;
    fs::create_dir_all(&object_directory).map_err(|error| {
        loop_factory_error(format!(
            "create imported checkpoint object directory: {error}"
        ))
    })?;
    sync_directory(&scenario_directory).map_err(scheduler_api_error)?;

    let staged_objects = object_parent(staging_root, scenario);
    for object in &preflight.objects {
        boundary()?;
        let mut scheduler_boundary = || boundary().map_err(lifecycle_boundary_scheduler_error);
        persist_file_object_with_boundary(
            &object_directory,
            object.identity(),
            &object_path(&staged_objects, object.identity()),
            &mut scheduler_boundary,
        )
        .map_err(scheduler_api_error)?;
    }
    sync_directory(&object_directory).map_err(scheduler_api_error)?;

    let manifest_staging = tempfile::Builder::new()
        .prefix(".closure-import-")
        .tempdir_in(&closure_directory)
        .map_err(|error| {
            loop_factory_error(format!(
                "create imported checkpoint manifest staging directory: {error}"
            ))
        })?;
    let mut scheduler_boundary = || boundary().map_err(lifecycle_boundary_scheduler_error);
    persist_file_bytes_with_boundary(
        &manifest_staging.path().join(MANIFEST_FILE),
        &preflight.manifest,
        &mut scheduler_boundary,
    )
    .map_err(scheduler_api_error)?;
    sync_directory(manifest_staging.path()).map_err(scheduler_api_error)?;
    let publication = PreparedExactCheckpointPublication::Staged {
        identity: preflight.identity,
        staging: manifest_staging,
        destination: destination.clone(),
        closure_parent: closure_directory,
        resource_limits: Box::new(limits),
    };
    match publication.publish() {
        Ok(()) => Ok(()),
        Err(error) if destination.exists() => authenticate_existing_import(
            run_state_root, source, preflight, boundary,
        )
        .map_err(|authentication| {
            loop_factory_error(format!(
                "checkpoint publication failed ({}) and the visible destination did not authenticate ({authentication})",
                persist_error_message(error)
            ))
        }),
        Err(error) => Err(persist_api_error(error)),
    }
}

fn admit_new_publication(
    closure_directory: &Path,
    destination: &Path,
    limits: FaultResourceLimits,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    boundary()?;
    if destination.exists() {
        return Ok(());
    }
    let entries = match fs::read_dir(closure_directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            limits
                .reserve("checkpoint_count", 0, 1)
                .map_err(scheduler_resource_limit)
                .map_err(scheduler_api_error)?;
            return Ok(());
        }
        Err(error) => {
            return Err(loop_factory_error(format!(
                "count imported checkpoint closures: {error}"
            )));
        }
    };
    let mut count = 0_u64;
    for entry in entries {
        boundary()?;
        let entry = entry.map_err(|error| {
            loop_factory_error(format!("enumerate imported checkpoint closures: {error}"))
        })?;
        let kind = entry.file_type().map_err(|error| {
            loop_factory_error(format!("inspect imported checkpoint closure: {error}"))
        })?;
        let is_identity = entry.file_name().to_str().is_some_and(|name| {
            name.len() == 64
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        });
        if kind.is_dir() && is_identity {
            count = count.checked_add(1).ok_or_else(|| {
                loop_factory_error("imported checkpoint count is not representable")
            })?;
        }
    }
    limits
        .reserve("checkpoint_count", count, 1)
        .map_err(scheduler_resource_limit)
        .map_err(scheduler_api_error)
}

fn authenticate_existing_import(
    run_state_root: &Path,
    source: &ScenarioDefForm,
    preflight: &PortableClosurePreflight,
    boundary: &mut dyn FnMut() -> Result<(), LifecycleApiError>,
) -> Result<(), LifecycleApiError> {
    let scenario = source.scenario_def();
    let manifest_path = closure_parent(run_state_root, scenario.id())
        .join(preflight.identity.to_hex())
        .join(MANIFEST_FILE);
    let existing =
        read_bounded_file_with_boundary(&manifest_path, MAX_MANIFEST_BYTES_U64, boundary).map_err(
            |error| match error {
                BoundedReadError::Boundary(error) => *error,
                error => loop_factory_error(format!(
                    "read existing imported checkpoint manifest: {error}"
                )),
            },
        )?;
    if existing != preflight.manifest {
        return Err(loop_factory_error(
            "existing imported checkpoint manifest differs at the same identity",
        ));
    }
    load_exact_checkpoint_set_with_boundary(
        run_state_root,
        &scenario,
        source,
        preflight.identity,
        boundary,
    )?;
    boundary()?;
    enforce_published_checkpoint_count(
        &closure_parent(run_state_root, scenario.id()),
        source.plan().fault_signals().resource_limits(),
    )
    .map_err(scheduler_api_error)
}

fn scheduler_api_error(error: SchedulerError) -> LifecycleApiError {
    match error {
        SchedulerError::OperationalBoundary { class, message } => {
            LifecycleApiError::AttemptOperational { class, message }
        }
        SchedulerError::ResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        } => LifecycleApiError::ResourceLimit(crate::LifecycleResourceLimit {
            field,
            current,
            requested,
            configured,
            hard,
        }),
        error => loop_factory_error(error.to_string()),
    }
}

fn lifecycle_boundary_scheduler_error(error: LifecycleApiError) -> SchedulerError {
    match error {
        LifecycleApiError::AttemptOperational { class, message } => {
            SchedulerError::OperationalBoundary { class, message }
        }
        error => SchedulerError::BoundaryViolation {
            message: error.to_string(),
        },
    }
}

fn persist_api_error(error: PersistExactCheckpointError) -> LifecycleApiError {
    match error {
        PersistExactCheckpointError::Unpublished(source) => scheduler_api_error(source),
        error @ PersistExactCheckpointError::Indeterminate { .. } => {
            loop_factory_error(persist_error_message(error))
        }
    }
}

fn persist_error_message(error: PersistExactCheckpointError) -> String {
    match error {
        PersistExactCheckpointError::Unpublished(source) => {
            format!("portable checkpoint publication was rolled back: {source}")
        }
        PersistExactCheckpointError::Indeterminate { identity, source } => format!(
            "portable checkpoint publication {} is indeterminate: {source}",
            identity.to_hex()
        ),
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- exact-checkpoint fixtures require explicit failure localization.
    #![allow(clippy::expect_used)]

    use super::*;

    struct TamperedPortableSource<'a> {
        original: &'a ProductionExactCheckpointClosure,
        identity: ContentHash,
        manifest: Vec<u8>,
        objects: Vec<ProductionExactCheckpointObject>,
        replacement_identity: ContentHash,
        replacement: Vec<u8>,
    }

    impl ProductionExactCheckpointSource for TamperedPortableSource<'_> {
        fn identity(&self) -> ContentHash {
            self.identity
        }

        fn scenario(&self) -> ContentHash {
            self.original.scenario()
        }

        fn configuration(&self) -> ContentHash {
            self.original.configuration()
        }

        fn manifest(&self) -> &[u8] {
            &self.manifest
        }

        fn objects(&self) -> &[ProductionExactCheckpointObject] {
            &self.objects
        }

        fn open_object(
            &self,
            identity: ContentHash,
        ) -> Result<Box<dyn Read + Send>, LifecycleApiError> {
            if identity == self.replacement_identity {
                return Ok(Box::new(std::io::Cursor::new(self.replacement.clone())));
            }
            self.original.open_object(identity)
        }

        fn copy_object_to(
            &self,
            identity: ContentHash,
            destination: &mut dyn Write,
        ) -> Result<u64, LifecycleApiError> {
            if identity == self.replacement_identity {
                destination.write_all(&self.replacement).map_err(|error| {
                    loop_factory_error(format!("write tampered portable fixture: {error}"))
                })?;
                return u64::try_from(self.replacement.len()).map_err(|_| {
                    loop_factory_error("tampered portable fixture length is not representable")
                });
            }
            self.original.copy_object_to(identity, destination)
        }
    }

    struct ClaimedBasisSource<'a> {
        original: &'a ProductionExactCheckpointClosure,
        identity: ContentHash,
        scenario: ContentHash,
        configuration: ContentHash,
    }

    impl ProductionExactCheckpointSource for ClaimedBasisSource<'_> {
        fn identity(&self) -> ContentHash {
            self.identity
        }

        fn scenario(&self) -> ContentHash {
            self.scenario
        }

        fn configuration(&self) -> ContentHash {
            self.configuration
        }

        fn manifest(&self) -> &[u8] {
            self.original.manifest()
        }

        fn objects(&self) -> &[ProductionExactCheckpointObject] {
            self.original.objects()
        }

        fn open_object(
            &self,
            identity: ContentHash,
        ) -> Result<Box<dyn Read + Send>, LifecycleApiError> {
            self.original.open_object(identity)
        }
    }

    #[test]
    fn portable_install_round_trips_complete_checkpoint_and_is_idempotent() {
        let source_store = tempfile::tempdir().expect("create source checkpoint store");
        let source = publish_empty_world_checkpoint(source_store.path());
        let closure = open_exact_checkpoint_closure(source_store.path(), &source.0, source.1)
            .expect("open source portable checkpoint");
        closure
            .validate_complete()
            .expect("authenticate complete source checkpoint");
        let destination = tempfile::tempdir().expect("create destination checkpoint store");

        let installed = install_exact_checkpoint_closure(destination.path(), &source.0, &closure)
            .expect("install portable checkpoint");
        assert_eq!(installed.identity(), closure.identity());
        assert_eq!(installed.manifest(), closure.manifest());
        assert_eq!(installed.objects(), closure.objects());
        let restored = load_exact_checkpoint_set(
            destination.path(),
            &source.0.scenario_def(),
            &source.0,
            source.1,
        )
        .expect("restore installed portable checkpoint");
        assert_eq!(restored.identity, source.1);

        let repeated = install_exact_checkpoint_closure(destination.path(), &source.0, &closure)
            .expect("repeat identical portable checkpoint install");
        assert_eq!(repeated.identity(), source.1);

        let basis = repeated
            .authenticate_resume_basis()
            .expect("authenticate installed resume basis");
        assert_eq!(basis.identity(), source.1);
        assert_eq!(basis.configuration().id(), repeated.configuration());
        assert_eq!(
            basis
                .scheduler()
                .configuration_for(&source.0.scenario_def())
                .expect("reconstruct resume scheduler configuration"),
            *basis.configuration()
        );
    }

    #[test]
    fn portable_install_cancellation_prevents_manifest_publication() {
        let source_store = tempfile::tempdir().expect("create source checkpoint store");
        let source = publish_empty_world_checkpoint(source_store.path());
        let closure = open_exact_checkpoint_closure(source_store.path(), &source.0, source.1)
            .expect("open source portable checkpoint");
        let destination = tempfile::tempdir().expect("create canceled checkpoint store");
        let scenario = source.0.scenario_def().id();
        let object_directory = object_parent(destination.path(), scenario);
        let publication = closure_parent(destination.path(), scenario).join(source.1.to_hex());
        let mut boundary = || {
            if object_directory.exists() {
                Err(LifecycleApiError::AttemptOperational {
                    class: crucible::SchedulerOperationalFailureClass::Canceled,
                    message: String::from("portable install canceled"),
                })
            } else {
                Ok(())
            }
        };

        let error = match install_exact_checkpoint_closure_with_boundary(
            destination.path(),
            &source.0,
            &closure,
            &mut boundary,
        ) {
            Ok(_) => panic!("cancellation must stop before the production manifest is published"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            LifecycleApiError::AttemptOperational {
                class: crucible::SchedulerOperationalFailureClass::Canceled,
                ..
            }
        ));
        assert!(!publication.exists());
    }

    #[test]
    fn rejected_resume_basis_publishes_no_native_closure() {
        let source_store = tempfile::tempdir().expect("create source checkpoint store");
        let source = publish_empty_world_checkpoint(source_store.path());
        let closure = open_exact_checkpoint_closure(source_store.path(), &source.0, source.1)
            .expect("open source portable checkpoint");
        let destination = tempfile::tempdir().expect("create rejected checkpoint store");
        let scenario = source.0.scenario_def().id();
        let object_directory = object_parent(destination.path(), scenario);
        let publication = closure_parent(destination.path(), scenario).join(source.1.to_hex());
        let mut observed_basis = None;
        let mut admit = |basis: &ProductionExactCheckpointResumeBasis| {
            observed_basis = Some(basis.clone());
            Err(LifecycleApiError::LoopFactory {
                message: String::from("checkpoint belongs to another attempt"),
            })
        };

        let error = match install_exact_checkpoint_closure_with_boundary_and_admission(
            destination.path(),
            &source.0,
            &closure,
            &mut || Ok(()),
            &mut admit,
        ) {
            Ok(_) => panic!("attempt admission must reject the native closure"),
            Err(error) => error,
        };

        assert!(matches!(error, LifecycleApiError::LoopFactory { .. }));
        assert_eq!(
            observed_basis
                .expect("admission receives authenticated basis")
                .identity(),
            source.1
        );
        assert!(!object_directory.exists());
        assert!(!publication.exists());
    }

    #[test]
    fn semantically_invalid_portable_source_publishes_no_destination_objects() {
        let source_store = tempfile::tempdir().expect("create source checkpoint store");
        let source = publish_empty_world_checkpoint(source_store.path());
        let closure = open_exact_checkpoint_closure(source_store.path(), &source.0, source.1)
            .expect("open source portable checkpoint");
        let replacement = b"not a canonical schedule".to_vec();
        let replacement_identity = ContentHash::from_bytes(&replacement);
        let mut manifest = decode::decode_manifest_with_limits(
            closure.manifest(),
            source.0.plan().fault_signals().resource_limits(),
        )
        .expect("decode source manifest fixture");
        manifest.schedule = replacement_identity;
        manifest.identity = closure_identity(&manifest).expect("derive tampered closure identity");
        let manifest_bytes = encode_manifest(&manifest).expect("encode tampered closure manifest");
        let lengths = closure
            .objects()
            .iter()
            .map(|object| (object.identity(), object.length()))
            .collect::<BTreeMap<_, _>>();
        let objects = manifest_object_identities(&manifest)
            .into_iter()
            .map(|identity| {
                let length = if identity == replacement_identity {
                    u64::try_from(replacement.len()).expect("replacement length fits")
                } else {
                    *lengths
                        .get(&identity)
                        .expect("unchanged object remains in source closure")
                };
                ProductionExactCheckpointObject::new(identity, length)
            })
            .collect();
        let tampered = TamperedPortableSource {
            original: &closure,
            identity: manifest.identity,
            manifest: manifest_bytes,
            objects,
            replacement_identity,
            replacement,
        };
        let destination = tempfile::tempdir().expect("create rejected checkpoint store");

        let error = match install_exact_checkpoint_closure(destination.path(), &source.0, &tampered)
        {
            Ok(_) => panic!("invalid schedule continuation must fail before publication"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("schedule"));
        let scenario = source.0.scenario_def().id();
        assert!(!closure_parent(destination.path(), scenario).exists());
        assert!(!object_parent(destination.path(), scenario).exists());
    }

    #[test]
    fn portable_install_rejects_a_transplanted_claimed_basis_before_writes() {
        let source_store = tempfile::tempdir().expect("create source checkpoint store");
        let source = publish_empty_world_checkpoint(source_store.path());
        let closure = open_exact_checkpoint_closure(source_store.path(), &source.0, source.1)
            .expect("open source portable checkpoint");
        let transplanted = ClaimedBasisSource {
            original: &closure,
            identity: ContentHash::from_bytes(b"foreign production closure"),
            scenario: closure.scenario(),
            configuration: closure.configuration(),
        };
        let destination = tempfile::tempdir().expect("create rejected checkpoint store");

        let error =
            match install_exact_checkpoint_closure(destination.path(), &source.0, &transplanted) {
                Ok(_) => panic!("a transplanted portable basis must fail before publication"),
                Err(error) => error,
            };

        assert!(error.to_string().contains("identity"));
        let scenario = source.0.scenario_def().id();
        assert!(!closure_parent(destination.path(), scenario).exists());
        assert!(!object_parent(destination.path(), scenario).exists());
    }

    fn publish_empty_world_checkpoint(run_state_root: &Path) -> (ScenarioDefForm, ContentHash) {
        let world = crucible::World::from_nodes(Vec::new()).expect("build empty checkpoint world");
        let source = ScenarioDefForm::from_components_with_app_random_draw_cap(
            &world,
            &crucible::Plan::empty(),
            &crucible::Properties::empty(),
            Seed::from_u64(0x504f_5254),
            0,
        )
        .expect("build empty checkpoint scenario");
        let scenario = source.scenario_def();
        let runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
            &scenario.id().to_hex(),
            Shift::new(0).expect("zero shift validates"),
            4,
            SimInstant { nanos: 4 },
            0,
            source.world(),
        )
        .with_scenario_def(scenario.clone());
        let scheduler = SingleScheduler::new(runtime_scenario).expect("build empty scheduler");
        let scheduler_checkpoint = scheduler.checkpoint().expect("checkpoint empty scheduler");
        let nodes = ProductionNodeSet::new();
        let fault_runtime = ProductionFaultRuntime::new(
            source.plan().fault_signals().clone(),
            None,
            SignalBoundarySnapshot::default(),
            scenario.id(),
            super::super::super::fault_implementation::test_host_manifests(),
            &nodes,
        )
        .expect("build empty fault runtime");
        let fault_runtime = Arc::new(std::sync::Mutex::new(fault_runtime));
        let cursor = Arc::new(std::sync::Mutex::new(
            ProductionFaultEvaluationCursor::default(),
        ));
        let observations = Arc::new(std::sync::Mutex::new(
            storage_faults::ProductionFaultObservationJournal::default(),
        ));
        let interceptor = ProductionFaultNetworkInterceptor::with_shared_runtime(
            fault_runtime,
            cursor,
            observations,
            source.world().fault_topology().clone(),
            source.world().links().to_vec(),
        );
        let fault_checkpoint = interceptor
            .checkpoint(
                &scheduler,
                VirtualTime { ticks: 0 },
                &[],
                &mut ProductionNodeSet::new(),
            )
            .expect("checkpoint empty fault runtime");
        let configuration = Configuration {
            def: scenario,
            schedule: Schedule::empty(),
        };
        let mut checkpoint = ProductionVmExactCheckpointSet {
            identity: ContentHash::default(),
            configuration,
            scheduler: scheduler_checkpoint,
            event_log_objects: BTreeMap::new(),
            signal_artifact_objects: BTreeMap::new(),
            trigger_state: EventGraphState::default(),
            assertion_state: HostAssertionEvaluator::new(source.properties()).checkpoint(),
            terminal_verdict: None,
            terminal_cause: None,
            initial_lifecycle_observations_pending: true,
            branch: None,
            recorded_controls: Vec::new(),
            fault_checkpoint: Some(fault_checkpoint),
            targets: BTreeMap::new(),
            node_generations: BTreeMap::new(),
            node_service_states: BTreeMap::new(),
        };
        let prepared = prepare_exact_checkpoint_set(
            run_state_root,
            source.scenario_def().id(),
            source.plan().fault_signals().resource_limits(),
            &mut checkpoint,
        )
        .expect("prepare empty production checkpoint");
        let identity = prepared.identity();
        prepared
            .publish()
            .expect("publish empty production checkpoint");
        (source, identity)
    }
}
