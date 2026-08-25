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
    let preflight = preflight_portable_source(source, portable)?;
    let staging = stage_and_validate_portable_source(source, portable, &preflight)?;

    publish_validated_portable_source(run_state_root, source, &preflight, staging.path())?;
    open_exact_checkpoint_closure(run_state_root, source, preflight.identity)
}

fn preflight_portable_source(
    source: &ScenarioDefForm,
    portable: &dyn ProductionExactCheckpointSource,
) -> Result<PortableClosurePreflight, LifecycleApiError> {
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
    manifest.extend_from_slice(source_manifest);

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
    for object in supplied {
        total = add_checkpoint_bytes(total, object.length()).map_err(scheduler_api_error)?;
    }
    limits
        .reserve("fat_checkpoint_bytes", 0, total)
        .map_err(scheduler_resource_limit)
        .map_err(scheduler_api_error)?;

    let mut objects = Vec::new();
    objects
        .try_reserve_exact(supplied.len())
        .map_err(|_| loop_factory_error("reserve portable exact checkpoint inventory"))?;
    objects.extend_from_slice(supplied);
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
) -> Result<tempfile::TempDir, LifecycleApiError> {
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
        stage_portable_object(&object_directory, portable, *object)?;
    }

    let publication =
        closure_parent(staging_parent.path(), scenario).join(preflight.identity.to_hex());
    fs::create_dir_all(&publication).map_err(|error| {
        loop_factory_error(format!(
            "create portable checkpoint staging publication: {error}"
        ))
    })?;
    persist_file_bytes(&publication.join(MANIFEST_FILE), &preflight.manifest)
        .map_err(scheduler_api_error)?;
    load_exact_checkpoint_set(
        staging_parent.path(),
        &source.scenario_def(),
        source,
        preflight.identity,
    )?;
    Ok(staging_parent)
}

fn stage_portable_object(
    object_directory: &Path,
    portable: &dyn ProductionExactCheckpointSource,
    object: ProductionExactCheckpointObject,
) -> Result<(), LifecycleApiError> {
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
    let (reported, observed, hash) = {
        let mut writer = BoundedObjectWriter::new(&mut file, object.length());
        let reported = portable.copy_object_to(object.identity(), &mut writer)?;
        writer.flush().map_err(|error| {
            loop_factory_error(format!(
                "flush staged portable checkpoint object {}: {error}",
                object.identity().to_hex()
            ))
        })?;
        (reported, writer.written, writer.hash())
    };
    if reported != object.length() || observed != object.length() || hash != object.identity() {
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
) -> Result<(), LifecycleApiError> {
    let scenario = source.scenario_def().id();
    let limits = source.plan().fault_signals().resource_limits();
    let closure_directory = closure_parent(run_state_root, scenario);
    let destination = closure_directory.join(preflight.identity.to_hex());
    admit_new_publication(&closure_directory, &destination, limits)?;

    if destination.exists() {
        return authenticate_existing_import(run_state_root, source, preflight);
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
        persist_file_object(
            &object_directory,
            object.identity(),
            &object_path(&staged_objects, object.identity()),
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
    persist_file_bytes(
        &manifest_staging.path().join(MANIFEST_FILE),
        &preflight.manifest,
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
            run_state_root,
            source,
            preflight,
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
) -> Result<(), LifecycleApiError> {
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
) -> Result<(), LifecycleApiError> {
    let scenario = source.scenario_def();
    let manifest_path = closure_parent(run_state_root, scenario.id())
        .join(preflight.identity.to_hex())
        .join(MANIFEST_FILE);
    let existing = read_bounded_file(&manifest_path, MAX_MANIFEST_BYTES_U64).map_err(|error| {
        loop_factory_error(format!(
            "read existing imported checkpoint manifest: {error}"
        ))
    })?;
    if existing != preflight.manifest {
        return Err(loop_factory_error(
            "existing imported checkpoint manifest differs at the same identity",
        ));
    }
    load_exact_checkpoint_set(run_state_root, &scenario, source, preflight.identity)?;
    enforce_published_checkpoint_count(
        &closure_parent(run_state_root, scenario.id()),
        source.plan().fault_signals().resource_limits(),
    )
    .map_err(scheduler_api_error)
}

fn scheduler_api_error(error: SchedulerError) -> LifecycleApiError {
    match error {
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
