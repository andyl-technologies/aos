//! Reads the actual prepublication capture under its retained original account.
//!
//! It neither fabricates a durable root nor exposes a decoded model owner.
//! Each actual file closes before its external descriptor loan is released.

use std::cell::Cell;
use std::fs::File;
use std::path::PathBuf;

use crucible::exact_checkpoint::authenticate_captured_exact_checkpoint;
use crucible::owned_decode::DecodeDescriptorLoan;

use super::*;

struct CapturedObjectReader<'a> {
    file: File,
    failure: &'a Cell<Option<io::Error>>,
    _descriptor: DecodeDescriptorLoan,
}

impl Read for CapturedObjectReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let previous = self.failure.take();
        if previous.is_some() {
            self.failure.set(previous);
            return Err(io::ErrorKind::Interrupted.into());
        }
        match self.file.read(bytes) {
            Ok(count) => Ok(count),
            Err(error) => {
                self.failure.set(Some(error));
                Err(io::ErrorKind::Interrupted.into())
            }
        }
    }
}

fn captured_object_path(
    directory: &Path,
    identity: ContentHash,
    original: &DecodeBudget,
) -> io::Result<PathBuf> {
    let extent = directory
        .as_os_str()
        .as_encoded_bytes()
        .len()
        .checked_add(1 + 2 + 1 + 64)
        .ok_or(io::ErrorKind::InvalidInput)?;
    original
        .charge_array::<u8>(extent)
        .and_then(|()| original.charge_array::<u8>(64))
        .map_err(|_| io::Error::from(io::ErrorKind::Interrupted))?;
    let mut path = PathBuf::new();
    path.try_reserve_exact(extent)
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    // Match the actual LocalDagStore two-level immutable object layout.
    let hex = identity.to_hex();
    path.push(directory);
    path.push(&hex[..2]);
    path.push(hex);
    Ok(path)
}

impl ProductionExactCheckpointClosure {
    /// Authenticates and decodes this retained capture under its original account.
    ///
    /// This operation borrows the actual prepublication manifest, object roster
    /// and leased RAM roots. It does not synthesize a durable repository root or
    /// create node restore admissions. All semantic bodies are read completely,
    /// EOF-checked and content-authenticated before role delivery. Actual source
    /// I/O and original failures survive downstream relation formatting.
    ///
    /// The supplied complete source must equal this capture's retained source.
    /// Native backing and complete physical-state evidence remain independent.
    ///
    /// # Errors
    /// Returns the first original, boundary, source I/O or relation/continuation
    /// failure. The result retains its original custody until physical model
    /// storage closes; it permits only opaque modeled comparison.
    pub fn decode_for_modeled_comparison_under_original(
        &self,
        source: &ScenarioDefForm,
        byte_limit: u64,
        boundary: impl FnMut() -> io::Result<()>,
        original: &DecodeBudget,
    ) -> Result<OriginalDecodedProductionExactCheckpoint, OriginalCheckpointDecodeError> {
        verify_original(original)?;
        let _scope = original.enter();
        let source_failure = Cell::new(None);
        let mut boundary = OriginalDecodeBoundary {
            original,
            boundary,
            first: None,
            admission: None,
            failure: None,
        };
        let result = self.decode_captured_model(source, byte_limit, &mut boundary, &source_failure);
        let source_error = source_failure.take();
        if source_error.is_some() && boundary.first.is_none() {
            boundary.first = Some(FirstFailure::Source);
        }
        boundary.finish(result).map_err(|mut error| {
            error.source = source_error;
            error
        })
    }

    fn decode_captured_model<F: FnMut() -> io::Result<()>>(
        &self,
        source: &ScenarioDefForm,
        byte_limit: u64,
        boundary: &mut OriginalDecodeBoundary<'_, F>,
        source_failure: &Cell<Option<io::Error>>,
    ) -> Result<DecodedProductionExactCheckpoint, LifecycleApiError> {
        boundary
            .check()
            .map_err(|_| loop_factory_error("original capture entry refused"))?;
        let Self {
            identity,
            scenario: captured_scenario,
            configuration,
            manifest,
            run_state_root: _,
            source: captured_source,
            object_directory,
            objects: captured_objects,
            ram_sources,
            ram_catalog_provider: _,
        } = self;
        if source != captured_source {
            return Err(loop_factory_error(
                "capture source differs from complete supplied source",
            ));
        }
        let scenario = source.scenario_def();
        let relation = authenticate_captured_exact_checkpoint(
            manifest,
            *identity,
            *captured_scenario,
            *configuration,
            captured_objects
                .iter()
                .map(|object| (object.identity(), object.length())),
            byte_limit,
        )
        .map_err(|error| loop_factory_error(format!("authenticate capture relation: {error}")))?;
        let mut ram_nodes = 0_usize;
        relation
            .visit_paged_ram_roots(|node, binding| {
                boundary.check().map_err(|_| {
                    crucible::exact_checkpoint::ExactCheckpointRelationError::InvalidStructure
                })?;
                let mut sources = ram_sources
                    .iter()
                    .filter(|source| source.node().name == node);
                let source = sources.next().ok_or(
                    crucible::exact_checkpoint::ExactCheckpointRelationError::InvalidStructure,
                )?;
                if sources.next().is_some() {
                    return Err(
                        crucible::exact_checkpoint::ExactCheckpointRelationError::InvalidStructure,
                    );
                }
                binding.authenticate_source(source.root())?;
                ram_nodes = ram_nodes.checked_add(1).ok_or(
                    crucible::exact_checkpoint::ExactCheckpointRelationError::InvalidStructure,
                )?;
                Ok(())
            })
            .map_err(|error| {
                loop_factory_error(format!("authenticate capture RAM relation: {error}"))
            })?;
        if ram_nodes != ram_sources.len() {
            return Err(loop_factory_error(
                "capture RAM source inventory differs from targets",
            ));
        }
        let mut objects = SemanticObjects::default();
        let original = boundary.original;
        relation
            .visit_semantic_objects(
                byte_limit,
                || boundary.check(),
                |identity| {
                    let descriptor = original
                        .reserve_descriptors(1)
                        .map_err(|_| io::Error::from(io::ErrorKind::Interrupted))?;
                    let path = captured_object_path(object_directory, identity, original)?;
                    match File::open(path) {
                        Ok(file) => Ok(CapturedObjectReader {
                            file,
                            failure: source_failure,
                            _descriptor: descriptor,
                        }),
                        Err(error) => {
                            source_failure.set(Some(error));
                            Err(io::ErrorKind::Interrupted.into())
                        }
                    }
                },
                |role, bytes| collect_semantic_object(&mut objects, role, bytes, &scenario, source),
            )
            .map_err(|error| {
                loop_factory_error(format!("authenticate capture semantic closure: {error}"))
            })?;
        reconstruct_semantic_checkpoint(*identity, &scenario, source, objects)
    }
}
