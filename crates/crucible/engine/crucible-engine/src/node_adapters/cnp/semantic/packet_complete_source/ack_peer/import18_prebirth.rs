//! Retains explicit import18 pre-report SourceBirth construction in admitted stages.
//!
//! The installer admits every opaque stage row outside Source loans. This owner
//! keeps actual inputs, completed DOMs, partial canonical banks and the private
//! File/key constructor across refusal. It creates neither an Initial row nor a
//! native startup, association, allocation or SDK witness.

use super::*;
use crate::node_contract::{NodeRuntime, RuntimeError};
use crucible_node_format::{ContentRef, canonical};
use crucible_node_transport::reference_packet::{
    coordinator::PacketNative5CoordinatorInstallation,
    service::complete_restore::import18::hello::{
        native_import18_hello_declaration_data, native_import18_prospective_host_registration_data,
    },
};
use serde_json::Value;
use std::{io::Write, mem::size_of, os::unix::ffi::OsStrExt, thread::ThreadId};

#[path = "import18_prebirth/storage.rs"]
mod storage;
#[path = "import18_prebirth/views.rs"]
mod views;

use birth::import18_construction::NativeImport18PrivateBirthAttempt;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Initialized,
    Validating,
    Validated,
    DecodingCoordinator,
    Coordinator,
    Materializing,
    Materialized,
    Encoding,
    Encoded,
    CreatingBirth,
    Complete,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    source: usize,
    process: u32,
    thread: ThreadId,
    launch_operands: [u8; 32],
}

/// Describes one exact stage's additional requested storage; it is not credit.
pub struct NativeImport18BirthConstructionQuote {
    identity: Identity,
    stage: Stage,
    requested: [usize; 3],
    encoded: [usize; 2],
}

impl NativeImport18BirthConstructionQuote {
    /// Returns this stage's additional retained/transient/fixed-scratch axes.
    pub fn requested_storage_data(&self) -> [usize; 3] {
        self.requested
    }
}

/// Owns immutable planned operands and all partial pre-report constructor state.
pub(in crate::node_adapters::cnp::semantic) struct NativeImport18BirthConstruction {
    identity: Identity,
    inputs_started: bool,
    registration: Option<PacketCompleteAckHostRegistrationPlan>,
    private_launch: Option<Id>,
    coordinator: Option<PacketNative5CoordinatorInstallation>,
    source_value: Option<Value>,
    registration_value: Option<Value>,
    source_bank: Option<Vec<u8>>,
    registration_bank: Option<Vec<u8>>,
    private_birth: NativeImport18PrivateBirthAttempt,
    stage: Stage,
    failed: bool,
}

impl NativeImport18BirthConstruction {
    /// Names the fixed quote, serializer, counter and constructor work.
    pub(in crate::node_adapters::cnp::semantic) fn counter_scratch_data() -> usize {
        storage::counter_scratch_data()
    }

    /// Counts all transferred inputs and partial outputs independently of success.
    ///
    /// # Errors
    /// Refuses unsupported nested metadata, checked overflow or excessive backing.
    pub(in crate::node_adapters::cnp::semantic) fn retained_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        storage::retained_storage(self, maximum)
    }
}

impl PacketCompleteSemanticSource {
    /// Names this staged constructor's defining fixed prewalk and execution work.
    ///
    /// The caller admits this before any quote or partial census. Dynamic
    /// formatter prewalk and each full stage row remain independent admissions.
    pub fn native_import18_birth_construction_counter_scratch_data() -> usize {
        storage::counter_scratch_data()
    }

    /// Observes every retained worker child, including failed and incomplete ones.
    ///
    /// The Source's enclosing inline header and actual private Birth are counted
    /// by their ordinary owning rows. This term owns only the worker allocation
    /// and its still-present children; transferred canonical banks are omitted
    /// here once the actual Birth owns them.
    ///
    /// # Errors
    /// Refuses a foreign creator, unsupported nested facts or checked overflow.
    pub fn native_import18_birth_construction_retained_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        self.native_import18_birth_construction
            .as_ref()
            .map(|owner| owner.retained_storage_data(maximum))
            .transpose()
            .map(|value| value.unwrap_or(0))
    }

    /// Checks storage custody without requiring a successful constructor stage.
    ///
    /// The enclosing pre-Child observer authenticates the Source origin first.
    /// Failed and not-yet-populated workers retain their real backing; neither
    /// a spent flag without an owner nor a transplanted owner is counted as empty.
    ///
    /// # Errors
    /// Refuses inconsistent spent/worker slots or another Source's worker.
    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn authenticate_template18_worker_storage_custody_data(
        &self,
    ) -> Result<(), RuntimeError> {
        match (
            self.ack_birth_attempted,
            self.native_import18_birth_construction.as_ref(),
        ) {
            (false, None) => Ok(()),
            (true, Some(owner)) => {
                if owner.identity.source != self as *const Self as usize
                    || owner.identity.process != self.process
                    || owner.identity.thread != self.thread
                {
                    return Err(RuntimeError::ForeignAuthority);
                }
                Ok(())
            }
            _ => Err(RuntimeError::OutstandingObligations),
        }
    }

    pub(in crate::node_adapters::cnp::semantic::packet_complete_source) fn template18_worker_storage_custody_counter_scratch_data()
    -> usize {
        let controls = [
            size_of::<&Self>(),
            size_of::<&Option<Box<NativeImport18BirthConstruction>>>(),
            size_of::<Option<&Box<NativeImport18BirthConstruction>>>(),
            size_of::<(bool, Option<&Box<NativeImport18BirthConstruction>>)>(),
            size_of::<&Box<NativeImport18BirthConstruction>>(),
            size_of::<&NativeImport18BirthConstruction>(),
            size_of::<*const Self>(),
            size_of::<usize>(),
            size_of::<&ThreadId>() * 2,
            // ThreadId's derived comparison reaches its NonZero<u64> field;
            // NonZero::ne takes both copied receivers and returns their u64s.
            size_of::<&std::num::NonZeroU64>() * 2,
            size_of::<std::num::NonZeroU64>() * 2,
            size_of::<u64>() * 2,
            size_of::<&u64>() * 2,
            size_of::<bool>(),
            size_of::<Result<(), RuntimeError>>(),
        ];
        controls
            .iter()
            .copied()
            .fold(0usize, usize::saturating_add)
            .saturating_add(std::mem::size_of_val(&controls))
            .saturating_add(std::mem::size_of_val(&controls.into_iter()))
    }

    /// Quotes the one lazy owner before its Box is allocated or inputs move.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn native_import18_birth_initialize_quote_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        maximum: usize,
    ) -> Result<NativeImport18BirthConstructionQuote, RuntimeError> {
        self.authenticate_import18_birth_source_data(launch)?;
        if self.ack_birth_attempted
            || self.native_import18_birth_construction.is_some()
            || self
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerUnavailable)?
                .is_some()
            || self
                .ack_peer_association
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerUnavailable)?
                .is_some()
            || self.ack_birth_input_banks.is_some()
            || self
                .preconstruction
                .try_borrow()
                .map_err(|_| RuntimeError::OwnerUnavailable)?
                .is_some()
            || self.complete_bytes_launch_reserved.get()
        {
            return Err(RuntimeError::DuplicateOperation);
        }
        Ok(NativeImport18BirthConstructionQuote {
            identity: self.import18_birth_identity_data(launch)?,
            stage: Stage::Initialized,
            requested: storage::initialize_storage_data(maximum)?,
            encoded: [0; 2],
        })
    }

    /// Installs the worker before taking the caller's same planned inputs.
    ///
    /// Input backing already exists in the caller's admitted holder. Moving it
    /// changes custody, not its cumulative allocation debit or whole-holder sum.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn retain_native_import18_birth_initialize_into_data(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        private_launch: &mut Option<Id>,
        registration: &mut Option<PacketCompleteAckHostRegistrationPlan>,
        quote: &NativeImport18BirthConstructionQuote,
    ) -> Result<(), RuntimeError> {
        let expected = self.native_import18_birth_initialize_quote_data(launch, usize::MAX)?;
        if quote.stage != Stage::Initialized
            || quote.identity != expected.identity
            || quote.requested != expected.requested
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.ack_birth_attempted = true;
        self.native_import18_birth_construction = Some(Box::new(NativeImport18BirthConstruction {
            identity: quote.identity,
            inputs_started: false,
            registration: None,
            private_launch: None,
            coordinator: None,
            source_value: None,
            registration_value: None,
            source_bank: None,
            registration_bank: None,
            private_birth: NativeImport18PrivateBirthAttempt::new_data(),
            stage: Stage::Initialized,
            failed: true,
        }));
        let owner = self
            .native_import18_birth_construction
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        owner.retain_initial_operands_data(private_launch, registration)
    }

    /// Quotes actual formatter work before the launch validator's serializer walk.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn native_import18_birth_validation_prewalk_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        maximum: usize,
    ) -> Result<[usize; 3], RuntimeError> {
        self.import18_birth_owner_data(launch, Stage::Initialized)?;
        let (transient, scratch) = launch
            .validation_construction_projection_storage_data()
            .map_err(|_| RuntimeError::ResourceLimit)?;
        storage::bounded(
            [
                0,
                transient,
                storage::sum(&[scratch, storage::counter_scratch_data()])?,
            ],
            maximum,
        )
    }

    /// Quotes the real launch validator under its independently admitted prewalk.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn native_import18_birth_validate_quote_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        maximum: usize,
    ) -> Result<NativeImport18BirthConstructionQuote, RuntimeError> {
        let owner = self.import18_birth_owner_data(launch, Stage::Initialized)?;
        let (transient, scratch) = launch
            .validation_construction_storage_data(maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        let (credit_failure, credit_controls) = PacketNative5SourceLaunch::original_import18_serialized_credit_failure_construction_data(maximum)
            .map_err(|_| RuntimeError::ResourceLimit)?;
        owner.quote(
            Stage::Validating,
            [
                0,
                storage::sum(&[transient, credit_failure])?,
                storage::sum(&[scratch, credit_controls, storage::counter_scratch_data()])?,
            ],
            [0; 2],
            maximum,
        )
    }

    /// Runs the unchanged launch validator with a sticky retained destination.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn retain_native_import18_birth_validate_into_data(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        quote: &NativeImport18BirthConstructionQuote,
    ) -> Result<(), RuntimeError> {
        self.start_import18_birth_stage_data(launch, quote, Stage::Initialized, Stage::Validating)?;
        launch
            .validate()
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        self.finish_import18_birth_stage_data(Stage::Validated)
    }

    /// Quotes the second actual coordinator decode, including its own validators.
    ///
    /// The defining Provider facade must be composed before this slice can be
    /// selected. Original lexical extent alone cannot fund expanded typed work.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn native_import18_birth_coordinator_quote_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        maximum: usize,
    ) -> Result<NativeImport18BirthConstructionQuote, RuntimeError> {
        let owner = self.import18_birth_owner_data(launch, Stage::Validated)?;
        let mut row = PacketNative5CoordinatorInstallation::decode_construction_storage_data(
            launch.initial_coordinator.bytes.as_slice(),
            maximum,
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        row[1] = storage::sum(&[row[1], storage::world_refusal_storage_data()])?;
        row[2] = storage::sum(&[row[2], storage::counter_scratch_data()])?;
        owner.quote(Stage::DecodingCoordinator, row, [0; 2], maximum)
    }

    /// Keeps the completed coordinator before the same Source world comparison.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn retain_native_import18_birth_coordinator_into_data(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        quote: &NativeImport18BirthConstructionQuote,
    ) -> Result<(), RuntimeError> {
        self.start_import18_birth_stage_data(
            launch,
            quote,
            Stage::Validated,
            Stage::DecodingCoordinator,
        )?;
        let coordinator = PacketNative5CoordinatorInstallation::decode(
            launch.initial_coordinator.bytes.as_slice(),
            &launch.selection,
        )
        .map_err(|_| RuntimeError::UnsupportedFacet)?;
        self.native_import18_birth_construction
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?
            .coordinator = Some(coordinator);
        let coordinator = self
            .native_import18_birth_construction
            .as_ref()
            .and_then(|owner| owner.coordinator.as_ref())
            .ok_or(RuntimeError::OwnerUnavailable)?;
        self.authenticate_collecting_world_scope(coordinator)
            .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.finish_import18_birth_stage_data(Stage::Coordinator)
    }

    /// Quotes actual Bytes formatting before inspecting the borrowed Source view.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn native_import18_birth_materialization_prewalk_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        maximum: usize,
    ) -> Result<[usize; 3], RuntimeError> {
        self.import18_birth_owner_data(launch, Stage::Coordinator)?;
        storage::bounded(
            [
                0,
                storage::source_formatter_storage_data(launch)?,
                storage::counter_scratch_data(),
            ],
            maximum,
        )
    }

    /// Quotes both actual typed views without a DOM or canonical allocation.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn native_import18_birth_materialize_quote_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        maximum: usize,
    ) -> Result<NativeImport18BirthConstructionQuote, RuntimeError> {
        let owner = self.import18_birth_owner_data(launch, Stage::Coordinator)?;
        let (source, registration) = owner.views(launch)?;
        let source = NodeRuntime::borrowed_serialization_geometry_data(&source, maximum)?;
        let registration =
            NodeRuntime::borrowed_serialization_geometry_data(&registration, maximum)?;
        // Each defining constructor term includes its own DOM plus subsequent
        // canonical/output work. Charging that complete real term on both axes
        // preserves partial materialization while the first DOM remains owned.
        let retained = storage::sum(&[source.0, registration.0])?;
        let formatter = storage::source_formatter_storage_data(launch)?;
        owner.quote(
            Stage::Materializing,
            [
                retained,
                storage::sum(&[retained, formatter])?,
                storage::counter_scratch_data(),
            ],
            [0; 2],
            maximum,
        )
    }

    /// Retains each completed Value before starting the following materialization.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn retain_native_import18_birth_materialize_into_data(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        quote: &NativeImport18BirthConstructionQuote,
    ) -> Result<(), RuntimeError> {
        self.start_import18_birth_stage_data(
            launch,
            quote,
            Stage::Coordinator,
            Stage::Materializing,
        )?;
        let owner = self
            .native_import18_birth_construction
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let (source, _) = owner.views(launch)?;
        owner.source_value =
            Some(serde_json::to_value(source).map_err(|_| RuntimeError::ResourceLimit)?);
        let (_, registration) = owner.views(launch)?;
        owner.registration_value =
            Some(serde_json::to_value(registration).map_err(|_| RuntimeError::ResourceLimit)?);
        // This is the same defining planned9/closed-Hello DATA comparison used
        // by the later authority join. It creates no authority or SDK witness.
        let declaration = native_import18_hello_declaration_data(launch)
            .map_err(|_| RuntimeError::UnsupportedFacet)?;
        native_import18_prospective_host_registration_data(
            launch,
            &declaration,
            owner
                .registration_value
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            usize::MAX,
        )
        .map_err(|_| RuntimeError::ForeignAuthority)?;
        self.finish_import18_birth_stage_data(Stage::Materialized)
    }

    /// Quotes exact requested canonical bank extents from the retained DOMs.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn native_import18_birth_encode_quote_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        maximum: usize,
    ) -> Result<NativeImport18BirthConstructionQuote, RuntimeError> {
        let owner = self.import18_birth_owner_data(launch, Stage::Materialized)?;
        let source = NodeRuntime::borrowed_serialization_geometry_data(
            owner
                .source_value
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            maximum,
        )?;
        let registration = NodeRuntime::borrowed_serialization_geometry_data(
            owner
                .registration_value
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            maximum,
        )?;
        owner.quote(
            Stage::Encoding,
            [
                storage::sum(&[source.1, registration.1])?,
                storage::sum(&[
                    source.0.max(registration.0),
                    storage::canonical_error_storage_data()?,
                ])?,
                storage::counter_scratch_data(),
            ],
            [source.1, registration.1],
            maximum,
        )
    }

    /// Reserves both banks in the owner and writes without hidden Vec growth.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn retain_native_import18_birth_encode_into_data(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        quote: &NativeImport18BirthConstructionQuote,
    ) -> Result<(), RuntimeError> {
        self.start_import18_birth_stage_data(launch, quote, Stage::Materialized, Stage::Encoding)?;
        let owner = self
            .native_import18_birth_construction
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        owner.source_bank = Some(Vec::new());
        owner.registration_bank = Some(Vec::new());
        for (bank, extent) in [
            (&mut owner.source_bank, quote.encoded[0]),
            (&mut owner.registration_bank, quote.encoded[1]),
        ] {
            let bank = bank.as_mut().ok_or(RuntimeError::OwnerUnavailable)?;
            bank.try_reserve_exact(extent)
                .map_err(|_| RuntimeError::ResourceLimit)?;
            if bank.capacity() > extent {
                return Err(RuntimeError::ResourceLimit);
            }
        }
        canonical::canonical_json_to_writer(
            owner
                .source_value
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            &mut ReservedWriter {
                bank: owner
                    .source_bank
                    .as_mut()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                maximum: quote.encoded[0],
            },
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        canonical::canonical_json_to_writer(
            owner
                .registration_value
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            &mut ReservedWriter {
                bank: owner
                    .registration_bank
                    .as_mut()
                    .ok_or(RuntimeError::OwnerUnavailable)?,
                maximum: quote.encoded[1],
            },
        )
        .map_err(|_| RuntimeError::ResourceLimit)?;
        self.finish_import18_birth_stage_data(Stage::Encoded)
    }

    /// Quotes the private clone/File/key component independently of startup rows.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn native_import18_birth_private_quote_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        maximum: usize,
    ) -> Result<NativeImport18BirthConstructionQuote, RuntimeError> {
        let owner = self.import18_birth_owner_data(launch, Stage::Encoded)?;
        let mut row = NativeImport18PrivateBirthAttempt::construction_storage_data(
            &launch.controller_executable,
            owner
                .private_launch
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            maximum,
        )?;
        row[2] = storage::sum(&[row[2], storage::counter_scratch_data()])?;
        owner.quote(Stage::CreatingBirth, row, [0; 2], maximum)
    }

    /// Moves the same canonical banks into the actual retained Birth destination.
    ///
    /// # Errors
    /// Refuses foreign or changed operands, the wrong/failed stage, missing
    /// custody, arithmetic overflow or work beyond the supplied restriction.
    pub fn retain_native_import18_birth_private_into_data(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        quote: &NativeImport18BirthConstructionQuote,
    ) -> Result<(), RuntimeError> {
        self.start_import18_birth_stage_data(launch, quote, Stage::Encoded, Stage::CreatingBirth)?;
        let owner = self
            .native_import18_birth_construction
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        OriginalAckPeerBirth::retain_import18_private_birth_into_data(
            &launch.controller_executable,
            owner
                .private_launch
                .as_ref()
                .ok_or(RuntimeError::OwnerUnavailable)?,
            &mut owner.source_bank,
            &mut owner.registration_bank,
            &mut owner.private_birth,
            self.ack_peer_birth.get_mut(),
        )?;
        self.finish_import18_birth_stage_data(Stage::Complete)
    }

    fn authenticate_import18_birth_source_data(
        &self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if !self.is_original_native_import18_declaration_data()? {
            return Err(RuntimeError::ForeignAuthority);
        }
        self.authenticate_native_launch_data(launch)?;
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                source.complete_preparation_unbound_with_error::<RuntimeError>()?
            }
            CompletePacketOriginal::Reactive(source) => {
                source.complete_preparation_unbound_with_error::<RuntimeError>()?
            }
        };
        if !unbound {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    fn import18_birth_identity_data(
        &self,
        launch: &PacketNative5SourceLaunch,
    ) -> Result<Identity, RuntimeError> {
        // The Source comparison binds the actual program, limits, optional
        // fields and installed provider/binding/owner tuples. Commit the other
        // realization fields and launch operands explicitly as well; a pointer
        // or a partial Source comparison never establishes full row currency.
        let mut hash = blake3::Hasher::new_derive_key("source-import18.prebirth-operands/1");
        for bytes in [
            launch.initial_coordinator.bytes.as_slice(),
            launch.admission_token.as_slice(),
            launch.effects.as_os_str().as_bytes(),
        ] {
            hash_bytes(&mut hash, bytes);
        }
        for reference in [
            &launch.controller_executable,
            &launch.initial_coordinator.reference,
        ] {
            for text in [
                &reference.hash.algorithm,
                &reference.hash.domain,
                &reference.hash.digest,
                &reference.media_type,
            ] {
                hash_bytes(&mut hash, text.as_bytes());
            }
            hash.update(&reference.length.get().to_be_bytes());
        }
        hash.update(&launch.schema_version.to_be_bytes());
        hash_bytes(
            &mut hash,
            launch.selection.prepared_token.as_str().as_bytes(),
        );
        let crucible_node_format::RealizationManifest {
            schema_version,
            realization_id,
            provider_manifest,
            owners,
            extensions,
            descriptors: _,
            bindings: _,
            owner_bindings: _,
        } = &launch.selection.realization;
        hash.update(&schema_version.to_be_bytes());
        hash_bytes(&mut hash, realization_id.as_str().as_bytes());
        for text in [
            &provider_manifest.hash.algorithm,
            &provider_manifest.hash.domain,
            &provider_manifest.hash.digest,
            &provider_manifest.media_type,
        ] {
            hash_bytes(&mut hash, text.as_bytes());
        }
        hash.update(&provider_manifest.length.get().to_be_bytes());
        hash.update(&(owners.len() as u64).to_be_bytes());
        for owner in owners {
            let crucible_node_format::OwnerRef {
                id,
                participant_ids,
                state_domain_ids,
            } = owner;
            hash_bytes(&mut hash, id.as_str().as_bytes());
            for ids in [participant_ids, state_domain_ids] {
                hash.update(&(ids.len() as u64).to_be_bytes());
                for id in ids {
                    hash_bytes(&mut hash, id.as_str().as_bytes());
                }
            }
        }
        hash.update(&(extensions.len() as u64).to_be_bytes());
        for (key, value) in extensions {
            hash_bytes(&mut hash, key.as_bytes());
            hash_value(&mut hash, value, 0)?;
        }
        Ok(Identity {
            source: self as *const Self as usize,
            process: std::process::id(),
            thread: std::thread::current().id(),
            launch_operands: *hash.finalize().as_bytes(),
        })
    }

    fn import18_birth_owner_data(
        &self,
        launch: &PacketNative5SourceLaunch,
        stage: Stage,
    ) -> Result<&NativeImport18BirthConstruction, RuntimeError> {
        self.authenticate_import18_birth_source_data(launch)?;
        let owner = self
            .native_import18_birth_construction
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if !self.ack_birth_attempted
            || !owner.inputs_started
            || owner.failed
            || owner.stage != stage
            || owner.identity != self.import18_birth_identity_data(launch)?
        {
            return Err(RuntimeError::OwnerUnavailable);
        }
        Ok(owner)
    }

    fn start_import18_birth_stage_data(
        &mut self,
        launch: &PacketNative5SourceLaunch,
        quote: &NativeImport18BirthConstructionQuote,
        before: Stage,
        during: Stage,
    ) -> Result<(), RuntimeError> {
        let owner = self
            .native_import18_birth_construction
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if owner.failed || owner.stage != before {
            return Err(RuntimeError::DuplicateOperation);
        }
        owner.failed = true;
        owner.stage = during;
        self.authenticate_import18_birth_source_data(launch)?;
        let owner = self
            .native_import18_birth_construction
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        if owner.identity != self.import18_birth_identity_data(launch)?
            || quote.identity != owner.identity
            || quote.stage != during
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }

    fn finish_import18_birth_stage_data(&mut self, stage: Stage) -> Result<(), RuntimeError> {
        let owner = self
            .native_import18_birth_construction
            .as_mut()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        owner.stage = stage;
        owner.failed = false;
        Ok(())
    }
}

impl NativeImport18BirthConstruction {
    /// Retains the same actual input banks even when a required peer is absent.
    fn retain_initial_operands_data(
        &mut self,
        private_launch: &mut Option<Id>,
        registration: &mut Option<PacketCompleteAckHostRegistrationPlan>,
    ) -> Result<(), RuntimeError> {
        if self.inputs_started || !self.failed || self.stage != Stage::Initialized {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.inputs_started = true;
        self.private_launch = private_launch.take();
        self.registration = registration.take();
        if self.private_launch.is_none() || self.registration.is_none() {
            return Err(RuntimeError::OwnerUnavailable);
        }
        self.failed = false;
        Ok(())
    }

    fn quote(
        &self,
        stage: Stage,
        row: [usize; 3],
        encoded: [usize; 2],
        maximum: usize,
    ) -> Result<NativeImport18BirthConstructionQuote, RuntimeError> {
        Ok(NativeImport18BirthConstructionQuote {
            identity: self.identity,
            stage,
            requested: storage::bounded(row, maximum)?,
            encoded,
        })
    }

    fn views<'a>(
        &'a self,
        launch: &'a PacketNative5SourceLaunch,
    ) -> Result<(views::SourceBirthView<'a>, views::RegistrationView<'a>), RuntimeError> {
        let coordinator = self
            .coordinator
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let registration = self
            .registration
            .as_ref()
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let [binding] = launch.selection.realization.bindings.as_slice() else {
            return Err(RuntimeError::ForeignAuthority);
        };
        Ok((
            views::SourceBirthView {
                launch,
                coordinator,
            },
            views::RegistrationView {
                schema: "source-owned.packet-canonical-ack-registration/5",
                role: "controller",
                connection_id: &registration.connection_id,
                session_id: &binding.authority.session_id,
                incarnation_id: &binding.authority.incarnation_id,
                limits: &launch.limits,
                features: &registration.features,
                extensions: &registration.extensions,
                envelope_extensions: &registration.envelope_extensions,
            },
        ))
    }
}

fn hash_bytes(hash: &mut blake3::Hasher, bytes: &[u8]) {
    hash.update(&(bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

// This walk commits literal Values without Serialize, canonicalization or a
// RawValue reset. The unchanged SourceBirth writer supports at most64 containers;
// a deeper extension cannot complete that writer and is refused before work.
fn hash_value(hash: &mut blake3::Hasher, value: &Value, depth: usize) -> Result<(), RuntimeError> {
    if depth > 64 {
        return Err(RuntimeError::ResourceLimit);
    }
    match value {
        Value::Null => {
            hash.update(&[0]);
        }
        Value::Bool(value) => {
            hash.update(&[1, u8::from(*value)]);
        }
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                hash.update(&[2]);
                hash.update(&value.to_be_bytes());
            } else if let Some(value) = value.as_u64() {
                hash.update(&[3]);
                hash.update(&value.to_be_bytes());
            } else {
                hash.update(&[4]);
                hash.update(
                    &value
                        .as_f64()
                        .ok_or(RuntimeError::InvalidReceipt)?
                        .to_bits()
                        .to_be_bytes(),
                );
            }
        }
        Value::String(value) => {
            hash.update(&[5]);
            hash_bytes(hash, value.as_bytes());
        }
        Value::Array(values) => {
            hash.update(&[6]);
            hash.update(&(values.len() as u64).to_be_bytes());
            for value in values {
                hash_value(hash, value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            hash.update(&[7]);
            hash.update(&(values.len() as u64).to_be_bytes());
            for (key, value) in values {
                hash_bytes(hash, key.as_bytes());
                hash_value(hash, value, depth + 1)?;
            }
        }
    }
    Ok(())
}

struct ReservedWriter<'a> {
    bank: &'a mut Vec<u8>,
    maximum: usize,
}

impl Write for ReservedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .bank
            .len()
            .checked_add(bytes.len())
            .filter(|end| *end <= self.maximum && *end <= self.bank.capacity())
            .ok_or(std::io::ErrorKind::WriteZero)?;
        self.bank.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[path = "import18_prebirth/tests.rs"]
mod tests;
