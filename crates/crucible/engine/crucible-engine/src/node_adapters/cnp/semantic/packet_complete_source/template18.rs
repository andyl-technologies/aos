//! Funds and retains a distinct neverborn Source from actual code declarations.
//!
//! The code Source stays retained independently. Only validated immutable
//! installation/model/coordinator DATA are cloned; all live, once, input,
//! transfer, registry and native state starts empty in the fresh Source. No
//! launch or admission authority follows from equal declarations. Selected
//! templates additionally retain the same preexisting sealed deployment owner;
//! their complete census and all worker/job/native routes remain unresolved.

use super::*;
use crate::node_adapters::cnp::source_birth_derivation::installation::VerifiedSourceBirthMechanism;

#[path = "template18/mechanism.rs"]
mod mechanism;
pub use mechanism::OriginalNativeSourceTemplate18MechanismQuote;

pub(super) const MECHANISM_GATE_CONTROLS: usize = mechanism::GATE_CONTROLS;
use crate::node_contract::RuntimeError;
use crucible_node_transport::reference_packet::PacketProgramDefinition;
use std::{
    mem::{size_of, size_of_val},
    rc::Rc,
};

/// Prices one immutable code declaration copy and its distinct fresh holders.
#[derive(Clone, Copy)]
pub struct OriginalNativeSourceTemplate18ConstructionData {
    template: *const PacketCompleteSemanticSource,
    mechanism: Option<*const VerifiedSourceBirthMechanism>,
    process: u32,
    thread: std::thread::ThreadId,
    retained: usize,
    transient: usize,
    scratch: usize,
}

impl OriginalNativeSourceTemplate18ConstructionData {
    /// Returns independent retained, temporary constructor and fixed controls.
    pub const fn requested_storage_data(&self) -> (usize, usize, usize) {
        (self.retained, self.transient, self.scratch)
    }
}

/// Retains the actual fresh Source and sticky once state across refusal.
///
/// Independently funded pure declaration-clone temporaries may drop. Once the
/// new Source is assembled, it is retained before lineage reserve or any later
/// fallible launch binding. No allocator failure can renew this attempt.
#[derive(Default)]
pub struct OriginalNativeSourceTemplate18Attempt {
    started: bool,
    failed: bool,
    transferred: bool,
    output: Option<Rc<PacketCompleteSemanticSource>>,
}

impl OriginalNativeSourceTemplate18Attempt {
    /// Counts the actual retained output across success or failed construction.
    ///
    /// The attempt header is owned by the enclosing capsule and counted there;
    /// after transfer the actual roster owns/counts that same Source instead.
    /// Cold outputs and same-Source failed/initialized workers remain pre-Child;
    /// actual Birth, native or association custody requires its later observer.
    ///
    /// # Errors
    /// Refuses foreign, borrowed or unsupported output custody, selected
    /// isolated deployment custody until its complete owner join, layout overflow,
    /// or actual retained output exceeding `maximum`.
    pub fn retained_requested_storage_data(&self, maximum: usize) -> Result<usize, RuntimeError> {
        let Some(source) = self.output.as_ref() else {
            return Ok(0);
        };
        if !self.started || self.transferred {
            return Err(RuntimeError::OutstandingObligations);
        }
        source.original_template18_construction_retained_storage_data(maximum)
    }

    /// Names this attempt's actual pre-Child output observer before its walk.
    ///
    /// The enclosing capsule owns the attempt header. Nested component visitors
    /// retain their defining counters; the purpose/lineage controls are distinct.
    pub fn retained_counter_scratch_data() -> usize {
        PacketCompleteSemanticSource::original_template18_storage_counter_scratch_data()
            .saturating_add(size_of::<&Self>())
            .saturating_add(size_of::<&Option<Rc<PacketCompleteSemanticSource>>>())
            .saturating_add(size_of::<Option<&Rc<PacketCompleteSemanticSource>>>())
            .saturating_add(size_of::<&Rc<PacketCompleteSemanticSource>>())
            .saturating_add(size_of::<Result<usize, RuntimeError>>())
            .saturating_add(size_of::<usize>())
            .saturating_add(size_of::<bool>())
    }

    /// Borrows only a completed fresh Source; construction grants no readiness.
    ///
    /// # Errors
    /// Refuses unused or failed construction, including retained partial output.
    pub fn completed_data(&self) -> Result<&Rc<PacketCompleteSemanticSource>, RuntimeError> {
        if !self.started || self.failed {
            return Err(RuntimeError::OutstandingObligations);
        }
        self.output
            .as_ref()
            .ok_or(RuntimeError::OutstandingObligations)
    }

    /// Moves completed custody once into the actual owning target roster.
    ///
    /// # Errors
    /// Refuses an incomplete, failed or already transferred output.
    pub fn take_completed_data(
        &mut self,
    ) -> Result<Rc<PacketCompleteSemanticSource>, RuntimeError> {
        self.completed_data()?;
        if self.transferred {
            return Err(RuntimeError::DuplicateOperation);
        }
        self.transferred = true;
        self.output
            .take()
            .ok_or(RuntimeError::OutstandingObligations)
    }

    /// Borrows the unique completed output before its actual roster publication.
    ///
    /// # Errors
    /// Refuses incomplete, failed, transferred or already shared custody.
    pub fn completed_unique_data(
        &mut self,
    ) -> Result<&mut PacketCompleteSemanticSource, RuntimeError> {
        self.completed_data()?;
        Rc::get_mut(
            self.output
                .as_mut()
                .ok_or(RuntimeError::OutstandingObligations)?,
        )
        .ok_or(RuntimeError::OutstandingObligations)
    }

    /// Borrows any retained Source, including partial allocation after refusal.
    pub fn partial_data(&self) -> Option<&Rc<PacketCompleteSemanticSource>> {
        self.output.as_ref()
    }
}

impl PacketCompleteSemanticSource {
    fn authenticate_template18_data(&self) -> Result<(), RuntimeError> {
        self.storage_origin_with_error::<RuntimeError>()?;
        if self.native_import18_derivation_mechanism.is_some()
            || self.native_import18_phase_bank_attempted.get()
            || self.native_import18_bank_attempted.get()
            || self.ack_birth_attempted
            || self.native_import18_birth_construction.is_some()
            || self.complete_bytes_launch_reserved.get()
            || self.registry_retention_attempted.get()
            || self.registry_retention_failed.get()
            || self
                .ack_peer_birth
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?
                .is_some()
            || self
                .ack_peer_association
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?
                .is_some()
            || self
                .preconstruction
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?
                .is_some()
            || self
                .capture_execution
                .try_borrow()
                .map_err(|_| RuntimeError::OutstandingObligations)?
                .is_some()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        let unbound = match &self.original {
            CompletePacketOriginal::Producer(source) => {
                source.complete_preparation_unbound_with_error::<RuntimeError>()?
            }
            CompletePacketOriginal::Reactive(source) => {
                source.complete_preparation_unbound_with_error::<RuntimeError>()?
            }
        };
        if !unbound {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(())
    }

    /// Quotes a fresh immutable declaration copy before any cloning or reserve.
    ///
    /// The installed caller first admits the fixed prewalk counter, and adds all
    /// actual code/cold/prepared/Host owners to this independent row. The row
    /// prices this copy only, never the native decoder or a Host constructor.
    ///
    /// # Errors
    /// Refuses foreign, born or busy templates, incomplete declarations, layout
    /// overflow, or the complete requested row beyond `maximum`.
    pub fn native_source_template18_construction_data(
        self: &Rc<Self>,
        maximum: usize,
    ) -> Result<OriginalNativeSourceTemplate18ConstructionData, RuntimeError> {
        self.authenticate_template18_data()?;
        let declarations =
            self.original_complete_installation_storage_data_with_error::<RuntimeError>(maximum)?;
        let (installation_clone_transient, installation_clone_scratch) = self
            .installation()
            .complete_template_clone_construction_data(maximum)?;
        let (underlying, lineage, constructor, returned) = match &self.original {
            CompletePacketOriginal::Producer(source) => (
                size_of_val(source.as_ref()),
                0,
                PacketSemanticSource::complete_template_constructor_transient_data(),
                size_of::<Result<PacketSemanticSource, RuntimeError>>(),
            ),
            CompletePacketOriginal::Reactive(source) => (
                size_of_val(source.as_ref()),
                source.complete_template_lineage_bytes_data()?,
                PacketConnectedSemanticSource::complete_template_constructor_transient_data(),
                size_of::<Result<PacketConnectedSemanticSource, RuntimeError>>(),
            ),
        };
        let retained = sum(
            [
                declarations,
                NodeRuntime::capture_shared_allocation_storage::<Self>(),
                underlying,
                lineage,
            ],
            maximum,
        )?;
        // These are actual defining return/owning-argument sites: immutable
        // installation clone, underlying fresh initializer return and Box input,
        // outer empty initializer return and Rc input. Clone-partial heaps are
        // a separate temporary window, bounded by the full declaration roster.
        let transient = sum(
            [
                declarations,
                constructor,
                size_of::<CnpSemanticInstallation>(),
                installation_clone_transient,
                returned,
                underlying,
                size_of::<Self>(),
                size_of::<Self>(),
                size_of::<ack_peer::Import18RecipeOwner>(),
                // Option::clone first returns the inner Clone-only profile,
                // then constructs its separate outer Option return.
                size_of::<PacketNative5CaptureProfile>(),
                size_of::<Option<PacketNative5CaptureProfile>>(),
            ],
            maximum,
        )?;
        let scratch = sum(
            [
                Self::native_source_template18_counter_scratch_data(),
                installation_clone_scratch,
            ],
            maximum,
        )?;
        sum([retained, transient, scratch], maximum)?;
        self.authenticate_template18_data()?;
        Ok(OriginalNativeSourceTemplate18ConstructionData {
            template: Rc::as_ptr(self),
            mechanism: None,
            process: self.process,
            thread: self.thread,
            retained,
            transient,
            scratch,
        })
    }

    /// Constructs into a retained sticky attempt under its genuine admitted row.
    ///
    /// The caller separately proves this template belongs to its actual code
    /// authority/plan and includes the complete attempt in every observation.
    /// Output is installed before lineage reservation. Later launch/policy/Birth
    /// steps must mutate that same fresh Source, never replace it on failure.
    ///
    /// # Errors
    /// Refuses reused attempts, another template/creator, changed row, borrowed
    /// native state, or lineage allocation beyond its original demand.
    pub fn native_source_template18_into(
        self: &Rc<Self>,
        row: &OriginalNativeSourceTemplate18ConstructionData,
        output: &mut OriginalNativeSourceTemplate18Attempt,
    ) -> Result<(), RuntimeError> {
        self.native_source_template18_inner_into(row, None, output)
    }

    fn native_source_template18_inner_into(
        self: &Rc<Self>,
        row: &OriginalNativeSourceTemplate18ConstructionData,
        mechanism: Option<&Rc<VerifiedSourceBirthMechanism>>,
        output: &mut OriginalNativeSourceTemplate18Attempt,
    ) -> Result<(), RuntimeError> {
        if output.started || output.output.is_some() {
            return Err(RuntimeError::DuplicateOperation);
        }
        output.started = true;
        output.failed = true;
        self.authenticate_template18_data()?;
        if row.template != Rc::as_ptr(self)
            || row.process != self.process
            || row.thread != self.thread
            || row.mechanism != mechanism.map(Rc::as_ptr)
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        if let Some(mechanism) = mechanism {
            mechanism.authenticate_current()?;
        }
        // Retain the same installed owner before constructing any fresh Source.
        // Its original supervisor and executable guards remain live on refusal.
        let retained_mechanism = mechanism.cloned();
        let installation = self.installation().cloned_complete_template_data();
        let original = match &self.original {
            CompletePacketOriginal::Producer(source) => CompletePacketOriginal::Producer(Box::new(
                source.cloned_complete_template_data(installation)?,
            )),
            CompletePacketOriginal::Reactive(source) => CompletePacketOriginal::Reactive(Box::new(
                source.cloned_complete_template_data(installation)?,
            )),
        };
        let mut fresh = Self::empty_template18_data(original);
        // Rc::clone allocates no mechanism payload. Retain the same sealed
        // deployment owner before output publication or lineage effects.
        fresh.native_import18_derivation_mechanism = retained_mechanism;
        output.output = Some(Rc::new(fresh));
        let fresh = Rc::get_mut(
            output
                .output
                .as_mut()
                .ok_or(RuntimeError::OutstandingObligations)?,
        )
        .ok_or(RuntimeError::OutstandingObligations)?;
        fresh.copy_template18_launch_choices_data(self)?;
        if let CompletePacketOriginal::Reactive(source) = &mut fresh.original {
            source.reserve_complete_template_lineage_data()?;
        }
        let lineage = match &mut fresh.original {
            CompletePacketOriginal::Producer(_) => 0,
            CompletePacketOriginal::Reactive(source) => {
                source.complete_template_retained_lineage_bytes_data()?
            }
        };
        let underlying = match &fresh.original {
            CompletePacketOriginal::Producer(source) => size_of_val(source.as_ref()),
            CompletePacketOriginal::Reactive(source) => size_of_val(source.as_ref()),
        };
        let declarations = fresh
            .original_complete_installation_storage_data_with_error::<RuntimeError>(row.retained)?;
        sum(
            [
                declarations,
                NodeRuntime::capture_shared_allocation_storage::<Self>(),
                underlying,
                lineage,
            ],
            row.retained,
        )?;
        self.authenticate_template18_data()?;
        output.failed = false;
        Ok(())
    }

    /// Names the actual borrowed clone-quote and fresh constructor controls.
    ///
    /// The defining Provider counter names the exact immutable field/container
    /// views used by RetainedCompleteSourceMetadata. The caller independently
    /// prices its outer factory/prepared/cold/Host traversal and callback state.
    pub fn native_source_template18_counter_scratch_data() -> usize {
        use crucible_node_transport::retained_metadata::{
            RetainedCompleteSourceDefinition, RetainedCompleteSourceMetadata,
            RetainedProtocolMetadataFacts,
        };
        use std::cell::{BorrowError, Ref};
        use std::thread::{Thread, ThreadId};
        let controls = [
            size_of::<&Self>(),
            size_of::<&mut Self>(),
            size_of::<(&mut CompletePacketOriginal, &CompletePacketOriginal)>(),
            size_of::<&mut Box<PacketSemanticSource>>(),
            size_of::<&Box<PacketSemanticSource>>(),
            size_of::<&mut Box<PacketConnectedSemanticSource>>(),
            size_of::<&Box<PacketConnectedSemanticSource>>(),
            size_of::<&Option<PacketNative5CaptureProfile>>(),
            size_of::<&Option<Box<ack_peer::NativeImport18BirthConstruction>>>(),
            size_of::<&PacketNative5CaptureProfile>(),
            size_of::<&Rc<Self>>(),
            size_of::<Rc<Self>>(),
            size_of::<&mut OriginalNativeSourceTemplate18Attempt>(),
            size_of::<OriginalNativeSourceTemplate18ConstructionData>(),
            size_of::<Result<OriginalNativeSourceTemplate18ConstructionData, RuntimeError>>(),
            size_of::<Result<&Rc<Self>, RuntimeError>>(),
            size_of::<Result<Rc<Self>, RuntimeError>>(),
            size_of::<Result<&mut Self, RuntimeError>>(),
            size_of::<Option<&mut Self>>(),
            size_of::<Option<Rc<Self>>>(),
            size_of::<RetainedCompleteSourceMetadata<'static>>(),
            size_of::<RetainedCompleteSourceDefinition<'static>>(),
            size_of::<RetainedProtocolMetadataFacts>(),
            size_of::<Result<RetainedProtocolMetadataFacts, crucible_node_transport::ProviderError>>(
            ),
            size_of::<(
                &PacketProgramDefinition,
                &PacketNative5CoordinatorInstallation,
                &SavedRuntimeActivation,
            )>(),
            size_of::<(
                &PacketConnectedDefinition,
                &PacketNative5CoordinatorInstallation,
                &SavedRuntimeActivation,
            )>(),
            size_of::<
                Result<
                    (
                        &PacketProgramDefinition,
                        &PacketNative5CoordinatorInstallation,
                        &SavedRuntimeActivation,
                    ),
                    RuntimeError,
                >,
            >(),
            size_of::<
                Result<
                    (
                        &PacketConnectedDefinition,
                        &PacketNative5CoordinatorInstallation,
                        &SavedRuntimeActivation,
                    ),
                    RuntimeError,
                >,
            >(),
            size_of::<std::slice::Iter<'static, FacetKind>>(),
            size_of::<std::slice::Iter<'static, OwnerIdentity>>(),
            size_of::<Ref<'static, Option<ack_peer::OriginalAckPeerBirth>>>(),
            size_of::<Result<Ref<'static, Option<ack_peer::OriginalAckPeerBirth>>, BorrowError>>(),
            size_of::<Result<Ref<'static, Option<ack_peer::OriginalAckPeerBirth>>, RuntimeError>>(),
            size_of::<Ref<'static, Option<ack_peer::OriginalAckPeerAssociation>>>(),
            size_of::<
                Result<Ref<'static, Option<ack_peer::OriginalAckPeerAssociation>>, BorrowError>,
            >(),
            size_of::<
                Result<Ref<'static, Option<ack_peer::OriginalAckPeerAssociation>>, RuntimeError>,
            >(),
            size_of::<Ref<'static, Option<preconstruction::OriginalCompletePreconstruction>>>(),
            size_of::<
                Result<
                    Ref<'static, Option<preconstruction::OriginalCompletePreconstruction>>,
                    BorrowError,
                >,
            >(),
            size_of::<
                Result<
                    Ref<'static, Option<preconstruction::OriginalCompletePreconstruction>>,
                    RuntimeError,
                >,
            >(),
            size_of::<Ref<'static, Option<execution::OriginalCompleteCaptureExecution>>>(),
            size_of::<
                Result<
                    Ref<'static, Option<execution::OriginalCompleteCaptureExecution>>,
                    BorrowError,
                >,
            >(),
            size_of::<
                Result<
                    Ref<'static, Option<execution::OriginalCompleteCaptureExecution>>,
                    RuntimeError,
                >,
            >(),
            size_of::<
                Ref<
                    'static,
                    Option<crate::node_adapters::cnp::semantic::process::CnpSemanticSourceRead>,
                >,
            >(),
            size_of::<
                Result<
                    Ref<
                        'static,
                        Option<crate::node_adapters::cnp::semantic::process::CnpSemanticSourceRead>,
                    >,
                    BorrowError,
                >,
            >(),
            size_of::<
                Result<
                    Ref<
                        'static,
                        Option<crate::node_adapters::cnp::semantic::process::CnpSemanticSourceRead>,
                    >,
                    RuntimeError,
                >,
            >(),
            size_of::<[usize; 11]>(),
            size_of::<std::array::IntoIter<usize, 11>>(),
            size_of::<[usize; 4]>(),
            size_of::<std::array::IntoIter<usize, 4>>(),
            size_of::<[usize; 3]>(),
            size_of::<std::array::IntoIter<usize, 3>>(),
            size_of::<[usize; 2]>(),
            size_of::<std::array::IntoIter<usize, 2>>(),
            size_of::<(usize, usize)>(),
            size_of::<Result<(usize, usize), RuntimeError>>(),
            // Actual tree-layout validation and its scalar argument/local set:
            // containers, entries, key/value bytes, alignment, maximum,
            // selected alignment, padding, node bytes and result bytes.
            size_of::<std::alloc::Layout>(),
            size_of::<Result<std::alloc::Layout, std::alloc::LayoutError>>(),
            size_of::<[usize; 9]>(),
            // Shared-header calculation has three inputs and three locals.
            size_of::<[usize; 6]>(),
            size_of::<Result<usize, RuntimeError>>(),
            size_of::<Result<(), RuntimeError>>(),
            size_of::<Result<bool, RuntimeError>>(),
            size_of::<Result<(), std::collections::TryReserveError>>(),
            size_of::<(usize, usize, usize)>(),
            size_of::<Thread>(),
            size_of::<ThreadId>(),
            size_of::<u32>(),
            size_of::<bool>(),
        ];
        // The terms array and its consumed iterator are separate actual controls.
        let own = controls.iter().copied().fold(0usize, usize::saturating_add);
        own.saturating_add(mechanism::BRIDGE_CONTROLS)
            .saturating_add(size_of_val(&controls))
            .saturating_add(size_of_val(&controls.into_iter()))
            .saturating_add(
                crucible_node_transport::retained_metadata::original_metadata_observer_layout_bytes(
                ),
            )
            .saturating_add(RetainedCompleteSourceMetadata::counter_scratch_data())
            .saturating_add(CnpSemanticInstallation::complete_template_clone_counter_scratch_data())
            .saturating_add(OriginalNativeSourceTemplate18Attempt::retained_counter_scratch_data())
    }

    fn copy_template18_launch_choices_data(&mut self, code: &Self) -> Result<(), RuntimeError> {
        // These privately validated declarations are DATA choices, not a copy
        // of the code Source's invocation purpose, once/history or native owner.
        // The genuine installer checks the complete same Launch5 before banks
        // or private Birth. Modeled archived histories stay in actual restored
        // owners; this fresh physical template neither replaces nor resets them.
        match (&mut self.original, &code.original) {
            (
                CompletePacketOriginal::Producer(fresh),
                CompletePacketOriginal::Producer(original),
            ) => {
                fresh.complete_capture_profile = original.complete_capture_profile.clone();
                fresh.complete_confirmation_selection = original.complete_confirmation_selection;
                fresh.complete_capture_allocation_selection =
                    original.complete_capture_allocation_selection;
            }
            (
                CompletePacketOriginal::Reactive(fresh),
                CompletePacketOriginal::Reactive(original),
            ) => {
                fresh.complete_capture_profile = original.complete_capture_profile.clone();
                fresh.complete_confirmation_selection = original.complete_confirmation_selection;
                fresh.complete_capture_allocation_selection =
                    original.complete_capture_allocation_selection;
            }
            _ => return Err(RuntimeError::ForeignAuthority),
        }
        self.ack_emitter_selection = code.ack_emitter_selection;
        self.ack_codec_metadata_extent = code.ack_codec_metadata_extent;
        self.native_ack_codec_metadata_extent = code.native_ack_codec_metadata_extent;
        self.protocol_metadata_limits = code.protocol_metadata_limits;
        self.capture_allocation_selection = code.capture_allocation_selection;
        self.fresh_restore_allocation_selection = code.fresh_restore_allocation_selection;
        self.complete_restore_selection = code.complete_restore_selection;
        self.restore_input_emitter_selection = code.restore_input_emitter_selection;
        Ok(())
    }

    fn empty_template18_data(original: CompletePacketOriginal) -> Self {
        Self {
            original,
            process: std::process::id(),
            thread: std::thread::current().id(),
            capture_banks: std::cell::RefCell::new(None),
            capture_execution: std::cell::RefCell::new(None),
            preconstruction: std::cell::RefCell::new(None),
            effect_receiver: None,
            ack_emitter_selection: None,
            ack_peer_birth: std::cell::RefCell::new(None),
            ack_birth_attempted: false,
            native_import18_birth_construction: None,
            native_import18_derivation: None,
            native_import18_derivation_mechanism: None,
            ack_peer_association: std::cell::RefCell::new(None),
            restored_suffix_attempted: std::cell::Cell::new(false),
            ack_codec_metadata_extent: None,
            native_ack_codec_metadata_extent: None,
            ack_birth_input_banks: None,
            protocol_metadata_limits: None,
            capture_allocation_selection: None,
            fresh_restore_allocation_selection: None,
            original_extension_registry: std::cell::RefCell::new(None),
            registry_capture: std::cell::RefCell::new(None),
            registry_retention_attempted: std::cell::Cell::new(false),
            registry_retention_failed: std::cell::Cell::new(false),
            complete_bytes_launch_reserved: std::cell::Cell::new(false),
            native_import18_declaration: None,
            native_import18_phase_bank_attempted: std::cell::Cell::new(false),
            native_import18_phase_bank: std::cell::RefCell::new(None),
            native_import18_bank_attempted: std::cell::Cell::new(false),
            native_import18_bank_reservation: std::cell::RefCell::new(None),
            native_import18_recipe: std::cell::RefCell::new(ack_peer::Import18RecipeOwner::empty()),
            invocation_snapshot_declaration: None,
            original_coordinator_policy17: None,
            original_coordinator_policy18: None,
            complete_restore_selection: None,
            restore_input_emitter_selection: None,
        }
    }
}

fn sum<const N: usize>(terms: [usize; N], maximum: usize) -> Result<usize, RuntimeError> {
    terms.into_iter().try_fold(0usize, |total, bytes| {
        total
            .checked_add(bytes)
            .filter(|total| *total <= maximum)
            .ok_or(RuntimeError::ResourceLimit)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_adapters::cnp::semantic::packet_complete_source::tests as fixture;

    fn code_source(reactive: bool) -> Rc<PacketCompleteSemanticSource> {
        let coordinator = fixture::coordinator();
        Rc::new(if reactive {
            PacketCompleteSemanticSource::new_reactive_for_collecting_world(
                fixture::installation(&coordinator, 1),
                fixture::reactive(&coordinator, 1),
                coordinator,
                fixture::storage_selection(),
            )
            .unwrap()
        } else {
            PacketCompleteSemanticSource::new_producer_for_collecting_world(
                fixture::installation(&coordinator, 0),
                fixture::producer(),
                coordinator,
                fixture::storage_selection(),
            )
            .unwrap()
        })
    }

    #[test]
    fn genuine_templates_quote_the_complete_copy_and_start_distinct_empty_sources() {
        for reactive in [false, true] {
            let mut code = code_source(reactive);
            let original = Rc::get_mut(&mut code).unwrap();
            original
                .bind_original_capture_profile(PacketNative5CaptureProfile::OriginalArrays6)
                .unwrap();
            original.bind_original_confirmation_selection(None).unwrap();
            let quoted = code
                .native_source_template18_construction_data(usize::MAX)
                .unwrap();
            let (retained, transient, scratch) = quoted.requested_storage_data();
            let total = retained
                .checked_add(transient)
                .unwrap()
                .checked_add(scratch)
                .unwrap();
            assert!(retained > 0 && transient > 0 && scratch > 0);
            assert_eq!(
                code.native_source_template18_construction_data(total)
                    .unwrap()
                    .requested_storage_data(),
                quoted.requested_storage_data()
            );
            assert!(
                code.native_source_template18_construction_data(total - 1)
                    .is_err()
            );

            let mut attempt = OriginalNativeSourceTemplate18Attempt::default();
            code.native_source_template18_into(&quoted, &mut attempt)
                .unwrap();
            let fresh = attempt.completed_data().unwrap();
            assert!(!Rc::ptr_eq(&code, fresh));
            assert!(fresh.authenticate_template18_data().is_ok());
            assert_eq!(fresh.installation().provider, code.installation().provider);
            assert_eq!(
                fresh.selected_storage_selection().unwrap(),
                code.selected_storage_selection().unwrap()
            );
            assert_eq!(fresh.ack_emitter_selection, code.ack_emitter_selection);
            assert_eq!(
                fresh.ack_codec_metadata_extent,
                code.ack_codec_metadata_extent
            );
            assert_eq!(
                fresh.protocol_metadata_limits,
                code.protocol_metadata_limits
            );
            assert_eq!(
                fresh.complete_restore_selection,
                code.complete_restore_selection
            );
            assert_eq!(
                fresh.fresh_restore_allocation_selection,
                code.fresh_restore_allocation_selection
            );
            match &fresh.original {
                CompletePacketOriginal::Producer(source) => {
                    assert_eq!(
                        source.complete_capture_profile,
                        Some(PacketNative5CaptureProfile::OriginalArrays6)
                    );
                    assert_eq!(source.complete_confirmation_selection, Some(None));
                }
                CompletePacketOriginal::Reactive(source) => {
                    assert_eq!(
                        source.complete_capture_profile,
                        Some(PacketNative5CaptureProfile::OriginalArrays6)
                    );
                    assert_eq!(source.complete_confirmation_selection, Some(None));
                }
            }
            assert!(!fresh.native_import18_phase_bank_attempted.get());
            assert!(fresh.native_import18_phase_bank.borrow().is_none());
            assert!(!fresh.native_import18_bank_attempted.get());
            assert!(fresh.native_import18_bank_reservation.borrow().is_none());
            assert!(fresh.native_import18_declaration.is_none());
            assert!(fresh.native_import18_birth_construction.is_none());
            assert!(fresh.native_import18_derivation_mechanism.is_none());
            assert!(fresh.original_coordinator_policy18.is_none());
            assert!(fresh.capture_banks.borrow().is_none());
            assert!(fresh.ack_peer_birth.borrow().is_none());
            assert!(fresh.ack_peer_association.borrow().is_none());
            assert!(fresh.authenticate_current_native().is_err());
            assert!(code.authenticate_current_native().is_err());
            let actual = attempt.retained_requested_storage_data(usize::MAX).unwrap();
            assert!(actual > 0 && actual <= retained);
            assert_eq!(attempt.retained_requested_storage_data(actual), Ok(actual));
            assert_eq!(
                attempt.retained_requested_storage_data(actual - 1),
                Err(RuntimeError::ResourceLimit)
            );
            // The new observer selects an actual construction purpose; it never
            // repairs the generic live observer's missing native-read owners.
            assert!(
                fresh
                    .original_complete_retained_storage_precredit_data(usize::MAX)
                    .is_err()
            );
            assert_eq!(
                fresh.original_complete_code_retained_storage_precredit_data(usize::MAX),
                Ok(actual)
            );

            let retained_source = attempt.take_completed_data().unwrap();
            assert!(attempt.completed_data().is_err());
            assert!(attempt.take_completed_data().is_err());
            assert!(
                code.native_source_template18_into(&quoted, &mut attempt)
                    .is_err()
            );
            assert!(retained_source.authenticate_template18_data().is_ok());
            assert_eq!(attempt.retained_requested_storage_data(0), Ok(0));
            assert_eq!(
                retained_source.original_complete_code_retained_storage_precredit_data(actual),
                Ok(actual)
            );
        }
    }

    #[test]
    fn real_post_output_refusal_keeps_partial_source_and_once_state_observable() {
        for reactive in [false, true] {
            let code = code_source(reactive);
            let mut row = code
                .native_source_template18_construction_data(usize::MAX)
                .unwrap();
            // Restrict the actual final retained-sum check. This deliberately
            // refused private DATA row cannot authorize a successful copy.
            row.retained = 0;
            let mut attempt = OriginalNativeSourceTemplate18Attempt::default();
            assert_eq!(
                code.native_source_template18_into(&row, &mut attempt),
                Err(RuntimeError::ResourceLimit)
            );
            assert!(attempt.started && attempt.failed);
            let address = Rc::as_ptr(attempt.partial_data().unwrap());
            let actual = attempt.retained_requested_storage_data(usize::MAX).unwrap();
            assert!(actual > 0);
            assert_eq!(attempt.retained_requested_storage_data(actual), Ok(actual));
            assert_eq!(
                attempt.retained_requested_storage_data(actual - 1),
                Err(RuntimeError::ResourceLimit)
            );
            assert!(attempt.completed_data().is_err());
            assert!(attempt.take_completed_data().is_err());
            assert!(
                code.native_source_template18_into(&row, &mut attempt)
                    .is_err()
            );
            assert_eq!(Rc::as_ptr(attempt.partial_data().unwrap()), address);
            assert_eq!(attempt.retained_requested_storage_data(actual), Ok(actual));
        }
    }

    #[test]
    fn attempt_census_refuses_busy_spent_and_later_launch_custody_without_fallback() {
        for reactive in [false, true] {
            let code = code_source(reactive);
            let row = code
                .native_source_template18_construction_data(usize::MAX)
                .unwrap();
            let mut attempt = OriginalNativeSourceTemplate18Attempt::default();
            code.native_source_template18_into(&row, &mut attempt)
                .unwrap();
            let actual = attempt.retained_requested_storage_data(usize::MAX).unwrap();
            let fresh = attempt.completed_data().unwrap();
            {
                let _loan = fresh.preconstruction.borrow_mut();
                assert!(attempt.retained_requested_storage_data(usize::MAX).is_err());
            }
            {
                let _loan = fresh.ack_peer_birth.borrow_mut();
                assert!(attempt.retained_requested_storage_data(usize::MAX).is_err());
            }
            {
                let _loan = fresh.ack_peer_association.borrow_mut();
                assert!(attempt.retained_requested_storage_data(usize::MAX).is_err());
            }
            assert_eq!(attempt.retained_requested_storage_data(actual), Ok(actual));
            attempt.completed_unique_data().unwrap().ack_birth_attempted = true;
            assert_eq!(
                attempt.retained_requested_storage_data(usize::MAX),
                Err(RuntimeError::OutstandingObligations)
            );
            assert!(
                attempt
                    .completed_data()
                    .unwrap()
                    .original_complete_code_retained_storage_precredit_data(usize::MAX)
                    .is_err()
            );
            // A spent flag is sticky; refusal never installs a substitute worker.
            assert!(attempt.completed_data().unwrap().ack_birth_attempted);
            assert!(
                attempt
                    .completed_data()
                    .unwrap()
                    .native_import18_birth_construction
                    .is_none()
            );
        }

        let code = code_source(false);
        let row = code
            .native_source_template18_construction_data(usize::MAX)
            .unwrap();
        let mut attempt = OriginalNativeSourceTemplate18Attempt::default();
        code.native_source_template18_into(&row, &mut attempt)
            .unwrap();
        attempt
            .completed_data()
            .unwrap()
            .complete_bytes_launch_reserved
            .set(true);
        assert!(attempt.retained_requested_storage_data(usize::MAX).is_err());
        assert!(
            attempt
                .completed_data()
                .unwrap()
                .complete_bytes_launch_reserved
                .get()
        );
        assert!(
            attempt
                .completed_data()
                .unwrap()
                .original_complete_retained_storage_precredit_data(usize::MAX)
                .is_err()
        );
    }

    #[test]
    fn another_real_code_owner_cannot_reuse_a_row_or_renew_its_failed_attempt() {
        let code = code_source(false);
        let foreign = code_source(false);
        let quoted = code
            .native_source_template18_construction_data(usize::MAX)
            .unwrap();
        let mut attempt = OriginalNativeSourceTemplate18Attempt::default();

        assert!(
            foreign
                .native_source_template18_into(&quoted, &mut attempt)
                .is_err()
        );
        assert!(attempt.started && attempt.failed);
        assert!(attempt.partial_data().is_none());
        assert!(
            code.native_source_template18_into(&quoted, &mut attempt)
                .is_err()
        );
        assert!(attempt.completed_data().is_err());
        assert!(code.authenticate_template18_data().is_ok());
        assert!(foreign.authenticate_template18_data().is_ok());
    }

    #[test]
    fn either_entered_bank_fence_refuses_the_actual_template_constructor() {
        for phase_bank in [false, true] {
            let code = code_source(false);
            let row = code
                .native_source_template18_construction_data(usize::MAX)
                .unwrap();
            if phase_bank {
                code.native_import18_phase_bank_attempted.set(true);
            } else {
                code.native_import18_bank_attempted.set(true);
            }
            let mut attempt = OriginalNativeSourceTemplate18Attempt::default();

            assert!(
                code.native_source_template18_into(&row, &mut attempt)
                    .is_err()
            );

            assert!(attempt.started && attempt.failed);
            assert!(attempt.partial_data().is_none());
            assert!(attempt.completed_data().is_err());
            assert!(
                code.native_source_template18_into(&row, &mut attempt)
                    .is_err()
            );
            assert!(
                code.native_source_template18_construction_data(usize::MAX)
                    .is_err()
            );
            assert!(code.native_import18_phase_bank.borrow().is_none());
            assert!(code.native_import18_bank_reservation.borrow().is_none());
        }
    }

    #[test]
    fn genuine_installation_clone_quote_preserves_all_extension_variants_and_outputs() {
        let coordinator = fixture::coordinator();
        let mut installation = fixture::installation(&coordinator, 0);
        installation
            .provider
            .extensions
            .insert("clone-null".into(), serde_json::Value::Null);
        installation
            .provider
            .extensions
            .insert("clone-bool".into(), serde_json::json!(true));
        installation
            .provider
            .extensions
            .insert("clone-number".into(), serde_json::json!(-3.5));
        installation
            .provider
            .extensions
            .insert("clone-string".into(), serde_json::json!("utf8-λ"));
        installation.provider.extensions.insert(
            "clone-array".into(),
            serde_json::json!([null, false, 7, "child"]),
        );
        installation.provider.extensions.insert(
            "clone-object".into(),
            serde_json::json!({"nested":{"array":[0,true,"owned"]}}),
        );
        for index in 0..64 {
            installation.provider.extensions.insert(
                format!("clone-key-{index:03}"),
                serde_json::json!({"index":index}),
            );
        }
        installation.binding.authority.activation_id = Some(installation.admission.clone());
        let original_id = installation.provider.provider_id.as_str().as_ptr();
        let original_entries = installation.provider.extensions.len();
        let (transient, scratch) = installation
            .complete_template_clone_construction_data(usize::MAX)
            .unwrap();
        let peak = transient.checked_add(scratch).unwrap();

        assert_eq!(
            installation
                .complete_template_clone_construction_data(peak)
                .unwrap(),
            (transient, scratch)
        );
        assert_eq!(
            installation.complete_template_clone_construction_data(peak - 1),
            Err(RuntimeError::ResourceLimit)
        );
        let cloned = installation.cloned_complete_template_data();

        assert_eq!(cloned.provider, installation.provider);
        assert_eq!(cloned.profile, installation.profile);
        assert_eq!(cloned.descriptor, installation.descriptor);
        assert_eq!(cloned.binding, installation.binding);
        assert_eq!(cloned.capabilities, installation.capabilities);
        assert_eq!(cloned.exact_facet, installation.exact_facet);
        assert_eq!(cloned.guarantees, installation.guarantees);
        assert_eq!(cloned.owner, installation.owner);
        assert_eq!(cloned.realize, installation.realize);
        assert_eq!(cloned.admission, installation.admission);
        assert_eq!(cloned.transaction, installation.transaction);
        assert_eq!(cloned.gate, installation.gate);
        assert_eq!(cloned.admission_receipt, installation.admission_receipt);
        assert_eq!(cloned.world_binding_hash, installation.world_binding_hash);
        assert_eq!(cloned.facets, installation.facets);
        assert_eq!(cloned.receipt_schema, installation.receipt_schema);
        assert_eq!(
            installation.provider.provider_id.as_str().as_ptr(),
            original_id
        );
        assert_ne!(cloned.provider.provider_id.as_str().as_ptr(), original_id);
        assert_eq!(installation.provider.extensions.len(), original_entries);
        assert_eq!(cloned.maximum_operations, installation.maximum_operations);
        assert_eq!(
            cloned.maximum_result_bytes,
            installation.maximum_result_bytes
        );
        assert_eq!(
            cloned.maximum_authorization_bytes,
            installation.maximum_authorization_bytes
        );
        assert_eq!(
            cloned.maximum_semantic_bytes,
            installation.maximum_semantic_bytes
        );
        assert!(transient > size_of::<CnpSemanticInstallation>());
    }

    #[test]
    fn actual_json_depth64_fits_the_prequoted_fixed_dfs_control_array() {
        use crucible_node_transport::retained_metadata::{
            RetainedCompleteSourceDefinition, RetainedCompleteSourceMetadata,
        };
        let coordinator = fixture::coordinator();
        let definition = fixture::producer();
        let mut installation = fixture::installation(&coordinator, 0);
        let mut value = serde_json::Value::Null;
        for _ in 1..64 {
            value = serde_json::Value::Array(vec![value]);
        }
        installation
            .provider
            .extensions
            .insert("deep-clone".into(), value);
        let original_metadata = RetainedCompleteSourceMetadata {
            provider: &installation.provider,
            manifest: &installation.profile,
            descriptor: &installation.descriptor,
            binding: &installation.binding,
            capabilities: &installation.capabilities,
            facet: &installation.exact_facet,
            guarantees: &installation.guarantees,
            owner: &installation.owner,
            realize: &installation.realize,
            admission: &installation.admission,
            transaction: &installation.transaction,
            gate: &installation.gate,
            admission_receipt: &installation.admission_receipt,
            world: &installation.world_binding_hash,
            receipt_schema: &installation.receipt_schema,
            operating_contract: &installation.binding.compatibility.operating_contract,
            coordinator: &coordinator,
            definition: RetainedCompleteSourceDefinition::Program(&definition),
        };

        // The genuine original observer accepts the same depth that this quote
        // must support; no new accepted-shape refusal is used to close Clone.
        assert!(original_metadata.observe_retained_metadata().is_ok());
        assert!(
            installation
                .complete_template_clone_construction_data(usize::MAX)
                .is_ok()
        );
        let cloned = installation.cloned_complete_template_data();

        assert_eq!(cloned.provider.extensions, installation.provider.extensions);
    }

    #[test]
    fn closed_copy_vectors_and_real_noncopy_vectors_use_their_actual_clone_routes() {
        let one = vec![FacetKind::Preservation];
        let many = vec![FacetKind::Preservation; 64];
        let one_copy = NodeRuntime::capture_installation_sequence_clone_storage_data::<FacetKind>(
            one.len(),
            true,
            usize::MAX,
        )
        .unwrap();
        let many_copy = NodeRuntime::capture_installation_sequence_clone_storage_data::<FacetKind>(
            many.len(),
            true,
            usize::MAX,
        )
        .unwrap();
        let originals = vec![String::from("cloned UTF8 λ"); 64];
        let one_owned = NodeRuntime::capture_installation_sequence_clone_storage_data::<String>(
            1,
            false,
            usize::MAX,
        )
        .unwrap();
        let many_owned = NodeRuntime::capture_installation_sequence_clone_storage_data::<String>(
            originals.len(),
            false,
            usize::MAX,
        )
        .unwrap();

        assert_eq!(one_copy.0, many_copy.0);
        assert_eq!(
            many_owned.0 - one_owned.0,
            63 * (size_of::<String>() // outer write owned argument
                + size_of::<String>() // MaybeUninit::new owned argument
                + size_of::<String>() // ManuallyDrop::new owned argument
                + size_of::<String>() // MaybeDangling::new owned argument
                + size_of::<String>() // transparent MaybeDangling return
                + size_of::<std::mem::ManuallyDrop<String>>()
                + size_of::<std::mem::MaybeUninit<String>>())
        );
        assert_eq!(one.clone(), one);
        assert_eq!(many.clone(), many);
        let cloned = originals.clone();
        assert_eq!(cloned, originals);
        assert_ne!(cloned[0].as_ptr(), originals[0].as_ptr());
        let peak = many_owned.0 + many_owned.1;
        assert_eq!(
            NodeRuntime::capture_installation_sequence_clone_storage_data::<String>(
                64, false, peak
            )
            .unwrap(),
            many_owned
        );
        assert_eq!(
            NodeRuntime::capture_installation_sequence_clone_storage_data::<String>(
                64,
                false,
                peak - 1
            ),
            Err(RuntimeError::ResourceLimit)
        );
    }
}
