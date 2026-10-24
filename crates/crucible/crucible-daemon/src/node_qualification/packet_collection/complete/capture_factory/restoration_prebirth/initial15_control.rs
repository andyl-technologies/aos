//! Retains independently admitted Initial15 parser owners before native birth.
//!
//! The target authority is already real, while native tickets and the archive
//! remain unbound. Each short constructor loan ends before the outer whole-holder
//! observer. Completion here is immutable DATA, never a native birth permission.

use super::*;
use crucible_engine::node_contract::RuntimeError;
use crucible_engine::node_state::{
    CompleteInitial15PrebirthControlAttempt as Attempt,
    CompleteInitial15PrebirthControlConstructionData as Construction,
};
use crucible_node_transport::protocol_snapshot::restored_settled17::Initial15NativeImportGeometryConstructionData as GeometryConstruction;
use crucible_node_transport::protocol_snapshot::{
    Initial15MappingNormalizationConstructionData as Normalization, PreparedArchivedProtocolMapping,
};
use std::{cell::Cell, mem::size_of};

const NORMALIZATION_REFUSAL: &str = "Initial15 normalization geometry refused";

/// Identifies one separately admitted parser quote or constructor seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node_qualification::packet_collection::complete) enum Initial15ControlStep {
    QuoteJournal,
    ConstructJournal,
    QuoteNormalization,
    QuoteGeometry,
    ConstructGeometry,
    QuoteControl,
    ConstructControl,
}

impl Initial15ControlStep {
    const fn ordinal(self) -> usize {
        match self {
            Self::QuoteJournal => 0,
            Self::ConstructJournal => 1,
            Self::QuoteNormalization => 2,
            Self::QuoteGeometry => 3,
            Self::ConstructGeometry => 4,
            Self::QuoteControl => 5,
            Self::ConstructControl => 6,
        }
    }
}

struct Member {
    attempt: Attempt,
    journal: Option<Construction>,
    control: Option<Construction>,
    normalization: Option<Normalization>,
    geometry: Option<GeometryConstruction>,
    next: usize,
    failed: bool,
}

/// Retains the three independent original parser attempts and their failed rows.
pub(super) struct Initial15PrebirthControlMembers {
    members: [Member; 3],
}

impl Initial15PrebirthControlMembers {
    /// Initializes only inline empty parser holders, without reserving banks.
    pub(super) fn new() -> Self {
        Self {
            members: std::array::from_fn(|_| Member {
                attempt: Attempt::new(),
                journal: None,
                control: None,
                normalization: None,
                geometry: None,
                next: 0,
                failed: false,
            }),
        }
    }

    /// Counts all actual reserved slots and initialized parser children.
    ///
    /// # Errors
    /// Refuses foreign parser custody, arithmetic overflow or the actual bound.
    pub(super) fn retained_requested_storage_data(
        &self,
        maximum: usize,
    ) -> Result<usize, RuntimeError> {
        // The actual array/Option roots already belong to the retained capsule.
        // Every initialized parser child and reserved-but-empty slot stays here.
        self.members.iter().try_fold(0usize, |total, member| {
            total
                .checked_add(member.attempt.retained_requested_storage_data(maximum)?)
                .filter(|bytes| *bytes <= maximum)
                .ok_or(RuntimeError::ResourceLimit)
        })
    }

    fn construction_data(&self) -> Result<[usize; 3], RuntimeError> {
        let mut total = [0usize; 3];
        for member in &self.members {
            for row in [member.journal.as_ref(), member.control.as_ref()]
                .into_iter()
                .flatten()
            {
                for (sum, axis) in total.iter_mut().zip(row.requested_storage_data()) {
                    *sum = sum.checked_add(axis).ok_or(RuntimeError::ResourceLimit)?;
                }
            }
            if let Some(row) = &member.geometry {
                for (sum, axis) in total.iter_mut().zip(row.requested_axes_data()) {
                    *sum = sum.checked_add(axis).ok_or(RuntimeError::ResourceLimit)?;
                }
            }
            if let Some(row) = &member.normalization {
                for (sum, axis) in total.iter_mut().zip(row.requested_storage_data()) {
                    *sum = sum.checked_add(axis).ok_or(RuntimeError::ResourceLimit)?;
                }
            }
        }
        Ok(total)
    }
}

impl PacketCompleteRestorationPrebirth {
    /// Identifies the real original-family capsule before target binding.
    ///
    /// # Errors
    /// Refuses a foreign creator or incomplete actual signed17 source transfer.
    pub(in crate::node_qualification::packet_collection::complete) fn requires_initial15_control_prebirth_data(
        &self,
    ) -> Result<bool, RuntimeError> {
        self.construction_origin_data()?;
        match self.source17_ticket_completion {
            None => Ok(true),
            Some(false) => Err(RuntimeError::OutstandingObligations),
            Some(true) => Ok(false),
        }
    }

    /// Spends this one prebirth parser sequence without admitting any constructor.
    ///
    /// # Errors
    /// Refuses a repeated/failed sequence or a non-original capsule.
    pub(in crate::node_qualification::packet_collection::complete) fn begin_initial15_control_data(
        &self,
    ) -> Result<Initial15ControlLoan<'_>, RuntimeError> {
        if !self.requires_initial15_control_prebirth_data()?
            || self.initial15_control_started.replace(true)
            || self.initial15_control_failed.get()
        {
            return Err(RuntimeError::OutstandingObligations);
        }
        Ok(Initial15ControlLoan {
            failed: &self.initial15_control_failed,
            completed: false,
        })
    }

    /// Performs one admitted parser seam for the same target and archive ticket.
    ///
    /// The caller releases this capsule loan before its whole-owner observer.
    ///
    /// # Errors
    /// Refuses wrong phase, another target/member, a repeated or failed seam,
    /// mismatched constructor input, decoding or any actual retained bound.
    pub(in crate::node_qualification::packet_collection::complete) fn prepare_initial15_control_step_data(
        &self,
        authority: &InstalledPacketCompleteCollectionAuthority,
        plan: &InstalledConformancePlan,
        selected: usize,
        launch: &crucible_node_transport::reference_packet::service::PacketNative5SourceLaunch,
        step: Initial15ControlStep,
        maximum: usize,
    ) -> Result<(), RuntimeError> {
        self.authenticate_native_startup_target_precredit_data(authority, plan)?;
        if !self.initial15_control_started.get() || self.initial15_control_failed.get() {
            return Err(RuntimeError::OutstandingObligations);
        }
        if !self.requires_initial15_control_prebirth_data()? {
            return Err(RuntimeError::UnsupportedFacet);
        }
        let source = authority
            .roster()
            .sources
            .get(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        let ticket = self
            .native
            .get(selected)
            .and_then(Option::as_ref)
            .ok_or(RuntimeError::OwnerUnavailable)?;
        let input = ticket.initial15_prebirth_control_input_data()?;
        let installed = source.installation();
        if input.owner_data().owner != installed.owner.owner.id
            || input.owner_data().participants != installed.owner.owner.participant_ids
        {
            return Err(RuntimeError::ForeignAuthority);
        }
        let mut members = self
            .initial15_control
            .try_borrow_mut()
            .map_err(|_| RuntimeError::OwnerBusy)?;
        let prior = members.retained_requested_storage_data(maximum)?;
        let member = members
            .members
            .get_mut(selected)
            .ok_or(RuntimeError::ForeignAuthority)?;
        if member.failed || member.next != step.ordinal() {
            return Err(RuntimeError::OutstandingObligations);
        }
        // Spend the exact constructor seam before any reservation or decoder.
        // A refused quote also leaves this same occurrence failed.
        member.failed = true;
        let result = (|| {
            match step {
                Initial15ControlStep::QuoteJournal => {
                    member.journal =
                        Some(Attempt::journal_construction_data(&input, prior, maximum)?);
                }
                Initial15ControlStep::ConstructJournal => {
                    let row = member
                        .journal
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?;
                    member.attempt.retain_journal_into(&input, row)?;
                }
                Initial15ControlStep::QuoteNormalization => {
                    let (controller, native) =
                        member.attempt.normalization_references_data(&input)?;
                    // Both roots come from the retained original Journal. The
                    // target Source lends its own planned registration under its
                    // private unstarted birth loan, and fences both outcomes.
                    let row = source
                        .with_original_initial15_prebirth_normalization_registration_data(
                            move |registration| {
                                PreparedArchivedProtocolMapping::initial15_normalization_construction_data(
                                    controller, native, registration, maximum,
                                )
                                .map_err(|_| crucible_engine::node_contract::OperationFailure {
                                    effects: crucible_engine::node_contract::EffectKnowledge::None,
                                    reason: NORMALIZATION_REFUSAL.into(),
                                })
                            },
                        )
                        .map_err(|_| RuntimeError::ResourceLimit)?;
                    member.normalization = Some(row);
                }
                Initial15ControlStep::QuoteGeometry => {
                    let normalization = member
                        .normalization
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?;
                    member.geometry = Some(member.attempt.geometry_construction_data(
                        &input,
                        normalization.normalization_maximum_bytes_data(),
                        maximum,
                    )?);
                }
                Initial15ControlStep::ConstructGeometry => {
                    let row = member
                        .geometry
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?;
                    member.attempt.retain_geometry_into(&input, row)?;
                }
                Initial15ControlStep::QuoteControl => {
                    member.control = Some(
                        member
                            .attempt
                            .control_construction_data(&input, launch, prior, maximum)?,
                    );
                }
                Initial15ControlStep::ConstructControl => {
                    let row = member
                        .control
                        .as_ref()
                        .ok_or(RuntimeError::OwnerUnavailable)?;
                    member.attempt.retain_control_into(&input, launch, row)?;
                }
            }
            input.authenticate_origin_data()?;
            Ok(())
        })();
        // Release the mutable parser bank before any outer callback/observer.
        // Origin is fenced on both constructor outcomes, and failed slots stay.
        let origin = self.authenticate_native_startup_target_precredit_data(authority, plan);
        result?;
        origin?;
        member.next = member
            .next
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        member.failed = false;
        Ok(())
    }

    /// Returns cumulative independently retained parser commitments as DATA.
    ///
    /// # Errors
    /// Refuses foreign custody, a busy bank or checked arithmetic overflow.
    pub(in crate::node_qualification::packet_collection::complete) fn initial15_control_construction_data(
        &self,
    ) -> Result<[usize; 3], RuntimeError> {
        self.construction_origin_data()?;
        self.initial15_control
            .try_borrow()
            .map_err(|_| RuntimeError::OwnerBusy)?
            .construction_data()
    }

    /// Declares the callback's own no-effect failure message before its loan.
    pub(in crate::node_qualification::packet_collection::complete) const fn initial15_control_normalization_failure_transient_data()
    -> usize {
        NORMALIZATION_REFUSAL.len()
    }

    /// Names the actual parser, row, bank and target-loan observer controls.
    pub(in crate::node_qualification::packet_collection::complete) fn initial15_control_counter_scratch_data()
    -> usize {
        Attempt::counter_scratch_data()
            // The move callback captures exactly two borrowed roots and the
            // independent maximum; its failure owns a separate reason String.
            + size_of::<(&crucible_node_format::ContentRef, &crucible_node_format::ContentRef, usize)>()
            + size_of::<String>()
            + size_of::<crucible_engine::node_contract::OperationFailure>()
            + PreparedArchivedProtocolMapping::initial15_normalization_counter_scratch_data()
            + crucible_engine::node_adapters::cnp::PacketCompleteSemanticSource::original_initial15_prebirth_normalization_registration_counter_scratch_data::<Normalization>()
            + size_of::<GeometryConstruction>()
            + size_of::<Option<GeometryConstruction>>()
            + size_of::<Normalization>()
            + size_of::<Option<Normalization>>()
            + size_of::<Result<Normalization, crucible_node_transport::ProviderError>>()
            + size_of::<Result<Normalization, crucible_engine::node_contract::OperationFailure>>()
            + size_of::<Initial15PrebirthControlMembers>()
            + size_of::<Member>()
            + size_of::<std::cell::Ref<'static, Initial15PrebirthControlMembers>>()
            + size_of::<std::cell::RefMut<'static, Initial15PrebirthControlMembers>>()
            + size_of::<std::slice::Iter<'static, Member>>()
            + size_of::<std::slice::IterMut<'static, usize>>()
            + size_of::<std::iter::Flatten<std::array::IntoIter<Option<&'static Construction>, 2>>>(
            )
            + size_of::<
                std::iter::Zip<std::slice::IterMut<'static, usize>, std::array::IntoIter<usize, 3>>,
            >()
            + size_of::<[Option<&Construction>; 2]>()
            + size_of::<[usize; 3]>()
            + size_of::<Initial15ControlStep>()
            + size_of::<Initial15ControlLoan<'static>>()
            + size_of::<Result<Initial15ControlLoan<'static>, RuntimeError>>()
            + size_of::<&Self>()
            + size_of::<&InstalledPacketCompleteCollectionAuthority>()
            + size_of::<&InstalledConformancePlan>()
            + size_of::<Result<(), RuntimeError>>()
            + size_of::<Result<bool, RuntimeError>>()
            + size_of::<Result<[usize; 3], RuntimeError>>()
            + size_of::<std::thread::Thread>()
    }
}

/// Poisons actual prebirth custody on any refused census, constructor or unwind.
pub(in crate::node_qualification::packet_collection::complete) struct Initial15ControlLoan<'a> {
    failed: &'a Cell<bool>,
    completed: bool,
}

impl Initial15ControlLoan<'_> {
    /// Records only completion of this parser sequence, without native rights.
    pub(in crate::node_qualification::packet_collection::complete) fn finish(mut self) {
        self.completed = true;
    }
}

impl Drop for Initial15ControlLoan<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.failed.set(true);
        }
    }
}
