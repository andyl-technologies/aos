//! Owns complete-source effects beneath sealed wrapper-five and original native journals.
//!
//! The source roster, finite program and grant schedule are installed before
//! Child. Only concrete original source scopes enroll native bodies; portable
//! reports cannot supply a journal or replace an independently owned receiver.

mod construction;
mod initial_construction;
mod retained;
pub(crate) use construction::PacketCompleteConstructionStorageData;

use std::{cell::RefCell, rc::Rc};

use crucible::node_adapters::cnp::{
    CnpSemanticRealizationScope, CnpSemanticSource, PacketCompleteNativeRecord,
    PacketCompleteSourceRole,
};
use crucible_node_contract::{ContentRef, Id, canonical};
use crucible_node_provider::reference_packet::{
    connected::{PacketCommitRecord, PacketConnectedNativeRecord, PacketStageRecord},
    control::PacketNativeRecord,
    coordinator::PacketNative5CoordinatorInstallation,
    service::PacketConnectedSourceProgram,
};

use super::super::connected::PacketConnectedSchedule;
use super::{PacketCompleteRoster, QualificationError, refused};
use crate::node_qualification::{
    CaseVerdict, ExactCompletionCase, InstalledRuntimeWitnessOracle, OriginalCompletionWitness,
    PlannedWitnessCase, WitnessPlan,
};

mod effects;
mod execution;
mod expected;
mod original;

const MAXIMUM_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_SEALS: usize = 256;
const MAXIMUM_EFFECTS: usize = 96;
const MAXIMUM_SNAPSHOT: u64 = 8 * 1024 * 1024;

/// Transfers three original independent receivers and their complete source scene.
pub struct PacketCompleteOracleRequest<'a> {
    /// Retains the same concrete producer, relay and sink objects.
    pub roster: PacketCompleteRoster,
    /// Borrows the complete native-three/host-one original world installation.
    pub coordinator: &'a PacketNative5CoordinatorInstallation,
    /// Owns each bounded source program in original participant order.
    pub programmes: [PacketConnectedSourceProgram; 3],
    /// Retains the exact source-bound inspection group without duplicating FDs.
    pub receiver_group: Rc<crucible::node_adapters::cnp::PacketCompleteEffectReceiverGroup>,
    /// Owns the sole consuming role for that same original group.
    pub receiver_reader: crucible::node_adapters::cnp::PacketCompleteEffectReceiverReader,
    /// Names each original native launch endpoint in participant order.
    pub effect_paths: [std::path::PathBuf; 3],
    /// Owns all predeclared operations and distinct causal cases.
    pub schedule: PacketConnectedSchedule,
    /// Borrows the complete mandatory and supplemental witness population.
    pub plan: &'a WitnessPlan,
    /// Bounds full native bodies, typed copies and datagrams before Child.
    pub maximum_bytes: usize,
}

/// Borrows no replacement reader: this selected request retains its same owner.
///
/// The caller funds and retains these actual inputs before installation. This
/// request grants no native, readiness, execution or resource admission rights.
pub(crate) struct PacketCompleteSharedOracleRequest<'a> {
    pub(crate) roster: PacketCompleteRoster,
    pub(crate) coordinator: &'a PacketNative5CoordinatorInstallation,
    pub(crate) programmes: [PacketConnectedSourceProgram; 3],
    pub(crate) receiver_group: Rc<crucible::node_adapters::cnp::PacketCompleteEffectReceiverGroup>,
    pub(crate) receiver_reader:
        Rc<crucible::node_adapters::cnp::PacketCompleteEffectReceiverReader>,
    pub(crate) effect_paths: [std::path::PathBuf; 3],
    pub(crate) schedule: PacketConnectedSchedule,
    pub(crate) plan: &'a WitnessPlan,
    pub(crate) maximum_bytes: usize,
}

enum ReaderOwner {
    Original(crucible::node_adapters::cnp::PacketCompleteEffectReceiverReader),
    Shared(Rc<crucible::node_adapters::cnp::PacketCompleteEffectReceiverReader>),
}

impl ReaderOwner {
    fn reader(&self) -> &crucible::node_adapters::cnp::PacketCompleteEffectReceiverReader {
        match self {
            Self::Original(reader) => reader,
            Self::Shared(reader) => reader.as_ref(),
        }
    }

    fn into_shared(self) -> Rc<crucible::node_adapters::cnp::PacketCompleteEffectReceiverReader> {
        match self {
            Self::Original(reader) => Rc::new(reader),
            Self::Shared(reader) => reader,
        }
    }
}

struct OracleInstallationRequest<'a> {
    roster: PacketCompleteRoster,
    coordinator: &'a PacketNative5CoordinatorInstallation,
    programmes: [PacketConnectedSourceProgram; 3],
    receiver_group: Rc<crucible::node_adapters::cnp::PacketCompleteEffectReceiverGroup>,
    receiver_reader: ReaderOwner,
    effect_paths: [std::path::PathBuf; 3],
    schedule: PacketConnectedSchedule,
    plan: &'a WitnessPlan,
    maximum_bytes: usize,
}

enum NativeBody {
    Producer(PacketNativeRecord),
    Reactive(PacketConnectedNativeRecord),
    Stage(PacketStageRecord),
    Commit(PacketCommitRecord),
}

struct Seal {
    member: usize,
    reference: ContentRef,
    bytes: Vec<u8>,
    body: NativeBody,
    native: Option<(ContentRef, Vec<u8>)>,
}

struct Observed {
    seals: Vec<Seal>,
    effects: [Vec<effects::Effect>; 3],
    bytes: usize,
    failed: bool,
}

/// Retains genuine source journals and independent datagrams before report reads.
///
/// The collector supplies no ordinary graph, Ready, capture or accepted class.
/// Original completion authority remains a separate runtime-owned witness.
pub struct PacketCompleteNativeOracle {
    roster: PacketCompleteRoster,
    programmes: [PacketConnectedSourceProgram; 3],
    receiver_group: Rc<crucible::node_adapters::cnp::PacketCompleteEffectReceiverGroup>,
    receiver_reader: Rc<crucible::node_adapters::cnp::PacketCompleteEffectReceiverReader>,
    effect_paths: [std::path::PathBuf; 3],
    schedule: PacketConnectedSchedule,
    plan: WitnessPlan,
    maximum_bytes: usize,
    observed: RefCell<Observed>,
    originals: original::OriginalBindings,
}

impl PacketCompleteNativeOracle {
    /// Checks that all original effect receivers have no queued datagram.
    ///
    /// The read is nonconsuming, including for zero-length datagrams. A caller
    /// must separately prove stopped native frontiers and complete retirement;
    /// queue emptiness alone grants no capture or fresh-resource authority.
    ///
    /// # Errors
    /// Refuses stale source custody, failed observation, queued bytes or an
    /// unavailable original receiver. Both source guards surround the check.
    pub fn authenticate_empty_effect_queues(&self) -> Result<(), QualificationError> {
        self.roster.current_native().map_err(native_failure)?;
        self.preflight()?;
        self.receiver_reader
            .authenticate_original_group(&self.receiver_group)
            .map_err(native_failure)?;
        for member in 0..3 {
            self.roster.sources[member]
                .authenticate_original_effect_receiver_binding(
                    &self.receiver_group,
                    member,
                    &self.effect_paths[member],
                )
                .map_err(native_failure)?;
        }
        let result = self
            .receiver_group
            .authenticate_empty()
            .map_err(native_failure);
        self.roster.current_native().map_err(native_failure)?;
        result
    }

    /// Reserves complete finite native, datagram and original-report custody.
    ///
    /// # Errors
    /// Refuses a foreign roster/program/plan, unsupported finite population,
    /// nonunique case or grant, unusable receiver or unavailable prospective credit.
    pub fn install(
        request: PacketCompleteOracleRequest<'_>,
    ) -> Result<Rc<Self>, QualificationError> {
        Self::install_selected(OracleInstallationRequest {
            roster: request.roster,
            coordinator: request.coordinator,
            programmes: request.programmes,
            receiver_group: request.receiver_group,
            receiver_reader: ReaderOwner::Original(request.receiver_reader),
            effect_paths: request.effect_paths,
            schedule: request.schedule,
            plan: request.plan,
            maximum_bytes: request.maximum_bytes,
        })
    }

    /// Installs the selected Oracle with the caller's same retained reader Rc.
    ///
    /// All original validations and finite reservations precede construction.
    /// No descriptor or consuming token is duplicated.
    ///
    /// # Errors
    /// Preserves the original install refusals for changed data or unavailable
    /// finite capacity. This method does not reserve caller resource authority.
    pub(crate) fn install_original_shared(
        request: PacketCompleteSharedOracleRequest<'_>,
    ) -> Result<Rc<Self>, QualificationError> {
        Self::install_selected(OracleInstallationRequest {
            roster: request.roster,
            coordinator: request.coordinator,
            programmes: request.programmes,
            receiver_group: request.receiver_group,
            receiver_reader: ReaderOwner::Shared(request.receiver_reader),
            effect_paths: request.effect_paths,
            schedule: request.schedule,
            plan: request.plan,
            maximum_bytes: request.maximum_bytes,
        })
    }

    fn install_selected(
        request: OracleInstallationRequest<'_>,
    ) -> Result<Rc<Self>, QualificationError> {
        request.roster.current_scope()?;
        request
            .receiver_reader
            .reader()
            .authenticate_original_group(&request.receiver_group)
            .map_err(native_failure)?;

        request.schedule.validate()?;
        if request.maximum_bytes == 0
            || request.maximum_bytes > MAXIMUM_BYTES
            || request.coordinator != &request.roster.coordinator
        {
            return Err(refused());
        }
        super::super::scope::encoded_size(
            &(&request.schedule, request.plan, &request.programmes),
            request.maximum_bytes,
        )?;
        for member in 0..3 {
            let selected = request.roster.sources[member].installation();
            let value = match &request.programmes[member] {
                PacketConnectedSourceProgram::Producer { program }
                    if request.roster.sources[member].role()
                        == PacketCompleteSourceRole::Producer
                        && program.events.len() == 2
                        && program.events[0].payload.is_none()
                        && program.events[1]
                            .payload
                            .as_ref()
                            .is_some_and(|value| value.as_slice().len() <= 32) =>
                {
                    serde_json::to_value(program)
                }
                PacketConnectedSourceProgram::Reactive { program }
                    if request.roster.sources[member].role()
                        == PacketCompleteSourceRole::Reactive =>
                {
                    serde_json::to_value(program)
                }
                _ => return Err(refused()),
            }
            .map_err(crucible_node_contract::ContractError::from)?;
            let bytes = canonical::canonical_json(&value)?;
            selected.descriptor.model_ref.verify(&bytes)?;
            if request.schedule.nodes[member] != selected.descriptor.id {
                return Err(refused());
            }
            request.roster.sources[member]
                .authenticate_original_effect_receiver_binding(
                    &request.receiver_group,
                    member,
                    &request.effect_paths[member],
                )
                .map_err(native_failure)?;
        }
        let mut seals = Vec::new();
        seals
            .try_reserve_exact(MAXIMUM_SEALS)
            .map_err(|_| refused())?;
        let mut effects = [Vec::new(), Vec::new(), Vec::new()];
        for member in &mut effects {
            member
                .try_reserve_exact(MAXIMUM_EFFECTS)
                .map_err(|_| refused())?;
        }
        let originals = original::OriginalBindings::reserve(request.schedule.cases.len())?;
        Ok(Rc::new(Self {
            roster: request.roster,
            programmes: request.programmes,
            receiver_group: request.receiver_group,
            receiver_reader: request.receiver_reader.into_shared(),
            effect_paths: request.effect_paths,
            schedule: request.schedule,
            plan: request.plan.clone(),
            maximum_bytes: request.maximum_bytes,
            observed: RefCell::new(Observed {
                seals,
                effects,
                bytes: 0,
                failed: false,
            }),
            originals,
        }))
    }

    /// Rechecks the exact original installation without minting native permission.
    ///
    /// # Errors
    /// Refuses replacement source objects, changed full scene or altered plan.
    pub fn authenticate_installation(
        &self,
        roster: &PacketCompleteRoster,
        coordinator: &PacketNative5CoordinatorInstallation,
        schedule: &PacketConnectedSchedule,
        plan: &WitnessPlan,
    ) -> Result<(), QualificationError> {
        if !self.roster.same_original(roster)
            || coordinator != &self.roster.coordinator
            || schedule != &self.schedule
            || plan != &self.plan
        {
            return Err(refused());
        }
        self.roster.current_scope()
    }

    /// Reserves the next complete source receipt and independent effect population.
    ///
    /// # Errors
    /// Refuses sticky observation failure or insufficient future receipt/body credit.
    pub fn preflight(&self) -> Result<(), QualificationError> {
        let observed = self.observed.try_borrow().map_err(|_| refused())?;
        if observed.failed
            || observed.seals.len() > MAXIMUM_SEALS - 6
            || observed
                .bytes
                .checked_add(6 * 2 * 65_536)
                .is_none_or(|bytes| bytes > self.maximum_bytes)
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Enrolls only source-authenticated original bodies and actual datagrams.
    ///
    /// # Errors
    /// Refuses foreign original process scope, changed journals, malformed/extra
    /// effects, full-byte credit exhaustion or a previously uncertain observation.
    pub fn observe(
        &self,
        member: usize,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), QualificationError> {
        self.observe_data(member, scope, false)
    }

    // Only the same issued inactive OriginalScene constructor selects this path.
    // Unsupported datagrams remain in the original descriptor; no effect parser
    // is invoked against an unfunded, unexpected constructor input.
    pub(super) fn observe_original_construction(
        &self,
        member: usize,
        scope: CnpSemanticRealizationScope<'_>,
    ) -> Result<(), QualificationError> {
        self.observe_data(member, scope, true)
    }

    fn observe_data(
        &self,
        member: usize,
        scope: CnpSemanticRealizationScope<'_>,
        initial: bool,
    ) -> Result<(), QualificationError> {
        self.preflight()?;
        let source = self.roster.sources.get(member).ok_or_else(refused)?;
        if !std::ptr::eq(scope.installation, source.installation()) {
            return Err(refused());
        }
        let result = (|| {
            let mut observed = self.observed.try_borrow_mut().map_err(|_| refused())?;
            if initial {
                initial_construction::authenticate_initial_journal_data(
                    &self.programmes,
                    &observed,
                )?;
                initial_construction::authenticate_initial_queues_data(
                    &self.receiver_group,
                    &self.receiver_reader,
                    &mut observed,
                )?;
            }
            let witness = source
                .latest_original_native_witness(&scope)
                .map_err(native_failure)?;
            if initial {
                initial_construction::authenticate_initial_record_data(
                    &self.programmes[member],
                    witness.native_record(),
                )?;
            }
            match witness.native_record() {
                PacketCompleteNativeRecord::Producer(record) => {
                    self.enroll(
                        &mut observed,
                        member,
                        witness.reference(),
                        witness.bytes(),
                        Some((witness.native_reference(), witness.native_bytes())),
                        || NativeBody::Producer(record.clone()),
                    )?;
                }
                PacketCompleteNativeRecord::Reactive(record) => {
                    for root in record
                        .inventory
                        .stages
                        .iter()
                        .chain(&record.inventory.commits)
                    {
                        let input = source
                            .original_input_witness(&scope, root)
                            .map_err(native_failure)?;
                        if let Some(stage) = input.stage() {
                            self.enroll(
                                &mut observed,
                                member,
                                input.reference(),
                                input.bytes(),
                                None,
                                || NativeBody::Stage(stage.clone()),
                            )?;
                        } else if let Some(commit) = input.commit() {
                            self.enroll(
                                &mut observed,
                                member,
                                input.reference(),
                                input.bytes(),
                                None,
                                || NativeBody::Commit(commit.clone()),
                            )?;
                        } else {
                            return Err(refused());
                        }
                    }
                    self.enroll(
                        &mut observed,
                        member,
                        witness.reference(),
                        witness.bytes(),
                        Some((witness.native_reference(), witness.native_bytes())),
                        || NativeBody::Reactive(record.clone()),
                    )?;
                }
            }
            if initial {
                initial_construction::authenticate_initial_queues_data(
                    &self.receiver_group,
                    &self.receiver_reader,
                    &mut observed,
                )?;
                initial_construction::authenticate_initial_journal_data(
                    &self.programmes,
                    &observed,
                )?;
            } else {
                effects::drain(self, member, &mut observed)?;
            }
            effects::verify_prefix(self, member, &observed)?;
            source.authenticate_current_native().map_err(native_failure)
        })();
        if result.is_err()
            && let Ok(mut observed) = self.observed.try_borrow_mut()
        {
            observed.failed = true;
        }
        result
    }

    fn enroll(
        &self,
        observed: &mut Observed,
        member: usize,
        reference: &ContentRef,
        bytes: &[u8],
        native: Option<(&ContentRef, &[u8])>,
        body: impl FnOnce() -> NativeBody,
    ) -> Result<(), QualificationError> {
        Self::enroll_data(
            self.maximum_bytes,
            observed,
            member,
            reference,
            bytes,
            native,
            body,
        )
    }

    fn enroll_data(
        maximum_bytes: usize,
        observed: &mut Observed,
        member: usize,
        reference: &ContentRef,
        bytes: &[u8],
        native: Option<(&ContentRef, &[u8])>,
        body: impl FnOnce() -> NativeBody,
    ) -> Result<(), QualificationError> {
        if let Some(old) = observed
            .seals
            .iter()
            .find(|old| old.member == member && old.reference == *reference)
        {
            if old.bytes != bytes
                || old
                    .native
                    .as_ref()
                    .map(|(reference, bytes)| (reference, bytes.as_slice()))
                    != native
            {
                return Err(refused());
            }
            return Ok(());
        }
        reference.verify(bytes)?;
        let native_bytes = if let Some((reference, bytes)) = native {
            reference.verify(bytes)?;
            bytes.len()
        } else {
            0
        };
        let credit = bytes
            .len()
            .checked_add(native_bytes)
            .and_then(|bytes| bytes.checked_mul(3))
            .and_then(|bytes| observed.bytes.checked_add(bytes))
            .filter(|bytes| *bytes <= maximum_bytes)
            .ok_or_else(refused)?;
        if observed.seals.len() == MAXIMUM_SEALS {
            return Err(refused());
        }
        // Native schema validators bound the expanded copy. Charge three complete
        // byte populations before cloning the canonical source-owned body.
        observed.seals.push(Seal {
            member,
            reference: reference.clone(),
            bytes: bytes.to_vec(),
            body: body(),
            native: native.map(|(reference, bytes)| (reference.clone(), bytes.to_vec())),
        });
        observed.bytes = credit;
        Ok(())
    }
}

fn native_failure(error: crucible::node_contract::OperationFailure) -> QualificationError {
    QualificationError::Evidence(error.reason)
}
