//! Owns independently observed connected effects beneath original native journals.
//!
//! The source roster, finite program and grant schedule are installed before
//! Child. Only concrete original source scopes enroll native bodies; portable
//! reports cannot supply a journal or replace an independently owned receiver.

use std::{cell::RefCell, os::unix::net::UnixDatagram, rc::Rc};

use crucible_engine::node_adapters::cnp::CnpSemanticRealizationScope;
use crucible_node_format::{ContentRef, Id, canonical};
use crucible_node_transport::reference_packet::{
    connected::{PacketCommitRecord, PacketConnectedNativeRecord, PacketStageRecord},
    control::PacketNativeRecord,
    coordinator::PacketConnectedCoordinatorInstallation,
    service::PacketConnectedSourceProgram,
};

use super::{
    PacketConnectedParticipant, PacketConnectedRoster, PacketConnectedSchedule, QualificationError,
    refused,
};
use crate::node_qualification::{
    CaseVerdict, ExactCompletionCase, InstalledRuntimeWitnessOracle, OriginalCompletionWitness,
    PlannedWitnessCase, WitnessPlan,
};

mod effects;
mod expected;
mod original;

const MAXIMUM_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_SEALS: usize = 256;
const MAXIMUM_EFFECTS: usize = 96;
const MAXIMUM_SNAPSHOT: u64 = 8 * 1024 * 1024;

/// Transfers three original independent receivers and their complete source scene.
pub struct PacketConnectedOracleRequest<'a> {
    /// Retains the same concrete producer, relay and sink objects.
    pub roster: PacketConnectedRoster,
    /// Borrows the complete native-three/host-one original world installation.
    pub coordinator: &'a PacketConnectedCoordinatorInstallation,
    /// Owns each bounded source program in original participant order.
    pub programmes: [PacketConnectedSourceProgram; 3],
    /// Exclusively owns the original independently observed effect receivers.
    pub receivers: [UnixDatagram; 3],
    /// Owns all predeclared operations and distinct causal cases.
    pub schedule: PacketConnectedSchedule,
    /// Borrows the complete mandatory and supplemental witness population.
    pub plan: &'a WitnessPlan,
    /// Bounds full native bodies, typed copies and datagrams before Child.
    pub maximum_bytes: usize,
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
pub struct PacketConnectedNativeOracle {
    roster: PacketConnectedRoster,
    programmes: [PacketConnectedSourceProgram; 3],
    receivers: [UnixDatagram; 3],
    schedule: PacketConnectedSchedule,
    plan: WitnessPlan,
    maximum_bytes: usize,
    observed: RefCell<Observed>,
    originals: original::OriginalBindings,
}

impl PacketConnectedNativeOracle {
    /// Reserves complete finite native, datagram and original-report custody.
    ///
    /// # Errors
    /// Refuses a foreign roster/program/plan, unsupported finite population,
    /// nonunique case or grant, unusable receiver or unavailable prospective credit.
    pub fn install(
        request: PacketConnectedOracleRequest<'_>,
    ) -> Result<Rc<Self>, QualificationError> {
        request.roster.current_scope()?;
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
                    if matches!(
                        request.roster.sources[member],
                        PacketConnectedParticipant::Producer(_)
                    ) && program.events.len() == 2
                        && program.events[0].payload.is_none()
                        && program.events[1]
                            .payload
                            .as_ref()
                            .is_some_and(|value| value.as_slice().len() <= 32) =>
                {
                    serde_json::to_value(program)
                }
                PacketConnectedSourceProgram::Reactive { program }
                    if matches!(
                        request.roster.sources[member],
                        PacketConnectedParticipant::Reactive(_)
                    ) =>
                {
                    serde_json::to_value(program)
                }
                _ => return Err(refused()),
            }
            .map_err(crucible_node_format::ContractError::from)?;
            let bytes = canonical::canonical_json(&value)?;
            selected.descriptor.model_ref.verify(&bytes)?;
            if request.schedule.nodes[member] != selected.descriptor.id {
                return Err(refused());
            }
            request.receivers[member]
                .set_nonblocking(true)
                .map_err(|error| QualificationError::Evidence(error.to_string()))?;
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
            receivers: request.receivers,
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
        roster: &PacketConnectedRoster,
        coordinator: &PacketConnectedCoordinatorInstallation,
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
        self.preflight()?;
        let source = self.roster.sources.get(member).ok_or_else(refused)?;
        if !std::ptr::eq(scope.installation, source.installation()) {
            return Err(refused());
        }
        let result = (|| {
            let mut observed = self.observed.try_borrow_mut().map_err(|_| refused())?;
            match source {
                PacketConnectedParticipant::Producer(source) => {
                    let witness = source
                        .latest_original_native_witness(&scope)
                        .map_err(native_failure)?;
                    self.enroll(
                        &mut observed,
                        member,
                        witness.reference(),
                        witness.bytes(),
                        || NativeBody::Producer(witness.record().clone()),
                    )?;
                }
                PacketConnectedParticipant::Reactive(source) => {
                    let witness = source
                        .latest_original_native_witness(&scope)
                        .map_err(native_failure)?;
                    for root in witness
                        .record()
                        .inventory
                        .stages
                        .iter()
                        .chain(&witness.record().inventory.commits)
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
                                || NativeBody::Stage(stage.clone()),
                            )?;
                        } else if let Some(commit) = input.commit() {
                            self.enroll(
                                &mut observed,
                                member,
                                input.reference(),
                                input.bytes(),
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
                        || NativeBody::Reactive(witness.record().clone()),
                    )?;
                }
            }
            effects::drain(self, member, &mut observed)?;
            effects::verify_prefix(self, member, &observed)?;
            source.current_native().map_err(native_failure)
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
        body: impl FnOnce() -> NativeBody,
    ) -> Result<(), QualificationError> {
        if let Some(old) = observed
            .seals
            .iter()
            .find(|old| old.member == member && old.reference == *reference)
        {
            if old.bytes != bytes {
                return Err(refused());
            }
            return Ok(());
        }
        reference.verify(bytes)?;
        let credit = bytes
            .len()
            .checked_mul(3)
            .and_then(|bytes| observed.bytes.checked_add(bytes))
            .filter(|bytes| *bytes <= self.maximum_bytes)
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
        });
        observed.bytes = credit;
        Ok(())
    }
}

fn native_failure(error: crucible_engine::node_contract::OperationFailure) -> QualificationError {
    QualificationError::Evidence(error.reason)
}
