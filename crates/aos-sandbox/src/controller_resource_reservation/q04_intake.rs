//! Pays the first original Q04 entry from its disjoint image subdivision.
//!
//! Q is already Reserved in the inclusive Controller account. This owner
//! prices the whole retained observer allowance before attachment and commits
//! that same Q once. The actual Project preparation retains this owner through
//! terminal posts and LAST; closed or abandoned rows never become free credit.

use std::sync::{Arc, Mutex};

use aos_sandbox_core::{RawPairedClockSample, ResourceDimension as D, ResourceVector};
use aos_sandbox_linux::cgroup::FirstGlobalCpuReadbackV1;

use crate::journal::JournalShape;
use super::bank::FAILURE_MEMORY_BYTES;
use super::service_interval::{
    ObserverAdmission, ObserverLifetime, OriginalReceiver, capacity_for, multiply,
};
use super::{
    AccountTransition, ClaimPurpose, ClaimState, ControllerResourceBankOpeningV1,
    ResourceReservationErrorV1, ReturnedAppend, bank, bootstrap,
};
use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
use crate::lifecycle::protected_journal_join::ProtectedSourceDomainJournalOwnerV1;
use crate::normal_root::{NormalRootStartupErrorV1, ProductionControllerNormalRootProfileV1};
use crate::{Journal, JournalError};

// This is only the proved entrance lower bound through HELLO: preparation's
// producer/post (3), existing enrolled arm (4), outer profile (1), connect
// (5), Query write (2), one HELLO receive (10), and HELLO acceptance (2).
// It is not a completion bound. Further progress and every AGAIN/Interrupted
// observation consume the same prepaid retained-row quota before growth.
const ENTRANCE_OBSERVER_ROWS: usize = 3 + 4 + 1 + 5 + 2 + 10 + 2;

pub(super) fn native_layout() -> super::bank::NativeLayoutDemand {
    super::bank::NativeLayoutDemand::new(
        std::mem::size_of::<Q04OriginalIntakeAttemptV1>(),
        std::mem::size_of::<crate::ProjectPreparationReservationAttemptV1>(),
    )
}

pub(super) fn minimum_failure_demand() -> Result<ResourceVector, ResourceReservationErrorV1> {
    super::bank::minimum_q04_failure_demand(native_layout())
        .map_err(ResourceReservationErrorV1::from)
}

pub(super) struct Q04OriginalIntakeAttemptV1 {
    bank: Arc<Mutex<ControllerResourceBankOpeningV1>>,
    original: Option<Result<bootstrap::OriginalEnrollment, ResourceReservationErrorV1>>,
    receiver: Option<Result<OriginalReceiver, ResourceReservationErrorV1>>,
    source_shape: Option<JournalShape>,
    observation_capacity: Option<usize>,
    preparation: Option<Result<(), ResourceReservationErrorV1>>,
    initial_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    cpu: FirstGlobalCpuReadbackV1,
    append: ReturnedAppend,
    controller_post: Option<Result<(), JournalError>>,
    source_post: Option<Result<(), JournalError>>,
    profile_post: Option<Result<(), NormalRootStartupErrorV1>>,
    cpu_post: Option<Result<(), NormalRootStartupErrorV1>>,
    last_clock: Option<Result<RawPairedClockSample, SourceGenesisErrorV1>>,
    clock_post: Option<Result<(), SourceGenesisErrorV1>>,
    lifetime: Option<ObserverLifetime>,
    attempted: bool,
    first: Option<FailureSite>,
}

#[derive(Clone, Copy)]
enum FailureSite {
    Original,
    Receiver,
    InitialClock,
    Cpu,
    Append,
    Preparation,
    ControllerPost,
    SourcePost,
    ProfilePost,
    CpuPost,
    LastClock,
    ClockPost,
}

impl Q04OriginalIntakeAttemptV1 {
    pub(super) fn begin(bank: Arc<Mutex<ControllerResourceBankOpeningV1>>) -> Self {
        Self {
            bank, original: None, receiver: None, source_shape: None, observation_capacity: None, preparation: None,
            initial_clock: None, cpu: FirstGlobalCpuReadbackV1::default(),
            append: ReturnedAppend::new(), controller_post: None, source_post: None,
            profile_post: None, cpu_post: None, last_clock: None, clock_post: None,
            lifetime: None, attempted: false, first: None,
        }
    }

    pub(super) fn prepare_once(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.attempted {
            self.close();
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.attempted = true;
        self.original = Some(self.bank.lock()
            .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)
            .and_then(|mut bank| bank.begin_q04_intake_once()));
        if !matches!(self.original, Some(Ok(_))) {
            // No genuine Q was acquired. Park its first cause and refuse
            // before any receiver, kernel/profile observation or raw clock.
            self.first = Some(FailureSite::Original);
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.receiver = Some(OriginalReceiver::capture(controller, source, profile));
        self.preparation = Some(self.prepare_body(controller, source, profile));
        self.first = if matches!(self.original, Some(Err(_))) {
            Some(FailureSite::Original)
        } else if matches!(self.receiver, Some(Err(_))) {
            Some(FailureSite::Receiver)
        } else if matches!(self.initial_clock, Some(Err(_))) {
            Some(FailureSite::InitialClock)
        } else if self.cpu.failure().is_some() {
            Some(FailureSite::Cpu)
        } else if self.append.failure().is_some() {
            Some(FailureSite::Append)
        } else if matches!(self.preparation, Some(Err(_))) {
            Some(FailureSite::Preparation)
        } else {
            None
        };

        // Available original posts run even after native Err; no bank lock
        // spans them. Unattached Q refuses without falling back to P/I/Ordinary.
        self.controller_post = Some(controller.validate_held_protected_names());
        self.source_post = Some(source.journal().validate_held_protected_names());
        self.profile_post = Some(profile.recheck_q04_intake_profile());
        self.cpu_post = Some(profile.recheck_first_global_cpu(&mut self.cpu));
        self.last_clock = Some(crate::policy_compiler::observe_root_first_source_successor_clock_v2(None));
        self.clock_post = Some(match (
            self.initial_clock.as_ref().and_then(|result| result.as_ref().ok()),
            self.last_clock.as_ref().and_then(|result| result.as_ref().ok()),
        ) {
            (Some(before), Some(after)) => before.validate_later_sample(*after)
                .map_err(|_| SourceGenesisErrorV1::Stale),
            _ => Err(SourceGenesisErrorV1::Stale),
        });
        if self.first.is_none() {
            self.first = if matches!(self.controller_post, Some(Err(_))) {
                Some(FailureSite::ControllerPost)
            } else if matches!(self.source_post, Some(Err(_))) {
                Some(FailureSite::SourcePost)
            } else if matches!(self.profile_post, Some(Err(_))) {
                Some(FailureSite::ProfilePost)
            } else if matches!(self.cpu_post, Some(Err(_))) {
                Some(FailureSite::CpuPost)
            } else if matches!(self.last_clock, Some(Err(_))) {
                Some(FailureSite::LastClock)
            } else if matches!(self.clock_post, Some(Err(_))) {
                Some(FailureSite::ClockPost)
            } else {
                None
            };
        }
        if self.failure().is_some() {
            self.close();
            Err(ResourceReservationErrorV1::Conflict)
        } else {
            Ok(())
        }
    }

    fn prepare_body(
        &mut self,
        controller: &mut Journal,
        source: &mut ProtectedSourceDomainJournalOwnerV1,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        self.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let provision = (original.policy.bootstrap_provisions().q04_original_intake)
            .ok_or(ResourceReservationErrorV1::EnrollmentUnavailable)?;
        let id = original
            .identity
            .account_id(b"controller-q04-original-intake-v1");
        let state = controller.controller_resource_state_v1()?;
        let claim = super::Claim::decode(
            bank::claim_bytes(state, id).ok_or(ResourceReservationErrorV1::Conflict)?,
        )
        .map_err(ResourceReservationErrorV1::from)?;
        if claim.native_fields().purpose != ClaimPurpose::Q04OriginalIntake
            || claim.native_fields().enrollment != original.identity
            || claim.native_fields().amount != provision
            || claim.native_fields().state != ClaimState::Reserved
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        let mut transition = AccountTransition::settle(
            bank::find_head(state, claim.native_fields().account)
                .map_err(ResourceReservationErrorV1::from)?,
            claim,
            true,
        )?;
        self.source_shape = Some(source.journal().first_global_allocation_shape_v1()?);
        let fixed = fixed_demand(&controller.first_global_allocation_shape_v1()?,
            self.source_shape.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?, provision)?;
        let row = ProductionControllerNormalRootProfileV1::first_global_observer_demand()?;
        let capacity = capacity_for(provision.checked_sub(fixed)?, row)?;
        if capacity < ENTRANCE_OBSERVER_ROWS {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        provision.checked_sub(fixed.checked_add(multiply(row, capacity)?)?)?;
        self.observation_capacity = Some(capacity);

        // All admitted archive rows and the fixed proof/CPU/native originals
        // have a genuine already-Reserved payer before the first new capture.
        // Check the actual private cgroup rate before observer archive growth;
        // the image's rate comparison alone is never physical evidence.
        profile.observe_first_global_cpu(&mut self.cpu)?;
        let (quota, period) = self.cpu.quota_and_period().ok_or(ResourceReservationErrorV1::Conflict)?;
        if period != 100_000 || quota > provision.get(D::CpuMicrosPerPeriod) {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.initial_clock = Some(crate::policy_compiler::observe_root_first_source_successor_clock_v2(None));
        let clock = self.initial_clock.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(ResourceReservationErrorV1::Conflict)?;
        if clock.host_boot_id() != original.identity.native_fields().boot {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.lifetime = Some(ObserverLifetime::begin());
        let admission = ObserverAdmission::for_q04_intake(
            profile, original, capacity,
            self.lifetime.as_ref().ok_or(ResourceReservationErrorV1::Conflict)?,
        );
        profile.attach_q04_intake_observers(&admission)?;
        let (recipient, producer) = profile.require_resource_producer()?;
        if recipient != original.recipient_invocation
            || producer != original.identity.native_fields().invocation
            || self
                .bank
                .lock()
                .map_err(|_| ResourceReservationErrorV1::EnrollmentUnavailable)?
                .first_global_original(controller)?
                != *original
        {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        self.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?.require_same(controller, source, profile)?;
        transition.original_clock = Some(clock);
        self.append.append_into(controller, Ok(transition));
        self.append.require_committed()?;
        self.receiver.as_mut().and_then(|result| result.as_mut().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?.controller_sequence = controller.snapshot_sequence();
        Ok(())
    }

    pub(super) fn require_original(
        &self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<(), ResourceReservationErrorV1> {
        if self.failure().is_some() {
            return Err(ResourceReservationErrorV1::Conflict);
        }
        profile.require_q04_intake_original(self.lifetime.as_ref()
            .ok_or(ResourceReservationErrorV1::Conflict)?)?;
        self.append.require_committed().map(|_| ())
    }

    pub(super) fn close(&self) {
        if let Some(lifetime) = &self.lifetime {
            lifetime.close();
        }
    }

    pub(super) fn association(
        &self,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<([u8; 16], u64), ResourceReservationErrorV1> {
        self.require_original(profile)?;
        let original = self.original.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        let capacity = self
            .observation_capacity
            .ok_or(ResourceReservationErrorV1::Conflict)?;
        Ok((
            original
                .identity
                .account_id(b"controller-q04-original-intake-v1"),
            u64::try_from(capacity).map_err(|_| ResourceReservationErrorV1::Conflict)?,
        ))
    }

    pub(super) fn preparation_source_shape(
        &self,
        original: &super::OriginalPreparationData,
        profile: &ProductionControllerNormalRootProfileV1,
    ) -> Result<&JournalShape, ResourceReservationErrorV1> {
        self.require_original(profile)?;
        self.receiver.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(ResourceReservationErrorV1::Conflict)?.require_q04_preparation_source(original)?;
        self.source_shape.as_ref().ok_or(ResourceReservationErrorV1::Conflict)
    }

    pub(super) fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self.first? {
            FailureSite::Original => self.original.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::Receiver => self.receiver.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::InitialClock => self.initial_clock.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::Cpu => self.cpu.failure().map(|error| error as _),
            FailureSite::Append => self.append.failure(),
            FailureSite::Preparation => self.preparation.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::ControllerPost => self.controller_post.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::SourcePost => self.source_post.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::ProfilePost => self.profile_post.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::CpuPost => self.cpu_post.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::LastClock => self.last_clock.as_ref()?.as_ref().err().map(|error| error as _),
            FailureSite::ClockPost => self.clock_post.as_ref()?.as_ref().err().map(|error| error as _),
        }
    }
}

impl Drop for Q04OriginalIntakeAttemptV1 {
    fn drop(&mut self) {
        self.close();
    }
}

fn fixed_demand(
    controller: &JournalShape,
    source: &JournalShape,
    provision: ResourceVector,
) -> Result<ResourceVector, ResourceReservationErrorV1> {
    use crate::policy_compiler::create_q04::{
        MAXIMUM_CLAIM_BYTES, MAXIMUM_PREHOLD_BYTES, MAXIMUM_PREVIEW_BYTES,
        OriginalCreateQ04InvocationV1,
    };
    let fail = || ResourceReservationErrorV1::Conflict;
    // Complete fixed wire families, original/encoding/retained receive copies,
    // and the eight Controller/seven Root phase slots. This counts retained
    // owners, not a bound on retry observations or future cleanup credit.
    let wire = MAXIMUM_CLAIM_BYTES.checked_add(MAXIMUM_PREVIEW_BYTES)
        .and_then(|bytes| bytes.checked_add(MAXIMUM_PREHOLD_BYTES))
        .and_then(|bytes| bytes.checked_add((8 + 7) * 4096)).ok_or_else(fail)?;
    // begin_original_q04 rechecks the actual existing Controller Cache source
    // before Completed/P admission. Its fixed opener bounds materialized source
    // records at 128MiB/native256MiB; read_source_records clones and decodes the
    // whole canonical manifest set. Q, not the future Project admission, pays
    // this entered prefix and its complete owning error/model copies.
    let cache_bytes = 128_usize * 1024 * 1024;
    let cache_cells = crate::policy_compiler::create_q04::cache_replay_cell_bytes()?;
    let cache_memory = cache_bytes.checked_mul(cache_cells)
        .and_then(|bytes| bytes.checked_mul(4))
        .and_then(|bytes| bytes.checked_add(256 * 1024 * 1024)).ok_or_else(fail)?;
    let native = controller.native_bytes.checked_add(source.native_bytes)
        .and_then(|bytes| bytes.checked_add(u64::try_from(controller.maximum_transaction_bytes).ok()?.checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(256 * 1024 * 1024))
        .ok_or_else(fail)?;
    let cells = controller.cells.checked_add(source.cells)
        .and_then(|count| count.checked_mul(2))
        .and_then(|count| count.checked_add(8 + 7 + 6 + 4)).ok_or_else(fail)?;
    let memory = controller.retained_bytes.checked_add(source.retained_bytes)
        .and_then(|bytes| bytes.checked_add(usize::try_from(native).ok()?))
        .and_then(|bytes| bytes.checked_add(wire.checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(cells.checked_mul(std::mem::size_of::<(ResourceVector, ResourceVector, [usize; 3])>())?))
        .and_then(|bytes| bytes.checked_add(cache_memory))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<OriginalCreateQ04InvocationV1<'_>>()))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<crate::public_api_session::ControllerQ04CredentialCustodyV1>()))
        // Six exact credential bodies and their rechecks, four ancestor paths;
        // the independently checked minimum retains fixed negative originals
        // and posts separately from wire DATA. It is not a retry allowance.
        .and_then(|bytes| bytes.checked_add((32 + 80 + 32 + 80 + 80 + 80) * 2 + 4 * 4096))
        .and_then(|bytes| bytes.checked_add(usize::try_from(FAILURE_MEMORY_BYTES).ok()?)).ok_or_else(fail)?;
    let memory = u64::try_from(memory).map_err(|_| fail())?;
    let wire = u64::try_from(wire).map_err(|_| fail())?;
    let cells = u64::try_from(cells.checked_add(cache_bytes).ok_or_else(fail)?).map_err(|_| fail())?;
    Ok(ResourceVector::new([
        provision.get(D::CpuMicrosPerPeriod), memory, 1, 3 + 2 + 3 + 6 + 4,
        // This entry creates no mounts, descendants, tmpfs, cache pin/fetch,
        // physical attachment or execution. It retains only existing writers,
        // read-only fixed credentials and the same local Root/profile flight.
        0, 0, native, 0, 0, 0, cells, 0, 0, 0, memory, 0, 0, 0,
        wire, wire, memory, 1,
    ]))
}

#[cfg(test)]
mod layout_bridge_tests {
    use super::*;

    #[test]
    fn authentic_native_intake_and_preparation_fit_the_failure_allowance() {
        let actual_native_bytes = std::mem::size_of::<Q04OriginalIntakeAttemptV1>()
            .checked_add(std::mem::size_of::<
                crate::ProjectPreparationReservationAttemptV1,
            >())
            .unwrap();
        let demand = minimum_failure_demand().unwrap();

        assert!(u64::try_from(actual_native_bytes).unwrap() < demand.get(D::MemoryBytes));
        assert!(matches!(
            ResourceReservationErrorV1::from(
                bank::minimum_q04_failure_demand(bank::NativeLayoutDemand::new(usize::MAX, 1))
                    .unwrap_err(),
            ),
            ResourceReservationErrorV1::Conflict
        ));
    }

    #[test]
    fn passive_snapshots_and_borrowed_views_remain_bounded() {
        use std::mem::{align_of, size_of};

        let snapshots = [
            (
                "EnrollmentIdentityFields",
                size_of::<bank::EnrollmentIdentityFields>(),
                size_of::<bank::EnrollmentIdentity>(),
            ),
            (
                "BootstrapProvisions",
                size_of::<bank::BootstrapProvisions>(),
                size_of::<bank::ImageBootstrapPolicy>(),
            ),
            (
                "AccountHeadFields",
                size_of::<bank::AccountHeadFields>(),
                size_of::<bank::AccountHead>(),
            ),
            (
                "ClaimFields",
                size_of::<bank::ClaimFields>(),
                size_of::<bank::Claim>(),
            ),
            (
                "CoissuanceFields",
                size_of::<bank::CoissuanceFields>(),
                size_of::<bank::CoissuanceBinding>(),
            ),
            (
                "TerminalFields",
                size_of::<bank::TerminalFields>(),
                size_of::<bank::TerminalBinding>(),
            ),
        ];

        for (name, bytes, canonical_bytes) in snapshots {
            println!("AOS_BANK_SNAPSHOT {name} bytes={bytes} canonical={canonical_bytes}");
            assert!(bytes <= canonical_bytes, "{name}");
            assert!(u64::try_from(bytes).unwrap() < FAILURE_MEMORY_BYTES, "{name}");
        }

        let views = [
            (
                "AccountMutation",
                size_of::<bank::AccountMutation<'static>>(),
                align_of::<bank::AccountMutation<'static>>(),
                8_usize,
            ),
            (
                "EnrollmentMutation",
                size_of::<bank::EnrollmentMutation<'static>>(),
                align_of::<bank::EnrollmentMutation<'static>>(),
                8,
            ),
            (
                "CoissuanceMutation",
                size_of::<bank::CoissuanceMutation<'static>>(),
                align_of::<bank::CoissuanceMutation<'static>>(),
                5,
            ),
        ];

        for (name, bytes, alignment, references) in views {
            let expected_bytes = references.checked_mul(size_of::<&()>()).unwrap();
            println!("AOS_BANK_VIEW {name} bytes={bytes} align={alignment} references={references}");
            assert_eq!(bytes, expected_bytes, "{name}");
            assert_eq!(alignment, align_of::<&()>(), "{name}");
        }
    }
}
