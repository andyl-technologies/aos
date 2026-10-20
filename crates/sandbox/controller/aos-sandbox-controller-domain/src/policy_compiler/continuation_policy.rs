//! Retains a fresh closed Root purpose's real policy-pair interval.
//!
//! The actual serving custody remains the sole owner of both fixed writers and
//! their original issuer pins. A concrete purpose receiver prepays this shape,
//! arms all four actual native destinations while healthy, and retains them
//! through the original before/independently owed after observations. Signed
//! policy decoding delegates the existing held-head verifier without a new key
//! input, raw Journal getter, RootOpen cast or authority factory.

use std::error::Error;
use std::marker::PhantomData;
use std::mem::size_of;

use aos_sandbox_broker::receiving::RootWriterPostOriginalV1;
use aos_sandbox_model::{RawPairedClockSample, ResourceDimension as D, ResourceVector};

use crate::controller_resource_reservation::{RootPeerPurposeV1, StopCleanupRootPeerPurposeV1, ExecutionNoApplyRootPeerPurposeV2,
    EnvironmentRootPeerPurposeV1, ApplyRootPeerPurposeV1, HostLaunchRootPeerPurposeV1, MaintenanceStorageRootPeerPurposeV2, FinalityRecoverRootPeerPurposeV1, DeleteRootPeerPurposeV1};
use crate::journal::{JournalError, root_construction::RootJournalServingIdentityV1};
use super::create_storage_current::{policy_inputs::RootCurrentPolicyInputDataV1,
    pins::{RootCurrentPinsStateV1, RootServingPinsErrorV1}};
use super::root_current_writers::{RootCreateStorageCurrentWritersV1, RootCurrentWriterRoleV1};
use super::root_signed_sources::{RootSignedProjectSourcesV1, RootSignedSourcesErrorV1};

pub(crate) type RootDeletePolicyOriginalV2 = RootPurposePolicyOriginalV1<DeleteRootPeerPurposeV1>;
pub(crate) type RootStopCleanupPolicyOriginalV1 = RootPurposePolicyOriginalV1<StopCleanupRootPeerPurposeV1>;
pub(crate) type RootExecutionNoApplyPolicyOriginalV2 = RootPurposePolicyOriginalV1<ExecutionNoApplyRootPeerPurposeV2>;
pub(crate) type RootEnvironmentPolicyOriginalV1 = RootPurposePolicyOriginalV1<EnvironmentRootPeerPurposeV1>;
pub(crate) type RootApplyPolicyOriginalV1 = RootPurposePolicyOriginalV1<ApplyRootPeerPurposeV1>;
pub(crate) type RootHostLaunchPolicyOriginalV1 = RootPurposePolicyOriginalV1<HostLaunchRootPeerPurposeV1>;
pub(crate) type RootMaintenanceStoragePolicyOriginalV2 = RootPurposePolicyOriginalV1<MaintenanceStorageRootPeerPurposeV2>;
pub(crate) type RootFinalityRecoverPairOriginalV1 = RootPurposePolicyOriginalV1<FinalityRecoverRootPeerPurposeV1>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum RootContinuationPolicyErrorV1 {
    #[error("fresh Root policy interval is incomplete or already entered")]
    Closed,
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Pins(#[from] RootServingPinsErrorV1),
    #[error(transparent)]
    Sources(#[from] RootSignedSourcesErrorV1),
}

#[derive(Clone, Copy)]
enum First { Identity, Arm(usize), Before(usize), BeforeBinding, VerificationAccess, Verification, After(usize), AfterBinding, Reentry }

pub(crate) struct RootPurposePolicyOriginalV1<K: RootPeerPurposeV1> {
    identities: Option<Result<[RootJournalServingIdentityV1; 2], JournalError>>,
    posts: [Option<Result<RootWriterPostOriginalV1, JournalError>>; 4],
    before: [Option<Result<(), JournalError>>; 2],
    before_binding: Option<Result<(), RootContinuationPolicyErrorV1>>,
    verification_access: Option<Result<(), JournalError>>,
    verified: Option<Result<RootSignedProjectSourcesV1, RootSignedSourcesErrorV1>>,
    verified_at: Option<RawPairedClockSample>,
    after: [Option<Result<(), JournalError>>; 2],
    after_binding: Option<Result<(), RootContinuationPolicyErrorV1>>,
    first: Option<First>,
    closed: Option<RootContinuationPolicyErrorV1>,
    entered: bool,
    after_entered: bool,
    purpose: PhantomData<K>,
}

impl<K: RootPeerPurposeV1> Default for RootPurposePolicyOriginalV1<K> {
    fn default() -> Self {
        Self { identities: None, posts: std::array::from_fn(|_| None),
            before: std::array::from_fn(|_| None), before_binding: None,
            verification_access: None, verified: None, verified_at: None, after: std::array::from_fn(|_| None),
            after_binding: None, first: None, closed: None, entered: false,
            after_entered: false, purpose: PhantomData }
    }
}

impl<K: RootPeerPurposeV1> RootPurposePolicyOriginalV1<K> {
    pub(crate) fn receiving_demand_v1(writers: &RootCreateStorageCurrentWritersV1)
        -> Result<ResourceVector, JournalError>
    {
        // The metadata-only purpose reads no signed source model. It still
        // pays the exact same actual pair/header and four native post owners.
        let decoder = if K::FINALITY_RECOVER_ONLY {
            Some(0)
        } else {
            aos_sandbox_policy::signed_inputs::fixed_root_startup_decoding_bytes_v1()
                .and_then(|bytes| bytes.checked_add(64 * 1024))
        };
        let bytes = decoder
            .and_then(|bytes| bytes.checked_add(size_of::<Self>().checked_mul(3)?))
            .and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let mut demand = RootJournalServingIdentityV1::pair_demand_v1()?
            .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
            .map_err(|_| JournalError::JournalTooLarge)?;
        for role in RootCurrentWriterRoleV1::ALL {
            let one = writers.serving_policy_interval_journal_v1(role)?.root_names_post_demand_v1()?;
            demand = demand.checked_add(one).and_then(|value| value.checked_add(one))
                .map_err(|_| JournalError::JournalTooLarge)?;
        }
        // Pure bounded decoder collections are bytes, not namespace entries.
        Ok(demand)
    }

    pub(crate) fn begin_for_actual_pair_once_v1(
        &mut self, writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
    ) -> Result<(), RootContinuationPolicyErrorV1> {
        if self.entered || self.closed.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootContinuationPolicyErrorV1::Closed);
            return Err(RootContinuationPolicyErrorV1::Closed);
        }
        self.entered = true;
        self.identities = Some(writers.serving_identities_v1());
        if !matches!(self.identities, Some(Ok(_))) {
            self.first.get_or_insert(First::Identity);
            return Err(RootContinuationPolicyErrorV1::Closed);
        }
        // Arm the two independently owed after owners before either native
        // before observation can refuse the permanent Root invocation.
        for index in 0..4 {
            let role = RootCurrentWriterRoleV1::ALL[index % 2];
            self.posts[index] = Some(writers.serving_policy_interval_journal_v1(role)
                .and_then(|journal| journal.arm_root_names_post_once_v1()));
            if !matches!(self.posts[index], Some(Ok(_))) {
                self.first.get_or_insert(First::Arm(index));
            }
        }
        if self.first.is_some() { return Err(RootContinuationPolicyErrorV1::Closed); }
        for index in 0..2 {
            self.before[index] = Some(self.observe_once(writers, index));
            if !matches!(self.before[index], Some(Ok(()))) {
                self.first.get_or_insert(First::Before(index));
            }
        }
        self.before_binding = Some(self.require_binding(writers, pins));
        if !matches!(self.before_binding, Some(Ok(()))) {
            self.first.get_or_insert(First::BeforeBinding);
        }
        if self.first.is_none() { Ok(()) } else { Err(RootContinuationPolicyErrorV1::Closed) }
    }

    pub(crate) fn verify_current_sources_once_v1(
        &mut self, writers: &RootCreateStorageCurrentWritersV1,
        data: &RootCurrentPolicyInputDataV1<'_>, now: RawPairedClockSample,
    ) -> Result<(), RootContinuationPolicyErrorV1> {
        if K::FINALITY_RECOVER_ONLY || !self.entered || self.first.is_some() || self.after_entered || self.verified.is_some() {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootContinuationPolicyErrorV1::Closed);
            return Err(RootContinuationPolicyErrorV1::Closed);
        }
        let policy = match writers.serving_policy_interval_journal_v1(RootCurrentWriterRoleV1::Policy) {
            Ok(policy) => {
                self.verification_access = Some(Ok(()));
                policy
            }
            Err(cause) => {
                self.verification_access = Some(Err(cause));
                self.first.get_or_insert(First::VerificationAccess);
                return Err(RootContinuationPolicyErrorV1::Closed);
            }
        };
        self.verified_at = Some(now);
        self.verified = Some(data.verify_current_sources_v1(policy, now.wall_seconds()));
        if matches!(self.verified, Some(Ok(_))) { Ok(()) } else {
            self.first.get_or_insert(First::Verification);
            Err(RootContinuationPolicyErrorV1::Closed)
        }
    }

    // These are already-armed owed observations. Their access deliberately
    // avoids a healthy serving/financial gate after an earlier native refusal.
    pub(crate) fn finish_actual_pair_once_v1(
        &mut self, writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
    ) -> Result<(), RootContinuationPolicyErrorV1> {
        self.finish_actual_pair_inner_v2(writers, pins, None)
    }

    fn finish_actual_pair_inner_v2(
        &mut self, writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        floor: Option<&super::execution_no_apply_root::RootExecutionNoApplyFloorOriginalV2>,
    ) -> Result<(), RootContinuationPolicyErrorV1> {
        if self.after_entered {
            self.first.get_or_insert(First::Reentry);
            self.closed.get_or_insert(RootContinuationPolicyErrorV1::Closed);
            return Err(RootContinuationPolicyErrorV1::Closed);
        }
        self.after_entered = true;
        for index in 0..2 {
            let post = index + 2;
            if matches!(self.posts[post], Some(Ok(_))) {
                self.after[index] = Some(self.observe_once(writers, post));
                if !matches!(self.after[index], Some(Ok(()))) {
                    self.first.get_or_insert(First::After(index));
                }
            }
        }
        self.after_binding = Some(match floor {
            Some(floor) => floor.require_policy_successor_v2(writers,pins,
                self.identities.as_ref().and_then(|v|v.as_ref().ok()).ok_or(RootContinuationPolicyErrorV1::Closed)?)
                .map_err(RootContinuationPolicyErrorV1::Journal),
            None => self.require_binding(writers,pins),
        });
        if !matches!(self.after_binding, Some(Ok(()))) {
            self.first.get_or_insert(First::AfterBinding);
        }
        self.require_complete_v1()
    }

    fn observe_once(&mut self, writers: &RootCreateStorageCurrentWritersV1, index: usize)
        -> Result<(), JournalError>
    {
        let post = self.posts[index].as_mut().and_then(|value| value.as_mut().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        // Access only the retained exact role slot; the lower post compares
        // the same actual writer/original Arc even when its healthy gate closed.
        writers.owed_policy_interval_journal_v1(RootCurrentWriterRoleV1::ALL[index % 2])?
            .finish_root_names_post_once_v1(post)
    }

    fn require_binding(&self, writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1) -> Result<(), RootContinuationPolicyErrorV1>
    {
        let identities = self.identities.as_ref().and_then(|value| value.as_ref().ok())
            .ok_or(RootContinuationPolicyErrorV1::Closed)?;
        writers.require_serving_identities_v1(identities)?;
        writers.require_serving_pins_v1(pins)?;
        Ok(())
    }

    pub(crate) fn verified_v1(&self) -> Option<&RootSignedProjectSourcesV1> {
        if self.first.is_some() || !matches!(self.before_binding, Some(Ok(()))) { return None; }
        self.verified.as_ref()?.as_ref().ok()
    }

    pub(crate) fn verified_at_v1(&self) -> Option<RawPairedClockSample> {
        self.verified_v1()?;
        self.verified_at
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), RootContinuationPolicyErrorV1> {
        let before = if K::FINALITY_RECOVER_ONLY {
            self.before.iter().all(|value| matches!(value, Some(Ok(()))))
                && matches!(self.before_binding, Some(Ok(())))
        } else { self.verified_v1().is_some() };
        if self.first.is_none() && before
            && self.after.iter().all(|value| matches!(value, Some(Ok(()))))
            && matches!(self.after_binding, Some(Ok(()))) && self.failure().is_none()
        { Ok(()) } else { Err(RootContinuationPolicyErrorV1::Closed) }
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let selected = match self.first {
            Some(First::Identity) => cause(&self.identities),
            Some(First::Arm(index)) => cause(&self.posts[index]),
            Some(First::Before(index)) => self.post_failure(index).or_else(|| cause(&self.before[index])),
            Some(First::BeforeBinding) => cause(&self.before_binding),
            Some(First::VerificationAccess) => cause(&self.verification_access),
            Some(First::Verification) => cause(&self.verified),
            Some(First::After(index)) => self.post_failure(index + 2).or_else(|| cause(&self.after[index])),
            Some(First::AfterBinding) => cause(&self.after_binding),
            Some(First::Reentry) => self.closed.as_ref().map(|cause| cause as _),
            None => None,
        };
        selected.or_else(|| self.closed.as_ref().map(|cause| cause as _))
    }

    fn post_failure(&self, index: usize) -> Option<&(dyn Error + 'static)> {
        self.posts[index].as_ref()?.as_ref().ok()?.failure()
    }
}

fn cause<T, E: Error + 'static>(slot: &Option<Result<T, E>>)
    -> Option<&(dyn Error + 'static)>
{
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod apply_first_cause_tests {
    use super::*;
    use crate::policy_compiler::storage_apply_root::{UnsignedFailureSourceV1, PhaseV1};

    #[test]
    fn earlier_owned_expiry_survives_later_policy_after_failure() {
        let mut policy = RootApplyPolicyOriginalV1::default();
        use aos_sandbox_model::RawClockProvenance;
        use crate::policy_compiler::provisioning_current::RootContinuationHorizonDataV1;
        let provenance = RawClockProvenance::new_untrusted([1; 16]).unwrap();
        let original_clock = RawPairedClockSample::new_untrusted(provenance, [2; 16], 100, 10).unwrap();
        let expired_clock = RawPairedClockSample::new_untrusted(provenance, [2; 16], 100, 20).unwrap();
        let horizon = RootContinuationHorizonDataV1::from_original_data_v1(original_clock, 20).unwrap();
        let body: Result<(), Box<dyn Error>> = horizon.require_sample_v1(expired_clock)
            .map_err(|cause| Box::new(cause) as Box<dyn Error>);
        let original = body.as_ref().unwrap_err().as_ref();
        let selected = UnsignedFailureSourceV1::select_v1(PhaseV1::Policy,
            false, policy.failure().is_some(), false);

        policy.after[0] = Some(Err(JournalError::JournalTooLarge));
        policy.first = Some(First::After(0));
        let later = policy.failure().unwrap();
        let retained = selected.resolve_v1(None, None, Some(later), None, None, Some(original)).unwrap();

        assert!(std::ptr::eq(retained, original));
        assert!(!std::ptr::eq(retained, later));
        assert!(matches!(retained.downcast_ref::<JournalError>(), Some(JournalError::ProtectedBoundary)));
    }

    #[test]
    fn existing_policy_native_failure_keeps_its_owned_identity() {
        let mut policy = RootApplyPolicyOriginalV1::default();
        policy.before[0] = Some(Err(JournalError::JournalTooLarge));
        policy.first = Some(First::Before(0));
        let selected = UnsignedFailureSourceV1::select_v1(PhaseV1::Policy,
            false, policy.failure().is_some(), false);
        let original = policy.failure().unwrap() as *const (dyn Error + 'static);

        policy.after[0] = Some(Err(JournalError::ProtectedBoundary));
        let body: Box<dyn Error> = Box::new(JournalError::ProtectedBoundary);
        let retained = selected.resolve_v1(None, None, policy.failure(), None, None, Some(body.as_ref())).unwrap();

        assert!(std::ptr::eq(retained, original));
        assert!(matches!(retained.downcast_ref::<JournalError>(), Some(JournalError::JournalTooLarge)));
    }
}

pub(crate) type RootStartAssignmentInputsPolicyOriginalV2 = RootPurposePolicyOriginalV1<
    crate::controller_resource_reservation::StartAssignmentInputsRootPeerPurposeV2,
>;

impl RootPurposePolicyOriginalV1<ExecutionNoApplyRootPeerPurposeV2> {
    /// Requires the original healthy pair before this purpose's only78 append.
    pub(crate) fn require_prepared_floor_pair_v2(&self, authority:&crate::Journal,
        policy:&crate::Journal,pins:&RootCurrentPinsStateV1)->Result<(),JournalError> {
        if self.verified_v1().is_none() || self.after_entered {return Err(JournalError::ProtectedBoundary);}
        let identities=self.identities.as_ref().and_then(|v|v.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)?;
        authority.require_root_serving_identity_v1(&identities[0])?;
        policy.require_root_serving_identity_v1(&identities[1])?;
        pins.require_serving_policy_v1(policy).map_err(|_|JournalError::ProtectedBoundary)
    }

    /// Uses the SAME independent post engine with only a genuine floor successor.
    pub(crate) fn finish_execution_floor_pair_once_v2(&mut self,
        writers:&RootCreateStorageCurrentWritersV1,pins:&RootCurrentPinsStateV1,
        floor:&super::execution_no_apply_root::RootExecutionNoApplyFloorOriginalV2)
        ->Result<(),RootContinuationPolicyErrorV1> {
        self.finish_actual_pair_inner_v2(writers,pins,Some(floor))
    }
}
