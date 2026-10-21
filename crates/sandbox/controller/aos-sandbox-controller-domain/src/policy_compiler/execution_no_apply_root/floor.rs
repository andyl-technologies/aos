//! Issues namespace78 only from the paid Root purpose and its actual held pair.
//!
//! The initial floor joins the independently captured final C global cut and
//! exact three-row plan to signed current43 under the same Root writer, policy
//! and native peer interval. Its common append engine takes a distinct closed
//! original. No DATA constructor, RootStorage loan or scalar readiness opens it.

use aos_sandbox_ledger_replay::replay::execution_no_apply_history as history;
pub(super) mod loan;
pub(super) mod signer;

pub(crate) use crate::journal::root_construction::RootJournalServingIdentityV1 as RootPolicyJournalServingIdentityV1;
pub(crate) use loan::RootExecutionNoApplyFloorAppendLoanV2;

use std::error::Error;
use std::fs::Metadata;
use std::mem::size_of;

use aos_sandbox_broker::bounded_entropy::{EntropyError, RetainedKernelNonceOriginalV1};
use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_linux_descriptors::unix_stream::RetainedUnixStream;
use aos_sandbox_protocol::domain_ledger::execution_no_apply_floor::{
    MAXIMUM_ROOT_EXECUTION_NO_APPLY_FLOOR_BYTES_V2 as MAXIMUM_FLOOR,
    ROOT_EXECUTION_NO_APPLY_HEAD_BYTES_V2 as HEAD_BYTES,
    ROOT_EXECUTION_NO_APPLY_INSTANCE_BYTES_V2 as INSTANCE_BYTES,
    ROOT_EXECUTION_NO_APPLY_INSTANCE_KEY_V2 as INSTANCE_KEY,
    RootExecutionNoApplyFloorFieldsV2 as FloorFields, RootExecutionNoApplyFloorHeadDataV2 as Head,
    RootExecutionNoApplyFloorRecordDataV2 as Floor, RootExecutionNoApplyInstanceDataV2 as Instance,
};
use aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordV2;
use sha2::{Digest as _, Sha256};

use crate::controller_resource_reservation::{
    RootContinuationDemandV1, service_interval::ObserverLifetime,
};
use crate::journal::{
    CommitResult, Journal, JournalError, JournalRecord, JournalTransaction,
};
use crate::normal_root::{
    NormalRootStartupErrorV1, RootControllerPeerCurrentSampleV1, RootPolicyAcceptedFlightV1,
};
use crate::policy_compiler::{
    continuation_policy::RootExecutionNoApplyPolicyOriginalV2,
    create_storage_current::pins::RootCurrentPinsStateV1,
    provisioning_current::finality_readonly::RootCreateFinalityReadonlyOriginalV1,
    root_current_writers::RootCreateStorageCurrentWritersV1,
};

use super::{
    RootExecutionNoApplyHostLeaseOriginalV2, RootExecutionNoApplyHostTrustOriginalV2,
    RootExecutionNoApplyModelsOriginalV2,
};

type Cause = Box<dyn Error>;

// Concrete origins share one append, native post, policy and signing engine.
enum FloorOriginV2<'held> {
    Active,
    Recovery(&'held mut super::RootExecutionNoApplyAcquisitionOriginalV2),
}

pub(crate) struct RootExecutionNoApplyFloorOriginalV2 {
    geometry: Option<Result<ResourceVector, JournalError>>,
    funding: Option<Result<(), NormalRootStartupErrorV1>>,
    native: Option<Box<Native>>,
    policy_post: Option<
        Result<(), crate::policy_compiler::continuation_policy::RootContinuationPolicyErrorV1>,
    >,
    reentry: Option<JournalError>,
}

struct Native {
    history: Option<Result<history::HistoryDataV2, JournalError>>,
    entropy_original: RetainedKernelNonceOriginalV1,
    entropy: Option<Result<[u8; 16], EntropyError>>,
    before: Option<Result<[RootPolicyJournalServingIdentityV1; 2], JournalError>>,
    floor: Option<Result<Floor, Cause>>,
    record: Option<Vec<u8>>,
    head: Option<[u8; HEAD_BYTES]>,
    instance: Option<Instance>,
    transaction: Option<Result<JournalTransaction, JournalError>>,
    crossing: loan::Crossing,
    signer: signer::RootFloorSignerV2,
    signing: Option<Result<(), JournalError>>,
    append: Option<Result<CommitResult, JournalError>>,
    readback: Option<Result<(), JournalError>>,
    end: Option<std::io::Result<Metadata>>,
    after: Option<Result<[RootPolicyJournalServingIdentityV1; 2], JournalError>>,
    body: Option<Result<(), Cause>>,
    external_trust: bool,
}

impl RootExecutionNoApplyFloorOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            geometry: None,
            funding: None,
            native: None,
            policy_post: None,
            reentry: None,
        }
    }

    /// Funds actual geometry before native peer/entropy/buffer construction.
    pub(crate) fn append_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &RetainedUnixStream,
        writers: &mut RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        policy: &mut RootExecutionNoApplyPolicyOriginalV2,
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
        models: &RootExecutionNoApplyModelsOriginalV2,
        host: &RootExecutionNoApplyHostLeaseOriginalV2,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
    ) -> Result<(), JournalError> {
        self.append_programme_once_v2(
            flight,
            original,
            writers,
            pins,
            policy,
            readonly,
            models,
            host,
            trust,
            FloorOriginV2::Active,
        )
    }

    /// Appends only through the same retained genuine recovery acquisition.
    pub(crate) fn append_recovery_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &RetainedUnixStream,
        writers: &mut RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        policy: &mut RootExecutionNoApplyPolicyOriginalV2,
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
        models: &RootExecutionNoApplyModelsOriginalV2,
        host: &RootExecutionNoApplyHostLeaseOriginalV2,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
        acquisition: &mut super::RootExecutionNoApplyAcquisitionOriginalV2,
    ) -> Result<(), JournalError> {
        self.append_programme_once_v2(
            flight,
            original,
            writers,
            pins,
            policy,
            readonly,
            models,
            host,
            trust,
            FloorOriginV2::Recovery(acquisition),
        )
    }

    fn append_programme_once_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &RetainedUnixStream,
        writers: &mut RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        policy: &mut RootExecutionNoApplyPolicyOriginalV2,
        readonly: &mut RootCreateFinalityReadonlyOriginalV1,
        models: &RootExecutionNoApplyModelsOriginalV2,
        host: &RootExecutionNoApplyHostLeaseOriginalV2,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
        mut origin: FloorOriginV2<'_>,
    ) -> Result<(), JournalError> {
        let returned = (|| {
            if self.geometry.is_some() {
                self.reentry.get_or_insert(JournalError::ProtectedBoundary);
                return Err(JournalError::ProtectedBoundary);
            }
            if let FloorOriginV2::Recovery(acquisition) = &mut origin {
                acquisition.require_floor_connection_once_v2(original)?;
                trust.narrow_recovery_cap_v2(acquisition)?;
            }
            self.geometry = Some((|| {
                let (authority, policy) = writers.authority_and_policy()?;
                let bytes = size_of::<Native>()
                    .checked_mul(2)
                    .and_then(|bytes| bytes.checked_add(3 * size_of::<Self>()))
                    .and_then(|bytes| {
                        bytes.checked_add(RetainedKernelNonceOriginalV1::construction_bytes_v1()?)
                    })
                    .and_then(|bytes| {
                        bytes.checked_add(4 * (MAXIMUM_FLOOR + HEAD_BYTES + INSTANCE_BYTES))
                    })
                    .and_then(|bytes| bytes.checked_add(9 * size_of::<JournalRecord>()))
                    .and_then(|bytes| bytes.checked_add(6 * size_of::<usize>()))
                    .and_then(|bytes| bytes.checked_add(2 * size_of::<FloorOriginV2<'_>>()))
                    .and_then(|bytes| u64::try_from(bytes).ok())
                    .ok_or(JournalError::JournalTooLarge)?;
                let mut posts = aos_sandbox_model::ResourceVector::ZERO;
                for journal in [&*authority, policy] {
                    let one = journal.root_names_post_demand_v1()?;
                    posts = posts.checked_add(one)?.checked_add(one)?;
                }
                authority
                    .create_storage_semantic_append_demand_v1()?
                    .checked_add(posts)?
                    .checked_add(signer::RootFloorSignerV2::receiving_demand_v2()?)?
                    .checked_add(RootPolicyJournalServingIdentityV1::pair_demand_v1()?)?
                    .checked_add(RootPolicyJournalServingIdentityV1::pair_demand_v1()?)?
                    .checked_add(
                        RootControllerPeerCurrentSampleV1::demand_v1()
                            .map_err(|_| JournalError::ProtectedBoundary)?,
                    )?
                    .checked_add(ResourceVector::ZERO.with(D::MemoryBytes, bytes))
                    .map_err(JournalError::ReceivingAccounting)
            })());
            let demand = self
                .geometry
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .copied()
                .ok_or(JournalError::ProtectedBoundary)?;
            self.funding = Some(flight.execution_no_apply_stage_receiving_v2().and_then(
                |mut stage| {
                    stage.admit_execution_no_apply_floor_once_v2(
                        RootContinuationDemandV1::from_demand_v1(demand),
                    )
                },
            ));
            if !matches!(self.funding, Some(Ok(()))) {
                return Err(JournalError::ProtectedBoundary);
            }
            self.native = Some(Box::new(Native {
                history: None,
                entropy_original: RetainedKernelNonceOriginalV1::new(),
                entropy: None,
                before: None,
                floor: None,
                record: None,
                head: None,
                instance: None,
                transaction: None,
                crossing: loan::Crossing::new(),
                signer: signer::RootFloorSignerV2::new(),
                signing: None,
                append: None,
                readback: None,
                end: None,
                after: None,
                body: None,
                external_trust: false,
            }));
            let native = self
                .native
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?;
            readonly.finish_posts_once_v1();
            native.body = Some(native.append_body_v2(
                flight, original, writers, pins, policy, readonly, models, host, trust, &origin,
            ));
            native.external_trust = trust.failure().is_some();
            // Every armed native destination runs despite an earlier refusal.
            native.crossing.finish_after_once(writers);
            trust.finish_posts_once_v2();
            // The same policy interval's already-armed after originals must
            // complete against the certified append before any signature escapes.
            self.policy_post =
                Some(policy.finish_execution_floor_pair_once_v2(writers, pins, self));
            let native = self
                .native
                .as_mut()
                .ok_or(JournalError::ProtectedBoundary)?;
            if matches!(self.policy_post, Some(Ok(()))) {
                native.signing = Some(
                    native.sign_completed_once_v2(writers, pins, policy, readonly, host, trust),
                );
            }
            native.signer.finish_posts_once_v2();
            self.attestation_bytes_v2().map(|_| ())
        })();
        // These obligations belong to earlier paid reader/trust/policy stages.
        // They remain owed even if254 geometry or admission refused before its
        // native prefix existed. No new254 work is performed in that case.
        readonly.finish_posts_once_v1();
        trust.finish_posts_once_v2();
        if self.policy_post.is_none() {
            self.policy_post = Some(policy.finish_actual_pair_once_v1(writers, pins));
        }
        returned
    }

    pub(crate) fn attestation_bytes_v2(&self) -> Result<&[u8], JournalError> {
        self.body_native_v2()?.signer.packet_bytes_v2()
    }

    pub(crate) fn floor_data_v2(&self) -> Result<Floor, JournalError> {
        let native = self.body_native_v2()?;
        native
            .floor
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)
    }

    fn completed_append_native_v2(&self) -> Result<&Native, JournalError> {
        let native = self
            .native
            .as_deref()
            .ok_or(JournalError::ProtectedBoundary)?;
        if self.reentry.is_some()
            || !matches!(self.funding, Some(Ok(())))
            || !matches!(native.body, Some(Ok(())))
            || native.failure_before_signing().is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        native.crossing.require_complete()?;
        Ok(native)
    }

    fn body_native_v2(&self) -> Result<&Native, JournalError> {
        let native = self.completed_append_native_v2()?;
        if !matches!(self.policy_post, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        native.signer.packet_bytes_v2()?;
        Ok(native)
    }

    /// Joins only the actual completed append to the same policy interval's cuts.
    pub(crate) fn require_policy_successor_v2(
        &self,
        writers: &RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        before: &[RootPolicyJournalServingIdentityV1; 2],
    ) -> Result<(), JournalError> {
        let native = self.completed_append_native_v2()?;
        let saved = native
            .before
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        for index in 0..2 {
            saved[index].require_same_captured_cut_v2(&before[index])?;
        }
        writers.require_serving_identities_v1(
            native
                .after
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?,
        )?;
        writers
            .require_serving_pins_v1(pins)
            .map_err(|_| JournalError::ProtectedBoundary)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.geometry
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .map(|cause| cause as _)
            .or_else(|| {
                self.funding
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.native.as_ref()?.failure_before_signing())
            .or_else(|| {
                self.policy_post
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.native.as_ref()?.failure())
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }
}

impl Native {
    fn append_body_v2(
        &mut self,
        flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        original: &RetainedUnixStream,
        writers: &mut RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        policy_interval: &RootExecutionNoApplyPolicyOriginalV2,
        readonly: &RootCreateFinalityReadonlyOriginalV1,
        models: &RootExecutionNoApplyModelsOriginalV2,
        host: &RootExecutionNoApplyHostLeaseOriginalV2,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
        origin: &FloorOriginV2<'_>,
    ) -> Result<(), Cause> {
        self.signer.prepare_once_v2()?;
        let plan = models.plan_data_v2()?;
        let lease = host.lease_data_v2()?;
        let fields = lease.fields();
        match origin {
            FloorOriginV2::Active => {
                if fields.scope != aos_sandbox_protocol::host_execution_no_apply::current_lease::HostNoApplyLeaseScopeV2::Active {
                    return Err(JournalError::ProtectedBoundary.into());
                }
            }
            FloorOriginV2::Recovery(acquisition) => acquisition.require_floor_inputs_v2(
                writers, pins, policy_interval, readonly, models, host)?,
        }
        if fields.marker
            != HostExecutionNoApplyRecordV2::ClosedV2BeforeArgument(plan.marker_data_v2())
            || fields.terminal_archive_head != *plan.terminal_archive_data_v2().as_bytes()
            || fields.signed_terminal_outcome != *plan.signed_terminal_data_v2().as_bytes()
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let controller_cut = readonly
            .execution_no_apply_current_data_v2()?
            .global_controller_cut_data_v2()?;
        self.before = Some(writers.serving_identities_v1());
        let (authority, policy) = writers.authority_and_policy()?;
        policy_interval.require_prepared_floor_pair_v2(authority, policy, pins)?;
        self.crossing.arm_once(authority, policy)?;
        self.history = Some(history::inspect_history_data_v2(
            authority.historical_read_view_v1(),
            *plan.operation_data_v2().as_bytes(),
        ).map_err(JournalError::from));
        let history = self
            .history
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        require_prepared_root_reference_data_v2(authority, plan)?;
        let instance = match history.instance_data_v2() {
            Some(instance) => instance,
            None => {
                self.entropy = Some(self.entropy_original.observe_once());
                Instance::new(
                    *self
                        .entropy
                        .as_ref()
                        .and_then(|value| value.as_ref().ok())
                        .ok_or(JournalError::ProtectedBoundary)?,
                )?
            }
        };
        self.instance = history.instance_data_v2().is_none().then_some(instance);
        let sample = trust.next_sample_v2()?;
        if let FloorOriginV2::Recovery(acquisition) = origin {
            acquisition.require_cleanup_sample_v2(policy_interval, sample)?;
        }
        let sources = policy_interval
            .verified_v1()
            .ok_or(JournalError::ProtectedBoundary)?;
        if sample.wall_seconds() >= sources.0.head().expires_at().min(sources.1.expires_at()) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        let (predecessor_rows, successor_rows) = plan.row_digests_data_v2();
        self.floor = Some((|| {
            let record = Floor::new(FloorFields {
                root_instance: instance.instance(),
                operation: *plan.operation_data_v2().as_bytes(),
                revision: history
                    .selected_data_v2()
                    .map_or(Some(1), |old| old.fields().revision.checked_add(1))
                    .ok_or(JournalError::SequenceExhausted)?,
                authority_next: authority.snapshot_sequence(),
                predecessor_floor: history.selected_data_v2().map_or([0; 32], |old| old.digest()),
                policy_commitment: *sources.0.head().packet_digest().as_bytes(),
                controller_cut,
                host_lease: lease,
                signed_current_outcome: host.signed_outcome_data_v2()?,
                predecessor_rows,
                successor_rows,
                terminal_wall_seconds: plan.wall_seconds_data_v2(),
            })?;
            if let Some(old) = history.selected_data_v2() {
                history::require_immutable_successor_data_v2(old, record)?;
            }
            Ok(record)
        })());
        let floor = self
            .floor
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        if let FloorOriginV2::Recovery(acquisition) = origin {
            acquisition.require_proposed_floor_v2(floor)?;
        }
        self.record = Some(floor.encode_canonical());
        self.head = Some(Head::from_floor_data_v2(floor).encode_canonical());
        self.transaction = Some(prepare_transaction_data_v2(
            floor,
            self.record
                .as_deref()
                .ok_or(JournalError::ProtectedBoundary)?,
            self.head.as_ref().ok_or(JournalError::ProtectedBoundary)?,
            self.instance,
        ));
        let transaction = self
            .transaction
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let before = self
            .before
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let mut loan = loan::RootExecutionNoApplyFloorAppendLoanV2::new(
            flight,
            original,
            policy,
            pins,
            policy_interval,
            readonly,
            host,
            trust,
            before,
            floor,
            transaction,
            &mut self.crossing,
        );
        self.append =
            Some(authority.commit_execution_no_apply_floor_original_v2(transaction, &mut loan));
        if matches!(self.append, Some(Ok(_))) {
            self.readback = Some(require_readback_data_v2(
                authority,
                transaction,
                floor,
                self.append
                    .as_ref()
                    .and_then(|value| value.as_ref().ok())
                    .ok_or(JournalError::ProtectedBoundary)?,
            ));
            self.end = Some(authority.held_native_receiving_metadata_v1().0);
        }
        if !matches!(self.readback, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        if self
            .end
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .map(Metadata::len)
            != self
                .append
                .as_ref()
                .and_then(|value| value.as_ref().ok())
                .map(|value| value.durable_bytes)
        {
            return Err(JournalError::ProtectedBoundary.into());
        }
        self.after = Some(writers.serving_identities_v1());
        if !matches!(self.after, Some(Ok(_))) {
            return Err(JournalError::ProtectedBoundary.into());
        }
        Ok(())
    }

    fn sign_completed_once_v2(
        &mut self,
        writers: &mut RootCreateStorageCurrentWritersV1,
        pins: &RootCurrentPinsStateV1,
        interval: &RootExecutionNoApplyPolicyOriginalV2,
        readonly: &RootCreateFinalityReadonlyOriginalV1,
        host: &RootExecutionNoApplyHostLeaseOriginalV2,
        trust: &mut RootExecutionNoApplyHostTrustOriginalV2,
    ) -> Result<(), JournalError> {
        let (authority, policy) = writers.authority_and_policy()?;
        let loan = signer::CompletedFloorSigningLoanV2 {
            authority,
            policy,
            pins,
            interval,
            readonly,
            host,
            before: self
                .before
                .as_ref()
                .and_then(|v| v.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?,
            after: self
                .after
                .as_ref()
                .and_then(|v| v.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?,
            transaction: self
                .transaction
                .as_ref()
                .and_then(|v| v.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?,
            committed: self
                .append
                .as_ref()
                .and_then(|v| v.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?,
            floor: *self
                .floor
                .as_ref()
                .and_then(|v| v.as_ref().ok())
                .ok_or(JournalError::ProtectedBoundary)?,
            crossing: &self.crossing,
        };
        self.signer.sign_once_v2(&loan, trust);
        self.signer.packet_bytes_v2().map(|_| ())
    }

    fn failure_before_signing(&self) -> Option<&(dyn Error + 'static)> {
        self.signer
            .prepare_failure()
            .or_else(|| self.before.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.history
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.entropy_original.failure())
            .or_else(|| {
                self.entropy
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| {
                self.floor
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause.as_ref())
            })
            .or_else(|| {
                self.transaction
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.crossing.before_failure())
            .or_else(|| self.append.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                self.readback
                    .as_ref()?
                    .as_ref()
                    .err()
                    .map(|cause| cause as _)
            })
            .or_else(|| self.end.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| self.after.as_ref()?.as_ref().err().map(|cause| cause as _))
            .or_else(|| {
                (!self.external_trust && !self.crossing.external_trust_failed())
                    .then_some(())
                    .and_then(|()| {
                        self.body
                            .as_ref()?
                            .as_ref()
                            .err()
                            .map(|cause| cause.as_ref())
                    })
            })
            .or_else(|| self.crossing.after_failure())
    }

    fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.failure_before_signing()
            .or_else(|| self.signer.failure())
            .or_else(|| {
                (!self.signer.external_trust_failed())
                    .then_some(())
                    .and_then(|()| {
                        self.signing
                            .as_ref()?
                            .as_ref()
                            .err()
                            .map(|cause| cause as _)
                    })
            })
    }
}

fn require_prepared_root_reference_data_v2(
    authority: &Journal,
    plan: &aos_sandbox_protocol::domain_ledger::create_failure::ClosedCreateFailurePlanDataV2,
) -> Result<(), JournalError> {
    let Some((digest, next)) = plan.prepared_root_reference_data_v2() else {
        return Ok(());
    };
    for (key, bytes) in
        authority.historical_read_view_v1().records(crate::journal::RecordNamespace::RootExecutionNoApplyFloorV2)
    {
        if key.len() != 24 {
            continue;
        }
        let floor =
            Floor::decode_canonical(key, bytes).map_err(|_| JournalError::ProtectedBoundary)?;
        if floor.digest() == *digest.as_bytes()
            && floor.fields().revision == next
            && floor.fields().operation == *plan.operation_data_v2().as_bytes()
        {
            return Ok(());
        }
    }
    Err(JournalError::ProtectedBoundary)
}

fn prepare_transaction_data_v2(
    floor: Floor,
    record: &[u8],
    head: &[u8; HEAD_BYTES],
    instance: Option<Instance>,
) -> Result<JournalTransaction, JournalError> {
    let namespace = crate::journal::RecordNamespace::RootExecutionNoApplyFloorV2;
    let mut rows = Vec::with_capacity(if instance.is_some() { 3 } else { 2 });
    if let Some(instance) = instance {
        rows.push(JournalRecord::put(
            namespace,
            INSTANCE_KEY.to_vec(),
            instance.encode_canonical().to_vec(),
        ));
    }
    rows.push(JournalRecord::put(
        namespace,
        floor.key().encode_canonical().to_vec(),
        record.to_vec(),
    ));
    rows.push(JournalRecord::put(
        namespace,
        floor.key().head_key_data_v2().to_vec(),
        head.to_vec(),
    ));
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.root.execution-no-apply-transaction.v2\0")
        .chain_update(floor.digest())
        .finalize();
    Ok(JournalTransaction::new(
        digest[..16]
            .try_into()
            .map_err(|_| JournalError::ProtectedBoundary)?,
        rows,
    )?)
}

fn require_readback_data_v2(
    authority: &Journal,
    transaction: &JournalTransaction,
    floor: Floor,
    committed: &CommitResult,
) -> Result<(), JournalError> {
    let count =
        u64::try_from(transaction.records().len()).map_err(|_| JournalError::JournalTooLarge)?;
    if floor
        .fields()
        .authority_next
        .checked_add(count)
        .and_then(|next| next.checked_add(2))
        != Some(authority.snapshot_sequence())
        || committed.commit_sequence.checked_add(1) != Some(authority.snapshot_sequence())
    {
        return Err(JournalError::ProtectedBoundary);
    }
    for row in transaction.records() {
        if row.value() != authority.historical_read_view_v1().get(row.namespace(), row.key()) {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    history::inspect_history_data_v2(authority.historical_read_view_v1(), floor.fields().operation)?;
    Ok(())
}
