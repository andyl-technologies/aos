//! Genuine startup and original-main comparisons for the closed deployment purpose.
//!
//! Move-only guards retain the original Journal borrow, protected name witness
//! and opaque snapshot. Current and prospective values are DATA comparisons,
//! not authenticated NV, a floor, a commit permit or guest readiness. The later
//! closed physical owner must separately retain both writers and authenticate
//! its helper, sidecar and fresh NV around every physical operation.
//!
//! No guard opens a Journal, exports its data descriptor, signs a phase or
//! mutates durable state. Native history, complete signed schema, credentials,
//! prepared transaction bytes and head hashing remain in their existing owners.

use std::collections::BTreeMap;

use aos_sandbox_linux::pidfd::PidFd;
use aos_sandbox_protocol::runtime_deployment::DeploymentGenesisV1;

use crate::immutable_image::RetainedImmutableFileV1;
use crate::journal::{
    Journal, JournalError, JournalLimits, JournalTransaction, ProtectedJournalLockCustodyV1,
    ProtectedJournalPreflight, ProtectedJournalSnapshot, ProtectedWriterNameWitness,
    RetainedDeploymentNativeHistoryV1, RuntimeDeploymentNativeTransactionDataV1,
};
use crate::tpm_nv_custody::{
    NvCustodyEndpointV1, NvCustodyErrorV1, canonical_purpose_main_head_v1,
};

use super::genesis::{NAMESPACE, VerifiedDeploymentGenesisV1};
use super::preparation::{
    MAIN_LIMITS, compared_deployment_native_prefix_v1,
    compared_prospective_deployment_head_v1, compared_retained_deployment_transition_v1,
    require_current_deployment_rows_v1, require_deployment_main_v1,
};
use super::{ProductionRuntimeDeploymentStartupV1, RuntimeDeploymentStartupErrorV1};
use super::{HostPhysicalInvocationErrorV1, HostPhysicalInvocationLeaseV1};

/// Reports rejection of a genuine deployment comparison or original lock loan.
#[derive(Debug, thiserror::Error)]
#[error("deployment original-main comparison rejected")]
pub struct RuntimeDeploymentComparisonErrorV1 {
    #[source]
    cause: ComparisonFailureV1,
}

#[derive(Debug, thiserror::Error)]
enum ComparisonFailureV1 {
    #[error("deployment fixed-purpose comparison differs")]
    Purpose(#[source] NvCustodyErrorV1),
    #[error("deployment original Journal differs")]
    Journal(#[source] JournalError),
    #[error("deployment original startup or child population differs")]
    Startup(#[source] RuntimeDeploymentStartupErrorV1),
    #[error("deployment comparison guard is unusable")]
    Unusable,
    #[error("deployment retained comparison differs")]
    Changed,
}

impl From<NvCustodyErrorV1> for RuntimeDeploymentComparisonErrorV1 {
    fn from(error: NvCustodyErrorV1) -> Self {
        Self {
            cause: ComparisonFailureV1::Purpose(error),
        }
    }
}

impl From<JournalError> for RuntimeDeploymentComparisonErrorV1 {
    fn from(error: JournalError) -> Self {
        Self {
            cause: ComparisonFailureV1::Journal(error),
        }
    }
}

impl From<RuntimeDeploymentStartupErrorV1> for RuntimeDeploymentComparisonErrorV1 {
    fn from(error: RuntimeDeploymentStartupErrorV1) -> Self {
        Self {
            cause: ComparisonFailureV1::Startup(error),
        }
    }
}

/// Retains genuine original startup and independently admitted deployment inputs.
///
/// Construction accepts only the existing actual startup owner. Its privately
/// retained seed has no getter or signing API. Borrowed genesis and PID1 views
/// are admitted input DATA, not fresh floor or physical-currentness proofs.
#[must_use = "deployment comparison origins must remain borrowed by their guards"]
pub struct RuntimeDeploymentComparisonOriginsV1<'startup> {
    genesis: VerifiedDeploymentGenesisV1<'startup>,
}

impl<'startup> RuntimeDeploymentComparisonOriginsV1<'startup> {
    /// Returns the existing fixed main limits as rechecked input DATA.
    ///
    /// This exposes no writer, reservation or permission to select other limits.
    ///
    /// # Errors
    ///
    /// Rejects drift of the same genuine startup or fixed genesis credentials.
    pub fn compared_main_limits(&self) -> Result<JournalLimits, RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        let limits = MAIN_LIMITS;
        self.recheck()?;
        Ok(limits)
    }

    /// Admits the fixed signed genesis through the existing genuine startup owner.
    ///
    /// # Errors
    ///
    /// Rejects changed startup, unavailable or substituted fixed credentials,
    /// bad signatures, role reuse or a deployment-purpose binding mismatch.
    pub fn admit(
        startup: &'startup ProductionRuntimeDeploymentStartupV1,
    ) -> Result<Self, RuntimeDeploymentComparisonErrorV1> {
        Ok(Self {
            genesis: VerifiedDeploymentGenesisV1::open(startup)?,
        })
    }

    /// Rechecks the same actual startup and independently fixed genesis roles.
    ///
    /// # Errors
    ///
    /// Rejects startup, policy, image, service or fixed credential drift.
    pub fn recheck(&self) -> Result<(), RuntimeDeploymentComparisonErrorV1> {
        self.genesis.recheck().map_err(Into::into)
    }

    /// Claims the original publisher's one physical invocation before any attempt.
    ///
    /// All Origins admitted from the same actual startup share the one-shot.
    /// Failure, unwind or lease drop permanently prevents another claim in
    /// that invocation. Comparison-only APIs remain non-authorizing DATA.
    /// This neither authenticates NV nor proves full-population retirement.
    ///
    /// # Errors
    ///
    /// Rejects a held or terminal invocation, original startup/genesis drift,
    /// or failure to retain and recheck the same actual cgroup population.
    pub fn claim_host_physical_invocation<'origin>(
        &'origin self,
    ) -> Result<HostPhysicalInvocationLeaseV1<'origin, 'startup>, HostPhysicalInvocationErrorV1> {
        HostPhysicalInvocationLeaseV1::claim(self)
    }

    pub(super) fn host_physical_invocation_startup(&self) -> &ProductionRuntimeDeploymentStartupV1 {
        self.genesis.startup()
    }

    /// Borrows the exact admitted signed genesis as historical input DATA.
    #[must_use]
    pub fn signed_genesis(&self) -> &[u8] {
        self.genesis.exact_bytes()
    }

    /// Borrows the independently admitted genesis claims without floor authority.
    ///
    /// NV and salt Names here are provisioning inputs, not fresh device readback.
    #[must_use]
    pub fn genesis_claims(&self) -> &DeploymentGenesisV1 {
        self.genesis.claims()
    }

    /// Borrows the actual originally captured PID1 file, not a reopened image.
    #[must_use]
    pub fn retained_pid1(&self) -> &RetainedImmutableFileV1 {
        self.genesis.startup().retained_pid1()
    }

    /// Compares a retained child's actual parent and fixed cgroup population.
    ///
    /// This reuses original startup custody. It does not authenticate the
    /// child's helper image, loader, MAC, credentials or physical TPM session.
    ///
    /// # Errors
    ///
    /// Rejects origin drift, a stale pidfd or a different parent/cgroup.
    pub fn require_child(&self, child: &PidFd) -> Result<(), RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        self.genesis.startup().require_child(child)?;
        self.recheck()
    }

    /// Borrows and compares the already-held original fixed deployment Journal.
    ///
    /// The guard retains the same mutable Journal borrow and original protected
    /// names. No writer is reopened, cloned, repaired, initialized or committed.
    ///
    /// # Errors
    ///
    /// Rejects origin drift, a wrong path/owner/limit set, stale names, unhealthy
    /// Journal, foreign or oversized rows, native-history or signed-schema
    /// disagreement, or an inconsistent protected snapshot.
    pub fn hold_main<'origin, 'main>(
        &'origin self,
        main: &'main mut Journal,
    ) -> Result<
        HeldRuntimeDeploymentMainComparisonV1<'origin, 'startup, 'main>,
        RuntimeDeploymentComparisonErrorV1,
    > {
        self.recheck()?;
        require_deployment_main_v1(&self.genesis, main)?;
        let witness = main.protected_writer_name_witness()?;
        let snapshot = main.claim_protected_authority(NAMESPACE)?.snapshot()?;
        let head = compared_current_head(&self.genesis, main, snapshot.sequence())?;

        let mut held = HeldRuntimeDeploymentMainComparisonV1 {
            origins: self,
            main,
            witness,
            snapshot,
            head,
            usable: true,
        };
        held.recheck()?;
        Ok(held)
    }

    /// Holds the actual original main and independent fixed sidecar.
    ///
    /// Main signed/native history remains fully authenticated by its existing
    /// engine. Sidecar observations are mechanical native DATA, not canonical
    /// checkpoint admission: the closed Security store must separately compare
    /// all eight derived limits and the complete typed retained transition chain.
    /// No writer is opened, initialized, committed, repaired or loaned here.
    ///
    /// # Errors
    ///
    /// Rejects origin/main drift, wrong protected sidecar names or ownership,
    /// aliased data/lock identities, unbounded limits, incomplete/foreign native
    /// history, snapshot disagreement or failed before/after physical checks.
    pub fn hold_pair<'origin, 'main, 'sidecar>(
        &'origin self,
        main: &'main mut Journal,
        sidecar: &'sidecar mut Journal,
    ) -> Result<
        HeldRuntimeDeploymentPairComparisonV1<'origin, 'startup, 'main, 'sidecar>,
        RuntimeDeploymentComparisonErrorV1,
    > {
        self.recheck()?;
        let current = self.hold_main(main)?;
        let main_history = current.main.capture_runtime_deployment_main_history_v1(&self.genesis)?;
        let sidecar_history = sidecar.capture_runtime_deployment_sidecar_history_v1(&self.genesis)?;
        current.main.require_deployment_pair_independence_v1(sidecar)?;
        let witness = sidecar.protected_writer_name_witness()?;
        let snapshot = sidecar.claim_protected_authority(NAMESPACE)?.snapshot()?;
        let limits = sidecar.configured_limits();
        let mut pair = HeldRuntimeDeploymentPairComparisonV1 {
            current,
            main_history,
            sidecar,
            witness,
            snapshot,
            limits,
            sidecar_history,
            usable: true,
        };
        pair.recheck()?;
        Ok(pair)
    }
}

/// Retains a genuine original pair and its bounded native transaction histories.
///
/// There is no constructor from DATA and no raw-writer, mutation, loan or floor
/// API. A failure or unwind closes this guard, not the underlying Journals.
/// The later private owning consumer must retain/fence both writers itself.
#[must_use = "the genuine original pair must remain held through comparison"]
pub struct HeldRuntimeDeploymentPairComparisonV1<'origin, 'startup, 'main, 'sidecar> {
    current: HeldRuntimeDeploymentMainComparisonV1<'origin, 'startup, 'main>,
    main_history: RetainedDeploymentNativeHistoryV1,
    sidecar: &'sidecar mut Journal,
    witness: ProtectedWriterNameWitness,
    snapshot: ProtectedJournalSnapshot,
    limits: JournalLimits,
    sidecar_history: RetainedDeploymentNativeHistoryV1,
    usable: bool,
}

impl HeldRuntimeDeploymentPairComparisonV1<'_, '_, '_, '_> {
    /// Rechecks the same original pair, full native snapshots and genuine Origins.
    ///
    /// # Errors
    ///
    /// Rejects any drift, prior failure, identity alias, changed retained native
    /// transaction/boundary or failed parse/physical/signed-schema comparison.
    pub fn recheck(&mut self) -> Result<(), RuntimeDeploymentComparisonErrorV1> {
        self.begin_operation()?;
        self.recheck_inner()?;
        self.usable = true;
        Ok(())
    }

    /// Returns the rechecked current main native cut and complete HEAD as DATA.
    ///
    /// # Errors
    ///
    /// Rejects any original pair/origin drift or an unusable guard.
    pub fn compared_current(
        &mut self,
    ) -> Result<(u64, [u8; 32]), RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        Ok((self.current.snapshot.sequence(), self.current.head))
    }

    /// Returns rechecked signed-genesis scope DATA, never a fresh NV observation.
    ///
    /// # Errors
    ///
    /// Rejects any original pair/origin drift or an unusable guard.
    pub fn compared_scope(&mut self) -> Result<[u8; 32], RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        Ok(self.current.origins.genesis.scope())
    }

    /// Returns all eight actually configured sidecar limits as comparison DATA.
    ///
    /// The closed consumer must compare these to its sole derived limits engine.
    ///
    /// # Errors
    ///
    /// Rejects any original pair/origin drift or an unusable guard.
    pub fn compared_sidecar_limits(
        &mut self,
    ) -> Result<JournalLimits, RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        Ok(self.limits)
    }

    /// Returns the actual rechecked sidecar next boundary, not a capacity token.
    ///
    /// # Errors
    ///
    /// Rejects any original pair/origin drift or an unusable guard.
    pub fn compared_sidecar_sequence(&mut self) -> Result<u64, RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        Ok(self.snapshot.sequence())
    }

    /// Borrows bounded exact sidecar native DATA after complete pair rechecks.
    ///
    /// Canonical interpretation and historical main joins remain the closed
    /// consumer's responsibility. Borrowed data cannot outlive this guard.
    ///
    /// # Errors
    ///
    /// Rejects any original pair/origin drift or an unusable guard.
    pub fn sidecar_native_history(
        &mut self,
    ) -> Result<&[RuntimeDeploymentNativeTransactionDataV1], RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        Ok(self.sidecar_history.transactions())
    }

    /// Reconstructs one actual retained main prefix through the existing engine.
    ///
    /// No full-map prefixes are retained. A requested sequence must be an
    /// observed original native boundary including the admitted genesis.
    ///
    /// # Errors
    ///
    /// Rejects pair drift, an absent/mid-frame prefix or any complete signed
    /// schema/HEAD disagreement. Failed comparison leaves this guard closed.
    pub fn compare_historical_prefix(
        &mut self,
        sequence: u64,
    ) -> Result<(u64, [u8; 32]), RuntimeDeploymentComparisonErrorV1> {
        self.begin_operation()?;
        self.recheck_inner()?;
        let cut = compared_deployment_native_prefix_v1(
            &self.current.origins.genesis, self.main_history.transactions(), sequence,
        )?;
        self.recheck_inner()?;
        self.usable = true;
        Ok(cut)
    }

    /// Compares an exact already-committed phase at its original native preimage.
    ///
    /// This is retained historical comparison, never prospective current-map
    /// preflight, a second append or recovery authority. The UUID and ordered
    /// transaction bytes must match the actual captured original transaction.
    ///
    /// # Errors
    ///
    /// Rejects pair drift, absent/substituted TX, genesis reappend, or original
    /// predecessor/target/schema/HEAD disagreement. Failure stays closed.
    pub fn compare_retained_transition(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<((u64, [u8; 32]), (u64, [u8; 32])), RuntimeDeploymentComparisonErrorV1> {
        self.begin_operation()?;
        self.recheck_inner()?;
        let cuts = compared_retained_deployment_transition_v1(
            &self.current.origins.genesis, self.main_history.transactions(), transaction,
        )?;
        self.recheck_inner()?;
        self.usable = true;
        Ok(cuts)
    }

    fn begin_operation(&mut self) -> Result<(), RuntimeDeploymentComparisonErrorV1> {
        require_usable(self.usable)?;
        self.usable = false;
        Ok(())
    }

    fn recheck_inner(&mut self) -> Result<(), RuntimeDeploymentComparisonErrorV1> {
        let origins = self.current.origins;
        origins.recheck()?;
        self.current.recheck()?;
        self.sidecar.validate_protected_writer_name_witness(&self.witness)?;
        self.sidecar.claim_protected_authority(NAMESPACE)?
            .validate_snapshot_for_effect(&self.snapshot)?;
        if self.sidecar.configured_limits() != self.limits {
            return Err(changed_comparison());
        }
        self.current.main.require_deployment_pair_independence_v1(self.sidecar)?;

        let main_history = self.current.main
            .capture_runtime_deployment_main_history_v1(&origins.genesis)?;
        if main_history != self.main_history {
            return Err(changed_comparison());
        }
        drop(main_history);
        let sidecar_history = self.sidecar
            .capture_runtime_deployment_sidecar_history_v1(&origins.genesis)?;
        if sidecar_history != self.sidecar_history {
            return Err(changed_comparison());
        }
        drop(sidecar_history);

        self.current.recheck()?;
        self.sidecar.validate_protected_writer_name_witness(&self.witness)?;
        self.sidecar.claim_protected_authority(NAMESPACE)?
            .validate_snapshot_for_effect(&self.snapshot)?;
        self.current.main.require_deployment_pair_independence_v1(self.sidecar)?;
        origins.recheck()
    }
}

/// Holds the genuine original main while comparing its current signed history.
///
/// All fields stay private. Each result brackets the same original native
/// audit, complete schema, names, opaque snapshot and independently rechecked
/// origins. A failed operation makes this guard unusable, but does not create
/// a Journal-wide physical-floor poison or ordinary-writer fence.
#[must_use = "the original Journal borrow must remain held through its comparison"]
pub struct HeldRuntimeDeploymentMainComparisonV1<'origin, 'startup, 'main> {
    origins: &'origin RuntimeDeploymentComparisonOriginsV1<'startup>,
    main: &'main mut Journal,
    witness: ProtectedWriterNameWitness,
    snapshot: ProtectedJournalSnapshot,
    head: [u8; 32],
    usable: bool,
}

impl<'origin, 'startup, 'main>
    HeldRuntimeDeploymentMainComparisonV1<'origin, 'startup, 'main>
{
    /// Rechecks the same original main, native history, complete schema and origins.
    ///
    /// # Errors
    ///
    /// Rejects any drift or a previous failed guard operation. No retry resets
    /// this guard, and no fresh physical NV observation is implied.
    pub fn recheck(&mut self) -> Result<(), RuntimeDeploymentComparisonErrorV1> {
        require_usable(self.usable)?;
        let result = self.recheck_inner();
        latch_failure(&mut self.usable, result)
    }

    /// Returns rechecked current next-sequence and complete-map head DATA.
    ///
    /// # Errors
    ///
    /// Rejects an unusable guard or any original-main/origin comparison failure.
    pub fn compared_current(
        &mut self,
    ) -> Result<(u64, [u8; 32]), RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        Ok((self.snapshot.sequence(), self.head))
    }

    /// Returns the admitted signed-genesis scope after original-main rechecks.
    ///
    /// This digest is input DATA, not authenticated NV or live currentness.
    ///
    /// # Errors
    ///
    /// Rejects an unusable guard or any original-main/origin comparison failure.
    pub fn compared_scope(&mut self) -> Result<[u8; 32], RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        Ok(self.origins.genesis.scope())
    }

    /// Loans only the same original flock OFD after full comparison bookends.
    ///
    /// The existing owned loan does not borrow this guard. Its closed physical
    /// consumer must retain both original writers until helper teardown and
    /// send it only to the authentic confined helper: a trusted child can
    /// explicitly unlock a duplicated flock OFD. No data descriptor is exposed.
    ///
    /// # Errors
    ///
    /// Rejects guard drift or failed original lock duplication. A failed
    /// postcheck drops the just-created loan and makes the guard unusable.
    pub fn loan_main_lock(
        &mut self,
    ) -> Result<ProtectedJournalLockCustodyV1, RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        let result = self.main.loan_protected_lock_custody().map_err(Into::into);
        let loan = latch_failure(&mut self.usable, result)?;
        self.recheck()?;
        Ok(loan)
    }

    /// Compares one exact prospective append while retaining its original preimage.
    ///
    /// Consumes this guard and borrows the actual transaction. The result is
    /// prospective DATA with native preflight, not a commit or mutation permit.
    ///
    /// # Errors
    ///
    /// Rejects any guard drift, native limit failure, bad signed current/target
    /// map, wrong original UUID, nonimmutable append or preparation-codec error.
    pub fn compare_append<'tx>(
        mut self,
        transaction: &'tx JournalTransaction,
    ) -> Result<
        HeldRuntimeDeploymentAppendComparisonV1<'origin, 'startup, 'main, 'tx>,
        RuntimeDeploymentComparisonErrorV1,
    > {
        self.recheck()?;
        let result = self
            .main
            .claim_protected_authority(NAMESPACE)?
            .preflight_transactions(std::slice::from_ref(transaction))
            .map_err(Into::into);
        let preflight = latch_failure(&mut self.usable, result)?;
        let result = self.compared_append_data(transaction);
        let (target, prepared) = latch_failure(&mut self.usable, result)?;
        self.recheck()?;

        let mut held = HeldRuntimeDeploymentAppendComparisonV1 {
            current: self,
            transaction,
            preflight,
            target,
            prepared,
        };
        held.recheck()?;
        Ok(held)
    }

    fn recheck_inner(&mut self) -> Result<(), RuntimeDeploymentComparisonErrorV1> {
        self.origins.recheck()?;
        self.main.validate_protected_writer_name_witness(&self.witness)?;
        self.main
            .claim_protected_authority(NAMESPACE)?
            .validate_snapshot_for_effect(&self.snapshot)?;

        let head = compared_current_head(
            &self.origins.genesis, self.main, self.snapshot.sequence(),
        )?;
        if head != self.head {
            return Err(changed_comparison());
        }

        self.main.validate_protected_writer_name_witness(&self.witness)?;
        self.main
            .claim_protected_authority(NAMESPACE)?
            .validate_snapshot_for_effect(&self.snapshot)?;
        let readback = compared_current_head(
            &self.origins.genesis, self.main, self.snapshot.sequence(),
        )?;
        if readback != self.head {
            return Err(changed_comparison());
        }
        self.main.validate_protected_writer_name_witness(&self.witness)?;
        self.main
            .claim_protected_authority(NAMESPACE)?
            .validate_snapshot_for_effect(&self.snapshot)?;
        self.origins.recheck()
    }

    fn compared_append_data(
        &self,
        transaction: &JournalTransaction,
    ) -> Result<((u64, [u8; 32]), Vec<u8>), RuntimeDeploymentComparisonErrorV1> {
        // The original-main audit refuses excess rows before this borrowed map.
        require_deployment_main_v1(&self.origins.genesis, self.main)?;
        let records = self.main.records(NAMESPACE).collect::<BTreeMap<_, _>>();
        let target = compared_prospective_deployment_head_v1(
            &self.origins.genesis, self.snapshot.sequence(), &records, transaction,
        )?;
        let prepared = transaction.encode_prepared_v1(MAIN_LIMITS)?;
        let maximum = JournalTransaction::maximum_prepared_bytes_v1(MAIN_LIMITS)?;
        if prepared.len() > maximum {
            return Err(changed_comparison());
        }
        Ok((target, prepared))
    }
}

/// Holds exact prospective append DATA under genuine original-main comparison.
///
/// The private borrowed transaction and opaque preflight preserve original
/// UUID, ordered records and values. Target head and prepared bytes have not
/// been observed as a durable native append. This guard signs or commits nothing.
#[must_use = "prospective DATA must retain its original transaction and Journal borrow"]
pub struct HeldRuntimeDeploymentAppendComparisonV1<'origin, 'startup, 'main, 'tx> {
    current: HeldRuntimeDeploymentMainComparisonV1<'origin, 'startup, 'main>,
    transaction: &'tx JournalTransaction,
    preflight: ProtectedJournalPreflight,
    target: (u64, [u8; 32]),
    prepared: Vec<u8>,
}

impl HeldRuntimeDeploymentAppendComparisonV1<'_, '_, '_, '_> {
    /// Rechecks actual current history and the same exact prospective transaction.
    ///
    /// # Errors
    ///
    /// Rejects current drift, stale/mismatched preflight, changed prospective
    /// schema/bytes or a previous guard failure. Never resets physical debt.
    pub fn recheck(&mut self) -> Result<(), RuntimeDeploymentComparisonErrorV1> {
        self.current.recheck()?;
        let result = self.recheck_inner();
        latch_failure(&mut self.current.usable, result)?;
        self.current.recheck()
    }

    /// Returns rechecked current next-sequence and complete-map head DATA.
    ///
    /// # Errors
    ///
    /// Rejects current, prospective or previously latched comparison failure.
    pub fn compared_current(
        &mut self,
    ) -> Result<(u64, [u8; 32]), RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        Ok((self.current.snapshot.sequence(), self.current.head))
    }

    /// Returns rechecked prospective next-sequence and target head DATA.
    ///
    /// These are not a durable observation, floor receipt or append permission.
    ///
    /// # Errors
    ///
    /// Rejects current, prospective or previously latched comparison failure.
    pub fn compared_target(
        &mut self,
    ) -> Result<(u64, [u8; 32]), RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        Ok(self.target)
    }

    /// Returns admitted signed-genesis scope after both comparison bookends.
    ///
    /// # Errors
    ///
    /// Rejects current, prospective or previously latched comparison failure.
    pub fn compared_scope(&mut self) -> Result<[u8; 32], RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        Ok(self.current.origins.genesis.scope())
    }

    /// Borrows exact bounded AOSJPT01 preparation DATA after both rechecks.
    ///
    /// The existing native codec owns these bytes. Their width is derived from
    /// the unchanged actual main limits and reserves no floor suffix or storage.
    ///
    /// # Errors
    ///
    /// Rejects current, prospective or previously latched comparison failure.
    pub fn prepared_bytes(&mut self) -> Result<&[u8], RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        Ok(&self.prepared)
    }

    /// Loans the original main flock OFD after current and prospective bookends.
    ///
    /// Both original writers must outlive the authentic confined helper; this
    /// owned lock-only loan is not an effect or fresh-currentness capability.
    ///
    /// # Errors
    ///
    /// Rejects comparison drift or failed duplication. A failed postcheck drops
    /// the new loan and latches this guard unusable.
    pub fn loan_main_lock(
        &mut self,
    ) -> Result<ProtectedJournalLockCustodyV1, RuntimeDeploymentComparisonErrorV1> {
        self.recheck()?;
        let loan = self.current.loan_main_lock()?;
        self.recheck()?;
        Ok(loan)
    }

    fn recheck_inner(&mut self) -> Result<(), RuntimeDeploymentComparisonErrorV1> {
        self.current
            .main
            .claim_protected_authority(NAMESPACE)?
            .validate_preflight_for_effect(
                &self.preflight, std::slice::from_ref(self.transaction),
            )?;
        let (target, prepared) = self.current.compared_append_data(self.transaction)?;
        if target != self.target || prepared != self.prepared {
            return Err(changed_comparison());
        }
        Ok(())
    }
}

fn compared_current_head(
    owner: &VerifiedDeploymentGenesisV1<'_>,
    main: &Journal,
    sequence: u64,
) -> Result<[u8; 32], RuntimeDeploymentComparisonErrorV1> {
    require_deployment_main_v1(owner, main)?;
    let records = main.records(NAMESPACE).collect::<BTreeMap<_, _>>();
    require_current_deployment_rows_v1(owner, sequence, &records)?;
    canonical_purpose_main_head_v1(
        NvCustodyEndpointV1::RuntimeDeployment, owner.scope(), sequence, &records,
    )
    .map_err(Into::into)
}

fn require_usable(usable: bool) -> Result<(), RuntimeDeploymentComparisonErrorV1> {
    if !usable {
        return Err(RuntimeDeploymentComparisonErrorV1 {
            cause: ComparisonFailureV1::Unusable,
        });
    }
    Ok(())
}

/// Latches only private comparison health, never Journal or floor authority.
fn latch_failure<T>(
    usable: &mut bool,
    result: Result<T, RuntimeDeploymentComparisonErrorV1>,
) -> Result<T, RuntimeDeploymentComparisonErrorV1> {
    if result.is_err() {
        *usable = false;
    }
    result
}

fn changed_comparison() -> RuntimeDeploymentComparisonErrorV1 {
    RuntimeDeploymentComparisonErrorV1 {
        cause: ComparisonFailureV1::Changed,
    }
}

#[cfg(test)]
mod tests;
