//! Prepares the same original enrollment mutation for its real Bank stage.
//!
//! These private values are derived only from the retained Controller startup
//! original and its actual compiled layout. Protocol retains the sole account,
//! subdivision, codec and replay predicates. No public constructor, grant or
//! caller-supplied resource vector is introduced here.

use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::resource_bank::{self as bank, AccountHead, Claim};

use crate::receiving::OriginalEnrollment;
use super::ControllerBankLaunchErrorV1;

type State = std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

pub(super) struct EnrollmentTransitionV1 {
    transaction_id: [u8; 16],
    heads: [AccountHead; 3],
    claims: [Claim; 2],
    host: Option<(AccountHead, [Claim; 2])>,
    first_global: Option<Claim>,
    nix_intake: Option<Claim>,
    q04_intake: Option<Claim>,
    root_receiving: Option<Claim>,
    create_intake: Option<Claim>,
    storage_receiving: Option<Claim>,
    delete_operation_intake: Option<Claim>,
    execution_operation_intake: Option<Claim>,
    host_execution_prepare: Option<Claim>,
    host_execution_accept: Option<Claim>,
    recipient_precharge: Option<bank::RecipientIncarnation>,
}

impl EnrollmentTransitionV1 {
    pub(super) fn prepare(
        original: &OriginalEnrollment,
        layout: bank::NativeLayoutDemand,
    ) -> Result<Self, ControllerBankLaunchErrorV1> {
        let identity = original.identity;
        let policy = original.policy;
        let (heads, host, first_global, nix_intake, q04_intake, root_receiving, create_intake, storage_receiving) =
            bank::prepare_enrollment_subdivisions(
                identity,
                policy,
                layout,
            )
            .map_err(ControllerBankLaunchErrorV1::from)?;

        let delete_operation_intake = bank::delete_operation_intake_claim(identity, policy)
            .map_err(ControllerBankLaunchErrorV1::from)?;

        let execution_operation_intake = bank::execution_operation_intake_claim(identity, policy)
            .map_err(ControllerBankLaunchErrorV1::from)?;

        let host_execution_prepare = bank::host_execution_prepare_claim(identity, policy)
            .map_err(ControllerBankLaunchErrorV1::from)?;

        let host_execution_accept = bank::host_execution_accept_claim(identity, policy)
            .map_err(ControllerBankLaunchErrorV1::from)?;

        let recipient_precharge = bank::initial_recipient_precharge_v1(identity, policy, original.recipient_invocation)?;
        if recipient_precharge.is_some() && original.controller_generation_v1 != Some(0) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        Ok(Self {
            transaction_id: aos_sandbox_model::OperationId::new().into_bytes(),
            heads,
            claims: bank::initial_enrollment_claims(identity, policy, &heads),
            host,
            first_global,
            nix_intake,
            q04_intake,
            root_receiving,
            create_intake,
            storage_receiving,
            delete_operation_intake,
            execution_operation_intake,
            host_execution_prepare,
            host_execution_accept,
            recipient_precharge,
        })
    }

    fn history(&self) -> bank::EnrollmentMutation<'_> {
        bank::EnrollmentMutation::new((
            &self.transaction_id,
            &self.heads,
            &self.claims,
            &self.host,
            &self.first_global,
            &self.nix_intake,
            &self.q04_intake,
            &self.root_receiving,
            &self.create_intake,
            &self.storage_receiving,
        )).with_delete_operation_intake(self.delete_operation_intake.as_ref())
            .with_execution_operation_intake(self.execution_operation_intake.as_ref())
            .with_host_execution_prepare(self.host_execution_prepare.as_ref())
            .with_host_execution_accept(self.host_execution_accept.as_ref())
            .with_recipient_precharge_v1(self.recipient_precharge.as_ref())
    }

    pub(super) fn transaction(&self) -> Result<JournalTransaction, ControllerBankLaunchErrorV1> {
        self.history()
            .transaction()
            .map_err(ControllerBankLaunchErrorV1::from)
    }

    pub(super) fn require_current(
        &self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.require_exact(state, transaction)
    }

    pub(super) fn require_exact(
        &self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.history()
            .require_exact(state, transaction)
            .map_err(ControllerBankLaunchErrorV1::from)
    }

    pub(super) fn require_returned<P>(
        &self,
        writer: &super::writer::ControllerFixedWriterOriginalV1<P>,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        let state = writer.bank_state_v1()?;
        if bank::validate(state).map_err(ControllerBankLaunchErrorV1::from)?
            != Some(self.heads[0].native_fields().enrollment)
            || !writer.contains_bank_transaction_v1(&self.transaction_id)?
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.history()
            .require_returned_rows(state)
            .map_err(ControllerBankLaunchErrorV1::from)
    }
}


/// Holds the actual fixed writer's initial Bank mutation without a PID1 channel.
///
/// Only the genuine coordinator's closed initial-enrollment recipe constructs
/// this value. Its transaction is DATA; actual semantic commit, native receipt,
/// same-writer readback and independently owed posts remain mandatory.
pub struct ControllerPreparedEnrollmentMutationV1 {
    identity: std::sync::Arc<super::identity::ControllerWriterIdentityV1>,
    transition: EnrollmentTransitionV1,
    transaction: JournalTransaction,
    gate_failure: std::cell::OnceCell<ControllerBankLaunchErrorV1>,
}

impl ControllerPreparedEnrollmentMutationV1 {
    /// Borrows the transaction produced from this SAME original enrollment.
    pub fn transaction(&self) -> &JournalTransaction {
        &self.transaction
    }

    /// Rechecks the sole enrollment predicate at the upper semantic frontier.
    ///
    /// # Errors
    /// Retains the actual first predicate error and refuses later reentry.
    pub fn require_exact(&self, state: &State, transaction: &JournalTransaction)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        if self.gate_failure.get().is_some() {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        match self.transition.require_exact(state, transaction) {
            Ok(()) => Ok(()),
            Err(cause) => {
                let _ = self.gate_failure.set(cause);
                Err(ControllerBankLaunchErrorV1::Conflict)
            }
        }
    }

    /// Rejoins the actual fixed writer and its native publication/readback.
    ///
    /// # Errors
    /// Refuses a different writer, missing transaction or changed Bank rows.
    pub fn require_returned<P>(&self, writer: &super::coordinator::ControllerCoordinatorWriterV1<P>)
        -> Result<(), ControllerBankLaunchErrorV1>
    {
        if !std::sync::Arc::ptr_eq(&self.identity, writer.fixed.identity()) {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        self.transition.require_returned(&writer.fixed)
    }

    /// Borrows the first actual semantic gate refusal, when one occurred.
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.gate_failure.get().map(|cause| cause as _)
    }
}

/// Prices the closed enrollment records before their builder grows.
///
/// Nineteen fixed rows cover the three heads, inclusive claims, Host rows and
/// all finite intake suffixes. Each canonical row is at most 1024 bytes; the
/// four lanes cover builder/encode/append/map co-residency. Native prefix and
/// actual namespace index demand are charged by their own suppliers.
pub(in crate::controller_receiving) fn enrollment_record_bytes_v1() -> Option<usize> {
    19usize.checked_mul(17 + 1024 + std::mem::size_of::<
        aos_sandbox_protocol::domain_ledger::transaction::JournalRecord>())?
        .checked_mul(4)
}

impl<P> super::coordinator::ControllerCoordinatorWriterV1<P> {
    /// Prepares initial enrollment on this real paired fixed writer.
    ///
    /// This trusted coordinator port certifies no upper semantic success and
    /// cannot issue a Cache or Publisher role loan. A launch-bearing image must
    /// use its actual PID1 channel instead.
    ///
    /// # Errors
    /// Refuses a launch-bearing image, existing enrollment, unavailable native
    /// owner or insufficient same-C representation before record growth.
    pub fn prepare_initial_enrollment_once_v1(&mut self)
        -> Result<ControllerPreparedEnrollmentMutationV1, ControllerBankLaunchErrorV1>
    {
        use aos_sandbox_model::{ResourceDimension as D, ResourceVector};

        self.fixed.enter_initial_bank_preparation_once_v1()?;
        let original = self.fixed.original().writer_enrollment()?;
        if original.policy.bootstrap_provisions().storage_receiving.is_some()
            || bank::validate(self.fixed.bank_state_v1()?)?.is_some()
        {
            return Err(ControllerBankLaunchErrorV1::Conflict);
        }
        let bytes = enrollment_record_bytes_v1()
            .and_then(|bytes| bytes.checked_add(3 * std::mem::size_of::<ControllerPreparedEnrollmentMutationV1>()))
            .ok_or(ControllerBankLaunchErrorV1::Conflict)?;
        let additional = ResourceVector::ZERO.with(D::MemoryBytes,
            u64::try_from(bytes).map_err(|_| ControllerBankLaunchErrorV1::Conflict)?);
        self.fixed.require_role_borrow_representation(additional)?;
        // Keep this actual resident builder in every later append allowance;
        // a successful debit is not a grant or an enrollment disposition.
        self.fixed.retain_bank_preparation_bytes_v1(additional)?;
        let transition = EnrollmentTransitionV1::prepare(&original,
            self.fixed.original().writer_native_layout())?;
        let transaction = transition.transaction()?;
        transition.require_exact(self.fixed.bank_state_v1()?, &transaction)?;
        Ok(ControllerPreparedEnrollmentMutationV1 {
            identity: std::sync::Arc::clone(self.fixed.identity()), transition,
            transaction, gate_failure: std::cell::OnceCell::new(),
        })
    }
}
