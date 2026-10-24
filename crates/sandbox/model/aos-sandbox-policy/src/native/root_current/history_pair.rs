//! Retains fixed Root history members, the native append and its exact readback.
//!
//! Concrete private purpose factories borrow the same completed native Current
//! owners. Record bytes and saved NEXT values only compare those originals;
//! neither can construct an append gate or replace its independently owed arm.

use std::error::Error;
use std::fs::Metadata;
use std::io;
use std::os::fd::BorrowedFd;

use aos_sandbox_broker::canonical_journal::CommitResult;
use aos_sandbox_broker::receiving::{RootObservationErrorV1, RootSelectedStartupBorrowV1, RootUpperMutationGuardV1};
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    HEAD_BYTES, HistoryErrorV1, KeyV1, LatestHeadV1, PhaseV1,
    RecordCoordinatesV1, RecordEnvelopeV1, prepare_history_pair_v1,
    readback::{HistoryPairReadbackBytesDataV1, HistoryPairReadbackDataV1},
};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

use crate::native::PolicyNativeJournalErrorV1;
use crate::native::journal::RootPolicyJournalV1;
use crate::native::startup::RootCurrentWritersPredecessorV1;
use crate::native::target::RootPolicyTargetOriginalV1;

use super::history_post::RootCurrentHistoryPostOriginalV1;
use super::initial_cache::RootInitialCacheProofOriginalV1;
use super::initial_controller::RootInitialControllerReadonlyOriginalV1;
use super::initial_open::{RootInitialOpenAppendGateV1, RootInitialOpenCrossingOriginalV1,
    RootInitialOpenErrorV1 as E, RootInitialOpenPreparedOriginalV1, RootHistoryAppendPurposeV1};
use super::initial_source_exchange::RootInitialSourceExchangeOriginalV1;
use super::owned::RootCurrentAcceptedOriginalsV1;

pub(super) struct RootCurrentHistoryPairV1<const RECORD: usize> {
    pub(super) record: [u8; RECORD],
    checksum: Option<Result<[u8; 32], HistoryErrorV1>>,
    pub(super) head: [u8; HEAD_BYTES],
    head_encoding: Option<Result<[u8; HEAD_BYTES], HistoryErrorV1>>,
    transaction: Option<Result<JournalTransaction, E>>,
    crossing: RootInitialOpenCrossingOriginalV1,
    history: Option<RootCurrentHistoryPostOriginalV1>,
    arm_returned: Option<Result<(), RootObservationErrorV1>>,
    pub(super) append: Option<Result<CommitResult, PolicyNativeJournalErrorV1>>,
    pub(super) readback: Option<Result<HistoryPairReadbackDataV1<RECORD>, E>>,
    native_end: Option<io::Result<Metadata>>,
    before_next: Option<u64>,
    policy_next: Option<u64>,
}

impl<const RECORD: usize> RootCurrentHistoryPairV1<RECORD> {
    pub(super) fn new() -> Self {
        Self {
            record: [0; RECORD],
            checksum: None,
            head: [0; HEAD_BYTES],
            head_encoding: None,
            transaction: None,
            crossing: RootInitialOpenCrossingOriginalV1::new(),
            history: None,
            arm_returned: None,
            append: None,
            readback: None,
            native_end: None,
            before_next: None,
            policy_next: None,
        }
    }

    pub(super) fn prepare_once_v1(
        &mut self,
        key: KeyV1,
        phase: PhaseV1,
        predecessor: [u8; 32],
        correlation: [u8; 32],
        body: &[u8],
    ) -> Result<(), E> {
        if self.checksum.is_some() {
            return Err(E::Boundary);
        }
        self.checksum = Some(RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key, phase, predecessor, correlation,
        }, body, &mut self.record));
        self.head_encoding = Some(LatestHeadV1::new(key.revision(), *positive(&self.checksum)?)
            .map(|head| head.encode()));
        self.head = *positive(&self.head_encoding)?;
        self.transaction = Some(prepare_history_pair_v1(key, phase, &self.record, &self.head)
            .map_err(E::Pair));
        positive(&self.transaction).map(|_| ())
    }

    pub(super) fn prepare_use_authorized_cut_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
    ) -> Result<(), E> {
        if self.before_next.is_some() {
            return Err(E::Boundary);
        }
        let body = open.body_v1()?;
        self.before_next = Some(body.authority_next.checked_add(4).ok_or(E::SequenceExhausted)?);
        self.policy_next = Some(body.policy_next);
        Ok(())
    }

    pub(super) fn prepare_use_admitted_cut_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
    ) -> Result<(), E> {
        if self.before_next.is_some() {
            return Err(E::Boundary);
        }
        let body = open.body_v1()?;
        self.before_next = Some(body.authority_next.checked_add(8).ok_or(E::SequenceExhausted)?);
        self.policy_next = Some(body.policy_next);
        Ok(())
    }

    pub(super) fn prepare_signed_cut_once_v1(
        &mut self,
        open: &RootInitialOpenPreparedOriginalV1,
    ) -> Result<(), E> {
        if self.before_next.is_some() {
            return Err(E::Boundary);
        }
        let body = open.body_v1()?;
        self.before_next = Some(
            body.authority_next
                .checked_add(12)
                .ok_or(E::SequenceExhausted)?,
        );
        self.policy_next = Some(body.policy_next);
        Ok(())
    }

    pub(super) fn arm_once_v1(
        &mut self,
        predecessor: RootCurrentWritersPredecessorV1<'_, '_, '_>,
        startup: &RootSelectedStartupBorrowV1<'_>,
        exclusion: &RootUpperMutationGuardV1<'_>,
    ) -> Result<(), RootObservationErrorV1> {
        if self.history.is_some() || self.arm_returned.is_some() {
            return Err(RootObservationErrorV1::Service);
        }
        self.history = Some(RootCurrentHistoryPostOriginalV1::arm_once_v1(predecessor, startup, exclusion));
        self.arm_returned = Some(match &self.history {
            Some(history) => history.require_armed_v1(),
            None => Err(RootObservationErrorV1::Service),
        });
        match &self.arm_returned {
            Some(Ok(())) => Ok(()),
            _ => Err(RootObservationErrorV1::Service),
        }
    }

    pub(super) fn append_use_authorized_once_v1(
        &mut self,
        authority: &mut RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        readonly: &RootInitialControllerReadonlyOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        endpoint: BorrowedFd<'_>,
    ) -> Result<(), E> {
        self.append_for_purpose_once_v1(authority, policy, open,
            RootHistoryAppendPurposeV1::UseAuthorized { open, readonly, source, cache },
            originals, endpoint)
    }

    pub(super) fn append_use_admitted_once_v1(
        &mut self,
        authority: &mut RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        authorization: &super::initial_use_authorized::RootInitialUseAuthorizedOriginalV1,
        reserved: &super::use_tail::reserved::RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        cache: &RootInitialCacheProofOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        endpoint: BorrowedFd<'_>,
    ) -> Result<(), E> {
        self.append_for_purpose_once_v1(authority, policy, open,
            RootHistoryAppendPurposeV1::UseAdmitted { open, authorization, reserved, source, cache },
            originals, endpoint)
    }

    pub(super) fn append_signed_once_v1(
        &mut self,
        authority: &mut RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        admitted: &super::use_tail::admitted::RootUseAdmittedOriginalV1,
        reserved: &super::use_tail::reserved::RootUseReservedOriginalV1,
        source: &RootInitialSourceExchangeOriginalV1,
        signed: &super::use_tail::signed::received::RootSignedReceivedOriginalV1,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        endpoint: BorrowedFd<'_>,
    ) -> Result<(), E> {
        self.append_for_purpose_once_v1(
            authority,
            policy,
            open,
            RootHistoryAppendPurposeV1::SignedBound {
                admitted,
                reserved,
                source,
                signed,
            },
            originals,
            endpoint,
        )
    }

    fn append_for_purpose_once_v1(
        &mut self,
        authority: &mut RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
        open: &RootInitialOpenPreparedOriginalV1,
        purpose: RootHistoryAppendPurposeV1<'_>,
        originals: &RootCurrentAcceptedOriginalsV1<'_>,
        endpoint: BorrowedFd<'_>,
    ) -> Result<(), E> {
        if self.append.is_some() {
            return Err(E::Boundary);
        }
        positive(&self.arm_returned)?;
        let transaction = positive(&self.transaction)?;
        let mut gate = RootInitialOpenAppendGateV1::for_purpose_v1(
            open, purpose, policy, transaction, &mut self.crossing,
            self.history.as_mut().ok_or(E::Boundary)?, &originals.peer, &originals.stream, endpoint,
        )?;
        self.append = Some(authority.commit_with_role_gate_v1(
            transaction, crate::native::append::PolicyMutationGateV1::RootOpen(&mut gate),
        ));
        drop(gate);

        // The durable result is resident before either following native query.
        // A refused readback cannot erase that actual committed transaction.
        if matches!(self.append, Some(Ok(_))) {
            self.readback = Some(self.readback_pair_v1(authority, policy));
            self.native_end = Some(authority.read_view().metadata());
        }
        positive(&self.append)?;
        positive(&self.readback)?;
        self.require_end_v1(&self.native_end)
    }

    pub(super) fn readback_pair_v1(
        &self,
        authority: &RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
    ) -> Result<HistoryPairReadbackDataV1<RECORD>, E> {
        let observed = self.readback_pair_data_v1(authority)?;
        if Some(policy.current_snapshot_sequence_data_v1()) != self.policy_next {
            return Err(E::Boundary);
        }
        Ok(observed)
    }

    fn readback_pair_data_v1(&self, authority: &RootPolicyJournalV1)
        -> Result<HistoryPairReadbackDataV1<RECORD>, E>
    {
        let transaction = positive(&self.transaction)?;
        let committed = positive(&self.append)?;
        let record = self.record.as_slice();
        let head = &self.head;
        let before_next = self.before_next.ok_or(E::Boundary)?;
        let journal = authority;
        let readback: Result<HistoryPairReadbackBytesDataV1<'_>, E> =
            aos_sandbox_protocol::readback_create_storage_history_pair_bytes_data_v1! {
                journal: journal,
                transaction: transaction,
                record: record,
                head: head,
                before_next: before_next,
                committed: committed,
                namespace: RecordNamespace::CreateStorageHistory,
                boundary: E::Boundary,
                result: HistoryPairReadbackBytesDataV1,
            };
        let bytes = readback?;
        Ok(HistoryPairReadbackDataV1 {
            record: bytes.record.try_into().map_err(|_| E::Boundary)?,
            head: bytes.head,
            next: bytes.next,
        })
    }

    pub(super) fn require_end_v1(&self, metadata: &Option<io::Result<Metadata>>) -> Result<(), E> {
        if positive(metadata)?.len() != positive(&self.append)?.durable_bytes {
            return Err(E::Boundary);
        }
        Ok(())
    }

    pub(super) fn readback_current_v1(
        &self,
        authority: &RootPolicyJournalV1,
        policy: &RootPolicyTargetOriginalV1,
    ) -> Result<HistoryPairReadbackDataV1<RECORD>, E> {
        let observed = self.readback_pair_data_v1(authority)?;
        let metadata = authority.read_view().metadata().map_err(E::Metadata)?;
        if metadata.len() != positive(&self.append)?.durable_bytes {
            return Err(E::Boundary);
        }
        if Some(policy.current_snapshot_sequence_data_v1()) != self.policy_next {
            return Err(E::Boundary);
        }
        Ok(observed)
    }

    pub(super) fn failure_v1(&self) -> Option<&(dyn Error + 'static)> {
        cause(&self.checksum)
            .or_else(|| cause(&self.head_encoding))
            .or_else(|| cause(&self.transaction))
            .or_else(|| self.crossing.failure_v1(self.history.as_ref()))
            .or_else(|| cause(&self.arm_returned))
            .or_else(|| cause(&self.append))
            .or_else(|| cause(&self.readback))
            .or_else(|| cause(&self.native_end))
    }
}

fn positive<T, F>(slot: &Option<Result<T, F>>) -> Result<&T, E> {
    slot.as_ref().and_then(|result| result.as_ref().ok()).ok_or(E::Boundary)
}

fn cause<T, F: Error + 'static>(slot: &Option<Result<T, F>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref().and_then(|result| result.as_ref().err()).map(|error| error as _)
}

impl<const RECORD: usize> RootCurrentHistoryPairV1<RECORD> {
    pub(super) fn control_bytes_v1() -> Option<usize> {
        use std::mem::size_of;
        let preparation = size_of::<(&mut Self, KeyV1, PhaseV1, [u8; 32], [u8; 32], &[u8])>().checked_mul(3)?
            .checked_add(size_of::<(&mut Self, &RootInitialOpenPreparedOriginalV1)>().checked_mul(3)?)?
            .checked_add(size_of::<Result<JournalTransaction, E>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<[u8; 32], HistoryErrorV1>>().checked_mul(3)?)?
            .checked_add(size_of::<Result<[u8; HEAD_BYTES], HistoryErrorV1>>().checked_mul(3)?)?;
        let arm = size_of::<(&mut Self, RootCurrentWritersPredecessorV1<'_, '_, '_>,
            &RootSelectedStartupBorrowV1<'_>, &RootUpperMutationGuardV1<'_>)>().checked_mul(3)?
            .checked_add(size_of::<Result<(), RootObservationErrorV1>>().checked_mul(6)?)?;
        let append = size_of::<(&mut Self, &mut RootPolicyJournalV1, &RootPolicyTargetOriginalV1,
            &RootInitialOpenPreparedOriginalV1, &RootInitialControllerReadonlyOriginalV1,
            &RootInitialSourceExchangeOriginalV1, &RootInitialCacheProofOriginalV1,
            &RootCurrentAcceptedOriginalsV1<'_>, BorrowedFd<'_>)>().checked_mul(3)?
            .checked_add(size_of::<Result<CommitResult, PolicyNativeJournalErrorV1>>().checked_mul(3)?)?;
        let readback = size_of::<(&Self, &RootPolicyJournalV1, &RootPolicyTargetOriginalV1)>().checked_mul(9)?
            .checked_add(size_of::<(&Self, &RootPolicyJournalV1)>().checked_mul(9)?)?
            .checked_add(size_of::<Result<HistoryPairReadbackBytesDataV1<'_>, E>>().checked_mul(9)?)?
            .checked_add(size_of::<Result<HistoryPairReadbackDataV1<RECORD>, E>>().checked_mul(18)?)?
            .checked_add(size_of::<(&Self, &Option<io::Result<Metadata>>)>().checked_mul(9)?)?
            .checked_add(size_of::<io::Result<Metadata>>().checked_mul(9)?)?;
        let results = size_of::<Result<(), E>>().checked_mul(30)?
            .checked_add(size_of::<&&Self>().checked_mul(8 * 3)?)?
            .checked_add(size_of::<Option<&(dyn Error + 'static)>>().checked_mul(8 * 3)?)?;
        preparation.checked_add(arm)?.checked_add(append)?.checked_add(readback)?.checked_add(results)
    }
}
