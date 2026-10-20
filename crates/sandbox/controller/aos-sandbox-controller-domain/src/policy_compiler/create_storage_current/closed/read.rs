//! Owns the final distinct Controller, Source and Cache native read interval.
//!
//! Each rooted acquisition precedes its actual-prefix native admission, then a
//! geometry audit precedes semantic admission. The sole full replay and exact
//! COMMIT suffix engine run only after those genuine same-R stages succeed.

use std::error::Error as StdError;
use std::os::unix::net::UnixStream;
use aos_sandbox_model::ResourceVector;
use aos_sandbox_protocol::domain_ledger::create_storage_history::{
    OwnerV1, KeyV1, PhaseV1, HistoryErrorV1,
    continuation::{ContinuationKindV1, ContinuationNativeReceiptDataV1},
    ready::ReadyBundleDataV1,
    source_held::SourceHeldReceiptDataV1, cache_held::CacheHeldReceiptDataV1,
};
use crate::journal::{JournalError, JournalTransaction, RecordNamespace};
use crate::journal::create_storage_history::{HistoryPairNativeSuffixV1,
    HistoryPairNativeSuffixProgressV1, HistoryPairSuffixErrorV1, prepare_readonly_history_pair_v1};
use crate::normal_root::{RootPolicyAcceptedFlightV1, NormalRootStartupErrorV1};
use crate::policy_compiler::root_current_writers::RootCreateStorageCurrentWritersV1;
use super::{input::{RootReleaseInputV1, require_live}, ClosedFinancialStageV1};
use super::super::{RootCreateStorageCurrentErrorV1 as Error,
    root_open::{RootCurrentOpenStateV1, RootCurrentHistoryPostsV1},
    ready::RootCurrentReadyStateV1, outcome::RootCurrentOutcomeStateV1,
    source_current::RootCurrentSourceExchangeStateV1, cache_current::RootCurrentCacheProofStateV1,
    use_authorized::RootCurrentUseAuthorizedStateV1, use_reserved::RootCurrentUseReservedStateV1,
    signed_bound::RootCurrentSignedBoundStateV1,
    bundle_ownership::RootCurrentBundleOwnershipStateV1, policy_inputs::RootCurrentPolicyInputDataV1,
    controller_readonly::{RootCurrentControllerReadonlyStateV1, native_read::RootFixedNativeReadOriginalsV1}};

struct ReleaseReaderV1 {
    native: RootFixedNativeReadOriginalsV1,
    expected: Option<Result<JournalTransaction, JournalError>>,
    progress: HistoryPairNativeSuffixProgressV1,
    suffix: Option<Result<(), HistoryPairSuffixErrorV1>>,
    binding: Option<Result<(), JournalError>>,
}

impl ReleaseReaderV1 {
    fn source() -> Self { Self::new(RootFixedNativeReadOriginalsV1::source_release_v1()) }
    fn cache() -> Self { Self::new(RootFixedNativeReadOriginalsV1::cache_release_v1()) }
    fn new(native: RootFixedNativeReadOriginalsV1) -> Self {
        Self { native, expected: None, progress: HistoryPairNativeSuffixProgressV1::new(), suffix: None, binding: None }
    }

    fn replay(&mut self, before: (u64, u64), receipt: ContinuationNativeReceiptDataV1<'_>) -> Result<(), Error> {
        let expected = positive(&self.expected).map_err(|_| Error::History)?;
        let suffix = HistoryPairNativeSuffixV1::new(expected, &mut self.progress,
            before.0, before.1, receipt.after_next, receipt.after_end);
        let mut suffix = match suffix {
            Ok(suffix) => { self.suffix = Some(Ok(())); suffix },
            Err(cause) => { self.suffix = Some(Err(cause)); return Err(Error::History); },
        };
        self.native.replay_suffix_once(&mut suffix);
        let native = self.native.replay_native_v1().map_err(|_| Error::History)?;
        self.binding = Some((|| {
            if !self.progress.is_complete() || native.names != receipt.names
                || (native.next, native.end) != (receipt.after_next, receipt.after_end) {
                return Err(JournalError::ProtectedBoundary);
            }
            for row in expected.records() {
                if native.state.get(&(row.namespace(), row.key().to_vec())).map(Vec::as_slice) != row.value() {
                    return Err(JournalError::ProtectedBoundary);
                }
            }
            Ok(())
        })());
        positive(&self.binding).map(|_| ()).map_err(|_| Error::History)
    }

    fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        cause(&self.expected)
            .or_else(|| if self.native.suffix_failure_is_selected_v1() {
                self.progress.failure().map(|cause| cause as _)
            } else { None })
            .or_else(|| self.native.failure()).or_else(|| self.progress.failure().map(|cause| cause as _))
            .or_else(|| cause(&self.suffix)).or_else(|| cause(&self.binding))
    }
}

pub(crate) struct RootCurrentClosedReadV1 {
    pub(super) input: RootReleaseInputV1,
    controller: RootCurrentControllerReadonlyStateV1,
    source: ReleaseReaderV1,
    cache: ReleaseReaderV1,
    funding: [Option<Result<(), NormalRootStartupErrorV1>>; 4],
    primary: Option<Result<(), Error>>,
    after: RootCurrentHistoryPostsV1,
    readback: Option<Result<(), JournalError>>,
    live: Option<Result<(), JournalError>>,
    complete: bool,
    closed: bool,
}

impl RootCurrentClosedReadV1 {
    pub(super) fn new() -> Self {
        Self { input: RootReleaseInputV1::new(), controller: RootCurrentControllerReadonlyStateV1::new(),
            source: ReleaseReaderV1::source(), cache: ReleaseReaderV1::cache(),
            funding: std::array::from_fn(|_| None), primary: None, after: Default::default(),
            readback: None, live: None, complete: false, closed: false }
    }

    pub(crate) fn additional_demand_v1(&self, stage: ClosedFinancialStageV1) -> Result<ResourceVector, JournalError> {
        match stage {
            ClosedFinancialStageV1::SourceNative => self.source.native.replay_demand_v1(),
            ClosedFinancialStageV1::SourceSemantic => self.source.native.additional_semantic_demand_v1(),
            ClosedFinancialStageV1::CacheNative => self.cache.native.replay_demand_v1(),
            ClosedFinancialStageV1::CacheSemantic => self.cache.native.additional_semantic_demand_v1(),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    pub(super) fn observe_once(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        source: &RootCurrentSourceExchangeStateV1, cache: &RootCurrentCacheProofStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1, policy: &RootCurrentPolicyInputDataV1<'_>,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        signed: &RootCurrentSignedBoundStateV1, outcome: &RootCurrentOutcomeStateV1,
    ) -> Result<(), Error> {
        if self.primary.is_some() || self.closed { self.closed = true; return Err(Error::Original); }
        self.after.arm_once(flight)?;
        self.primary = Some(self.observe_inner(flight, writers, original, root, ready, source, cache,
            ownership, policy, authorization, reserved, signed, outcome));
        // Every entered native reader has an independently owed same-name post,
        // even after native/semantic payment or parser refusal. Unentered readers
        // perform no IO. Neither reader's first model or raw error is replaced.
        self.source.native.finish_post_once();
        self.cache.native.finish_post_once();
        let body = root.completed_body().ok();
        let origin = root.original_clock_origin_v1().ok();
        self.after.observe_once(flight, writers, body.as_ref(), origin.map(|p| p.0), origin.map(|p| p.1));
        self.readback = Some(match writers.authority_and_policy() {
            Ok((authority, policy)) => outcome.readback_current_v1(authority, policy).map(|_| ()),
            Err(cause) => Err(cause),
        });
        self.live = Some((|| {
            self.after.require_complete()?;
            positive(&self.readback)?;
            self.source.native.terminal_native_v1()?;
            self.cache.native.terminal_native_v1()?;
            self.controller.require_live_at_v1(self.after.sample()?)?;
            require_live(root, outcome, reserved, source, self.after.sample()?)
        })());
        self.complete = matches!(self.primary, Some(Ok(()))) && matches!(self.live, Some(Ok(())))
            && self.failure_with_original(flight).is_none();
        self.require_complete_v1()
    }

    fn observe_inner(&mut self, flight: &mut RootPolicyAcceptedFlightV1<'_, '_>,
        writers: &mut RootCreateStorageCurrentWritersV1, original: &UnixStream,
        root: &RootCurrentOpenStateV1, ready: &RootCurrentReadyStateV1,
        source: &RootCurrentSourceExchangeStateV1, cache: &RootCurrentCacheProofStateV1,
        ownership: &RootCurrentBundleOwnershipStateV1, policy: &RootCurrentPolicyInputDataV1<'_>,
        authorization: &RootCurrentUseAuthorizedStateV1, reserved: &RootCurrentUseReservedStateV1,
        signed: &RootCurrentSignedBoundStateV1, outcome: &RootCurrentOutcomeStateV1,
    ) -> Result<(), Error> {
        self.input.receive_once(flight, writers, original, root, ready, outcome, reserved, source, cache)?;
        self.controller.capture_closed_once(flight, writers, root, ready, cache, source, ownership, policy,
            authorization, reserved, signed, outcome, &self.input)?;
        let open = root.completed_body()?;
        let bundle = ReadyBundleDataV1::borrow_field_framing_data_v1(ready.raw_ready_bytes()?)
            .map_err(|_| Error::History)?;
        let held_source = SourceHeldReceiptDataV1::decode(bundle.source_held, open.open.lane).map_err(|_| Error::History)?;
        let held_cache = CacheHeldReceiptDataV1::decode(bundle.cache_held, open.open.lane).map_err(|_| Error::History)?;
        let releases = self.input.proofs_v1(open.open.lane)?;
        let source_receipt = ContinuationNativeReceiptDataV1::decode(releases.source, open.open.lane,
            ContinuationKindV1::SourceReleased).map_err(|_| Error::History)?;
        let cache_receipt = ContinuationNativeReceiptDataV1::decode(releases.cache, open.open.lane,
            ContinuationKindV1::CacheReleased).map_err(|_| Error::History)?;
        if source_receipt.names != held_source.source_names || cache_receipt.names != held_cache.hold_names {
            return Err(Error::History);
        }
        self.source.expected = Some(prepare_readonly_history_pair_v1(
            KeyV1::new(open.open.lane, OwnerV1::Source, 2).map_err(|_| Error::History)?,
            PhaseV1::new(OwnerV1::Source, 2).map_err(|_| Error::History)?, source_receipt.record, &source_receipt.latest_head));
        self.cache.expected = Some(prepare_readonly_history_pair_v1(
            KeyV1::new(open.open.lane, OwnerV1::Cache, 2).map_err(|_| Error::History)?,
            PhaseV1::new(OwnerV1::Cache, 2).map_err(|_| Error::History)?, cache_receipt.record, &cache_receipt.latest_head));
        positive(&self.source.expected).map_err(|_| Error::History)?;
        positive(&self.cache.expected).map_err(|_| Error::History)?;
        self.source.native.capture_once(open.controller_uid);
        self.source.native.require_captured_v1().map_err(|_| Error::History)?;
        self.funding[0] = Some(flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_closed_release_once(root, signed, outcome, self, ClosedFinancialStageV1::SourceNative));
        positive(&self.funding[0]).map_err(|_| Error::History)?;
        self.source.native.audit_once();
        self.funding[1] = Some(flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_closed_release_once(root, signed, outcome, self, ClosedFinancialStageV1::SourceSemantic));
        positive(&self.funding[1]).map_err(|_| Error::History)?;
        self.source.replay((held_source.source_after_next, held_source.source_after_end), source_receipt)?;
        let source_state = self.source.native.replay_native_v1().map_err(|_| Error::History)?;
        require_held_row(source_state.state, open.open.lane, OwnerV1::Source, held_source.record).map_err(|_| Error::History)?;
        self.cache.native.capture_once(cache.verified_body_v1()?.snapshot.physical.uid);
        self.cache.native.require_captured_v1().map_err(|_| Error::History)?;
        self.funding[2] = Some(flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_closed_release_once(root, signed, outcome, self, ClosedFinancialStageV1::CacheNative));
        positive(&self.funding[2]).map_err(|_| Error::History)?;
        self.cache.native.audit_once();
        self.funding[3] = Some(flight.current_cut_startup().map_err(|_| Error::Original)?
            .prepay_create_storage_closed_release_once(root, signed, outcome, self, ClosedFinancialStageV1::CacheSemantic));
        positive(&self.funding[3]).map_err(|_| Error::History)?;
        self.cache.replay((held_cache.hold_after_next, held_cache.hold_after_end), cache_receipt)?;
        let cache_state = self.cache.native.replay_native_v1().map_err(|_| Error::History)?;
        require_held_row(cache_state.state, open.open.lane, OwnerV1::Cache, held_cache.record).map_err(|_| Error::History)
    }

    pub(crate) fn require_complete_v1(&self) -> Result<(), Error> {
        if self.complete && !self.closed { self.controller.require_complete_v1() }
        else { Err(Error::History) }
    }

    pub(crate) fn controller_v1(&self) -> Result<&RootCurrentControllerReadonlyStateV1, Error> {
        self.require_complete_v1()?;
        Ok(&self.controller)
    }

    pub(crate) fn require_live_at_v1(&self, root: &RootCurrentOpenStateV1,
        reserved: &RootCurrentUseReservedStateV1, source: &RootCurrentSourceExchangeStateV1,
        outcome: &RootCurrentOutcomeStateV1, sample: aos_sandbox_model::RawPairedClockSample)
        -> Result<(), JournalError> {
        self.require_complete_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        self.controller.require_live_at_v1(sample)?;
        require_live(root, outcome, reserved, source, sample)
    }

    pub(super) fn failed_financial_entry_v1(&self) -> Option<ClosedFinancialStageV1> {
        self.controller.failed_closed_financial_entry_v1().or_else(|| {
            self.funding.iter().position(|slot| matches!(slot, Some(Err(_)))).map(|index|
                [ClosedFinancialStageV1::SourceNative, ClosedFinancialStageV1::SourceSemantic,
                    ClosedFinancialStageV1::CacheNative, ClosedFinancialStageV1::CacheSemantic][index])
        })
    }

    pub(crate) fn failure_with_original<'a>(&'a self, flight: &'a RootPolicyAcceptedFlightV1<'_, '_>)
        -> Option<&'a (dyn StdError + 'static)> {
        self.input.failure().or_else(|| self.controller.failure_with_original(flight))
            .or_else(|| self.source.failure()).or_else(|| self.cache.failure())
            .or_else(|| self.funding.iter().find_map(|result| result.as_ref()?.as_ref().err()).map(|cause| cause as _))
            .or_else(|| cause(&self.primary)).or_else(|| self.source.native.post_failure())
            .or_else(|| self.cache.native.post_failure()).or_else(|| self.after.failure())
            .or_else(|| cause(&self.readback)).or_else(|| cause(&self.live))
    }
}

fn require_held_row(state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    lane: [u8; 16], owner: OwnerV1, held: &[u8]) -> Result<(), JournalError> {
    let key = KeyV1::new(lane, owner, 1).map_err(|_| JournalError::ProtectedBoundary)?.encode();
    if state.get(&(RecordNamespace::CreateStorageHistory, key.to_vec())).map(Vec::as_slice) != Some(held) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

fn positive<T, E>(slot: &Option<Result<T, E>>) -> Result<&T, JournalError> {
    slot.as_ref().and_then(|value| value.as_ref().ok()).ok_or(JournalError::ProtectedBoundary)
}

fn cause<T, E: StdError + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn StdError + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}
