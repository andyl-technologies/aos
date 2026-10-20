//! Retains the actual Controller-to-Root peer under the same paid J turn.
//!
//! The private RootExchange borrower supplies the original profile, connected
//! stream and pending received chunk. No caller path, descriptor, UID, Hello
//! field or comparison result constructs a peer. Two serial native destinations
//! cover the primary observation and its single independently owed observation.

use std::error::Error;

use aos_sandbox_linux::cgroup::{CgroupV2Root, RetainedCgroupAnchor};
use aos_sandbox_linux::unix_stream::SubjectStreamReceiveGeometryV1;
use aos_sandbox_protocol::domain_ledger::create_storage_history::root_open::RootOpenBodyDataV1;

use crate::{CreateStorageEndpointRevalidationShapeDataV1,
    CreateStorageRootExchangeClosedV1 as Closed, OriginalCreateStorageRootExchangeV1};
use crate::immutable_image::PendingImmutableFileV1;

use super::{NormalRootStartupErrorV1 as Refusal, ProductionControllerNormalRootProfileV1};
use super::super::{profile, service};

mod demand;
pub(super) mod refusal;
pub(super) mod sample;
mod queued_cutoff;
use sample::PeerSampleV1;

const MATERIALIZED_BYTES: usize = 64 * 1024;

type RootPropertiesV1 = (service::ServiceObservationV1, [u8; 16]);

pub(super) struct StableRootPeerV1 {
    pair: (CgroupV2Root, RetainedCgroupAnchor),
    fragment: PendingImmutableFileV1,
    observed: RootPropertiesV1,
    pid: u32,
}

// This private borrowed view keeps the actual first native originals resident.
// It has no constructor outside their owner and supplies comparison only.
#[derive(Clone, Copy)]
pub(super) struct RootPeerBindingRefV1<'held> {
    pair: &'held (CgroupV2Root, RetainedCgroupAnchor),
    fragment: &'held PendingImmutableFileV1,
    observed: &'held RootPropertiesV1,
    pid: u32,
}

impl StableRootPeerV1 {
    fn as_binding(&self) -> RootPeerBindingRefV1<'_> {
        RootPeerBindingRefV1 { pair: &self.pair, fragment: &self.fragment,
            observed: &self.observed, pid: self.pid }
    }
}

#[derive(Clone, Copy)]
enum FailureStage {
    Preparation,
    Before(usize),
    OwedEntry(usize),
    Native(usize),
    After(usize),
    Settlement(usize),
    Disposal(usize),
    Hello,
    Closed,
}

#[derive(Clone, Copy)]
enum ObservationPurpose {
    Capture,
    Recheck,
    Chunk,
}

/// Retains the original Root peer, actual samples and exact first refusal.
///
/// Only the actual same-J borrower enters this receiver. A failure permits one
/// separately prepaid negative-only recheck; that observation cannot publish an
/// initial binding, dispose a failed sample, restore the turn or admit more IO.
#[must_use = "retain the real peer and all failed native samples with the J turn"]
pub(crate) struct CreateStorageRootPeerReceivingOriginalsV1 {
    stable: Option<StableRootPeerV1>,
    samples: [Option<Box<PeerSampleV1>>; 2],
    preparation: Option<Result<(), Closed>>,
    before: [Option<Result<(), Closed>>; 2],
    owed_entry: [Option<Result<(), Closed>>; 2],
    native_returned: [Option<Result<(), Closed>>; 2],
    after: [Option<Result<(), Closed>>; 2],
    disposal: [Option<Result<(), Closed>>; 2],
    hello: Option<Result<(), Refusal>>,
    first: Option<FailureStage>,
    closed: Option<Closed>,
    capture_entered: bool,
    owed_entered: bool,
}

impl CreateStorageRootPeerReceivingOriginalsV1 {
    /// Creates only inert native/result destinations.
    pub(crate) fn new() -> Self {
        Self {
            stable: None,
            samples: [None, None],
            preparation: None,
            before: [None, None],
            owed_entry: [None, None],
            native_returned: [None, None],
            after: [None, None],
            disposal: [None, None],

            hello: None,
            first: None,
            closed: None,
            capture_entered: false,
            owed_entered: false,
        }
    }

    /// Describes the actual selected Root SID control geometry without IO.
    pub(crate) fn receiving_geometry_v1()
        -> Result<SubjectStreamReceiveGeometryV1, aos_sandbox_linux::seqpacket::SeqpacketError>
    {
        SubjectStreamReceiveGeometryV1::for_context_bytes(profile::CONTEXT.len())
    }

    /// Requires one sequential existing PID1 worker, never a ninth task grant.
    pub(crate) const fn worker_threads_v1() -> usize {
        1
    }

    /// Names two actual bounded PID1 rows per complete peer observation.
    pub(crate) const fn property_rows_per_observation_v1() -> usize {
        2
    }

    pub(crate) fn capture_once(
        &mut self,
        loan: &mut OriginalCreateStorageRootExchangeV1<'_, '_, '_>,
    ) -> Result<(), Closed> {
        if self.capture_entered || self.first.is_some() {
            return self.close();
        }
        self.capture_entered = true;
        self.observe(loan, ObservationPurpose::Capture)
    }

    pub(crate) fn recheck_once(
        &mut self,
        loan: &mut OriginalCreateStorageRootExchangeV1<'_, '_, '_>,
    ) -> Result<(), Closed> {
        if !self.capture_entered || self.closed.is_some() || self.owed_entered {
            return self.close();
        }
        self.observe(loan, ObservationPurpose::Recheck)
    }

    pub(crate) fn require_chunk_v1(
        &mut self,
        loan: &mut OriginalCreateStorageRootExchangeV1<'_, '_, '_>,
    ) -> Result<(), Closed> {
        if self.stable.is_none() || self.first.is_some() || self.closed.is_some() {
            return self.close();
        }
        self.observe(loan, ObservationPurpose::Chunk)
    }

    fn observe(
        &mut self,
        loan: &mut OriginalCreateStorageRootExchangeV1<'_, '_, '_>,
        purpose: ObservationPurpose,
    ) -> Result<(), Closed> {
        let owed = self.first.is_some();
        // The only recheck entrance is the actual turn's independent post.
        // Its prearmed native observations remain owed even if its own fresh
        // J before sample refuses. Healthy primary/chunk work stays gated.
        let independent_post = matches!(purpose, ObservationPurpose::Recheck);
        if owed {
            if !matches!(purpose, ObservationPurpose::Recheck) || self.owed_entered {
                return self.close();
            }
            self.owed_entered = true;
        }
        let actual_profile = loan.root_peer_profile_v1()?;
        if self.preparation.is_none() {
            let shape = Self::receiving_shape_v1(actual_profile).ok_or(Closed)?;
            self.preparation = Some(loan.require_fixed_root_peer_preparation_v1(shape));
        }
        if !matches!(self.preparation, Some(Ok(()))) {
            self.first.get_or_insert(FailureStage::Preparation);
            return Err(Closed);
        }
        let index = self.samples.iter().position(Option::is_none).ok_or(Closed)?;
        if independent_post {
            self.owed_entry[index] = Some(loan.require_root_peer_owed_observation_v1());
            if !matches!(self.owed_entry[index], Some(Ok(()))) {
                self.first.get_or_insert(FailureStage::OwedEntry(index));
                return Err(Closed);
            }
        }
        let ordinal = loan.enter_root_peer_sample_once_v1()?;
        // The same fixed Root purpose has admitted both actual sample backings
        // and this constructor before this first allocation. Empty intake
        // custody holds only the two once slots, not future native samples.
        self.samples[index] = Some(Box::new(PeerSampleV1::new()));
        self.before[index] = Some(loan.require_root_peer_sample_entry_v1(ordinal));
        if !matches!(self.before[index], Some(Ok(()))) {
            self.first.get_or_insert(FailureStage::Before(index));
        }
        // Only this receiver's prearmed owed continuation can observe after a
        // negative before post. It uses the same fixed profile/socket originals
        // and can never publish or dispose an otherwise-positive new binding.
        if matches!(self.before[index], Some(Ok(()))) || independent_post {
            let sample = self.samples[index].as_mut().ok_or(Closed)?;
            let captured = (|| {
                let cutoff = loan.root_peer_cutoff_v1()?;
                let stream = loan.root_peer_transport_v1()?;
                let chunk = if matches!(purpose, ObservationPurpose::Chunk) {
                    Some(loan.root_peer_chunk_v1()?)
                } else { None };
                sample.observe_once(actual_profile, stream, self.stable.as_ref(), chunk, independent_post, cutoff)
                    .map_err(|_| Closed)
            })();
            self.native_returned[index] = Some(captured);
            if !matches!(self.native_returned[index], Some(Ok(()))) {
                self.first.get_or_insert(FailureStage::Native(index));
            }
        }
        // This independent J/Cache post is reached after every entered sample,
        // including native/property/semantic and initial before refusals.
        self.after[index] = Some(loan.after_root_peer_sample_once_v1(ordinal));
        if !matches!(self.after[index], Some(Ok(()))) {
            self.first.get_or_insert(FailureStage::After(index));
        }
        if self.first.is_some() || owed {
            return Err(Closed);
        }
        let sample = self.samples[index].as_mut().ok_or(Closed)?;
        if sample.settle_positive_once().is_err() {
            self.first = Some(FailureStage::Settlement(index));
            return Err(Closed);
        }
        self.disposal[index] = Some(loan.require_root_peer_sample_disposal_v1(ordinal, actual_profile));
        if !matches!(self.disposal[index], Some(Ok(()))) {
            self.first = Some(FailureStage::Disposal(index));
            return Err(Closed);
        }
        if self.stable.is_none() {
            self.stable = sample.take_initial_binding();
            if self.stable.is_none() {
                return self.close();
            }
        }
        // Native, semantic, transport and same-J/Cache comparisons have all
        // completed. Drop the actual transient backing/FDs before slot reuse.
        drop(self.samples[index].take());
        self.before[index] = None;
        self.owed_entry[index] = None;
        self.native_returned[index] = None;
        self.after[index] = None;
        self.disposal[index] = None;
        Ok(())
    }

    pub(crate) fn require_hello_v1(
        &mut self,
        loan: &mut OriginalCreateStorageRootExchangeV1<'_, '_, '_>,
        body: &RootOpenBodyDataV1,
    ) -> Result<(), Closed> {
        if self.hello.is_some() || self.first.is_some() || self.closed.is_some() {
            return self.close();
        }
        self.hello = Some((|| {
            let actual = loan.root_peer_profile_v1().map_err(|_| Refusal::Service)?;
            let stable = self.stable.as_ref().ok_or(Refusal::Service)?;
            require_hello_identity(
                body, actual.original.profile_measurement().measured_digest_v1(), &stable.observed,
                stable.pid, [std::process::id(), actual.original.schema().identities[0], actual.original.schema().identities[1]],
            )
        })());
        if matches!(self.hello, Some(Ok(()))) { Ok(()) } else {
            self.first = Some(FailureStage::Hello);
            Err(Closed)
        }
    }

    /// Borrows only the actual chronological resident refusal.
    ///
    /// J before/after causes live in the SAME enclosing borrower; returning
    /// `None` for those stages lets that owner select its exact native cause.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        match self.first {
            Some(FailureStage::Preparation) => error(&self.preparation),
            Some(FailureStage::OwedEntry(index)) => error(&self.owed_entry[index]),
            Some(FailureStage::Before(_)) | Some(FailureStage::After(_))
                | Some(FailureStage::Disposal(_)) => None,
            Some(FailureStage::Native(index) | FailureStage::Settlement(index)) =>
                self.samples.get(index).and_then(Option::as_deref).and_then(PeerSampleV1::failure)
                    .or_else(|| error(&self.native_returned[index])),
            Some(FailureStage::Hello) => error(&self.hello),
            Some(FailureStage::Closed) => self.closed.as_ref().map(|cause| cause as _),
            None => None,
        }
    }

    /// Keeps the SAME failed worker guard alive for its nested native cause.
    ///
    /// This view is selected only for the actual chronological property stage;
    /// returning comparison DATA neither heals nor completes the failed turn.
    pub(crate) fn property_failure_view_v1(&self)
        -> Option<aos_systemd::FixedPid1PropertyFailureViewV1<'_>>
    {
        match self.first {
            Some(FailureStage::Native(index) | FailureStage::Settlement(index)) =>
                self.samples.get(index)?.as_ref()?.property_failure_view_v1(),
            _ => None,
        }
    }

    fn close(&mut self) -> Result<(), Closed> {
        self.closed.get_or_insert(Closed);
        self.first.get_or_insert(FailureStage::Closed);
        Err(Closed)
    }
}

impl Default for CreateStorageRootPeerReceivingOriginalsV1 {
    fn default() -> Self {
        Self::new()
    }
}

fn error<T, E: Error + 'static>(slot: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    slot.as_ref()?.as_ref().err().map(|cause| cause as _)
}

// Correlation only: the sole production caller obtains every expected field
// from its actual same-J profile and completed kernel/PID1 peer originals.
fn require_hello_identity(
    body: &RootOpenBodyDataV1,
    root_profile: [u8; 32],
    observed: &RootPropertiesV1,
    root_pid: u32,
    controller: [u32; 3],
) -> Result<(), Refusal> {
    if body.root_profile != root_profile
        || body.root_recipient != observed.0.invocation
        || body.root_producer != observed.1
        || body.root_pid != root_pid
        || [body.controller_pid, body.controller_uid, body.controller_gid] != controller
    {
        return Err(Refusal::Service);
    }
    Ok(())
}

#[cfg(test)]
mod hello_tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::transport::OpenQueryV1;
    use aos_sandbox_protocol::domain_ledger::protected_names::ProtectedJournalNamesV1;

    // These are codec-valid untrusted historical DATA, never a Root owner,
    // socket, selected profile, signature or positive native fixture.
    fn body() -> RootOpenBodyDataV1 {
        RootOpenBodyDataV1 {
            open: OpenQueryV1 { controller_nonce: [1; 16], lane: [2; 16], seed: [3; 32], ready: [4; 32] },
            root_nonce: [5; 16], boot: [6; 16], started: 100, cutoff: 200,
            authority_names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            policy_names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (7, 8), (9, 10)),
            authority_next: 11, policy_next: 12, root_profile: [13; 32], root_recipient: [14; 16],
            root_producer: [15; 16], root_pid: 16, controller_pid: 17, controller_uid: 18, controller_gid: 19,
        }
    }

    #[test]
    fn canonical_hello_does_not_substitute_any_captured_peer_coordinate() {
        let original = body();
        let observed = (service::ServiceObservationV1 { fragment: "/untrusted-data-only".into(), invocation: original.root_recipient }, original.root_producer);
        let controller = [original.controller_pid, original.controller_uid, original.controller_gid];
        let decoded = RootOpenBodyDataV1::decode(&original.encode().unwrap()).unwrap();
        assert!(require_hello_identity(&decoded, original.root_profile, &observed, original.root_pid, controller).is_ok());

        let changes: [fn(&mut RootOpenBodyDataV1); 7] = [
            |body| body.root_profile[0] ^= 1,
            |body| body.root_recipient[0] ^= 1,
            |body| body.root_producer[0] ^= 1,
            |body| body.root_pid += 1,
            |body| body.controller_pid += 1,
            |body| body.controller_uid += 1,
            |body| body.controller_gid += 1,
        ];
        for change in changes {
            let mut changed = original;
            change(&mut changed);
            let decoded = RootOpenBodyDataV1::decode(&changed.encode().unwrap()).unwrap();
            assert!(require_hello_identity(&decoded, original.root_profile, &observed, original.root_pid, controller).is_err());
        }
    }
}
