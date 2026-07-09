//! Per-device adapters that fit the three sub-nodes to the uniform harness.
//!
//! The three I/O sub-nodes expose structurally-different surfaces:
//!
//! - [`BlockDevice`] and [`NinepDevice`] ride [`IoCore`](crate::subnode::IoCore)
//!   and answer `submit(icount, request)` / `advance_to(limit)` /
//!   `core_mut().pop_response()`;
//! - [`NetLink`] has its own `emit(frame, draws, policy)` / `advance_to(limit)` /
//!   `next_delivery(limit)`.
//!
//! This module owns one thin [`HarnessDevice`] adapter per
//! kind — [`BlockHarness`], [`NinepHarness`], [`NetLinkHarness`] — that projects
//! each surface onto the harness's three uniform operations (apply a request,
//! advance the clock, drain normalized [`DeliveryRecord`]s)
//! so the run-twice/divergence/idle-busy-poll machinery is written once and
//! reused across all three ([IO-27]). Each adapter drains through the device's
//! own [`IoCore`](crate::subnode::IoCore)/in-flight queue, so the delivery key
//! (`delivery_icount`, `src_node`, `seq`) is preserved verbatim in every record
//! ([IO-10]).

use crate::block::BlockDevice;
use crate::block::codec::BlockRequest;
use crate::error::DeviceError;
use crate::netlink::link::{Frame, FrameDraws, NetLink, PastDeliveryPolicy};
// `Delivery` is reached transitively through `NetLink::advance_to`'s return type.
use crate::ninep::device::NinepDevice;
use crate::request::ResponseStatus;

use super::{DeliveryRecord, HarnessDevice};

/// A [`HarnessDevice`] adapter over a [`BlockDevice`].
///
/// Wraps an owned block device; [`HarnessDevice::apply_request`] encodes and
/// submits a [`BlockRequest`], and [`HarnessDevice::drain_records`] pops every
/// delivered [`PendingResponse`](crate::inflight::PendingResponse) through the
/// composed [`IoCore`](crate::subnode::IoCore) so the full delivery key is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHarness {
    device: BlockDevice,
}

impl BlockHarness {
    /// Wraps a block device for harness driving.
    #[must_use]
    pub fn new(device: BlockDevice) -> Self {
        Self { device }
    }

    /// Returns a shared reference to the wrapped device.
    ///
    /// Tests use this to assert device-visible state (overlay pages, dirty set,
    /// length) after a run ([IO-27]).
    #[must_use]
    pub fn device(&self) -> &BlockDevice {
        &self.device
    }

    /// Returns a mutable reference to the wrapped device.
    pub fn device_mut(&mut self) -> &mut BlockDevice {
        &mut self.device
    }
}

impl HarnessDevice for BlockHarness {
    type Request = BlockRequest;

    fn apply_request(
        &mut self,
        at_icount: u64,
        request: &Self::Request,
    ) -> Result<(), DeviceError> {
        self.device.submit(at_icount, request)
    }

    fn advance_to(&mut self, limit: u64) -> Result<(), DeviceError> {
        self.device.advance_to(limit)?;
        Ok(())
    }

    fn drain_records(&mut self) -> Result<Vec<DeliveryRecord>, DeviceError> {
        let mut records = Vec::new();
        while let Some(pending) = self.device.core_mut().pop_response() {
            records.push(DeliveryRecord::new(
                pending.key,
                pending.response.request_id,
                pending.response.status,
                pending.response.payload,
            ));
        }
        Ok(records)
    }

    fn next_exact_local_event(&self) -> Option<u64> {
        self.device.core().next_exact_local_event()
    }
}

/// A [`HarnessDevice`] adapter over a [`NinepDevice`].
///
/// Wraps an owned 9p device; [`HarnessDevice::apply_request`] submits a raw 9p
/// request frame, and [`HarnessDevice::drain_records`] pops every delivered reply
/// through the composed [`IoCore`](crate::subnode::IoCore) so the delivery key
/// and the reply frame bytes land in each record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NinepHarness {
    device: NinepDevice,
}

impl NinepHarness {
    /// Wraps a 9p device for harness driving.
    #[must_use]
    pub fn new(device: NinepDevice) -> Self {
        Self { device }
    }

    /// Returns a shared reference to the wrapped device.
    ///
    /// Tests use this to assert device-visible state (the fid table, negotiated
    /// `msize`) after a run ([IO-27]).
    #[must_use]
    pub fn device(&self) -> &NinepDevice {
        &self.device
    }

    /// Returns a mutable reference to the wrapped device.
    pub fn device_mut(&mut self) -> &mut NinepDevice {
        &mut self.device
    }
}

impl HarnessDevice for NinepHarness {
    /// A 9p request is an encoded request frame's bytes.
    type Request = Vec<u8>;

    fn apply_request(
        &mut self,
        at_icount: u64,
        request: &Self::Request,
    ) -> Result<(), DeviceError> {
        self.device.submit(at_icount, request)
    }

    fn advance_to(&mut self, limit: u64) -> Result<(), DeviceError> {
        self.device.advance_to(limit)?;
        Ok(())
    }

    fn drain_records(&mut self) -> Result<Vec<DeliveryRecord>, DeviceError> {
        let mut records = Vec::new();
        while let Some(pending) = self.device.core_mut().pop_response() {
            records.push(DeliveryRecord::new(
                pending.key,
                pending.response.request_id,
                pending.response.status,
                pending.response.payload,
            ));
        }
        Ok(records)
    }

    fn next_exact_local_event(&self) -> Option<u64> {
        self.device.core().next_exact_local_event()
    }
}

/// A [`HarnessDevice`] adapter over a [`NetLink`].
///
/// The link's request is a `(Frame, FrameDraws)` pair plus a fixed
/// [`PastDeliveryPolicy`] chosen at construction; [`HarnessDevice::apply_request`]
/// `emit`s the frame with its injected draws, and [`HarnessDevice::drain_records`]
/// pulls every due [`Delivery`](crate::netlink::link::Delivery) — which carries
/// the delivery key, the frame id, and the (possibly corrupted) payload — out via
/// `next_delivery`. A link delivery is always [`ResponseStatus::Ok`] (loss is
/// absence of a delivery, not an error status), matching the link's response
/// model.
///
/// The `emit` frame ignores the harness's `at_icount` because a link [`Frame`]
/// carries its own `emit_icount`; the adapter therefore keys delivery off the
/// frame's own emit icount, and the harness `at_icount` is unused for links. This
/// is the one place the three surfaces genuinely differ, and it is contained
/// entirely here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetLinkHarness {
    link: NetLink,
    policy: PastDeliveryPolicy,
    /// Records delivered by `advance_to` but not yet drained.
    ///
    /// [`NetLink::advance_to`] *returns* and removes the due deliveries from the
    /// in-flight queue in one call (unlike the [`IoCore`](crate::subnode::IoCore)
    /// devices, which push due responses onto a separate outbox). The adapter
    /// buffers them here so [`HarnessDevice::drain_records`] can hand them out in
    /// the same uniform pull model, in their delivered order.
    pending: Vec<DeliveryRecord>,
}

/// A network-link harness request: a frame and its injected fault draws.
///
/// The link is the one sub-node whose request is not an opaque payload — it
/// carries the [`Frame`] to deliver and the [`FrameDraws`] that resolve its
/// probabilistic faults deterministically ([IO-20], [IO-4]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkRequest {
    /// The frame to emit (carries its own `emit_icount`).
    pub frame: Frame,
    /// The injected RNG draws resolving this frame's faults.
    pub draws: FrameDraws,
}

impl LinkRequest {
    /// Builds a link request from a frame and its draws.
    #[must_use]
    pub fn new(frame: Frame, draws: FrameDraws) -> Self {
        Self { frame, draws }
    }
}

impl NetLinkHarness {
    /// Wraps a link with the past-delivery policy to apply on every emit.
    #[must_use]
    pub fn new(link: NetLink, policy: PastDeliveryPolicy) -> Self {
        Self {
            link,
            policy,
            pending: Vec::new(),
        }
    }

    /// Returns a shared reference to the wrapped link.
    ///
    /// Tests use this to assert link-visible state (in-flight count, the
    /// next exact local event) after a run ([IO-27]).
    #[must_use]
    pub fn link(&self) -> &NetLink {
        &self.link
    }

    /// Returns a mutable reference to the wrapped link.
    pub fn link_mut(&mut self) -> &mut NetLink {
        &mut self.link
    }
}

impl HarnessDevice for NetLinkHarness {
    type Request = LinkRequest;

    fn apply_request(
        &mut self,
        _at_icount: u64,
        request: &Self::Request,
    ) -> Result<(), DeviceError> {
        // The frame carries its own emit_icount; `at_icount` is unused for links.
        self.link
            .emit(&request.frame, &request.draws, self.policy)?;
        Ok(())
    }

    fn advance_to(&mut self, limit: u64) -> Result<(), DeviceError> {
        // `NetLink::advance_to` advances the clock and *returns* the due
        // deliveries, removing them from the in-flight queue. Capture them into
        // the pending buffer so `drain_records` can hand them out uniformly.
        let due = self.link.advance_to(limit)?;
        self.pending.extend(due.into_iter().map(|delivery| {
            DeliveryRecord::new(
                delivery.key,
                delivery.frame_id,
                ResponseStatus::Ok,
                delivery.payload,
            )
        }));
        Ok(())
    }

    fn drain_records(&mut self) -> Result<Vec<DeliveryRecord>, DeviceError> {
        Ok(core::mem::take(&mut self.pending))
    }

    fn next_exact_local_event(&self) -> Option<u64> {
        self.link.next_exact_local_event()
    }
}
