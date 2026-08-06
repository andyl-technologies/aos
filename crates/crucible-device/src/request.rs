//! The device-agnostic request, response, and latency vocabulary.
//!
//! This module owns the *shape* of the request/response lifecycle without
//! committing to any concrete device semantics (disk, 9p, net land in later
//! changesets). A [`Request`] carries the requester's emit icount and an opaque
//! payload; a [`Response`] carries the COMPUTEd status and payload; a
//! [`LatencyModel`] maps a request to a modeled latency in nanoseconds.
//!
//! The critical contract is that latency is a deterministic function of the
//! request alone ([IO-4]): it never reads the host clock, host scheduling, or
//! how long the host actually spent producing the payload.

/// A correlation identifier echoed from a request to its response.
///
/// Opaque to the sub-node core; concrete devices map it to their wire
/// `request_id`.
pub type RequestId = u32;

/// The terminal status of a COMPUTEd response.
///
/// Concrete devices map richer device errors (out-of-range read, `EROFS`, a
/// dropped frame) onto these two outcomes at their wire boundary; the uniform
/// core only needs to know whether the operation succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseStatus {
    /// The operation completed successfully.
    Ok,
    /// The operation failed; the payload, if any, is device-defined error data.
    Error,
}

/// A request observed at the requester's emit icount.
///
/// The payload is opaque bytes the concrete device interprets. The
/// `request_icount` is the requester's icount at ARRIVE; it is the base for the
/// completion-time computation ([IO-2]) and never the host clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The requester's icount when the request was emitted (ARRIVE time).
    pub request_icount: u64,
    /// The correlation id echoed into the response.
    pub request_id: RequestId,
    /// The opaque device request payload.
    pub payload: Vec<u8>,
}

impl Request {
    /// Creates a request at the given emit icount with an opaque payload.
    #[must_use]
    pub fn new(request_icount: u64, request_id: RequestId, payload: Vec<u8>) -> Self {
        Self {
            request_icount,
            request_id,
            payload,
        }
    }
}

/// A COMPUTEd response whose visibility is gated on `delivery_icount`.
///
/// The status and payload are fixed at COMPUTE; the `delivery_icount` is the
/// exact virtual-time instant at which the response becomes visible to the
/// consumer ([IO-2]). Until the consumer clock reaches it, the response sits in
/// the in-flight queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// The correlation id echoed from the originating request.
    pub request_id: RequestId,
    /// The COMPUTEd terminal status.
    pub status: ResponseStatus,
    /// The COMPUTEd response payload (read data, length, or device error bytes).
    pub payload: Vec<u8>,
}

impl Response {
    /// Creates a response with a fixed status and payload.
    #[must_use]
    pub fn new(request_id: RequestId, status: ResponseStatus, payload: Vec<u8>) -> Self {
        Self {
            request_id,
            status,
            payload,
        }
    }
}

/// One additional protocol-valid completion derived from a primary response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdditionalCompletion {
    /// Delay after the primary completion in virtual nanoseconds.
    pub gap_nanos: u64,
    /// Exact duplicate or protocol-transformed response.
    pub response: Response,
}

/// Complete deterministic COMPUTE result before delivery-time scheduling.
///
/// A device returns the primary response together with adapter-owned timing and
/// duplication decisions. [`crate::subnode::IoCore`] converts every nanosecond
/// delay to the device clock exactly once and inserts all completions into its
/// canonical delivery order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComputedResponse {
    /// Primary response, or none when completion is intentionally retained.
    pub primary: Option<Response>,
    /// Additional delay applied after the device's immutable base latency.
    pub additional_latency_nanos: u64,
    /// Ordered protocol-valid additional completions.
    pub additional: Vec<AdditionalCompletion>,
}

impl ComputedResponse {
    /// Builds an ordinary result with no dynamic delay or duplicate.
    #[must_use]
    pub fn primary(response: Response) -> Self {
        Self {
            primary: Some(response),
            additional_latency_nanos: 0,
            additional: Vec::new(),
        }
    }

    /// Builds a retained result that schedules no completion yet.
    #[must_use]
    pub const fn retained() -> Self {
        Self {
            primary: None,
            additional_latency_nanos: 0,
            additional: Vec::new(),
        }
    }
}

/// A deterministic map from a request to its modeled latency in nanoseconds.
///
/// Implementations MUST be pure functions of the request (and per-device
/// parameters baked into the implementor) — never of host timing ([IO-4],
/// [IO-22]). The returned value is added to the requester's virtual time to
/// derive the completion instant.
pub trait LatencyModel {
    /// Returns the modeled latency of `request` in virtual nanoseconds.
    ///
    /// The result MUST depend only on the request and per-device parameters,
    /// never on the host clock or how long the host COMPUTE actually took.
    fn latency_ns(&self, request: &Request) -> u64;
}

/// A latency model with a fixed base plus a per-payload-byte component.
///
/// Models `base_ns + per_byte_ns * request.payload.len()`, saturating at
/// `u64::MAX` so an adversarial byte count cannot panic. This is the device-
/// agnostic default; concrete devices may supply richer models that still honor
/// the purity contract of [`LatencyModel`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffineLatency {
    /// The fixed latency floor in nanoseconds.
    pub base_ns: u64,
    /// The per-payload-byte latency increment in nanoseconds.
    pub per_byte_ns: u64,
}

impl AffineLatency {
    /// Creates an affine latency model from a base and a per-byte increment.
    #[must_use]
    pub fn new(base_ns: u64, per_byte_ns: u64) -> Self {
        Self {
            base_ns,
            per_byte_ns,
        }
    }
}

impl LatencyModel for AffineLatency {
    fn latency_ns(&self, request: &Request) -> u64 {
        let len = request.payload.len() as u64;
        let variable = self.per_byte_ns.saturating_mul(len);
        self.base_ns.saturating_add(variable)
    }
}
