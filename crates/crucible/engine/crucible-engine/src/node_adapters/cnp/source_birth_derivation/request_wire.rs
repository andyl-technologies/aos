//! Encodes the closed actual typed operand graph and literal Value subtrees.

#[path = "request_wire/error.rs"]
mod error;
#[path = "request_wire/guard.rs"]
mod guard;
#[path = "request_wire/records.rs"]
mod records;
#[path = "request_wire/request.rs"]
mod request;
#[path = "request_wire/runner.rs"]
mod runner;
#[path = "request_wire/scalar.rs"]
mod scalar;
#[path = "request_wire/value_clone.rs"]
mod value_clone;
pub use super::literal_value::LiteralWriteWorkspace as ExportWorkspace;
pub use error::{CodecError, ExportError, ProtocolFault};
pub use runner::run_worker;

/// Reports the defining fixed export header windows for the concrete sink.
///
/// The frame bank's separately requested backing/header and actual capacity
/// census remain in `ExportWorkspace`. These are workspace restrictions, not
/// observed input population or Source authorization.
pub const fn export_fixed_bytes<W: Write>() -> [usize; 6] {
    [
        std::mem::size_of::<RequestInput<'_>>(),
        REQUEST_HEADER_BYTES,
        std::mem::size_of::<Encoder<'_, std::io::Sink>>(),
        std::mem::size_of::<Encoder<'_, &mut W>>(),
        std::mem::size_of::<RequestReceipt>(),
        // Measure and emit reuse this synchronous borrowed-walker window.
        std::mem::size_of::<super::literal_value::walk::Walker<'_, false>>(),
    ]
}

use guard::{Owned, Retire};
use std::io::{self, Read, Write};

/// Names the closed private typed request edition.
pub const REQUEST_CODEC_ID: &str = "crucible.source-birth.request/1";
/// Counts the complete version-one fixed request header.
pub const REQUEST_HEADER_BYTES: usize = 160;
/// Selects the version-one request scalar/record framing.
pub const WIRE_VERSION: u32 = 1;

/// Restricts one contained operation independently of Source authority.
///
/// No defaults or request-controlled overrides exist. The installed launcher
/// supplies these bounds before executing the child. They constrain logical
/// codec/output work, not allocator, stack or total process residency; the real
/// OS envelope and parent-held cleanup owner remain mandatory.
#[derive(Clone, Copy, Debug)]
pub struct OperationalLimits {
    /// Bounds the complete request, including its fixed header.
    pub maximum_input_bytes: usize,
    /// Bounds typed decode visits plus literal read and explicit clone visits.
    ///
    /// Each borrowed writer pass uses this same bound; parent export performs
    /// two passes and needs its own installed work/storage boundary.
    pub maximum_elements: usize,
    /// Bounds both requested canonical output-bank reservations together.
    pub maximum_output_bytes: usize,
    /// Bounds complete UTF-8 diagnostic bytes, independently of output banks.
    pub maximum_diagnostic_bytes: usize,
}

/// Carries inert job/executable/algorithm correlations, never a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobContext {
    /// Binds the parent's original pending operation through its private journal.
    pub task_digest: [u8; 32],
    /// Names the exact independently measured installed worker artifact.
    pub worker_digest: [u8; 32],
    /// Names the independently measured algorithm/source/dependency selection.
    pub algorithm_digest: [u8; 32],
}

/// Carries the trusted launcher's expected installed identity DATA.
#[derive(Clone, Copy, Debug)]
pub struct ExpectedIdentity {
    /// Matches the independently measured selected executable identity.
    pub worker_digest: [u8; 32],
    /// Matches the separately installed algorithm/source/dependency identity.
    pub algorithm_digest: [u8; 32],
}

/// Borrows the actual selected nonsecret operands for one synchronous export.
///
/// Source code must obtain `expected` from its independently retained original,
/// not from reparsing or copying candidate Coordinator bytes. Constructing this
/// public DATA view authenticates none of those claims.
pub struct RequestInput<'a> {
    /// Carries inert context associated privately by the original parent.
    pub context: JobContext,
    /// Borrows the actual fields and exact token/path serialization shapes.
    pub launch: &'a crucible_node_transport::reference_packet::service::PacketNative5LaunchValidationProjection<'a>,
    /// Borrows an independent original-world operand or deferred guard refusal.
    pub expected: super::derive::ExpectedCoordinator<'a>,
    /// Borrows the actual original planned registration.
    pub registration: &'a crate::node_adapters::cnp::PacketCompleteAckHostRegistrationPlan,
}

/// Reports the commitment over actual emitted header and payload bytes.
///
/// It is copyable DATA, not an accepted input or worker capability. A Source
/// must invoke the writer itself on its real L2 prepared-input owner and retain
/// this observation under its same private once/job state before releasing loans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestReceipt {
    /// Returns the context serialized in the actual fixed header.
    pub context: JobContext,
    /// Commits the complete actual header/payload under the private input domain.
    pub input_digest: [u8; 32],
    /// Counts actual header and payload bytes written successfully.
    pub wire_bytes: usize,
    /// Counts one payload pass's actual typed/literal/clone work declarations.
    pub elements: usize,
}

/// Streams actual borrowed operands without a parent JSON DOM or launch clone.
///
/// The writer uses two bounded borrowed passes: exact payload measure/hash,
/// followed by header and actual payload writes. Every arbitrary Value uses the
/// original iterative literal codec. The concrete caller retains its original
/// operands and partial output file on any refusal; no Source permission arises.
///
/// # Errors
/// Refuses limits, unrepresentable extents, allocation/stream failure or changed
/// measured output. Earlier emitted bytes remain in the caller's same writer.
pub fn write_request<'a, W: Write>(
    input: RequestInput<'a>,
    writer: &mut W,
    limits: OperationalLimits,
    workspace: super::literal_value::LiteralWriteWorkspace<'a>,
) -> Result<RequestReceipt, ExportError> {
    request::write(input, writer, limits, workspace)
}

trait Wire: Retire + Sized {
    fn encode<'a, W: Write>(&'a self, out: &mut Encoder<'a, W>) -> Result<(), ExportError>;
    fn decode<R: Read>(input: &mut Decoder<R>) -> Result<Owned<Self>, CodecError>;
}

struct Encoder<'a, W> {
    workspace: super::literal_value::LiteralWriteWorkspace<'a>,
    writer: W,
    maximum: usize,
    bytes: usize,
    work: usize,
    maximum_work: usize,
    payload: blake3::Hasher,
    complete: blake3::Hasher,
}
impl<'a, W: Write> Encoder<'a, W> {
    fn new(
        writer: W,
        maximum: usize,
        maximum_work: usize,
        header: Option<&[u8]>,
        workspace: super::literal_value::LiteralWriteWorkspace<'a>,
    ) -> Self {
        let mut complete = blake3::Hasher::new_derive_key("crucible.source-birth.input/1");
        if let Some(header) = header {
            complete.update(header);
        }
        Self {
            workspace,
            writer,
            maximum,
            bytes: 0,
            work: 0,
            maximum_work,
            payload: blake3::Hasher::new_derive_key("crucible.source-birth.payload/1"),
            complete,
        }
    }
    fn item(&mut self) -> Result<(), ExportError> {
        self.charge(1)
    }
    fn charge(&mut self, count: usize) -> Result<(), ExportError> {
        self.work = self
            .work
            .checked_add(count)
            .ok_or(ProtocolFault::Overflow)?;
        if self.work > self.maximum_work {
            return Err(ProtocolFault::Limit.into());
        }
        Ok(())
    }
    fn remaining_work(&self) -> usize {
        self.maximum_work - self.work
    }
    fn remaining_bytes(&self) -> usize {
        self.maximum - self.bytes
    }
    fn length(&mut self, n: usize) -> Result<(), ExportError> {
        self.write_all(
            &u64::try_from(n)
                .map_err(|_| ProtocolFault::Overflow)?
                .to_be_bytes(),
        )?;
        Ok(())
    }
    fn raw(&mut self, bytes: &[u8]) -> Result<(), ExportError> {
        self.length(bytes.len())?;
        self.write_all(bytes)?;
        Ok(())
    }
}
impl<W: Write> Write for Encoder<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining_bytes() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        let n = self.writer.write(bytes)?;
        if n > bytes.len() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.bytes += n;
        self.payload.update(&bytes[..n]);
        self.complete.update(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

struct Decoder<R> {
    reader: R,
    remaining: usize,
    work: usize,
    maximum_work: usize,
    payload: blake3::Hasher,
    complete: blake3::Hasher,
}
impl<R: Read> Decoder<R> {
    fn new(reader: R, bytes: usize, limits: OperationalLimits, header: &[u8]) -> Self {
        let mut complete = blake3::Hasher::new_derive_key("crucible.source-birth.input/1");
        complete.update(header);
        Self {
            reader,
            remaining: bytes,
            work: 0,
            maximum_work: limits.maximum_elements,
            payload: blake3::Hasher::new_derive_key("crucible.source-birth.payload/1"),
            complete,
        }
    }
    fn item(&mut self) -> Result<(), CodecError> {
        self.charge(1)
    }
    fn charge(&mut self, n: usize) -> Result<(), CodecError> {
        self.work = self.work.checked_add(n).ok_or(ProtocolFault::Overflow)?;
        if self.work > self.maximum_work {
            return Err(ProtocolFault::Limit.into());
        }
        Ok(())
    }
    fn remaining_work(&self) -> usize {
        self.maximum_work - self.work
    }
    fn length(&mut self) -> Result<usize, CodecError> {
        let mut b = [0; 8];
        self.read_exact(&mut b)?;
        Ok(usize::try_from(u64::from_be_bytes(b)).map_err(|_| ProtocolFault::Overflow)?)
    }
    fn raw(&mut self) -> Result<Vec<u8>, CodecError> {
        let n = self.length()?;
        if n > self.remaining {
            return Err(ProtocolFault::Limit.into());
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(n)?;
        bytes.resize(n, 0);
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}
impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min(self.remaining);
        if n == 0 {
            return Ok(0);
        }
        let read = self.reader.read(&mut out[..n])?;
        if read > n {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        self.remaining -= read;
        self.payload.update(&out[..read]);
        self.complete.update(&out[..read]);
        Ok(read)
    }
}
fn read_field<T: Wire, R: Read>(input: &mut Decoder<R>) -> Result<Owned<T>, CodecError> {
    T::decode(input)
}

#[cfg(test)]
#[path = "request_wire/tests.rs"]
mod tests;
