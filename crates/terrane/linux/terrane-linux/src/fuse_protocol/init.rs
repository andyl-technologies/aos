//! Selects a bounded read-only FUSE protocol from an actual kernel INIT offer.
//!
//! The Linux UAPI's native-order response has a fixed 64-byte storage bound.
//! Negotiation alone grants no backing registration or mount authority. The
//! dispatcher must enforce INIT ordering and send the response successfully
//! before accepting operations under the selected protocol.
//!
//! ```text
//! major | minor | max_readahead | flags | background:u16 | congestion:u16 |
//! max_write | time_gran | max_pages:u16 | map_alignment:u16 | flags2 |
//! max_stack_depth | reserved[6]
//! ```

use super::Request;
use std::fmt;

const MAJOR: u32 = 7;
const MINOR: u32 = 40;
const EXTENDED: u32 = 1 << 30;
const PASSTHROUGH: u32 = 1 << 5;
const NO_EXPORT: u32 = 1 << 6;

/// Selects whether a connection may use implemented native backing registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Passthrough {
    /// Uses passthrough only when both the kernel and worker support it.
    Auto,
    /// Refuses initialization unless both participants support passthrough.
    Require,
    /// Serves reads without negotiating passthrough.
    Off,
}

/// Bounds protocol fields by the worker's already allocated request buffer.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Complete device-read buffer size, including protocol overhead.
    pub request_bytes: usize,
    /// Maximum readahead bytes accepted from the kernel's offer.
    pub readahead_bytes: u32,
    /// Maximum simultaneously pending background requests; must be nonzero.
    pub background_requests: u16,
}

/// Describes initialization failure without accepting subsequent operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The request is not an ordinary rootless INIT or has malformed fields.
    Encoding,
    /// The worker cannot serve the offered major or minor protocol.
    Version,
    /// Required passthrough is unavailable in the worker or kernel.
    PassthroughUnavailable,
    /// Configured request or background bounds cannot support the protocol.
    Limit,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Encoding => "invalid FUSE INIT request",
            Self::Version => "unsupported FUSE protocol version",
            Self::PassthroughUnavailable => "required FUSE passthrough unavailable",
            Self::Limit => "invalid FUSE initialization bounds",
        })
    }
}

impl std::error::Error for Error {}

/// Owns one initialization body without claiming the kernel accepted it.
#[derive(Clone, Debug)]
pub struct Initialization {
    bytes: [u8; 64],
    length: usize,
    selected: Option<(u32, bool)>,
}

impl Initialization {
    /// Borrows the exact response body, excluding the ordinary reply header.
    pub fn body(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    /// Returns the selected minor and passthrough mode, or a major-version retry.
    ///
    /// `None` requires another actual INIT. `Some` still requires a successful
    /// connection write before any operation can use the selected protocol.
    pub const fn selected(&self) -> Option<(u32, bool)> {
        self.selected
    }
}

/// Selects only protocol features implemented by the original worker.
///
/// Negotiation supports FUSE 7.31 through 7.40. A newer major receives the UAPI's
/// short version retry, ignoring its remaining body. Unknown offered flags are
/// never echoed. Passthrough requires explicit local implementation readiness;
/// a kernel capability bit alone does not establish native custody. A selected
/// passthrough connection reserves one stacking level for its non-stacked
/// backing, leaving room for an overlay above it. Writeback, export, request
/// extensions, ACLs and permission-changing operations are never negotiated.
///
/// # Errors
/// Refuses malformed INIT headers/bodies or reserved fields, older unsupported
/// versions, impossible buffer bounds and unavailable required passthrough.
pub fn negotiate(
    request: Request<'_>,
    limits: Limits,
    policy: Passthrough,
    backing_registration_ready: bool,
) -> Result<Initialization, Error> {
    if limits.request_bytes < 8192
        || u32::try_from(limits.request_bytes).is_err()
        || limits.background_requests == 0
    {
        return Err(Error::Limit);
    }
    if request.opcode() != 26 || request.node() != 0 || request.unique() == 0 {
        return Err(Error::Encoding);
    }
    let major = request.body_u32(0).map_err(|_| Error::Encoding)?;
    let mut response = Initialization {
        bytes: [0; 64],
        length: 64,
        selected: None,
    };
    put(&mut response.bytes, 0, MAJOR);
    put(&mut response.bytes, 4, MINOR);
    if major > MAJOR {
        response.length = 8;
        return Ok(response);
    }
    if major != MAJOR {
        return Err(Error::Version);
    }
    let minor = request.body_u32(4).map_err(|_| Error::Encoding)?;
    if minor < 31 {
        return Err(Error::Version);
    }
    let flags = request.body_u32(12).map_err(|_| Error::Encoding)?;
    let extended = minor >= 36 && flags & EXTENDED != 0;
    if request.body().len() != if extended { 64 } else { 16 } {
        return Err(Error::Encoding);
    }
    let flags2 = if extended {
        if request.body()[20..].iter().any(|byte| *byte != 0) {
            return Err(Error::Encoding);
        }
        request.body_u32(16).map_err(|_| Error::Encoding)?
    } else {
        0
    };
    let available = minor >= 40 && flags2 & PASSTHROUGH != 0 && backing_registration_ready;
    if policy == Passthrough::Require && !available {
        return Err(Error::PassthroughUnavailable);
    }
    let passthrough = available && policy != Passthrough::Off;
    let selected = minor.min(MINOR);
    put(&mut response.bytes, 4, selected);
    let readahead = request.body_u32(8).map_err(|_| Error::Encoding)?;
    put(
        &mut response.bytes,
        8,
        readahead.min(limits.readahead_bytes),
    );
    response.bytes[16..18].copy_from_slice(&limits.background_requests.to_ne_bytes());
    response.bytes[18..20].copy_from_slice(&(limits.background_requests / 2).max(1).to_ne_bytes());
    // Kernel device reads require a page of header space above max_write even
    // on a read-only service. Keep this field within the actual supplied buffer.
    put(
        &mut response.bytes,
        20,
        (limits.request_bytes - 4096).min(131072) as u32,
    );
    put(&mut response.bytes, 24, 1);
    let no_export = if selected >= 40 {
        flags2 & NO_EXPORT
    } else {
        0
    };
    let selected_flags2 = no_export | if passthrough { PASSTHROUGH } else { 0 };
    put(&mut response.bytes, 32, selected_flags2);
    put(&mut response.bytes, 36, u32::from(passthrough));
    response.selected = Some((selected, passthrough));
    Ok(response)
}

fn put(bytes: &mut [u8; 64], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

#[cfg(test)]
mod tests;
