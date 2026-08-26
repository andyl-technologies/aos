//! Canonical operational control messages for live campaign runtimes.
//!
//! Runtime attachment is deliberately outside immutable campaign semantics:
//! an executor socket path is a deployment detail, not modeled evidence. This
//! module nevertheless gives the local control operation one strict,
//! language-neutral, request-bound component-message contract:
//!
//! ```text
//! AttachCampaignRuntimeRequestV1 = version:u32be |
//!     principal:string | campaign:string | executor_endpoint:bytes
//! AttachCampaignRuntimeResponseV1 = version:u32be | request_digest:[u8;32] |
//!     campaign:string | disposition:u8 | attached_runtime_count:u32be
//! disposition = 1 (Attached) | 2 (Replayed)
//! string = length:u32be | utf8[length]
//! bytes = length:u32be | octets[length]
//! ```

use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crucible_campaign::{CampaignHash, CampaignName, CampaignPrincipal};
use thiserror::Error;

use crate::{ExecutorLoopbackEndpointConfig, MAX_ATTACHED_CANONICAL_CAMPAIGN_RUNTIMES};

const SCHEMA_VERSION: u32 = 1;
const REQUEST_DIGEST_DOMAIN: &str = "crucible.campaign.attach-runtime-request.v1";
/// Maximum canonical bytes in one runtime-control component message.
pub const MAX_CAMPAIGN_RUNTIME_CONTROL_MESSAGE_BYTES: usize = 4 * 1024;

/// Canonical request to attach one campaign runtime to a local executor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachCampaignRuntimeRequest {
    principal: CampaignPrincipal,
    campaign: CampaignName,
    executor_endpoint: PathBuf,
}

impl AttachCampaignRuntimeRequest {
    /// Builds one bounded runtime-attachment request.
    ///
    /// The endpoint is only an operational deployment locator. It never enters
    /// a campaign record, artifact, snapshot, or other content identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRuntimeControlCodecError::InvalidEndpoint`] when the
    /// path is not an absolute canonical Linux pathname-socket address, or
    /// [`CampaignRuntimeControlCodecError::Oversized`] when the complete
    /// canonical request exceeds the fixed message ceiling.
    pub fn new(
        principal: CampaignPrincipal,
        campaign: CampaignName,
        executor_endpoint: impl Into<PathBuf>,
    ) -> Result<Self, CampaignRuntimeControlCodecError> {
        let executor_endpoint = executor_endpoint.into();
        validate_endpoint(&executor_endpoint)?;
        let request = Self {
            principal,
            campaign,
            executor_endpoint,
        };
        ensure_size(&request.canonical_bytes())?;
        Ok(request)
    }

    /// Returns the authenticated operational principal.
    #[must_use]
    pub const fn principal(&self) -> &CampaignPrincipal {
        &self.principal
    }

    /// Returns the exact campaign selected for attachment.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns the absolute executor socket path.
    #[must_use]
    pub fn executor_endpoint(&self) -> &Path {
        &self.executor_endpoint
    }

    /// Returns the digest of every canonical request byte.
    #[must_use]
    pub fn request_digest(&self) -> CampaignHash {
        CampaignHash::derive(REQUEST_DIGEST_DOMAIN, &self.canonical_bytes())
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128);
        put_u32(&mut bytes, SCHEMA_VERSION);
        put_bytes(&mut bytes, self.principal.as_str().as_bytes());
        put_bytes(&mut bytes, self.campaign.as_str().as_bytes());
        put_bytes(&mut bytes, self.executor_endpoint.as_os_str().as_bytes());
        bytes
    }

    /// Decodes one strict bounded runtime-attachment request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRuntimeControlCodecError`] for malformed,
    /// noncanonical, unsupported, invalid, trailing, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignRuntimeControlCodecError> {
        ensure_size(bytes)?;
        let mut decoder = Decoder::new(bytes);
        decoder.require_version()?;
        let principal = CampaignPrincipal::new(decoder.string()?)
            .map_err(|_| CampaignRuntimeControlCodecError::InvalidPrincipal)?;
        let campaign = CampaignName::new(decoder.string()?)
            .map_err(|_| CampaignRuntimeControlCodecError::InvalidCampaign)?;
        let endpoint = PathBuf::from(OsString::from_vec(decoder.bytes()?.to_vec()));
        decoder.finish()?;
        let request = Self::new(principal, campaign, endpoint)?;
        if request.canonical_bytes() != bytes {
            return Err(CampaignRuntimeControlCodecError::Noncanonical);
        }
        Ok(request)
    }
}

/// Idempotent outcome of one accepted runtime-attachment request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignRuntimeAttachmentDisposition {
    /// This request installed the runtime.
    Attached,
    /// The exact request had already installed the runtime.
    Replayed,
}

impl CampaignRuntimeAttachmentDisposition {
    const fn tag(self) -> u8 {
        match self {
            Self::Attached => 1,
            Self::Replayed => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, CampaignRuntimeControlCodecError> {
        match tag {
            1 => Ok(Self::Attached),
            2 => Ok(Self::Replayed),
            _ => Err(CampaignRuntimeControlCodecError::InvalidDisposition),
        }
    }
}

/// Exact request-bound result of one runtime attachment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachCampaignRuntimeResponse {
    request_digest: CampaignHash,
    campaign: CampaignName,
    disposition: CampaignRuntimeAttachmentDisposition,
    attached_runtime_count: u32,
}

impl AttachCampaignRuntimeResponse {
    /// Builds a response for one exact accepted request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRuntimeControlCodecError::InvalidRuntimeCount`] when
    /// the reported count is zero or exceeds the daemon's fixed runtime cap.
    pub fn new(
        request: &AttachCampaignRuntimeRequest,
        disposition: CampaignRuntimeAttachmentDisposition,
        attached_runtime_count: u32,
    ) -> Result<Self, CampaignRuntimeControlCodecError> {
        validate_runtime_count(attached_runtime_count)?;
        Ok(Self {
            request_digest: request.request_digest(),
            campaign: request.campaign().clone(),
            disposition,
            attached_runtime_count,
        })
    }

    /// Returns the exact canonical request digest.
    #[must_use]
    pub const fn request_digest(&self) -> CampaignHash {
        self.request_digest
    }

    /// Returns the attached campaign.
    #[must_use]
    pub const fn campaign(&self) -> &CampaignName {
        &self.campaign
    }

    /// Returns whether this call installed or replayed the runtime.
    #[must_use]
    pub const fn disposition(&self) -> CampaignRuntimeAttachmentDisposition {
        self.disposition
    }

    /// Returns the number of live attached runtimes after acceptance.
    #[must_use]
    pub const fn attached_runtime_count(&self) -> u32 {
        self.attached_runtime_count
    }

    /// Verifies this response against the complete request basis.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRuntimeControlCodecError::ResponseMismatch`] when the
    /// response belongs to another request or campaign.
    pub fn validate_for(
        &self,
        request: &AttachCampaignRuntimeRequest,
    ) -> Result<(), CampaignRuntimeControlCodecError> {
        validate_runtime_count(self.attached_runtime_count)?;
        if self.request_digest != request.request_digest() || self.campaign != *request.campaign() {
            return Err(CampaignRuntimeControlCodecError::ResponseMismatch);
        }
        Ok(())
    }

    /// Returns strict canonical component-message bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(96);
        put_u32(&mut bytes, SCHEMA_VERSION);
        bytes.extend_from_slice(&self.request_digest.as_bytes());
        put_bytes(&mut bytes, self.campaign.as_str().as_bytes());
        bytes.push(self.disposition.tag());
        put_u32(&mut bytes, self.attached_runtime_count);
        bytes
    }

    /// Decodes one strict bounded runtime-attachment response.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignRuntimeControlCodecError`] for malformed,
    /// noncanonical, unsupported, invalid, trailing, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignRuntimeControlCodecError> {
        ensure_size(bytes)?;
        let mut decoder = Decoder::new(bytes);
        decoder.require_version()?;
        let request_digest = CampaignHash::from_bytes(decoder.fixed()?);
        let campaign = CampaignName::new(decoder.string()?)
            .map_err(|_| CampaignRuntimeControlCodecError::InvalidCampaign)?;
        let disposition = CampaignRuntimeAttachmentDisposition::from_tag(decoder.byte()?)?;
        let attached_runtime_count = decoder.u32()?;
        validate_runtime_count(attached_runtime_count)?;
        decoder.finish()?;
        let response = Self {
            request_digest,
            campaign,
            disposition,
            attached_runtime_count,
        };
        if response.canonical_bytes() != bytes {
            return Err(CampaignRuntimeControlCodecError::Noncanonical);
        }
        Ok(response)
    }
}

/// Strict runtime-control canonical-codec failure.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CampaignRuntimeControlCodecError {
    /// The message exceeds the fixed control-message bound.
    #[error("campaign runtime control message exceeds its byte bound")]
    Oversized,
    /// The message ended before a complete canonical field was available.
    #[error("campaign runtime control message is truncated")]
    Truncated,
    /// The message uses an unsupported schema version.
    #[error("campaign runtime control message version is unsupported")]
    UnsupportedVersion,
    /// Bytes remain after the complete canonical value.
    #[error("campaign runtime control message has trailing bytes")]
    TrailingBytes,
    /// A length prefix exceeds the remaining message.
    #[error("campaign runtime control field length is invalid")]
    InvalidLength,
    /// The decoded principal violates its canonical grammar.
    #[error("campaign runtime control principal is invalid")]
    InvalidPrincipal,
    /// The decoded campaign name violates its canonical grammar.
    #[error("campaign runtime control campaign name is invalid")]
    InvalidCampaign,
    /// The endpoint is not one admissible Linux pathname-socket locator.
    #[error("campaign runtime control executor endpoint is invalid")]
    InvalidEndpoint,
    /// The disposition tag is outside the closed v1 set.
    #[error("campaign runtime control disposition is invalid")]
    InvalidDisposition,
    /// The runtime count is outside the daemon's fixed attachment bound.
    #[error("campaign runtime control attached count is invalid")]
    InvalidRuntimeCount,
    /// A response does not belong to the supplied exact request.
    #[error("campaign runtime control response does not match its request")]
    ResponseMismatch,
    /// The bytes decode to a value with a different canonical representation.
    #[error("campaign runtime control message is not canonical")]
    Noncanonical,
}

fn validate_endpoint(path: &Path) -> Result<(), CampaignRuntimeControlCodecError> {
    ExecutorLoopbackEndpointConfig::new(path.to_owned(), 0, 0, 0o600)
        .map(|_| ())
        .map_err(|_| CampaignRuntimeControlCodecError::InvalidEndpoint)
}

fn validate_runtime_count(count: u32) -> Result<(), CampaignRuntimeControlCodecError> {
    let maximum = u32::try_from(MAX_ATTACHED_CANONICAL_CAMPAIGN_RUNTIMES)
        .map_err(|_| CampaignRuntimeControlCodecError::InvalidRuntimeCount)?;
    if count == 0 || count > maximum {
        return Err(CampaignRuntimeControlCodecError::InvalidRuntimeCount);
    }
    Ok(())
}

fn ensure_size(bytes: &[u8]) -> Result<(), CampaignRuntimeControlCodecError> {
    if bytes.len() > MAX_CAMPAIGN_RUNTIME_CONTROL_MESSAGE_BYTES {
        Err(CampaignRuntimeControlCodecError::Oversized)
    } else {
        Ok(())
    }
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    put_u32(output, length);
    output.extend_from_slice(bytes);
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn require_version(&mut self) -> Result<(), CampaignRuntimeControlCodecError> {
        if self.u32()? == SCHEMA_VERSION {
            Ok(())
        } else {
            Err(CampaignRuntimeControlCodecError::UnsupportedVersion)
        }
    }

    fn byte(&mut self) -> Result<u8, CampaignRuntimeControlCodecError> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or(CampaignRuntimeControlCodecError::Truncated)?;
        self.offset += 1;
        Ok(byte)
    }

    fn u32(&mut self) -> Result<u32, CampaignRuntimeControlCodecError> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CampaignRuntimeControlCodecError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(CampaignRuntimeControlCodecError::InvalidLength)?;
        let source = self
            .bytes
            .get(self.offset..end)
            .ok_or(CampaignRuntimeControlCodecError::Truncated)?;
        let mut output = [0_u8; N];
        output.copy_from_slice(source);
        self.offset = end;
        Ok(output)
    }

    fn bytes(&mut self) -> Result<&'a [u8], CampaignRuntimeControlCodecError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| CampaignRuntimeControlCodecError::InvalidLength)?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CampaignRuntimeControlCodecError::InvalidLength)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CampaignRuntimeControlCodecError::InvalidLength)?;
        self.offset = end;
        Ok(value)
    }

    fn string(&mut self) -> Result<String, CampaignRuntimeControlCodecError> {
        String::from_utf8(self.bytes()?.to_vec())
            .map_err(|_| CampaignRuntimeControlCodecError::Noncanonical)
    }

    fn finish(self) -> Result<(), CampaignRuntimeControlCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CampaignRuntimeControlCodecError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn attachment_messages_are_canonical_and_request_bound() {
        let request = AttachCampaignRuntimeRequest::new(
            CampaignPrincipal::new("operator").expect("principal"),
            CampaignName::new("nightly/signals").expect("campaign"),
            "/run/aos/executor.sock",
        )
        .expect("request");
        assert_eq!(
            AttachCampaignRuntimeRequest::from_canonical_bytes(&request.canonical_bytes())
                .expect("decode request"),
            request
        );

        let response = AttachCampaignRuntimeResponse::new(
            &request,
            CampaignRuntimeAttachmentDisposition::Attached,
            7,
        )
        .expect("response");
        response.validate_for(&request).expect("request binding");
        assert_eq!(
            AttachCampaignRuntimeResponse::from_canonical_bytes(&response.canonical_bytes())
                .expect("decode response"),
            response
        );

        let other = AttachCampaignRuntimeRequest::new(
            request.principal().clone(),
            request.campaign().clone(),
            "/run/aos/other.sock",
        )
        .expect("other request");
        assert_eq!(
            response.validate_for(&other),
            Err(CampaignRuntimeControlCodecError::ResponseMismatch)
        );
    }

    #[test]
    fn attachment_message_decoder_rejects_invalid_bounds_and_shape() {
        assert_eq!(
            AttachCampaignRuntimeRequest::from_canonical_bytes(&vec![
                0;
                MAX_CAMPAIGN_RUNTIME_CONTROL_MESSAGE_BYTES
                    + 1
            ]),
            Err(CampaignRuntimeControlCodecError::Oversized)
        );
        let request = AttachCampaignRuntimeRequest::new(
            CampaignPrincipal::new("operator").expect("principal"),
            CampaignName::new("campaign").expect("campaign"),
            "/run/aos/executor.sock",
        )
        .expect("request");
        let mut trailing = request.canonical_bytes();
        trailing.push(0);
        assert_eq!(
            AttachCampaignRuntimeRequest::from_canonical_bytes(&trailing),
            Err(CampaignRuntimeControlCodecError::TrailingBytes)
        );
        assert_eq!(
            AttachCampaignRuntimeRequest::new(
                request.principal().clone(),
                request.campaign().clone(),
                "relative.sock",
            ),
            Err(CampaignRuntimeControlCodecError::InvalidEndpoint)
        );

        let mut response = AttachCampaignRuntimeResponse::new(
            &request,
            CampaignRuntimeAttachmentDisposition::Attached,
            1,
        )
        .expect("response")
        .canonical_bytes();
        let disposition_offset = 4 + 32 + 4 + request.campaign().as_str().len();
        response[disposition_offset] = 3;
        assert_eq!(
            AttachCampaignRuntimeResponse::from_canonical_bytes(&response),
            Err(CampaignRuntimeControlCodecError::InvalidDisposition)
        );
    }

    #[test]
    fn attachment_message_golden_bytes_and_digest_are_stable() {
        let request = AttachCampaignRuntimeRequest::new(
            CampaignPrincipal::new("operator").expect("principal"),
            CampaignName::new("campaign").expect("campaign"),
            "/run/aos/executor.sock",
        )
        .expect("request");
        assert_eq!(
            encode_hex(&request.canonical_bytes()),
            "00000001000000086f70657261746f720000000863616d706169676e000000162f72756e2f616f732f6578656375746f722e736f636b"
        );
        assert_eq!(
            request.request_digest().to_hex(),
            "548c88863176613006848e15eb8dc94b7a647aea954f188646ef27bf8028af37"
        );
        let response = AttachCampaignRuntimeResponse::new(
            &request,
            CampaignRuntimeAttachmentDisposition::Attached,
            7,
        )
        .expect("response");
        assert_eq!(
            encode_hex(&response.canonical_bytes()),
            "00000001548c88863176613006848e15eb8dc94b7a647aea954f188646ef27bf8028af370000000863616d706169676e0100000007"
        );
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}
