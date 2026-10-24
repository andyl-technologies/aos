//! Encodes bounded, session-bound requests for immutable logical RAM pages.
//!
//! A page source retains its backing lease independently of these records.
//! Receivers bind the complete root record before using this protocol and
//! verify the opaque proof with their logical RAM implementation. Session and
//! owner fields are operational namespaces and never enter a RAM digest.
//!
//! ```text
//! request = magic:8 | edition:4 | binding:72 | sequence:8 | region:4 | page:8
//! response = magic:8 | edition:4 | binding:72 | sequence:8 | status:1
//!            reserved:3 | page-length:4 | proof-length:4 | page | proof
//! binding = session:16 | owner-incarnation:16 | source-generation:8 | root:32
//! ```

use std::io::{self, Read, Write};

use thiserror::Error;

/// The single admitted page service edition.
pub const RAM_PAGE_PROTOCOL_EDITION: u32 = 1;

/// The fixed encoded request size.
pub const RAM_PAGE_REQUEST_BYTES: usize = 104;

/// The fixed response prefix size, checked before allocating a payload.
pub const RAM_PAGE_RESPONSE_HEADER_BYTES: usize = 104;

/// The maximum valid bytes in one logical page.
pub const RAM_PAGE_MAX_BYTES: usize = 4096;

/// The maximum encoded logical proof, including a 255-byte region identifier.
pub const RAM_PAGE_MAX_PROOF_BYTES: usize = 2048;

/// The largest admitted response including its fixed prefix.
pub const RAM_PAGE_MAX_RESPONSE_BYTES: usize =
    RAM_PAGE_RESPONSE_HEADER_BYTES + RAM_PAGE_MAX_BYTES + RAM_PAGE_MAX_PROOF_BYTES;

const REQUEST_MAGIC: &[u8; 8] = b"CRUPRQ01";
const RESPONSE_MAGIC: &[u8; 8] = b"CRUPRS01";
const MAX_REGION_ORDINAL: u32 = 4095;
const MAX_PAGE_INDEX: u64 = (1_u64 << 52) - 1;

/// An authenticated source namespace, independent of physical residency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamPageBinding {
    /// Fresh identifier for this independently owned source endpoint.
    pub session: [u8; 16],
    /// Fresh process/controller incarnation selecting this source owner.
    pub owner_incarnation: [u8; 16],
    /// Positive retained-source generation within that incarnation.
    pub source_generation: u64,
    /// Separately authenticated logical scoped root digest.
    pub root_digest: [u8; 32],
}

impl RamPageBinding {
    /// Validates operational namespace fields without interpreting a RAM digest.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero session, owner incarnation, or generation.
    pub fn validate(self) -> Result<(), RamPageProtocolError> {
        if self.session == [0; 16]
            || self.owner_incarnation == [0; 16]
            || self.source_generation == 0
        {
            return Err(RamPageProtocolError::Invalid("empty source namespace"));
        }
        Ok(())
    }

    fn write(self, output: &mut [u8]) {
        output[..16].copy_from_slice(&self.session);
        output[16..32].copy_from_slice(&self.owner_incarnation);
        output[32..40].copy_from_slice(&self.source_generation.to_be_bytes());
        output[40..72].copy_from_slice(&self.root_digest);
    }

    fn read(input: &[u8]) -> Result<Self, RamPageProtocolError> {
        let mut session = [0; 16];
        let mut owner_incarnation = [0; 16];
        let mut root_digest = [0; 32];
        session.copy_from_slice(&input[..16]);
        owner_incarnation.copy_from_slice(&input[16..32]);
        root_digest.copy_from_slice(&input[40..72]);
        let binding = Self {
            session,
            owner_incarnation,
            source_generation: read_u64(&input[32..40]),
            root_digest,
        };
        binding.validate()?;
        Ok(binding)
    }
}

/// One immutable logical page selected within a previously bound root record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamPageRequest {
    /// The exact session, owner incarnation, generation, and logical root.
    pub binding: RamPageBinding,
    /// Positive, strictly increasing request sequence checked by the service.
    pub sequence: u64,
    /// Canonical region inventory ordinal, checked against the bound inventory.
    pub region_ordinal: u32,
    /// Real logical page index, excluding padding positions.
    pub page_index: u64,
}

impl RamPageRequest {
    /// Encodes one fixed-size request after validating scalar bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty namespace, zero sequence, or excessive
    /// region ordinal or page index.
    pub fn encode(self) -> Result<[u8; RAM_PAGE_REQUEST_BYTES], RamPageProtocolError> {
        self.validate()?;
        let mut output = [0; RAM_PAGE_REQUEST_BYTES];
        output[..8].copy_from_slice(REQUEST_MAGIC);
        output[8..12].copy_from_slice(&RAM_PAGE_PROTOCOL_EDITION.to_be_bytes());
        self.binding.write(&mut output[12..84]);
        output[84..92].copy_from_slice(&self.sequence.to_be_bytes());
        output[92..96].copy_from_slice(&self.region_ordinal.to_be_bytes());
        output[96..104].copy_from_slice(&self.page_index.to_be_bytes());
        Ok(output)
    }

    /// Decodes an exact-length request without allocating.
    ///
    /// # Errors
    ///
    /// Returns an error for a truncated, trailing, incompatible, or invalid
    /// request. Inventory membership requires the separately bound root record.
    pub fn decode(input: &[u8]) -> Result<Self, RamPageProtocolError> {
        if input.len() != RAM_PAGE_REQUEST_BYTES {
            return Err(RamPageProtocolError::Invalid("request length"));
        }
        check_prefix(input, REQUEST_MAGIC)?;
        let request = Self {
            binding: RamPageBinding::read(&input[12..84])?,
            sequence: read_u64(&input[84..92]),
            region_ordinal: read_u32(&input[92..96]),
            page_index: read_u64(&input[96..104]),
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(self) -> Result<(), RamPageProtocolError> {
        self.binding.validate()?;
        if self.sequence == 0
            || self.region_ordinal > MAX_REGION_ORDINAL
            || self.page_index > MAX_PAGE_INDEX
        {
            return Err(RamPageProtocolError::Invalid("request coordinates"));
        }
        Ok(())
    }
}

/// A closed service result; every failure carries no page or proof bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RamPageStatus {
    /// Authenticated page bytes and a logical proof are present.
    Page = 1,
    /// The selected logical coordinate is absent from the bound root.
    Absent = 2,
    /// Sticky source cancellation revoked admission.
    Canceled = 3,
    /// Namespace, sequence, or source ownership did not match.
    Rejected = 4,
    /// Required backing could not be read or authenticated.
    Unavailable = 5,
}

impl RamPageStatus {
    fn decode(value: u8) -> Result<Self, RamPageProtocolError> {
        match value {
            1 => Ok(Self::Page),
            2 => Ok(Self::Absent),
            3 => Ok(Self::Canceled),
            4 => Ok(Self::Rejected),
            5 => Ok(Self::Unavailable),
            _ => Err(RamPageProtocolError::Invalid("response status")),
        }
    }
}

/// A bounded response borrowing authenticated page and opaque proof bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RamPageResponse<'a> {
    /// Exact source namespace echoed by the owner.
    pub binding: RamPageBinding,
    /// Exact request sequence echoed by the owner.
    pub sequence: u64,
    /// The closed result of the request.
    pub status: RamPageStatus,
    /// Valid logical bytes; partial final pages are never padded here.
    pub page: &'a [u8],
    /// Bounded opaque logical proof encoded by the RAM format implementation.
    pub proof: &'a [u8],
}

impl RamPageResponse<'_> {
    /// Encodes one response after enforcing all independent payload bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid namespace, zero sequence, invalid payload
    /// shape, excessive page/proof lengths, or allocation failure.
    pub fn encode(self) -> Result<Vec<u8>, RamPageProtocolError> {
        self.validate()?;
        let length = RAM_PAGE_RESPONSE_HEADER_BYTES + self.page.len() + self.proof.len();
        let mut output = Vec::new();
        output
            .try_reserve_exact(length)
            .map_err(|_| RamPageProtocolError::Allocation)?;
        output.resize(RAM_PAGE_RESPONSE_HEADER_BYTES, 0);
        output[..8].copy_from_slice(RESPONSE_MAGIC);
        output[8..12].copy_from_slice(&RAM_PAGE_PROTOCOL_EDITION.to_be_bytes());
        self.binding.write(&mut output[12..84]);
        output[84..92].copy_from_slice(&self.sequence.to_be_bytes());
        output[92] = self.status as u8;
        output[96..100].copy_from_slice(&(self.page.len() as u32).to_be_bytes());
        output[100..104].copy_from_slice(&(self.proof.len() as u32).to_be_bytes());
        output.extend_from_slice(self.page);
        output.extend_from_slice(self.proof);
        Ok(output)
    }

    /// Decodes a complete response without allocating or accepting trailing data.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible fields, excessive declared lengths,
    /// inconsistent status/payload shape, truncation, or trailing bytes.
    pub fn decode(input: &[u8]) -> Result<RamPageResponse<'_>, RamPageProtocolError> {
        if input.len() < RAM_PAGE_RESPONSE_HEADER_BYTES {
            return Err(RamPageProtocolError::Invalid("response prefix length"));
        }
        let (binding, sequence, status, page_length, proof_length) =
            decode_response_header(&input[..RAM_PAGE_RESPONSE_HEADER_BYTES])?;
        let length = RAM_PAGE_RESPONSE_HEADER_BYTES + page_length + proof_length;
        if input.len() != length {
            return Err(RamPageProtocolError::Invalid("response length"));
        }
        Ok(RamPageResponse {
            binding,
            sequence,
            status,
            page: &input
                [RAM_PAGE_RESPONSE_HEADER_BYTES..RAM_PAGE_RESPONSE_HEADER_BYTES + page_length],
            proof: &input[RAM_PAGE_RESPONSE_HEADER_BYTES + page_length..],
        })
    }

    fn validate(self) -> Result<(), RamPageProtocolError> {
        self.binding.validate()?;
        validate_payload(
            self.sequence,
            self.status,
            self.page.len(),
            self.proof.len(),
        )
    }
}

/// A wire, allocation, or transport failure during page source exchange.
#[derive(Debug, Error)]
pub enum RamPageProtocolError {
    /// A bounded wire record was invalid or incompatible.
    #[error("invalid RAM page protocol: {0}")]
    Invalid(&'static str),
    /// A bounded response allocation failed.
    #[error("RAM page protocol allocation failed")]
    Allocation,
    /// The stream failed before completing a record.
    #[error("RAM page source transport failed: {0}")]
    Io(#[from] io::Error),
}

/// Reads one fixed request into a stack buffer before decoding it.
///
/// # Errors
///
/// Returns a transport error for incomplete reads or a codec error for invalid
/// fields. Callers install their operational deadline on the stream.
pub fn read_ram_page_request(
    reader: &mut impl Read,
) -> Result<RamPageRequest, RamPageProtocolError> {
    let mut bytes = [0; RAM_PAGE_REQUEST_BYTES];
    reader.read_exact(&mut bytes)?;
    RamPageRequest::decode(&bytes)
}

/// Reads a response after validating its prefix before any payload allocation.
///
/// # Errors
///
/// Returns a transport or codec error for incomplete or invalid records, or an
/// allocation error. The returned buffer remains bounded by the protocol limit.
pub fn read_ram_page_response(reader: &mut impl Read) -> Result<Vec<u8>, RamPageProtocolError> {
    let mut header = [0; RAM_PAGE_RESPONSE_HEADER_BYTES];
    reader.read_exact(&mut header)?;
    let (_, _, _, page_length, proof_length) = decode_response_header(&header)?;
    let length = RAM_PAGE_RESPONSE_HEADER_BYTES + page_length + proof_length;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| RamPageProtocolError::Allocation)?;
    bytes.extend_from_slice(&header);
    bytes.resize(length, 0);
    reader.read_exact(&mut bytes[RAM_PAGE_RESPONSE_HEADER_BYTES..])?;
    Ok(bytes)
}

/// Writes one complete response without exposing a native layout.
///
/// # Errors
///
/// Returns validation, allocation, or stream errors before a full record is sent.
pub fn write_ram_page_response(
    writer: &mut impl Write,
    response: RamPageResponse<'_>,
) -> Result<(), RamPageProtocolError> {
    writer.write_all(&response.encode()?)?;
    Ok(())
}

type ResponseHeader = (RamPageBinding, u64, RamPageStatus, usize, usize);

fn decode_response_header(input: &[u8]) -> Result<ResponseHeader, RamPageProtocolError> {
    check_prefix(input, RESPONSE_MAGIC)?;
    if input[93..96] != [0; 3] {
        return Err(RamPageProtocolError::Invalid(
            "nonzero reserved response bytes",
        ));
    }
    let binding = RamPageBinding::read(&input[12..84])?;
    let sequence = read_u64(&input[84..92]);
    let status = RamPageStatus::decode(input[92])?;
    let page_length = read_u32(&input[96..100]) as usize;
    let proof_length = read_u32(&input[100..104]) as usize;
    validate_payload(sequence, status, page_length, proof_length)?;
    Ok((binding, sequence, status, page_length, proof_length))
}

fn validate_payload(
    sequence: u64,
    status: RamPageStatus,
    page_length: usize,
    proof_length: usize,
) -> Result<(), RamPageProtocolError> {
    if sequence == 0 || page_length > RAM_PAGE_MAX_BYTES || proof_length > RAM_PAGE_MAX_PROOF_BYTES
    {
        return Err(RamPageProtocolError::Invalid("response payload bounds"));
    }
    if (status == RamPageStatus::Page && (page_length == 0 || proof_length == 0))
        || (status != RamPageStatus::Page && (page_length != 0 || proof_length != 0))
    {
        return Err(RamPageProtocolError::Invalid("response payload shape"));
    }
    Ok(())
}

fn check_prefix(input: &[u8], magic: &[u8; 8]) -> Result<(), RamPageProtocolError> {
    if &input[..8] != magic || read_u32(&input[8..12]) != RAM_PAGE_PROTOCOL_EDITION {
        return Err(RamPageProtocolError::Invalid("wire edition or magic"));
    }
    Ok(())
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> RamPageBinding {
        RamPageBinding {
            session: [1; 16],
            owner_incarnation: [2; 16],
            source_generation: 3,
            root_digest: [4; 32],
        }
    }

    #[test]
    fn request_has_fixed_big_endian_coordinates_and_rejects_trailing_data() {
        let request = RamPageRequest {
            binding: binding(),
            sequence: 5,
            region_ordinal: 6,
            page_index: 7,
        };
        let bytes = request
            .encode()
            .unwrap_or_else(|error| panic!("invalid page fixture: {error}"));

        assert_eq!(bytes.len(), RAM_PAGE_REQUEST_BYTES);
        assert_eq!(&bytes[84..92], &5_u64.to_be_bytes());
        assert_eq!(
            RamPageRequest::decode(&bytes)
                .unwrap_or_else(|error| panic!("invalid page fixture: {error}")),
            request
        );
        assert!(RamPageRequest::decode(&bytes[..103]).is_err());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(RamPageRequest::decode(&trailing).is_err());
    }

    #[test]
    fn response_rejects_excessive_lengths_before_reading_payload() {
        let response = RamPageResponse {
            binding: binding(),
            sequence: 1,
            status: RamPageStatus::Page,
            page: &[1],
            proof: &[2],
        };
        let mut bytes = response
            .encode()
            .unwrap_or_else(|error| panic!("invalid page fixture: {error}"));
        bytes[96..100].copy_from_slice(&u32::MAX.to_be_bytes());
        bytes.truncate(RAM_PAGE_RESPONSE_HEADER_BYTES);
        let mut input = io::Cursor::new(bytes);

        assert!(matches!(
            read_ram_page_response(&mut input),
            Err(RamPageProtocolError::Invalid(_))
        ));
        assert_eq!(input.position(), RAM_PAGE_RESPONSE_HEADER_BYTES as u64);
    }

    #[test]
    fn failures_cannot_carry_page_bytes_or_accept_unknown_status() {
        let response = RamPageResponse {
            binding: binding(),
            sequence: 1,
            status: RamPageStatus::Canceled,
            page: &[],
            proof: &[],
        };
        let bytes = response
            .encode()
            .unwrap_or_else(|error| panic!("invalid page fixture: {error}"));

        assert_eq!(
            RamPageResponse::decode(&bytes)
                .unwrap_or_else(|error| panic!("invalid page fixture: {error}")),
            response
        );
        assert!(
            RamPageResponse {
                page: &[0],
                ..response
            }
            .encode()
            .is_err()
        );
        let mut unknown = bytes;
        unknown[92] = 0;
        assert!(RamPageResponse::decode(&unknown).is_err());
    }

    #[test]
    fn reserved_bytes_and_zero_namespaces_fail_closed() {
        let response = RamPageResponse {
            binding: binding(),
            sequence: 1,
            status: RamPageStatus::Rejected,
            page: &[],
            proof: &[],
        };
        let mut bytes = response
            .encode()
            .unwrap_or_else(|error| panic!("invalid page fixture: {error}"));
        bytes[93] = 1;
        assert!(RamPageResponse::decode(&bytes).is_err());
        assert!(
            RamPageBinding {
                session: [0; 16],
                ..binding()
            }
            .validate()
            .is_err()
        );
    }
}
