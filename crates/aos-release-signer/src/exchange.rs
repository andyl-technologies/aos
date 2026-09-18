//! Binary framing of the `sign-exchange-v1` operation.
//!
//! The coordinator writes the request domain, a 64-bit big-endian request
//! length, canonical request JSON, a 64-bit payload length, and the exact
//! payload bytes. The adapter answers with the response domain, a framed
//! canonical response, and a framed transformed output that is empty for
//! detached operations.

use std::io::{Read, Write};

use anyhow::{Context as _, Result, bail};

/// Domain prefix written before every signing request.
pub const REQUEST_DOMAIN: &[u8] = b"aos.release.signer-exchange/v1\0";

/// Domain prefix written before every signing response.
pub const RESPONSE_DOMAIN: &[u8] = b"aos.release.signer-exchange-response/v1\0";

/// Largest canonical request the adapter accepts.
pub const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

/// Largest payload the adapter accepts; large enough for a unified kernel image.
pub const MAX_PAYLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// One complete request read from the coordinator.
#[derive(Debug)]
pub struct ExchangeRequest {
    /// Canonical signing-request JSON bytes.
    pub request: Vec<u8>,
    /// Exact public payload or unsigned artifact bytes.
    pub payload: Vec<u8>,
}

/// Reads one complete framed request and requires the stream to end after it.
///
/// # Errors
///
/// Returns an error for a wrong domain, a frame longer than its limit, a
/// truncated stream, or trailing bytes after the payload.
pub fn read_request(reader: &mut impl Read) -> Result<ExchangeRequest> {
    let mut domain = vec![0_u8; REQUEST_DOMAIN.len()];
    reader
        .read_exact(&mut domain)
        .context("reading signer request domain")?;
    if domain != REQUEST_DOMAIN {
        bail!("signer request uses an unknown exchange domain");
    }
    let request = read_frame(reader, MAX_REQUEST_BYTES, "signing request")?;
    let payload = read_frame(reader, MAX_PAYLOAD_BYTES, "signing payload")?;

    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .context("checking for trailing bytes")?
        != 0
    {
        bail!("signer request carries trailing bytes after its payload");
    }
    Ok(ExchangeRequest { request, payload })
}

/// Writes the framed response and transformed output.
///
/// # Errors
///
/// Returns an error when the writer fails.
pub fn write_response(writer: &mut impl Write, response: &[u8], output: &[u8]) -> Result<()> {
    writer.write_all(RESPONSE_DOMAIN)?;
    write_frame(writer, response)?;
    write_frame(writer, output)?;
    writer.flush()?;
    Ok(())
}

fn read_frame(reader: &mut impl Read, maximum: u64, label: &str) -> Result<Vec<u8>> {
    let mut length = [0_u8; 8];
    reader
        .read_exact(&mut length)
        .with_context(|| format!("reading {label} length"))?;
    let length = u64::from_be_bytes(length);
    if length > maximum {
        bail!("{label} exceeds its {maximum}-byte limit");
    }
    let mut bytes = vec![0_u8; usize::try_from(length)?];
    reader
        .read_exact(&mut bytes)
        .with_context(|| format!("reading {label} bytes"))?;
    Ok(bytes)
}

fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> Result<()> {
    writer.write_all(&u64::try_from(bytes.len())?.to_be_bytes())?;
    writer.write_all(bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(request: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut bytes = REQUEST_DOMAIN.to_vec();
        write_frame(&mut bytes, request).unwrap();
        write_frame(&mut bytes, payload).unwrap();
        bytes
    }

    #[test]
    fn reads_a_complete_request() {
        let bytes = framed(b"{}", b"payload");
        let request = read_request(&mut bytes.as_slice()).unwrap();
        assert_eq!(request.request, b"{}");
        assert_eq!(request.payload, b"payload");
    }

    #[test]
    fn rejects_wrong_domain_and_trailing_bytes() {
        let mut wrong = framed(b"{}", b"payload");
        wrong[0] ^= 1;
        assert!(read_request(&mut wrong.as_slice()).is_err());

        let mut trailing = framed(b"{}", b"payload");
        trailing.push(0);
        assert!(read_request(&mut trailing.as_slice()).is_err());
    }

    #[test]
    fn response_framing_matches_the_coordinator_reader() {
        let mut bytes = Vec::new();
        write_response(&mut bytes, b"response", b"").unwrap();
        let mut expected = RESPONSE_DOMAIN.to_vec();
        expected.extend(8_u64.to_be_bytes());
        expected.extend(b"response");
        expected.extend(0_u64.to_be_bytes());
        assert_eq!(bytes, expected);
    }
}
