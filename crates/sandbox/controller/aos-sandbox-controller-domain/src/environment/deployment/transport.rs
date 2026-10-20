//! Encodes the closed Root Environment interval's comparison-only framing.
//!
//! ```text
//! open96 = AOSENQ01 | version1/reserved | operation16 | original-clock48 |
//!          unchanged-absolute-cutoff8 | original-wall-expiry8
//! response216 = AOSENR01 | version1/reserved | operation/execution/project/sandbox |
//!               generation-length8 | activation-length8 | evidence-length8 |
//!               actual-Root-clock48 | digest(open96)32 | digest(body)32
//! body = canonical-generation | canonical-prepared-activation | canonical-evidence
//! closed112 = AOSENC01 | version1/reserved | operation16 | digest(response+body)32 |
//!             actual-final-Root-clock48
//! ```
//!
//! All decoded values remain DATA. Only the genuine same-C18 client and owning
//! Root purpose may supply provenance, currentness and continuously held native
//! authority. Neither a digest nor EOF proves Source lease publication.

use aos_sandbox_model::{RawClockProvenance, RawPairedClockSample};
use sha2::{Digest as _, Sha256};

pub(crate) const OPEN_BYTES: usize = 96;
pub(crate) const RESPONSE_BYTES: usize = 216;
pub(crate) const CLOSED_BYTES: usize = 112;
const OPEN_DOMAIN: &[u8] = b"aos.environment.root.open.v1\0";
const BODY_DOMAIN: &[u8] = b"aos.environment.root.body.v1\0";
const RESPONSE_DOMAIN: &[u8] = b"aos.environment.root.response.v1\0";

#[derive(Debug, thiserror::Error)]
#[error("Root Environment framing or original comparison coordinates differ")]
pub(crate) struct EnvironmentRootWireErrorV1;

type Result<T> = std::result::Result<T, EnvironmentRootWireErrorV1>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EnvironmentRootOpenDataV1 {
    pub(crate) operation: [u8; 16],
    pub(crate) original: RawPairedClockSample,
    pub(crate) cutoff: u64,
    pub(crate) expires: i64,
}

impl EnvironmentRootOpenDataV1 {
    pub(crate) fn encode(self) -> Result<[u8; OPEN_BYTES]> {
        self.require_canonical()?;
        let mut bytes = [0; OPEN_BYTES];
        put_header(&mut bytes, b"AOSENQ01");
        bytes[16..32].copy_from_slice(&self.operation);
        put_clock(&mut bytes, 32, self.original);
        bytes[80..88].copy_from_slice(&self.cutoff.to_be_bytes());
        bytes[88..96].copy_from_slice(&self.expires.to_be_bytes());
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        header(bytes, OPEN_BYTES, b"AOSENQ01")?;
        let value = Self { operation: array(bytes, 16)?, original: clock(bytes, 32)?,
            cutoff: u64::from_be_bytes(array(bytes, 80)?),
            expires: i64::from_be_bytes(array(bytes, 88)?) };
        value.require_canonical()?;
        Ok(value)
    }

    fn require_canonical(self) -> Result<()> {
        if self.operation == [0; 16] || self.cutoff <= self.original.boottime_nanoseconds()
            || self.expires <= self.original.wall_seconds()
        { return Err(EnvironmentRootWireErrorV1); }
        Ok(())
    }

    /// Compares DATA against this unchanged, non-renewable original bound.
    pub(crate) fn require_later_sample_v1(self, actual: RawPairedClockSample) -> Result<()> {
        self.original.validate_later_sample(actual).map_err(|_| EnvironmentRootWireErrorV1)?;
        if actual.wall_seconds() >= self.expires || actual.boottime_nanoseconds() >= self.cutoff {
            return Err(EnvironmentRootWireErrorV1);
        }
        Ok(())
    }

    pub(crate) fn digest(self) -> Result<[u8; 32]> {
        Ok(Sha256::new().chain_update(OPEN_DOMAIN).chain_update(self.encode()?).finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EnvironmentRootResponseDataV1 {
    pub(crate) operation: [u8; 16],
    pub(crate) execution: [u8; 16],
    pub(crate) project: [u8; 16],
    pub(crate) sandbox: [u8; 16],
    pub(crate) generation_bytes: u64,
    pub(crate) activation_bytes: u64,
    pub(crate) evidence_bytes: u64,
    pub(crate) observed: RawPairedClockSample,
    pub(crate) opening: [u8; 32],
    pub(crate) body: [u8; 32],
}

impl EnvironmentRootResponseDataV1 {
    pub(crate) fn body_bytes(self) -> Result<usize> {
        let count = self.generation_bytes.checked_add(self.activation_bytes)
            .and_then(|bytes| bytes.checked_add(self.evidence_bytes)).ok_or(EnvironmentRootWireErrorV1)?;
        usize::try_from(count).map_err(|_| EnvironmentRootWireErrorV1)
    }

    pub(crate) fn encode(self) -> Result<[u8; RESPONSE_BYTES]> {
        self.require_canonical()?;
        let mut bytes = [0; RESPONSE_BYTES];
        put_header(&mut bytes, b"AOSENR01");
        for (offset, identity) in [(16, self.operation), (32, self.execution),
            (48, self.project), (64, self.sandbox)] {
            bytes[offset..offset + 16].copy_from_slice(&identity);
        }
        bytes[80..88].copy_from_slice(&self.generation_bytes.to_be_bytes());
        bytes[88..96].copy_from_slice(&self.activation_bytes.to_be_bytes());
        bytes[96..104].copy_from_slice(&self.evidence_bytes.to_be_bytes());
        put_clock(&mut bytes, 104, self.observed);
        bytes[152..184].copy_from_slice(&self.opening);
        bytes[184..216].copy_from_slice(&self.body);
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        header(bytes, RESPONSE_BYTES, b"AOSENR01")?;
        let value = Self { operation: array(bytes, 16)?, execution: array(bytes, 32)?,
            project: array(bytes, 48)?, sandbox: array(bytes, 64)?,
            generation_bytes: u64::from_be_bytes(array(bytes, 80)?),
            activation_bytes: u64::from_be_bytes(array(bytes, 88)?),
            evidence_bytes: u64::from_be_bytes(array(bytes, 96)?), observed: clock(bytes, 104)?,
            opening: array(bytes, 152)?, body: array(bytes, 184)? };
        value.require_canonical()?;
        Ok(value)
    }

    fn require_canonical(self) -> Result<()> {
        if [self.operation, self.execution, self.project, self.sandbox].contains(&[0; 16])
            || self.opening == [0; 32] || self.body == [0; 32]
            || self.generation_bytes == 0 || self.activation_bytes == 0 || self.evidence_bytes == 0
        { return Err(EnvironmentRootWireErrorV1); }
        self.body_bytes().map(|_| ())
    }

    pub(crate) fn require_body(self, body: &[u8]) -> Result<()> {
        if body.len() != self.body_bytes()? || body_digest(body) != self.body {
            return Err(EnvironmentRootWireErrorV1);
        }
        Ok(())
    }

    pub(crate) fn split_body(self, body: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
        self.require_body(body)?;
        let generation = usize::try_from(self.generation_bytes).map_err(|_| EnvironmentRootWireErrorV1)?;
        let activation = usize::try_from(self.activation_bytes).map_err(|_| EnvironmentRootWireErrorV1)?;
        let (generation, rest) = body.split_at(generation);
        let (activation, evidence) = rest.split_at(activation);
        Ok((generation, activation, evidence))
    }

    pub(crate) fn complete_digest(self, body: &[u8]) -> Result<[u8; 32]> {
        self.require_body(body)?;
        Ok(Sha256::new().chain_update(RESPONSE_DOMAIN).chain_update(self.encode()?)
            .chain_update(body).finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EnvironmentRootClosedDataV1 {
    pub(crate) operation: [u8; 16],
    pub(crate) response: [u8; 32],
    pub(crate) observed: RawPairedClockSample,
}

impl EnvironmentRootClosedDataV1 {
    pub(crate) fn encode(self) -> Result<[u8; CLOSED_BYTES]> {
        if self.operation == [0; 16] || self.response == [0; 32] { return Err(EnvironmentRootWireErrorV1); }
        let mut bytes = [0; CLOSED_BYTES];
        put_header(&mut bytes, b"AOSENC01");
        bytes[16..32].copy_from_slice(&self.operation);
        bytes[32..64].copy_from_slice(&self.response);
        put_clock(&mut bytes, 64, self.observed);
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        header(bytes, CLOSED_BYTES, b"AOSENC01")?;
        let value = Self { operation: array(bytes, 16)?, response: array(bytes, 32)?, observed: clock(bytes, 64)? };
        value.encode()?;
        Ok(value)
    }
}

pub(crate) fn body_digest(body: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(BODY_DOMAIN).chain_update(body).finalize().into()
}

fn header(bytes: &[u8], expected: usize, magic: &[u8; 8]) -> Result<()> {
    if bytes.len() != expected || bytes.get(..8) != Some(magic.as_slice())
        || bytes.get(8..10) != Some(1_u16.to_be_bytes().as_slice())
        || bytes.get(10..16) != Some([0; 6].as_slice())
    { return Err(EnvironmentRootWireErrorV1); }
    Ok(())
}

fn put_header(bytes: &mut [u8], magic: &[u8; 8]) {
    bytes[..8].copy_from_slice(magic);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    bytes.get(offset..offset.checked_add(N).ok_or(EnvironmentRootWireErrorV1)?)
        .ok_or(EnvironmentRootWireErrorV1)?.try_into().map_err(|_| EnvironmentRootWireErrorV1)
}

fn clock(bytes: &[u8], offset: usize) -> Result<RawPairedClockSample> {
    let provenance = RawClockProvenance::new_untrusted(array(bytes, offset)?)
        .map_err(|_| EnvironmentRootWireErrorV1)?;
    RawPairedClockSample::new_untrusted(provenance, array(bytes, offset + 16)?,
        i64::from_be_bytes(array(bytes, offset + 32)?), u64::from_be_bytes(array(bytes, offset + 40)?))
        .map_err(|_| EnvironmentRootWireErrorV1)
}

fn put_clock(bytes: &mut [u8], offset: usize, sample: RawPairedClockSample) {
    bytes[offset..offset + 16].copy_from_slice(&sample.provenance().as_bytes());
    bytes[offset + 16..offset + 32].copy_from_slice(&sample.host_boot_id());
    bytes[offset + 32..offset + 40].copy_from_slice(&sample.wall_seconds().to_be_bytes());
    bytes[offset + 40..offset + 48].copy_from_slice(&sample.boottime_nanoseconds().to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> EnvironmentRootOpenDataV1 {
        EnvironmentRootOpenDataV1 { operation: [1; 16],
            original: RawPairedClockSample::new_untrusted(
                RawClockProvenance::new_untrusted([2; 16]).unwrap(), [3; 16], 100, 1_000).unwrap(),
            cutoff: 2_000, expires: 101 }
    }

    #[test]
    fn fixed_open_keeps_the_one_original_horizon_and_rejects_new_framing() {
        let value = open();
        let encoded = value.encode().unwrap();
        assert_eq!(EnvironmentRootOpenDataV1::decode(&encoded).unwrap(), value);
        assert_eq!(&encoded[..8], b"AOSENQ01");
        let mut changed = encoded;
        changed[9] = 2;
        assert!(EnvironmentRootOpenDataV1::decode(&changed).is_err());
        let mut expired = value;
        expired.cutoff = value.original.boottime_nanoseconds();
        assert!(expired.encode().is_err());
    }

    #[test]
    fn whole_response_body_and_operation_remain_bound_through_closed_data() {
        let open = open();
        let body = b"genactivationevidence";
        let response = EnvironmentRootResponseDataV1 { operation: open.operation,
            execution: [4; 16], project: [5; 16], sandbox: [6; 16],
            generation_bytes: 3, activation_bytes: 10, evidence_bytes: 8,
            observed: open.original, opening: open.digest().unwrap(), body: body_digest(body) };
        let encoded = response.encode().unwrap();
        let decoded = EnvironmentRootResponseDataV1::decode(&encoded).unwrap();
        assert_eq!(decoded.split_body(body).unwrap(), (&b"gen"[..], &b"activation"[..], &b"evidence"[..]));
        assert!(decoded.require_body(b"genactivationchanged!").is_err());
        let closed = EnvironmentRootClosedDataV1 { operation: open.operation,
            response: decoded.complete_digest(body).unwrap(), observed: open.original };
        assert_eq!(EnvironmentRootClosedDataV1::decode(&closed.encode().unwrap()).unwrap(), closed);
    }
}
