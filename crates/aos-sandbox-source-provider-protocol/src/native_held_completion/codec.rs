//! Checked byte mechanics for the closed native held-completion formats.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::{NativeHeldCompletionErrorV1, Result};

pub(super) fn invalid(reason: &'static str) -> NativeHeldCompletionErrorV1 {
    NativeHeldCompletionErrorV1::Invalid(reason)
}

pub(super) fn nonzero(value: ObjectDigest) -> bool {
    value.as_bytes() != &[0; 32]
}

pub(super) fn digest(domain: &[u8], bytes: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(domain)
            .chain_update(bytes)
            .finalize()
            .into(),
    )
}

pub(super) fn put_length(bytes: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| invalid("length overflow"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn bytes(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid("length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid("truncated value"))?;
        self.offset = end;
        Ok(value)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| invalid("fixed-width value"))
    }

    pub(super) fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(super) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(super) fn digest(&mut self) -> Result<ObjectDigest> {
        Ok(ObjectDigest::from_bytes(self.array()?))
    }

    pub(super) fn zeros(&mut self, length: usize) -> Result<()> {
        if self.bytes(length)?.iter().any(|byte| *byte != 0) {
            return Err(invalid("reserved bytes"));
        }
        Ok(())
    }

    pub(super) fn header(&mut self, magic: &[u8; 8]) -> Result<()> {
        if self.bytes(8)? != magic || self.u16()? != 1 {
            return Err(invalid("magic or version"));
        }
        Ok(())
    }

    pub(super) fn finish(self) -> Result<()> {
        if self.offset != self.bytes.len() {
            return Err(invalid("trailing bytes"));
        }
        Ok(())
    }
}
