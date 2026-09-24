//! Bounded primitive reads for advanced policy recovery records.

use super::AdvancedNetworkPolicyError;

/// Reads canonical recovery fields without advancing past a truncated input.
pub(super) struct RecoveryReader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> RecoveryReader<'a> {
    pub(super) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub(super) fn take(&mut self, length: usize) -> Result<&'a [u8], AdvancedNetworkPolicyError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(AdvancedNetworkPolicyError::NonCanonical)?;
        self.cursor = end;
        Ok(value)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], AdvancedNetworkPolicyError> {
        self.take(N)?
            .try_into()
            .map_err(|_| AdvancedNetworkPolicyError::NonCanonical)
    }

    pub(super) fn byte(&mut self) -> Result<u8, AdvancedNetworkPolicyError> {
        Ok(self.array::<1>()?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, AdvancedNetworkPolicyError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(super) fn u32(&mut self) -> Result<u32, AdvancedNetworkPolicyError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, AdvancedNetworkPolicyError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(super) fn boolean(&mut self) -> Result<bool, AdvancedNetworkPolicyError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AdvancedNetworkPolicyError::NonCanonical),
        }
    }

    pub(super) fn blob(
        &mut self,
        maximum: usize,
    ) -> Result<Option<&'a [u8]>, AdvancedNetworkPolicyError> {
        let length =
            usize::try_from(self.u32()?).map_err(|_| AdvancedNetworkPolicyError::NonCanonical)?;
        if length == 0 {
            return Ok(None);
        }
        if length > maximum {
            return Err(AdvancedNetworkPolicyError::NonCanonical);
        }
        Ok(Some(self.take(length)?))
    }

    pub(super) fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}
