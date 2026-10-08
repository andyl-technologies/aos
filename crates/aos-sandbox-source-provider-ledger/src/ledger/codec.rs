//! Bounded primitive codecs shared by the closed AOSSPL01 record bodies.

use aos_sandbox_core::{
    ObjectDigest,
    bounded_codec::{BoundedReader, ReadError},
};
use aos_sandbox_source_provider_protocol::{
    SourceProviderAuthorityV1, SourceProviderKeyUsageV1, SourceProviderSigningKeyV1,
};

use super::LedgerFormatErrorV1;
use super::model::SourceRootIdentityV1;

pub(super) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub(super) fn array<const N: usize>(&mut self, value: &[u8; N]) {
        self.bytes(value);
    }

    pub(super) fn zeros(&mut self, count: usize) {
        self.bytes.resize(self.bytes.len() + count, 0);
    }

    pub(super) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(super) fn u32(&mut self, value: u32) {
        self.bytes(&value.to_be_bytes());
    }

    pub(super) fn u64(&mut self, value: u64) {
        self.bytes(&value.to_be_bytes());
    }

    pub(super) fn i64(&mut self, value: i64) {
        self.bytes(&value.to_be_bytes());
    }

    pub(super) fn digest(&mut self, value: ObjectDigest) {
        self.array(value.as_bytes());
    }

    pub(super) fn optional_digest(&mut self, value: Option<ObjectDigest>) {
        self.digest(value.unwrap_or_else(|| ObjectDigest::from_bytes([0; 32])));
    }

    pub(super) fn optional_array<const N: usize>(&mut self, value: Option<[u8; N]>) {
        self.array(&value.unwrap_or([0; N]));
    }

    pub(super) fn optional_i64(&mut self, value: Option<i64>) {
        self.i64(value.unwrap_or(-1));
    }

    pub(super) fn authority(&mut self, value: &SourceProviderAuthorityV1) {
        self.array(&value.authority_id());
        self.u64(value.authority_generation());
        self.digest(value.authority_digest());
    }

    pub(super) fn signer(&mut self, value: &SourceProviderSigningKeyV1) {
        self.array(&value.authority_id());
        self.u64(value.authority_generation());
        self.digest(value.authority_digest());
        self.array(&value.key_id());
        self.u64(value.key_generation());
        self.digest(value.public_key_digest());
        self.u8(value.usage() as u8);
        self.zeros(7);
    }

    pub(super) fn source_root(&mut self, value: Option<SourceRootIdentityV1>) {
        let value = value.unwrap_or(SourceRootIdentityV1 {
            kernel_boot_id: [0; 16],
            device: 0,
            inode: 0,
            unique_mount_id: 0,
        });
        self.array(&value.kernel_boot_id);
        self.u64(value.device);
        self.u64(value.inode);
        self.u64(value.unique_mount_id);
    }
}

pub(super) struct Decoder<'a> {
    reader: BoundedReader<'a, LedgerFormatErrorV1>,
    // Fixed-layout checks observe consumed bytes; Core owns cursor advances.
    initial_len: usize,
}

impl<'a> Decoder<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self {
            reader: BoundedReader::new(bytes, body_read_error),
            initial_len: bytes.len(),
        }
    }

    pub(super) fn offset(&self) -> usize {
        self.initial_len - self.reader.remaining()
    }

    pub(super) fn take(&mut self, count: usize) -> Result<&'a [u8], LedgerFormatErrorV1> {
        self.reader.bytes(count)
    }

    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8; N], LedgerFormatErrorV1> {
        self.take(N)?
            .try_into()
            .map_err(|_| LedgerFormatErrorV1::Corrupt("truncated array"))
    }

    pub(super) fn nonzero_array<const N: usize>(&mut self) -> Result<[u8; N], LedgerFormatErrorV1> {
        let value = self.array()?;
        if value == [0; N] {
            return Err(LedgerFormatErrorV1::Corrupt("zero identity"));
        }
        Ok(value)
    }

    pub(super) fn optional_array<const N: usize>(
        &mut self,
    ) -> Result<Option<[u8; N]>, LedgerFormatErrorV1> {
        let value = self.array()?;
        Ok((value != [0; N]).then_some(value))
    }

    pub(super) fn u8(&mut self) -> Result<u8, LedgerFormatErrorV1> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn nonzero_u8(&mut self) -> Result<u8, LedgerFormatErrorV1> {
        let value = self.u8()?;
        if value == 0 {
            Err(LedgerFormatErrorV1::Corrupt("zero code"))
        } else {
            Ok(value)
        }
    }

    pub(super) fn u32(&mut self) -> Result<u32, LedgerFormatErrorV1> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub(super) fn nonzero_u32(&mut self) -> Result<u32, LedgerFormatErrorV1> {
        let value = self.u32()?;
        if value == 0 {
            Err(LedgerFormatErrorV1::Corrupt("zero u32"))
        } else {
            Ok(value)
        }
    }

    pub(super) fn u64(&mut self) -> Result<u64, LedgerFormatErrorV1> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub(super) fn nonzero_u64(&mut self) -> Result<u64, LedgerFormatErrorV1> {
        let value = self.u64()?;
        if value == 0 {
            Err(LedgerFormatErrorV1::Corrupt("zero generation"))
        } else {
            Ok(value)
        }
    }

    pub(super) fn i64(&mut self) -> Result<i64, LedgerFormatErrorV1> {
        Ok(i64::from_be_bytes(self.array()?))
    }

    pub(super) fn nonnegative_i64(&mut self) -> Result<i64, LedgerFormatErrorV1> {
        let value = self.i64()?;
        if value < 0 {
            Err(LedgerFormatErrorV1::Corrupt("negative time"))
        } else {
            Ok(value)
        }
    }

    pub(super) fn optional_i64(&mut self) -> Result<Option<i64>, LedgerFormatErrorV1> {
        let value = self.i64()?;
        if value == -1 {
            Ok(None)
        } else if value >= 0 {
            Ok(Some(value))
        } else {
            Err(LedgerFormatErrorV1::Corrupt("invalid optional time"))
        }
    }

    pub(super) fn digest(&mut self) -> Result<ObjectDigest, LedgerFormatErrorV1> {
        Ok(ObjectDigest::from_bytes(self.array()?))
    }

    pub(super) fn nonzero_digest(&mut self) -> Result<ObjectDigest, LedgerFormatErrorV1> {
        let value = self.digest()?;
        if value.as_bytes() == &[0; 32] {
            Err(LedgerFormatErrorV1::Corrupt("zero digest"))
        } else {
            Ok(value)
        }
    }

    pub(super) fn optional_digest(&mut self) -> Result<Option<ObjectDigest>, LedgerFormatErrorV1> {
        let value = self.digest()?;
        Ok((value.as_bytes() != &[0; 32]).then_some(value))
    }

    pub(super) fn boolean(&mut self) -> Result<bool, LedgerFormatErrorV1> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(LedgerFormatErrorV1::Corrupt("noncanonical boolean")),
        }
    }

    pub(super) fn zeros(&mut self, count: usize) -> Result<(), LedgerFormatErrorV1> {
        if self.take(count)?.iter().any(|byte| *byte != 0) {
            Err(LedgerFormatErrorV1::Corrupt("nonzero reserved bytes"))
        } else {
            Ok(())
        }
    }

    pub(super) fn bounded_len(&mut self, maximum: usize) -> Result<usize, LedgerFormatErrorV1> {
        let value = self.u32()? as usize;
        if value > maximum {
            Err(LedgerFormatErrorV1::LimitExceeded("record artifact"))
        } else {
            Ok(value)
        }
    }

    pub(super) fn authority(&mut self) -> Result<SourceProviderAuthorityV1, LedgerFormatErrorV1> {
        SourceProviderAuthorityV1::new(
            self.nonzero_array()?,
            self.nonzero_u64()?,
            self.nonzero_digest()?,
        )
        .map_err(|_| LedgerFormatErrorV1::Corrupt("authority reference"))
    }

    pub(super) fn signer(&mut self) -> Result<SourceProviderSigningKeyV1, LedgerFormatErrorV1> {
        let authority_id = self.nonzero_array()?;
        let authority_generation = self.nonzero_u64()?;
        let authority_digest = self.nonzero_digest()?;
        let key_id = self.nonzero_array()?;
        let key_generation = self.nonzero_u64()?;
        let public_key_digest = self.nonzero_digest()?;
        let usage = match self.u8()? {
            1 => SourceProviderKeyUsageV1::RootMountHello,
            2 => SourceProviderKeyUsageV1::ProviderHello,
            3 => SourceProviderKeyUsageV1::RootMountRecord,
            4 => SourceProviderKeyUsageV1::ProviderOutcome,
            5 => SourceProviderKeyUsageV1::CatalogPublisher,
            _ => return Err(LedgerFormatErrorV1::Corrupt("signer usage")),
        };
        self.zeros(7)?;
        SourceProviderSigningKeyV1::new(
            authority_id,
            authority_generation,
            authority_digest,
            key_id,
            key_generation,
            public_key_digest,
            usage,
        )
        .map_err(|_| LedgerFormatErrorV1::Corrupt("signer reference"))
    }

    pub(super) fn optional_source_root(
        &mut self,
        present: bool,
    ) -> Result<Option<SourceRootIdentityV1>, LedgerFormatErrorV1> {
        let value = SourceRootIdentityV1 {
            kernel_boot_id: self.array()?,
            device: self.u64()?,
            inode: self.u64()?,
            unique_mount_id: self.u64()?,
        };
        let is_zero = value.kernel_boot_id == [0; 16]
            && value.device == 0
            && value.inode == 0
            && value.unique_mount_id == 0;
        if present
            && !is_zero
            && value.kernel_boot_id != [0; 16]
            && value.device > 0
            && value.inode > 0
            && value.unique_mount_id > 0
        {
            Ok(Some(value))
        } else if !present && is_zero {
            Ok(None)
        } else {
            Err(LedgerFormatErrorV1::Corrupt("source-root identity"))
        }
    }

    pub(super) fn finish(&self) -> Result<(), LedgerFormatErrorV1> {
        if self.reader.is_empty() {
            Ok(())
        } else {
            Err(LedgerFormatErrorV1::Corrupt("trailing record bytes"))
        }
    }
}

fn body_read_error(error: ReadError) -> LedgerFormatErrorV1 {
    match error {
        ReadError::LengthOverflow => LedgerFormatErrorV1::Corrupt("body offset overflow"),
        ReadError::Truncated => LedgerFormatErrorV1::Corrupt("truncated record body"),
        ReadError::NonzeroReserved => LedgerFormatErrorV1::Corrupt("nonzero reserved bytes"),
        ReadError::TrailingBytes => LedgerFormatErrorV1::Corrupt("trailing record bytes"),
    }
}

pub(super) fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], LedgerFormatErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(LedgerFormatErrorV1::Corrupt("truncated envelope"))
}

pub(super) fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, LedgerFormatErrorV1> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

pub(super) fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, LedgerFormatErrorV1> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_failures_preserve_offset_and_reserved_and_tail_checks_keep_their_order() {
        let mut reader = Decoder::new(&[0, 1, 0]);
        assert_eq!(reader.u8().unwrap(), 0);
        assert_eq!(reader.offset(), 1);

        assert!(matches!(
            reader.take(usize::MAX),
            Err(LedgerFormatErrorV1::Corrupt("body offset overflow"))
        ));
        assert!(matches!(
            reader.array::<3>(),
            Err(LedgerFormatErrorV1::Corrupt("truncated record body"))
        ));
        assert_eq!(reader.offset(), 1);

        assert!(matches!(
            reader.zeros(1),
            Err(LedgerFormatErrorV1::Corrupt("nonzero reserved bytes"))
        ));
        assert_eq!(reader.offset(), 2);
        assert!(matches!(
            reader.finish(),
            Err(LedgerFormatErrorV1::Corrupt("trailing record bytes"))
        ));

        assert_eq!(reader.take(1).unwrap(), &[0]);
        reader.finish().unwrap();
        assert_eq!(reader.offset(), 3);
    }

    #[test]
    fn semantic_field_refusals_keep_consumed_bytes_and_exact_errors() {
        let mut digest = Decoder::new(&[0; 32]);
        assert!(matches!(
            digest.nonzero_digest(),
            Err(LedgerFormatErrorV1::Corrupt("zero digest"))
        ));
        assert_eq!(digest.offset(), 32);
        digest.finish().unwrap();

        let bytes = 2_u32.to_be_bytes();
        let mut length = Decoder::new(&bytes);
        assert!(matches!(
            length.bounded_len(1),
            Err(LedgerFormatErrorV1::LimitExceeded("record artifact"))
        ));
        assert_eq!(length.offset(), bytes.len());
        length.finish().unwrap();
    }
}
