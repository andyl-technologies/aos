//! Bounded, transport-neutral portable-object loading.

use std::io::Read;

use aos_sandbox_core::{ObjectDescriptor, descriptor_for_bytes};

const READ_SCRATCH_BYTES: usize = 8 * 1024;

/// Opens one portable object as a non-buffering byte stream.
///
/// This is a trusted adapter boundary: implementations may fetch, map, or
/// read locally, but [`ObjectSource::open`] must not first retain the complete
/// object. Transport buffering must be fixed and independent of the object
/// length. The compiler owns the only object-sized allocation and admits it
/// from the authenticated descriptor before calling the adapter.
pub trait ObjectSource {
    /// Source-specific failure.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Streaming reader returned for one object request.
    type Reader: Read;

    /// Opens the object named by the exact descriptor.
    ///
    /// The reader must begin at byte zero and reach EOF immediately after the
    /// object. The compiler verifies length and digest before decoding.
    ///
    /// # Errors
    ///
    /// Returns a source-specific error when the object cannot be opened.
    fn open(&mut self, descriptor: &ObjectDescriptor) -> Result<Self::Reader, Self::Error>;
}

/// Contains bytes proven to match an exact portable object descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExactObject(Vec<u8>);

impl ExactObject {
    /// Returns the verified stored-object bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Reports failure before portable object bytes enter graph semantics.
#[derive(Debug, thiserror::Error)]
pub enum SourceError<E: std::error::Error + 'static> {
    /// The authenticated descriptor exceeds the configured object ceiling.
    #[error("object descriptor exceeds the configured byte ceiling")]
    DescriptorTooLarge,
    /// The compiler could not reserve its admitted object buffer.
    #[error("object buffer allocation was refused")]
    AllocationRefused,
    /// The source failed to open the requested object.
    #[error("object source failed: {0}")]
    Source(#[source] E),
    /// Reading the opened object failed.
    #[error("object source read failed: {0}")]
    Read(#[source] std::io::Error),
    /// The stream ended before or continued after its authenticated length.
    #[error("object source returned a different encoded length")]
    LengthMismatch,
    /// Returned bytes differ in media type, size, or digest.
    #[error("object bytes do not match the requested descriptor")]
    DescriptorMismatch,
}

/// Loads and verifies one exact object into a compiler-owned bounded buffer.
///
/// The descriptor length is checked and the full allocation is reserved before
/// the source is opened. A fixed scratch buffer prevents transport chunking
/// from changing peak object-buffer memory.
///
/// # Errors
///
/// Returns [`SourceError`] for an oversized descriptor, allocation refusal,
/// source/read failure, length mismatch, or digest/media-type mismatch.
pub fn load_exact<S: ObjectSource>(
    source: &mut S,
    descriptor: &ObjectDescriptor,
    maximum_bytes: usize,
) -> Result<ExactObject, SourceError<S::Error>> {
    let described =
        usize::try_from(descriptor.encoded_size()).map_err(|_| SourceError::DescriptorTooLarge)?;
    if described > maximum_bytes {
        return Err(SourceError::DescriptorTooLarge);
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(described)
        .map_err(|_| SourceError::AllocationRefused)?;
    let mut reader = source.open(descriptor).map_err(SourceError::Source)?;
    let mut scratch = [0_u8; READ_SCRATCH_BYTES];
    while bytes.len() < described {
        let remaining = described - bytes.len();
        let chunk = remaining.min(scratch.len());
        let read = reader
            .read(&mut scratch[..chunk])
            .map_err(SourceError::Read)?;
        if read == 0 {
            return Err(SourceError::LengthMismatch);
        }
        bytes.extend_from_slice(&scratch[..read]);
    }
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra).map_err(SourceError::Read)? != 0 {
        return Err(SourceError::LengthMismatch);
    }

    let actual = descriptor_for_bytes(descriptor.media_type().clone(), &bytes);
    if &actual != descriptor {
        return Err(SourceError::DescriptorMismatch);
    }
    Ok(ExactObject(bytes))
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::io::Cursor;

    use aos_sandbox_core::{MediaType, descriptor_for_bytes};

    use super::*;

    struct Bytes(Vec<u8>);

    impl ObjectSource for Bytes {
        type Error = Infallible;
        type Reader = Cursor<Vec<u8>>;

        fn open(&mut self, _descriptor: &ObjectDescriptor) -> Result<Self::Reader, Self::Error> {
            Ok(Cursor::new(self.0.clone()))
        }
    }

    #[test]
    fn exact_loader_rejects_substitution_length_and_preflights_size() {
        let media = MediaType::new("application/vnd.aos.sandbox.content.v1")
            .unwrap_or_else(|error| panic!("media type failed: {error}"));
        let descriptor = descriptor_for_bytes(media.clone(), b"expected");
        let mut source = Bytes(b"substitute".to_vec());
        assert!(matches!(
            load_exact(&mut source, &descriptor, 64),
            Err(SourceError::LengthMismatch)
        ));
        let mut source = Bytes(b"replaced".to_vec());
        assert!(matches!(
            load_exact(&mut source, &descriptor, 64),
            Err(SourceError::DescriptorMismatch)
        ));
        assert!(matches!(
            load_exact(&mut source, &descriptor, 1),
            Err(SourceError::DescriptorTooLarge)
        ));
    }
}
