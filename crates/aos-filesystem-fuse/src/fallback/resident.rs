//! Resident reads from retained admitted fs-verity descriptions.
//!
//! There is intentionally no production constructor: immutable bytes are not
//! consumer disclosure authority. Repository fixtures supply their own sealed
//! descriptions. No pathname, network fetch or caller-shaped proof is used.

use std::fs::File;
#[cfg(any(test, feature = "test-fixtures"))]
use std::os::fd::AsFd;
use std::os::unix::fs::{FileExt, MetadataExt};

use aos_filesystem_view::{
    DataError, ObjectReadRequest, ObjectReadResult, RequestCheckpoint, RequestControl,
    RequestControlState, VerifiedObjectReader,
};
use aos_sandbox_core::{ObjectDescriptor, format::ObjectDescriptorVerifier};
use aos_sandbox_linux::immutable_file::FsVerityBacking;

use crate::control::Control;

struct ResidentObject {
    descriptor: ObjectDescriptor,
    backing: FsVerityBacking,
    reader: File,
}

pub(super) struct ResidentVerifiedReader {
    objects: Vec<ResidentObject>,
    verification: Vec<u8>,
    cancellation: libc::c_int,
}

impl ResidentVerifiedReader {
    #[cfg(any(test, feature = "test-fixtures"))]
    pub(super) fn for_fixture(
        objects: Vec<(ObjectDescriptor, FsVerityBacking)>,
        cancellation: libc::c_int,
    ) -> Result<Self, DataError> {
        // Two owned FDs per object (admission pin and positioned reader),
        // plus fixed verification scratch; no descriptors open during READ.
        if objects.is_empty() || objects.len() > 32 || cancellation < 0 {
            return Err(DataError::ResourceExhausted);
        }
        let mut admitted = Vec::new();
        admitted
            .try_reserve_exact(objects.len())
            .map_err(|_| DataError::AllocationRefused)?;
        for (descriptor, backing) in objects {
            if descriptor.encoded_size() > 64 * 1024 * 1024
                || descriptor.encoded_size() != backing.identity().bytes()
                || admitted
                    .iter()
                    .any(|prior: &ResidentObject| prior.descriptor == descriptor)
            {
                return Err(DataError::IntegrityFailure);
            }
            let reader = File::from(
                backing
                    .as_fd()
                    .try_clone_to_owned()
                    .map_err(|_| DataError::IntegrityFailure)?,
            );
            admitted.push(ResidentObject {
                descriptor,
                backing,
                reader,
            });
        }
        let mut verification = Vec::new();
        verification
            .try_reserve_exact(65_536)
            .map_err(|_| DataError::AllocationRefused)?;
        if verification.capacity() > 65_536 {
            return Err(DataError::ResourceExhausted);
        }
        verification.resize(65_536, 0);
        Ok(Self {
            objects: admitted,
            verification,
            cancellation,
        })
    }
}

impl VerifiedObjectReader for ResidentVerifiedReader {
    fn read_verified(
        &mut self,
        request: ObjectReadRequest<'_>,
        destination: &mut [u8],
    ) -> Result<ObjectReadResult, DataError> {
        // All outputs are private staging; even validation failures discard
        // any bytes left by an earlier attempt in the same caller scratch.
        destination.fill(0);
        let object = self
            .objects
            .iter()
            .find(|object| {
                object.descriptor.digest() == request.descriptor.digest()
                    && object.descriptor.encoded_size() == request.descriptor.encoded_size()
                    && object.descriptor.media_type().as_str() == request.descriptor.media_type()
            })
            .ok_or(DataError::IntegrityFailure)?;
        let control = Control::from_absolute_deadline(self.cancellation, request.deadline_ns)
            .map_err(|_| DataError::DeadlineExpired)?;
        let end = request
            .object_offset
            .checked_add(request.length as u64)
            .ok_or(DataError::InvalidRequest)?;
        if destination.len() != request.length || end > object.descriptor.encoded_size() {
            return Err(DataError::InvalidRequest);
        }

        let result = verify_and_read(
            object,
            request,
            destination,
            &mut self.verification,
            &control,
        );
        self.verification.fill(0);
        if result.is_err() {
            destination.fill(0);
        }
        result
    }
}

fn verify_and_read(
    object: &ResidentObject,
    request: ObjectReadRequest<'_>,
    destination: &mut [u8],
    verification: &mut [u8],
    control: &Control,
) -> Result<ObjectReadResult, DataError> {
    check_control(control)?;
    check_identity(object)?;
    verify_complete_file(&object.reader, &object.descriptor, verification, control)?;
    check_identity(object)?;
    check_control(control)?;

    // A same retained sealed inode cannot change between full verification and
    // slice copying. Never accept a verified prefix of an unverified object.
    read_exact_at(&object.reader, destination, request.object_offset, control)?;
    check_identity(object)?;
    check_control(control)?;
    Ok(ObjectReadResult::Complete {
        digest: object.descriptor.digest(),
        encoded_size: object.descriptor.encoded_size(),
        object_offset: request.object_offset,
        bytes: destination.len(),
    })
}

// Hash mechanics alone establish no seal, backing admission or read grant.
// The only caller that publishes slices first checks the retained backing.
fn verify_complete_file(
    file: &File,
    descriptor: &ObjectDescriptor,
    verification: &mut [u8],
    control: &Control,
) -> Result<(), DataError> {
    if verification.is_empty() {
        return Err(DataError::ResourceExhausted);
    }
    check_control(control)?;
    let mut verifier = ObjectDescriptorVerifier::new(descriptor.clone());
    let mut position = 0_u64;
    while position < descriptor.encoded_size() {
        check_control(control)?;
        let remaining = descriptor.encoded_size() - position;
        let amount = usize::try_from(remaining.min(verification.len() as u64))
            .map_err(|_| DataError::ResourceExhausted)?;
        read_exact_at(file, &mut verification[..amount], position, control)?;
        verifier
            .update(&verification[..amount])
            .map_err(|_| DataError::IntegrityFailure)?;
        position += amount as u64;
    }
    // Descriptor size and actual EOF must agree, including empty objects.
    let mut trailing = [0_u8; 1];
    if file
        .read_at(&mut trailing, position)
        .map_err(|_| DataError::IntegrityFailure)?
        != 0
    {
        return Err(DataError::IntegrityFailure);
    }
    verifier.finish().map_err(|_| DataError::IntegrityFailure)?;
    check_control(control)?;
    Ok(())
}

fn read_exact_at(
    file: &File,
    mut output: &mut [u8],
    mut offset: u64,
    control: &Control,
) -> Result<(), DataError> {
    while !output.is_empty() {
        check_control(control)?;
        let amount = match file.read_at(output, offset) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.map_err(|_| DataError::IntegrityFailure)?,
        };
        if amount == 0 {
            return Err(DataError::IntegrityFailure);
        }
        offset = offset
            .checked_add(amount as u64)
            .ok_or(DataError::IntegrityFailure)?;
        output = &mut output[amount..];
    }
    Ok(())
}

fn check_identity(object: &ResidentObject) -> Result<(), DataError> {
    let metadata = object
        .reader
        .metadata()
        .map_err(|_| DataError::IntegrityFailure)?;
    let admitted = object.backing.identity();
    if !metadata.is_file()
        || metadata.dev() != admitted.device()
        || metadata.ino() != admitted.inode()
        || metadata.len() != admitted.bytes()
    {
        return Err(DataError::IntegrityFailure);
    }
    Ok(())
}

fn check_control(control: &Control) -> Result<(), DataError> {
    match control.state(RequestCheckpoint::DuringReadOnlyWork) {
        RequestControlState::Continue => Ok(()),
        RequestControlState::Cancelled => Err(DataError::Cancelled),
        RequestControlState::DeadlineExpired => Err(DataError::DeadlineExpired),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    use aos_sandbox_core::{MediaType, ObjectDigest, descriptor_for_bytes};

    use super::*;

    // These regular-file tests check the private descriptor verifier only.
    // They never construct FsVerityBacking or consumer authority.
    #[test]
    fn fallback_resident_hash_verifies_entire_descriptor_and_exact_eof() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"verified object").unwrap();
        let media = MediaType::new("application/vnd.aos.sandbox.content.v1").unwrap();
        let descriptor = descriptor_for_bytes(media.clone(), b"verified object");
        let (cancellation, _peer) = UnixStream::pair().unwrap();
        let control = Control::new(cancellation.as_raw_fd(), 2).unwrap();
        let mut scratch = [0; 3];
        assert_eq!(
            verify_complete_file(&file, &descriptor, &mut scratch, &control),
            Ok(())
        );

        let bad_digest = ObjectDescriptor::new(
            media.clone(),
            ObjectDigest::from_bytes([0; 32]),
            descriptor.encoded_size(),
        );
        let short = descriptor_for_bytes(media.clone(), b"verified");
        let long = descriptor_for_bytes(media, b"verified object plus");
        let wrong_media = descriptor_for_bytes(
            MediaType::new("application/octet-stream").unwrap(),
            b"verified object",
        );
        // A descriptor for another media type is a distinct valid commitment;
        // retaining the original digest under the substituted type must fail.
        let relabeled = ObjectDescriptor::new(
            wrong_media.media_type().clone(),
            descriptor.digest(),
            descriptor.encoded_size(),
        );
        for mismatch in [bad_digest, short, long, relabeled] {
            assert_eq!(
                verify_complete_file(&file, &mismatch, &mut scratch, &control),
                Err(DataError::IntegrityFailure)
            );
        }
        assert_eq!(
            verify_complete_file(&file, &descriptor, &mut [], &control),
            Err(DataError::ResourceExhausted)
        );
    }

    #[test]
    fn fallback_resident_empty_object_and_cancelled_hash_remain_bounded() {
        let file = tempfile::tempfile().unwrap();
        let descriptor = descriptor_for_bytes(
            MediaType::new("application/vnd.aos.sandbox.content.v1").unwrap(),
            b"",
        );
        let (cancellation, peer) = UnixStream::pair().unwrap();
        let control = Control::new(cancellation.as_raw_fd(), 2).unwrap();
        let mut scratch = [0; 1];
        assert_eq!(
            verify_complete_file(&file, &descriptor, &mut scratch, &control),
            Ok(())
        );
        drop(peer);
        assert_eq!(
            verify_complete_file(&file, &descriptor, &mut scratch, &control),
            Err(DataError::Cancelled)
        );
    }
}
