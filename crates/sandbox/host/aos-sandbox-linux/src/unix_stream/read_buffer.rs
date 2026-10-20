//! Assembles exact byte DATA while retaining each strict stream chunk.
//!
//! This mechanism does not price input, authenticate an application role, or
//! grant permission to decode a frame. The caller prepays the actual length,
//! validates each pending chunk against its own live original, and retains the
//! moved chunk through its independent posts before disposing it. Captured
//! bytes stay cumulative even after a successful chunk is actually disposed.

use std::collections::TryReserveError;
use std::error::Error as StdError;

use super::{RetainedUnixStream, RetainedUnixStreamSubjectReceiveErrorV1, SubjectStreamReceiveGeometryV1, UnixStreamSubjectChunk};

const MAXIMUM_CHUNK_BYTES: usize = 4096;

/// Reports an invalid or repeated exact-byte assembly action.
#[derive(Debug, thiserror::Error)]
pub enum SubjectStreamReadErrorV1 {
    /// The owner has no exact preparation or already holds a pending result.
    #[error("strict stream assembly action is out of order")]
    Order,
    /// The requested or reached byte extent is inconsistent.
    #[error("strict stream assembly byte extent is invalid")]
    Extent,
    /// A retained allocator or strict native receive result has failed.
    #[error("strict stream assembly retains an earlier failure")]
    Retained,
}

/// Retains one exact byte buffer and every unresolved strict receive result.
///
/// Construction performs no IO or allocation. No reset, socket constructor,
/// callback, role-proof boolean or authority factory is provided. Moving out a
/// copied chunk transfers its actual custody to the caller; it does not prove
/// that the caller's role binding, independent posts or frame decoder passed.
#[derive(Debug, Default)]
pub struct RetainedSubjectStreamReadV1 {
    target: Option<usize>,
    bytes: Vec<u8>,
    preparation: Option<Result<(), TryReserveError>>,
    extension: Option<Result<(), TryReserveError>>,
    received: Option<Result<UnixStreamSubjectChunk, RetainedUnixStreamSubjectReceiveErrorV1>>,
    copy: Option<Result<(), SubjectStreamReadErrorV1>>,
    closed: Option<SubjectStreamReadErrorV1>,
}

impl RetainedSubjectStreamReadV1 {
    /// Creates an empty DATA reservoir without allocating or observing a socket.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves one previously paid exact encoded byte extent.
    ///
    /// The length is DATA, not a resource permit. Its actual upper bound and
    /// dominant representations must already be admitted by the caller's owner.
    ///
    /// # Errors
    /// Retains the original allocation failure and rejects zero or reentry.
    pub fn prepare_exact_once(&mut self, length: usize) -> Result<(), SubjectStreamReadErrorV1> {
        if self.target.is_some() || self.closed.is_some() {
            self.closed.get_or_insert(SubjectStreamReadErrorV1::Order);
            return Err(SubjectStreamReadErrorV1::Order);
        }
        self.target = Some(length);
        if length == 0 {
            self.closed = Some(SubjectStreamReadErrorV1::Extent);
            return Err(SubjectStreamReadErrorV1::Extent);
        }

        self.preparation = Some(self.bytes.try_reserve_exact(length));
        if matches!(self.preparation, Some(Ok(()))) {
            Ok(())
        } else {
            Err(SubjectStreamReadErrorV1::Retained)
        }
    }

    /// Extends one completed exact prefix to its already admitted total once.
    ///
    /// This supports a fixed header followed by a checked variable payload on
    /// the same stream. The caller has already checked the header and funded
    /// the complete representation; this method creates no receiving allowance.
    /// All original prefix bytes remain resident, and there is no reset or
    /// replacement of failed native custody.
    ///
    /// # Errors
    /// Rejects incomplete or failed prefix custody, reentry, a shorter total,
    /// or allocation failure. The original allocation cause remains retained.
    pub fn extend_completed_exact_once(
        &mut self,
        total: usize,
    ) -> Result<(), SubjectStreamReadErrorV1> {
        if !self.completed_exact() || self.extension.is_some() || total < self.bytes.len() {
            self.closed.get_or_insert(SubjectStreamReadErrorV1::Order);
            return Err(SubjectStreamReadErrorV1::Order);
        }
        self.target = Some(total);
        self.extension = Some(self.bytes.try_reserve_exact(total - self.bytes.len()));
        if matches!(self.extension, Some(Ok(()))) {
            Ok(())
        } else {
            Err(SubjectStreamReadErrorV1::Retained)
        }
    }

    /// Computes the next bounded syscall length without allocating or IO.
    ///
    /// # Errors
    /// Rejects failed preparation, pending custody, completion or reentry debt.
    pub fn next_chunk_maximum(&self) -> Result<usize, SubjectStreamReadErrorV1> {
        if self.failure().is_some() || !matches!(self.preparation, Some(Ok(())))
            || self.received.is_some() || self.copy.is_some()
        {
            return Err(SubjectStreamReadErrorV1::Order);
        }
        let remaining = self.target.and_then(|length| length.checked_sub(self.bytes.len()))
            .ok_or(SubjectStreamReadErrorV1::Extent)?;
        if remaining == 0 {
            return Err(SubjectStreamReadErrorV1::Extent);
        }
        Ok(remaining.min(MAXIMUM_CHUNK_BYTES))
    }

    /// Parks the whole next receive from the same caller-retained stream.
    ///
    /// The stream must already have strict subject reporting enabled. This
    /// method neither retries nor discards nonconsuming errors; the caller can
    /// retain and classify every original returned result.
    ///
    /// # Errors
    /// Retains lower partial custody on any native failure and rejects reentry.
    pub fn receive_next_once(
        &mut self,
        stream: &mut RetainedUnixStream,
    ) -> Result<(), SubjectStreamReadErrorV1> {
        self.receive_next_profile_once(stream, None)
    }

    /// Parks a receive with the caller's already prepaid ancillary geometry.
    ///
    /// The geometry restricts storage and context width only. Exact role and
    /// subject binding remain the same enclosing owner's responsibility.
    ///
    /// # Errors
    /// Retains the same native failures and rejects pending or reentry debt.
    pub fn receive_next_with_geometry_once(
        &mut self,
        stream: &mut RetainedUnixStream,
        geometry: &SubjectStreamReceiveGeometryV1,
    ) -> Result<(), SubjectStreamReadErrorV1> {
        self.receive_next_profile_once(stream, Some(geometry))
    }

    fn receive_next_profile_once(
        &mut self,
        stream: &mut RetainedUnixStream,
        geometry: Option<&SubjectStreamReceiveGeometryV1>,
    ) -> Result<(), SubjectStreamReadErrorV1> {
        let maximum = match self.next_chunk_maximum() {
            Ok(maximum) => maximum,
            Err(error) => {
                self.closed.get_or_insert(SubjectStreamReadErrorV1::Order);
                return Err(error);
            }
        };
        self.received = Some(match geometry {
            Some(geometry) => stream.try_receive_subject_chunk_with_geometry_retaining(maximum, geometry),
            None => stream.try_receive_subject_chunk_retaining(maximum),
        });
        if matches!(self.received, Some(Ok(_))) {
            Ok(())
        } else {
            Err(SubjectStreamReadErrorV1::Retained)
        }
    }

    /// Borrows the actual pending chunk for the caller's independent role join.
    ///
    /// # Errors
    /// Rejects absent or failed native custody; no inferred chunk is returned.
    pub fn pending_chunk(&self) -> Result<&UnixStreamSubjectChunk, SubjectStreamReadErrorV1> {
        self.received.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(SubjectStreamReadErrorV1::Retained)
    }

    /// Copies exact pending payload into the already reserved cumulative buffer.
    ///
    /// The actual chunk stays owned here. Calling this DATA operation does not
    /// assert any role binding or frame validity, and never disposes evidence.
    ///
    /// # Errors
    /// Rejects repeated copy, missing custody or inconsistent reached lengths.
    pub fn append_pending_payload_once(&mut self) -> Result<(), SubjectStreamReadErrorV1> {
        if self.copy.is_some() || self.failure().is_some() {
            self.closed.get_or_insert(SubjectStreamReadErrorV1::Order);
            return Err(SubjectStreamReadErrorV1::Order);
        }
        self.copy = Some((|| {
            let chunk = self.received.as_ref().and_then(|result| result.as_ref().ok())
                .ok_or(SubjectStreamReadErrorV1::Retained)?;
            let target = self.target.ok_or(SubjectStreamReadErrorV1::Extent)?;
            let length = self.bytes.len().checked_add(chunk.payload().len())
                .ok_or(SubjectStreamReadErrorV1::Extent)?;
            if chunk.payload().is_empty() || chunk.payload().len() > MAXIMUM_CHUNK_BYTES
                || length > target || length > self.bytes.capacity()
            {
                return Err(SubjectStreamReadErrorV1::Extent);
            }
            self.bytes.extend_from_slice(chunk.payload());
            Ok(())
        })());
        if matches!(self.copy, Some(Ok(()))) {
            Ok(())
        } else {
            Err(SubjectStreamReadErrorV1::Retained)
        }
    }

    /// Moves actual copied chunk custody to its enclosing role owner.
    ///
    /// The caller keeps this returned chunk through its real independent posts.
    /// It may dispose a completed positive chunk before the next receive; failed
    /// or ambiguous binding keeps the returned chunk resident. This method
    /// transfers ownership only and never checks or grants application authority.
    ///
    /// # Errors
    /// Rejects missing or failed copy and leaves every failed result retained.
    pub fn take_copied_chunk_once(&mut self) -> Result<UnixStreamSubjectChunk, SubjectStreamReadErrorV1> {
        if self.failure().is_some() || !matches!(self.copy, Some(Ok(()))) {
            return Err(SubjectStreamReadErrorV1::Order);
        }
        match self.received.take() {
            Some(Ok(chunk)) => {
                self.copy = None;
                Ok(chunk)
            }
            other => {
                self.received = other;
                self.closed.get_or_insert(SubjectStreamReadErrorV1::Order);
                Err(SubjectStreamReadErrorV1::Order)
            }
        }
    }

    /// Borrows cumulative reached bytes, including an incomplete or invalid frame.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Reports the actual retained response byte allocation as passive DATA.
    ///
    /// This includes spare capacity of the same original buffer. It allocates
    /// nothing and supplies no frame, subject, currentness or receiving grant.
    #[must_use]
    pub fn retained_backing_bytes_v2(&self) -> usize {
        self.bytes.capacity()
    }

    /// Reports exact DATA completion without claiming subject or frame authority.
    #[must_use]
    pub fn completed_exact(&self) -> bool {
        self.failure().is_none() && matches!(self.preparation, Some(Ok(())))
            && self.target == Some(self.bytes.len())
            && self.received.is_none() && self.copy.is_none()
    }

    /// Borrows the earliest retained allocator, native or assembly cause.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn StdError + 'static)> {
        self.preparation.as_ref().and_then(|result| result.as_ref().err())
            .map(|cause| cause as &(dyn StdError + 'static))
            .or_else(|| self.extension.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn StdError + 'static)))
            .or_else(|| self.received.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn StdError + 'static)))
            .or_else(|| self.copy.as_ref().and_then(|result| result.as_ref().err())
                .map(|cause| cause as &(dyn StdError + 'static)))
            .or_else(|| self.closed.as_ref().map(|cause| cause as &(dyn StdError + 'static)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_reservation_keeps_original_allocator_cause_across_reentry() {
        let mut read = RetainedSubjectStreamReadV1::new();

        assert!(matches!(read.prepare_exact_once(usize::MAX), Err(SubjectStreamReadErrorV1::Retained)));
        assert!(read.failure().is_some_and(|cause| cause.is::<TryReserveError>()));
        assert!(read.prepare_exact_once(1).is_err());

        assert!(read.failure().is_some_and(|cause| cause.is::<TryReserveError>()));
        assert!(read.bytes().is_empty());
        assert!(!read.completed_exact());
        assert!(read.next_chunk_maximum().is_err());
    }

    #[test]
    fn extension_requires_completed_disposed_prefix_and_never_resets_failure() {
        let mut read = RetainedSubjectStreamReadV1::new();
        read.prepare_exact_once(3).expect("prefix capacity");
        assert!(read.extend_completed_exact_once(5).is_err());
        assert!(read.failure().is_some());
        assert!(read.extend_completed_exact_once(5).is_err());
        assert!(read.bytes().is_empty());
    }

    #[test]
    fn failed_extension_keeps_completed_prefix_and_actual_allocator_cause() {
        let mut read = RetainedSubjectStreamReadV1::new();
        read.prepare_exact_once(3).expect("prefix capacity");
        // This internal fixture represents a completed/disposed strict prefix;
        // the public API cannot assert native completion from these bytes.
        read.bytes.extend_from_slice(b"hdr");
        assert!(read.completed_exact());

        assert!(matches!(read.extend_completed_exact_once(usize::MAX),
            Err(SubjectStreamReadErrorV1::Retained)));
        let original = read.failure().expect("allocator cause") as *const dyn StdError;
        assert!(read.failure().is_some_and(|cause| cause.is::<TryReserveError>()));
        assert_eq!(read.bytes(), b"hdr");
        assert!(!read.completed_exact());
        assert!(read.extend_completed_exact_once(4).is_err());
        assert!(std::ptr::eq(original, read.failure().expect("same original")));
    }

}
