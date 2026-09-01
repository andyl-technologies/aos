//! Fallible reader for canonical I/O-core continuation records.

use super::*;

pub(super) struct IoCoreSnapshotReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> IoCoreSnapshotReader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Result<Self, IoCoreSnapshotCodecError> {
        let bytes = bytes
            .strip_prefix(IO_CORE_SNAPSHOT_MAGIC)
            .ok_or(IoCoreSnapshotCodecError::Version)?;
        Ok(Self { bytes, offset: 0 })
    }

    fn take<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], IoCoreSnapshotCodecError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(IoCoreSnapshotCodecError::Malformed(field))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(IoCoreSnapshotCodecError::Malformed(field))?
            .try_into()
            .map_err(|_| IoCoreSnapshotCodecError::Malformed(field))?;
        self.offset = end;
        Ok(value)
    }

    pub(super) fn byte(&mut self, field: &'static str) -> Result<u8, IoCoreSnapshotCodecError> {
        Ok(self.take::<1>(field)?[0])
    }

    pub(super) fn u32(&mut self, field: &'static str) -> Result<u32, IoCoreSnapshotCodecError> {
        Ok(u32::from_le_bytes(self.take(field)?))
    }

    pub(super) fn u64(&mut self, field: &'static str) -> Result<u64, IoCoreSnapshotCodecError> {
        Ok(u64::from_le_bytes(self.take(field)?))
    }

    fn count(&mut self, field: &'static str) -> Result<usize, IoCoreSnapshotCodecError> {
        let count = usize::try_from(self.u32(field)?)
            .map_err(|_| IoCoreSnapshotCodecError::Malformed(field))?;
        if count > HARD_IO_CORE_CHECKPOINT_ENTRIES {
            return Err(io_core_resource_limit(
                field,
                0,
                count as u64,
                HARD_IO_CORE_CHECKPOINT_ENTRIES as u64,
            ));
        }
        Ok(count)
    }

    fn blob(&mut self, field: &'static str) -> Result<Vec<u8>, IoCoreSnapshotCodecError> {
        let length = usize::try_from(self.u32(field)?)
            .map_err(|_| IoCoreSnapshotCodecError::Malformed(field))?;
        if length > crucible_shmem::MAX_FRAME_DATA {
            return Err(io_core_resource_limit(
                field,
                0,
                length as u64,
                crucible_shmem::MAX_FRAME_DATA as u64,
            ));
        }
        let end = self
            .offset
            .checked_add(length)
            .ok_or(IoCoreSnapshotCodecError::Malformed(field))?;
        let source = self
            .bytes
            .get(self.offset..end)
            .ok_or(IoCoreSnapshotCodecError::Malformed(field))?;
        let mut value = Vec::new();
        value.try_reserve_exact(length).map_err(|_| {
            io_core_resource_limit(
                field,
                0,
                length as u64,
                crucible_shmem::MAX_FRAME_DATA as u64,
            )
        })?;
        value.extend_from_slice(source);
        self.offset = end;
        Ok(value)
    }

    pub(super) fn request_queue(
        &mut self,
        field: &'static str,
    ) -> Result<Vec<Request>, IoCoreSnapshotCodecError> {
        let count = self.count(field)?;
        let mut queue = Vec::new();
        queue.try_reserve_exact(count).map_err(|_| {
            io_core_resource_limit(
                field,
                0,
                count as u64,
                HARD_IO_CORE_CHECKPOINT_ENTRIES as u64,
            )
        })?;
        for _ in 0..count {
            queue.push(Request::new(
                self.u64("request icount")?,
                self.u32("request identity")?,
                self.blob("request payload")?,
            ));
        }
        Ok(queue)
    }

    pub(super) fn response_queue(
        &mut self,
        field: &'static str,
    ) -> Result<Vec<PendingResponse>, IoCoreSnapshotCodecError> {
        let count = self.count(field)?;
        let mut queue = Vec::new();
        queue.try_reserve_exact(count).map_err(|_| {
            io_core_resource_limit(
                field,
                0,
                count as u64,
                HARD_IO_CORE_CHECKPOINT_ENTRIES as u64,
            )
        })?;
        for _ in 0..count {
            let delivery_icount = self.u64("delivery icount")?;
            let src_node = self.u32("response source")?;
            let sequence = self.u32("response sequence")?;
            let request_id = self.u32("response identity")?;
            let status = match self.byte("response status")? {
                1 => crate::request::ResponseStatus::Ok,
                2 => crate::request::ResponseStatus::Error,
                _ => return Err(IoCoreSnapshotCodecError::Malformed("response status")),
            };
            queue.push(PendingResponse::from_parts(
                delivery_icount,
                src_node,
                sequence,
                crate::request::Response::new(request_id, status, self.blob("response payload")?),
            ));
        }
        Ok(queue)
    }

    pub(super) fn finish(self) -> Result<(), IoCoreSnapshotCodecError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(IoCoreSnapshotCodecError::Noncanonical)
        }
    }
}
