//! Retains the actual bounded worker cgroup-name observation for READY.
//!
//! The path is correlation DATA. Only the separately held actual child cgroup
//! and PIDFD join can establish native custody; this procfs text grants no role,
//! Source, account, deadline or permission to enter a worker programme.

use std::error::Error;
use std::fs::{File, Metadata};
use std::io::Read as _;
use std::os::fd::AsFd as _;
use std::os::unix::fs::MetadataExt as _;

use aos_sandbox_broker::receiving::NetworkChildSourceLoanV2;
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

const PATH: &str = "/proc/self/cgroup";
const MAXIMUM_BYTES: usize = 512;
const PROCFS_MAGIC: u64 = 0x9fa0;

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("the original worker cgroup-name observation is closed")]
pub(crate) struct NetworkWorkerCgroupClosedV2;

#[derive(Clone, Copy)]
enum First {
    Order,
    Source,
    Open,
    Filesystem,
    Before,
    Read,
    End,
    Shape,
    After,
}

/// Keeps the same procfs file, bytes and native posts through READY custody.
pub(crate) struct NetworkWorkerCgroupOriginalV2 {
    entered: bool,
    taken: bool,
    file: Option<std::io::Result<File>>,
    filesystem: Option<rustix::io::Result<rustix::fs::StatFs>>,
    before: Option<std::io::Result<Metadata>>,
    bytes: [u8; MAXIMUM_BYTES + 1],
    read: Option<std::io::Result<usize>>,
    end: Option<std::io::Result<usize>>,
    end_byte: [u8; 1],
    decoded: Option<Result<String, NetworkWorkerCgroupClosedV2>>,
    after: Option<std::io::Result<Metadata>>,
    first: Option<First>,
    closed: NetworkWorkerCgroupClosedV2,
}

impl NetworkWorkerCgroupOriginalV2 {
    pub(crate) fn new() -> Self {
        Self {
            entered: false,
            taken: false,
            file: None,
            filesystem: None,
            before: None,
            bytes: [0; MAXIMUM_BYTES + 1],
            read: None,
            end: None,
            end_byte: [0],
            decoded: None,
            after: None,
            first: None,
            closed: NetworkWorkerCgroupClosedV2,
        }
    }

    /// Quotes this fixed record before its native read and bounded String copy.
    pub(crate) fn receiving_obligations_data_v2() -> Option<ResourceVector> {
        let bytes = std::mem::size_of::<Self>()
            .checked_mul(2)?
            .checked_add(MAXIMUM_BYTES.checked_mul(3)?)?
            .checked_add(2 * (PATH.len() + 1))?;
        Some(
            ResourceVector::ZERO
                .with(D::MemoryBytes, u64::try_from(bytes).ok()?)
                .with(D::OpenFiles, 1)
                .with(D::MetadataEntries, 1),
        )
    }

    /// Captures one bounded procfs observation under the already-paid Source.
    ///
    /// The caller independently retains its Source before and owed after.
    /// This never derives native identity or authority from the decoded path.
    pub(crate) fn capture_once_v2(
        &mut self,
        source: &NetworkChildSourceLoanV2<'_>,
    ) -> Result<(), NetworkWorkerCgroupClosedV2> {
        if self.entered {
            return self.refuse(First::Order);
        }
        self.entered = true;
        if source.operation_binding_data_v2().is_none() {
            return self.refuse(First::Source);
        }
        let body = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = self.capture_inner();
        }));
        if body.is_err() {
            self.first.get_or_insert(First::Shape);
        }
        if let Some(Ok(file)) = self.file.as_ref() {
            self.after = Some(file.metadata());
            if !matches!((&self.before, &self.after), (Some(Ok(before)), Some(Ok(after)))
                if same_file(before, after))
            {
                self.first.get_or_insert(First::After);
            }
        }
        if let Err(payload) = body {
            std::panic::resume_unwind(payload);
        }
        if self.first.is_some() {
            Err(self.closed)
        } else {
            Ok(())
        }
    }

    fn capture_inner(&mut self) -> Result<(), NetworkWorkerCgroupClosedV2> {
        self.file = Some(File::open(PATH));
        let Some(Ok(file)) = self.file.as_ref() else {
            return self.refuse(First::Open);
        };
        self.filesystem = Some(rustix::fs::fstatfs(file.as_fd()));
        if !matches!(self.filesystem, Some(Ok(ref value)) if value.f_type as u64 == PROCFS_MAGIC) {
            return self.refuse(First::Filesystem);
        }
        self.before = Some(file.metadata());
        if !matches!(self.before, Some(Ok(_))) {
            return self.refuse(First::Before);
        }
        let mut reader = file;
        self.read = Some(reader.read(&mut self.bytes));
        let length = match self.read.as_ref() {
            Some(Ok(length)) if *length != 0 && *length <= MAXIMUM_BYTES => *length,
            Some(Ok(_)) => return self.refuse(First::Shape),
            _ => return self.refuse(First::Read),
        };
        self.end = Some(reader.read(&mut self.end_byte));
        if !matches!(self.end, Some(Ok(0))) {
            return self.refuse(First::End);
        }
        self.decoded = Some(decode(&self.bytes[..length]));
        if !matches!(self.decoded, Some(Ok(_))) {
            return self.refuse(First::Shape);
        }
        Ok(())
    }

    /// Moves only the completed path after the actual same-file post passed.
    pub(crate) fn take_completed_once_v2(&mut self) -> Option<String> {
        if self.first.is_some() || self.taken || !matches!(self.decoded, Some(Ok(_))) {
            return None;
        }
        self.taken = true;
        // Future READY validation uses the moved bytes and native birth pins,
        // not this proc file. All observations and the prepaid peak remain.
        drop(self.file.take());
        self.decoded.take()?.ok()
    }

    fn refuse<T>(&mut self, cause: First) -> Result<T, NetworkWorkerCgroupClosedV2> {
        self.first.get_or_insert(cause);
        Err(self.closed)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        let cause = match self.first? {
            First::Open => failed(&self.file),
            First::Filesystem => failed(&self.filesystem),
            First::Before => failed(&self.before),
            First::Read => failed(&self.read),
            First::End => failed(&self.end),
            First::Shape => failed(&self.decoded),
            First::After => failed(&self.after),
            First::Order | First::Source => None,
        };
        cause.or(Some(&self.closed))
    }
}

fn decode(bytes: &[u8]) -> Result<String, NetworkWorkerCgroupClosedV2> {
    let text = std::str::from_utf8(bytes).map_err(|_| NetworkWorkerCgroupClosedV2)?;
    let path = text
        .strip_prefix("0::/")
        .and_then(|text| text.strip_suffix('\n'))
        .ok_or(NetworkWorkerCgroupClosedV2)?;
    if path.is_empty()
        || path
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(NetworkWorkerCgroupClosedV2);
    }
    Ok(path.to_owned())
}

fn same_file(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.nlink() == after.nlink()
}

fn failed<T, E: Error + 'static>(value: &Option<Result<T, E>>) -> Option<&(dyn Error + 'static)> {
    value.as_ref()?.as_ref().err().map(|cause| cause as _)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_complete_unified_relative_path_is_ready_data() {
        let path = "aoscomponents.slice/aoscomponents-network.slice/worker.service";
        assert_eq!(decode(format!("0::/{path}\n").as_bytes()).unwrap(), path);

        for invalid in [
            b"0::/\n".as_slice(),
            b"0::/a//b\n",
            b"0::/a/../b\n",
            b"0::/a",
            b"0::/a\n0::/b\n",
            b"1:x:/a\n",
            b"0::/a\0b\n",
        ] {
            assert!(decode(invalid).is_err());
        }
        assert!(
            NetworkWorkerCgroupOriginalV2::new()
                .take_completed_once_v2()
                .is_none()
        );
    }
}
