//! Verifies birth in the private operator's already-enforced original domain.
//!
//! The root/operator service creates the hierarchy before exec. These readbacks
//! authenticate that fixed deployment contract; they do not reserve resources
//! or permit moving an already-loaded parent into a new memory account.

use super::{ParentFailure, account::ExternalSourceContract};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;

pub(super) const ROOT: &str = "/sys/fs/cgroup/system.slice/crucible-private-parent.service";

pub(super) struct Enclosure {
    _root: File,
    _guardian: File,
}

impl Enclosure {
    pub(super) fn verify(source: &ExternalSourceContract) -> Result<Self, ParentFailure> {
        let root = directory(ROOT)?;
        let guardian = directory(&format!("{ROOT}/guardian"))?;
        if rustix::fs::fstatfs(&root)
            .map_err(|error| ParentFailure::Io(error.into()))?
            .f_type
            != libc::CGROUP2_SUPER_MAGIC
        {
            return Err(ParentFailure::CompiledInput(
                "original Parent cgroup filesystem",
            ));
        }
        let resident = (20u64 << 30).checked_add(source.resident_bytes).ok_or(
            ParentFailure::CompiledInput("original Parent resident extent"),
        )?;
        let descriptor_bound = u64::from(source.tasks)
            .checked_mul(1024)
            .ok_or(ParentFailure::CompiledInput("Source descriptor extent"))?;
        if source.descriptors < descriptor_bound {
            return Err(ParentFailure::CompiledInput(
                "Source aggregate process-table bound",
            ));
        }
        for (name, expected) in [
            ("memory.max", format!("{resident}\n")),
            ("memory.swap.max", "0\n".to_owned()),
            ("cpu.max", "1000000 100000\n".to_owned()),
            ("pids.max", format!("{}\n", source.tasks)),
            ("cgroup.procs", String::new()),
        ] {
            if control(&root, name)?.as_slice() != expected.as_bytes() {
                return Err(ParentFailure::CompiledInput(
                    "preborn Parent aggregate controls",
                ));
            }
        }
        let mut membership = File::open("/proc/self/cgroup").map_err(ParentFailure::Io)?;
        let mut bytes = Vec::with_capacity(257);
        (&mut membership)
            .take(257)
            .read_to_end(&mut bytes)
            .map_err(ParentFailure::Io)?;
        if bytes != b"0::/system.slice/crucible-private-parent.service/guardian\n" {
            return Err(ParentFailure::CompiledInput(
                "original Parent guardian birth",
            ));
        }
        let actual = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        if actual.current != Some(1024) || actual.maximum != Some(1024) {
            return Err(ParentFailure::CompiledInput(
                "original Parent process descriptor ceiling",
            ));
        }
        Ok(Self {
            _root: root,
            _guardian: guardian,
        })
    }
}

fn directory(path: &str) -> Result<File, ParentFailure> {
    OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW).bits() as i32)
        .open(path)
        .map_err(ParentFailure::Io)
}

fn control(root: &File, name: &str) -> Result<Vec<u8>, ParentFailure> {
    let fd = rustix::fs::openat(
        root,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| ParentFailure::Io(error.into()))?;
    let mut file = File::from(fd);
    let mut bytes = Vec::with_capacity(65);
    (&mut file)
        .take(65)
        .read_to_end(&mut bytes)
        .map_err(ParentFailure::Io)?;
    if bytes.len() > 64 {
        return Err(ParentFailure::CompiledInput(
            "original Parent control extent",
        ));
    }
    Ok(bytes)
}
