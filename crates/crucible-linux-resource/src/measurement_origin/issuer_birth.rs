//! Pins the generated fresh-actor birth route inside the owned disposable VM.
//!
//! The whole guest remains externally paid and physically contained. The fixed
//! leaf readbacks verify the trusted PID1 setup; they do not create entitlement.
//! An immutable birth script enters that leaf before exec loads the actual actor.

use super::*;

const LEAF: &str = "/sys/fs/cgroup/crucible-measurement-actor";
const BIRTH: &str = "/etc/crucible/measurement-actor-birth";

pub(super) struct ActorBirth {
    executable: PathBuf,
    _executable_pin: File,
    _parent: File,
    guardian: File,
}

impl ActorBirth {
    pub(super) fn verify(
        mode: &StaticMode,
        interval: OriginalInterval,
    ) -> Result<Self, MeasurementOriginError> {
        interval.before()?;
        let executable = interval.after_io(std::fs::canonicalize(BIRTH))?;
        interval.before()?;
        let executable_pin = interval.after_result(immutable_file(&executable))?;
        interval.before()?;
        let leaf = interval.after_io(
            OpenOptions::new()
                .read(true)
                .custom_flags(
                    (rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW).bits() as i32,
                )
                .open(LEAF),
        )?;
        interval.before()?;
        let filesystem = interval.after_kernel(rustix::fs::fstatfs(&leaf))?;
        if filesystem.f_type != libc::CGROUP2_SUPER_MAGIC {
            return Err(MeasurementOriginError::Authentication(
                "owned actor cgroup filesystem",
            ));
        }
        let swap = match mode {
            StaticMode::NativeOnly => b"0\n".as_slice(),
            StaticMode::KernelMeasurement => b"4294967296\n".as_slice(),
        };
        for (name, expected) in [
            ("memory.max", b"17179869184\n".as_slice()),
            ("memory.swap.max", swap),
            ("cpu.max", b"1000000 100000\n".as_slice()),
            ("pids.max", b"4096\n".as_slice()),
            ("cgroup.procs", b"".as_slice()),
        ] {
            if read_control(&leaf, name, interval)?.as_slice() != expected {
                return Err(MeasurementOriginError::Authentication(
                    "fresh actor leaf controls",
                ));
            }
        }
        interval.before()?;
        let descriptor = interval.after_kernel(rustix::fs::openat(
            &leaf,
            "guardian",
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        ))?;
        let guardian = File::from(descriptor);
        if read_control(&guardian, "memory.swap.max", interval)?.as_slice() != b"0\n" {
            return Err(MeasurementOriginError::Authentication(
                "unswapped actor guardian",
            ));
        }
        if !read_control(&guardian, "cgroup.procs", interval)?.is_empty() {
            return Err(MeasurementOriginError::Authentication(
                "occupied fresh actor guardian",
            ));
        }
        Ok(Self {
            executable,
            _executable_pin: executable_pin,
            _parent: leaf,
            guardian,
        })
    }

    pub(super) fn program(&self) -> &Path {
        &self.executable
    }

    pub(super) fn verify_child(
        &self,
        child: &std::process::Child,
        interval: OriginalInterval,
    ) -> Result<(), MeasurementOriginError> {
        // The PID comes only from our retained actual Child. This verifies its
        // fresh birth placement before acknowledging the same actor's adoption.
        let membership = read_control(&self.guardian, "cgroup.procs", interval)?;
        let actual = child.id().to_string();
        if membership.as_slice() != [actual.as_bytes(), b"\n"].concat() {
            return Err(MeasurementOriginError::Authentication(
                "actual actor birth leaf",
            ));
        }
        Ok(())
    }
}

fn read_control(
    leaf: &File,
    name: &str,
    interval: OriginalInterval,
) -> Result<Vec<u8>, MeasurementOriginError> {
    interval.before()?;
    let descriptor = interval.after_kernel(rustix::fs::openat(
        leaf,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    ))?;
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(65);
    interval.before()?;
    interval.after_io((&mut file).take(65).read_to_end(&mut bytes))?;
    if bytes.len() > 64 {
        return Err(MeasurementOriginError::Authentication(
            "actor control extent",
        ));
    }
    Ok(bytes)
}
