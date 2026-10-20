//! Original sealed constructor and boot-image descriptor custody before exec.
//!
//! These memory objects are the public process protocol's immutable inputs,
//! never build storage. The same descriptor bodies survive early native pinning
//! and the later plugin setup transfer. They do not qualify native readiness.

use crucible_qemu_protocol::whole_control::staged::launch::LaunchArchitecture;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crucible_qemu_protocol::plugin_setup_plan::PluginSetupPlan;
use sha2::{Digest, Sha256};

use super::{
    QEMU_WHOLE_IMAGE_LAUNCH_FD_BASE, QEMU_WHOLE_SETUP_LAUNCH_FD, QemuSpawnError,
    close_child_source_fd, dup_to_fixed_child_fd, duplicate_cloexec_fd,
};
use crate::QemuLaunchCommand;

const IMAGE_OPTIONS: [&str; 3] = ["-kernel", "-initrd", "-bios"];

#[derive(Clone, Copy)]
pub(super) struct ChildDescriptorPins {
    plan: RawFd,
    images: [Option<RawFd>; 4],
}

/// Retains exact original protocol inputs before any native constructor effect.
#[derive(Debug)]
pub(crate) struct QemuEarlyWholeSetup {
    plan: Option<OwnedFd>,
    body: Box<[u8]>,
    images: [Option<OwnedFd>; 4],
    child_plan: OwnedFd,
    child_images: [Option<OwnedFd>; 4],
}

impl QemuEarlyWholeSetup {
    #[cfg(test)]
    pub(super) fn original_descriptors(&self) -> impl Iterator<Item = std::os::fd::BorrowedFd<'_>> {
        self.plan
            .iter()
            .chain(self.images.iter().flatten())
            .map(std::os::fd::AsFd::as_fd)
    }

    pub(super) fn from_command(
        command: &QemuLaunchCommand,
        run_directory: &Path,
    ) -> Result<Option<Self>, QemuSpawnError> {
        let plan = command.plugin_setup_plan();
        let Some(selection) = plan.whole_constructor() else {
            return Ok(None);
        };
        let launch = selection.launch2().map_err(protocol_error)?;
        if launch.ram_backing_kind != 2 {
            return Err(invalid(
                "guarded whole launch has no authenticated inherited guest RAM handle",
            ));
        }
        if launch.architecture != LaunchArchitecture::X86_64 {
            return Err(invalid(
                "original ARM constructor property enrollment is not yet available",
            ));
        }
        if command.args().iter().any(|argument| {
            matches!(
                argument.as_str(),
                "-qmp" | "-gdb" | "-s" | "-S" | "-chardev" | "-trace" | "-D" | "-d"
            )
        }) {
            return Err(invalid(
                "selected constructor has an unenrolled debug or tracing endpoint",
            ));
        }
        let machine = option_value(command.args(), "-machine")?;
        let cpu = option_value(command.args(), "-cpu")?;
        if option_value(command.args(), "-mem-path")?.is_some()
            || command
                .args()
                .windows(2)
                .any(|pair| pair[0] == "-object" && pair[1].starts_with("memory-backend-"))
        {
            return Err(invalid(
                "native-owned RAM selection cannot adopt a caller-provided backing",
            ));
        }
        let command_line = option_value(command.args(), "-append")?.unwrap_or_default();
        let seed = launch.run_seed.to_string();
        let icount = format!(
            "shift=0,sleep=off,align=off,rr_switch_quantum={}",
            launch.rr_switch_quantum
        );
        if command.resource_requirements().virtual_cpus() != 4
            || command.resource_requirements().guest_memory_bytes() != launch.ram_byte_length
            || machine != Some("pc-q35-9.2")
            || cpu != Some("qemu64,-rdrand,-rdseed")
            || command_line != launch.kernel_command_line
            || option_value(command.args(), "-crucible-whole-setup-fd")? != Some("9")
            || option_value(command.args(), "-seed")? != Some(seed.as_str())
            || option_value(command.args(), "-icount")? != Some(icount.as_str())
            || option_value(command.args(), "-rtc")? != Some("base=2026-01-01T00:00:00,clock=vm")
            || option_value(command.args(), "-accel")? != Some("sim,thread=single")
            || option_value(command.args(), "-smp")? != Some("4")
        {
            return Err(invalid(
                "original whole launch selection differs from the complete validated command",
            ));
        }
        for flag in ["-nodefaults", "-no-user-config"] {
            if command
                .args()
                .iter()
                .filter(|argument| argument.as_str() == flag)
                .count()
                != 1
            {
                return Err(invalid(
                    "original whole launch changes a canonical default-device flag",
                ));
            }
        }
        for option in ["-display", "-monitor", "-serial", "-parallel"] {
            if option_value(command.args(), option)? != Some("none") {
                return Err(invalid(
                    "original whole launch changes a canonical external endpoint",
                ));
            }
        }
        let bytes = plan.encode().map_err(protocol_error)?;
        // The selected entry admitted every simultaneously retained image,
        // mapping, protocol history and argv byte before this allocation. The
        // writable VMState minimum is a lower bound, not an image upper bound.

        let mut paths: [Option<PathBuf>; 4] = [None, None, None, None];
        for (index, option) in IMAGE_OPTIONS.iter().enumerate() {
            paths[index] = option_value(command.args(), option)?.map(PathBuf::from);
        }
        if paths[2].is_none() {
            let executable = Path::new(command.executable());
            if !executable.is_absolute() {
                return Err(invalid(
                    "implicit whole firmware lacks its original absolute package executable",
                ));
            }
            let prefix = executable
                .parent()
                .and_then(Path::parent)
                .ok_or_else(|| invalid("original Q35 firmware package prefix is absent"))?;
            paths[2] = Some(prefix.join("share/qemu/bios-256k.bin"));
        }
        let entropy = option_value(command.args(), "-fw_cfg")?
            .and_then(|argument| argument.strip_prefix("name=opt/crucible/seed,file="))
            .ok_or_else(|| invalid("original whole entropy descriptor source is absent"))?;
        paths[3] = Some(PathBuf::from(entropy));
        if option_value(command.args(), "-object")? != Some("rng-builtin,id=crucible-rng0") {
            return Err(invalid(
                "original whole RNG backend differs from its actual declared cohort",
            ));
        }
        let mut images: [Option<OwnedFd>; 4] = [None, None, None, None];
        for (index, asset) in launch.assets.iter().enumerate() {
            let path = paths[index].as_ref();
            if asset.present != path.is_some()
                || (asset.present
                    && asset.inherited_fd
                        != (QEMU_WHOLE_IMAGE_LAUNCH_FD_BASE + index as i32) as u32)
            {
                return Err(invalid(
                    "whole launch image presence or descriptor role differs",
                ));
            }
            if let Some(path) = path {
                let path = if path.is_absolute() {
                    path.clone()
                } else {
                    run_directory.join(path)
                };
                images[index] = Some(sealed_image(&path, asset.byte_length, asset.sha256)?);
            }
        }
        let plan_fd =
            crate::host_setup::sealed_plugin_setup_plan_fd(&bytes).map_err(protocol_error)?;
        let child_plan =
            duplicate_cloexec_fd(plan_fd.as_raw_fd(), "pin original whole setup descriptor")?;
        let mut child_images: [Option<OwnedFd>; 4] = [None, None, None, None];
        for (index, image) in images.iter().enumerate() {
            if let Some(image) = image {
                child_images[index] = Some(duplicate_cloexec_fd(
                    image.as_raw_fd(),
                    "pin original whole image descriptor",
                )?);
            }
        }
        Ok(Some(Self {
            plan: Some(plan_fd),
            body: bytes.into_boxed_slice(),
            images,
            child_plan,
            child_images,
        }))
    }

    pub(crate) fn plan_fd(&self) -> Result<RawFd, io::Error> {
        self.plan
            .as_ref()
            .map(AsRawFd::as_raw_fd)
            .ok_or_else(|| io::Error::other("original plan already belongs to the setup journal"))
    }

    pub(crate) fn validate_plan(&self, plan: &PluginSetupPlan) -> Result<(), io::Error> {
        let bytes = plan.encode().map_err(io::Error::other)?;
        if bytes.as_slice() != self.body.as_ref() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "late setup changed original early constructor bytes",
            ));
        }
        Ok(())
    }

    pub(super) fn child_descriptor_pins(&self) -> ChildDescriptorPins {
        ChildDescriptorPins {
            plan: self.child_plan.as_raw_fd(),
            images: std::array::from_fn(|index| {
                self.child_images[index].as_ref().map(AsRawFd::as_raw_fd)
            }),
        }
    }

    pub(super) fn take_original_plan(&mut self) -> Result<OwnedFd, QemuSpawnError> {
        self.plan
            .take()
            .ok_or_else(|| invalid("original whole setup descriptor already transferred"))
    }

    pub(super) fn pinned_launch_args(
        &self,
        original: &[String],
    ) -> Result<Vec<String>, QemuSpawnError> {
        let mut args = original.to_vec();
        for (index, option) in IMAGE_OPTIONS.iter().enumerate() {
            if self.images[index].is_none() {
                continue;
            }
            let path = format!(
                "/proc/self/fd/{}",
                QEMU_WHOLE_IMAGE_LAUNCH_FD_BASE + index as i32
            );
            match args.iter().position(|value| value == option) {
                Some(position) => {
                    let value = args
                        .get_mut(position + 1)
                        .ok_or_else(|| invalid("original image launch value disappeared"))?;
                    *value = path;
                }
                None if *option == "-bios" => args.extend([option.to_string(), path]),
                None => return Err(invalid("original image launch argument disappeared")),
            }
        }
        let position = args
            .iter()
            .position(|value| value == "-fw_cfg")
            .ok_or_else(|| invalid("original entropy launch argument disappeared"))?;
        *args
            .get_mut(position + 1)
            .ok_or_else(|| invalid("original entropy launch value disappeared"))? =
            "name=opt/crucible/seed,file=/proc/self/fd/13".to_string();
        Ok(args)
    }
}

pub(super) fn install_child_descriptor_pins(pins: ChildDescriptorPins) -> io::Result<()> {
    // Every source was relocated above all fixed targets before fork. This
    // routine performs only async-signal-safe descriptor operations in pre_exec.
    dup_to_fixed_child_fd(pins.plan, QEMU_WHOLE_SETUP_LAUNCH_FD)?;
    for (index, image) in pins.images.iter().enumerate() {
        if let Some(image) = image {
            dup_to_fixed_child_fd(*image, QEMU_WHOLE_IMAGE_LAUNCH_FD_BASE + index as i32)?;
        }
    }
    close_child_source_fd(pins.plan)?;
    for image in pins.images.into_iter().flatten() {
        close_child_source_fd(image)?;
    }
    Ok(())
}

fn option_value<'a>(args: &'a [String], option: &str) -> Result<Option<&'a str>, QemuSpawnError> {
    let mut value = None;
    for (index, argument) in args.iter().enumerate() {
        if argument != option {
            continue;
        }
        if value.is_some() {
            return Err(invalid("duplicate original whole image launch role"));
        }
        value = Some(
            args.get(index + 1)
                .ok_or_else(|| invalid("missing original image launch value"))?
                .as_str(),
        );
    }
    Ok(value)
}

fn sealed_image(
    path: impl AsRef<Path>,
    length: u64,
    expected_sha256: [u8; 32],
) -> Result<OwnedFd, QemuSpawnError> {
    let mut source = File::open(path).map_err(protocol_error)?;
    let before = source.metadata().map_err(protocol_error)?;
    if !before.is_file() || before.len() != length || length == 0 {
        return Err(invalid(
            "whole source image is not the original complete regular file",
        ));
    }
    let raw = unsafe {
        // SAFETY: The static NUL-terminated name lives throughout this syscall.
        libc::memfd_create(
            c"crucible-whole-image".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if raw < 0 {
        return Err(protocol_error(io::Error::last_os_error()));
    }
    let mut destination = unsafe {
        // SAFETY: Successful memfd_create returned one uniquely owned descriptor.
        File::from_raw_fd(raw)
    };
    destination.set_len(length).map_err(protocol_error)?;
    let mut hasher = Sha256::new();
    let mut copied = 0u64;
    let mut chunk = [0; 64 * 1024];
    loop {
        let count = source.read(&mut chunk).map_err(protocol_error)?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(count as u64)
            .ok_or_else(|| invalid("whole image read extent overflow"))?;
        if copied > length {
            return Err(invalid("whole source image grew during pinning"));
        }
        hasher.update(&chunk[..count]);
        destination
            .write_all(&chunk[..count])
            .map_err(protocol_error)?;
    }
    let after = source.metadata().map_err(protocol_error)?;
    if copied != length
        || hasher.finalize().as_slice() != expected_sha256
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err(invalid(
            "original whole source image changed or differs from its full commitment",
        ));
    }
    let seals = libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
    let result = unsafe {
        // SAFETY: The uniquely owned descriptor permits sealing; no writable
        // mapping or borrowed writer remains. All four seals are permanent.
        libc::fcntl(destination.as_raw_fd(), libc::F_ADD_SEALS, seals)
    };
    if result != 0 {
        return Err(protocol_error(io::Error::last_os_error()));
    }
    Ok(destination.into())
}

pub(super) fn protocol_error(
    error: impl std::error::Error + Send + Sync + 'static,
) -> QemuSpawnError {
    QemuSpawnError::Io {
        operation: "pin original whole constructor before native effects",
        source: io::Error::other(error),
    }
}

fn invalid(reason: &'static str) -> QemuSpawnError {
    QemuSpawnError::Io {
        operation: "validate original whole constructor before native effects",
        source: io::Error::new(io::ErrorKind::InvalidData, reason),
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Lost fixture descriptor custody is a test failure.
#[allow(clippy::unwrap_used)]
pub(super) fn unqualified_custody_fixture() -> QemuEarlyWholeSetup {
    // This fixture owns real sealed protocol bytes and descriptor copies. It
    // installs no QEMU constructor and can issue no native source capability.
    let body = b"unqualified whole-launch ownership fixture".to_vec();
    let plan = crate::host_setup::sealed_plugin_setup_plan_fd(&body).unwrap();
    let child_plan = duplicate_cloexec_fd(plan.as_raw_fd(), "fixture child setup fd").unwrap();
    QemuEarlyWholeSetup {
        plan: Some(plan),
        body: body.into_boxed_slice(),
        images: [None, None, None, None],
        child_plan,
        child_images: [None, None, None, None],
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Exact fixture descriptor identities are test assertions.
#[allow(clippy::unwrap_used)]
pub(super) fn unqualified_image_custody_fixture() -> QemuEarlyWholeSetup {
    let mut fixture = unqualified_custody_fixture();
    for (index, label) in [b"kernel".as_slice(), b"initrd", b"firmware", b"entropy"]
        .into_iter()
        .enumerate()
    {
        let image = crate::host_setup::sealed_plugin_setup_plan_fd(label).unwrap();
        fixture.child_images[index] =
            Some(duplicate_cloexec_fd(image.as_raw_fd(), "fixture child image fd").unwrap());
        fixture.images[index] = Some(image);
    }
    fixture
}

#[cfg(test)]
mod tests {
    //! Actual immutable image descriptor controls; no native readiness claim.

    // crucible-lint: allow panic-shortcut -- Descriptor controls panic on lost original bytes or seal failures.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::os::unix::fs::FileExt;

    #[test]
    fn sealed_image_keeps_complete_original_bytes_and_refuses_mutation() {
        let bytes = b"complete original source image\0including binary tail\xff";
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(bytes).unwrap();
        let path = source.path().to_str().unwrap();
        let expected: [u8; 32] = Sha256::digest(bytes).into();

        let descriptor = sealed_image(path, bytes.len() as u64, expected).unwrap();
        let image = File::from(descriptor);
        let mut actual = vec![0; bytes.len()];
        image.read_exact_at(&mut actual, 0).unwrap();
        assert_eq!(actual, bytes);
        assert_eq!(image.metadata().unwrap().len(), bytes.len() as u64);
        let seals = unsafe {
            // SAFETY: The live descriptor is queried without changing ownership.
            libc::fcntl(image.as_raw_fd(), libc::F_GET_SEALS)
        };
        assert_eq!(
            seals,
            libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL
        );
        assert_eq!(
            image.write_at(b"changed", 0).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
        assert!(image.set_len(0).is_err());
    }

    #[test]
    fn changed_extent_or_full_source_commitment_refuses_before_descriptor_handoff() {
        let bytes = b"original kernel source bytes";
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(bytes).unwrap();
        let expected: [u8; 32] = Sha256::digest(bytes).into();
        let path = source.path().to_str().unwrap();

        assert!(sealed_image(path, bytes.len() as u64 + 1, expected).is_err());
        let mut changed = expected;
        changed[31] ^= 1;
        assert!(sealed_image(path, bytes.len() as u64, changed).is_err());
        assert_eq!(std::fs::read(source.path()).unwrap(), bytes);
    }
}
