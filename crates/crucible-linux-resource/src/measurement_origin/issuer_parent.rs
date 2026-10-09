//! Receives external ownership evidence through the immutable PID1 boot route.
//!
//! The fixed virtio locator is not itself authority. This module is called only
//! by the real root PID1 in the trusted generated image, whose parent retains the
//! original whole-VM and Source reservation. The frame carries no loans or clock
//! coordinates. Actual files remain in the issuer slot through child retirement.

use super::*;

const FRAME_BYTES: usize = 224;
const PORT: &str = "/dev/vport0p1";
const IMAGE_PATH: &str = "/etc/crucible/measurement-images.json";
const SOURCE_PATH: &str = "/etc/crucible/measurement-source.json";
const WORKFLOW_PATH: &str = "/etc/crucible/measurement-workflow.json";
const MAX_DESCRIPTOR_BYTES: u64 = 1 << 20;

pub(super) struct ParentBinding {
    device: File,
    _kernel_port: File,
    _kernel_device: File,
    record: File,
    images: Option<File>,
    source: Option<File>,
    workflow: Option<File>,
    bytes: [u8; FRAME_BYTES],
}

impl ParentBinding {
    pub(super) fn receive(interval: OriginalInterval) -> Result<Self, MeasurementOriginError> {
        interval.before()?;
        let opened = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(
                (rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOFOLLOW).bits() as i32,
            )
            .open(PORT);
        let device = match opened {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return interval.after_result(Err(MeasurementOriginError::MissingIssuerPurpose));
            }
            result => interval.after_io(result)?,
        };
        let (kernel_port, kernel_device) = pin_kernel_port(&device, interval)?;
        interval.before()?;
        let record = interval.after_kernel(memfd_create(
            "crucible-original-parent-evidence",
            MemfdFlags::ALLOW_SEALING | MemfdFlags::CLOEXEC,
        ))?;
        let mut binding = Self {
            device,
            _kernel_port: kernel_port,
            _kernel_device: kernel_device,
            record: File::from(record),
            images: None,
            source: None,
            workflow: None,
            bytes: [0; FRAME_BYTES],
        };
        let mut filled = 0;
        while filled != FRAME_BYTES {
            interval.before()?;
            match binding.device.read(&mut binding.bytes[filled..]) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    interval.after_io(Ok(()))?;
                    wait_ready(&binding.device, rustix::event::PollFlags::IN, interval)?;
                }
                result => {
                    let count = interval.after_io(result)?;
                    if count == 0 {
                        return Err(MeasurementOriginError::Authentication("parent port EOF"));
                    }
                    filled += count;
                }
            }
        }
        Ok(binding)
    }

    pub(super) fn validate_and_seal(
        &mut self,
        policy: &OperatorPolicy,
        digest: [u8; 32],
        interval: OriginalInterval,
    ) -> Result<(), MeasurementOriginError> {
        let word = |offset: usize| {
            let mut bytes = [0; 8];
            bytes.copy_from_slice(&self.bytes[offset..offset + 8]);
            u64::from_le_bytes(bytes)
        };
        let mode = match policy.mode {
            StaticMode::NativeOnly => 0,
            StaticMode::KernelMeasurement => 1,
        };
        if &self.bytes[..8] != b"CPARNT02"
            || self.bytes[8..40] != digest
            || self.bytes[104..136] == [0; 32]
            || word(136) == 0
            || u64::from(self.bytes[144]) != policy.native_count
            || !matches!(self.bytes[144], 1 | 2 | 4)
            || self.bytes[145] != mode
            || self.bytes[146..152] != [0; 6]
            || word(152) != 4096
            || word(160) != 1024
            || word(168) != 16 << 30
            || word(176) != 20 << 30
            || word(184) != 64 << 30
            || policy.actor_task_limit != 4096
            || policy.actor_descriptors != 1024
            || policy.actor_cpu_slots != 10
            || policy.actor_resident_bytes != 16 << 30
            || policy.host_memory_bytes != 20 << 30
            || policy.host_backing_bytes != 64 << 30
        {
            return Err(MeasurementOriginError::Authentication(
                "external parent role",
            ));
        }
        let (images, image_digest) = digest_descriptor(IMAGE_PATH, interval)?;
        self.images = Some(images);
        interval.after_io(Ok(()))?;
        let (source, source_digest) = digest_descriptor(SOURCE_PATH, interval)?;
        self.source = Some(source);
        interval.after_io(Ok(()))?;
        let (workflow, workflow_digest) = digest_descriptor(WORKFLOW_PATH, interval)?;
        self.workflow = Some(workflow);
        interval.after_io(Ok(()))?;
        if self.bytes[40..72] != image_digest
            || self.bytes[72..104] != source_digest
            || self.bytes[192..224] != workflow_digest
        {
            return Err(MeasurementOriginError::Authentication(
                "external installed images",
            ));
        }
        interval.before()?;
        interval.after_io(self.record.write_all(&self.bytes))?;
        interval.before()?;
        interval.after_kernel(fcntl_add_seals(&self.record, required_seals()))
    }

    pub(super) fn complete(
        &mut self,
        interval: OriginalInterval,
    ) -> Result<(), MeasurementOriginError> {
        interval.before()?;
        interval.after_io(self.device.write_all(&[1]))
    }

    pub(super) fn send(
        &self,
        peer: &UnixStream,
        interval: OriginalInterval,
    ) -> Result<(), MeasurementOriginError> {
        send_record(peer, &self.record, interval)
    }
}

fn character_device_number(
    device: &File,
    interval: OriginalInterval,
) -> Result<u64, MeasurementOriginError> {
    interval.before()?;
    let metadata = interval.after_io(device.metadata())?;
    if !std::os::unix::fs::FileTypeExt::is_char_device(&metadata.file_type()) {
        return Err(MeasurementOriginError::Authentication(
            "parent port character device",
        ));
    }
    Ok(metadata.rdev())
}

fn pin_kernel_port(
    device: &File,
    interval: OriginalInterval,
) -> Result<(File, File), MeasurementOriginError> {
    // A userspace name or regular file cannot represent the kernel's virtio
    // endpoint. Both sysfs aliases must identify the same retained device.
    let number = character_device_number(device, interval)?;
    let major = rustix::fs::major(number);
    let minor = rustix::fs::minor(number);
    let port = pin_sysfs_directory("/sys/class/virtio-ports/vport0p1", interval)?;
    let by_number = pin_sysfs_directory(&format!("/sys/dev/char/{major}:{minor}"), interval)?;
    interval.before()?;
    let port_metadata = interval.after_io(port.metadata())?;
    interval.before()?;
    let device_metadata = interval.after_io(by_number.metadata())?;
    if (port_metadata.dev(), port_metadata.ino()) != (device_metadata.dev(), device_metadata.ino())
        || read_kernel_attribute(&port, "dev", interval)? != format!("{major}:{minor}\n").as_bytes()
        || read_kernel_attribute(&port, "name", interval)? != b"crucible.original.parent\n"
    {
        return Err(MeasurementOriginError::Authentication(
            "same kernel parent virtio device",
        ));
    }
    Ok((port, by_number))
}

fn pin_sysfs_directory(
    locator: &str,
    interval: OriginalInterval,
) -> Result<File, MeasurementOriginError> {
    interval.before()?;
    let path = interval.after_io(std::fs::canonicalize(locator))?;
    if !path.starts_with("/sys/devices") {
        return Err(MeasurementOriginError::Authentication(
            "kernel parent port location",
        ));
    }
    interval.before()?;
    let directory = interval.after_io(
        OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW).bits() as i32,
            )
            .open(path),
    )?;
    interval.before()?;
    let filesystem = interval.after_kernel(rustix::fs::fstatfs(&directory))?;
    if filesystem.f_type != libc::SYSFS_MAGIC {
        return Err(MeasurementOriginError::Authentication(
            "kernel parent port filesystem",
        ));
    }
    Ok(directory)
}

fn read_kernel_attribute(
    directory: &File,
    name: &str,
    interval: OriginalInterval,
) -> Result<Vec<u8>, MeasurementOriginError> {
    interval.before()?;
    let descriptor = interval.after_kernel(rustix::fs::openat(
        directory,
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
            "kernel parent attribute extent",
        ));
    }
    Ok(bytes)
}

fn digest_descriptor(
    locator: &str,
    interval: OriginalInterval,
) -> Result<(File, [u8; 32]), MeasurementOriginError> {
    interval.before()?;
    let path = interval.after_io(std::fs::canonicalize(locator))?;
    interval.before()?;
    let mut file = interval.after_result(immutable_file(&path))?;
    interval.before()?;
    let extent = interval.after_io(file.metadata())?.len();
    if extent == 0 || extent > MAX_DESCRIPTOR_BYTES {
        return Err(MeasurementOriginError::Authentication(
            "installed descriptor extent",
        ));
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0; 4096];
    let mut total = 0u64;
    loop {
        interval.before()?;
        let count = interval.after_io(file.read(&mut buffer))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or(MeasurementOriginError::Contract)?;
        if total > MAX_DESCRIPTOR_BYTES {
            return Err(MeasurementOriginError::Authentication(
                "installed descriptor growth",
            ));
        }
        hasher.update(&buffer[..count]);
    }
    if total != extent {
        return Err(MeasurementOriginError::Authentication(
            "installed descriptor changed",
        ));
    }
    Ok((file, *hasher.finalize().as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_file_with_parent_frame_cannot_substitute_for_kernel_port() {
        let directory = tempfile::tempdir().unwrap();
        let substitute_path = directory.path().join("vport0p1");
        std::fs::write(directory.path().join("name"), b"crucible.original.parent\n").unwrap();
        let mut substitute = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(substitute_path)
            .unwrap();
        substitute
            .write_all(b"CPARNT01crucible.original.parent\n")
            .unwrap();
        substitute.rewind().unwrap();
        let start_ns = monotonic_ns().unwrap();
        let interval = OriginalInterval {
            start_ns,
            end_ns: start_ns + 30_000_000_000,
        };

        let refused = pin_kernel_port(&substitute, interval);

        assert!(matches!(
            refused,
            Err(MeasurementOriginError::Authentication(
                "parent port character device"
            ))
        ));
        assert_eq!(substitute.stream_position().unwrap(), 0);
    }
}
