//! Expected fingerprint projection manifests for admitted QEMU launches.

use crucible_shmem::FaultCapabilityScope;

use crate::qmp::{QmpFingerprintProjectionManifest, QmpFingerprintProjectionManifestRow};

use super::QemuVmLaunchConfig;

const VOLATILE: u32 = 1;
const DEVICE: u32 = 2;
const CONTROL: u32 = 4;

#[derive(Clone, Copy)]
struct ProjectionManifestShape {
    architecture: FaultCapabilityScope,
    smp_vcpus: u16,
    console_capture: bool,
    debug_guest_activation_endpoint: bool,
    root_block: bool,
    shmem_block: bool,
    ninep: bool,
    network: bool,
    accelerator: bool,
}

#[derive(Clone, Copy)]
struct ProjectionRow {
    id: &'static str,
    instance: u32,
    vmsd_name: &'static str,
    vmsd_version: u32,
    domain: u32,
    projection_schema: &'static str,
    projection_version: u32,
}

impl ProjectionRow {
    const fn new(
        id: &'static str,
        instance: u32,
        vmsd_name: &'static str,
        vmsd_version: u32,
        domain: u32,
        projection_schema: &'static str,
    ) -> Self {
        Self {
            id,
            instance,
            vmsd_name,
            vmsd_version,
            domain,
            projection_schema,
            projection_version: 1,
        }
    }

    const fn with_instance(mut self, instance: u32) -> Self {
        self.instance = instance;
        self
    }

    const fn with_projection_version(mut self, projection_version: u32) -> Self {
        self.projection_version = projection_version;
        self
    }

    fn into_qmp(self) -> QmpFingerprintProjectionManifestRow {
        QmpFingerprintProjectionManifestRow {
            id: self.id.to_owned(),
            instance: self.instance,
            vmsd_name: self.vmsd_name.to_owned(),
            vmsd_version: self.vmsd_version,
            domain: self.domain,
            projection_schema: self.projection_schema.to_owned(),
            projection_version: self.projection_version,
        }
    }
}

macro_rules! row {
    ($id:literal, $instance:literal, $vmsd:literal, $version:literal, $domain:ident, $schema:literal) => {
        ProjectionRow::new(
            $id,
            $instance,
            $vmsd,
            $version,
            $domain,
            concat!("crucible.qemu.", $schema, ".v1"),
        )
    };
}

macro_rules! virtio_row {
    ($id:literal, $instance:literal, $vmsd:literal, $version:literal, $schema:literal) => {
        ProjectionRow::new(
            $id,
            $instance,
            $vmsd,
            $version,
            DEVICE,
            concat!("crucible.qemu.", $schema, ".v3"),
        )
        .with_projection_version(3)
    };
}

// Versioned rows must match the live QMP registry pinned by the projection-manifest gate.
macro_rules! versioned_row {
    ($id:literal, $instance:literal, $vmsd:literal, $version:literal, $domain:ident, $schema:literal, $projection:literal) => {
        ProjectionRow::new(
            $id,
            $instance,
            $vmsd,
            $version,
            $domain,
            concat!("crucible.qemu.", $schema, ".v", stringify!($projection)),
        )
        .with_projection_version($projection)
    };
}

const X86_APIC: ProjectionRow = versioned_row!("apic", 0, "apic", 3, VOLATILE, "x86-apic", 3);
const UI_INPUT_QUEUE: ProjectionRow =
    row!("ui-input-queue", 0, "ui-input-queue", 1, DEVICE, "ui-input-queue");
const TIMER: ProjectionRow = versioned_row!("timer", 0, "timer", 2, VOLATILE, "cpu-timers", 5);
const CPU_COMMON: ProjectionRow = row!("cpu_common", 0, "cpu_common", 1, VOLATILE, "cpu-common");
const X86_CPU: ProjectionRow = versioned_row!("cpu", 0, "cpu", 12, VOLATILE, "x86-cpu", 2);
const AARCH64_CPU: ProjectionRow = versioned_row!("cpu", 0, "cpu", 22, VOLATILE, "aarch64-cpu", 2);
const VIRTIO_RNG: ProjectionRow = versioned_row!(
    "0000:00:01.0/virtio-rng",
    0,
    "virtio-rng",
    3,
    DEVICE,
    "virtio-rng",
    5
);

const Q35_BODY_BEFORE_SERIAL: &[ProjectionRow] = &[
    versioned_row!("fw_cfg", 0, "fw_cfg", 2, DEVICE, "fw-cfg", 3),
    row!("0000:00:00.0/mch", 0, "mch", 1, DEVICE, "q35-mch"),
    row!("PCIHost", 0, "PCIHost", 1, DEVICE, "pci-host"),
    row!("PCIBUS", 0, "PCIBUS", 1, DEVICE, "pci-bus"),
    row!("dma", 0, "dma", 1, DEVICE, "i8257"),
    row!("dma", 1, "dma", 1, DEVICE, "i8257"),
    versioned_row!(
        "mc146818rtc",
        0,
        "mc146818rtc",
        3,
        VOLATILE,
        "mc146818rtc",
        6
    ),
    versioned_row!(
        "0000:00:1f.0/ICH9LPC",
        0,
        "ICH9LPC",
        1,
        DEVICE,
        "ich9-lpc",
        3
    ),
    row!("i8259", 0, "i8259", 1, VOLATILE, "x86-i8259"),
    row!("i8259", 1, "i8259", 1, VOLATILE, "x86-i8259"),
    versioned_row!("ioapic", 0, "ioapic", 3, VOLATILE, "x86-ioapic", 3),
    versioned_row!("hpet", 0, "hpet", 2, VOLATILE, "hpet", 3),
    versioned_row!("i8254", 0, "i8254", 3, VOLATILE, "i8254", 3),
    row!("pcspk", 0, "pcspk", 1, DEVICE, "pcspk"),
];

const Q35_BODY_AFTER_SERIAL: &[ProjectionRow] = &[
    row!("ps2kbd", 0, "ps2kbd", 3, DEVICE, "ps2-keyboard"),
    row!("ps2mouse", 0, "ps2mouse", 2, DEVICE, "ps2-mouse"),
    versioned_row!("pckbd", 0, "pckbd", 3, DEVICE, "pckbd", 2),
    row!("vmmouse", 0, "vmmouse", 0, DEVICE, "vmmouse"),
    row!("port92", 0, "port92", 1, DEVICE, "port92"),
    row!(
        "0000:00:1f.2/ich9_ahci",
        0,
        "ich9_ahci",
        1,
        DEVICE,
        "ich9-ahci"
    ),
    row!("i2c_bus", 0, "i2c_bus", 1, DEVICE, "i2c-bus"),
    row!(
        "0000:00:1f.3/ich9_smb",
        0,
        "ich9_smb",
        1,
        DEVICE,
        "ich9-smb"
    ),
    row!("smbus-eeprom", 0, "smbus-eeprom", 1, DEVICE, "smbus-eeprom"),
    row!("smbus-eeprom", 1, "smbus-eeprom", 1, DEVICE, "smbus-eeprom"),
    row!("smbus-eeprom", 2, "smbus-eeprom", 1, DEVICE, "smbus-eeprom"),
    row!("smbus-eeprom", 3, "smbus-eeprom", 1, DEVICE, "smbus-eeprom"),
    row!("smbus-eeprom", 4, "smbus-eeprom", 1, DEVICE, "smbus-eeprom"),
    row!("smbus-eeprom", 5, "smbus-eeprom", 1, DEVICE, "smbus-eeprom"),
    row!("smbus-eeprom", 6, "smbus-eeprom", 1, DEVICE, "smbus-eeprom"),
    row!("smbus-eeprom", 7, "smbus-eeprom", 1, DEVICE, "smbus-eeprom"),
    VIRTIO_RNG,
];

const AARCH64_BODY_BEFORE_CPUS: &[ProjectionRow] = &[
    row!("pflash_cfi01", 0, "pflash_cfi01", 1, DEVICE, "pflash-cfi01"),
    row!("pflash_cfi01", 1, "pflash_cfi01", 1, DEVICE, "pflash-cfi01"),
];

const AARCH64_BODY_AFTER_CPUS: &[ProjectionRow] = &[
    row!("arm_gic", 0, "arm_gic", 12, VOLATILE, "arm-gicv2"),
    row!("pl011", 0, "pl011", 2, DEVICE, "pl011"),
    versioned_row!("pl031", 0, "pl031", 1, VOLATILE, "pl031", 4),
    row!(
        "0000:00:00.0/gpex_root",
        0,
        "gpex_root",
        1,
        DEVICE,
        "gpex-root"
    ),
    row!("PCIHost", 0, "PCIHost", 1, DEVICE, "pci-host"),
    row!("PCIBUS", 0, "PCIBUS", 1, DEVICE, "pci-bus"),
    row!("pl061", 0, "pl061", 4, DEVICE, "pl061"),
    versioned_row!("gpio-key", 0, "gpio-key", 1, DEVICE, "gpio-key", 2),
    versioned_row!("fw_cfg", 0, "fw_cfg", 2, DEVICE, "fw-cfg", 3),
    VIRTIO_RNG,
];

const SHMEM_CONTROL: ProjectionRow = versioned_row!(
    "block/crucible-shmem",
    0,
    "block/crucible-shmem",
    2,
    CONTROL,
    "block-shmem",
    2
);
const SERIAL: ProjectionRow = versioned_row!("serial", 0, "serial", 3, DEVICE, "serial-isa", 2);
const DEBUG_CONSOLE: ProjectionRow = virtio_row!(
    "0000:00:07.0/virtio-console",
    0,
    "virtio-console",
    3,
    "virtio-console"
);
const ROOT_BLOCK: ProjectionRow =
    virtio_row!("0000:00:02.0/virtio-blk", 0, "virtio-blk", 2, "virtio-blk");
const SHMEM_BLOCK: ProjectionRow =
    virtio_row!("0000:00:03.0/virtio-blk", 0, "virtio-blk", 2, "virtio-blk");
const NINEP: ProjectionRow = virtio_row!("0000:00:04.0/virtio-9p", 0, "virtio-9p", 1, "virtio-9p");
const NETWORK: ProjectionRow = ProjectionRow::new(
    "0000:00:05.0/virtio-net",
    0,
    "virtio-net",
    11,
    DEVICE,
    "crucible.qemu.virtio-net.v5",
)
.with_projection_version(5);
const ACCELERATOR: ProjectionRow = virtio_row!(
    "0000:00:06.0/virtio-crucible-accelerator",
    0,
    "virtio-crucible-accelerator",
    1,
    "virtio-crucible-accelerator"
);
const FAULT: ProjectionRow = versioned_row!(
    "crucible-fault",
    0,
    "crucible-fault",
    1,
    CONTROL,
    "fault-continuation",
    2
);
const Q35_ACPI: ProjectionRow = row!("acpi_build", 0, "acpi_build", 1, DEVICE, "acpi-build");
const AARCH64_ACPI: ProjectionRow = row!(
    "virt_acpi_build",
    0,
    "virt_acpi_build",
    1,
    DEVICE,
    "virt-acpi-build"
);

pub(super) fn expected_fingerprint_projection_manifest(
    architecture: FaultCapabilityScope,
    smp_vcpus: u16,
    vm: &QemuVmLaunchConfig,
    console_capture: bool,
    debug_guest_activation_endpoint: bool,
) -> Option<QmpFingerprintProjectionManifest> {
    expected_manifest_for_shape(ProjectionManifestShape {
        architecture,
        smp_vcpus,
        console_capture,
        debug_guest_activation_endpoint,
        root_block: vm.root_image.is_some(),
        shmem_block: vm.crucible_shmem_block.is_some(),
        ninep: vm.crucible_shmem_9p.is_some(),
        network: vm.crucible_shmem_network.is_some(),
        accelerator: vm.crucible_accelerator.is_some(),
    })
}

fn expected_manifest_for_shape(
    shape: ProjectionManifestShape,
) -> Option<QmpFingerprintProjectionManifest> {
    if shape.smp_vcpus == 0 {
        return None;
    }

    let mut rows = Vec::with_capacity(48 + usize::from(shape.smp_vcpus) * 3);
    match shape.architecture {
        FaultCapabilityScope::X86_64 => {
            rows.extend(
                (0..u32::from(shape.smp_vcpus)).map(|instance| X86_APIC.with_instance(instance)),
            );
            rows.push(UI_INPUT_QUEUE);
            rows.push(TIMER);
            if shape.shmem_block {
                rows.push(SHMEM_CONTROL);
            }
            rows.push(CPU_COMMON);
            rows.push(X86_CPU);
            rows.push(row!(
                "kvm-tpr-opt",
                0,
                "kvm-tpr-opt",
                1,
                DEVICE,
                "kvm-tpr-opt"
            ));
            for instance in 1..u32::from(shape.smp_vcpus) {
                rows.push(CPU_COMMON.with_instance(instance));
                rows.push(X86_CPU.with_instance(instance));
            }
            rows.extend_from_slice(Q35_BODY_BEFORE_SERIAL);
            if shape.console_capture {
                rows.push(SERIAL);
            }
            rows.extend_from_slice(Q35_BODY_AFTER_SERIAL);
        }
        FaultCapabilityScope::Aarch64 => {
            rows.push(UI_INPUT_QUEUE);
            rows.push(TIMER);
            if shape.shmem_block {
                rows.push(SHMEM_CONTROL);
            }
            rows.extend_from_slice(AARCH64_BODY_BEFORE_CPUS);
            for instance in 0..u32::from(shape.smp_vcpus) {
                rows.push(CPU_COMMON.with_instance(instance));
                rows.push(AARCH64_CPU.with_instance(instance));
            }
            rows.extend_from_slice(AARCH64_BODY_AFTER_CPUS);
        }
        _ => return None,
    }

    if shape.root_block {
        rows.push(ROOT_BLOCK);
    }
    if shape.shmem_block {
        rows.push(SHMEM_BLOCK);
    }
    if shape.ninep {
        rows.push(NINEP);
    }
    if shape.network {
        rows.push(NETWORK);
    }
    if shape.accelerator {
        rows.push(ACCELERATOR);
    }
    if shape.debug_guest_activation_endpoint {
        rows.push(DEBUG_CONSOLE);
    }
    rows.push(FAULT);
    rows.push(match shape.architecture {
        FaultCapabilityScope::X86_64 => Q35_ACPI,
        FaultCapabilityScope::Aarch64 => AARCH64_ACPI,
        _ => return None,
    });

    Some(QmpFingerprintProjectionManifest::from_rows(
        rows.into_iter().map(ProjectionRow::into_qmp).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn base_shape(architecture: FaultCapabilityScope) -> ProjectionManifestShape {
        ProjectionManifestShape {
            architecture,
            smp_vcpus: 1,
            console_capture: false,
            debug_guest_activation_endpoint: false,
            root_block: false,
            shmem_block: false,
            ninep: false,
            network: false,
            accelerator: false,
        }
    }

    fn assert_projection_row(
        manifest: &QmpFingerprintProjectionManifest,
        index: usize,
        id: &str,
        instance: u32,
        vmsd_version: u32,
        projection_schema: &str,
        projection_version: u32,
    ) {
        let row = &manifest.rows[index];

        assert_eq!((row.id.as_str(), row.instance), (id, instance));
        assert_eq!(row.vmsd_version, vmsd_version);
        assert_eq!(row.projection_schema, projection_schema);
        assert_eq!(row.projection_version, projection_version);
    }

    #[test]
    fn base_manifests_match_real_qemu_registry() -> Result<(), &'static str> {
        let q35 = expected_manifest_for_shape(base_shape(FaultCapabilityScope::X86_64))
            .ok_or("missing x86 manifest")?;
        assert_eq!(q35.sections, 39);
        assert_eq!(
            q35.digest,
            "ee6010553d7a7d1a8ee4740b5f5f265f87539ab7ae492eaae5b8b84562d787bc"
        );

        let aarch64 = expected_manifest_for_shape(base_shape(FaultCapabilityScope::Aarch64))
            .ok_or("missing AArch64 manifest")?;
        assert_eq!(aarch64.sections, 18);
        assert_eq!(
            aarch64.digest,
            "9b3f3e1b09e31333bd6a44b4dd87b00f7cea73e06612be6ef2b41a65dd885c3a"
        );
        Ok(())
    }

    #[test]
    fn timer_uses_current_projection_schema() -> Result<(), &'static str> {
        let manifest = expected_manifest_for_shape(base_shape(FaultCapabilityScope::X86_64))
            .ok_or("missing x86 manifest")?;
        let timer = manifest
            .rows
            .iter()
            .find(|row| row.id == "timer")
            .ok_or("missing timer projection")?;

        assert_eq!(timer.projection_schema, "crucible.qemu.cpu-timers.v5");
        assert_eq!(timer.projection_version, 5);
        Ok(())
    }

    #[test]
    fn envoy_manifest_matches_realized_registry() -> Result<(), &'static str> {
        let manifest = expected_manifest_for_shape(ProjectionManifestShape {
            architecture: FaultCapabilityScope::X86_64,
            smp_vcpus: 1,
            console_capture: true,
            debug_guest_activation_endpoint: true,
            root_block: true,
            shmem_block: false,
            ninep: false,
            network: true,
            accelerator: false,
        })
        .ok_or("missing Envoy manifest")?;

        assert_eq!(manifest.sections, 43);
        assert_eq!(
            manifest.digest,
            "1ea959c79dc528bd190896d40918df1c0065fef8f451a13949d6509c0c7ffa4d"
        );
        Ok(())
    }

    #[test]
    fn isa_serial_uses_current_projection_schema() -> Result<(), &'static str> {
        let manifest = expected_manifest_for_shape(ProjectionManifestShape {
            console_capture: true,
            ..base_shape(FaultCapabilityScope::X86_64)
        })
        .ok_or("missing x86 manifest with ISA serial")?;
        let serial = manifest
            .rows
            .iter()
            .find(|row| row.id == "serial")
            .ok_or("missing ISA serial projection")?;

        assert_eq!(serial.projection_schema, "crucible.qemu.serial-isa.v2");
        assert_eq!(serial.projection_version, 2);
        Ok(())
    }

    #[test]
    fn virtio_devices_use_current_projection_schema() -> Result<(), &'static str> {
        let manifest = expected_manifest_for_shape(ProjectionManifestShape {
            architecture: FaultCapabilityScope::X86_64,
            smp_vcpus: 1,
            console_capture: true,
            debug_guest_activation_endpoint: true,
            root_block: true,
            shmem_block: true,
            ninep: true,
            network: true,
            accelerator: true,
        })
        .ok_or("missing combined q35 manifest")?;
        let virtio_rows = manifest
            .rows
            .iter()
            .filter(|row| row.projection_schema.starts_with("crucible.qemu.virtio-"))
            .collect::<Vec<_>>();

        let expected_provider_versions = virtio_rows.iter().all(|row| {
            if matches!(row.vmsd_name.as_str(), "virtio-rng" | "virtio-net") {
                row.projection_schema.ends_with(".v5") && row.projection_version == 5
            } else {
                row.projection_schema.ends_with(".v3") && row.projection_version == 3
            }
        });
        let rng_vmstate_is_v3 = virtio_rows
            .iter()
            .any(|row| row.vmsd_name == "virtio-rng" && row.vmsd_version == 3);

        assert_eq!(virtio_rows.len(), 7);
        assert!(expected_provider_versions);
        assert!(rng_vmstate_is_v3);
        Ok(())
    }

    #[test]
    fn combined_q35_manifest_matches_fixed_slot_registry() -> Result<(), &'static str> {
        let manifest = expected_manifest_for_shape(ProjectionManifestShape {
            architecture: FaultCapabilityScope::X86_64,
            smp_vcpus: 1,
            console_capture: true,
            debug_guest_activation_endpoint: true,
            root_block: true,
            shmem_block: true,
            ninep: true,
            network: true,
            accelerator: true,
        })
        .ok_or("missing combined q35 manifest")?;

        assert_eq!(manifest.sections, 47);
        assert_eq!(
            manifest.digest,
            "3ae28b0d8f1e20fb1791f058a57a807b0dbe69c5c7349885e5bf6e9744a4b27c"
        );
        Ok(())
    }

    #[test]
    fn production_q35_manifest_matches_fixed_slot_registry() -> Result<(), &'static str> {
        let manifest = expected_manifest_for_shape(ProjectionManifestShape {
            architecture: FaultCapabilityScope::X86_64,
            smp_vcpus: 4,
            console_capture: true,
            debug_guest_activation_endpoint: true,
            root_block: false,
            shmem_block: false,
            ninep: false,
            network: false,
            accelerator: false,
        })
        .ok_or("missing production q35 manifest")?;

        assert_eq!(manifest.sections, 50);
        assert_eq!(
            manifest.digest,
            "ab43c207d4f86cc2ed9f64aca69a2a6b6ffb979b37e6df0ac73cea266e1e9912"
        );
        Ok(())
    }

    #[test]
    fn combined_aarch64_manifest_matches_fixed_slot_registry() -> Result<(), &'static str> {
        let manifest = expected_manifest_for_shape(ProjectionManifestShape {
            architecture: FaultCapabilityScope::Aarch64,
            smp_vcpus: 1,
            console_capture: true,
            debug_guest_activation_endpoint: true,
            root_block: true,
            shmem_block: true,
            ninep: true,
            network: true,
            accelerator: true,
        })
        .ok_or("missing combined AArch64 manifest")?;

        assert_eq!(manifest.sections, 25);
        assert_eq!(
            manifest.digest,
            "a6461b16ae8c401844bb60ea8c0bff4b23ac4bc1a99413e4a85cf397e691fd64"
        );
        Ok(())
    }

    #[test]
    fn four_vcpu_manifests_match_real_qemu_registry() -> Result<(), &'static str> {
        let q35 = expected_manifest_for_shape(ProjectionManifestShape {
            smp_vcpus: 4,
            ..base_shape(FaultCapabilityScope::X86_64)
        })
        .ok_or("missing four-vCPU x86 manifest")?;
        assert_eq!(q35.sections, 48);
        assert_eq!(
            q35.digest,
            "3a59da71dc11e4fe2f146574977be521b3cb160bc5aadd584cbef5afde25569f"
        );

        let identities = q35
            .rows
            .iter()
            .take(15)
            .map(|row| (row.id.as_str(), row.instance))
            .collect::<Vec<_>>();
        assert_eq!(
            identities,
            [
                ("apic", 0),
                ("apic", 1),
                ("apic", 2),
                ("apic", 3),
                ("ui-input-queue", 0),
                ("timer", 0),
                ("cpu_common", 0),
                ("cpu", 0),
                ("kvm-tpr-opt", 0),
                ("cpu_common", 1),
                ("cpu", 1),
                ("cpu_common", 2),
                ("cpu", 2),
                ("cpu_common", 3),
                ("cpu", 3),
            ]
        );

        let aarch64 = expected_manifest_for_shape(ProjectionManifestShape {
            smp_vcpus: 4,
            ..base_shape(FaultCapabilityScope::Aarch64)
        })
        .ok_or("missing four-vCPU AArch64 manifest")?;
        assert_eq!(aarch64.sections, 24);
        assert_eq!(
            aarch64.digest,
            "394588ec1ff0acef7dba6260f9b54b30d9802b12971bd900423b96197f6e02fc"
        );
        Ok(())
    }

    #[test]
    fn realized_profiles_pin_every_changed_projection_row() -> Result<(), &'static str> {
        let envoy = expected_manifest_for_shape(ProjectionManifestShape {
            architecture: FaultCapabilityScope::X86_64,
            smp_vcpus: 1,
            console_capture: true,
            debug_guest_activation_endpoint: true,
            root_block: true,
            shmem_block: false,
            ninep: false,
            network: true,
            accelerator: false,
        })
        .ok_or("missing Envoy manifest")?;
        let production = expected_manifest_for_shape(ProjectionManifestShape {
            architecture: FaultCapabilityScope::X86_64,
            smp_vcpus: 4,
            console_capture: true,
            debug_guest_activation_endpoint: true,
            root_block: false,
            shmem_block: false,
            ninep: false,
            network: false,
            accelerator: false,
        })
        .ok_or("missing production manifest")?;

        // The digest pins every ordered row; these assertions expose each changed provider.
        assert_projection_row(&envoy, 0, "apic", 0, 3, "crucible.qemu.x86-apic.v3", 3);
        for (index, instance) in [(0, 0), (1, 1), (2, 2), (3, 3)] {
            assert_projection_row(
                &production,
                index,
                "apic",
                instance,
                3,
                "crucible.qemu.x86-apic.v3",
                3,
            );
        }

        for (manifest, offset) in [(&envoy, 1), (&production, 10)] {
            assert_projection_row(
                manifest,
                5 + offset,
                "fw_cfg",
                0,
                2,
                "crucible.qemu.fw-cfg.v3",
                3,
            );
            assert_projection_row(
                manifest,
                11 + offset,
                "mc146818rtc",
                0,
                3,
                "crucible.qemu.mc146818rtc.v6",
                6,
            );
            assert_projection_row(
                manifest,
                12 + offset,
                "0000:00:1f.0/ICH9LPC",
                0,
                1,
                "crucible.qemu.ich9-lpc.v3",
                3,
            );
            assert_projection_row(
                manifest,
                15 + offset,
                "ioapic",
                0,
                3,
                "crucible.qemu.x86-ioapic.v3",
                3,
            );
            assert_projection_row(
                manifest,
                16 + offset,
                "hpet",
                0,
                2,
                "crucible.qemu.hpet.v3",
                3,
            );
            assert_projection_row(
                manifest,
                17 + offset,
                "i8254",
                0,
                3,
                "crucible.qemu.i8254.v3",
                3,
            );
        }

        assert_projection_row(
            &envoy,
            37,
            "0000:00:01.0/virtio-rng",
            0,
            3,
            "crucible.qemu.virtio-rng.v5",
            5,
        );
        assert_projection_row(
            &envoy,
            41,
            "crucible-fault",
            0,
            1,
            "crucible.qemu.fault-continuation.v2",
            2,
        );
        assert_projection_row(
            &production,
            46,
            "0000:00:01.0/virtio-rng",
            0,
            3,
            "crucible.qemu.virtio-rng.v5",
            5,
        );
        assert_projection_row(
            &production,
            48,
            "crucible-fault",
            0,
            1,
            "crucible.qemu.fault-continuation.v2",
            2,
        );
        Ok(())
    }

    #[test]
    fn stale_realized_projection_versions_are_detected() -> Result<(), &'static str> {
        let expected = expected_manifest_for_shape(ProjectionManifestShape {
            architecture: FaultCapabilityScope::X86_64,
            smp_vcpus: 4,
            console_capture: true,
            debug_guest_activation_endpoint: true,
            root_block: false,
            shmem_block: false,
            ninep: false,
            network: false,
            accelerator: false,
        })
        .ok_or("missing production manifest")?;

        let mut stale_apic_rows = expected.rows.clone();
        stale_apic_rows[0].projection_schema = "crucible.qemu.x86-apic.v2".to_owned();
        stale_apic_rows[0].projection_version = 2;
        let stale_apic = QmpFingerprintProjectionManifest::from_rows(stale_apic_rows);
        assert!(expected.first_difference(&stale_apic).contains("row 0:"));

        let mut stale_rng_rows = expected.rows.clone();
        stale_rng_rows[46].vmsd_version = 2;
        stale_rng_rows[46].projection_schema = "crucible.qemu.virtio-rng.v4".to_owned();
        stale_rng_rows[46].projection_version = 4;
        let stale_rng = QmpFingerprintProjectionManifest::from_rows(stale_rng_rows);
        assert!(expected.first_difference(&stale_rng).contains("row 46:"));
        Ok(())
    }

    #[test]
    fn every_composed_manifest_has_unique_section_identity() -> Result<(), &'static str> {
        for architecture in [FaultCapabilityScope::X86_64, FaultCapabilityScope::Aarch64] {
            for smp_vcpus in [1, 4] {
                for options in 0_u8..=u8::MAX {
                    let manifest = expected_manifest_for_shape(ProjectionManifestShape {
                        architecture,
                        smp_vcpus,
                        console_capture: options & 1 != 0,
                        debug_guest_activation_endpoint: options & 2 != 0,
                        root_block: options & 4 != 0,
                        shmem_block: options & 8 != 0,
                        ninep: options & 16 != 0,
                        network: options & 32 != 0,
                        accelerator: options & 64 != 0,
                    })
                    .ok_or("missing supported architecture manifest")?;
                    let identities = manifest
                        .rows
                        .iter()
                        .map(|row| (&row.id, row.instance))
                        .collect::<BTreeSet<_>>();

                    assert_eq!(manifest.sections as usize, manifest.rows.len());
                    assert_eq!(identities.len(), manifest.rows.len());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn optional_pci_slots_are_distinct() {
        let slots = [
            super::super::QEMU_RNG_PCI_ADDRESS,
            super::super::QEMU_ROOT_PCI_ADDRESS,
            super::super::QEMU_SHMEM_BLOCK_PCI_ADDRESS,
            super::super::QEMU_NINEP_PCI_ADDRESS,
            super::super::QEMU_NETWORK_PCI_ADDRESS,
            super::super::QEMU_ACCELERATOR_PCI_ADDRESS,
            super::super::QEMU_DEBUG_SERIAL_PCI_ADDRESS,
        ];

        assert_eq!(
            slots.into_iter().collect::<BTreeSet<_>>().len(),
            slots.len()
        );
    }
}
