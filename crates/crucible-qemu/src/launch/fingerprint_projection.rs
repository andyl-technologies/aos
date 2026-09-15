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
        }
    }

    const fn with_instance(mut self, instance: u32) -> Self {
        self.instance = instance;
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
            projection_version: 1,
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

const X86_APIC: ProjectionRow = row!("apic", 0, "apic", 3, VOLATILE, "x86-apic");
const TIMER: ProjectionRow = row!("timer", 0, "timer", 2, VOLATILE, "cpu-timers");
const CPU_COMMON: ProjectionRow = row!("cpu_common", 0, "cpu_common", 1, VOLATILE, "cpu-common");
const X86_CPU: ProjectionRow = row!("cpu", 0, "cpu", 12, VOLATILE, "x86-cpu");
const AARCH64_CPU: ProjectionRow = row!("cpu", 0, "cpu", 22, VOLATILE, "aarch64-cpu");

const Q35_BODY_BEFORE_SERIAL: &[ProjectionRow] = &[
    row!("fw_cfg", 0, "fw_cfg", 2, DEVICE, "fw-cfg"),
    row!("0000:00:00.0/mch", 0, "mch", 1, DEVICE, "q35-mch"),
    row!("PCIHost", 0, "PCIHost", 1, DEVICE, "pci-host"),
    row!("PCIBUS", 0, "PCIBUS", 1, DEVICE, "pci-bus"),
    row!("dma", 0, "dma", 1, DEVICE, "i8257"),
    row!("dma", 1, "dma", 1, DEVICE, "i8257"),
    row!("mc146818rtc", 0, "mc146818rtc", 3, VOLATILE, "mc146818rtc"),
    row!("0000:00:1f.0/ICH9LPC", 0, "ICH9LPC", 1, DEVICE, "ich9-lpc"),
    row!("i8259", 0, "i8259", 1, VOLATILE, "x86-i8259"),
    row!("i8259", 1, "i8259", 1, VOLATILE, "x86-i8259"),
    row!("ioapic", 0, "ioapic", 3, VOLATILE, "x86-ioapic"),
    row!("hpet", 0, "hpet", 2, VOLATILE, "hpet"),
    row!("i8254", 0, "i8254", 3, VOLATILE, "i8254"),
    row!("pcspk", 0, "pcspk", 1, DEVICE, "pcspk"),
];

const Q35_BODY_AFTER_SERIAL: &[ProjectionRow] = &[
    row!("ps2kbd", 0, "ps2kbd", 3, DEVICE, "ps2-keyboard"),
    row!("ps2mouse", 0, "ps2mouse", 2, DEVICE, "ps2-mouse"),
    row!("pckbd", 0, "pckbd", 3, DEVICE, "pckbd"),
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
    row!(
        "0000:00:01.0/virtio-rng",
        0,
        "virtio-rng",
        1,
        DEVICE,
        "virtio-rng"
    ),
];

const AARCH64_BODY_BEFORE_CPUS: &[ProjectionRow] = &[
    row!("pflash_cfi01", 0, "pflash_cfi01", 1, DEVICE, "pflash-cfi01"),
    row!("pflash_cfi01", 1, "pflash_cfi01", 1, DEVICE, "pflash-cfi01"),
];

const AARCH64_BODY_AFTER_CPUS: &[ProjectionRow] = &[
    row!("arm_gic", 0, "arm_gic", 12, VOLATILE, "arm-gicv2"),
    row!("pl011", 0, "pl011", 2, DEVICE, "pl011"),
    row!("pl031", 0, "pl031", 1, VOLATILE, "pl031"),
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
    row!("gpio-key", 0, "gpio-key", 1, DEVICE, "gpio-key"),
    row!("fw_cfg", 0, "fw_cfg", 2, DEVICE, "fw-cfg"),
    row!(
        "0000:00:01.0/virtio-rng",
        0,
        "virtio-rng",
        1,
        DEVICE,
        "virtio-rng"
    ),
];

const SHMEM_CONTROL: ProjectionRow = row!(
    "block/crucible-shmem",
    0,
    "block/crucible-shmem",
    1,
    CONTROL,
    "block-shmem"
);
const SERIAL: ProjectionRow = row!("serial", 0, "serial", 3, DEVICE, "serial-isa");
const DEBUG_CONSOLE: ProjectionRow = row!(
    "0000:00:07.0/virtio-console",
    0,
    "virtio-console",
    3,
    DEVICE,
    "virtio-console"
);
const ROOT_BLOCK: ProjectionRow = row!(
    "0000:00:02.0/virtio-blk",
    0,
    "virtio-blk",
    2,
    DEVICE,
    "virtio-blk"
);
const SHMEM_BLOCK: ProjectionRow = row!(
    "0000:00:03.0/virtio-blk",
    0,
    "virtio-blk",
    2,
    DEVICE,
    "virtio-blk"
);
const NINEP: ProjectionRow = row!(
    "0000:00:04.0/virtio-9p",
    0,
    "virtio-9p",
    1,
    DEVICE,
    "virtio-9p"
);
const NETWORK: ProjectionRow = row!(
    "0000:00:05.0/virtio-net",
    0,
    "virtio-net",
    11,
    DEVICE,
    "virtio-net"
);
const ACCELERATOR: ProjectionRow = row!(
    "0000:00:06.0/virtio-crucible-accelerator",
    0,
    "virtio-crucible-accelerator",
    1,
    DEVICE,
    "virtio-crucible-accelerator"
);
const FAULT: ProjectionRow = row!(
    "crucible-fault",
    0,
    "crucible-fault",
    1,
    CONTROL,
    "fault-continuation"
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

    #[test]
    fn base_manifests_match_real_qemu_registry() -> Result<(), &'static str> {
        let q35 = expected_manifest_for_shape(base_shape(FaultCapabilityScope::X86_64))
            .ok_or("missing x86 manifest")?;
        assert_eq!(q35.sections, 38);
        assert_eq!(
            q35.digest,
            "b16a021575e8531db6113dca25b8e81d4030ac83ef71e412bb9a0f1608cac716"
        );

        let aarch64 = expected_manifest_for_shape(base_shape(FaultCapabilityScope::Aarch64))
            .ok_or("missing AArch64 manifest")?;
        assert_eq!(aarch64.sections, 17);
        assert_eq!(
            aarch64.digest,
            "56416e60b98c89d742067f6b778065f4703067f8194844522188af9e2567d398"
        );
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

        assert_eq!(manifest.sections, 46);
        assert_eq!(
            manifest.digest,
            "aca862dd10cea0ecee1421ac1dd7f922c2ed153a424fb7d6e3e52e9649774f55"
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

        assert_eq!(manifest.sections, 24);
        assert_eq!(
            manifest.digest,
            "93cbf8ca6b9d02ded1d71ba48ea9fecd953d92f558a695643054cbed5e7c1bdc"
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
        assert_eq!(q35.sections, 47);
        assert_eq!(
            q35.digest,
            "3e1a188d6e5e81c1c219b89ddd807cbe7c8d2f509da9f9e50519a7f2b6a52a93"
        );

        let identities = q35
            .rows
            .iter()
            .take(14)
            .map(|row| (row.id.as_str(), row.instance))
            .collect::<Vec<_>>();
        assert_eq!(
            identities,
            [
                ("apic", 0),
                ("apic", 1),
                ("apic", 2),
                ("apic", 3),
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
        assert_eq!(aarch64.sections, 23);
        assert_eq!(
            aarch64.digest,
            "2b853f147b00af4c4298cb851e8478ca83cf9a1533122a35f4b0a3c18d129a1c"
        );
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
