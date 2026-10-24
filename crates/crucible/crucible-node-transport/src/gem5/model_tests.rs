//! Checks model data and actual terminal-name distinctions without live authority.

#![allow(clippy::unwrap_used)]

use crucible_node_format::{Phase, Position, canonical};

use super::*;

fn asset(file: &str) -> Box<Gem5ModelAsset> {
    Box::new(Gem5ModelAsset {
        file: file.into(),
        content: canonical::content_ref(b"fixed model bytes", "application/octet-stream").unwrap(),
        sha256: "ab".repeat(32),
    })
}

fn configuration() -> Gem5ConfigurationTree {
    Gem5ConfigurationTree {
        files: U64::new(2),
        bytes: U64::new(4096),
        sha256: "cd".repeat(32),
    }
}

fn x86() -> Gem5ModelSelection {
    Gem5ModelSelection::X86Linux {
        kernel: asset("kernel.elf"),
        initramfs: asset("initrd.img"),
        configuration: configuration(),
    }
}

fn arm() -> Gem5ModelSelection {
    Gem5ModelSelection::ArmLinux {
        kernel: asset("kernel.elf"),
        initramfs: asset("initrd.img"),
        firmware: asset("boot_v2.arm64"),
        configuration: configuration(),
    }
}

fn boundary(ordinal: u64) -> Gem5Boundary {
    Gem5Boundary {
        logical_position: Position::new(U64::new(557), U64::new(0), Phase::BoundaryControl),
        tick: U64::new(557),
        ordinal: U64::new(ordinal),
        tick_ordinal: U64::new(3),
        has_next_event: true,
        next_tick: U64::new(558),
        next_priority: 0,
        inventory: serde_json::json!({"complete":false}),
    }
}

#[test]
fn new_x86_dialect_never_falls_back_to_se_or_arm() {
    let selected = x86();
    assert!(selected.validate_for(Gem5ModelDialect::X86Linux).is_ok());
    for dialect in [
        Gem5ModelDialect::LegacySe,
        Gem5ModelDialect::ReservedSe,
        Gem5ModelDialect::ArmLinux,
    ] {
        assert!(selected.validate_for(dialect).is_err());
    }
    let se = Gem5ModelSelection::FreestandingO3 {
        guest_isa: "x86_64".into(),
        executable: *asset("guest.elf"),
    };
    assert!(se.validate_for(Gem5ModelDialect::LegacySe).is_ok());
    assert!(se.validate_for(Gem5ModelDialect::ReservedSe).is_ok());
    assert!(se.validate_for(Gem5ModelDialect::X86Linux).is_err());
    assert!(arm().validate_for(Gem5ModelDialect::X86Linux).is_err());
}

#[test]
fn x86_assets_and_loader_credit_are_closed_before_native_use() {
    let mut selected = x86();
    let Gem5ModelSelection::X86Linux { kernel, .. } = &mut selected else {
        unreachable!();
    };
    kernel.file = "guest.elf".into();
    assert!(selected.validate_for(Gem5ModelDialect::X86Linux).is_err());

    let Gem5ModelSelection::X86Linux {
        kernel, initramfs, ..
    } = &mut selected
    else {
        unreachable!();
    };
    kernel.file = "kernel.elf".into();
    initramfs.content.length = U64::new(32 * 1024 * 1024 + 1);
    assert!(selected.validate_for(Gem5ModelDialect::X86Linux).is_err());

    let Gem5ModelSelection::X86Linux {
        initramfs,
        configuration,
        ..
    } = &mut selected
    else {
        unreachable!();
    };
    *initramfs = asset("initrd.img");
    configuration.files = U64::new(0);
    assert!(selected.validate_for(Gem5ModelDialect::X86Linux).is_err());

    let value = serde_json::to_value(x86()).unwrap();
    let mut extra = value.clone();
    extra["firmware"] = serde_json::to_value(asset("arbitrary-bios.bin")).unwrap();
    assert!(serde_json::from_value::<Gem5ModelSelection>(extra).is_err());
    assert_eq!(
        serde_json::from_value::<Gem5ModelSelection>(value).unwrap(),
        x86()
    );
}

#[test]
fn serial_birth_keeps_real_x86_owner_and_native_picosecond_coordinate() {
    let before = boundary(10);
    let after = boundary(11);
    let mut publication = Gem5SerialPublication {
        output_id: U64::new(7),
        tick: U64::new(557),
        event_ordinal: U64::new(11),
        tick_ordinal: U64::new(3),
        causal_parent: U64::new(17),
        facet: "serial".into(),
        terminal: "system.pc.com_1.device".into(),
        payload: vec![0],
    };
    assert!(
        publication
            .validate_birth_for_model(
                &x86(),
                Gem5ModelDialect::X86Linux,
                &before,
                &after,
                U64::new(7),
                U64::new(17)
            )
            .is_ok()
    );
    assert!(
        publication
            .validate_birth(&before, &after, U64::new(7), U64::new(17))
            .is_err()
    );
    assert!(
        publication
            .validate_birth_for_model(
                &arm(),
                Gem5ModelDialect::ArmLinux,
                &before,
                &after,
                U64::new(7),
                U64::new(17)
            )
            .is_err()
    );

    publication.terminal = "system.terminal".into();
    assert!(
        publication
            .validate_birth(&before, &after, U64::new(7), U64::new(17))
            .is_ok()
    );
    assert!(
        publication
            .validate_birth_for_model(
                &x86(),
                Gem5ModelDialect::X86Linux,
                &before,
                &after,
                U64::new(7),
                U64::new(17)
            )
            .is_err()
    );
    publication.tick = U64::new(550);
    assert!(
        publication
            .validate_birth(&before, &after, U64::new(7), U64::new(17))
            .is_err()
    );
}

#[test]
fn old_native_dialect_bytes_remain_exact() {
    for (dialect, bytes) in [
        (
            Gem5ModelDialect::LegacySe,
            b"\"crucible.gem5.native/2\"".as_slice(),
        ),
        (
            Gem5ModelDialect::ReservedSe,
            b"\"crucible.gem5.native/3\"".as_slice(),
        ),
        (
            Gem5ModelDialect::ArmLinux,
            b"\"crucible.gem5.arm-linux-native/1\"".as_slice(),
        ),
    ] {
        assert_eq!(serde_json::to_vec(&dialect).unwrap(), bytes);
    }
}
