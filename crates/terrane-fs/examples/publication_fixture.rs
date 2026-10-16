//! Runs explicit non-production native publication fixtures in a fresh process.
//!
//! The guest supervisor provisions fixed disk-backed roots and encoded inputs
//! before starting UID 841/GID 845 with empty capabilities. This executable
//! installs the actual confinement policy before creating runtimes, threads or
//! mutable publisher handles. A selector is never a content-validity receipt.

use std::{io, process::ExitCode, sync::Arc};

#[path = "../tests/host_publish_kernel.rs"]
mod kernel_fixture;

const SELECTORS: &[&str] = &[
    "disk_ext4_seal_noreplace_recovery_and_domain_isolation",
    "canceled_waiter_retains_owner_through_actual_binding_durability",
    "startup_reports_actual_private_state_recovery_failure",
    "unsupported_wipe_policy_is_refused_before_directory_effects",
    "pending_restart_rebuilds_lease_and_requires_canonical_adoption",
    "pack_pair_reconciles_actual_partial_rename_without_replacing_collision",
    "failed_second_unlink_recovers_orphan_index_without_pack_authority",
    "prepared_roots_defer_staging_effects_and_retain_actual_exclusion",
    "staged_writer_retains_root_exclusion_after_adapter_drop",
    "actual_binding_path_failure_rolls_back_before_backing_acknowledgment",
];

fn fixture_inputs() -> io::Result<()> {
    use terrane_core::identity::{IdentityKind, TERRANE_V1};
    use terrane_core::pack_format::{HEADER_SIZE, Header, PackView, Record, encode_pack};

    // Fixed stdout-only image assets carry no native verification or admission
    // authority. The unconfined guest supervisor installs ownership separately.
    let plaintext = b"pack-payload";
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, plaintext)
        .map_err(io::Error::other)?;
    let mut body = vec![0];
    body.extend_from_slice(plaintext);
    for (root, id) in [
        ("worker-pack-partial-rename", [0x31; 16]),
        ("worker-pack-partial-unlink", [0x42; 16]),
    ] {
        let record = Record {
            hash: identity.digest().try_into().map_err(io::Error::other)?,
            offset: HEADER_SIZE as u64,
            body_len: body.len() as u32,
            plaintext_len: plaintext.len() as u32,
            codec: 0,
            kind: 0,
            dictionary_id: 0,
        };
        let pack = encode_pack(Header::new(id, false, false), &body, &[record])
            .map_err(io::Error::other)?;
        let index = PackView::decode(&pack)
            .map_err(io::Error::other)?
            .index_object();
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let id = hex(&id);
        for (extension, bytes) in [("pack", pack), ("idx", index)] {
            println!(
                "{root}/objects/pack/{}/{id}.{extension}\t{}",
                &id[..2],
                hex(&bytes)
            );
        }
    }
    Ok(())
}

fn run() -> io::Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let [selector] = arguments.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected exactly one fixture selector or --list",
        ));
    };
    if selector == "--fixture-inputs" {
        return fixture_inputs();
    }
    if selector == "--list" {
        for selector in SELECTORS {
            println!("{selector}");
        }
        return Ok(());
    }
    if !SELECTORS.contains(&selector.as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unknown publication fixture",
        ));
    }
    if rustix::process::geteuid().as_raw() != 841 || rustix::process::getegid().as_raw() != 845 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "native fixture requires supervised publisher UID 841/GID 845",
        ));
    }

    let confinement = Arc::new(terrane_fs::quota_confinement::install()?);
    confinement.check_current()?;
    if selector == SELECTORS[0] {
        kernel_fixture::run(confinement)?;
    } else {
        terrane_fs::publisher_io::run_native_fixture(selector, confinement)?;
    }
    println!("PASS native-publication {selector}");
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("native publication fixture failed: {error}");
            ExitCode::FAILURE
        }
    }
}
