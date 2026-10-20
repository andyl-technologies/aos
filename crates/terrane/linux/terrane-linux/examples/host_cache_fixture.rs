//! Runs bounded component witnesses over the real native cache owner in a guest.
//!
//! Each role starts in a fresh process with no capabilities or inherited cache
//! descriptors. Confinement precedes every executor and owner thread. Successful
//! empty recovery is not Resume, serving readiness, admission or BKT-15 proof.

#[path = "host_cache_fixture/actor.rs"]
mod actor;
#[path = "host_cache_fixture/admission.rs"]
mod admission;
#[path = "host_cache_fixture/admission_cache.rs"]
mod admission_cache;
#[path = "host_cache_fixture/config.rs"]
mod config;
#[path = "host_cache_fixture/consumer.rs"]
mod consumer;
#[path = "host_cache_fixture/dictionary_custody.rs"]
mod dictionary_custody;
#[path = "host_cache_fixture/manifest_publication.rs"]
mod manifest_publication;
#[path = "host_cache_fixture/network.rs"]
mod network;
#[path = "host_cache_fixture/publication.rs"]
mod publication;
#[path = "host_cache_fixture/recovery.rs"]
mod recovery;
#[path = "host_cache_fixture/running_retention.rs"]
mod running_retention;
#[path = "host_cache_fixture/source_cleanup.rs"]
mod source_cleanup;

fn main() -> std::process::ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "--list" {
        for selector in [
            "prepare",
            "empty",
            "refuse",
            "late-refuse",
            "cancel",
            "edquot",
            "hold",
            "start-refuse",
            "admit-chunk",
            "admit-metadata",
            "admit-cancel",
            "cache-admission-handoff",
            "dictionary-custody",
            "seed-manifest",
            "seed-bad-manifest",
            "seed-unsealed-manifest",
            "seed-unsealed-writable-manifest",
            "seed-truncated-manifest",
            "seed-writable-manifest",
            "recover-manifest",
            "refuse-manifest",
            "refuse-unsealed-manifest",
            "refuse-unsealed-writable-manifest",
            "refuse-truncated-manifest",
            "recover-writable-manifest",
            "publisher-confinement",
            "publisher-reject-descriptor",
            "publisher-reject-stdio",
            "seed-mixed-manifest",
            "seed-mixed-bad-manifest",
            "recover-mixed-manifest",
            "refuse-mixed-manifest",
            "consumer-leases",
            "publish-inline",
            "publish-inline-cancel",
            "publish-inline-transfer",
            "publish-inline-transfer-cancel",
            "publish-inline-transfer-conflict",
            "retain-running",
            "retain-running-cancel",
            "publish-manifest",
            "publish-manifest-cancel",
            "publish-manifest-bad-whole",
            "publish-manifest-dictionary",
            "publish-manifest-reuse",
            "publish-manifest-reuse-bad-whole",
            "source-cleanup",
            "source-cleanup-early",
            "seed-index-recovery",
            "seed-index-disabled",
            "seed-index-bound",
            "seed-index-mismatch",
            "recover-index-recovery",
            "refuse-index-disabled",
            "refuse-index-bound",
            "refuse-index-mismatch",
            "seed-pending-inline",
            "refuse-pending-inline",
            "recover-pending-inline",
            "seed-pending-raw",
            "seed-pending-zstd",
            "seed-pending-dictionary",
            "refuse-pending-chunk",
            "recover-pending-chunk",
            "seed-pending-pack",
            "refuse-pending-pack",
            "recover-pending-pack",
            "refuse-pending-pack-foreign",
        ] {
            println!("host-cache:{selector}");
        }
        return std::process::ExitCode::SUCCESS;
    }
    let result = if mode == "seed-pending-pack" {
        recovery::pending_packs::seed()
    } else if mode == "seed-pending-inline" {
        recovery::pending::seed()
    } else if matches!(
        mode.as_str(),
        "seed-pending-raw" | "seed-pending-zstd" | "seed-pending-dictionary"
    ) {
        recovery::pending::seed_encoded(&mode)
    } else if matches!(
        mode.as_str(),
        "seed-manifest"
            | "seed-index-recovery"
            | "seed-index-disabled"
            | "seed-index-bound"
            | "seed-index-mismatch"
            | "seed-bad-manifest"
            | "seed-unsealed-manifest"
            | "seed-unsealed-writable-manifest"
            | "seed-truncated-manifest"
            | "seed-writable-manifest"
            | "seed-mixed-manifest"
            | "seed-mixed-bad-manifest"
    ) {
        recovery::seed(&mode)
    } else if matches!(
        mode.as_str(),
        "publisher-confinement" | "publisher-reject-descriptor" | "publisher-reject-stdio"
    ) {
        network::run(&mode)
    } else {
        actor::run(&mode)
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("host-cache component proof: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
