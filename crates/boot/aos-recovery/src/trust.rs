//! Applies the immutable Secure Boot db trust snapshot inside recovery.
//!
//! The recovery initrd carries the currently signing db certificate together
//! with every configured rotation-overlap db certificate. Verification is
//! delegated to [`aos_boot_media::trust::DbTrust`], which accepts an artifact
//! only when one complete PEM certificate authorizes it.

use std::path::{Path, PathBuf};

use aos_boot_media::Tools;
use aos_boot_media::trust::DbTrust;

const AUTHORIZED_DB_CERTS: &str = "/etc/aos/trust/authorized-db-certs.pem";
const WORK_DIR: &str = "/run/aos-recovery";

fn snapshot() -> DbTrust {
    DbTrust {
        bundle: PathBuf::from(AUTHORIZED_DB_CERTS),
        work_dir: PathBuf::from(WORK_DIR),
    }
}

/// Verifies one UKI against the immutable configured db snapshot.
pub(crate) fn verify_uki(uki: &Path) -> Result<(), String> {
    snapshot()
        .verify_uki(&Tools::initrd(), uki)
        .map_err(|error| error.to_string())
}

/// Verifies a detached SHA-256 signature against the configured db snapshot.
pub(crate) fn verify_detached_signature(data: &Path, signature: &Path) -> Result<(), String> {
    snapshot()
        .verify_detached_signature(&Tools::initrd(), data, signature)
        .map_err(|error| error.to_string())
}
