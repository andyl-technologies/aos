//! Tests for committed Secure Boot certificate enrollment, retirement, and SBAT floors.

use super::{add_sb_cert, retire_sb_cert, set_sbat_floor};
use crate::registry::sb_certs::SbCertsToml;
use crate::registry_ops::test_support::{SBCERT_A, SBCERT_B};

#[test]
fn add_sb_cert_enrolls_and_rejects_dupes() {
    let mut catalog = SbCertsToml::default();
    add_sb_cert(&mut catalog, "db-2026", SBCERT_A).unwrap();
    assert_eq!(catalog.active.len(), 1);
    assert_eq!(catalog.active[0].cert_sha256, SBCERT_A);
    // Uppercase digest is normalized to lowercase.
    let mut c2 = SbCertsToml::default();
    add_sb_cert(&mut c2, "db", &SBCERT_A.to_ascii_uppercase()).unwrap();
    assert_eq!(c2.active[0].cert_sha256, SBCERT_A);
    // Duplicate id and duplicate digest both rejected.
    assert!(add_sb_cert(&mut catalog, "db-2026", SBCERT_B).is_err());
    assert!(add_sb_cert(&mut catalog, "other", SBCERT_A).is_err());
    // Bad digest rejected.
    assert!(add_sb_cert(&mut catalog, "bad", "nothex").is_err());
}

#[test]
fn retire_sb_cert_moves_active_to_revoked() {
    let mut catalog = SbCertsToml::default();
    add_sb_cert(&mut catalog, "db", SBCERT_A).unwrap();
    retire_sb_cert(&mut catalog, "db", Some("compromised")).unwrap();
    assert_eq!(catalog.revoked.len(), 1);
    // Still active-listed (validate_catalog requires it) but revoked.
    assert!(catalog.active.iter().any(|c| c.id == "db"));
    assert!(!catalog.accepts_signer(SBCERT_A));
    // Already revoked / unknown id rejected.
    assert!(retire_sb_cert(&mut catalog, "db", None).is_err());
    assert!(retire_sb_cert(&mut catalog, "ghost", None).is_err());
}

#[test]
fn set_sbat_floor_raises_only() {
    let mut catalog = SbCertsToml::default();
    set_sbat_floor(&mut catalog, "aos", 1).unwrap();
    set_sbat_floor(&mut catalog, "aos", 3).unwrap();
    assert_eq!(catalog.sbat_floor[0].generation, 3);
    // Lowering is refused.
    assert!(set_sbat_floor(&mut catalog, "aos", 2).is_err());
    // Equal is allowed (idempotent re-set).
    set_sbat_floor(&mut catalog, "aos", 3).unwrap();
    // New component inserted.
    set_sbat_floor(&mut catalog, "systemd", 1).unwrap();
    assert_eq!(catalog.sbat_floor.len(), 2);
    assert!(set_sbat_floor(&mut catalog, "", 1).is_err());
}
