//! End-to-end coverage for the RFC-0006 phase-4 registry Secure Boot
//! catalog: the committed `sb-certs.toml` roster (load/parse/round-trip),
//! the production accept/refuse predicates over the active db-cert set and
//! the SBAT revocation floor, and the schema/serde contract that carries
//! `sb_signer_cert_sha256` / `sbat` / `expected_pcr11` on a published image.
//!
//! # Test split
//!
//! This integration test drives the *real* production predicates
//! ([`SbCertsToml::accepts_signer`], [`SbCertsToml::first_below_floor`],
//! [`effective_cert_revocations`]) — the exact functions `apm`'s
//! download-time gate (`validate_image_secure_boot` in `sysroot.rs`) calls —
//! rather than any local reimplementation, plus the on-disk catalog
//! round-trip the `apr sb-certs` authoring path writes and `apm update`
//! materializes. The gate function itself is private to `sysroot.rs`; its
//! end-to-end accept/refuse and the C1 directory-pickup regression are
//! covered by unit tests inside that module (`sysroot::tests`).
//!
//! The *full signed-binary extraction* — `apr publish` deriving
//! `sb_signer_cert_sha256` from a real `sbverify`/PE cert table, `.sbat`
//! dump, and `systemd-measure` over an actual UKI, then `apm` refusing a
//! below-floor or retired-cert upgrade before reboot — is left to the fleet
//! test (`checks.fleet.secure-boot` extension), which has the signing
//! tooling and a vTPM available.

use anyhow::Result;
use tempfile::TempDir;

use aos_package::registry::sb_certs::{
    self, RevokedSbCert, SbCert, SbCertsToml, effective_cert_revocations,
};
use aos_package::types::{SbatEntry, SysrootImageEntry};

/// A db cert digest fixture (a valid 64-char lowercase hex SHA-256).
const SIGNER_ACTIVE: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
/// A second db cert digest fixture, used as the retired signer.
const SIGNER_RETIRED: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

fn sbat(pairs: &[(&str, u32)]) -> Vec<SbatEntry> {
    pairs
        .iter()
        .map(|(c, g)| SbatEntry {
            component: (*c).into(),
            generation: *g,
        })
        .collect()
}

/// Build a signed image entry as `apr publish` would record it.
fn signed_image(
    signer: &str,
    sbat_pairs: &[(&str, u32)],
    pcr11: Option<&str>,
) -> SysrootImageEntry {
    SysrootImageEntry {
        format: "raw".into(),
        store_path: "/nix/store/deadbeef-aos-image".into(),
        nar_hash: "sha256:abc".into(),
        nar_size: 4096,
        sb_signer_cert_sha256: Some(signer.into()),
        sbat: sbat(sbat_pairs),
        expected_pcr11: pcr11.map(str::to_string),
        ukis: Vec::new(),
        root_image: None,
        root_verity: None,
        root_hash: None,
        root_hash_sig: None,
    }
}

/// Evaluate `apm`'s download-time accept decision using **only** the
/// production [`SbCertsToml`] predicates (`accepts_signer` + `first_below_floor`)
/// — the same calls `validate_image_secure_boot` makes — so a regression in
/// either predicate surfaces here, not in a copy of the logic.
fn catalog_accepts(catalog: &SbCertsToml, img: &SysrootImageEntry) -> bool {
    let signer_ok = img
        .sb_signer_cert_sha256
        .as_deref()
        .is_some_and(|cert| catalog.accepts_signer(cert));
    signer_ok && catalog.first_below_floor(&img.sbat).is_none()
}

/// Phase 4 "publish records facts": a published image entry round-trips
/// through the package-TOML serde contract carrying all three SB fields,
/// and an unsigned image omits them entirely (legacy publishes still parse).
#[test]
fn published_image_roundtrips_sb_fields() -> Result<()> {
    let img = signed_image(SIGNER_ACTIVE, &[("aos", 2), ("systemd", 1)], Some("ff00ff"));
    let serialized = toml::to_string(&img)?;
    assert!(serialized.contains("sb_signer_cert_sha256"));
    assert!(serialized.contains("expected_pcr11"));
    assert!(serialized.contains("aos"));
    let parsed: SysrootImageEntry = toml::from_str(&serialized)?;
    assert_eq!(parsed.sb_signer_cert_sha256.as_deref(), Some(SIGNER_ACTIVE));
    assert_eq!(parsed.sbat, sbat(&[("aos", 2), ("systemd", 1)]));
    assert_eq!(parsed.expected_pcr11.as_deref(), Some("ff00ff"));

    // An unsigned/legacy image serializes without any SB keys and parses.
    let legacy: SysrootImageEntry = toml::from_str(
        "format = \"raw\"\nstore_path = \"/nix/store/x\"\nnar_hash = \"sha256:y\"\nnar_size = 1",
    )?;
    assert!(legacy.sb_signer_cert_sha256.is_none());
    assert!(legacy.sbat.is_empty());
    let legacy_toml = toml::to_string(&legacy)?;
    assert!(!legacy_toml.contains("sb_signer_cert_sha256"));
    Ok(())
}

/// The committed `sb-certs.toml` catalog round-trips through the loader the
/// same way `apr sb-certs` writes it and `apm update` materializes it for the
/// install-time check.
#[test]
fn sb_certs_catalog_roundtrips_on_disk() -> Result<()> {
    let tmp = TempDir::new()?;
    let catalog = SbCertsToml {
        active: vec![SbCert {
            id: "db-2026".into(),
            cert_sha256: SIGNER_ACTIVE.into(),
        }],
        sbat_floor: sbat(&[("aos", 1)]),
        ..SbCertsToml::default()
    };
    sb_certs::write_sb_certs_toml(tmp.path(), &catalog)?;
    let loaded = sb_certs::load_sb_certs_toml(tmp.path())?.expect("catalog present");
    assert_eq!(loaded, catalog);

    // Absent catalog yields None (registries that record no SB facts work).
    let empty = TempDir::new()?;
    assert!(sb_certs::load_sb_certs_toml(empty.path())?.is_none());
    Ok(())
}

/// Download-time accept: signer active and every SBAT generation at or above
/// the floor.
#[test]
fn accepts_active_signer_above_floor() {
    let catalog = SbCertsToml {
        active: vec![SbCert {
            id: "db".into(),
            cert_sha256: SIGNER_ACTIVE.into(),
        }],
        sbat_floor: sbat(&[("aos", 1)]),
        ..SbCertsToml::default()
    };
    let img = signed_image(SIGNER_ACTIVE, &[("aos", 2)], None);
    assert!(catalog_accepts(&catalog, &img));
}

/// Download-time refuse (the headline): raising the floor above the
/// published component makes `apm` refuse the upgrade before reboot.
#[test]
fn refuses_when_floor_raised_above_component() {
    let img = signed_image(SIGNER_ACTIVE, &[("aos", 1)], None);

    let at_floor = SbCertsToml {
        active: vec![SbCert {
            id: "db".into(),
            cert_sha256: SIGNER_ACTIVE.into(),
        }],
        sbat_floor: sbat(&[("aos", 1)]),
        ..SbCertsToml::default()
    };
    assert!(catalog_accepts(&at_floor, &img));

    // Signed metadata change: bump the floor to revoke generation 1.
    let raised = SbCertsToml {
        sbat_floor: sbat(&[("aos", 2)]),
        ..at_floor
    };
    assert!(!catalog_accepts(&raised, &img));
    let violation = raised.first_below_floor(&img.sbat);
    assert_eq!(violation, Some(("aos".into(), 1, 2)));
}

/// Retired-cert refuse: marking the signer cert retired makes `apm` refuse a
/// component signed by it, even when the SBAT floor is satisfied.
#[test]
fn refuses_retired_signer_cert() {
    let catalog = SbCertsToml {
        active: vec![
            SbCert {
                id: "db-2026".into(),
                cert_sha256: SIGNER_ACTIVE.into(),
            },
            SbCert {
                id: "db-2024".into(),
                cert_sha256: SIGNER_RETIRED.into(),
            },
        ],
        revoked: vec![RevokedSbCert {
            id: "db-2024".into(),
            reason: Some("compromised".into()),
        }],
        sbat_floor: sbat(&[("aos", 1)]),
        ..SbCertsToml::default()
    };

    let retired = signed_image(SIGNER_RETIRED, &[("aos", 5)], None);
    assert!(!catalog_accepts(&catalog, &retired));

    let active = signed_image(SIGNER_ACTIVE, &[("aos", 5)], None);
    assert!(catalog_accepts(&catalog, &active));

    // The retirement is only effective when vouched for by a surviving cert.
    assert_eq!(
        effective_cert_revocations(&catalog, "db-2026"),
        vec!["db-2024"]
    );
    assert!(effective_cert_revocations(&catalog, "db-2024").is_empty());
}

/// An unknown signer (never in the active set) is refused even with no
/// revocations and a satisfied floor.
#[test]
fn refuses_unknown_signer() {
    let catalog = SbCertsToml {
        active: vec![SbCert {
            id: "db".into(),
            cert_sha256: SIGNER_ACTIVE.into(),
        }],
        ..SbCertsToml::default()
    };
    let img = signed_image(SIGNER_RETIRED, &[("aos", 9)], None);
    assert!(!catalog_accepts(&catalog, &img));
}
