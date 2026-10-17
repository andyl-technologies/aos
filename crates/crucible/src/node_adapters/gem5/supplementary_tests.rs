//! Mapping-data adversarial checks; no test issues capture or native authority.

use super::*;

fn original_roster() -> Vec<(&'static str, &'static str)> {
    vec![
        ("image", "image/ckpt_owner.dmtcp"),
        ("image", "image/ckpt_owner_files/stats.txt_17"),
        ("image", "image/ckpt_owner_files/guest.elf_19"),
        ("resource", "resource/output/stats.txt"),
    ]
}

#[test]
fn absent_source_namespace_is_inert_mapping_data() {
    assert_eq!(
        validate_supplementary_root(
            "/absent/original/native-images/ckpt_owner_files",
            original_roster().into_iter(),
        ),
        Ok(())
    );
}

#[test]
fn another_checkpoint_root_or_missing_checkpoint_is_not_guessed() {
    assert!(
        validate_supplementary_root(
            "/original/native-images/foreign_files",
            original_roster().into_iter(),
        )
        .is_err()
    );
    assert!(
        validate_supplementary_root(
            "/original/native-images/ckpt_owner_files",
            original_roster().into_iter().skip(1),
        )
        .is_err()
    );
}

#[test]
fn omitted_or_multiple_supplementary_roots_are_refused() {
    let mut roster = original_roster();
    roster.push(("image", "image/foreign_files/payload"));
    assert!(
        validate_supplementary_root(
            "/original/native-images/ckpt_owner_files",
            roster.into_iter(),
        )
        .is_err()
    );
    assert!(
        validate_supplementary_root(
            "/original/native-images/ckpt_owner_files",
            [("image", "image/ckpt_owner.dmtcp")].into_iter(),
        )
        .is_err()
    );
}

#[test]
fn noncanonical_original_root_and_artifact_names_are_refused() {
    for root in [
        "relative/ckpt_owner_files",
        "/original//ckpt_owner_files",
        "/original/./ckpt_owner_files",
        "/original/../ckpt_owner_files",
        "/original/ckpt_owner_files/",
        "/original/ckpt_owner_files\0",
    ] {
        assert!(validate_supplementary_root(root, original_roster().into_iter()).is_err());
    }
    let roster = [
        ("image", "image/ckpt_owner.dmtcp"),
        ("image", "image/ckpt_owner_files/../outside"),
    ];
    assert!(
        validate_supplementary_root(
            "/original/native-images/ckpt_owner_files",
            roster.into_iter(),
        )
        .is_err()
    );
}
