//! UNRUN private format vectors; no genuine fixed archive/custody fixture is fabricated.

use super::*;

#[test]
fn deployment_identity_commits_whole_public_image_not_only_existing_d() {
    let mut first = header(DEPLOYMENT_MAGIC);
    first.extend_from_slice(&[1; 32]);
    first.extend_from_slice(&[2; 32]);
    first.extend_from_slice(b"actual public image bytes");
    let mut changed = first.clone();
    changed[80] ^= 1;

    assert_eq!(&first[16..48], &changed[16..48]);
    assert_ne!(identity(b"aos.source.original.deployment-image.v5\0", &first),
        identity(b"aos.source.original.deployment-image.v5\0", &changed));
    assert_ne!(identity(b"aos.source.original.deployment-image.v5\0", &first),
        identity(b"aos.source.original.origin-envelope.v5\0", &first));
}

#[test]
fn archive_sections_refuse_truncation_trailing_bytes_and_changed_reserved_header() {
    let mut bytes = header(CUT_MAGIC);
    bytes.resize(CUT_HEADER, 0);
    bytes[384..388].copy_from_slice(&3_u32.to_be_bytes());
    bytes.extend_from_slice(&[1, 2, 3]);

    require_header(&bytes, CUT_MAGIC, CUT_HEADER).unwrap();
    assert_eq!(sections(&bytes, CUT_HEADER, 384, 1).unwrap(), vec![&[1, 2, 3][..]]);
    assert!(sections(&bytes[..bytes.len() - 1], CUT_HEADER, 384, 1).is_err());
    let mut trailing = bytes.clone();
    trailing.push(4);
    assert!(sections(&trailing, CUT_HEADER, 384, 1).is_err());
    bytes[10] = 1;
    assert!(require_header(&bytes, CUT_MAGIC, CUT_HEADER).is_err());
}

#[test]
fn cut_reference_requires_exact_inode_ordered_digest_and_preappend_boundary() {
    let mut bytes = header(CUT_MAGIC);
    for value in [1_u64, 2, 3, 4] { bytes.extend_from_slice(&value.to_be_bytes()); }
    bytes.extend_from_slice(&[5; 16]);
    bytes.extend_from_slice(&[6; 32]);
    bytes.resize(CUT_HEADER, 0);

    require_cut_subject(&bytes, (1, 2), ([5; 16], [6; 32]), (3, 4)).unwrap();
    for (inode, digest, sequence, offset) in [(9, 6, 3, 4), (2, 9, 3, 4), (2, 6, 9, 4), (2, 6, 3, 9)] {
        assert!(require_cut_subject(&bytes, (1, inode), ([5; 16], [digest; 32]), (sequence, offset)).is_err());
    }
    assert!(require_cut_subject(&bytes[..90], (1, 2), ([5; 16], [6; 32]), (3, 4)).is_err());
}

#[test]
fn names_are_domain_separated_generated_components_not_caller_paths() {
    let digest = ObjectDigest::from_bytes([7; 32]);
    let deployment = filename(b'e', digest);
    let origin = filename(b'o', digest);
    let cut = cut_filename((1, 2), [3; 16], [4; 32]);

    assert_eq!(deployment.len(), 66);
    assert_eq!(origin.len(), 66);
    assert_eq!(cut.len(), 66);
    assert_ne!(deployment, origin);
    assert!(!cut.contains('/'));
    assert_ne!(cut, cut_filename((1, 9), [3; 16], [4; 32]));
}
