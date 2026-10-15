//! Preserves linear first-read semantics and separation between observed images.

use super::PhysicalReads;
use std::path::Path;

#[test]
fn indexed_lookup_matches_linear_first_read_selection() {
    let entries = [
        (
            Path::new("control/publication/commits/0"),
            Some(&b"first"[..]),
        ),
        (
            Path::new("control/publication/commits/0"),
            Some(&b"later"[..]),
        ),
        (Path::new("control/publication/commits/1"), None),
        (
            Path::new("control/publication/commits/1"),
            Some(&b"late"[..]),
        ),
        (Path::new("control/publication/commits/2"), Some(&b""[..])),
        (
            Path::new("other/publication/commits/3"),
            Some(&b"other"[..]),
        ),
    ];
    let physical = PhysicalReads::from_entries(entries);
    let control = Path::new("control");

    for revision in 0..=3 {
        let key = format!("publication/commits/{revision}");
        let expected = entries
            .iter()
            .find(|(path, _)| *path == control.join(&key))
            .and_then(|(_, bytes)| *bytes);
        let actual = physical.bytes(control, &key);

        assert_eq!(actual.as_ref().ok().copied(), expected, "{key}");
        assert_eq!(actual.is_err(), expected.is_none(), "{key}");
    }
}

#[test]
fn indexed_lookup_preserves_path_component_equality() {
    let entries = [
        (
            Path::new("control/./publication//commits/0"),
            Some(&b"first"[..]),
        ),
        (
            Path::new("control/publication/commits/0"),
            Some(&b"later"[..]),
        ),
    ];
    let physical = PhysicalReads::from_entries(entries);

    assert_eq!(
        physical
            .bytes(Path::new("control"), "publication/commits/0")
            .ok(),
        Some(&b"first"[..]),
    );
}

#[test]
fn separate_images_keep_their_own_changed_bytes_and_absence() {
    let path = Path::new("control/publication/commits/0");
    let first = PhysicalReads::from_entries([(path, Some(&b"original"[..]))]);
    let changed = PhysicalReads::from_entries([(path, Some(&b"changed"[..]))]);
    let absent = PhysicalReads::from_entries([(path, None)]);
    let missing = PhysicalReads::from_entries([]);
    let control = Path::new("control");
    let key = "publication/commits/0";

    assert_eq!(first.bytes(control, key).ok(), Some(&b"original"[..]));
    assert_eq!(changed.bytes(control, key).ok(), Some(&b"changed"[..]));
    assert!(absent.bytes(control, key).is_err());
    assert!(missing.bytes(control, key).is_err());
}
