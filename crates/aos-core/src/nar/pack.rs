use sha2::{Digest, Sha256};

/// A store path to be included in an upload pack.
pub struct PackPath {
    /// 32-character hex store hash (e.g. the hash portion of a Nix store path).
    pub hash: String,
    /// NAR export data for this path.
    pub nar_data: Vec<u8>,
}

/// Create a pack from a list of paths.
///
/// Wire format:
/// - `AOSP` magic (4 bytes)
/// - version: `1` as big-endian u32 (4 bytes)
/// - entry count as big-endian u32 (4 bytes)
/// - for each entry:
///   - hash as raw ASCII bytes (32 bytes)
///   - NAR data length as big-endian u64 (8 bytes)
///   - NAR data (variable)
/// - SHA-256 digest of everything above (32 bytes)
pub fn create_pack(paths: &[PackPath]) -> Vec<u8> {
    let mut buf = Vec::new();

    // Header.
    buf.extend_from_slice(b"AOSP");
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&(paths.len() as u32).to_be_bytes());

    // Entries.
    for p in paths {
        buf.extend_from_slice(p.hash.as_bytes());
        buf.extend_from_slice(&(p.nar_data.len() as u64).to_be_bytes());
        buf.extend_from_slice(&p.nar_data);
    }

    // SHA-256 trailer.
    let hash = Sha256::digest(&buf);
    buf.extend_from_slice(&hash);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_round_trip_header() {
        let paths = vec![
            PackPath {
                hash: "0123456789abcdef0123456789abcdef".to_string(),
                nar_data: vec![0xDE, 0xAD],
            },
        ];

        let pack = create_pack(&paths);

        // Magic.
        assert_eq!(&pack[0..4], b"AOSP");
        // Version.
        assert_eq!(&pack[4..8], &1u32.to_be_bytes());
        // Count.
        assert_eq!(&pack[8..12], &1u32.to_be_bytes());
        // Hash (32 bytes).
        assert_eq!(&pack[12..44], b"0123456789abcdef0123456789abcdef");
        // NAR length.
        assert_eq!(&pack[44..52], &2u64.to_be_bytes());
        // NAR data.
        assert_eq!(&pack[52..54], &[0xDE, 0xAD]);
        // Trailing SHA-256 (32 bytes).
        assert_eq!(pack.len(), 54 + 32);

        let expected_hash = Sha256::digest(&pack[..54]);
        assert_eq!(&pack[54..], expected_hash.as_slice());
    }

    #[test]
    fn empty_pack() {
        let pack = create_pack(&[]);
        // Magic(4) + version(4) + count(4) + sha256(32) = 44
        assert_eq!(pack.len(), 44);
        assert_eq!(&pack[8..12], &0u32.to_be_bytes());
    }
}
