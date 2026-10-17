//! Early public denial of reserved private-stage and qualification namespaces.
//!
//! Classification happens before origin forwarding or object-store dispatch.
//! Internal authenticated work routes do not contain these reserved segments.

/// Recognizes reserved segments, including percent-encoded separators and names.
pub(crate) fn contains_private_namespace(path: &str) -> bool {
    let mut bytes = path.as_bytes().to_vec();
    for _ in 0..=4 {
        if bytes.split(|byte| *byte == b'/').any(|segment| {
            segment == b".aos-direct-upload"
                || segment == b".aos-direct-qualification"
                || segment == b".aos-mirror-qualification"
                || segment == b".aos-mirror-query"
        }) {
            return true;
        }
        let mut decoded = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'%' && index + 2 < bytes.len() {
                if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                    decoded.push(high * 16 + low);
                    index += 3;
                    continue;
                }
            }
            decoded.push(bytes[index]);
            index += 1;
        }
        if decoded == bytes {
            break;
        }
        bytes = decoded;
    }
    false
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_canonical_and_encoded_reserved_segments() {
        for path in [
            "/.aos-direct-upload/source",
            "/org/.aos-direct-qualification/run",
            "/org/%2eaos-direct-upload/source",
            "/org%2f.aos-direct-upload%2fsource",
            "/%252eaos-direct-qualification/run",
            "/.aos-mirror-qualification/run/final/object",
            "/%252eaos-mirror-qualification/run/final/object",
            "/org/.aos-mirror-query/cache",
            "/%252eaos-mirror-query/cache",
        ] {
            assert!(contains_private_namespace(path), "{path}");
        }
    }

    #[test]
    fn authenticated_controls_and_legitimate_public_routes_remain_reachable() {
        for path in [
            "/_internal/storage/direct-upload-sdk-conformance",
            "/_internal/storage/direct-upload-qualification",
            "/org/packages/file.nar",
            "/org/aos-direct-upload/file",
            "/org/.aos-direct-upload-not-private/file",
        ] {
            assert!(!contains_private_namespace(path), "{path}");
        }
    }
}
