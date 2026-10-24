//! Fixed-size ASCII material for the scalar shared event-log prefix fold.
//!
//! Two 64-byte hexadecimal digests, two decimal u64 values and fixed labels
//! fit within 256 stack bytes. This preserves the semantic material hash without
//! heap formatting, temporary strings or an additional origin allocation.

use super::*;

pub(crate) fn prefix_after_append(
    previous: ContentHash,
    appended: ContentHash,
    bytes: u64,
    events: u64,
) -> ContentHash {
    let mut material = PrefixMaterial {
        bytes: [0; 256],
        length: 0,
    };
    material.text(b"previous_prefix=");
    material.hash(previous);
    material.text(b"\nappended_segment=");
    material.hash(appended);
    material.text(b"\nbytes=");
    material.decimal(bytes);
    material.text(b"\nevents=");
    material.decimal(events);
    crate::model::content_hash_from_canonical_material_bytes(
        "crucible.scheduler.event-log.prefix.v2",
        &material.bytes[..material.length],
    )
}

struct PrefixMaterial {
    bytes: [u8; 256],
    length: usize,
}

impl PrefixMaterial {
    fn text(&mut self, bytes: &[u8]) {
        self.bytes[self.length..self.length + bytes.len()].copy_from_slice(bytes);
        self.length += bytes.len();
    }

    fn hash(&mut self, hash: ContentHash) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in hash.bytes {
            self.text(&[HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]]);
        }
    }

    fn decimal(&mut self, mut value: u64) {
        let mut digits = [0; 20];
        let mut first = digits.len();
        loop {
            first -= 1;
            digits[first] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.text(&digits[first..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_prefix_material_matches_original_format_at_integer_extremes() {
        let previous = ContentHash { bytes: [0; 32] };
        let appended = ContentHash { bytes: [255; 32] };
        for bytes in [0, 1, u64::MAX] {
            for events in [0, 1, u64::MAX] {
                let material = format!(
                    "previous_prefix={}\nappended_segment={}\nbytes={bytes}\nevents={events}",
                    previous.to_hex(),
                    appended.to_hex()
                );
                assert_eq!(
                    prefix_after_append(previous, appended, bytes, events),
                    ContentHash::from_canonical_material(
                        "crucible.scheduler.event-log.prefix.v2",
                        &material
                    )
                );
            }
        }
    }
}
