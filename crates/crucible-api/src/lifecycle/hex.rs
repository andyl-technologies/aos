//! Canonical lowercase hexadecimal material for lifecycle identities.

pub(super) fn optional_hex_string(value: Option<&str>) -> String {
    value.map_or_else(|| String::from("none"), hex_string)
}

pub(super) fn hex_string(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
