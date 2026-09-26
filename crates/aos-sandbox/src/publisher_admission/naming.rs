//! Canonical private and final basenames for sealed publisher artifacts.

use std::ffi::OsStr;

use aos_sandbox_core::ObjectDescriptor;
use aos_sandbox_linux::immutable_file::{InvalidPublicationName, PublicationName};

pub(super) fn published_name_for_object(
    object: &ObjectDescriptor,
) -> Result<PublicationName, InvalidPublicationName> {
    let name = format!("sha256-{}", hex(object.digest().as_bytes()));
    PublicationName::new(OsStr::new(&name))
}

pub(super) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}
