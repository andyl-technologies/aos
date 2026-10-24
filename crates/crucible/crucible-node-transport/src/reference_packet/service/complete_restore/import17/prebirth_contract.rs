//! Names the distinct fresh17 prebirth namespace and process-protocol edition.
//!
//! ```text
//! wrapper = 9; private prefix magic = CNPNI17 NUL
//! mapping nonce domain = source-owned.packet-native-import-mapping-nonce/17
//! ```
//!
//! These constants create no Source lease, phase allocation, native installation
//! or grant. A completed actual producer and private Source-MAC verifier must
//! independently bind the same complete recipe before emitting/accepting it.
//! Wrapper8 and the old native17 prefix568 remain separate closed grammars.

/// Names the private Source-Birth derivation of the original new17 mapping nonce.
///
/// The genuine unstarted Source Birth derives it internally and retains that
/// one original generation. Later Window binding must not renew or reissue it.
pub const NATIVE_IMPORT17_MAPPING_NONCE_DOMAIN: &str =
    "source-owned.packet-native-import-mapping-nonce/17";

/// Selects the distinct complete import17 startup wrapper instead of wrapper8.
pub const NATIVE_IMPORT17_STARTUP_WRAPPER_VERSION: u64 = 9;

/// Selects the distinct import17 private prefix without widening old prefix17.
///
/// This is an explicit eight-byte process-protocol value, never a Rust layout.
/// Its complete framing is defined by the paired recipe writer/strict reader.
pub const NATIVE_IMPORT17_PRIVATE_PREFIX_MAGIC: [u8; 8] = *b"CNPNI17\0";

/// Names the separate derived-key domain authenticating the complete new prefix.
pub const NATIVE_IMPORT17_PRIVATE_PREFIX_DOMAIN: &str =
    "source-owned.packet-native-import-private-startup/17";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_new_prefix_and_domains_leave_prior_editions_distinct() {
        assert_eq!(NATIVE_IMPORT17_STARTUP_WRAPPER_VERSION, 9);
        assert_eq!(NATIVE_IMPORT17_PRIVATE_PREFIX_MAGIC, *b"CNPNI17\0");
        assert_ne!(NATIVE_IMPORT17_PRIVATE_PREFIX_MAGIC, *b"CNPNS17\0");
        assert_ne!(
            NATIVE_IMPORT17_MAPPING_NONCE_DOMAIN,
            NATIVE_IMPORT17_PRIVATE_PREFIX_DOMAIN
        );
        assert!(NATIVE_IMPORT17_MAPPING_NONCE_DOMAIN.ends_with("/17"));
        assert!(NATIVE_IMPORT17_PRIVATE_PREFIX_DOMAIN.ends_with("/17"));
    }
}
