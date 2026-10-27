//! Portable endpoint grammar for public OpenSSH attach routes.
//!
//! Host validates deployment trust and protected routes before gate readback;
//! Controller validates the same endpoint before issuing a certificate. Both
//! must accept the same host and login names.

use std::net::IpAddr;

/// Names the fixed executable for the v1 public attach certificate profile.
pub const PUBLIC_ATTACH_GATE_PATH_V1: &str = "/usr/libexec/aos-sandbox-exec-gate";

/// Names the only certificate algorithm accepted by the v1 attach gate.
pub const PUBLIC_ATTACH_CERTIFICATE_TYPE_V1: &str = "ssh-ed25519-cert-v01@openssh.com";

/// Bounds the original v1 attach certificate lifetime without permitting renewal.
pub const PUBLIC_ATTACH_CERTIFICATE_MAXIMUM_SECONDS_V1: u32 = 300;

/// Formats the byte-stable identity of an issued v1 attach certificate.
///
/// Formatting is non-authorizing. Callers validate the identities against
/// their protected admission or route before issuing or checking a certificate.
#[must_use]
pub fn public_attach_certificate_key_id_v1(
    operation: &[u8],
    execution: &[u8],
    incarnation: &[u8],
    principal: &[u8],
    audit: &[u8],
) -> String {
    format!(
        "aos-exec:{}:{}:{}:{}:{}",
        hex_id(operation),
        hex_id(execution),
        hex_id(incarnation),
        hex_id(principal),
        hex_id(audit),
    )
}

/// Formats the byte-stable forced command of an issued v1 attach certificate.
///
/// The fixed executable and argument order match the original certificate
/// profile. This function neither authorizes an attach nor validates a route.
#[must_use]
pub fn public_attach_force_command_v1(
    operation: &[u8],
    execution: &[u8],
    incarnation: &[u8],
    assignment_epoch: u64,
    principal: &[u8],
    audit: &[u8],
) -> String {
    format!(
        "{PUBLIC_ATTACH_GATE_PATH_V1} --operation-id {} --execution-id {} --incarnation-id {} --assignment-epoch {} --principal-id {} --audit-id {}",
        hex_id(operation),
        hex_id(execution),
        hex_id(incarnation),
        assignment_epoch,
        hex_id(principal),
        hex_id(audit),
    )
}

fn hex_id(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

/// Returns whether a public attach host is a parsed IP address or DNS-like name.
#[must_use]
pub fn valid_public_attach_host_v1(host: &str) -> bool {
    let dns_valid = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'));
    host.parse::<IpAddr>().is_ok() || dns_valid
}

/// Returns whether a public attach login is a bounded, non-option-like name.
#[must_use]
pub fn valid_public_attach_user_v1(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 32
        && user.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || byte == b'_' || (index != 0 && byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_identity_preserves_original_v1_bytes() {
        assert_eq!(
            public_attach_certificate_key_id_v1(&[1; 16], &[2; 16], &[3; 16], &[4; 16], &[5; 16]),
            "aos-exec:01010101010101010101010101010101:02020202020202020202020202020202:03030303030303030303030303030303:04040404040404040404040404040404:05050505050505050505050505050505",
        );
        assert_eq!(
            public_attach_force_command_v1(&[1; 16], &[2; 16], &[3; 16], 17, &[4; 16], &[5; 16]),
            "/usr/libexec/aos-sandbox-exec-gate --operation-id 01010101010101010101010101010101 --execution-id 02020202020202020202020202020202 --incarnation-id 03030303030303030303030303030303 --assignment-epoch 17 --principal-id 04040404040404040404040404040404 --audit-id 05050505050505050505050505050505",
        );
    }

    #[test]
    fn attach_host_accepts_dns_and_ip_but_rejects_non_ip_colons_and_brackets() {
        for host in ["guest.example", "127.0.0.1", "2001:db8::1"] {
            assert!(valid_public_attach_host_v1(host), "{host}");
        }
        for host in ["", "-guest", "guest:port", "[2001:db8::1]", "a/b"] {
            assert!(!valid_public_attach_host_v1(host), "{host}");
        }
        assert!(!valid_public_attach_host_v1(&"a".repeat(254)));
    }

    #[test]
    fn attach_user_rejects_leading_hyphen_and_noncanonical_characters() {
        for user in ["aos_exec", "aos-exec", "_service"] {
            assert!(valid_public_attach_user_v1(user), "{user}");
        }
        for user in ["", "-service", "service.name", "service:name"] {
            assert!(!valid_public_attach_user_v1(user), "{user}");
        }
        assert!(!valid_public_attach_user_v1(&"a".repeat(33)));
    }
}
