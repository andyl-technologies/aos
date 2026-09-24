//! Portable endpoint grammar for public OpenSSH attach routes.
//!
//! Host validates deployment trust and protected routes before gate readback;
//! Controller validates the same endpoint before issuing a certificate. Both
//! must accept the same host and login names.

use std::net::IpAddr;

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
