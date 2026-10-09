//! Shared canonical text grammars for retained-control adapters and clients.

/// Returns whether a value is a canonical lowercase slug.
#[must_use]
pub fn is_slug(value: &str, maximum_len: usize) -> bool {
    if value.is_empty() || value.len() > maximum_len {
        return false;
    }
    canonical_component(value, false)
}

/// Returns whether a value is a canonical lowercase ASCII DNS name.
#[must_use]
pub fn is_dns_name(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 253
        || value.trim() != value
        || value.ends_with('.')
        || !value.contains('.')
    {
        return false;
    }
    matches!(url::Host::parse(value), Ok(url::Host::Domain(domain)) if domain == value)
}

/// Returns whether a value is a canonical permission verb.
#[must_use]
pub fn is_permission(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase()
        || (!bytes[bytes.len() - 1].is_ascii_lowercase()
            && !bytes[bytes.len() - 1].is_ascii_digit())
    {
        return false;
    }
    let mut separator = false;
    for byte in bytes {
        let current_separator = matches!(*byte, b'.' | b'_' | b'-');
        if !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && !current_separator {
            return false;
        }
        if separator && current_separator {
            return false;
        }
        separator = current_separator;
    }
    true
}

fn canonical_component(value: &str, allow_underscore: bool) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || !bytes[0].is_ascii_lowercase()
        || (!bytes[bytes.len() - 1].is_ascii_lowercase()
            && !bytes[bytes.len() - 1].is_ascii_digit())
    {
        return false;
    }
    let mut separator = false;
    for byte in bytes {
        let current_separator = *byte == b'-' || (allow_underscore && *byte == b'_');
        if !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && !current_separator {
            return false;
        }
        if separator && current_separator {
            return false;
        }
        separator = current_separator;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_grammars_reject_ambiguous_or_non_ascii_values() {
        assert!(is_slug("release-cache", 64));
        assert!(!is_slug("Release_Cache", 64));
        assert!(is_dns_name("cache.example.test"));
        assert!(!is_dns_name("127.0.0.1"));
        assert!(is_dns_name("xn--bcher-kva.example"));
        assert!(!is_dns_name("bücher.example"));
        assert!(is_permission("registry.publish"));
        assert!(!is_permission("registry..publish"));
    }
}
