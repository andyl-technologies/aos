//! Selects trusted Cloudflare delivery ingress from deployment configuration.
//!
//! `HUB_LAYER7_DELIVERY_HOSTS` lists comma-separated DNS hostnames served through
//! a Layer 7 delivery endpoint. Selection uses the edge-verified request URL;
//! request headers cannot opt a caller into another ingress kind.

use url::{Host, Url};

/// Selects the ingress kind for an edge-verified request URL.
///
/// # Errors
///
/// Returns an error when configured entries are not bare DNS hostnames.
pub(crate) fn ingress_kind(
    verified_url: &Url,
    configured_hosts: Option<&str>,
) -> Result<&'static str, &'static str> {
    let Some(configured_hosts) = configured_hosts else {
        return Ok("hub");
    };

    let mut matched = false;
    for hostname in configured_hosts.split(',').map(str::trim) {
        if hostname.is_empty() {
            continue;
        }

        let hostname = hostname.trim_end_matches('.');
        let valid_hostname = hostname.parse::<std::net::IpAddr>().is_err()
            && hostname.len() <= 253
            && hostname.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            });
        if !valid_hostname {
            return Err("HUB_LAYER7_DELIVERY_HOSTS must contain bare DNS hostnames");
        }

        // IP literals and non-TLS requests retain ordinary Hub ingress. The
        // shared router still binds the exact authority, port, and endpoint.
        if let Some(Host::Domain(request_host)) = verified_url.host() {
            matched |= request_host
                .trim_end_matches('.')
                .eq_ignore_ascii_case(hostname);
        }
    }

    Ok(if matched && verified_url.scheme() == "https" {
        "layer7"
    } else {
        "hub"
    })
}

#[cfg(test)]
mod tests {
    use super::ingress_kind;
    use url::Url;

    #[test]
    fn configured_delivery_hosts_use_layer7_ingress() {
        let url = Url::parse("https://cdn.example.test/v2/").unwrap();

        assert_eq!(
            ingress_kind(&url, Some("other.example.test, CDN.EXAMPLE.TEST.")),
            Ok("layer7")
        );
        assert_eq!(ingress_kind(&url, None), Ok("hub"));
    }

    #[test]
    fn other_authorities_and_non_tls_requests_keep_hub_ingress() {
        for address in [
            "https://hub.example.test/v2/",
            "https://cdn.example.test.other.test/v2/",
            "http://cdn.example.test/v2/",
            "https://192.0.2.1/v2/",
        ] {
            let url = Url::parse(address).unwrap();

            assert_eq!(ingress_kind(&url, Some("cdn.example.test")), Ok("hub"));
        }
    }

    #[test]
    fn malformed_deployment_hostnames_fail_closed() {
        let url = Url::parse("https://cdn.example.test/v2/").unwrap();
        for configuration in [
            "https://cdn.example.test",
            "cdn.example.test/path",
            "cdn.example.test:443",
            "*.example.test",
            "192.0.2.1",
            "cdn..example.test",
            "cdn.example.test, invalid/path",
        ] {
            assert!(ingress_kind(&url, Some(configuration)).is_err());
        }
    }
}
