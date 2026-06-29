//! Engine-neutral URL/path SSRF guards shared by the native hub and the Worker.
//!
//! These are the pure, IO-free halves of the hub's outbound-fetch hardening:
//! the global-address predicate ([`is_global_ip`]), the network-origin URL
//! check ([`is_safe_remote_url`]), the HTTP surface-path validator
//! ([`validate_http_surface_path`]), and the filesystem-join traversal guard
//! ([`safe_join`]). They contain no DNS resolution, no filesystem access, and
//! no environment reads, so they compile to `wasm32-unknown-unknown` and run
//! identically on the Cloudflare Worker (RFC-0004 Phase 5).
//!
//! The native hub layers the IO-bound parts on top in its `fetch` module: a
//! write-time DNS pre-check and a connect-time validating resolver around
//! [`is_safe_remote_url`], and symlink-escape canonicalization around
//! [`safe_join`]. On the Worker those IO-bound parts are supplied by the
//! Cloudflare platform's egress policy. The scheme and literal-IP rejections
//! here run on every target regardless of deployment.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};

/// Marker error for transport-level surface fetch failures.
///
/// All transport failures — reqwest errors, non-404 HTTP statuses, local
/// IO errors other than `NotFound`, symlink escapes — are wrapped in this
/// type (with the detail preserved in the message) so callers can
/// classify them through `anyhow` context chains via [`is_fetch_error`].
#[derive(Debug, thiserror::Error)]
#[error("surface fetch failed: {0}")]
pub struct FetchError(pub String);

/// Whether any error in `err`'s chain is a transport-level [`FetchError`].
///
/// Walks the full `anyhow` context chain, so classification survives any
/// number of `.context(…)` layers added by callers.
#[must_use]
pub fn is_fetch_error(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.downcast_ref::<FetchError>().is_some())
}

/// Wraps a message as a transport-level fetch failure.
#[must_use]
pub fn fetch_err(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(FetchError(message.into()))
}

/// Parses `raw` and requires an `http`/`https` scheme, returning the URL.
///
/// This is the scheme half of [`is_safe_remote_url`], exposed separately so the
/// native hub can enforce the scheme even on the debug-only path that relaxes
/// the local/internal address rejection.
///
/// # Errors
///
/// Returns a [`FetchError`] when `raw` is not a valid URL or its scheme is not
/// `http(s)`.
pub fn require_http_scheme(raw: &str) -> Result<url::Url> {
    let url = url::Url::parse(raw).map_err(|err| {
        fetch_err(format!(
            "mirror/frontend URL '{raw}' is not a valid URL: {err}"
        ))
    })?;
    match url.scheme() {
        "http" | "https" => Ok(url),
        other => Err(fetch_err(format!(
            "mirror/frontend URL '{raw}' uses unsupported scheme '{other}' \
             (a network origin must be http(s)://)"
        ))),
    }
}

/// Reject a network-origin URL that is non-HTTP or a local/internal literal IP.
///
/// This is the **pure** SSRF pre-check: it enforces an `http(s)://` scheme and,
/// when the host is an IP literal, rejects loopback, link-local (cloud
/// metadata), private/unique-local, unspecified, and documentation/benchmarking
/// ranges via [`is_global_ip`]. A *hostname* host is accepted here because
/// resolving it requires DNS, which this IO-free function does not perform:
///
/// - the native hub wraps this with a write-time DNS pre-check and a
///   connect-time validating resolver (closing the DNS-rebinding TOCTOU), and
/// - the Cloudflare Worker relies on the platform's egress policy.
///
/// The scheme and literal-IP rejections run identically on every target.
///
/// # Errors
///
/// Returns a [`FetchError`] when the scheme is not `http(s)`, the URL has no
/// host, or a literal-IP host is local/internal.
/// Whether the SSRF local/internal-address guard is relaxed by the
/// `AOS_HUB_ALLOW_LOCAL_REMOTES` dev/test escape hatch.
///
/// Honored **only in debug builds** — compiled out of release entirely, so a
/// production hub binary and the release Worker never relax the guard — and only
/// when the variable is set to a truthy value (`1`/`true`/`yes`/`on`).
/// Integration tests stand up upstream servers on `127.0.0.1`; this lets them
/// register a local mirror/frontend/webhook URL while a release build always
/// keeps the guard. The non-`http(s)` scheme rejection is never relaxed.
#[must_use]
pub fn allow_local_remotes() -> bool {
    // Compiled out entirely in release: a production binary never honors the
    // hatch no matter what is in the environment.
    if !cfg!(debug_assertions) {
        return false;
    }
    match std::env::var("AOS_HUB_ALLOW_LOCAL_REMOTES") {
        Ok(value) => {
            let value = value.trim();
            let on = matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
            if on {
                // Loud, one-time breadcrumb: this should only ever appear in
                // test/dev logs, never in production (where it is unreachable).
                static WARNED: std::sync::Once = std::sync::Once::new();
                WARNED.call_once(|| {
                    eprintln!(
                        "aos-hub-core: SSRF local-remote guard RELAXED via \
                         AOS_HUB_ALLOW_LOCAL_REMOTES (debug build only)"
                    );
                });
            }
            on
        }
        Err(_) => false,
    }
}

pub fn is_safe_remote_url(raw: &str) -> Result<()> {
    let url = require_http_scheme(raw)?;
    // The dev/test escape hatch relaxes the local/internal rejection (the scheme
    // rejection above always applies). Honored only in debug builds.
    if allow_local_remotes() {
        return Ok(());
    }
    // `url::Host` classifies the host precisely: an IPv6 literal serializes with
    // brackets through `host_str()` (so a bare `parse::<IpAddr>()` would miss
    // it), but `Host::Ipv6` hands back the parsed address directly. A literal IP
    // host is checked here; a domain name cannot be resolved without DNS, so it
    // is accepted (the native hub's resolver / the Worker's egress policy
    // enforce the address check for names at connect time).
    match url.host() {
        Some(url::Host::Ipv4(v4)) => {
            let ip = IpAddr::V4(v4);
            if !is_global_ip(ip) {
                return Err(fetch_err(format!(
                    "mirror/frontend URL '{raw}' resolves to a local/internal address {ip}"
                )));
            }
        }
        Some(url::Host::Ipv6(v6)) => {
            let ip = IpAddr::V6(v6);
            if !is_global_ip(ip) {
                return Err(fetch_err(format!(
                    "mirror/frontend URL '{raw}' resolves to a local/internal address {ip}"
                )));
            }
        }
        Some(url::Host::Domain(_)) => {}
        None => {
            return Err(fetch_err(format!(
                "mirror/frontend URL '{raw}' has no host"
            )));
        }
    }
    Ok(())
}

/// Whether `ip` is a globally routable address (not local/internal).
///
/// Rejects loopback, link-local, private/unique-local, unspecified, and broadcast
/// ranges for both IPv4 and IPv6 (including IPv4-mapped IPv6). The std-stable
/// predicates are combined manually because `Ipv6Addr::is_unique_local` and
/// related helpers are not yet stable.
#[must_use]
pub fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_ipv4(v4),
        IpAddr::V6(v6) => {
            // Unwrap IPv4-mapped/compatible IPv6 to apply the IPv4 rules.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_global_ipv4(mapped);
            }
            if let Some(compat) = v6.to_ipv4() {
                return is_global_ipv4(compat);
            }
            is_global_ipv6(v6)
        }
    }
}

/// Whether an IPv4 address is globally routable (not local/internal).
///
/// Rejects every IANA special-purpose range that is not globally reachable.
/// The `is_shared`/`is_benchmarking`/`is_documentation` std helpers are still
/// unstable (feature `ip`), so the shared-address, benchmarking, protocol-
/// assignment, and documentation ranges are matched explicitly.
#[must_use]
pub fn is_global_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    // 100.64.0.0/10 — RFC 6598 carrier-grade NAT shared address space.
    let is_cgnat = o[0] == 100 && (o[1] & 0xc0) == 64;
    // 192.0.0.0/24 — RFC 6890 IETF protocol assignments.
    let is_protocol = o[0] == 192 && o[1] == 0 && o[2] == 0;
    // 198.18.0.0/15 — RFC 2544 benchmarking.
    let is_benchmarking = o[0] == 198 && (o[1] & 0xfe) == 18;
    // Documentation ranges (RFC 5737): 192.0.2.0/24 (TEST-NET-1),
    // 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3).
    let is_documentation = (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113);
    !(v4.is_loopback()           // 127.0.0.0/8
        || v4.is_private()        // 10/8, 172.16/12, 192.168/16
        || v4.is_link_local()     // 169.254.0.0/16 (cloud metadata)
        || v4.is_unspecified()    // 0.0.0.0
        || v4.is_broadcast()      // 255.255.255.255
        || o[0] == 0              // 0.0.0.0/8
        || is_cgnat               // 100.64.0.0/10
        || is_protocol            // 192.0.0.0/24
        || is_benchmarking        // 198.18.0.0/15
        || is_documentation) // 192.0.2/24, 198.51.100/24, 203.0.113/24
}

/// Whether an IPv6 address is globally routable (not local/internal).
#[must_use]
pub fn is_global_ipv6(v6: Ipv6Addr) -> bool {
    let segs = v6.segments();
    let is_unique_local = (segs[0] & 0xfe00) == 0xfc00; // fc00::/7
    let is_link_local = (segs[0] & 0xffc0) == 0xfe80; // fe80::/10
    let is_documentation = segs[0] == 0x2001 && segs[1] == 0x0db8; // 2001:db8::/32
    !(v6.is_loopback()
        || v6.is_unspecified()
        || is_unique_local
        || is_link_local
        || is_documentation)
}

/// Validate a relative surface path before interpolating it into an HTTP URL.
///
/// The HTTP surface fetcher builds `"{base}/{path}"`, so a `path` that is
/// absolute, contains a `..` segment, embeds a scheme (`://`), starts a
/// network-path reference (`//host`), or carries control characters could escape
/// the base or repoint the request at a different host. Because several surface
/// segments derive from a remote's own `info/refs`/channel data during a mirror
/// sync, this guard gives the HTTP transport protection equivalent to the local
/// fetcher's [`safe_join`] (which it cannot reuse — there is no filesystem to
/// canonicalize against).
///
/// Legitimate surface paths (`nar/<hash>.nar.zst`, `objects/ab/cdef…`,
/// `channels/stable/00`, `info/refs`, `<hash>.narinfo`) pass unchanged.
///
/// # Errors
///
/// Returns a [`FetchError`] when `path` is empty, absolute (leading `/`),
/// contains a `\` or a control character, embeds `://`, or has any `.`/`..`
/// or empty path segment (which includes a leading `//`).
pub fn validate_http_surface_path(path: &str) -> Result<()> {
    let reject = |reason: &str| {
        Err(fetch_err(format!(
            "refusing HTTP surface path '{path}': {reason}"
        )))
    };
    if path.is_empty() {
        return reject("path is empty");
    }
    if path.starts_with('/') {
        return reject("path is absolute");
    }
    if path.contains('\\') {
        return reject("path contains a backslash");
    }
    if path.contains("://") {
        return reject("path embeds a URL scheme");
    }
    if path.chars().any(|c| c.is_control()) {
        return reject("path contains a control character");
    }
    // Reject `..`/`.`/empty segments. An empty segment covers a leading `//`
    // (network-path reference) and any doubled slash that could collapse the
    // base, and `..` covers traversal toward the host root.
    for segment in path.split('/') {
        if segment.is_empty() {
            return reject("path contains an empty segment (e.g. a leading or doubled '/')");
        }
        if segment == ".." || segment == "." {
            return reject("path contains a '.' or '..' segment");
        }
    }
    Ok(())
}

/// Join a relative surface path onto a root, rejecting traversal.
///
/// # Errors
///
/// Returns an error for absolute paths or any `..` component.
pub fn safe_join(root: &std::path::Path, relative: &str) -> Result<std::path::PathBuf> {
    let rel = std::path::Path::new(relative);
    if rel.is_absolute() {
        bail!("surface path must be relative: '{relative}'");
    }
    for component in rel.components() {
        match component {
            std::path::Component::Normal(_) => {}
            _ => bail!("surface path contains illegal component: '{relative}'"),
        }
    }
    Ok(root.join(rel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_join_rejects_traversal() {
        let root = std::path::Path::new("/srv/reg");
        assert!(safe_join(root, "objects/ab/cd").is_ok());
        assert!(safe_join(root, "../etc/passwd").is_err());
        assert!(safe_join(root, "/etc/passwd").is_err());
        assert!(safe_join(root, "a/../../b").is_err());
    }

    #[test]
    fn validate_http_surface_path_allows_legit_and_rejects_escapes() {
        // Legitimate surface paths pass unchanged.
        for ok in [
            "nar/0a1b2c.nar.zst",
            "objects/ab/cdef0123",
            "channels/stable/00",
            "info/refs",
            "abc123.narinfo",
            "HEAD",
        ] {
            assert!(validate_http_surface_path(ok).is_ok(), "should allow {ok}");
        }
        // Escapes and repointing attempts are rejected.
        for bad in [
            "",
            "/etc/passwd",
            "../secret",
            "objects/../../etc/passwd",
            "//evil.example.com/x",
            "objects//ab",
            "https://evil.example.com/x",
            "objects/ab\\cd",
            "objects/ab/cd\r\nHost: evil",
            "objects/./ab",
        ] {
            assert!(
                validate_http_surface_path(bad).is_err(),
                "should reject {bad:?}"
            );
        }
    }

    #[test]
    fn is_safe_remote_url_rejects_local_and_non_http() {
        // Non-HTTP schemes and bare paths are rejected outright.
        assert!(is_safe_remote_url("file:///etc/passwd").is_err());
        assert!(is_safe_remote_url("/srv/secret").is_err());
        assert!(is_safe_remote_url("ftp://example.com/x").is_err());

        // Loopback, link-local (cloud metadata), and RFC-1918 literals.
        assert!(is_safe_remote_url("http://127.0.0.1/").is_err());
        assert!(is_safe_remote_url("http://127.0.0.1:8500/v1/").is_err());
        assert!(is_safe_remote_url("http://169.254.169.254/latest/meta-data/").is_err());
        assert!(is_safe_remote_url("http://10.0.0.5/").is_err());
        assert!(is_safe_remote_url("http://172.16.3.4/").is_err());
        assert!(is_safe_remote_url("http://192.168.1.1/").is_err());
        assert!(is_safe_remote_url("http://[::1]/").is_err());
        assert!(is_safe_remote_url("http://[fe80::1]/").is_err());
        assert!(is_safe_remote_url("http://[fc00::1]/").is_err());
        // IPv4-mapped IPv6 form of loopback must not slip through.
        assert!(is_safe_remote_url("http://[::ffff:127.0.0.1]/").is_err());

        // A public literal IP passes (no DNS needed).
        assert!(is_safe_remote_url("https://93.184.216.34/").is_ok());
    }

    #[test]
    fn is_global_ip_classifies_ranges() {
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))));
        assert!(!is_global_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(is_global_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(is_global_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn is_global_ipv4_rejects_special_purpose_ranges() {
        // 100.64.0.0/10 carrier-grade NAT (RFC 6598).
        assert!(!is_global_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(!is_global_ipv4(Ipv4Addr::new(100, 127, 255, 255)));
        // Boundaries of the /10 are global on either side.
        assert!(is_global_ipv4(Ipv4Addr::new(100, 63, 255, 255)));
        assert!(is_global_ipv4(Ipv4Addr::new(100, 128, 0, 1)));
        // 192.0.0.0/24 IETF protocol assignments (RFC 6890).
        assert!(!is_global_ipv4(Ipv4Addr::new(192, 0, 0, 1)));
        // 198.18.0.0/15 benchmarking (RFC 2544).
        assert!(!is_global_ipv4(Ipv4Addr::new(198, 18, 0, 1)));
        assert!(!is_global_ipv4(Ipv4Addr::new(198, 19, 255, 255)));
        assert!(is_global_ipv4(Ipv4Addr::new(198, 17, 255, 255)));
        assert!(is_global_ipv4(Ipv4Addr::new(198, 20, 0, 1)));
        // Documentation ranges (RFC 5737).
        assert!(!is_global_ipv4(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!is_global_ipv4(Ipv4Addr::new(198, 51, 100, 1)));
        assert!(!is_global_ipv4(Ipv4Addr::new(203, 0, 113, 1)));
        // A neighbour outside the documentation /24 is global.
        assert!(is_global_ipv4(Ipv4Addr::new(203, 0, 114, 1)));
    }

    #[test]
    fn is_safe_remote_url_rejects_new_special_ranges() {
        assert!(is_safe_remote_url("http://100.64.0.1/").is_err());
        assert!(is_safe_remote_url("http://192.0.0.1/").is_err());
        assert!(is_safe_remote_url("http://198.18.0.1/").is_err());
        assert!(is_safe_remote_url("http://192.0.2.1/").is_err());
        assert!(is_safe_remote_url("http://198.51.100.1/").is_err());
        assert!(is_safe_remote_url("http://203.0.113.1/").is_err());
        // IPv6 documentation range.
        assert!(is_safe_remote_url("http://[2001:db8::1]/").is_err());
    }

    #[test]
    fn literal_ip_metadata_host_is_rejected_by_the_call_site_predicate() {
        // SECURITY regression (SSRF, finding #7): a hub-originated request to a
        // literal-IP internal/metadata host must be refused. reqwest hands an
        // IP-literal host straight to the connector and never consults a DNS
        // resolver, so the literal-IP defense is `is_safe_remote_url` applied at
        // every call site. This pins the predicate: every internal literal —
        // loopback, the cloud-metadata link-local, RFC-1918, and their
        // IPv4-mapped IPv6 / IPv6 forms — is rejected, while a public literal
        // passes.
        for blocked in [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/x.narinfo",
            "http://10.0.0.5/x.narinfo",
            "http://192.168.1.1/x.narinfo",
            "http://[::1]/x.narinfo",
            "http://[fd00::1]/x.narinfo",
            "http://[::ffff:169.254.169.254]/x.narinfo",
        ] {
            assert!(
                is_safe_remote_url(blocked).is_err(),
                "literal-IP internal host must be refused: {blocked}"
            );
        }
        // A public literal still passes, so legitimate IP-addressed caches work.
        assert!(is_safe_remote_url("http://93.184.216.34/x.narinfo").is_ok());
    }

    #[test]
    fn fetch_error_classification_survives_context() {
        use anyhow::Context as _;
        let err: anyhow::Error = fetch_err("connection refused");
        let wrapped = Err::<(), _>(err)
            .context("indexing demo")
            .context("outer")
            .unwrap_err();
        assert!(is_fetch_error(&wrapped));
        assert!(!is_fetch_error(&anyhow::anyhow!("parse error")));
    }
}
