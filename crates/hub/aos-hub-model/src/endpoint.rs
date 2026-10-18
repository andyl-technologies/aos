//! Typed endpoint origins and request-authority validation.
//!
//! Endpoints are inbound client identities, not storage origins. This
//! module canonicalizes their scheme, DNS/IPv4/IPv6 host, and effective port;
//! rejects URL aliases that could split routing identity; and derives the
//! stable RFC-0012 endpoint digest using a NetworkPolicy identity
//! fingerprint rather than a replaceable database id.

use sha2::{Digest, Sha256};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;
use url::{Host, Url};

const ENDPOINT_IDENTITY_DOMAIN: &[u8] = b"aos-hub-delivery-endpoint-v1\0";

/// The transport scheme of a endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeliveryScheme {
    /// Cleartext HTTP, permitted only under RFC-0012's explicit policy gates.
    Http,
    /// TLS-protected HTTP.
    Https,
}

impl DeliveryScheme {
    /// Parses the canonical lowercase scheme.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointOriginError::UnsupportedScheme`] for any scheme other
    /// than `http` or `https`.
    pub fn parse(value: &str) -> Result<Self, EndpointOriginError> {
        match value {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            _ => Err(EndpointOriginError::UnsupportedScheme(value.to_string())),
        }
    }

    /// Returns the canonical lowercase spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// Returns the default effective port.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }

    const fn identity_tag(self) -> u8 {
        match self {
            Self::Http => 0x01,
            Self::Https => 0x02,
        }
    }
}

impl fmt::Display for DeliveryScheme {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A canonical endpoint host.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DeliveryHost {
    /// An IDNA-ASCII, lowercase DNS name without a trailing dot.
    Dns(String),
    /// A four-byte IPv4 address.
    Ipv4(Ipv4Addr),
    /// A sixteen-byte IPv6 address that is not IPv4-mapped and has no zone id.
    Ipv6(Ipv6Addr),
}

impl DeliveryHost {
    /// Returns the canonical host rendering without an IPv6 bracket pair.
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::Dns(name) => name.clone(),
            Self::Ipv4(address) => address.to_string(),
            Self::Ipv6(address) => address.to_string(),
        }
    }

    fn identity_tag(&self) -> u8 {
        match self {
            Self::Dns(_) => 0x01,
            Self::Ipv4(_) => 0x02,
            Self::Ipv6(_) => 0x03,
        }
    }

    fn identity_bytes(&self) -> Vec<u8> {
        match self {
            Self::Dns(name) => name.as_bytes().to_vec(),
            Self::Ipv4(address) => address.octets().to_vec(),
            Self::Ipv6(address) => address.octets().to_vec(),
        }
    }
}

impl fmt::Display for DeliveryHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => formatter.write_str(name),
            Self::Ipv4(address) => write!(formatter, "{address}"),
            Self::Ipv6(address) => write!(formatter, "[{address}]"),
        }
    }
}

/// Verified TLS identity evidence supplied by the listener or trusted ingress.
///
/// The caller constructs this value only after its TLS stack has validated the
/// certificate and, for layer-7 ingress, authenticated the forwarding hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsEndpointIdentity<'a> {
    /// DNS SNI used for a certificate-validating HTTPS handshake.
    DnsSni(&'a str),
    /// IP subject alternative name validated from the peer certificate.
    IpSubjectAltName(IpAddr),
}

/// One canonical inbound delivery origin.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointOrigin {
    /// HTTP transport scheme.
    scheme: DeliveryScheme,
    /// Typed canonical host.
    host: DeliveryHost,
    /// Effective port, including the scheme default when omitted by the user.
    port: u16,
}

impl EndpointOrigin {
    /// Parses an endpoint origin URL with no path, query, fragment, or userinfo.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointOriginError`] for unsupported schemes, URL aliases,
    /// userinfo, non-root paths, queries/fragments, invalid IDNA/IP literals,
    /// IPv6 zones/mapped addresses, or a missing effective port.
    pub fn parse(value: &str) -> Result<Self, EndpointOriginError> {
        let url = Url::parse(value).map_err(|error| EndpointOriginError::InvalidUrl {
            detail: error.to_string(),
        })?;
        Self::from_url(value, &url)
    }

    /// Returns the endpoint's transport scheme.
    #[must_use]
    pub const fn scheme(&self) -> DeliveryScheme {
        self.scheme
    }

    /// Returns the endpoint's typed canonical host.
    #[must_use]
    pub const fn host(&self) -> &DeliveryHost {
        &self.host
    }

    /// Returns the endpoint's effective port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Parses an HTTP request authority under the listener's actual scheme.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointOriginError`] if the authority is not a canonical host
    /// plus optional port or contains any origin component other than authority.
    pub fn parse_authority(
        scheme: DeliveryScheme,
        authority: &str,
    ) -> Result<Self, EndpointOriginError> {
        let value = format!("{}://{authority}/", scheme.as_str());
        let url = Url::parse(&value).map_err(|error| EndpointOriginError::InvalidAuthority {
            detail: error.to_string(),
        })?;
        Self::from_url(&value, &url)
    }

    /// Renders the canonical origin, omitting only a default port.
    #[must_use]
    pub fn canonical_origin(&self) -> String {
        if self.port == self.scheme.default_port() {
            format!("{}://{}", self.scheme, self.host)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }

    /// Computes the stable endpoint identity digest for one network realm.
    #[must_use]
    pub fn identity_digest(&self, boundary_identity_fingerprint: &[u8; 32]) -> [u8; 32] {
        let host = self.host.identity_bytes();
        let host_length = host.len() as u32;
        let mut hasher = Sha256::new();
        hasher.update(ENDPOINT_IDENTITY_DOMAIN);
        hasher.update([self.scheme.identity_tag()]);
        hasher.update([self.host.identity_tag()]);
        hasher.update(host_length.to_be_bytes());
        hasher.update(host);
        hasher.update(self.port.to_be_bytes());
        hasher.update(boundary_identity_fingerprint);
        hasher.finalize().into()
    }

    /// Verifies an incoming listener scheme, authority, and TLS identity.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointOriginError::OriginMismatch`] when the normalized
    /// request does not equal this endpoint, when HTTPS lacks exact typed TLS
    /// identity evidence, or when cleartext HTTP is accompanied by TLS evidence.
    pub fn validate_request(
        &self,
        listener_scheme: DeliveryScheme,
        authority: &str,
        tls_identity: Option<TlsEndpointIdentity<'_>>,
    ) -> Result<(), EndpointOriginError> {
        let request = Self::parse_authority(listener_scheme, authority)?;
        if request != *self {
            return Err(EndpointOriginError::OriginMismatch);
        }
        match (self.scheme, &self.host, tls_identity) {
            (DeliveryScheme::Http, _, None) => Ok(()),
            (DeliveryScheme::Http, _, Some(_)) => Err(EndpointOriginError::UnexpectedTlsIdentity),
            (DeliveryScheme::Https, _, None) => Err(EndpointOriginError::MissingTlsIdentity),
            (
                DeliveryScheme::Https,
                DeliveryHost::Dns(expected),
                Some(TlsEndpointIdentity::DnsSni(sni)),
            ) => {
                let normalized = normalize_dns_name(sni)?;
                if &normalized == expected {
                    Ok(())
                } else {
                    Err(EndpointOriginError::SniMismatch)
                }
            }
            (
                DeliveryScheme::Https,
                DeliveryHost::Ipv4(expected),
                Some(TlsEndpointIdentity::IpSubjectAltName(IpAddr::V4(actual))),
            ) if &actual == expected => Ok(()),
            (
                DeliveryScheme::Https,
                DeliveryHost::Ipv6(expected),
                Some(TlsEndpointIdentity::IpSubjectAltName(IpAddr::V6(actual))),
            ) if &actual == expected => Ok(()),
            (DeliveryScheme::Https, DeliveryHost::Dns(_), Some(_)) => {
                Err(EndpointOriginError::SniMismatch)
            }
            (DeliveryScheme::Https, _, Some(_)) => Err(EndpointOriginError::IpSanMismatch),
        }
    }

    fn from_url(original: &str, url: &Url) -> Result<Self, EndpointOriginError> {
        let scheme = DeliveryScheme::parse(url.scheme())?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(EndpointOriginError::UserInfo);
        }
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(EndpointOriginError::NonOriginComponents);
        }
        if authority_contains_zone_id(original) {
            return Err(EndpointOriginError::Ipv6ZoneId);
        }
        let host = match url.host().ok_or(EndpointOriginError::MissingHost)? {
            Host::Domain(name) => DeliveryHost::Dns(normalize_dns_name(name)?),
            Host::Ipv4(address) => DeliveryHost::Ipv4(address),
            Host::Ipv6(address) => {
                if address.to_ipv4_mapped().is_some() {
                    return Err(EndpointOriginError::Ipv4MappedIpv6);
                }
                DeliveryHost::Ipv6(address)
            }
        };
        let port = url
            .port_or_known_default()
            .ok_or(EndpointOriginError::MissingPort)?;
        if port == 0 {
            return Err(EndpointOriginError::InvalidPort);
        }
        Ok(Self { scheme, host, port })
    }
}

impl fmt::Display for EndpointOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical_origin())
    }
}

/// An invalid endpoint origin or request authority.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EndpointOriginError {
    /// URL parsing failed.
    #[error("invalid endpoint URL: {detail}")]
    InvalidUrl {
        /// Parser diagnostic without credentials.
        detail: String,
    },
    /// Request-authority parsing failed.
    #[error("invalid request authority: {detail}")]
    InvalidAuthority {
        /// Parser diagnostic without credentials.
        detail: String,
    },
    /// The scheme was not HTTP(S).
    #[error("unsupported endpoint scheme '{0}'")]
    UnsupportedScheme(String),
    /// No host was present.
    #[error("endpoint origin has no host")]
    MissingHost,
    /// No effective port was available.
    #[error("endpoint origin has no effective port")]
    MissingPort,
    /// Port zero cannot identify an HTTP listener.
    #[error("endpoint port must be from 1 through 65535")]
    InvalidPort,
    /// Userinfo could leak credentials or create an origin alias.
    #[error("endpoint origin cannot contain userinfo")]
    UserInfo,
    /// A path, query, or fragment was present.
    #[error("endpoint must be an origin without path, query, or fragment")]
    NonOriginComponents,
    /// A DNS trailing-dot alias was supplied.
    #[error("endpoint DNS name cannot have a trailing dot")]
    TrailingDot,
    /// A DNS name was empty or invalid after IDNA processing.
    #[error("endpoint DNS name is invalid")]
    InvalidDnsName,
    /// An IPv6 zone id was supplied.
    #[error("endpoint IPv6 address cannot contain a zone id")]
    Ipv6ZoneId,
    /// An IPv4 address used an IPv4-mapped IPv6 alias.
    #[error("endpoint rejects IPv4-mapped IPv6 aliases")]
    Ipv4MappedIpv6,
    /// The incoming scheme/authority did not identify this endpoint.
    #[error("request scheme or authority does not match the endpoint")]
    OriginMismatch,
    /// HTTPS did not provide identity evidence from the validated handshake.
    #[error("HTTPS endpoint requires verified TLS identity evidence")]
    MissingTlsIdentity,
    /// Cleartext HTTP unexpectedly carried TLS identity evidence.
    #[error("HTTP endpoint cannot use TLS identity evidence")]
    UnexpectedTlsIdentity,
    /// TLS SNI disagreed with the endpoint DNS identity.
    #[error("TLS SNI does not match the endpoint")]
    SniMismatch,
    /// The validated certificate IP SAN disagreed with the endpoint identity.
    #[error("TLS certificate IP subject alternative name does not match the endpoint")]
    IpSanMismatch,
}

fn normalize_dns_name(name: &str) -> Result<String, EndpointOriginError> {
    if name.is_empty() || name.ends_with('.') {
        return Err(if name.ends_with('.') {
            EndpointOriginError::TrailingDot
        } else {
            EndpointOriginError::InvalidDnsName
        });
    }
    let probe =
        Url::parse(&format!("https://{name}/")).map_err(|_| EndpointOriginError::InvalidDnsName)?;
    let Host::Domain(ascii) = probe.host().ok_or(EndpointOriginError::InvalidDnsName)? else {
        return Err(EndpointOriginError::InvalidDnsName);
    };
    if ascii.is_empty() || ascii.ends_with('.') {
        return Err(EndpointOriginError::TrailingDot);
    }
    let ascii = ascii.to_ascii_lowercase();
    if ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(EndpointOriginError::InvalidDnsName);
    }
    Ok(ascii)
}

fn authority_contains_zone_id(value: &str) -> bool {
    let authority = value
        .split_once("//")
        .map_or(value, |(_scheme, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    authority
        .split_once('[')
        .and_then(|(_before, bracketed)| bracketed.split_once(']'))
        .is_some_and(|(host, _after)| host.contains('%'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_dns_ip_and_effective_ports() {
        let dns = EndpointOrigin::parse("https://BÜCHER.example:443").unwrap();
        assert_eq!(dns.canonical_origin(), "https://xn--bcher-kva.example");
        assert_eq!(dns.port(), 443);

        let ipv4 = EndpointOrigin::parse("http://192.0.2.10:8080").unwrap();
        assert_eq!(ipv4.canonical_origin(), "http://192.0.2.10:8080");

        let ipv6 = EndpointOrigin::parse("https://[2001:db8::1]").unwrap();
        assert_eq!(ipv6.canonical_origin(), "https://[2001:db8::1]");
    }

    #[test]
    fn rejects_origin_aliases_and_extra_components() {
        for origin in [
            "ftp://example.com",
            "https://user@example.com",
            "https://example.com/path",
            "https://example.com/?query=yes",
            "https://example.com/#fragment",
            "https://example.com./",
            "https://bad_name.example/",
            "https://-bad.example/",
            "https://bad-.example/",
            "https://example.com:0/",
            "https://[::ffff:192.0.2.1]/",
            "https://[fe80::1%25eth0]/",
        ] {
            assert!(EndpointOrigin::parse(origin).is_err(), "{origin}");
        }
    }

    #[test]
    fn request_validation_requires_exact_scheme_authority_port_and_sni() {
        let endpoint = EndpointOrigin::parse("https://example.com:8443").unwrap();
        assert!(endpoint
            .validate_request(
                DeliveryScheme::Https,
                "EXAMPLE.com:8443",
                Some(TlsEndpointIdentity::DnsSni("example.com")),
            )
            .is_ok());
        assert!(endpoint
            .validate_request(DeliveryScheme::Http, "example.com:8443", None)
            .is_err());
        assert!(endpoint
            .validate_request(DeliveryScheme::Https, "example.com", None)
            .is_err());
        assert!(endpoint
            .validate_request(DeliveryScheme::Https, "example.com:8443", None)
            .is_err());
        assert!(endpoint
            .validate_request(
                DeliveryScheme::Https,
                "example.com:8443",
                Some(TlsEndpointIdentity::DnsSni("other.example")),
            )
            .is_err());

        let ip = EndpointOrigin::parse("https://192.0.2.10:8443").unwrap();
        assert!(ip
            .validate_request(
                DeliveryScheme::Https,
                "192.0.2.10:8443",
                Some(TlsEndpointIdentity::IpSubjectAltName(IpAddr::V4(
                    Ipv4Addr::new(192, 0, 2, 10),
                ))),
            )
            .is_ok());
        assert!(ip
            .validate_request(
                DeliveryScheme::Https,
                "192.0.2.10:8443",
                Some(TlsEndpointIdentity::IpSubjectAltName(IpAddr::V4(
                    Ipv4Addr::new(192, 0, 2, 11),
                ))),
            )
            .is_err());
    }

    #[test]
    fn endpoint_digest_uses_stable_boundary_identity() {
        let endpoint = EndpointOrigin::parse("https://10.0.0.1/cache");
        assert!(
            endpoint.is_err(),
            "endpoint origins cannot include route paths"
        );
        let endpoint = EndpointOrigin::parse("https://10.0.0.1").unwrap();
        let boundary_a = [0x11; 32];
        let boundary_b = [0x22; 32];
        assert_eq!(
            endpoint.identity_digest(&boundary_a),
            endpoint.identity_digest(&boundary_a)
        );
        assert_ne!(
            endpoint.identity_digest(&boundary_a),
            endpoint.identity_digest(&boundary_b)
        );
    }

    #[test]
    fn endpoint_digest_matches_normative_vectors() {
        let cases = [
            (
                "https://example.com",
                [0; 32],
                "5f4355f82aabce6be5993fd4e7a2cc8daf9517f65e7c33a853a4fbd1d2e0a845",
            ),
            (
                "http://192.0.2.10:8080",
                [0x11; 32],
                "dd2386a556c359981c96f5e1406f4b1d8a703652256d564ce2231666e70195f3",
            ),
            (
                "https://[2001:db8::1]:8443",
                [0x22; 32],
                "5d13ab476e10142123363cfb3b168c9073cb5cca41411feddd5e1f072db7d62f",
            ),
        ];
        for (origin, boundary, expected) in cases {
            let endpoint = EndpointOrigin::parse(origin).unwrap();
            assert_eq!(hex::encode(endpoint.identity_digest(&boundary)), expected);
        }
    }
}
