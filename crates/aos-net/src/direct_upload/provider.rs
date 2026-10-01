//! Confined, credential-free provider UploadPart requests.
//!
//! Authenticated discovery pins each placement to one HTTPS origin. DNS is
//! checked once and pinned for the operation; private origins require a separate
//! operator allowance. Signed URLs are never error sources or progress labels.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aos_proto_types::direct_upload::{
    DirectChecksumAlgorithm, DirectManifestPart, DirectPart, DirectPartChecksum, DirectPartGrant,
    DirectPlacementRef, DirectProviderProfile, DirectSessionRef, DirectUploadIntent,
    MAX_DIRECT_PLACEMENTS, WireInteger, valid_direct_digest, valid_direct_etag,
};
use futures_util::StreamExt as _;
use reqwest::header::{ETAG, HeaderName, HeaderValue};
use tokio::sync::OnceCell;
use url::{Host, Url};

use super::{PartChecksumAlgorithm, PartSource};

const MAX_PROVIDER_RESPONSE_BYTES: u64 = 8 * 1024;

/// Redacted provider transport failure without an underlying capability URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderError {
    /// A grant, source or authenticated origin fails exact admission.
    InvalidGrant,
    /// Network/TLS/timeout prevents obtaining a provider response.
    Unavailable,
    /// The provider refused the capability; refresh remains control-plane work.
    Denied,
    /// Its exclusive lifetime cannot cover dispatch; retry needs a new grant.
    Expired,
    /// The provider returned an unsupported status, ETag or oversized reply.
    Rejected,
    /// The operation's local clock cannot represent a bounded grant time.
    Clock,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGrant => "direct provider grant is invalid",
            Self::Unavailable => "direct provider transport is unavailable",
            Self::Denied => "direct provider capability was refused",
            Self::Expired => "direct provider capability expired before dispatch",
            Self::Rejected => "direct provider response was rejected",
            Self::Clock => "direct provider clock is invalid",
        })
    }
}

impl std::error::Error for ProviderError {}

/// One exact operator-selected HTTPS origin and its permitted private peers.
#[derive(Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivateProviderEndpoint {
    /// Exact bare HTTPS origin, without credentials, paths or queries.
    pub origin: String,
    /// Canonical wholly private or loopback CIDRs; metadata denial overrides.
    pub private_cidrs: Vec<String>,
}

impl fmt::Debug for PrivateProviderEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateProviderEndpoint")
            .field("cidr_count", &self.private_cidrs.len())
            .finish_non_exhaustive()
    }
}

/// Operator network policy independent of authenticated server discovery.
#[derive(Clone)]
pub struct ProviderOptions {
    /// Exact HTTPS origins and private CIDRs allowed by local operator policy.
    pub private_endpoints: Vec<PrivateProviderEndpoint>,
    /// Additional public CA certificates, without client keys or credentials.
    pub additional_roots: Vec<reqwest::Certificate>,
    /// Maximum DNS/connect establishment time.
    pub connect_timeout: Duration,
    /// Maximum duration of one content-bound provider attempt.
    pub request_timeout: Duration,
    /// Conservative client clock skew added before grant validity checks.
    pub clock_skew_seconds: u64,
    /// Minimum remaining exclusive grant lifetime before body dispatch.
    pub minimum_validity_seconds: u64,
    /// Aggregate provider request concurrency, from1 through32.
    pub maximum_parallel_parts: usize,
    /// Shared streamed-byte budget; zero leaves transfer bandwidth unlimited.
    pub bytes_per_second: u64,
}

impl Default for ProviderOptions {
    fn default() -> Self {
        Self {
            private_endpoints: Vec::new(),
            additional_roots: Vec::new(),
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(5 * 60),
            clock_skew_seconds: 10,
            minimum_validity_seconds: 30,
            maximum_parallel_parts: 32,
            bytes_per_second: 0,
        }
    }
}

impl fmt::Debug for ProviderOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderOptions")
            .field("private_origin_count", &self.private_endpoints.len())
            .field("additional_root_count", &self.additional_roots.len())
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

/// Independently retained admission inputs used to check a delegated grant.
#[derive(Debug, Clone)]
pub struct ProviderContext {
    /// Exact admitted logical session and immutable fingerprint.
    pub session: DirectSessionRef,
    /// Exact required destination and selected provider checksum algorithm.
    pub placement: DirectPlacementRef,
    /// Original source, geometry and logical owner.
    pub intent: DirectUploadIntent,
}

/// A bounded set of shared provider pools with no Hub credentials or redirects.
pub struct ProviderTransport {
    profiles: BTreeMap<u64, DirectProviderProfile>,
    clients: BTreeMap<String, Arc<OnceCell<reqwest::Client>>>,
    private_origins: BTreeMap<String, Vec<super::network::PrivateRange>>,
    options: ProviderOptions,
    request_budget: tokio::sync::Semaphore,
    byte_budget: Arc<ByteBudget>,
    metrics: Arc<super::DirectTransferMetrics>,
}

impl fmt::Debug for ProviderTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderTransport")
            .field("placement_count", &self.profiles.len())
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl ProviderTransport {
    /// Admits exact authenticated placement profiles and local network policy.
    ///
    /// # Errors
    ///
    /// Rejects excess/duplicate placements, malformed origins/fingerprints,
    /// unsupported timeouts or oversized local trust configuration.
    pub fn new(
        profiles: Vec<DirectProviderProfile>,
        options: ProviderOptions,
    ) -> Result<Self, ProviderError> {
        if options.maximum_parallel_parts == 0 || options.maximum_parallel_parts > 32 {
            return Err(ProviderError::InvalidGrant);
        }

        if profiles.is_empty()
            || profiles.len() > MAX_DIRECT_PLACEMENTS
            || options.private_endpoints.len() > MAX_DIRECT_PLACEMENTS
            || options.additional_roots.len() > MAX_DIRECT_PLACEMENTS
            || options.connect_timeout.is_zero()
            || options.connect_timeout > Duration::from_secs(60)
            || options.request_timeout.is_zero()
            || options.request_timeout > Duration::from_secs(15 * 60)
            || options.clock_skew_seconds > 60
            || options.minimum_validity_seconds > 10 * 60
        {
            return Err(ProviderError::InvalidGrant);
        }
        let mut private_origins = BTreeMap::new();
        for endpoint in &options.private_endpoints {
            let origin = checked_origin(&endpoint.origin)?;
            if endpoint.private_cidrs.is_empty() || endpoint.private_cidrs.len() > 16 {
                return Err(ProviderError::InvalidGrant);
            }
            let mut unique = BTreeSet::new();
            let ranges = endpoint
                .private_cidrs
                .iter()
                .map(|value| {
                    if !unique.insert(value) {
                        return Err(ProviderError::InvalidGrant);
                    }
                    super::network::PrivateRange::parse(value)
                })
                .collect::<Result<Vec<_>, _>>()?;
            if private_origins.insert(origin, ranges).is_some() {
                return Err(ProviderError::InvalidGrant);
            }
        }

        let mut admitted = BTreeMap::new();
        let mut clients = BTreeMap::new();
        for profile in profiles {
            for revision in [
                profile.placement_id,
                profile.placement_resource_version,
                profile.write_spec_version,
                profile.binding_id,
                profile.binding_resource_version,
                profile.binding_write_revision,
            ] {
                if !(1..=i64::MAX as u64).contains(&revision.get()) {
                    return Err(ProviderError::InvalidGrant);
                }
            }
            if !valid_direct_digest(&profile.profile_fingerprint)
                || !valid_direct_digest(&profile.private_policy_digest)
            {
                return Err(ProviderError::InvalidGrant);
            }
            let origin = checked_origin(&profile.provider_origin)?;
            clients
                .entry(origin)
                .or_insert_with(|| Arc::new(OnceCell::new()));
            if admitted
                .insert(profile.placement_id.get(), profile)
                .is_some()
            {
                return Err(ProviderError::InvalidGrant);
            }
        }
        Ok(Self {
            profiles: admitted,
            clients,
            private_origins,
            request_budget: tokio::sync::Semaphore::new(options.maximum_parallel_parts),
            byte_budget: Arc::new(ByteBudget {
                rate: options.bytes_per_second,
                next: tokio::sync::Mutex::new(tokio::time::Instant::now()),
            }),
            metrics: Arc::new(super::DirectTransferMetrics::default()),
            options,
        })
    }

    /// Shares value-free counters with its owning direct coordinator.
    pub fn with_metrics(mut self, metrics: Arc<super::DirectTransferMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Sends one exact part directly to its admitted provider origin.
    ///
    /// The caller holds the global/file/part concurrency permits. A successful
    /// result is a provider observation, not final publication or capability
    /// settlement. Retrying these same checksum-bound bytes stays on this part;
    /// provider create/complete/promote/abort remain server control operations.
    ///
    /// # Errors
    ///
    /// Rejects scope/source/headers/origin/expiry changes before body dispatch,
    /// unsafe DNS, network errors, provider denial or malformed bounded replies.
    pub async fn upload_part(
        &self,
        context: &ProviderContext,
        source: &PartSource,
        grant: &DirectPartGrant,
    ) -> Result<DirectManifestPart, ProviderError> {
        let _permit = self
            .request_budget
            .acquire()
            .await
            .map_err(|_| ProviderError::Unavailable)?;
        let part = portable_part(source);
        if source.source().sha256() != context.intent.expected_sha256
            || source.source().byte_size() != context.intent.byte_size.get()
            || source.source().part_size() != context.intent.part_size.get()
        {
            return Err(ProviderError::InvalidGrant);
        }
        self.check_grant(context, &part, grant)?;
        let profile = self
            .profiles
            .get(&context.placement.placement_id.get())
            .ok_or(ProviderError::InvalidGrant)?;
        profile
            .validate_placement(&context.placement)
            .map_err(|_| ProviderError::InvalidGrant)?;
        let url = Url::parse(&grant.url).map_err(|_| ProviderError::InvalidGrant)?;
        let origin = url.origin().ascii_serialization();
        if checked_origin(&profile.provider_origin)? != origin {
            return Err(ProviderError::InvalidGrant);
        }
        let cell = self
            .clients
            .get(&origin)
            .ok_or(ProviderError::InvalidGrant)?;
        let client = cell
            .get_or_try_init(|| self.build_client(&url, &origin))
            .await?;

        // DNS/pool establishment can consume grant lifetime. Recheck it at the
        // actual dispatch rather than relying on batch issuance time.
        self.check_grant(context, &part, grant)?;
        let budget = Arc::clone(&self.byte_budget);
        let body = source.stream().then(move |chunk| {
            let budget = Arc::clone(&budget);
            async move {
                if let Ok(bytes) = &chunk {
                    budget.acquire(bytes.len()).await?;
                }
                chunk
            }
        });
        let mut request = client
            .put(&grant.url)
            .body(reqwest::Body::wrap_stream(body));
        for header in &grant.required_headers {
            let name = HeaderName::from_bytes(header.name.as_bytes())
                .map_err(|_| ProviderError::InvalidGrant)?;
            let value =
                HeaderValue::from_str(&header.value).map_err(|_| ProviderError::InvalidGrant)?;
            request = request.header(name, value);
        }
        let attempt = self.metrics.provider_attempt();
        let mut response = request
            .send()
            .await
            .map_err(|_| ProviderError::Unavailable)?;
        match response.status().as_u16() {
            200 => {}
            401 | 403 => return Err(ProviderError::Denied),
            429 | 500..=599 => return Err(ProviderError::Unavailable),
            _ => return Err(ProviderError::Rejected),
        }
        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .filter(|value| valid_direct_etag(value))
            .ok_or(ProviderError::Rejected)?
            .to_owned();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES)
        {
            return Err(ProviderError::Rejected);
        }
        let mut received = 0_u64;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| ProviderError::Unavailable)?
        {
            received = received
                .checked_add(chunk.len() as u64)
                .filter(|bytes| *bytes <= MAX_PROVIDER_RESPONSE_BYTES)
                .ok_or(ProviderError::Rejected)?;
        }
        attempt.acknowledge(part.byte_size.get());
        Ok(DirectManifestPart { part, etag })
    }

    fn check_grant(
        &self,
        context: &ProviderContext,
        part: &DirectPart,
        grant: &DirectPartGrant,
    ) -> Result<(), ProviderError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ProviderError::Clock)?
            .as_secs()
            .checked_add(self.options.clock_skew_seconds)
            .ok_or(ProviderError::Clock)?;
        if now
            .checked_add(self.options.minimum_validity_seconds)
            .is_none_or(|deadline| deadline >= grant.expires_at.get())
        {
            return Err(ProviderError::Expired);
        }
        grant
            .validate_for(
                &context.session,
                &context.placement,
                &context.intent,
                part,
                now,
                self.options.minimum_validity_seconds,
            )
            .map_err(|_| ProviderError::InvalidGrant)
    }

    async fn build_client(
        &self,
        url: &Url,
        origin: &str,
    ) -> Result<reqwest::Client, ProviderError> {
        let private_ranges = self.private_origins.get(origin);
        let host = url.host().ok_or(ProviderError::InvalidGrant)?;
        let port = url
            .port_or_known_default()
            .ok_or(ProviderError::InvalidGrant)?;
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(self.options.connect_timeout)
            .timeout(self.options.request_timeout)
            .pool_max_idle_per_host(32);
        for root in &self.options.additional_roots {
            builder = builder.add_root_certificate(root.clone());
        }
        match host {
            Host::Ipv4(address) => check_selected_address(IpAddr::V4(address), private_ranges)?,
            Host::Ipv6(address) => check_selected_address(IpAddr::V6(address), private_ranges)?,
            Host::Domain(domain) => {
                let addresses = tokio::time::timeout(
                    self.options.connect_timeout,
                    tokio::net::lookup_host((domain, port)),
                )
                .await
                .map_err(|_| ProviderError::Unavailable)?
                .map_err(|_| ProviderError::Unavailable)?;
                let addresses: Vec<SocketAddr> = addresses.take(17).collect();
                if addresses.is_empty() || addresses.len() > 16 {
                    return Err(ProviderError::InvalidGrant);
                }
                for address in &addresses {
                    check_selected_address(address.ip(), private_ranges)?;
                }
                builder = builder.resolve_to_addrs(domain, &addresses);
            }
        }
        builder.build().map_err(|_| ProviderError::Unavailable)
    }
}

pub(crate) fn portable_part(source: &PartSource) -> DirectPart {
    let identity = source.identity();
    DirectPart {
        part_number: identity.part_number,
        offset: WireInteger::new(identity.offset),
        byte_size: WireInteger::new(identity.byte_size),
        sha256: identity.sha256.clone(),
        checksum: DirectPartChecksum {
            algorithm: match identity.checksum.algorithm {
                PartChecksumAlgorithm::Md5 => DirectChecksumAlgorithm::Md5,
                PartChecksumAlgorithm::Sha256 => DirectChecksumAlgorithm::Sha256,
            },
            value: identity.checksum.value.clone(),
        },
    }
}

pub(super) fn checked_origin(value: &str) -> Result<String, ProviderError> {
    if value.len() > 2048 {
        return Err(ProviderError::InvalidGrant);
    }
    let url = Url::parse(value).map_err(|_| ProviderError::InvalidGrant)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(ProviderError::InvalidGrant);
    }
    let origin = url.origin().ascii_serialization();
    if value != origin && value != format!("{origin}/") {
        return Err(ProviderError::InvalidGrant);
    }
    Ok(origin)
}

fn check_selected_address(
    address: IpAddr,
    ranges: Option<&Vec<super::network::PrivateRange>>,
) -> Result<(), ProviderError> {
    // Mandatory metadata/link-local denial precedes any local CIDR exemption.
    check_address(address, ranges.is_some())?;
    if check_address(address, false).is_ok()
        || ranges.is_some_and(|ranges| ranges.iter().any(|range| range.contains(address)))
    {
        Ok(())
    } else {
        Err(ProviderError::InvalidGrant)
    }
}

fn check_address(address: IpAddr, allow_private: bool) -> Result<(), ProviderError> {
    let forbidden = match address {
        IpAddr::V4(address) => {
            address.is_unspecified()
                || address.is_link_local()
                || address.is_multicast()
                || address.octets()[0] == 0
                || address.octets()[0] >= 224
        }
        IpAddr::V6(address) => {
            // `to_ipv4` also maps ::1 to 0.0.0.1. Loopback is a distinct
            // operator-only exemption, while mapped metadata stays refused.
            if address.is_loopback() {
                return if allow_private {
                    Ok(())
                } else {
                    Err(ProviderError::InvalidGrant)
                };
            }
            if let Some(mapped) = address.to_ipv4() {
                return check_address(IpAddr::V4(mapped), allow_private);
            }
            address.is_unspecified()
                || address.is_unicast_link_local()
                || address.is_multicast()
                || address.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
        }
    };
    if forbidden {
        return Err(ProviderError::InvalidGrant);
    }
    if allow_private {
        return Ok(());
    }
    let allowed = match address {
        IpAddr::V4(address) => remote_ipv4(address),
        IpAddr::V6(address) => remote_ipv6(address),
    };
    if allowed {
        Ok(())
    } else {
        Err(ProviderError::InvalidGrant)
    }
}

fn remote_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !(address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_unspecified()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 198 && matches!(octets[1], 18 | 19))
        || octets[0] >= 224)
}

fn remote_ipv6(address: Ipv6Addr) -> bool {
    if let Some(address) = address.to_ipv4() {
        return remote_ipv4(address);
    }
    !(address.is_loopback()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || address.is_multicast()
        || address.is_unspecified()
        || address.segments()[0] & 0xffc0 == 0xfec0)
}

#[cfg(test)]
#[path = "provider_tests.rs"]
mod tests;

// Reservations serialize only byte accounting. Bodies and provider sockets
// remain parallel, and dropping a body never sends its remaining source bytes.
struct ByteBudget {
    rate: u64,
    next: tokio::sync::Mutex<tokio::time::Instant>,
}

impl ByteBudget {
    async fn acquire(&self, bytes: usize) -> Result<(), std::io::Error> {
        if self.rate == 0 {
            return Ok(());
        }
        let nanos = (bytes as u128)
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(u128::from(self.rate) - 1))
            .map(|value| value / u128::from(self.rate))
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| std::io::Error::other("direct byte budget overflow"))?;
        let mut next = self.next.lock().await;
        let scheduled = (*next).max(tokio::time::Instant::now());
        *next = scheduled
            .checked_add(Duration::from_nanos(nanos))
            .ok_or_else(|| std::io::Error::other("direct byte budget overflow"))?;
        drop(next);
        tokio::time::sleep_until(scheduled).await;
        Ok(())
    }
}
