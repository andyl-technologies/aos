//! Fresh uncached upstream delivery after an authorized Hybrid storage miss.
//!
//! This grant supplies a source selection, never an immutable object identity or
//! publication permission. Its separate MAC domain binds the entire verified
//! public request. Upstream bytes travel from the Worker directly to the client.
//!
//! ```text
//! grant = {request: exact ingress assertion, target: current mirror selection}
//! ```

use super::*;

pub mod candidate;

/// Internal response header for fresh upstream delivery, never stored delivery.
pub const HYBRID_LIVE_DELIVERY_HEADER: &str = "x-aos-hybrid-live-delivery";

/// Maximum elapsed lifetime of an already dispatched uncached response stream.
pub const LIVE_STREAM_SECONDS: i64 = 600;

const DOMAIN: &[u8] = b"aos-hybrid-live-delivery-v1\0";

/// Counts actual native stream views without retaining body bytes.
///
/// This establishes only response framing. It neither authenticates content
/// nor grants source, storage, publication or immutable-object authority.
pub struct LiveBodyBudget {
    maximum: u64,
    declared: Option<u64>,
    consumed: u64,
    ended: bool,
}

impl LiveBodyBudget {
    /// Admits a separately qualified ceiling and optional exact response length.
    ///
    /// # Errors
    /// Returns an error for excessive or zero ceilings or a declared oversize body.
    pub fn new(maximum: u64, declared: Option<u64>) -> anyhow::Result<Self> {
        anyhow::ensure!(
            maximum > 0
                && maximum <= crate::mirror_work::MIRROR_MAX_OBJECT_BYTES
                && declared.is_none_or(|length| length <= maximum),
            "live body ceiling refused"
        );
        Ok(Self {
            maximum,
            declared,
            consumed: 0,
            ended: false,
        })
    }

    /// Checks an actual view before copying or delivering it, including EOF data.
    ///
    /// # Errors
    /// Returns an error for a view over 64 KiB, excess bytes, truncation or reads after EOF.
    pub fn consume(&mut self, length: u64, done: bool) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.ended && length <= 64 * 1024 && (done || length > 0),
            "live source view refused"
        );
        let consumed = self
            .consumed
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("live body length overflow"))?;
        anyhow::ensure!(
            consumed <= self.maximum
                && self.declared.is_none_or(|size| consumed <= size)
                && (!done || self.declared.is_none_or(|size| consumed == size)),
            "live body excess or truncation refused"
        );
        self.consumed = consumed;
        self.ended = done;
        Ok(())
    }

    /// Reports the independently observed EOF flag after consuming its final view.
    #[must_use]
    pub fn ended(&self) -> bool {
        self.ended
    }
}

/// Separates bounded pointer metadata from full uncached pack responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HybridLiveDeliveryClass {
    /// Fresh pointer or canonical metadata, at most 128 KiB.
    Metadata,
    /// Full encoded pack or companion index, never an immutable publication.
    Pack,
}

/// Current SQL source and placement selected for one uncached upstream read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridLiveDeliveryTarget {
    /// Current registry identity and authorization generation.
    pub registry_id: i64,
    /// Current registry resource version.
    pub registry_resource_version: i64,
    /// Exact mirror configuration version.
    pub mirror_resource_version: i64,
    /// Reconciled placement identity.
    pub placement_id: i64,
    /// Reconciled placement version.
    pub placement_resource_version: i64,
    /// Current placement write-authority generation.
    pub write_spec_version: i64,
    /// Exact reconciled destination prefix; no destination write is authorized.
    pub placement_prefix: String,
    /// Current binding identity.
    pub binding_id: i64,
    /// Current binding version.
    pub binding_resource_version: i64,
    /// Current independently qualified full managed profile commitment.
    pub protected_profile_digest: String,
    /// Validated public HTTPS upstream root, without credentials or query.
    pub upstream_base: String,
    /// Exact ordinary registry-relative path; no immutable import is implied.
    pub path: String,
    /// Exact path-derived capacity class, bound by the Native signature.
    pub class: HybridLiveDeliveryClass,
    /// Conservative full-response byte ceiling, independently measured at Worker.
    pub maximum_bytes: u64,
}

impl HybridLiveDeliveryTarget {
    /// Checks safe source containment, live classification and exact pin shape.
    ///
    /// # Errors
    /// Returns an error for unsafe paths, unsupported sources or malformed pins.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            [
                self.registry_id,
                self.registry_resource_version,
                self.mirror_resource_version,
                self.placement_id,
                self.placement_resource_version,
                self.write_spec_version,
                self.binding_id,
                self.binding_resource_version
            ]
            .into_iter()
            .all(|value| value > 0)
                && crate::direct_upload::valid_direct_digest(&self.protected_profile_digest)
                && self.maximum_bytes > 0
                && self.maximum_bytes <= crate::mirror_work::MIRROR_MAX_OBJECT_BYTES,
            "live mirror selection is malformed"
        );
        crate::url_guard::validate_http_surface_path(&self.path)?;
        anyhow::ensure!(
            crate::storage_work::valid_relative_path(&self.placement_prefix, true),
            "live placement prefix is malformed"
        );
        anyhow::ensure!(
            live_path(&self.path),
            "live delivery cannot replace verified import"
        );
        anyhow::ensure!(
            self.class == delivery_class(&self.path)
                && (self.class != HybridLiveDeliveryClass::Metadata
                    || self.maximum_bytes <= 128 * 1024),
            "live class or metadata ceiling differs"
        );
        let base = url::Url::parse(&self.upstream_base)?;
        crate::url_guard::is_safe_remote_url(&self.upstream_base)?;
        anyhow::ensure!(
            base.scheme() == "https" && base.query().is_none() && self.upstream_base.len() <= 2048,
            "live upstream root is unsupported"
        );
        self.upstream_url()?;
        Ok(())
    }

    /// Resolves the exact path without escaping the upstream root or origin.
    ///
    /// # Errors
    /// Returns an error for malformed URLs or path escapes.
    pub fn upstream_url(&self) -> anyhow::Result<url::Url> {
        crate::url_guard::validate_http_surface_path(&self.path)?;
        let base = url::Url::parse(&format!("{}/", self.upstream_base.trim_end_matches('/')))?;
        let joined = base.join(&self.path)?;
        anyhow::ensure!(
            joined.origin() == base.origin()
                && joined.path().starts_with(base.path())
                && joined.query().is_none()
                && joined.fragment().is_none(),
            "live upstream path escaped"
        );
        Ok(joined)
    }
}

/// Identifies paths served fresh rather than as verified loose objects or NARs.
#[must_use]
pub fn live_path(path: &str) -> bool {
    if path.starts_with("nar/") || (path.ends_with(".narinfo") && !path.contains('/')) {
        return false;
    }
    if let Some(rest) = path.strip_prefix("objects/") {
        return rest.starts_with("info/") || rest.starts_with("pack/");
    }
    true
}

/// Selects the signed capacity class from ordinary path semantics.
#[must_use]
pub fn delivery_class(path: &str) -> HybridLiveDeliveryClass {
    if path.starts_with("objects/pack/") || path.contains("/objects/pack/") {
        HybridLiveDeliveryClass::Pack
    } else {
        HybridLiveDeliveryClass::Metadata
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    version: u8,
    request: HybridIngressAssertion,
    target: HybridLiveDeliveryTarget,
}

impl HybridIngressKey {
    /// Signs fresh upstream delivery after current Native read authorization.
    ///
    /// # Errors
    /// Returns an error for unsupported methods, malformed pins or excessive wire size.
    pub fn sign_live_delivery(
        &self,
        request: &HybridIngressAssertion,
        target: HybridLiveDeliveryTarget,
    ) -> Result<String, HybridIngressError> {
        validate_assertion(request)?;
        validate_intrinsic_lifetime(request)?;
        if !matches!(request.method.as_str(), "GET" | "HEAD") {
            return Err(HybridIngressError::RequestMismatch);
        }
        target
            .validate()
            .map_err(|_| HybridIngressError::Malformed)?;
        let bytes = serde_json::to_vec(&Grant {
            version: 1,
            request: request.clone(),
            target,
        })
        .map_err(|_| HybridIngressError::Malformed)?;
        if bytes.len() > 4096 {
            return Err(HybridIngressError::Malformed);
        }
        let payload = URL_SAFE_NO_PAD.encode(bytes);
        let mut mac =
            HmacSha256::new_from_slice(&self.bytes).map_err(|_| HybridIngressError::WeakKey)?;
        mac.update(DOMAIN);
        mac.update(payload.as_bytes());
        Ok(format!(
            "{payload}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
    }

    /// Authenticates the exact fresh request and purpose before upstream dispatch.
    ///
    /// # Errors
    /// Returns an error for foreign contexts, stale grants, malformed sources or MACs.
    pub fn verify_live_delivery(
        &self,
        compact: &str,
        request: &HybridIngressAssertion,
        latest_now: i64,
    ) -> Result<HybridLiveDeliveryTarget, HybridIngressError> {
        validate_assertion(request)?;
        validate_intrinsic_lifetime(request)?;
        let (payload, bytes, signature_bytes) = decode_compact_frame(compact, 6144)?;
        if bytes.len() > 4096 {
            return Err(HybridIngressError::Malformed);
        }
        let mut mac =
            HmacSha256::new_from_slice(&self.bytes).map_err(|_| HybridIngressError::WeakKey)?;
        mac.update(DOMAIN);
        mac.update(payload.as_bytes());
        mac.verify_slice(&signature_bytes)
            .map_err(|_| HybridIngressError::InvalidSignature)?;
        let target = correlate_recorded_grant(&bytes, request)?;
        if latest_now < request.issued_at || latest_now >= request.expires_at {
            return Err(HybridIngressError::InvalidTime);
        }
        Ok(target)
    }
}

/// Decodes recorded live grant shape and exact original equality without authentication.
///
/// This checks neither a MAC nor a current clock and creates no authority proof.
/// Capture tooling must independently join the exact bytes with successful
/// Worker grant-verification and source/client evidence. Expired recordings may
/// be inspected; this function cannot authorize another source read.
///
/// # Errors
/// Returns an error for excessive framing, foreign originals or invalid source/class pins.
pub fn decode_hybrid_live_delivery_observation(
    compact: &str,
    original: &HybridIngressAssertion,
) -> Result<HybridLiveDeliveryTarget, HybridIngressError> {
    validate_assertion(original)?;
    validate_intrinsic_lifetime(original)?;
    let (_, bytes, _) = decode_compact_frame(compact, 6144)?;
    if bytes.len() > 4096 {
        return Err(HybridIngressError::Malformed);
    }
    correlate_recorded_grant(&bytes, original)
}

fn correlate_recorded_grant(
    bytes: &[u8],
    original: &HybridIngressAssertion,
) -> Result<HybridLiveDeliveryTarget, HybridIngressError> {
    let grant: Grant = serde_json::from_slice(bytes).map_err(|_| HybridIngressError::Malformed)?;
    grant
        .target
        .validate()
        .map_err(|_| HybridIngressError::Malformed)?;
    if grant.version != 1
        || grant.request != *original
        || !matches!(original.method.as_str(), "GET" | "HEAD")
    {
        return Err(HybridIngressError::RequestMismatch);
    }
    Ok(grant.target)
}

#[cfg(test)]
mod tests;
