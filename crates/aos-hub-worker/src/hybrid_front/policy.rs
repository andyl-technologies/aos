//! Strict cache admission for explicitly public immutable origin responses.

use http::{HeaderMap, Method};
use sha2::{Digest as _, Sha256};

pub(crate) const MAX_CACHE_BODY_BYTES: usize = 256 * 1024;
pub(crate) const MAX_CACHE_AGE_SECS: i64 = 60;

/// Separates expensive browse pages from machine delivery and batched controls.
pub(crate) fn origin_class(
    method: &Method,
    url: &url::Url,
    headers: &HeaderMap,
) -> super::OriginClass {
    let page = matches!(*method, Method::GET | Method::HEAD)
        && (url.path().starts_with("/-/")
            || crate::requestshard::anonymous_browse_route(
                method.as_str(),
                url.path(),
                headers.get("accept").and_then(|value| value.to_str().ok()),
                false,
                false,
            )
            .is_some());
    if page {
        super::OriginClass::Browse
    } else {
        super::OriginClass::Control
    }
}

/// Addresses small immutable bytes only after an exact fresh delivery grant.
pub(crate) fn delivery_key(
    deployment: &str,
    url: &url::Url,
    method: &Method,
    headers: &HeaderMap,
    target: &aos_hub_core::hybrid_ingress::HybridDeliveryTarget,
) -> Option<String> {
    if *method != Method::GET
        || url.scheme() != "https"
        || url.query().is_some()
        || headers.contains_key("authorization")
        || headers.contains_key("cookie")
        || headers.contains_key("range")
        || target.object_size > MAX_CACHE_BODY_BYTES as u64
        || target
            .planned_response
            .as_ref()
            .is_some_and(|plan| plan.status != 200)
    {
        return None;
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert("cache-control", target.cache_control.parse().ok()?);
    if let Some(plan) = &target.planned_response {
        for (name, value) in &plan.headers {
            response_headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).ok()?,
                value.parse().ok()?,
            );
        }
    }
    response_age(
        200,
        &response_headers,
        usize::try_from(target.object_size).ok()?,
    )?;
    let mut digest = Sha256::new();
    let commitment = serde_json::to_vec(target).ok()?;
    for bytes in [
        b"aos-hybrid-delivery-cache-v1".as_slice(),
        deployment.as_bytes(),
        url.as_str().as_bytes(),
        commitment.as_slice(),
    ] {
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    for name in ["accept", "accept-encoding", "accept-language"] {
        for value in headers.get_all(name) {
            digest.update((value.as_bytes().len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        digest.update(0_u64.to_be_bytes());
    }
    Some(format!(
        "{}/_internal/hybrid-byte-cache/{}",
        url.origin().ascii_serialization(),
        hex::encode(digest.finalize())
    ))
}

/// Binds anonymous request variants to one deployment and asset build.
pub(crate) fn request_key(
    deployment: &str,
    asset_version: &str,
    method: &Method,
    url: &url::Url,
    headers: &HeaderMap,
) -> Option<String> {
    if *method != Method::GET
        || url.scheme() != "https"
        || url.query().is_some()
        || url.fragment().is_some()
        || headers.contains_key("authorization")
        || headers.contains_key("cookie")
        || headers.contains_key("range")
        || headers.contains_key("transfer-encoding")
        || headers
            .get("content-length")
            .is_some_and(|value| value.as_bytes() != b"0")
        || headers.keys().any(|name| name.as_str().starts_with("if-"))
        || crate::requestshard::anonymous_browse_route(
            method.as_str(),
            url.path(),
            headers.get("accept").and_then(|value| value.to_str().ok()),
            false,
            false,
        )
        .is_none()
    {
        return None;
    }

    let mut digest = Sha256::new();
    for value in [
        "aos-hybrid-public-cache-v1",
        deployment,
        asset_version,
        url.as_str(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    for name in ["accept", "accept-encoding", "accept-language"] {
        for value in headers.get_all(name) {
            digest.update((value.as_bytes().len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        digest.update(0_u64.to_be_bytes());
    }
    Some(format!(
        "{}/_internal/hybrid-public-cache/{}",
        url.origin().ascii_serialization(),
        hex::encode(digest.finalize())
    ))
}

/// Returns the bounded freshness that Native explicitly permits.
///
/// Mutable HTML without an invalidation contract stays at Native. Neither a
/// familiar route nor a successful status upgrades private or unmarked content.
pub(crate) fn response_age(status: u16, headers: &HeaderMap, body_bytes: usize) -> Option<i64> {
    if status != 200 || body_bytes > MAX_CACHE_BODY_BYTES || headers.contains_key("set-cookie") {
        return None;
    }
    let mut public = false;
    let mut immutable = false;
    let mut max_age = None;
    let mut shared_age = None;
    for value in headers.get_all("cache-control") {
        for directive in value.to_str().ok()?.split(',').map(str::trim) {
            let directive = directive.to_ascii_lowercase();
            match directive.as_str() {
                "private" | "no-store" | "no-cache" | "must-revalidate" | "proxy-revalidate" => {
                    return None;
                }
                "public" => public = true,
                "immutable" => immutable = true,
                _ => {
                    if directive.starts_with("private=") || directive.starts_with("no-cache=") {
                        return None;
                    }
                    if let Some(value) = directive.strip_prefix("max-age=") {
                        if max_age.is_some() {
                            return None;
                        }
                        max_age = Some(value.parse::<i64>().ok()?);
                    }
                    if let Some(value) = directive.strip_prefix("s-maxage=") {
                        if shared_age.is_some() {
                            return None;
                        }
                        shared_age = Some(value.parse::<i64>().ok()?);
                    }
                }
            }
        }
    }
    if !public || !immutable || max_age.is_none_or(|age| age <= 0) {
        return None;
    }
    for value in headers.get_all("vary") {
        if value.to_str().ok()?.split(',').any(|name| {
            !matches!(
                name.trim().to_ascii_lowercase().as_str(),
                "accept" | "accept-encoding" | "accept-language"
            )
        }) {
            return None;
        }
    }
    let mut age_headers = headers.get_all("age").iter();
    let age = age_headers
        .next()
        .map(|value| value.to_str().ok()?.parse::<i64>().ok())
        .unwrap_or(Some(0))?;
    if age < 0 || age_headers.next().is_some() {
        return None;
    }
    let fresh = max_age?
        .min(shared_age.unwrap_or(i64::MAX))
        .checked_sub(age)?;
    (fresh > 0).then_some(fresh.min(MAX_CACHE_AGE_SECS))
}
