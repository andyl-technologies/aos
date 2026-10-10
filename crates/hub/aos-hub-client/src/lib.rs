//! Typed clients for Hub management and authentication.
//!
//! [`hub`] provides Connect-JSON RPC calls using [`hub_types`]; [`login`]
//! implements OAuth provisioning, device authorization, refresh, and revocation.
//! This crate is independent of the build server client and its Connect runtime.

use anyhow::Context;

/// Typed Connect-JSON requests for the Hub control plane.
pub mod hub;

/// OAuth token exchanges and device authorization flows.
pub mod login;

pub use aos_hub_api as hub_types;
pub use aos_hub_api::{
    HashRangeV1, Placement, PlacementObservation, PlacementSpec, PlacementStatus,
};
pub use hub::{HubClient, HubRpc, HubSurfaceRef, hub_rpc};
pub use login::{
    DeviceAuthorization, DeviceTokenPoll, TokenGrant, exchange_token, poll_device_token,
    refresh_token, revoke_refresh_token, start_device_authorization,
};

/// Preserves the HTTP URL syntax accepted by existing Hub clients.
fn validate_base_url(base_url: &str) -> anyhow::Result<http::Uri> {
    if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
        anyhow::bail!("base_url must start with http:// or https://");
    }

    base_url.parse().context("invalid base URL")
}

#[cfg(test)]
mod tests {
    use super::validate_base_url;

    #[test]
    fn rejects_non_http_and_malformed_urls() {
        for input in ["file:///tmp/hub", "hub.example", "https://a b"] {
            assert!(validate_base_url(input).is_err(), "accepted {input}");
        }
    }

    #[test]
    fn preserves_http_base_paths() {
        let uri = validate_base_url("https://hub.example/prefix/").unwrap();
        assert_eq!(uri.to_string(), "https://hub.example/prefix/");
    }
}
