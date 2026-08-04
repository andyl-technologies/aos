//! Wasm-clean message structs for the `aos.hub.v1` Hub API.
//!
//! RFC-0004 Phase 5 unifies the native registry hub and the Cloudflare Worker
//! on one shared `axum` router. Because the `connectrpc` server runtime cannot
//! target `wasm32-unknown-unknown` (it pulls `hyper`/`tokio`/`zstd-sys`), the
//! hub serves a single **Connect-JSON** transport — plain JSON over HTTP
//! (`POST /aos.hub.v1.{Service}/{Method}`) — as ordinary `axum` handlers
//! on both targets. This crate holds the request/response **message types** for
//! that surface, generated from the `.proto` (owned by `aos-proto`) with
//! `prost-build` + `serde` derives and **nothing else**: no `connectrpc`, no
//! `buffa`, no `hyper`/`tokio`. That keeps it wasm-clean, so the worker, the
//! native hub (`aos-hub-core`'s shared handlers), and the `aos-remote`
//! Connect-JSON client all share one set of types.
//!
//! # Wire format
//!
//! The structs serialize as the Connect-JSON request/response bodies using
//! canonical proto3 JSON field names (`lowerCamelCase`). Oneof fields are
//! flattened to their named alternatives; for example, a topology surface is
//! `{ "registrySlug": "acme/cdn" }` rather than a Rust-shaped `target`
//! wrapper. The `prost` binary codec the derives also provide is unused on the
//! wire.
//!
//! ```text
//! POST /aos.hub.v1.RegistryService/GetRegistry
//! Content-Type: application/json
//! { "slug": "acme/cdn" }
//!   -> 200 { "registry": { "slug": "acme/cdn", "name": "…", … } }
//!   -> 4xx { "code": "not_found", "message": "no such registry" }
//! ```
//!
//! The generated module mirrors the proto package path: the
//! `aos.hub.v1` messages are re-exported at the crate root.

#![allow(clippy::all)]

/// Canonical JSON adapter for the generated [`SurfaceRef`] oneof.
///
/// The empty variant represents an unset proto oneof. The three payload
/// structs deny unknown fields so JSON containing both oneof alternatives is
/// rejected instead of silently choosing whichever untagged variant happens
/// to deserialize first.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum SurfaceRefJson {
    Registry(RegistrySurfaceRefJson),
    Cache(CacheSurfaceRefJson),
    Empty(EmptySurfaceRefJson),
}

/// JSON payload for the registry alternative of [`SurfaceRefJson`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RegistrySurfaceRefJson {
    registry_slug: String,
}

/// JSON payload for the binary-cache alternative of [`SurfaceRefJson`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CacheSurfaceRefJson {
    cache_slug: String,
}

/// JSON payload for an unset [`SurfaceRef`] oneof.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EmptySurfaceRefJson {}

/// The generated `aos.hub.v1` message structs.
///
/// `prost-build` emits one file per proto package; this is the
/// `aos.hub.v1` package. The contents are re-exported at the crate root
/// (see the [`pub use`] below) so consumers write `aos_proto_types::Registry`.
pub mod hub_v1 {
    include!(concat!(env!("OUT_DIR"), "/aos.hub.v1.rs"));
}

pub use hub_v1::*;

impl From<SurfaceRefJson> for SurfaceRef {
    fn from(value: SurfaceRefJson) -> Self {
        let target = match value {
            SurfaceRefJson::Registry(value) => {
                Some(surface_ref::Target::RegistrySlug(value.registry_slug))
            }
            SurfaceRefJson::Cache(value) => Some(surface_ref::Target::CacheSlug(value.cache_slug)),
            SurfaceRefJson::Empty(_) => None,
        };
        Self { target }
    }
}

impl From<SurfaceRef> for SurfaceRefJson {
    fn from(value: SurfaceRef) -> Self {
        match value.target {
            Some(surface_ref::Target::RegistrySlug(registry_slug)) => {
                Self::Registry(RegistrySurfaceRefJson { registry_slug })
            }
            Some(surface_ref::Target::CacheSlug(cache_slug)) => {
                Self::Cache(CacheSurfaceRefJson { cache_slug })
            }
            None => Self::Empty(EmptySurfaceRefJson::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{surface_ref, SurfaceRef};

    #[test]
    fn surface_ref_uses_canonical_flat_json_for_each_oneof_alternative() {
        for (surface, expected) in [
            (
                SurfaceRef {
                    target: Some(surface_ref::Target::RegistrySlug("acme/main".into())),
                },
                serde_json::json!({ "registrySlug": "acme/main" }),
            ),
            (
                SurfaceRef {
                    target: Some(surface_ref::Target::CacheSlug("acme/shared".into())),
                },
                serde_json::json!({ "cacheSlug": "acme/shared" }),
            ),
            (SurfaceRef { target: None }, serde_json::json!({})),
        ] {
            let json = serde_json::to_value(&surface).unwrap();
            assert_eq!(json, expected);
            assert_eq!(serde_json::from_value::<SurfaceRef>(json).unwrap(), surface);
        }
    }

    #[test]
    fn surface_ref_rejects_wrapped_ambiguous_and_unknown_json() {
        for invalid in [
            serde_json::json!({ "target": { "registrySlug": "acme/main" } }),
            serde_json::json!({
                "registrySlug": "acme/main",
                "cacheSlug": "acme/shared"
            }),
            serde_json::json!({ "registry_slug": "acme/main" }),
            serde_json::json!({ "unknown": "acme/main" }),
        ] {
            assert!(serde_json::from_value::<SurfaceRef>(invalid).is_err());
        }
    }

    #[test]
    fn generated_surface_ref_uses_the_custom_adapter_without_flatten() {
        let generated = include_str!(concat!(env!("OUT_DIR"), "/aos.hub.v1.rs"));
        assert!(generated
            .contains("serde(from = \"crate::SurfaceRefJson\", into = \"crate::SurfaceRefJson\")"));
        assert!(!generated.contains("serde(flatten)"));
    }
}
