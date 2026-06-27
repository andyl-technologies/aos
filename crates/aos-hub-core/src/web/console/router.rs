//! The shared producer-console router (RFC-0004 Phase 5, console-dedup stage B).
//!
//! [`console_router`] mounts every console route whose handler is wasm-clean —
//! the ones ported into [`handlers`](super::handlers) — onto a stateless
//! [`axum::Router`] carrying a [`ConsoleDeps`] `State`. The native hub and the
//! Cloudflare Worker both merge this router into their top-level router, so the
//! producer console is served from one code path.
//!
//! The OIDC flow is shared here too (RFC-0004 Phase 5, console-dedup stage F):
//! its two network calls go through the
//! [`HttpClient`](super::ports::HttpClient) port, so it is wasm-clean.
//!
//! The git-backed config/change-request flow is shared here too (RFC-0004
//! Phase 5, stage H3): its base-commit reads go through the
//! [`SurfaceProvider`](crate::fetch::SurfaceProvider) read port and its
//! draft-object writes through the new
//! [`SurfaceWriteProvider`](crate::surface_write::SurfaceWriteProvider) write
//! port, so the loose-object/ref writes and the committed-file reads are
//! store-neutral. With it shared, **every** console route runs on both shells;
//! the only thing that stays native is the hub's nested-canonical fallback
//! ([`crate::web`] is single-segment; a registry whose canonical path has
//! slashes is dispatched by the hub's own catch-all, exactly as for the other
//! per-registry pages).
//!
//! # The wasm `Send` bridge
//!
//! `axum`'s `Handler` and `Router` state demand `Send + Sync`, but the Worker's
//! [`ConsoleDeps`] is `?Send` (its `Database`/`RateLimiter`/port futures hold
//! non-`Send` JS values). On the single-threaded Worker that is sound, so a
//! [`SendWrapper`](send_wrapper::SendWrapper) bridges both the state and the
//! handler futures exactly as [`crate::connect`] does for the RPC router. On
//! native the bridge is the identity.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, Uri};
use axum::routing::{get, post};
use axum::Router;

#[cfg(target_arch = "wasm32")]
use send_wrapper::SendWrapper;

use super::handlers;
use super::handlers::RequestStart;
use super::ports::ConsoleDeps;

/// The axum state type carrying [`ConsoleDeps`], made `Send + Sync`.
#[cfg(not(target_arch = "wasm32"))]
type SharedState = ConsoleDeps;
/// See the native definition — `SendWrapper`-wrapped on the wasm32 Worker.
#[cfg(target_arch = "wasm32")]
type SharedState = SendWrapper<ConsoleDeps>;

/// Wrap the deps as axum state (identity on native, `SendWrapper` on wasm).
#[cfg(not(target_arch = "wasm32"))]
fn into_state(deps: ConsoleDeps) -> SharedState {
    deps
}
/// See the native definition.
#[cfg(target_arch = "wasm32")]
fn into_state(deps: ConsoleDeps) -> SharedState {
    SendWrapper::new(deps)
}

/// Recover the [`ConsoleDeps`] from axum state (identity on native).
#[cfg(not(target_arch = "wasm32"))]
fn from_state(state: SharedState) -> ConsoleDeps {
    state
}
/// See the native definition — `take()` is sound on the single-threaded Worker.
#[cfg(target_arch = "wasm32")]
fn from_state(state: SharedState) -> ConsoleDeps {
    state.take()
}

/// Make a handler future satisfy axum's `Send` bound (identity on native).
#[cfg(not(target_arch = "wasm32"))]
fn send_bridge<F: std::future::Future>(fut: F) -> F {
    fut
}
/// See the native definition — `SendWrapper` makes the `?Send` future `Send`.
#[cfg(target_arch = "wasm32")]
fn send_bridge<F: std::future::Future>(fut: F) -> SendWrapper<F> {
    SendWrapper::new(fut)
}

/// Builds the shared producer-console router over `deps`.
///
/// The returned router is fully stated (`Router<()>`): it carries `deps` as its
/// `axum` `State`, so it can be `merge`d straight into a host router. It mounts
/// the cookie-authenticated management surface — the account profile and passkey
/// pages, the magic-link consume and logout endpoints, the org/project
/// dashboards, the instance-settings page, and the per-registry management pages
/// (settings, tokens, channel rollout, hosted keys, webhooks, SSO, serving, key
/// roster, publishes) — with the same paths the hub's router historically used.
///
/// The pre-auth `/login` (`GET` + `POST`) and `/login/password` (`POST`) paths
/// are served here too (RFC-0004 Phase 5, console-dedup stage D): they rate-limit
/// on the client IP through the runtime-neutral
/// [`CLIENT_IP_HEADER`](handlers::CLIENT_IP_HEADER) that each shell stamps on
/// ingress, so they need neither the native `ConnectInfo` socket nor a
/// reverse-proxy trust flag.
///
/// The pre-auth `/auth/passkey/begin` (`POST`) and `/activate` (`GET` + `POST`)
/// paths are served here too (RFC-0004 Phase 5, console-dedup stage E): like the
/// login paths they rate-limit on the runtime-neutral
/// [`CLIENT_IP_HEADER`](handlers::CLIENT_IP_HEADER) each shell stamps on ingress.
///
/// The OIDC flow (`/auth/sso` POST, `/auth/oidc/start` GET, `/auth/oidc/callback`
/// GET) is served here too (RFC-0004 Phase 5, console-dedup stage F): its token
/// exchange and JWKS fetch go through the
/// [`HttpClient`](super::ports::HttpClient) port, so it needs no native client.
///
/// The git-backed config/change-request flow (`/{slug}/-/settings/config`
/// GET + POST, `/{slug}/-/changes` GET) is served here too (RFC-0004 Phase 5,
/// stage H3): its base-commit reads go through the
/// [`SurfaceProvider`](crate::fetch::SurfaceProvider) port and its draft writes
/// through the [`SurfaceWriteProvider`](crate::surface_write::SurfaceWriteProvider)
/// port, so no route stays native-only.
#[must_use]
pub fn console_router(deps: ConsoleDeps) -> Router {
    // Each route is a thin closure that recovers `ConsoleDeps` from the
    // (possibly `SendWrapper`-bridged) state, forwards the request's extractors
    // to the inner handler, and bridges the returned future's `Send` bound. The
    // inner handlers ([`handlers`]) take `ConsoleDeps` by value plus their own
    // extractors, so they stay free of the wasm bridge details.
    Router::new()
        .route(
            "/login",
            get(|State(s): State<SharedState>, r: RequestStart| {
                send_bridge(handlers::login_form(from_state(s), r))
            })
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::login_submit(from_state(s), h, r, f))
                },
            ),
        )
        .route(
            "/login/password",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::login_password(from_state(s), h, r, f))
                },
            ),
        )
        .route(
            "/auth/magic",
            get(
                |State(s): State<SharedState>, r: RequestStart, q: Query<_>| {
                    send_bridge(handlers::magic_consume(from_state(s), r, q))
                },
            ),
        )
        .route(
            "/auth/sso",
            post(
                |State(s): State<SharedState>, r: RequestStart, f: axum::extract::Form<_>| {
                    send_bridge(handlers::login_sso(from_state(s), r, f))
                },
            ),
        )
        .route(
            "/auth/oidc/start",
            get(
                |State(s): State<SharedState>, r: RequestStart, q: Query<_>| {
                    send_bridge(handlers::oidc_start(from_state(s), r, q))
                },
            ),
        )
        .route(
            "/auth/oidc/callback",
            get(
                |State(s): State<SharedState>, r: RequestStart, q: Query<_>| {
                    send_bridge(handlers::oidc_callback(from_state(s), r, q))
                },
            ),
        )
        .route(
            "/logout",
            get(|State(s): State<SharedState>, h: HeaderMap| {
                send_bridge(handlers::logout(from_state(s), h))
            }),
        )
        .route(
            "/-/account",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart| {
                    send_bridge(handlers::account(from_state(s), h, r))
                },
            ),
        )
        .route(
            "/-/account/password",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::account_set_password(from_state(s), h, r, f))
                },
            ),
        )
        .route(
            "/-/reauth",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::reauth(from_state(s), h, r, f))
                },
            ),
        )
        .route(
            "/-/account/sessions/revoke-all",
            post(
                |State(s): State<SharedState>, h: HeaderMap, f: axum::extract::Form<_>| {
                    send_bridge(handlers::account_revoke_all_sessions(from_state(s), h, f))
                },
            ),
        )
        .route(
            "/-/account/passkeys",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart| {
                    send_bridge(handlers::passkeys(from_state(s), h, r))
                },
            ),
        )
        .route(
            "/-/account/passkeys/remove",
            post(
                |State(s): State<SharedState>, h: HeaderMap, f: axum::extract::Form<_>| {
                    send_bridge(handlers::passkeys_remove(from_state(s), h, f))
                },
            ),
        )
        .route(
            "/-/account/passkeys/begin",
            post(
                |State(s): State<SharedState>, h: HeaderMap, f: axum::extract::Form<_>| {
                    send_bridge(handlers::passkeys_begin(from_state(s), h, f))
                },
            ),
        )
        .route(
            "/-/account/passkeys/finish",
            post(
                |State(s): State<SharedState>, h: HeaderMap, j: axum::Json<_>| {
                    send_bridge(handlers::passkeys_finish(from_state(s), h, j))
                },
            ),
        )
        .route(
            "/auth/passkey/begin",
            post(|State(s): State<SharedState>, h: HeaderMap| {
                send_bridge(handlers::passkey_login_begin(from_state(s), h))
            }),
        )
        .route(
            "/auth/passkey/finish",
            post(|State(s): State<SharedState>, j: axum::Json<_>| {
                send_bridge(handlers::passkey_login_finish(from_state(s), j))
            }),
        )
        .route(
            "/activate",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, q: Query<_>| {
                    send_bridge(handlers::activate_form(from_state(s), h, r, q))
                },
            )
            .post(
                |State(s): State<SharedState>, h: HeaderMap, f: axum::extract::Form<_>| {
                    send_bridge(handlers::activate_submit(from_state(s), h, f))
                },
            ),
        )
        .route(
            "/new",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart| {
                    send_bridge(handlers::new_org_form(from_state(s), h, r))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::new_org_submit(from_state(s), h, r, f))
                },
            ),
        )
        .route(
            "/-/orgs",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, q: Query<_>| {
                    send_bridge(handlers::orgs(from_state(s), h, r, q))
                },
            ),
        )
        .route(
            "/-/caches",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart| {
                    send_bridge(handlers::caches(from_state(s), h, r))
                },
            ),
        )
        .route(
            "/-/org/{org}",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::org_dashboard(from_state(s), h, r, p, q))
                },
            ),
        )
        .route(
            "/-/org/{org}/audit",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::org_audit(from_state(s), h, r, p, q))
                },
            ),
        )
        .route(
            "/-/org/{org}/members",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::org_members(from_state(s), h, r, p, q))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_invite_member(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/members/remove",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_remove_member(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/members/role",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_member_role(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/projects",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::org_projects(from_state(s), h, r, p, q))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_create_project(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/projects/delete",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_delete_project(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/storage",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::org_storage(from_state(s), h, r, p, q))
                },
            ),
        )
        .route(
            "/-/org/{org}/danger",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::org_danger(from_state(s), h, r, p, q))
                },
            ),
        )
        .route(
            "/-/org/{org}/bindings",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_create_binding(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/bindings/delete",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_delete_binding(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/bindings/{id}",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::org_binding(from_state(s), h, r, p))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_binding_action(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::org_caches(from_state(s), h, r, p, q))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_create_cache(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/settings",
            get(|p: Path<_>| send_bridge(handlers::org_settings(p))),
        )
        .route(
            "/-/org/{org}/caches/{slug}",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::cache_detail(from_state(s), h, r, p))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_update(from_state(s), h, p, f))
                },
            ),
        )
        // Cache settings tabs (each renders the cache chrome with its section
        // active): Linked registries, GC & pins, and Danger.
        .route(
            "/-/org/{org}/caches/{slug}/links",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::cache_links(from_state(s), h, r, p))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/pins",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::cache_pins(from_state(s), h, r, p))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/danger",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::cache_danger(from_state(s), h, r, p))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/link",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_link(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/unlink",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_unlink(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/storage",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::cache_storage_tab(from_state(s), h, r, p))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_change_storage(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/serving",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::cache_serving_tab(from_state(s), h, r, p))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/advertise-frontend",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_set_advertise_frontend(
                        from_state(s),
                        h,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/gc",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_gc(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/pin/add",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_pin_add(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/pin/remove",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_pin_remove(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/delete",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_delete(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/registries/new",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::org_new_registry_form(from_state(s), h, r, p))
                },
            ),
        )
        .route(
            "/-/org/{org}/registries",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_create_registry(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/delete",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_delete(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/keys",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::org_keys(from_state(s), h, r, p))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_keys_action(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/webhooks",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::org_webhooks(from_state(s), h, r, p))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 b: axum::body::Bytes| {
                    send_bridge(handlers::org_webhooks_action(from_state(s), h, r, p, b))
                },
            ),
        )
        .route(
            "/-/org/{org}/sso",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::org_sso(from_state(s), h, r, p))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 b: axum::body::Bytes| {
                    send_bridge(handlers::org_sso_action(from_state(s), h, r, p, b))
                },
            ),
        )
        .route(
            "/-/instance",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart| {
                    send_bridge(handlers::instance_settings(from_state(s), h, r))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::instance_settings_action(from_state(s), h, r, f))
                },
            ),
        )
        .route(
            "/-/instance/storage",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart| {
                    send_bridge(handlers::instance_storage(from_state(s), h, r))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::instance_storage_action(from_state(s), h, r, f))
                },
            ),
        )
        .route(
            "/-/instance/branding",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart| {
                    send_bridge(handlers::instance_branding(from_state(s), h, r))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::instance_branding_action(from_state(s), h, r, f))
                },
            ),
        )
        .route(
            "/-/instance/serving",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart| {
                    send_bridge(handlers::instance_serving(from_state(s), h, r))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::instance_serving_action(from_state(s), h, r, f))
                },
            ),
        )
        .route(
            "/{slug}/-/settings",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::registry_settings(from_state(s), h, r, u, p))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/visibility",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_visibility(from_state(s), h, r, u, p, f))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/crawl",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_crawl_policy(
                        from_state(s),
                        h,
                        r,
                        u,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/storage",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::registry_storage(from_state(s), h, r, u, p))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_change_storage(
                        from_state(s),
                        h,
                        r,
                        u,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/advertise-frontend",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_set_advertise_frontend(
                        from_state(s),
                        h,
                        r,
                        u,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/caches",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::registry_caches(from_state(s), h, r, u, p))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/danger",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::registry_danger(from_state(s), h, r, u, p))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/cache-link",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_cache_link(from_state(s), h, r, u, p, f))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/cache-unlink",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_cache_unlink(
                        from_state(s),
                        h,
                        r,
                        u,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/delete",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_delete(from_state(s), h, u, p, f))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/serving",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::serving(from_state(s), h, r, u, p))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 b: axum::body::Bytes| {
                    send_bridge(handlers::serving_post(from_state(s), h, r, u, p, b))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/tokens",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::tokens(from_state(s), h, r, u, p, q))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::tokens_create(from_state(s), h, r, u, p, f))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/tokens/revoke",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::tokens_revoke(from_state(s), h, r, u, p, f))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/tokens/rotate",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::tokens_rotate(from_state(s), h, r, u, p, f))
                },
            ),
        )
        .route(
            "/{slug}/-/channels/{name}/console",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::channel_console(from_state(s), h, r, u, p))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::channel_advance(from_state(s), h, r, u, p, f))
                },
            ),
        )
        .route(
            "/{slug}/-/channels/{name}/advance",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::channel_advance_direct(
                        from_state(s),
                        h,
                        r,
                        u,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/{slug}/-/keys",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::keys(from_state(s), h, r, u, p, q))
                },
            ),
        )
        .route(
            "/{slug}/-/keys/rotate",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::keys_rotate(from_state(s), h, r, u, p))
                },
            ),
        )
        .route(
            "/{slug}/-/publishes",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::publishes(from_state(s), h, r, u, p))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/config",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::config_edit(from_state(s), h, r, u, p))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 b: String| {
                    send_bridge(handlers::config_submit(from_state(s), h, r, u, p, b))
                },
            ),
        )
        .route(
            "/{slug}/-/changes",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::changes(from_state(s), h, r, u, p))
                },
            ),
        )
        .route(
            "/{slug}/-/changes/{id}",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::change_detail(from_state(s), h, r, u, p))
                },
            ),
        )
        .route(
            "/{slug}/-/changes/{id}/comment",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::change_comment(from_state(s), h, u, p, f))
                },
            ),
        )
        .route(
            "/{slug}/-/changes/{id}/review",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::change_review(from_state(s), h, u, p, f))
                },
            ),
        )
        .route(
            "/{slug}/-/changes/{id}/close",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::change_close(from_state(s), h, u, p, f))
                },
            ),
        )
        .route(
            "/{slug}/-/changes/{id}/reopen",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::change_reopen(from_state(s), h, u, p, f))
                },
            ),
        )
        .with_state(into_state(deps))
}
