//! The shared producer-console router.
//!
//! [`console_router`] mounts every console route whose handler is wasm-clean —
//! the ones ported into [`handlers`](super::handlers) — onto a stateless
//! [`axum::Router`] carrying a [`ConsoleDeps`] `State`. The native hub and the
//! Cloudflare Worker both merge this router into their top-level router, so the
//! producer console is served from one code path.
//!
//! The OIDC flow is shared here too:
//! its two network calls go through the
//! [`HttpClient`](super::ports::HttpClient) port, so it is wasm-clean.
//!
//! The git-backed config/change-request flow is shared here too: its base-commit
//! reads go through the
//! [`SurfaceProvider`](crate::fetch::SurfaceProvider) read port and its
//! draft-object writes through the new
//! [`SurfaceWriteProvider`](crate::surface_write::SurfaceWriteProvider) write
//! port, so the loose-object/ref writes and the committed-file reads are
//! store-neutral. Every console route runs on both shells. Each runtime offers
//! unmatched nested-canonical paths to the shared
//! [`dispatch_nested`](super::nested::dispatch_nested) dispatcher before its
//! machine-facade fallback.
//!
//! # The wasm `Send` bridge
//!
//! `axum`'s `Handler` and `Router` state demand `Send + Sync`, but the Worker's
//! [`ConsoleDeps`] is `?Send` (its `Database`/`RateLimiter`/port futures hold
//! non-`Send` JS values). On the single-threaded Worker that is sound, so a
//! [`SendWrapper`](send_wrapper::SendWrapper) bridges both the state and the
//! handler futures exactly as [`crate::connect`] does for the RPC router. On
//! native the bridge is the identity.

use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, MethodRouter};
use axum::Router;

#[cfg(target_arch = "wasm32")]
use send_wrapper::SendWrapper;

use super::handlers;
use super::handlers::RequestStart;
use super::manifest::{declared_route, route_methods_for_path, ConsoleRouteMatched};
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

/// Rejects HEAD explicitly on console reads as a route-local safeguard.
///
/// Axum normally supplies HEAD automatically for a GET route. The nested
/// console classifier deliberately accepts only declared GET/POST methods, so
/// flat and nested registry settings must override that implicit behavior to
/// expose one method contract on both shells. The manifest middleware is the
/// authoritative method guard for all routes.
async fn method_not_allowed() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

/// Enforces the manifest method contract before Axum's implicit HEAD handling.
async fn enforce_declared_route(request: Request, next: Next) -> Response {
    let methods = route_methods_for_path(request.uri().path());
    let allowed = methods.is_some_and(|declared| {
        (*request.method() == Method::GET && declared.allows_get())
            || (*request.method() == Method::POST && declared.allows_post())
    });
    let mut response = if allowed {
        next.run(request).await
    } else if let Some(methods) = methods {
        let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
        response.headers_mut().insert(
            header::ALLOW,
            HeaderValue::from_static(methods.allow_header()),
        );
        response
    } else {
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    };
    response.extensions_mut().insert(ConsoleRouteMatched);
    response
}

/// Router builder that rejects route declarations absent from the manifest.
///
/// This makes router-to-manifest parity constructive: every `.route(...)` call
/// below passes through this type, while request tests prove the reverse
/// manifest-to-router direction through [`ConsoleRouteMatched`].
struct DeclaredRouter(Router<SharedState>);

impl DeclaredRouter {
    fn new() -> Self {
        Self(Router::new())
    }

    fn route(self, path: &'static str, method_router: MethodRouter<SharedState>) -> Self {
        assert!(
            declared_route(path).is_some(),
            "console router path is absent from its manifest: {path}",
        );
        Self(self.0.route(path, method_router))
    }

    fn finish(self, deps: ConsoleDeps) -> Router {
        self.0
            .route_layer(axum::middleware::from_fn(enforce_declared_route))
            .with_state(into_state(deps))
    }
}

/// Builds the shared producer-console router over `deps`.
///
/// The returned router is fully stated (`Router<()>`): it carries `deps` as its
/// `axum` `State`, so it can be `merge`d straight into a host router. It mounts
/// the cookie-authenticated management surface — the account profile and passkey
/// pages, the magic-link consume and logout endpoints, the org/project
/// dashboards, the instance-settings page, and the per-registry management pages
/// (overview, access, tokens, channels, publish history, configuration, hosted
/// keys, webhooks, SSO, delivery routes, and cache placements) — under the
/// canonical topology resource paths. Removed storage, serving, and
/// cache-association aliases are intentionally absent.
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
/// The git-backed config/change-request flow (`/{slug}/-/settings/configuration`
/// GET + POST, `/{slug}/-/settings/change-requests` GET) is served here too:
/// its base-commit reads go through the
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
    DeclaredRouter::new()
        .route(
            "/oauth2/device_authorization",
            post(
                |State(s): State<SharedState>, h: HeaderMap, f: axum::extract::Form<_>| {
                    send_bridge(handlers::device_authorization(from_state(s), h, f))
                },
            ),
        )
        .route(
            "/oauth2/token",
            post(
                |State(s): State<SharedState>, h: HeaderMap, f: axum::extract::Form<_>| {
                    send_bridge(handlers::oauth_token(from_state(s), h, f))
                },
            ),
        )
        .route(
            "/oauth2/revoke",
            post(
                |State(s): State<SharedState>, h: HeaderMap, f: axum::extract::Form<_>| {
                    send_bridge(handlers::oauth_revoke(from_state(s), h, f))
                },
            ),
        )
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
            "/-/auth/session-token",
            post(|State(s): State<SharedState>, h: HeaderMap| {
                send_bridge(handlers::session_token(from_state(s), h))
            }),
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
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart| {
                    send_bridge(handlers::logout_form(from_state(s), h, r))
                },
            )
            .post(
                |State(s): State<SharedState>, h: HeaderMap, f: axum::extract::Form<_>| {
                    send_bridge(handlers::logout(from_state(s), h, f))
                },
            ),
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
            "/-/instance/identity-and-signup",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart| {
                    send_bridge(handlers::instance_identity(from_state(s), h, r))
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
            "/-/orgs/new",
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
            "/-/org/{org}/audit-log",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::org_audit_log(from_state(s), h, r, p, q))
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
            ),
        )
        .route(
            "/-/org/{org}/members/invitations/new",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::org_new_resource(
                        from_state(s),
                        h,
                        r,
                        p,
                        "member-invitation",
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/members/invitations",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_invite_member(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/invitations/accept",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::invitation_acceptance(from_state(s), h, r, p, q))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::accept_invitation(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/members/invitations/{invitation_id}/cancel",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cancel_invitation(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/members/{principal}/remove",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_remove_member(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/members/{principal}/role",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_member_role(from_state(s), h, r, p, f))
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
            ),
        )
        .route(
            "/-/org/{org}/storage-bindings",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::org_storage_bindings(from_state(s), h, r, p, q))
                },
            ),
        )
        .route(
            "/-/org/{org}/storage-bindings/plan-create",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_plan_create_binding(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/storage-bindings/new",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::org_new_resource(
                        from_state(s),
                        h,
                        r,
                        p,
                        "storage-binding",
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/domains",
            get(|State(s): State<SharedState>, h, r, p, q| {
                send_bridge(handlers::org_settings_collection(
                    from_state(s),
                    h,
                    r,
                    p,
                    q,
                    "domains",
                ))
            }),
        )
        .route(
            "/-/org/{org}/network-boundaries",
            get(|State(s): State<SharedState>, h, r, p, q| {
                send_bridge(handlers::org_settings_collection(
                    from_state(s),
                    h,
                    r,
                    p,
                    q,
                    "network-boundaries",
                ))
            }),
        )
        .route(
            "/-/org/{org}/delivery-endpoints",
            get(|State(s): State<SharedState>, h, r, p, q| {
                send_bridge(handlers::org_settings_collection(
                    from_state(s),
                    h,
                    r,
                    p,
                    q,
                    "delivery-endpoints",
                ))
            }),
        )
        .route(
            "/-/org/{org}/storage-gateways",
            get(|State(s): State<SharedState>, h, r, p, q| {
                send_bridge(handlers::org_settings_collection(
                    from_state(s),
                    h,
                    r,
                    p,
                    q,
                    "storage-gateways",
                ))
            }),
        )
        .route(
            "/-/org/{org}/topology-defaults",
            get(|State(s): State<SharedState>, h, r, p, q| {
                send_bridge(handlers::org_settings_collection(
                    from_state(s),
                    h,
                    r,
                    p,
                    q,
                    "topology-defaults",
                ))
            }),
        )
        .route(
            "/-/org/{org}/identity-and-access",
            get(|State(s): State<SharedState>, h, r, p, q| {
                send_bridge(handlers::org_settings_collection(
                    from_state(s),
                    h,
                    r,
                    p,
                    q,
                    "identity-and-access",
                ))
            }),
        )
        .route(
            "/-/org/{org}/operations",
            get(|State(s): State<SharedState>, h, r, p, q| {
                send_bridge(handlers::org_settings_collection(
                    from_state(s),
                    h,
                    r,
                    p,
                    q,
                    "operations",
                ))
            }),
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
            "/-/org/{org}/storage-bindings/create",
            post(|State(s): State<SharedState>, h, p, f| {
                send_bridge(handlers::org_apply_create_binding(from_state(s), h, p, f))
            }),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/plan-delete",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_plan_delete_binding(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/delete",
            post(|State(s): State<SharedState>, h, p, f| {
                send_bridge(handlers::org_delete_binding(from_state(s), h, p, f))
            }),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::org_binding(from_state(s), h, r, p))
                },
            ),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/credentials",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::org_binding_section(
                    from_state(s),
                    h,
                    r,
                    p,
                    "credentials",
                ))
            }),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/write-revisions",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::org_binding_section(
                    from_state(s),
                    h,
                    r,
                    p,
                    "write-revisions",
                ))
            }),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/consumer-grants",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::org_binding_section(
                    from_state(s),
                    h,
                    r,
                    p,
                    "consumer-grants",
                ))
            }),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/placements",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::org_binding_section(
                    from_state(s),
                    h,
                    r,
                    p,
                    "placements",
                ))
            }),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/storage-gateways",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::org_binding_section(
                    from_state(s),
                    h,
                    r,
                    p,
                    "storage-gateways",
                ))
            }),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/danger",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::org_binding_section(
                    from_state(s),
                    h,
                    r,
                    p,
                    "danger",
                ))
            }),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/credentials/plan-set",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_plan_set_binding_credential(
                        from_state(s),
                        h,
                        r,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/credentials/set",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_set_binding_credential(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/credentials/plan-rotate",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_plan_rotate_binding_credential(
                        from_state(s),
                        h,
                        r,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/credentials/rotate",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_rotate_binding_credential(
                        from_state(s),
                        h,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/consumer-grants/plan-grant",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_plan_grant_binding_scope(
                        from_state(s),
                        h,
                        r,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/consumer-grants/grant",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_grant_binding_scope(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/consumer-grants/plan-revoke",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_plan_revoke_binding_scope(
                        from_state(s),
                        h,
                        r,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/storage-bindings/{binding}/consumer-grants/revoke",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_revoke_binding_scope(from_state(s), h, p, f))
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
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}",
            // The canonical cache landing page is deliberately read-only.
            // Mutable cache policy lives at the General section below.
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::cache_detail(from_state(s), h, r, p))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/access",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::cache_access(from_state(s), h, r, p))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/access/plan-update",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_plan_update(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/access/update",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_update(from_state(s), h, p, f))
                },
            ),
        )
        // Cache settings sections, each rendered in the same grouped chrome.
        .route(
            "/-/org/{org}/caches/{slug}/retention-subscriptions",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::cache_retention_subscriptions(
                        from_state(s),
                        h,
                        r,
                        p,
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/population-targets",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::cache_population_targets(from_state(s), h, r, p))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/manual-roots",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::cache_manual_roots(from_state(s), h, r, p))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/objects",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::cache_objects(from_state(s), h, r, p))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/signing-key",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::cache_signing_key(from_state(s), h, r, p))
            })
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_signing_key_action(
                        from_state(s),
                        h,
                        r,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/operations",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::cache_operations(from_state(s), h, r, p))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/garbage-collection",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::cache_garbage_collection(from_state(s), h, r, p))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/garbage-collection/plans",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::cache_gc_section(
                    from_state(s),
                    h,
                    r,
                    p,
                    "gc-plans",
                ))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/garbage-collection/runs",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::cache_gc_section(
                    from_state(s),
                    h,
                    r,
                    p,
                    "gc-runs",
                ))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/garbage-collection/jobs",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::cache_gc_section(
                    from_state(s),
                    h,
                    r,
                    p,
                    "gc-jobs",
                ))
            }),
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
            "/-/org/{org}/caches/{slug}/placements",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::cache_placements(from_state(s), h, r, p))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placement-policies",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::cache_placement_policies(from_state(s), h, r, p))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placement-equivalences",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::cache_placement_equivalences(
                    from_state(s),
                    h,
                    r,
                    p,
                ))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/new",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::cache_new_placement(from_state(s), h, r, p))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/plan-create",
            post(|State(s): State<SharedState>, h, r, p, f| {
                send_bridge(handlers::cache_plan_create_placement(
                    from_state(s),
                    h,
                    r,
                    p,
                    f,
                ))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/create",
            post(|State(s): State<SharedState>, h, p, f| {
                send_bridge(handlers::cache_create_placement(from_state(s), h, p, f))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/{placement}/plan-promote",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_plan_promote_placement(
                        from_state(s),
                        h,
                        r,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/{placement}/promote",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_promote_placement(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/{placement}/plan-update",
            post(|State(s): State<SharedState>, h, r, p, f| {
                send_bridge(handlers::cache_plan_update_placement(
                    from_state(s),
                    h,
                    r,
                    p,
                    f,
                ))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/{placement}/update",
            post(|State(s): State<SharedState>, h, p, f| {
                send_bridge(handlers::cache_update_placement(from_state(s), h, p, f))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/{placement}/plan-drain",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_plan_drain_placement(
                        from_state(s),
                        h,
                        r,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/{placement}/drain",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_drain_placement(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/{placement}/plan-delete",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_plan_delete_placement(
                        from_state(s),
                        h,
                        r,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/{placement}/delete",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_delete_placement(from_state(s), h, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/plan-remove-write-authority",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_plan_remove_write_authority(
                        from_state(s),
                        h,
                        r,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/remove-write-authority",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_remove_write_authority(
                        from_state(s),
                        h,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/plan-cancel-promotion",
            post(|State(s): State<SharedState>, h, r, p, f| {
                send_bridge(handlers::cache_plan_cancel_placement_promotion(
                    from_state(s),
                    h,
                    r,
                    p,
                    f,
                ))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/placements/cancel-promotion",
            post(|State(s): State<SharedState>, h, p, f| {
                send_bridge(handlers::cache_cancel_placement_promotion(
                    from_state(s),
                    h,
                    p,
                    f,
                ))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/delivery-routes",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::cache_delivery(from_state(s), h, r, p))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/delivery-routes/canonical-audiences",
            get(|State(s): State<SharedState>, h, r, p| {
                send_bridge(handlers::cache_canonical_audiences(from_state(s), h, r, p))
            }),
        )
        .route(
            "/-/org/{org}/caches/{slug}/danger/plan-delete",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::cache_plan_delete(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/caches/{slug}/danger/delete",
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
            "/-/org/{org}/registries",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::org_registries(from_state(s), h, r, p, q))
                },
            ),
        )
        .route(
            "/-/org/{org}/danger/delete",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::org_delete(from_state(s), h, r, p, f))
                },
            ),
        )
        .route(
            "/-/org/{org}/signing-keys",
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
            "/-/org/{org}/signing-keys/new",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::org_new_resource(
                        from_state(s),
                        h,
                        r,
                        p,
                        "signing-key",
                    ))
                },
            ),
        )
        .route(
            "/-/org/{org}/webhooks",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::org_webhooks(from_state(s), h, r, p))
                },
            ),
        )
        .route(
            "/-/org/{org}/webhooks/new",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart, p: Path<_>| {
                    send_bridge(handlers::org_new_resource(
                        from_state(s),
                        h,
                        r,
                        p,
                        "webhook",
                    ))
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
            ),
        )
        .route(
            "/-/instance/storage-bindings",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart| {
                    send_bridge(handlers::instance_storage(from_state(s), h, r))
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
            "/-/instance/resource-defaults",
            get(
                |State(s): State<SharedState>, h: HeaderMap, r: RequestStart| {
                    send_bridge(handlers::instance_resource_defaults(from_state(s), h, r))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::instance_resource_defaults_action(
                        from_state(s),
                        h,
                        r,
                        f,
                    ))
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
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/access",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::registry_access(from_state(s), h, r, u, p))
                },
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/placements",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::registry_placements(from_state(s), h, r, u, p))
                },
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/placement-policies",
            get(|State(s): State<SharedState>, h, r, u, p| {
                send_bridge(handlers::registry_placement_policies(
                    from_state(s),
                    h,
                    r,
                    u,
                    p,
                ))
            })
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/placement-equivalences",
            get(|State(s): State<SharedState>, h, r, u, p| {
                send_bridge(handlers::registry_placement_equivalences(
                    from_state(s),
                    h,
                    r,
                    u,
                    p,
                ))
            })
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/placements/new",
            get(|State(s): State<SharedState>, h, r, u, p| {
                send_bridge(handlers::registry_new_placement(from_state(s), h, r, u, p))
            }),
        )
        .route(
            "/{slug}/-/settings/placements/plan-create",
            post(|State(s): State<SharedState>, h, r, u, p, f| {
                send_bridge(handlers::registry_plan_create_placement(
                    from_state(s),
                    h,
                    r,
                    u,
                    p,
                    f,
                ))
            }),
        )
        .route(
            "/{slug}/-/settings/placements/create",
            post(|State(s): State<SharedState>, h, u, p, f| {
                send_bridge(handlers::registry_create_placement(
                    from_state(s),
                    h,
                    u,
                    p,
                    f,
                ))
            }),
        )
        .route(
            "/{slug}/-/settings/placements/{placement}/plan-promote",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_plan_promote_placement(
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
            "/{slug}/-/settings/placements/{placement}/promote",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_promote_placement(
                        from_state(s),
                        h,
                        u,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/placements/{placement}/plan-update",
            post(|State(s): State<SharedState>, h, r, u, p, f| {
                send_bridge(handlers::registry_plan_update_placement(
                    from_state(s),
                    h,
                    r,
                    u,
                    p,
                    f,
                ))
            }),
        )
        .route(
            "/{slug}/-/settings/placements/{placement}/update",
            post(|State(s): State<SharedState>, h, u, p, f| {
                send_bridge(handlers::registry_update_placement(
                    from_state(s),
                    h,
                    u,
                    p,
                    f,
                ))
            }),
        )
        .route(
            "/{slug}/-/settings/placements/{placement}/plan-drain",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_plan_drain_placement(
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
            "/{slug}/-/settings/placements/{placement}/drain",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_drain_placement(
                        from_state(s),
                        h,
                        u,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/placements/{placement}/plan-delete",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_plan_delete_placement(
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
            "/{slug}/-/settings/placements/{placement}/delete",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_delete_placement(
                        from_state(s),
                        h,
                        u,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/placements/plan-remove-write-authority",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_plan_remove_write_authority(
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
            "/{slug}/-/settings/placements/remove-write-authority",
            post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::registry_remove_write_authority(
                        from_state(s),
                        h,
                        u,
                        p,
                        f,
                    ))
                },
            ),
        )
        .route(
            "/{slug}/-/settings/placements/plan-cancel-promotion",
            post(|State(s): State<SharedState>, h, r, u, p, f| {
                send_bridge(handlers::registry_plan_cancel_placement_promotion(
                    from_state(s),
                    h,
                    r,
                    u,
                    p,
                    f,
                ))
            }),
        )
        .route(
            "/{slug}/-/settings/placements/cancel-promotion",
            post(|State(s): State<SharedState>, h, u, p, f| {
                send_bridge(handlers::registry_cancel_placement_promotion(
                    from_state(s),
                    h,
                    u,
                    p,
                    f,
                ))
            }),
        )
        .route(
            "/{slug}/-/settings/cache-stack",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::registry_cache_stack(from_state(s), h, r, u, p))
                },
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/retention-consumers",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::registry_retention_consumers(
                        from_state(s),
                        h,
                        r,
                        u,
                        p,
                    ))
                },
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/population-targets",
            get(|State(s): State<SharedState>, h, r, u, p| {
                send_bridge(handlers::registry_population_targets(
                    from_state(s),
                    h,
                    r,
                    u,
                    p,
                ))
            })
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/operations",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::registry_operations(from_state(s), h, r, u, p))
                },
            )
            .head(method_not_allowed),
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
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/delivery-routes",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::registry_delivery(from_state(s), h, r, u, p))
                },
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/delivery-routes/canonical-audiences",
            get(|State(s): State<SharedState>, h, r, u, p| {
                send_bridge(handlers::registry_canonical_audiences(
                    from_state(s),
                    h,
                    r,
                    u,
                    p,
                ))
            })
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/upstream-mirror",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::registry_upstream_mirror(
                        from_state(s),
                        h,
                        r,
                        u,
                        p,
                    ))
                },
            )
            .head(method_not_allowed),
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
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/tokens/{token}/revoke",
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
            "/{slug}/-/settings/channels",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::registry_channels(from_state(s), h, r, u, p))
                },
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/channels/{name}",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::channel_console(from_state(s), h, r, u, p))
                },
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/signing-keys",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 q: Query<_>| {
                    send_bridge(handlers::keys(from_state(s), h, r, u, p, q))
                },
            )
            .post(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>,
                 f: axum::extract::Form<_>| {
                    send_bridge(handlers::keys_action(from_state(s), h, r, u, p, f))
                },
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/signing-keys/rotate",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::keys_rotate(from_state(s), h, r, u, p))
                },
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/publish-history",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::publishes(from_state(s), h, r, u, p))
                },
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/configuration",
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
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/change-requests",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::changes(from_state(s), h, r, u, p))
                },
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/change-requests/{id}",
            get(
                |State(s): State<SharedState>,
                 h: HeaderMap,
                 r: RequestStart,
                 u: Uri,
                 p: Path<_>| {
                    send_bridge(handlers::change_detail(from_state(s), h, r, u, p))
                },
            )
            .head(method_not_allowed),
        )
        .route(
            "/{slug}/-/settings/change-requests/{id}/comment",
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
            "/{slug}/-/settings/change-requests/{id}/review",
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
            "/{slug}/-/settings/change-requests/{id}/close",
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
            "/{slug}/-/settings/change-requests/{id}/reopen",
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
        .finish(deps)
}
