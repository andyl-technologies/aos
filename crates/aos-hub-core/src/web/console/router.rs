//! Authentication endpoints and the canonical browser-console application shell.
//!
//! Management reads and mutations use the generated Connect API. This router
//! retains only authentication/account ceremonies plus exact GET deep links
//! from [`aos_hub_console_contract`]. Native and Worker deployments mount this
//! same router, so neither runtime can retain a server-rendered management form
//! or a private mutation alias.

use axum::extract::{Query, State};
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

#[cfg(not(target_arch = "wasm32"))]
type SharedState = ConsoleDeps;
#[cfg(target_arch = "wasm32")]
type SharedState = SendWrapper<ConsoleDeps>;

#[cfg(not(target_arch = "wasm32"))]
fn into_state(deps: ConsoleDeps) -> SharedState {
    deps
}

#[cfg(target_arch = "wasm32")]
fn into_state(deps: ConsoleDeps) -> SharedState {
    SendWrapper::new(deps)
}

#[cfg(not(target_arch = "wasm32"))]
fn from_state(state: SharedState) -> ConsoleDeps {
    state
}

#[cfg(target_arch = "wasm32")]
fn from_state(state: SharedState) -> ConsoleDeps {
    state.take()
}

#[cfg(not(target_arch = "wasm32"))]
fn send_bridge<F: std::future::Future>(future: F) -> F {
    future
}

#[cfg(target_arch = "wasm32")]
fn send_bridge<F: std::future::Future>(future: F) -> SendWrapper<F> {
    SendWrapper::new(future)
}

async fn method_not_allowed() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

async fn enforce_declared_route(request: axum::extract::Request, next: Next) -> Response {
    let methods = route_methods_for_path(request.uri().path());
    let Some(methods) = methods else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let allowed = (*request.method() == Method::GET && methods.allows_get())
        || (*request.method() == Method::POST && methods.allows_post());
    let mut response = if allowed {
        next.run(request).await
    } else {
        let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
        response.headers_mut().insert(
            header::ALLOW,
            HeaderValue::from_static(methods.allow_header()),
        );
        response
    };
    response.extensions_mut().insert(ConsoleRouteMatched);
    response
}

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

async fn management_app(state: SharedState, headers: HeaderMap, uri: Uri) -> Response {
    if let Some(destination) = aos_hub_console_contract::registry_catalog_redirect(uri.path()) {
        return axum::response::Redirect::to(&destination).into_response();
    }
    if aos_hub_console_contract::ConsoleRoute::resolve(uri.path()).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    handlers::management_app(from_state(state), headers).await
}

fn management_get() -> MethodRouter<SharedState> {
    get(
        |State(state): State<SharedState>, headers: HeaderMap, uri: Uri| {
            send_bridge(management_app(state, headers, uri))
        },
    )
    .head(method_not_allowed)
}

/// Builds the shared authentication and browser-console router.
#[must_use]
pub fn console_router(deps: ConsoleDeps) -> Router {
    DeclaredRouter::new()
        .route(
            "/oauth2/device_authorization",
            post(
                |State(state): State<SharedState>, headers, form: axum::extract::Form<_>| {
                    send_bridge(handlers::device_authorization(
                        from_state(state),
                        headers,
                        form,
                    ))
                },
            ),
        )
        .route(
            "/oauth2/token",
            post(
                |State(state): State<SharedState>, headers, form: axum::extract::Form<_>| {
                    send_bridge(handlers::oauth_token(from_state(state), headers, form))
                },
            ),
        )
        .route(
            "/oauth2/revoke",
            post(
                |State(state): State<SharedState>, headers, form: axum::extract::Form<_>| {
                    send_bridge(handlers::oauth_revoke(from_state(state), headers, form))
                },
            ),
        )
        .route(
            "/login",
            get(
                |State(state): State<SharedState>, start: RequestStart, query: Query<_>| {
                    send_bridge(handlers::login_form(from_state(state), start, query))
                },
            )
            .post(|State(state): State<SharedState>, headers, start, form| {
                send_bridge(handlers::login_submit(
                    from_state(state),
                    headers,
                    start,
                    form,
                ))
            }),
        )
        .route(
            "/login/password",
            post(|State(state): State<SharedState>, headers, start, form| {
                send_bridge(handlers::login_password(
                    from_state(state),
                    headers,
                    start,
                    form,
                ))
            }),
        )
        .route(
            "/-/auth/session-token",
            post(|State(state): State<SharedState>, headers| {
                send_bridge(handlers::session_token(from_state(state), headers))
            }),
        )
        .route(
            "/auth/magic",
            get(
                |State(state): State<SharedState>, start: RequestStart, query: Query<_>| {
                    send_bridge(handlers::magic_consume(from_state(state), start, query))
                },
            ),
        )
        .route(
            "/auth/sso",
            post(|State(state): State<SharedState>, start, form| {
                send_bridge(handlers::login_sso(from_state(state), start, form))
            }),
        )
        .route(
            "/auth/oidc/start",
            get(
                |State(state): State<SharedState>, start: RequestStart, query: Query<_>| {
                    send_bridge(handlers::oidc_start(from_state(state), start, query))
                },
            ),
        )
        .route(
            "/auth/oidc/callback",
            get(
                |State(state): State<SharedState>, start: RequestStart, query: Query<_>| {
                    send_bridge(handlers::oidc_callback(from_state(state), start, query))
                },
            ),
        )
        .route(
            "/logout",
            get(|State(state): State<SharedState>, headers, start| {
                send_bridge(handlers::logout_form(from_state(state), headers, start))
            })
            .post(|State(state): State<SharedState>, headers, form| {
                send_bridge(handlers::logout(from_state(state), headers, form))
            }),
        )
        .route(
            "/-/account",
            get(|State(state): State<SharedState>, headers, start| {
                send_bridge(handlers::account(from_state(state), headers, start))
            }),
        )
        .route(
            "/-/account/password",
            post(|State(state): State<SharedState>, headers, start, form| {
                send_bridge(handlers::account_set_password(
                    from_state(state),
                    headers,
                    start,
                    form,
                ))
            }),
        )
        .route(
            "/-/reauth",
            post(|State(state): State<SharedState>, headers, start, form| {
                send_bridge(handlers::reauth(from_state(state), headers, start, form))
            }),
        )
        .route(
            "/-/account/sessions/revoke-all",
            post(|State(state): State<SharedState>, headers, form| {
                send_bridge(handlers::account_revoke_all_sessions(
                    from_state(state),
                    headers,
                    form,
                ))
            }),
        )
        .route(
            "/-/account/passkeys",
            get(|State(state): State<SharedState>, headers, start| {
                send_bridge(handlers::passkeys(from_state(state), headers, start))
            }),
        )
        .route(
            "/-/account/passkeys/remove",
            post(|State(state): State<SharedState>, headers, form| {
                send_bridge(handlers::passkeys_remove(from_state(state), headers, form))
            }),
        )
        .route(
            "/-/account/passkeys/begin",
            post(|State(state): State<SharedState>, headers, form| {
                send_bridge(handlers::passkeys_begin(from_state(state), headers, form))
            }),
        )
        .route(
            "/-/account/passkeys/finish",
            post(
                |State(state): State<SharedState>, headers, body: axum::Json<_>| {
                    send_bridge(handlers::passkeys_finish(from_state(state), headers, body))
                },
            ),
        )
        .route(
            "/auth/passkey/begin",
            post(|State(state): State<SharedState>, headers| {
                send_bridge(handlers::passkey_login_begin(from_state(state), headers))
            }),
        )
        .route(
            "/auth/passkey/finish",
            post(|State(state): State<SharedState>, body: axum::Json<_>| {
                send_bridge(handlers::passkey_login_finish(from_state(state), body))
            }),
        )
        .route(
            "/activate",
            get(|State(state): State<SharedState>, headers, start, query| {
                send_bridge(handlers::activate_form(
                    from_state(state),
                    headers,
                    start,
                    query,
                ))
            })
            .post(|State(state): State<SharedState>, headers, form| {
                send_bridge(handlers::activate_submit(from_state(state), headers, form))
            }),
        )
        .route("/-/instance", management_get())
        .route("/-/instance/{page}", management_get())
        .route("/-/instance/bindings/new", management_get())
        .route("/-/instance/domains/new", management_get())
        .route("/-/instance/network-policies/new", management_get())
        .route("/-/instance/endpoints/new", management_get())
        .route("/-/instance/gateways/new", management_get())
        .route("/-/caches", management_get())
        .route("/-/orgs", management_get())
        .route("/-/orgs/new", management_get())
        .route("/-/org/{org}", management_get())
        .route("/-/org/{org}/{page}", management_get())
        .route("/-/org/{org}/projects/new", management_get())
        .route("/-/org/{org}/registries/new", management_get())
        .route("/-/org/{org}/caches/new", management_get())
        .route("/-/org/{org}/bindings/new", management_get())
        .route("/-/org/{org}/domains/new", management_get())
        .route("/-/org/{org}/network-policies/new", management_get())
        .route("/-/org/{org}/endpoints/new", management_get())
        .route("/-/org/{org}/gateways/new", management_get())
        .route("/-/org/{org}/caches/{cache}", management_get())
        .route("/-/org/{org}/caches/{cache}/{page}", management_get())
        .route(
            "/-/org/{org}/invitations/accept",
            get(
                |State(state): State<SharedState>, headers, start, path, query| {
                    send_bridge(handlers::invitation_acceptance(
                        from_state(state),
                        headers,
                        start,
                        path,
                        query,
                    ))
                },
            )
            .post(|State(state): State<SharedState>, headers, path, form| {
                send_bridge(handlers::accept_invitation(
                    from_state(state),
                    headers,
                    path,
                    form,
                ))
            }),
        )
        .route("/{registry}/-/settings", management_get())
        .route("/{registry}/-/settings/{page}", management_get())
        .finish(deps)
}
