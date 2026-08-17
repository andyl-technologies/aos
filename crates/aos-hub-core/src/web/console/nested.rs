//! Canonical registry-console dispatch for flat and nested registry paths.
//!
//! Axum parameters capture one segment, while registry identities may contain
//! several. Both deployment runtimes therefore offer requests containing
//! `/-/settings` to this shared dispatcher before consumer browse routing. It
//! serves the same authenticated application shell for every exact route in
//! [`aos_hub_console_contract`] and leaves all other paths untouched.

use axum::body::Bytes;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use crate::web::console::handlers;
use crate::web::console::manifest::ConsoleRouteMatched;
use crate::web::console::ports::ConsoleDeps;

/// Dispatches an exact registry management deep link to the browser app shell.
///
/// # Returns
///
/// Returns `None` for non-registry or unknown paths. A canonical path returns
/// the shell for GET and `405 Method Not Allowed` for every other method.
pub async fn dispatch_nested(
    deps: ConsoleDeps,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    _body: Bytes,
) -> Option<Response> {
    let path = uri.path();
    if !path.contains("/-/settings") {
        return None;
    }
    let route = aos_hub_console_contract::ConsoleRoute::resolve(path)?;
    if !matches!(
        route.scope,
        aos_hub_console_contract::ConsoleScope::Registry { .. }
    ) {
        return None;
    }

    let mut response = if method == Method::GET {
        handlers::management_app(deps, headers).await
    } else {
        let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET"));
        response
    };
    response.extensions_mut().insert(ConsoleRouteMatched);
    Some(response)
}

#[cfg(test)]
mod tests {
    #[test]
    fn shared_contract_rejects_removed_registry_aliases() {
        assert!(aos_hub_console_contract::ConsoleRoute::resolve(
            "/andyl/main/-/settings/signing-key"
        )
        .is_none());
        assert!(aos_hub_console_contract::ConsoleRoute::resolve(
            "/andyl/main/-/settings/signing-keys"
        )
        .is_some());
    }
}
