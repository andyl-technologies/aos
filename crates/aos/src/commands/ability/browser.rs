//! Loopback browser for a checked native reference or desired transaction.

use anyhow::{Result, ensure};
use aos_core::output::Printer;
use aos_doc_model::runtime::RuntimeDocument;
use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::get,
};
use std::net::SocketAddr;
use std::sync::Arc;

/// Serves the checked native document without evaluating or executing it.
///
/// # Errors
/// Returns an error for non-loopback listeners, binding failures, or server errors.
pub(super) async fn serve(
    document: RuntimeDocument,
    listen: SocketAddr,
    printer: &Printer,
) -> Result<()> {
    ensure!(
        listen.ip().is_loopback(),
        "native ability browser requires a loopback listener"
    );
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let address = listener.local_addr()?;
    let state = Arc::new((address.to_string(), document.render_html()));
    let router = Router::new().route("/", get(render)).with_state(state);
    printer.raw(&format!("http://{address}/"));
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn render(
    State(state): State<Arc<(String, String)>>,
    headers: HeaderMap,
) -> axum::response::Response {
    if headers.get("host").and_then(|value| value.to_str().ok()) != Some(state.0.as_str()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    (
        [
            ("cache-control", "no-store"),
            (
                "content-security-policy",
                "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
            ),
            ("x-content-type-options", "nosniff"),
        ],
        Html(state.1.clone()),
    )
        .into_response()
}
