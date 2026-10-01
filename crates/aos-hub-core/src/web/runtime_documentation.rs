//! Read-only native module and transaction document viewer shared by both Hub runtimes.
//!
//! The viewer accepts caller-supplied JSON. It does not publish documents, select
//! registry releases, modify a deployment, or treat imported graphs as live state.

use aos_doc_model::runtime::RuntimeDocument;
use axum::body::Bytes;
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};

use super::console_render::{SessionIndicator, StateLine, page_with_session};

/// Limits documents so URL-encoded forms, including `document=`, fit the request ceiling.
pub const VIEWER_DOCUMENT_BYTES: usize = (crate::connect::CONNECT_REQUEST_BODY_LIMIT_BYTES - 9) / 3;

const SCRIPT: &str = r#"document.querySelector('#runtime-json')?.addEventListener('input', (event) => {
  event.target.setCustomValidity('');
});
document.querySelector('#runtime-file')?.addEventListener('change', async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  const input = document.querySelector('#runtime-json');
  if (file.size > Number(input.dataset.limit)) {
    input.setCustomValidity('The selected document exceeds the viewer size limit.');
    input.reportValidity();
    return;
  }
  input.setCustomValidity('');
  input.value = await file.text();
});"#;

fn page(content: &str) -> String {
    let body = format!(
        r#"<h1>Runtime abilities</h1>
<p>Browse a generated module reference or inspect a deferred transaction before deployment.</p>
<ol><li>Build package payloads and module sources.</li><li>Compose package, operator, and handler modules.</li><li>Generate a typed effect graph.</li><li>APM executes handlers and records the generation.</li></ol>
<p>Load <code>options.json</code> from a package documentation artifact, or an exported <code>aos.package.transaction</code> document. This viewer reads the supplied document; it does not connect to a running system or save an uploaded document.</p>
<form method="post" action="/-/runtime-abilities">
<label for="runtime-file">Choose a JSON document</label><input id="runtime-file" type="file" accept="application/json,.json">
<label for="runtime-json">Document JSON</label><textarea id="runtime-json" name="document" rows="12" required data-limit="{}"></textarea>
<button type="submit">Inspect document</button></form>
<script src="/_assets/runtime-documentation.js" defer></script>
{}
"#,
        VIEWER_DOCUMENT_BYTES, content
    );
    page_with_session(
        "runtime abilities",
        &[(String::new(), "runtime abilities".into())],
        &body,
        &StateLine::timed(crate::clock::Instant::now()),
        &SessionIndicator::anonymous(),
    )
}

/// Serves the native document import page.
pub async fn viewer() -> Response {
    Html(page("")).into_response()
}

/// Serves the progressive file-picker enhancement.
pub async fn script() -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        SCRIPT,
    )
        .into_response()
}

/// Parses a browser form and renders an imported document without retaining it.
///
/// Invalid documents return HTTP 400 with a readable diagnostic.
pub async fn preview(body: Bytes) -> Response {
    let response = if body.len() > crate::connect::CONNECT_REQUEST_BODY_LIMIT_BYTES {
        Err("Document exceeds the viewer size limit".to_owned())
    } else {
        let document = url::form_urlencoded::parse(&body)
            .find_map(|(key, value)| (key == "document").then(|| value.into_owned()));
        document
            .ok_or_else(|| "Document JSON is required".to_owned())
            .and_then(|document| {
                if document.len() > VIEWER_DOCUMENT_BYTES {
                    return Err("Document exceeds the viewer size limit".to_owned());
                }
                RuntimeDocument::from_json(document.as_bytes()).map_err(|error| error.to_string())
            })
    };
    let (status, content) = match response {
        Ok(document) => (StatusCode::OK, document.render_html()),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            format!("<p role=\"alert\">{}</p>", super::render::escape(&error)),
        ),
    };
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Html(page(&content)),
    )
        .into_response()
}

/// Inspects raw document JSON through the same reader used by the CLI and browser.
///
/// Returns normalized JSON by default or a rendered fragment with `?format=html`.
/// Invalid documents and unsupported output formats return HTTP 400.
pub async fn inspect(
    query: axum::extract::Query<std::collections::BTreeMap<String, String>>,
    body: Bytes,
) -> Response {
    let format = query.get("format").map(String::as_str).unwrap_or("json");
    let document = match RuntimeDocument::from_json(&body) {
        Ok(document) => document,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                [(header::CACHE_CONTROL, "no-store")],
                axum::Json(serde_json::json!({"error":error.to_string()})),
            )
                .into_response();
        }
    };
    match format {
        "json" => (
            [(header::CACHE_CONTROL, "no-store")],
            axum::Json(document.value()),
        )
            .into_response(),
        "html" => (
            [(header::CACHE_CONTROL, "no-store")],
            Html(document.render_html()),
        )
            .into_response(),
        _ => (StatusCode::BAD_REQUEST, "format must be json or html").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preview_rejects_legacy_input_and_escapes_errors() {
        let response = preview(Bytes::from("document=%7B%22schema%22%3A%22old%22%7D")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn api_and_browser_render_the_same_native_reference() {
        let document = serde_json::json!({
            "schema":"aos.module.documentation",
            "scope":["package","example"],
            "system":"x86_64-linux",
            "packages":[{"name":"example", "version":"1"}],
            "options":[{
                "path":["aos","example","settings"],"owner":"@base",
                "description":"Nested <settings>","visibility":"public","readOnly":false,"extensible":true,
                "type":{"kind":"submodule","fields":{"enabled":{"kind":"bool"}},"open":false}
            }], "abilities":{},
            "osRelease":{"name":"aos","version":"1.0.0"},
            "osRequirements":[{"owner":"example","osVersion":"^1.2"}],
            "moduleRequirements":[{"owner":"example","package":"service-interface",
                "packageVersion":"^7"}]
        });
        let json = serde_json::to_string(&document).unwrap();
        let response = inspect(
            axum::extract::Query(Default::default()),
            Bytes::from(json.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            document
        );

        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("document", &json)
            .finish();
        let response = preview(Bytes::from(form)).await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(html.contains("Packages and environment"));
        assert!(html.contains("Generated options"));
        assert!(html.contains("aos.example.settings"));
        assert!(html.contains("Base module declarations."));
        assert!(html.contains("Nested &lt;settings&gt;"));
        assert!(html.contains("enabled"));
        assert!(html.contains("OS release: aos <code>1.0.0</code>"));
        assert!(html.contains("OS requirements"));
        assert!(html.contains("Module requirements"));
        assert!(html.contains("^1.2"));
        assert!(html.contains("^7"));

        let response = inspect(
            axum::extract::Query(std::collections::BTreeMap::from([(
                "format".into(),
                "html".into(),
            )])),
            Bytes::from(json),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8(bytes.to_vec()).unwrap(),
            RuntimeDocument::from_json(&serde_json::to_vec(&document).unwrap())
                .unwrap()
                .render_html()
        );
        assert!(html.contains(&aos_doc_model::documentation_anchor(
            "runtime-owner",
            "example"
        )));
    }

    #[tokio::test]
    async fn api_rejects_unsupported_output_format() {
        let query = axum::extract::Query(std::collections::BTreeMap::from([(
            "format".into(),
            "invalid".into(),
        )]));
        let response = inspect(query, Bytes::from_static(br#"{"schema":"aos.package.transaction","scope":["host","main"],"system":"x86_64-linux","retire":[],"graph":{"schema":"aos.activation.graph","nodes":{},"order":[]}}"#)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
