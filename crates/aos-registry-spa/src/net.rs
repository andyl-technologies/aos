//! Browser networking: same-origin GETs and the optional hub Connect POST.
//!
//! All snapshot and surface reads are *same-origin relative* fetches, so
//! the SPA needs zero CORS configuration: a registry served from
//! `https://cdn.example/aos-core/` resolves `web/index.json` against the
//! document base. The one off-origin call is the optional hub search, gated
//! on `config.json`'s `hub_url`; the hub answers it only for origins it has
//! registered as frontends.
//!
//! [`BrowserFetch`] implements [`crate::verify::SurfaceFetch`] over
//! `fetch()`, distinguishing a clean 404 (`None`) from a transport error so
//! the verifier can tell "absent" from "unreachable".

use anyhow::{anyhow, Context, Result};
use gloo_net::http::Request;

use crate::verify::SurfaceFetch;

/// A same-origin `fetch()` reader, relative to the document base URL.
#[derive(Debug, Clone, Default)]
pub struct BrowserFetch;

impl SurfaceFetch for BrowserFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let response = Request::get(path)
            .send()
            .await
            .map_err(|err| anyhow!("GET {path}: {err}"))?;
        if response.status() == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&response.status()) {
            return Err(anyhow!("GET {path}: HTTP {}", response.status()));
        }
        let bytes = response
            .binary()
            .await
            .map_err(|err| anyhow!("reading {path} body: {err}"))?;
        Ok(Some(bytes))
    }
}

/// Fetch and deserialize a same-origin JSON snapshot.
///
/// # Errors
///
/// Returns an error when the request fails, the path 404s or returns a
/// non-2xx status, or the body does not deserialize into `T`.
pub async fn get_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T> {
    let response = Request::get(path)
        .send()
        .await
        .map_err(|err| anyhow!("GET {path}: {err}"))?;
    if !(200..300).contains(&response.status()) {
        return Err(anyhow!("GET {path}: HTTP {}", response.status()));
    }
    let text = response
        .text()
        .await
        .map_err(|err| anyhow!("reading {path} body: {err}"))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {path}"))
}

/// Call the hub's `PackageService/ListPackages` over Connect-JSON.
///
/// The Connect protocol's unary JSON encoding is a plain `POST` of the
/// request message to `{hub_url}/aos.registry.v1.PackageService/ListPackages`
/// with `Content-Type: application/json`; the response body is the JSON
/// message. This lights up server-side search when `config.json` carries a
/// `hub_url`; absent it, the caller degrades to a client-side substring
/// filter over `index.json` (see [`crate::app`]). The returned value is the
/// raw response JSON, left untyped so the SPA tolerates hub schema additions.
///
/// # Errors
///
/// Returns an error when the request fails or the hub answers non-2xx
/// (including a CORS rejection for an unregistered frontend origin).
pub async fn hub_list_packages(hub_url: &str, query: &str) -> Result<serde_json::Value> {
    let url = format!(
        "{}/aos.registry.v1.PackageService/ListPackages",
        hub_url.trim_end_matches('/')
    );
    let body = serde_json::json!({ "query": query }).to_string();
    let response = Request::post(&url)
        .header("content-type", "application/json")
        .body(body)
        .map_err(|err| anyhow!("building hub request: {err}"))?
        .send()
        .await
        .map_err(|err| anyhow!("POST {url}: {err}"))?;
    if !(200..300).contains(&response.status()) {
        return Err(anyhow!("hub search: HTTP {}", response.status()));
    }
    let text = response
        .text()
        .await
        .map_err(|err| anyhow!("reading hub response: {err}"))?;
    serde_json::from_str(&text).with_context(|| "parsing hub ListPackages response")
}
