//! Exact selected production shell template and canonical bounded attributes.

use super::Capture;
use crate::files;
use anyhow::{ensure, Result};
use serde_json::Value;

pub(super) const TEMPLATE: &str = include_str!("browser/template.txt");

pub(super) fn source() -> Value {
    serde_json::json!({
        "handlerSourceSha256": env!("NATIVE_BROWSER_HANDLER_SHA256"),
        "templateSha256": files::digest(TEMPLATE.as_bytes()),
        "assetVersion": aos_hub_core::web::assets::asset_version(),
        "consoleJsSha256": files::digest(aos_hub_core::web::assets::CONSOLE_JS),
        "consoleWasmSha256": files::digest(aos_hub_core::web::assets::CONSOLE_WASM),
        "consoleCssSha256": files::digest(aos_hub_core::web::assets::CONSOLE_CSS),
    })
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn attribute(value: &str) -> Result<()> {
    ensure!(
        value.len() <= 4096 && !value.chars().any(char::is_control),
        "browser attribute exceeds bound"
    );
    let plain = value
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&");
    ensure!(escape(&plain) == value, "noncanonical browser escape");
    Ok(())
}

pub(super) fn classify(capture: &Capture, request: &[u8], response: &[u8]) -> Result<()> {
    ensure!(
        capture.method == "GET"
            && capture.phase.is_none()
            && capture.status == 200
            && capture.procedure == "/-/instance"
            && request.is_empty()
            && capture.response_content_type.as_deref() == Some("text/html; charset=utf-8")
            && response.len() <= 64 * 1024,
        "browser transport differs"
    );
    let response = std::str::from_utf8(response)?;
    let mut values = std::collections::BTreeMap::new();
    let mut template = TEMPLATE;
    let mut remaining = response;
    while let Some(start) = template.find('{') {
        let prefix = &template[..start];
        remaining = remaining
            .strip_prefix(prefix)
            .ok_or_else(|| anyhow::anyhow!("browser template differs"))?;
        template = &template[start + 1..];
        let end = template
            .find('}')
            .ok_or_else(|| anyhow::anyhow!("invalid selected template"))?;
        let name = &template[..end];
        template = &template[end + 1..];
        let suffix = template.split('{').next().unwrap_or(template);
        ensure!(!suffix.is_empty(), "ambiguous selected template slot");
        let length = remaining
            .find(suffix)
            .ok_or_else(|| anyhow::anyhow!("browser template suffix differs"))?;
        let value = &remaining[..length];
        attribute(value)?;
        if let Some(previous) = values.insert(name, value) {
            ensure!(previous == value, "browser repeated slot changed");
        }
        remaining = &remaining[length..];
    }
    ensure!(remaining == template, "browser trailing bytes differ");
    let brand = values
        .get("brand")
        .ok_or_else(|| anyhow::anyhow!("missing brand"))?;
    ensure!(
        values.get("title") == Some(&if brand.is_empty() { "AOS Hub" } else { brand }),
        "browser title does not match brand"
    );
    ensure!(
        values.get("asset_version") == Some(&aos_hub_core::web::assets::asset_version())
            && values.get("css").copied()
                == Some(aos_hub_core::web::assets::console_css_name().as_str())
            && values.get("bootstrap").copied()
                == Some(aos_hub_core::web::assets::console_bootstrap_name().as_str())
            && values.get("app_version").copied() == Some(env!("NATIVE_APP_VERSION")),
        "browser installed asset identity differs"
    );
    ensure!(
        values
            .get("container_gc_enabled")
            .is_some_and(|value| matches!(*value, "true" | "false")),
        "browser rollout slot differs"
    );
    let csrf = values
        .get("csrf")
        .ok_or_else(|| anyhow::anyhow!("missing CSRF slot"))?;
    ensure!(
        !csrf.is_empty()
            && csrf.len() <= 128
            && csrf
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "browser CSRF encoding differs"
    );
    Ok(())
}
