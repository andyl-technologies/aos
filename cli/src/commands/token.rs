use std::path::Path;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::cli::TokenCmd;
use aos::output::Printer;

/// `aos token` — manage provisioning tokens via the bootstrap socket.
pub async fn run(printer: &Printer, command: &TokenCmd, socket_path: &Path) -> Result<()> {
    match command {
        TokenCmd::Create {
            view,
            permissions,
            expires,
            comment,
        } => create(printer, socket_path, view, permissions, expires, comment.as_deref()).await,
        TokenCmd::List => list(printer, socket_path).await,
        TokenCmd::Revoke { token_id } => revoke(printer, socket_path, token_id).await,
        TokenCmd::Rotate { token_id } => rotate(printer, socket_path, token_id).await,
    }
}

async fn send_request(
    socket_path: &Path,
    request: &serde_json::Value,
) -> Result<serde_json::Value> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connecting to bootstrap socket at {}", socket_path.display()))?;

    let (reader, mut writer) = stream.into_split();

    let mut json = serde_json::to_string(request)?;
    json.push('\n');
    writer.write_all(json.as_bytes()).await?;
    writer.shutdown().await?;

    let mut lines = BufReader::new(reader).lines();
    let line = lines
        .next_line()
        .await?
        .context("no response from bootstrap socket")?;

    let resp: serde_json::Value =
        serde_json::from_str(&line).context("invalid response from bootstrap socket")?;

    if resp.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let err = resp
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        anyhow::bail!("{err}");
    }

    Ok(resp
        .get("data")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

async fn create(
    printer: &Printer,
    socket_path: &Path,
    views: &[String],
    permissions: &str,
    expires: &Option<String>,
    comment: Option<&str>,
) -> Result<()> {
    let perms: Vec<&str> = permissions.split(',').map(|s| s.trim()).collect();

    let expires_in: Option<i64> = match expires {
        Some(s) => {
            let dur: std::time::Duration = s
                .parse::<humantime::Duration>()
                .context("invalid duration for --expires")?
                .into();
            Some(dur.as_secs() as i64)
        }
        None => None,
    };

    let mut req = serde_json::json!({
        "action": "create",
        "views": views,
        "permissions": perms,
    });
    if let Some(ei) = expires_in {
        req["expires_in"] = serde_json::json!(ei);
    }
    if let Some(c) = comment {
        req["comment"] = serde_json::json!(c);
    }

    let data = send_request(socket_path, &req).await?;

    if printer.json_if_active(&data) {
        return Ok(());
    }

    let token = data
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or("???");
    let id = data.get("id").and_then(|v| v.as_str()).unwrap_or("???");

    printer.header("Token created");
    printer.plain(&format!("  ID:    {id}"));
    printer.plain(&format!("  Token: {token}"));
    printer.plain("");
    printer.plain("  Store this token securely. It will NOT be shown again.");

    Ok(())
}

async fn list(printer: &Printer, socket_path: &Path) -> Result<()> {
    let req = serde_json::json!({ "action": "list" });
    let data = send_request(socket_path, &req).await?;

    if printer.json_if_active(&data) {
        return Ok(());
    }

    let tokens = data
        .get("tokens")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if tokens.is_empty() {
        printer.info("No provisioning tokens found.");
        return Ok(());
    }

    printer.header("Provisioning tokens:");
    for t in &tokens {
        let id = t.get("id").and_then(|v| v.as_str()).unwrap_or("???");
        let views = t
            .get("views")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let perms = t
            .get("permissions")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let comment = t.get("comment").and_then(|v| v.as_str()).unwrap_or("-");

        printer.plain(&format!("  {id}  views={views}  perms={perms}  comment={comment}"));
    }

    Ok(())
}

async fn revoke(printer: &Printer, socket_path: &Path, token_id: &str) -> Result<()> {
    let req = serde_json::json!({ "action": "revoke", "token_id": token_id });
    let data = send_request(socket_path, &req).await?;

    if printer.json_if_active(&data) {
        return Ok(());
    }

    printer.success(&format!("Token {token_id} revoked"));
    Ok(())
}

async fn rotate(printer: &Printer, socket_path: &Path, token_id: &str) -> Result<()> {
    let req = serde_json::json!({ "action": "rotate", "token_id": token_id });
    let data = send_request(socket_path, &req).await?;

    if printer.json_if_active(&data) {
        return Ok(());
    }

    let new_token = data
        .get("token")
        .and_then(|v| v.as_str())
        .unwrap_or("???");
    let new_id = data.get("id").and_then(|v| v.as_str()).unwrap_or("???");

    printer.header("Token rotated");
    printer.plain(&format!("  Old ID: {token_id}  (revoked with 1h grace period)"));
    printer.plain(&format!("  New ID: {new_id}"));
    printer.plain(&format!("  Token:  {new_token}"));
    printer.plain("");
    printer.plain("  Store this token securely. It will NOT be shown again.");

    Ok(())
}
