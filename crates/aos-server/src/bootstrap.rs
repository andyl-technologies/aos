use std::path::Path;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::routes::AppState;

/// Request sent over the bootstrap socket (one JSON line per request).
#[derive(Debug, Deserialize)]
#[serde(tag = "action")]
enum BootstrapRequest {
    #[serde(rename = "create")]
    Create {
        views: Vec<String>,
        permissions: Vec<String>,
        #[serde(default)]
        expires_in: Option<i64>,
        #[serde(default)]
        comment: Option<String>,
    },
    #[serde(rename = "list")]
    List,
    #[serde(rename = "revoke")]
    Revoke { token_id: String },
    #[serde(rename = "rotate")]
    Rotate { token_id: String },
}

/// Response sent back over the bootstrap socket.
#[derive(Debug, Serialize)]
struct BootstrapResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

impl BootstrapResponse {
    fn success(data: serde_json::Value) -> Self {
        Self {
            ok: true,
            error: None,
            data: Some(data),
        }
    }

    fn error(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            data: None,
        }
    }
}

/// Start the bootstrap Unix socket listener.
///
/// This socket allows local administrators (root or members of the configured
/// socket group) to create, list, revoke, and rotate provisioning tokens.
pub async fn run_bootstrap_listener(state: Arc<AppState>, socket_path: &Path) -> Result<()> {
    // Remove stale socket file if it exists.
    let _ = std::fs::remove_file(socket_path);

    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding bootstrap socket at {}", socket_path.display()))?;

    loop {
        let (stream, _addr) = listener.accept().await?;

        // Check peer credentials for authorization.
        let cred = match stream.peer_cred() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("bootstrap: failed to get peer credentials: {e}");
                continue;
            }
        };

        let uid = cred.uid();
        let peer_gid = cred.gid();

        // Authorization: uid == 0 (root) or primary GID matches configured group.
        if uid != 0 {
            let required_gid = match resolve_group_gid(&state.config.bootstrap.socket_group) {
                Some(gid) => gid,
                None => {
                    eprintln!(
                        "bootstrap: cannot resolve group '{}', rejecting uid={uid}",
                        state.config.bootstrap.socket_group
                    );
                    continue;
                }
            };
            if peer_gid != required_gid {
                eprintln!(
                    "bootstrap: uid={uid} gid={peer_gid} not in group '{}' (gid={required_gid}), rejecting",
                    state.config.bootstrap.socket_group
                );
                continue;
            }
        }

        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_bootstrap_connection(stream, &state, uid).await {
                eprintln!("bootstrap: connection error: {e}");
            }
        });
    }
}

async fn handle_bootstrap_connection(
    stream: tokio::net::UnixStream,
    state: &AppState,
    caller_uid: u32,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let response = match serde_json::from_str::<BootstrapRequest>(&line) {
            Ok(req) => handle_request(req, state, caller_uid).await,
            Err(e) => BootstrapResponse::error(format!("invalid request: {e}")),
        };

        let mut json = serde_json::to_string(&response)?;
        json.push('\n');
        writer.write_all(json.as_bytes()).await?;
    }

    Ok(())
}

async fn handle_request(
    req: BootstrapRequest,
    state: &AppState,
    caller_uid: u32,
) -> BootstrapResponse {
    match req {
        BootstrapRequest::Create {
            views,
            permissions,
            expires_in,
            comment,
        } => {
            let expires_at = expires_in.map(|secs| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
                    + secs
            });

            match state.tokens.create_token(
                &views,
                &permissions,
                Some(caller_uid),
                expires_at,
                comment.as_deref(),
            ) {
                Ok((secret, record)) => BootstrapResponse::success(serde_json::json!({
                    "token": secret,
                    "id": record.id,
                    "views": record.views,
                    "permissions": record.permissions,
                    "expires_at": record.expires_at,
                })),
                Err(e) => BootstrapResponse::error(format!("creating token: {e}")),
            }
        }
        BootstrapRequest::List => match state.tokens.list_tokens() {
            Ok(records) => {
                let items: Vec<serde_json::Value> = records
                    .into_iter()
                    .map(|r| {
                        serde_json::json!({
                            "id": r.id,
                            "views": r.views,
                            "permissions": r.permissions,
                            "created_at": r.created_at,
                            "expires_at": r.expires_at,
                            "comment": r.comment,
                        })
                    })
                    .collect();
                BootstrapResponse::success(serde_json::json!({ "tokens": items }))
            }
            Err(e) => BootstrapResponse::error(format!("listing tokens: {e}")),
        },
        BootstrapRequest::Revoke { token_id } => match state.tokens.revoke_token(&token_id) {
            Ok(true) => BootstrapResponse::success(serde_json::json!({ "revoked": token_id })),
            Ok(false) => BootstrapResponse::error("token not found"),
            Err(e) => BootstrapResponse::error(format!("revoking token: {e}")),
        },
        BootstrapRequest::Rotate { token_id } => match state.tokens.rotate_token(&token_id) {
            Ok(Some((secret, record))) => BootstrapResponse::success(serde_json::json!({
                "token": secret,
                "id": record.id,
                "old_id": token_id,
                "views": record.views,
                "permissions": record.permissions,
                "expires_at": record.expires_at,
            })),
            Ok(None) => BootstrapResponse::error("token not found"),
            Err(e) => BootstrapResponse::error(format!("rotating token: {e}")),
        },
    }
}

/// Resolve a Unix group name to its GID by reading `/etc/group`.
fn resolve_group_gid(group_name: &str) -> Option<u32> {
    let contents = std::fs::read_to_string("/etc/group").ok()?;
    for line in contents.lines() {
        // Format: group_name:password:GID:user_list
        let fields: Vec<&str> = line.splitn(4, ':').collect();
        if fields.len() >= 3 && fields[0] == group_name {
            return fields[2].parse().ok();
        }
    }
    None
}
