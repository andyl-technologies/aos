//! Cloudflare deployment orchestration — provision, deploy, and initialise a
//! Worker deployment of this hub's wasm sibling (`aos-registry-worker`).
//!
//! The native binary is both the hub *server* and the *installer* for its
//! Cloudflare counterpart: `wasm32-unknown-unknown` in the Workers runtime
//! cannot spawn `wrangler`, read operator credentials, or touch the filesystem,
//! so the install/maintenance tooling is necessarily native and the compiled
//! Worker (`shim.mjs` + `index.wasm`) is a **payload it ships**, not something it
//! runs in-process. This module shells out to a bundled `wrangler` (located via
//! [`Assets::from_env`], packaged by the `aos-registry-hub-cloudflare` Nix
//! wrapper) and drives the deployment end to end:
//!
//! 1. **provision** — create the D1 database, R2 bucket, and KV namespace,
//! 2. **deploy** — render a [`wrangler.toml`](render_wrangler_toml) over the
//!    bundled wasm dist and `wrangler deploy` it,
//! 3. **secrets** — `wrangler secret put` the runtime secrets,
//! 4. **init** — `GET /_init` on the live Worker, which applies the shared
//!    `aos_registry_core` migrations over D1 and (when `HUB_ROOT_EMAIL` /
//!    `HUB_ROOT_PASSWORD` are set) bootstraps the root admin.
//!
//! The generated config has no `[build]` command — it deploys the *prebuilt*
//! hermetic dist rather than re-running `worker-build` on the operator's
//! machine:
//!
//! ```toml
//! name = "aos-registry-hub"
//! main = "shim.mjs"
//! compatibility_date = "2024-09-23"
//! compatibility_flags = ["nodejs_compat"]
//!
//! [vars]
//! HUB_EXTERNAL_URL = "https://reg.example.com"
//!
//! [[d1_databases]]
//! binding = "REGISTRY_DB"
//! database_name = "aos-registry-hub"
//! database_id = "…"
//!
//! [[r2_buckets]]
//! binding = "REGISTRY_BUCKET"
//! bucket_name = "aos-registry-surfaces"
//!
//! [[kv_namespaces]]
//! binding = "SESSIONS"
//! id = "…"
//!
//! [triggers]
//! crons = ["*/15 * * * *"]
//! ```
//!
//! Operator Cloudflare credentials are **not** handled here: `wrangler` reads
//! `CLOUDFLARE_API_TOKEN` (or an OAuth login) from the inherited environment, so
//! the installer passes the operator's auth through transparently.
//!
//! ## Validation boundary
//!
//! The pure pieces — argv construction, TOML rendering, `wrangler … list --json`
//! id parsing, secret generation — are unit-tested in this module. The live
//! `wrangler` invocations and the `/_init` request require a real Cloudflare
//! account and are validated operator-side (see `DEPLOY.md`), exactly like the
//! Worker runtime tests that need a workerd host.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// The D1 binding name — must match `aos_registry_worker::handlers::bindings`.
const D1_BINDING: &str = "REGISTRY_DB";
/// The R2 binding name — must match the Worker's bindings.
const R2_BINDING: &str = "REGISTRY_BUCKET";
/// The KV binding name — must match the Worker's bindings.
const KV_BINDING: &str = "SESSIONS";
/// The Workers compatibility date the dist is built and tested against.
const COMPAT_DATE: &str = "2024-09-23";
/// The Cron cadence that drives the indexer's `scheduled` handler.
const INDEXER_CRON: &str = "*/15 * * * *";

/// The bundled deployment assets resolved from the wrapper environment.
///
/// The `aos-registry-hub-cloudflare` Nix wrapper sets `AOS_HUB_WORKER_DIST` (the
/// directory holding `shim.mjs` + `index.wasm`) and `AOS_HUB_WRANGLER` (the
/// `wrangler` launcher). A lean (non-wrapped) build leaves them unset, and the
/// `cloudflare` commands fail with guidance to use the wrapped package.
pub struct Assets {
    /// Directory containing the prebuilt `shim.mjs` and `index.wasm`.
    pub dist_dir: PathBuf,
    /// The `wrangler` launcher argv (a single store path, or a multi-word
    /// launcher such as `nix run .#miniflare -- wrangler`).
    pub wrangler: Vec<String>,
}

impl Assets {
    /// Resolves the bundled wasm dist and `wrangler` launcher from the wrapper
    /// environment (`AOS_HUB_WORKER_DIST`, `AOS_HUB_WRANGLER`).
    ///
    /// # Errors
    ///
    /// Returns an error if either environment variable is unset/empty (the build
    /// was not packaged with the worker artifact — use the
    /// `aos-registry-hub-cloudflare` package), or if `shim.mjs`/`index.wasm` is
    /// missing from the dist directory.
    pub fn from_env() -> Result<Assets> {
        let dist = non_empty_env("AOS_HUB_WORKER_DIST").context(
            "AOS_HUB_WORKER_DIST is not set — this build was not packaged with the worker \
             artifact; install and run the `aos-registry-hub-cloudflare` package",
        )?;
        let wrangler = non_empty_env("AOS_HUB_WRANGLER").context(
            "AOS_HUB_WRANGLER is not set — install and run the \
             `aos-registry-hub-cloudflare` package",
        )?;
        let dist_dir = PathBuf::from(dist);
        for f in ["shim.mjs", "index.wasm"] {
            let p = dist_dir.join(f);
            if !p.exists() {
                bail!("worker dist is missing {f} at {}", p.display());
            }
        }
        let wrangler = wrangler.split_whitespace().map(str::to_string).collect();
        Ok(Assets { dist_dir, wrangler })
    }
}

/// Reads an environment variable, treating an empty value as absent.
fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// The fully-resolved inputs for rendering a deployment `wrangler.toml`.
pub struct DeployConfig {
    /// The Worker name (`name` in `wrangler.toml`).
    pub name: String,
    /// The D1 database name.
    pub d1_name: String,
    /// The provisioned D1 database id (a uuid).
    pub d1_id: String,
    /// The R2 bucket name.
    pub bucket: String,
    /// The provisioned KV namespace id.
    pub kv_id: String,
    /// The externally-reachable hub URL (`HUB_EXTERNAL_URL` `[vars]` entry).
    pub external_url: String,
    /// The root admin email (`HUB_ROOT_EMAIL` `[vars]`); `None` skips bootstrap.
    pub root_email: Option<String>,
    /// The magic-link email relay endpoint (`HUB_EMAIL_API_URL` `[vars]`).
    pub email_relay_url: Option<String>,
}

/// Renders the deployment `wrangler.toml` over the prebuilt wasm dist.
///
/// `main` is `shim.mjs` (relative to the config's directory, where the dist is
/// staged). There is intentionally **no** `[build]` command — the hermetic dist
/// is deployed as-is rather than rebuilt on the operator's machine. The non-
/// secret configuration (`HUB_EXTERNAL_URL`, optional `HUB_ROOT_EMAIL` /
/// `HUB_EMAIL_API_URL`) is baked into `[vars]`; secrets are applied separately
/// with [`secret_put_args`].
#[must_use]
pub fn render_wrangler_toml(cfg: &DeployConfig) -> String {
    let mut vars = format!(
        "[vars]\nHUB_EXTERNAL_URL = {}\n",
        toml_string(&cfg.external_url)
    );
    if let Some(email) = &cfg.root_email {
        vars.push_str(&format!("HUB_ROOT_EMAIL = {}\n", toml_string(email)));
    }
    if let Some(relay) = &cfg.email_relay_url {
        vars.push_str(&format!("HUB_EMAIL_API_URL = {}\n", toml_string(relay)));
    }
    format!(
        "# Generated by `aos-registry-hub cloudflare` — do not edit by hand.\n\
         name = {name}\n\
         main = \"shim.mjs\"\n\
         compatibility_date = \"{compat}\"\n\
         compatibility_flags = [\"nodejs_compat\"]\n\
         \n{vars}\n\
         [[d1_databases]]\n\
         binding = \"{d1b}\"\n\
         database_name = {d1name}\n\
         database_id = {d1id}\n\
         \n\
         [[r2_buckets]]\n\
         binding = \"{r2b}\"\n\
         bucket_name = {bucket}\n\
         \n\
         [[kv_namespaces]]\n\
         binding = \"{kvb}\"\n\
         id = {kvid}\n\
         \n\
         [triggers]\n\
         crons = [\"{cron}\"]\n",
        name = toml_string(&cfg.name),
        compat = COMPAT_DATE,
        d1b = D1_BINDING,
        d1name = toml_string(&cfg.d1_name),
        d1id = toml_string(&cfg.d1_id),
        r2b = R2_BINDING,
        bucket = toml_string(&cfg.bucket),
        kvb = KV_BINDING,
        kvid = toml_string(&cfg.kv_id),
        cron = INDEXER_CRON,
    )
}

/// Renders a string as a TOML basic-string literal (quoted, with `"` and `\`
/// escaped).
fn toml_string(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

// ── wrangler argv builders (pure; unit-tested) ──────────────────────────────

/// `wrangler d1 create <name>` — provision a D1 database.
#[must_use]
pub fn d1_create_args(name: &str) -> Vec<String> {
    vec!["d1".into(), "create".into(), name.into()]
}

/// `wrangler r2 bucket create <bucket>` — provision an R2 bucket.
#[must_use]
pub fn r2_create_args(bucket: &str) -> Vec<String> {
    vec!["r2".into(), "bucket".into(), "create".into(), bucket.into()]
}

/// `wrangler kv namespace create <title>` — provision a KV namespace.
#[must_use]
pub fn kv_create_args(title: &str) -> Vec<String> {
    vec![
        "kv".into(),
        "namespace".into(),
        "create".into(),
        title.into(),
    ]
}

/// `wrangler d1 list --json` — list D1 databases as JSON (for id discovery).
#[must_use]
pub fn d1_list_args() -> Vec<String> {
    vec!["d1".into(), "list".into(), "--json".into()]
}

/// `wrangler kv namespace list` — list KV namespaces as JSON (for id discovery).
///
/// Unlike `d1 list`, `kv namespace list` takes no `--json` flag — it emits a
/// JSON array by default (passing `--json` is rejected as an unknown flag), so
/// this relies on that default output shape.
#[must_use]
pub fn kv_list_args() -> Vec<String> {
    vec!["kv".into(), "namespace".into(), "list".into()]
}

/// `wrangler secret put <name> --config <path>` — set a Worker secret (the value
/// is supplied on stdin).
#[must_use]
pub fn secret_put_args(name: &str, config: &Path) -> Vec<String> {
    vec![
        "secret".into(),
        "put".into(),
        name.into(),
        "--config".into(),
        config.display().to_string(),
    ]
}

/// `wrangler deploy --config <path>` — deploy the staged dist.
#[must_use]
pub fn deploy_args(config: &Path) -> Vec<String> {
    vec![
        "deploy".into(),
        "--config".into(),
        config.display().to_string(),
    ]
}

// ── id parsing from `wrangler … list` JSON (pure; unit-tested) ──────────────

/// Extracts the database id for `name` from `wrangler d1 list --json` output.
///
/// Tolerates both a bare array (`[{ "uuid": …, "name": … }]`) and a
/// `{ "result": [...] }` envelope, and reads the id from either `uuid` or
/// `database_id`.
///
/// # Errors
///
/// Returns an error if the JSON cannot be parsed, has an unexpected shape, or
/// contains no database named `name`.
pub fn parse_d1_id(list_json: &str, name: &str) -> Result<String> {
    let v: serde_json::Value =
        serde_json::from_str(list_json).context("parsing `wrangler d1 list --json` output")?;
    let arr = json_array(&v).context("unexpected `wrangler d1 list` JSON shape")?;
    for db in arr {
        if db.get("name").and_then(serde_json::Value::as_str) == Some(name) {
            if let Some(id) = db
                .get("uuid")
                .or_else(|| db.get("database_id"))
                .and_then(serde_json::Value::as_str)
            {
                return Ok(id.to_string());
            }
        }
    }
    bail!("D1 database {name:?} not found in `wrangler d1 list` output");
}

/// Extracts the namespace id for `title` from `wrangler kv namespace list`
/// output.
///
/// # Errors
///
/// Returns an error if the JSON cannot be parsed, has an unexpected shape, or
/// contains no namespace whose `title` matches `title`.
pub fn parse_kv_id(list_json: &str, title: &str) -> Result<String> {
    let v: serde_json::Value = serde_json::from_str(list_json)
        .context("parsing `wrangler kv namespace list` output")?;
    let arr = json_array(&v).context("unexpected `wrangler kv namespace list` JSON shape")?;
    for ns in arr {
        if ns.get("title").and_then(serde_json::Value::as_str) == Some(title) {
            if let Some(id) = ns.get("id").and_then(serde_json::Value::as_str) {
                return Ok(id.to_string());
            }
        }
    }
    bail!("KV namespace titled {title:?} not found in `wrangler kv namespace list` output");
}

/// Returns the top-level array of a `wrangler … list` response, accepting either
/// a bare array or a `{ "result": [...] }` envelope.
fn json_array(v: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    v.as_array()
        .or_else(|| v.get("result").and_then(serde_json::Value::as_array))
}

/// Generates a random secret as a lowercase hex string of `bytes` bytes.
///
/// Used to mint `HUB_JWT_SECRET` / `HUB_SEAL_KEY` when the operator does not
/// supply them. A 32-byte value yields the 64 hex chars the seal key parses as a
/// raw AES-256 key.
#[must_use]
pub fn generate_hex_secret(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

// ── live orchestration (operator-validated) ─────────────────────────────────

/// Runs the bundled `wrangler` with `args`, optionally piping `stdin`, and
/// returns captured stdout.
///
/// `cwd` sets the working directory (used so a relative `main = "shim.mjs"`
/// resolves against the staged dist). `wrangler` inherits the operator's
/// `CLOUDFLARE_API_TOKEN`/OAuth from the environment.
///
/// # Errors
///
/// Returns an error if the process cannot be spawned, the stdin pipe cannot be
/// written, or `wrangler` exits non-zero (the captured stderr is included).
async fn run_wrangler(
    assets: &Assets,
    args: &[String],
    stdin: Option<&str>,
    cwd: Option<&Path>,
) -> Result<String> {
    let (program, prefix) = assets
        .wrangler
        .split_first()
        .context("AOS_HUB_WRANGLER resolved to an empty launcher")?;
    let mut cmd = Command::new(program);
    cmd.args(prefix).args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawning `{program} {}`", args.join(" ")))?;
    if let Some(value) = stdin {
        let mut pipe = child
            .stdin
            .take()
            .context("wrangler stdin pipe was not captured")?;
        pipe.write_all(value.as_bytes())
            .await
            .context("writing to wrangler stdin")?;
        drop(pipe); // close stdin so wrangler sees EOF
    }
    let output = child
        .wait_with_output()
        .await
        .context("waiting for wrangler")?;
    if !output.status.success() {
        bail!(
            "`wrangler {}` failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Runs `wrangler`, tolerating failure (used for idempotent provisioning where a
/// resource that already exists is not an error). Logs the swallowed stderr.
async fn run_wrangler_tolerant(assets: &Assets, args: &[String], what: &str) {
    if let Err(err) = run_wrangler(assets, args, None, None).await {
        tracing::info!(error = %format!("{err:#}"), "{what} (continuing; likely already exists)");
    }
}

/// The runtime secrets to apply to the Worker.
///
/// `jwt_secret` and `seal_key` are required by the Worker at request time and
/// are minted randomly when `None`. The others are optional features.
pub struct Secrets {
    /// `HUB_JWT_SECRET` — HS256 JWT signing key (minted if `None`).
    pub jwt_secret: Option<String>,
    /// `HUB_SEAL_KEY` — at-rest AES-GCM sealing key (minted if `None`).
    pub seal_key: Option<String>,
    /// `HUB_ROOT_PASSWORD` — bootstrap root admin password (paired with
    /// `HUB_ROOT_EMAIL`).
    pub root_password: Option<String>,
    /// `HUB_EMAIL_API_TOKEN` — bearer token for the magic-link email relay.
    pub email_api_token: Option<String>,
}

/// The outcome of a deploy: the secrets actually applied (so minted ones can be
/// reported back to the operator to record).
pub struct Applied {
    /// The `HUB_JWT_SECRET` value applied (possibly freshly minted).
    pub jwt_secret: String,
    /// The `HUB_SEAL_KEY` value applied (possibly freshly minted).
    pub seal_key: String,
    /// Whether a `HUB_JWT_SECRET`/`HUB_SEAL_KEY` was freshly minted this run.
    pub minted: bool,
}

/// Provisions the D1 database, R2 bucket, and KV namespace, then resolves their
/// ids into a [`DeployConfig`].
///
/// Provisioning is idempotent: a resource that already exists is logged and
/// skipped. Ids are read back from `wrangler … list` (the stable JSON
/// interface) rather than parsed from `create` output.
///
/// # Errors
///
/// Returns an error if the id-discovery `list` calls fail or the named
/// resources cannot be found afterwards.
pub async fn provision(
    assets: &Assets,
    name: &str,
    d1_name: &str,
    bucket: &str,
    kv_title: &str,
    external_url: &str,
    root_email: Option<&str>,
    email_relay_url: Option<&str>,
) -> Result<DeployConfig> {
    run_wrangler_tolerant(assets, &d1_create_args(d1_name), "d1 create").await;
    run_wrangler_tolerant(assets, &r2_create_args(bucket), "r2 bucket create").await;
    run_wrangler_tolerant(assets, &kv_create_args(kv_title), "kv namespace create").await;

    let d1_list = run_wrangler(assets, &d1_list_args(), None, None).await?;
    let d1_id = parse_d1_id(&d1_list, d1_name)?;
    let kv_list = run_wrangler(assets, &kv_list_args(), None, None).await?;
    let kv_id = parse_kv_id(&kv_list, kv_title)?;

    Ok(DeployConfig {
        name: name.to_string(),
        d1_name: d1_name.to_string(),
        d1_id,
        bucket: bucket.to_string(),
        kv_id,
        external_url: external_url.to_string(),
        root_email: root_email.map(str::to_string),
        email_relay_url: email_relay_url.map(str::to_string),
    })
}

/// Stages the dist + generated `wrangler.toml` into `dir` and returns the config
/// path.
///
/// # Errors
///
/// Returns an error if the dist files cannot be copied or the config cannot be
/// written.
async fn stage_deploy(assets: &Assets, cfg: &DeployConfig, dir: &Path) -> Result<PathBuf> {
    for f in ["shim.mjs", "index.wasm"] {
        tokio::fs::copy(assets.dist_dir.join(f), dir.join(f))
            .await
            .with_context(|| format!("staging {f}"))?;
    }
    let config = dir.join("wrangler.toml");
    tokio::fs::write(&config, render_wrangler_toml(cfg))
        .await
        .context("writing generated wrangler.toml")?;
    Ok(config)
}

/// Deploys the staged dist and applies the runtime secrets.
///
/// Stages the dist + generated config into a private temporary directory (cleaned
/// up on return). Order matters: `wrangler deploy` creates the Worker (and bakes
/// `[vars]`), then `wrangler secret put` attaches the secrets to the live Worker.
///
/// # Errors
///
/// Returns an error if the temp dir, staging, the deploy, or any `secret put`
/// fails.
pub async fn deploy(assets: &Assets, cfg: &DeployConfig, secrets: &Secrets) -> Result<Applied> {
    let work = tempfile::Builder::new()
        .prefix("aos-hub-deploy")
        .tempdir()
        .context("creating a temporary deploy directory")?;
    let work_dir = work.path();
    let config = stage_deploy(assets, cfg, work_dir).await?;
    run_wrangler(assets, &deploy_args(&config), None, Some(work_dir)).await?;

    let jwt_secret = secrets
        .jwt_secret
        .clone()
        .unwrap_or_else(|| generate_hex_secret(32));
    let seal_key = secrets
        .seal_key
        .clone()
        .unwrap_or_else(|| generate_hex_secret(32));
    let minted = secrets.jwt_secret.is_none() || secrets.seal_key.is_none();

    put_secret(assets, "HUB_JWT_SECRET", &jwt_secret, &config).await?;
    put_secret(assets, "HUB_SEAL_KEY", &seal_key, &config).await?;
    if let Some(pw) = &secrets.root_password {
        put_secret(assets, "HUB_ROOT_PASSWORD", pw, &config).await?;
    }
    if let Some(tok) = &secrets.email_api_token {
        put_secret(assets, "HUB_EMAIL_API_TOKEN", tok, &config).await?;
    }

    Ok(Applied {
        jwt_secret,
        seal_key,
        minted,
    })
}

/// Sets one Worker secret via `wrangler secret put` (value piped on stdin).
///
/// # Errors
///
/// Returns an error if the `wrangler secret put` invocation fails.
async fn put_secret(assets: &Assets, name: &str, value: &str, config: &Path) -> Result<()> {
    run_wrangler(assets, &secret_put_args(name, config), Some(value), None)
        .await
        .with_context(|| format!("setting secret {name}"))?;
    Ok(())
}

/// Requests `GET {base_url}/_init` to apply the schema (and bootstrap root) on
/// the live Worker.
///
/// The Worker's `/_init` runs the shared `aos_registry_core` migrations over D1
/// and — when `HUB_ROOT_EMAIL`/`HUB_ROOT_PASSWORD` are set — creates the root
/// admin. It needs no JWT/seal secret (that path is Worker-local), so it can run
/// immediately after deploy.
///
/// # Errors
///
/// Returns an error if the request fails or the Worker responds non-success
/// (the body is included for diagnosis).
pub async fn init_remote(base_url: &str) -> Result<String> {
    let url = format!("{}/_init", base_url.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .with_context(|| format!("requesting {url}"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("GET {url} returned {status}: {}", body.trim());
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d1_id_parses_bare_array_and_envelope() {
        let bare = r#"[{"uuid":"abc-123","name":"aos-registry-hub","version":"alpha"}]"#;
        assert_eq!(parse_d1_id(bare, "aos-registry-hub").unwrap(), "abc-123");

        let env = r#"{"result":[{"database_id":"def-456","name":"other"},
                                 {"uuid":"ghi-789","name":"aos-registry-hub"}]}"#;
        assert_eq!(parse_d1_id(env, "aos-registry-hub").unwrap(), "ghi-789");
    }

    #[test]
    fn d1_id_missing_is_an_error() {
        let bare = r#"[{"uuid":"abc","name":"something-else"}]"#;
        assert!(parse_d1_id(bare, "aos-registry-hub").is_err());
    }

    #[test]
    fn kv_id_parses_by_title() {
        let json = r#"[{"id":"ns-1","title":"other"},{"id":"ns-2","title":"SESSIONS"}]"#;
        assert_eq!(parse_kv_id(json, "SESSIONS").unwrap(), "ns-2");
        assert!(parse_kv_id(json, "absent").is_err());
    }

    #[test]
    fn generated_secret_is_hex_of_expected_length() {
        let s = generate_hex_secret(32);
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        // Two draws differ with overwhelming probability.
        assert_ne!(s, generate_hex_secret(32));
    }

    #[test]
    fn argv_builders_match_wrangler_grammar() {
        assert_eq!(d1_create_args("db"), ["d1", "create", "db"]);
        assert_eq!(
            r2_create_args("bkt"),
            ["r2", "bucket", "create", "bkt"]
        );
        assert_eq!(
            kv_create_args("SESSIONS"),
            ["kv", "namespace", "create", "SESSIONS"]
        );
        assert_eq!(d1_list_args(), ["d1", "list", "--json"]);
        assert_eq!(kv_list_args(), ["kv", "namespace", "list"]);
        assert_eq!(
            secret_put_args("HUB_JWT_SECRET", Path::new("/tmp/w.toml")),
            ["secret", "put", "HUB_JWT_SECRET", "--config", "/tmp/w.toml"]
        );
        assert_eq!(
            deploy_args(Path::new("/tmp/w.toml")),
            ["deploy", "--config", "/tmp/w.toml"]
        );
    }

    #[test]
    fn rendered_toml_has_bindings_vars_and_no_build() {
        let cfg = DeployConfig {
            name: "aos-registry-hub".into(),
            d1_name: "aos-registry-hub".into(),
            d1_id: "d1-uuid".into(),
            bucket: "aos-registry-surfaces".into(),
            kv_id: "kv-id".into(),
            external_url: "https://reg.example.com".into(),
            root_email: Some("ops@example.com".into()),
            email_relay_url: None,
        };
        let toml = render_wrangler_toml(&cfg);
        // Parses as valid TOML.
        let parsed: toml::Value = toml::from_str(&toml).expect("valid TOML");
        assert_eq!(parsed["name"].as_str(), Some("aos-registry-hub"));
        assert_eq!(parsed["main"].as_str(), Some("shim.mjs"));
        assert_eq!(
            parsed["vars"]["HUB_EXTERNAL_URL"].as_str(),
            Some("https://reg.example.com")
        );
        assert_eq!(
            parsed["vars"]["HUB_ROOT_EMAIL"].as_str(),
            Some("ops@example.com")
        );
        assert_eq!(parsed["d1_databases"][0]["binding"].as_str(), Some(D1_BINDING));
        assert_eq!(parsed["d1_databases"][0]["database_id"].as_str(), Some("d1-uuid"));
        assert_eq!(parsed["kv_namespaces"][0]["id"].as_str(), Some("kv-id"));
        assert_eq!(parsed["triggers"]["crons"][0].as_str(), Some(INDEXER_CRON));
        // No build command — we deploy the prebuilt dist.
        assert!(parsed.get("build").is_none());
    }

    #[test]
    fn toml_string_escapes_quotes_and_backslashes() {
        assert_eq!(toml_string(r#"a"b\c"#), r#""a\"b\\c""#);
    }
}
