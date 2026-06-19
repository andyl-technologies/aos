//! Cloudflare deployment orchestration — provision, deploy, and initialise a
//! Worker deployment of this hub's wasm sibling (`aos-hub-worker`).
//!
//! The native binary is both the hub *server* and the *installer* for its
//! Cloudflare counterpart: `wasm32-unknown-unknown` in the Workers runtime
//! cannot spawn `wrangler`, read operator credentials, or touch the filesystem,
//! so the install/maintenance tooling is necessarily native and the compiled
//! Worker (`shim.mjs` + `index.wasm`) is a **payload it ships**, not something it
//! runs in-process. This module shells out to a bundled `wrangler` (located via
//! [`Assets::from_env`], packaged by the `aos-hub-cloudflare` Nix
//! wrapper) for the **provider-specific** part of a deployment:
//!
//! 1. **provision** — create the D1 database, R2 bucket, and KV namespace,
//! 2. **deploy** — render a [`wrangler.toml`](render_wrangler_toml) over the
//!    bundled wasm dist and `wrangler deploy` it,
//! 3. **secrets** — `wrangler secret put` the runtime secrets.
//!
//! Database migration and root-admin bootstrap are **not** done here and there
//! is no public init endpoint: they run through the provider-neutral CLI `init`
//! over `--target d1:<name>` (the [`WranglerD1Backend`] in this module), so the
//! schema is applied by the authenticated operator, not over HTTP.
//!
//! The generated config has no `[build]` command — it deploys the *prebuilt*
//! hermetic dist rather than re-running `worker-build` on the operator's
//! machine:
//!
//! ```toml
//! name = "aos-hub"
//! main = "shim.mjs"
//! compatibility_date = "2024-09-23"
//! compatibility_flags = ["nodejs_compat"]
//!
//! [vars]
//! HUB_EXTERNAL_URL = "https://reg.example.com"
//!
//! [[d1_databases]]
//! binding = "REGISTRY_DB"
//! database_name = "aos-hub"
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
//! `wrangler` invocations (provision, deploy, `d1 execute`) require a real Cloudflare
//! account and are validated operator-side (see `DEPLOY.md`), exactly like the
//! Worker runtime tests that need a workerd host.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// The D1 binding name — must match `aos_hub_worker::handlers::bindings`.
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
/// The `aos-hub-cloudflare` Nix wrapper sets `AOS_HUB_WORKER_DIST` (the
/// directory holding `shim.mjs` + `index.wasm`) and `AOS_HUB_WRANGLER` (the
/// `wrangler` launcher). A lean (non-wrapped) build leaves them unset, and the
/// `cloudflare` commands fail with guidance to use the wrapped package.
pub struct Assets {
    /// Directory containing the prebuilt `shim.mjs` and `index.wasm`.
    pub dist_dir: PathBuf,
    /// The static-asset directory (`dist_dir/assets`) Cloudflare serves from its
    /// CDN edge via the `[assets]` binding, or `None` when the dist predates the
    /// static-asset bundle (then `/_assets/*` falls back to the Worker handlers).
    pub assets_dir: Option<PathBuf>,
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
    /// `aos-hub-cloudflare` package), or if `shim.mjs`/`index.wasm` is
    /// missing from the dist directory.
    pub fn from_env() -> Result<Assets> {
        let dist = non_empty_env("AOS_HUB_WORKER_DIST").context(
            "AOS_HUB_WORKER_DIST is not set — this build was not packaged with the worker \
             artifact; install and run the `aos-hub-cloudflare` package",
        )?;
        let wrangler = non_empty_env("AOS_HUB_WRANGLER").context(
            "AOS_HUB_WRANGLER is not set — install and run the \
             `aos-hub-cloudflare` package",
        )?;
        let dist_dir = PathBuf::from(dist);
        for f in ["shim.mjs", "index.wasm"] {
            let p = dist_dir.join(f);
            if !p.exists() {
                bail!("worker dist is missing {f} at {}", p.display());
            }
        }
        let assets_path = dist_dir.join("assets");
        let assets_dir = assets_path.is_dir().then_some(assets_path);
        let wrangler = wrangler.split_whitespace().map(str::to_string).collect();
        Ok(Assets {
            dist_dir,
            assets_dir,
            wrangler,
        })
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
    /// The hub's canonical public base URL, baked into the `HUB_EXTERNAL_URL`
    /// `[vars]` entry — or **empty** to omit it, in which case the Worker derives
    /// its canonical URL from each request's origin (its `*.workers.dev` URL or a
    /// bound [`custom_domains`](Self::custom_domains) entry).
    ///
    /// When set, it's the origin the hub emits about itself (the `{url}/{slug}`
    /// push URL in setup snippets, the OIDC `redirect_uri` base, the WebAuthn
    /// relying-party ID, browse links). The `worker` CLI leaves it empty by
    /// default and relies on the request-origin fallback.
    pub external_url: String,
    /// The magic-link email relay endpoint (`HUB_EMAIL_API_URL` `[vars]`).
    pub email_relay_url: Option<String>,
    /// Custom domains to bind the Worker to (e.g. `aos.example.com`), each
    /// emitted as its own `custom_domain` route so Cloudflare sends that hostname
    /// to this Worker. Empty serves on `*.workers.dev` only. Every domain's zone
    /// must be on the same Cloudflare account. Bind the hub's own domain plus any
    /// per-registry/per-cache frontend domains it dispatches by `Host`.
    pub custom_domains: Vec<String>,
    /// Whether to emit an `[assets]` directory binding so Cloudflare serves the
    /// staged `/_assets/*` files from its CDN edge (bypassing the Worker). Set
    /// from [`Assets::assets_dir`] at deploy time; `false` for a dist without the
    /// static-asset bundle, in which case `/_assets/*` is served by the Worker.
    pub serve_assets: bool,
}

/// Renders the deployment `wrangler.toml` over the prebuilt wasm dist.
///
/// `main` is `shim.mjs` (relative to the config's directory, where the dist is
/// staged). There is intentionally **no** `[build]` command — the hermetic dist
/// is deployed as-is rather than rebuilt on the operator's machine. The non-
/// secret configuration (optional `HUB_EXTERNAL_URL` / `HUB_EMAIL_API_URL`) is
/// baked into `[vars]`; secrets are applied separately with [`secret_put_args`].
///
/// `HUB_EXTERNAL_URL` is omitted when [`DeployConfig::external_url`] is empty —
/// the Worker then derives its canonical URL from each request's origin (its
/// `*.workers.dev` URL or a bound domain), so a no-custom-domain deploy needs no
/// URL configuration.
#[must_use]
pub fn render_wrangler_toml(cfg: &DeployConfig) -> String {
    let mut vars = String::from("[vars]\n");
    if !cfg.external_url.is_empty() {
        vars.push_str(&format!(
            "HUB_EXTERNAL_URL = {}\n",
            toml_string(&cfg.external_url)
        ));
    }
    if let Some(relay) = &cfg.email_relay_url {
        vars.push_str(&format!("HUB_EMAIL_API_URL = {}\n", toml_string(relay)));
    }
    // Each custom-domain route binds the Worker to one hostname (e.g.
    // aos.example.com); `wrangler deploy` provisions the domain (DNS record +
    // cert) when the zone is on the account. With none, the Worker serves on
    // *.workers.dev only. Multiple routes let one Worker serve the hub's own
    // domain plus per-registry/per-cache frontend domains it dispatches by Host.
    let routes: String = cfg
        .custom_domains
        .iter()
        .map(|domain| {
            format!(
                "[[routes]]\npattern = {}\ncustom_domain = true\n\n",
                toml_string(domain)
            )
        })
        .collect();
    // Serve the staged static files (`/_assets/*`) straight from Cloudflare's CDN
    // edge: a request matching a file under `./assets` is answered without
    // invoking the Worker. `html_handling = "none"` keeps the match literal (no
    // trailing-slash/index.html remapping), so every non-asset path — `/`, the
    // `/{slug}/-/…` browse routes, and the Connect RPCs — still falls through to
    // the Worker as before.
    let assets = if cfg.serve_assets {
        "[assets]\ndirectory = \"./assets\"\nhtml_handling = \"none\"\n\n"
    } else {
        ""
    };
    format!(
        "# Generated by `aos-hub worker` — do not edit by hand.\n\
         name = {name}\n\
         main = \"shim.mjs\"\n\
         compatibility_date = \"{compat}\"\n\
         compatibility_flags = [\"nodejs_compat\"]\n\
         \n{vars}\n\
         {assets}\
         {routes}\
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
        assets = assets,
        routes = routes,
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

/// `wrangler secret list --config <path>` — list the names of the secrets
/// already attached to the Worker.
///
/// Used to make redeploys idempotent: a secret that already exists is preserved
/// rather than re-minted (see [`deploy`]).
#[must_use]
pub fn secret_list_args(config: &Path) -> Vec<String> {
    vec![
        "secret".into(),
        "list".into(),
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

/// Extracts the secret names from `wrangler secret list` output.
///
/// Accepts either a bare array (`[{ "name": …, "type": … }]`) or a
/// `{ "result": [...] }` envelope, and tolerates a non-JSON progress prelude
/// printed before the payload by skipping to the first `[`/`{`. A Worker with no
/// secrets yields an empty list.
///
/// # Errors
///
/// Returns an error if the JSON cannot be parsed or has an unexpected shape.
pub fn parse_secret_names(list_json: &str) -> Result<Vec<String>> {
    let start = list_json.find(['[', '{']).unwrap_or(0);
    let v: serde_json::Value = serde_json::from_str(&list_json[start..])
        .context("parsing `wrangler secret list` output")?;
    let arr = json_array(&v).context("unexpected `wrangler secret list` JSON shape")?;
    Ok(arr
        .iter()
        .filter_map(|s| s.get("name").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect())
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
        // wrangler prints some failures (notably a D1 `{"error":…}` envelope on
        // `d1 execute`) to stdout, not stderr — include both so the real cause
        // isn't swallowed.
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = [stderr.trim(), stdout.trim()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" | ");
        bail!(
            "`wrangler {}` failed ({}): {detail}",
            args.join(" "),
            output.status,
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

/// Runs `wrangler` with the parent's stdio **inherited** (no capture), for
/// interactive flows such as the OAuth browser login that print a URL and wait
/// on a local callback.
///
/// # Errors
///
/// Returns an error if the process cannot be spawned or exits non-zero.
async fn run_wrangler_interactive(assets: &Assets, args: &[String]) -> Result<()> {
    let (program, prefix) = assets
        .wrangler
        .split_first()
        .context("AOS_HUB_WRANGLER resolved to an empty launcher")?;
    let status = Command::new(program)
        .args(prefix)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .with_context(|| format!("spawning `{program} {}`", args.join(" ")))?;
    if !status.success() {
        bail!("`wrangler {}` failed ({status})", args.join(" "));
    }
    Ok(())
}

/// Cloudflare's interactive **OAuth browser login** (`wrangler login`).
///
/// An alternative to the `CLOUDFLARE_API_TOKEN` environment variable: it opens
/// the operator's browser to authorize, then stores the OAuth credentials that
/// the deploy/`d1 execute` calls pick up automatically. The callback runs on a
/// localhost port of the *host running this command*, so over SSH to a remote
/// builder it needs a forwarded port (see `DEPLOY.md`).
///
/// # Errors
///
/// Returns an error if `wrangler login` fails.
pub async fn login(assets: &Assets) -> Result<()> {
    run_wrangler_interactive(assets, &["login".to_string()]).await
}

/// Clears Cloudflare's stored OAuth credentials (`wrangler logout`).
///
/// # Errors
///
/// Returns an error if `wrangler logout` fails.
pub async fn logout(assets: &Assets) -> Result<()> {
    run_wrangler_interactive(assets, &["logout".to_string()]).await
}

/// Shows the current Cloudflare authentication — token or OAuth, and the account
/// (`wrangler whoami`).
///
/// # Errors
///
/// Returns an error if `wrangler whoami` fails.
pub async fn whoami(assets: &Assets) -> Result<()> {
    run_wrangler_interactive(assets, &["whoami".to_string()]).await
}

/// The runtime secrets to apply to the Worker.
///
/// An explicit `jwt_secret`/`seal_key` is always pushed (an intentional
/// rotation). When `None`, [`deploy`] preserves the value already on the Worker
/// and mints a fresh one only on a first deploy where the secret is absent. The
/// others are optional features.
pub struct Secrets {
    /// `HUB_JWT_SECRET` — HS256 JWT signing key. `None` = preserve-or-mint.
    pub jwt_secret: Option<String>,
    /// `HUB_SEAL_KEY` — at-rest AES-GCM sealing key. `None` = preserve-or-mint.
    pub seal_key: Option<String>,
    /// `HUB_EMAIL_API_TOKEN` — bearer token for the magic-link email relay.
    pub email_api_token: Option<String>,
}

/// The outcome of a deploy: the secrets *freshly minted* this run, so the
/// operator can record values that are otherwise unrecoverable.
///
/// A field is `Some` only when [`deploy`] generated a new random value (the
/// operator passed `None` and the Worker had no prior secret of that name). A
/// secret supplied explicitly or preserved from a previous deploy is reported as
/// `None` — there is nothing new to record.
pub struct Applied {
    /// A freshly minted `HUB_JWT_SECRET`, or `None` if supplied or preserved.
    pub minted_jwt_secret: Option<String>,
    /// A freshly minted `HUB_SEAL_KEY`, or `None` if supplied or preserved.
    pub minted_seal_key: Option<String>,
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
    email_relay_url: Option<&str>,
    custom_domains: &[String],
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
        email_relay_url: email_relay_url.map(str::to_string),
        custom_domains: custom_domains.to_vec(),
        serve_assets: assets.assets_dir.is_some(),
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
    // Stage the static-asset bundle next to the config so the generated
    // `directory = "./assets"` resolves. Skipped for a dist without one (then no
    // `[assets]` block is emitted and the Worker serves `/_assets/*` itself).
    if let Some(src) = &assets.assets_dir {
        copy_dir_all(src, &dir.join("assets"))
            .await
            .context("staging the static-asset bundle")?;
    }
    let config = dir.join("wrangler.toml");
    tokio::fs::write(&config, render_wrangler_toml(cfg))
        .await
        .context("writing generated wrangler.toml")?;
    Ok(config)
}

/// Recursively copies the directory tree rooted at `src` into `dst`, creating
/// `dst` and any intermediate directories.
///
/// # Errors
///
/// Returns an error if any directory cannot be created or any entry cannot be
/// read or copied.
async fn copy_dir_all(src: &Path, dst: &Path) -> Result<()> {
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((from, to)) = stack.pop() {
        tokio::fs::create_dir_all(&to)
            .await
            .with_context(|| format!("creating {}", to.display()))?;
        let mut entries = tokio::fs::read_dir(&from)
            .await
            .with_context(|| format!("reading {}", from.display()))?;
        while let Some(entry) = entries.next_entry().await? {
            let kind = entry.file_type().await?;
            let child_from = entry.path();
            let child_to = to.join(entry.file_name());
            if kind.is_dir() {
                stack.push((child_from, child_to));
            } else {
                tokio::fs::copy(&child_from, &child_to)
                    .await
                    .with_context(|| format!("copying {}", child_from.display()))?;
            }
        }
    }
    Ok(())
}

/// Deploys the staged dist and applies the runtime secrets.
///
/// Stages the dist + generated config into a private temporary directory (cleaned
/// up on return). Order matters: `wrangler deploy` creates the Worker (and bakes
/// `[vars]`), then `wrangler secret put` attaches the secrets to the live Worker.
///
/// Secret application is **idempotent across redeploys**: after deploying, the
/// Worker's existing secrets are listed and any already-present `HUB_JWT_SECRET`
/// / `HUB_SEAL_KEY` is preserved rather than re-minted. Rotating `HUB_SEAL_KEY`
/// would orphan at-rest sealed data and rotating `HUB_JWT_SECRET` would
/// invalidate every active session, so a fresh value is minted only on a first
/// deploy where the secret is absent (or when the operator passes one explicitly
/// to force a rotation).
///
/// # Errors
///
/// Returns an error if the temp dir, staging, the deploy, the secret listing, or
/// any `secret put` fails.
pub async fn deploy(assets: &Assets, cfg: &DeployConfig, secrets: &Secrets) -> Result<Applied> {
    let work = tempfile::Builder::new()
        .prefix("aos-hub-deploy")
        .tempdir()
        .context("creating a temporary deploy directory")?;
    let work_dir = work.path();
    let config = stage_deploy(assets, cfg, work_dir).await?;
    run_wrangler(assets, &deploy_args(&config), None, Some(work_dir)).await?;

    let listed = run_wrangler(assets, &secret_list_args(&config), None, None).await?;
    let existing = parse_secret_names(&listed)?;

    let minted_jwt_secret =
        apply_secret(assets, "HUB_JWT_SECRET", secrets.jwt_secret.as_deref(), &existing, &config)
            .await?;
    let minted_seal_key =
        apply_secret(assets, "HUB_SEAL_KEY", secrets.seal_key.as_deref(), &existing, &config)
            .await?;
    if let Some(tok) = &secrets.email_api_token {
        put_secret(assets, "HUB_EMAIL_API_TOKEN", tok, &config).await?;
    }

    Ok(Applied {
        minted_jwt_secret,
        minted_seal_key,
    })
}

/// Resolves and applies one preserve-or-mint secret, returning a freshly minted
/// value to report (or `None` when supplied or preserved).
///
/// Precedence: an explicit `provided` value is always pushed (an intentional
/// rotation); otherwise a secret already present in `existing` is left untouched;
/// otherwise a fresh 32-byte hex value is minted and pushed.
///
/// # Errors
///
/// Returns an error if the `wrangler secret put` invocation fails.
async fn apply_secret(
    assets: &Assets,
    name: &str,
    provided: Option<&str>,
    existing: &[String],
    config: &Path,
) -> Result<Option<String>> {
    match provided {
        Some(value) => {
            put_secret(assets, name, value, config).await?;
            Ok(None)
        }
        None if existing.iter().any(|n| n == name) => Ok(None),
        None => {
            let minted = generate_hex_secret(32);
            put_secret(assets, name, &minted, config).await?;
            Ok(Some(minted))
        }
    }
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

// ── WranglerD1Backend — the unification seam ────────────────────────────────
//
// A `Backend` that runs SQL against a live D1 database through the bundled
// `wrangler d1 execute`. Attaching it to the shared `aos_hub_core::Database`
// makes every hub maintenance operation (e.g. resetting the root password) run
// over Cloudflare D1 with the *same* application code that runs against the
// native sqlite file — the demonstration that the CLI is one codebase across the
// native and Cloudflare backends.

use aos_hub_core::backend::{with_returning_id, Backend, Statement};
use aos_hub_core::dialect::Dialect;
use aos_hub_core::value::{FromValue, Row, Value};

/// Renders a [`Value`] as a SQLite literal for inlining into a statement.
///
/// `wrangler d1 execute` exposes no bound-parameter binding (only a SQL string),
/// so [`WranglerD1Backend`] substitutes each `?N` placeholder with the escaped
/// literal of its parameter. Text is single-quoted with `'` doubled; bytes
/// become an `X'…'` blob literal.
///
/// # Errors
///
/// Returns an error for a non-finite [`Value::Real`] (NaN/∞ has no SQL literal).
fn sql_literal(v: &Value) -> Result<String> {
    Ok(match v {
        Value::Null => "NULL".to_string(),
        Value::Int(i) => i.to_string(),
        Value::Real(f) => {
            if !f.is_finite() {
                bail!("cannot render non-finite float {f} as a SQL literal");
            }
            format!("{f:?}") // {:?} keeps a decimal point (e.g. 1.0), a valid numeric literal
        }
        Value::Text(s) => format!("'{}'", s.replace('\'', "''")),
        Value::Bytes(b) => format!("X'{}'", hex::encode(b)),
    })
}

/// Substitutes `?N` placeholders in `sql` with the SQL literals of `params`.
///
/// `?N` is one-based (`?1` → `params[0]`), matching the sqlite numbered
/// placeholders the `Database` methods write. Placeholders inside `'…'` string
/// literals are left untouched (a `?` in a default value is data, not a bind
/// site).
///
/// # Errors
///
/// Returns an error if a `?` is not followed by a decimal index, an index is out
/// of range, or a parameter cannot be rendered ([`sql_literal`]).
fn inline_params(sql: &str, params: &[Value]) -> Result<String> {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if c == '\'' {
                // A doubled '' is two toggles (close then re-open), so the
                // in-string region is tracked correctly across escapes.
                in_string = false;
            }
            continue;
        }
        match c {
            '\'' => {
                in_string = true;
                out.push(c);
            }
            '?' => {
                let mut digits = String::new();
                while let Some(d) = chars.peek() {
                    if d.is_ascii_digit() {
                        digits.push(*d);
                        chars.next();
                    } else {
                        break;
                    }
                }
                let n: usize = digits
                    .parse()
                    .ok()
                    .filter(|n| *n >= 1)
                    .with_context(|| format!("placeholder '?' not followed by a 1-based index in: {sql}"))?;
                let value = params
                    .get(n - 1)
                    .with_context(|| format!("placeholder ?{n} has no parameter ({} bound)", params.len()))?;
                out.push_str(&sql_literal(value)?);
            }
            _ => out.push(c),
        }
    }
    Ok(out)
}

/// Converts a JSON scalar from a D1 result row into a [`Value`].
///
/// Integers map to [`Value::Int`], non-integer numbers to [`Value::Real`], a
/// JSON array of byte-range integers to [`Value::Bytes`] (D1's BLOB encoding),
/// and `null` to [`Value::Null`]. Anything else falls back to its JSON text as
/// [`Value::Text`].
fn json_to_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Int(i64::from(*b)),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i)
            } else if let Some(u) = n.as_u64() {
                Value::Int(i64::try_from(u).unwrap_or(i64::MAX))
            } else {
                Value::Real(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => Value::Text(s.clone()),
        serde_json::Value::Array(items) => {
            let bytes: Option<Vec<u8>> = items
                .iter()
                .map(|i| i.as_u64().and_then(|u| u8::try_from(u).ok()))
                .collect();
            match bytes {
                Some(b) => Value::Bytes(b),
                None => Value::Text(v.to_string()),
            }
        }
        serde_json::Value::Object(_) => Value::Text(v.to_string()),
    }
}

/// One D1 result row, deserialized preserving column order.
///
/// `serde_json`'s default object map sorts keys, which would scramble the
/// positional [`Row`] the `Database` reads by index. This visits the JSON object
/// in source order (which `wrangler d1 execute --json` emits in SELECT-list
/// order) and keeps the values in that order.
#[derive(Debug)]
struct D1Row(Vec<Value>);

impl<'de> serde::Deserialize<'de> for D1Row {
    fn deserialize<D>(deserializer: D) -> std::result::Result<D1Row, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct RowVisitor;
        impl<'de> serde::de::Visitor<'de> for RowVisitor {
            type Value = D1Row;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a D1 result row object")
            }
            fn visit_map<A>(self, mut map: A) -> std::result::Result<D1Row, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some((_key, value)) =
                    map.next_entry::<String, serde_json::Value>()?
                {
                    values.push(json_to_value(&value));
                }
                Ok(D1Row(values))
            }
        }
        deserializer.deserialize_map(RowVisitor)
    }
}

/// D1 per-statement metadata; `changes`/`last_row_id` are populated on the
/// remote backend (the `--local` miniflare engine omits them).
#[derive(Debug, serde::Deserialize, Default)]
struct D1Meta {
    #[serde(default)]
    changes: Option<i64>,
}

/// One result set from `wrangler d1 execute --json` (one per statement).
#[derive(Debug, serde::Deserialize)]
struct D1ResultSet {
    #[serde(default)]
    results: Vec<D1Row>,
    #[serde(default)]
    meta: D1Meta,
}

/// The `{ "error": { "text": … } }` envelope `wrangler d1 execute` prints on a
/// SQL/engine error (in place of the success array).
#[derive(serde::Deserialize)]
struct D1ErrorEnvelope {
    error: D1ErrorBody,
}

/// The body of a [`D1ErrorEnvelope`].
#[derive(serde::Deserialize)]
struct D1ErrorBody {
    text: String,
}

/// Parses the first result set from `wrangler d1 execute --json` stdout,
/// surfacing a D1 error envelope as an error.
///
/// # Errors
///
/// Returns an error if `stdout` is a D1 error envelope, or cannot be parsed as a
/// non-empty array of result sets.
fn parse_first_result_set(stdout: &str) -> Result<D1ResultSet> {
    // On a `--file`/`--remote` run, wrangler 4.x prints file-upload progress
    // lines (`├ Checking if file needs uploading`, `🌀 Uploading…`) to stdout
    // *before* the JSON payload, so parse from the first `[`/`{` rather than the
    // start of the buffer. The progress prelude contains no brackets.
    let json = stdout
        .find(['[', '{'])
        .map_or(stdout, |start| &stdout[start..]);
    match serde_json::from_str::<Vec<D1ResultSet>>(json) {
        Ok(sets) => sets
            .into_iter()
            .next()
            .context("`wrangler d1 execute --json` returned no result set"),
        Err(parse_err) => {
            if let Ok(env) = serde_json::from_str::<D1ErrorEnvelope>(json) {
                bail!("D1 error: {}", env.error.text);
            }
            Err(parse_err).context("parsing `wrangler d1 execute --json` output")
        }
    }
}

/// `wrangler d1 execute <db> [--remote|--local] --json --file <path>`.
#[must_use]
fn d1_file_args(db: &str, remote: bool, file: &Path) -> Vec<String> {
    vec![
        "d1".into(),
        "execute".into(),
        db.into(),
        if remote { "--remote" } else { "--local" }.into(),
        "--json".into(),
        "--file".into(),
        file.display().to_string(),
    ]
}

/// `wrangler d1 execute <db> --remote --json --command <sql>` — run `sql` inline.
///
/// Used for remote reads only: unlike `--file` (which wrangler bulk-uploads,
/// returning only a stats summary), `--command` returns the query's row data.
/// The SQL is passed as a single argv element (the process is spawned directly,
/// not via a shell), so no escaping is required.
#[must_use]
fn d1_command_args(db: &str, sql: &str) -> Vec<String> {
    vec![
        "d1".into(),
        "execute".into(),
        db.into(),
        "--remote".into(),
        "--json".into(),
        "--command".into(),
        sql.into(),
    ]
}

/// Renders a minimal `wrangler.toml` declaring just the D1 binding.
///
/// `wrangler d1 execute <name>` resolves the database through a configuration
/// file's `[[d1_databases]]` entry (both `--local` and `--remote`), so the
/// backend writes this into its working directory. For `--local` the
/// `database_id` is irrelevant (local state is keyed by name); for `--remote` it
/// must be the real provisioned id.
fn d1_only_config(db_name: &str, db_id: &str) -> String {
    format!(
        "name = {name}\n\
         compatibility_date = \"{compat}\"\n\
         [[d1_databases]]\n\
         binding = \"{binding}\"\n\
         database_name = {name}\n\
         database_id = {id}\n",
        name = toml_string(db_name),
        compat = COMPAT_DATE,
        binding = D1_BINDING,
        id = toml_string(db_id),
    )
}

/// A [`Backend`] over a live Cloudflare D1 database, driven by the bundled
/// `wrangler d1 execute`.
///
/// SQL (with `?N` parameters inlined as literals — D1's CLI has no bind API) is
/// run via `--file` (SQL in a private temp file, kept out of the process argv)
/// for writes and batches. Remote *reads* are the exception: wrangler's
/// `--remote --file` path bulk-uploads the file and returns only a stats summary,
/// discarding the query's rows, so a remote `SELECT` or `INSERT … RETURNING`
/// goes through `--command` (the only remote transport that returns row data).
/// The inlined values that then reach the argv are query keys and ids, never a
/// secret — password hashes ride a write (`--file`). Results are read from the
/// `--json` output. `wrangler` runs with its working directory set to a private
/// temp dir holding a minimal `wrangler.toml` (so it can resolve the D1 binding,
/// and so `--local` state persists across calls). This is operator/bootstrap
/// tooling, not a request hot path: each call is one `wrangler` process and one
/// round-trip, which is fine for the low-volume maintenance it backs.
///
/// It implements the full [`Backend`] surface — `execute`/`execute_insert`/
/// `query`/`execute_batch`, and an atomic [`batch`](Backend::batch) via a
/// multi-statement `--file` run (which the D1 engine executes all-or-nothing) —
/// so the entire hub admin command tree can run against D1 through it.
pub struct WranglerD1Backend {
    /// The bundled `wrangler` launcher + dist locator.
    assets: Assets,
    /// The D1 database name passed to `d1 execute`.
    db_name: String,
    /// Whether to target the remote database (`--remote`) or the local miniflare
    /// engine (`--local`, used by the round-trip test).
    remote: bool,
    /// The working directory holding the generated `wrangler.toml` (and, for
    /// `--local`, the `.wrangler` state). Held for its lifetime so wrangler sees
    /// a stable config + state across calls; removed on drop.
    workdir: std::sync::Arc<tempfile::TempDir>,
}

impl WranglerD1Backend {
    /// Builds a backend over `db_name` (resolved by `db_id`), targeting the
    /// remote D1 when `remote`.
    ///
    /// Writes a minimal `wrangler.toml` into a private temp working directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the working directory or config file cannot be
    /// created.
    pub fn create(
        assets: Assets,
        db_name: String,
        db_id: &str,
        remote: bool,
    ) -> Result<WranglerD1Backend> {
        let workdir = tempfile::Builder::new()
            .prefix("aos-d1-ctx-")
            .tempdir()
            .context("creating the wrangler working directory")?;
        std::fs::write(workdir.path().join("wrangler.toml"), d1_only_config(&db_name, db_id))
            .context("writing the wrangler.toml for d1 execute")?;
        Ok(WranglerD1Backend {
            assets,
            db_name,
            remote,
            workdir: std::sync::Arc::new(workdir),
        })
    }

    /// Runs `sql` through `wrangler d1 execute` and parses the first result set.
    /// `sql` may contain multiple statements (used for migrations).
    ///
    /// `needs_rows` selects the transport. wrangler's `--remote --file` path
    /// bulk-uploads the file and returns only a stats summary (`Total queries
    /// executed`, `Rows read`, …) — **not** the query's rows — so a remote
    /// statement whose result rows the caller needs (a `SELECT`, or an
    /// `INSERT … RETURNING`) must go through `--command`, which returns the row
    /// data. Writes keep `--file` (only `meta` is read), so their SQL — and any
    /// inlined secret literal such as a password hash — stays out of the process
    /// argv. The `--local` engine returns rows from `--file`, so it is unaffected
    /// and always uses the file path.
    async fn run_sql(&self, sql: &str, needs_rows: bool) -> Result<D1ResultSet> {
        let stdout = if self.remote && needs_rows {
            let args = d1_command_args(&self.db_name, sql);
            run_wrangler(&self.assets, &args, None, Some(self.workdir.path())).await?
        } else {
            let file = tempfile::Builder::new()
                .prefix("aos-d1-")
                .suffix(".sql")
                .tempfile_in(self.workdir.path())
                .context("creating a temporary SQL file")?;
            tokio::fs::write(file.path(), sql)
                .await
                .context("writing the SQL to run")?;
            let args = d1_file_args(&self.db_name, self.remote, file.path());
            run_wrangler(&self.assets, &args, None, Some(self.workdir.path())).await?
        };
        parse_first_result_set(&stdout)
    }
}

/// Resolves a D1 database's id from its name via `wrangler d1 list --json`.
///
/// # Errors
///
/// Returns an error if the `d1 list` call fails or no database matches `name`.
pub async fn resolve_d1_id(assets: &Assets, name: &str) -> Result<String> {
    let list = run_wrangler(assets, &d1_list_args(), None, None).await?;
    parse_d1_id(&list, name)
}

#[async_trait::async_trait]
impl Backend for WranglerD1Backend {
    fn dialect(&self) -> Dialect {
        Dialect::Sqlite
    }

    async fn execute(&self, sql: &str, params: &[Value]) -> Result<u64> {
        let set = self.run_sql(&inline_params(sql, params)?, false).await?;
        // `meta.changes` is present on the remote backend; the `--local`
        // engine omits it, so fall back to 0 (no caller in the maintenance
        // paths depends on the affected-row count).
        Ok(set.meta.changes.unwrap_or(0).max(0) as u64)
    }

    async fn execute_insert(&self, sql: &str, params: &[Value]) -> Result<i64> {
        // Read the id back via RETURNING rather than `meta.last_row_id` (which
        // the `--local` engine omits), so inserts work on both targets.
        let set = self
            .run_sql(&inline_params(&with_returning_id(sql), params)?, true)
            .await?;
        let row = set
            .results
            .first()
            .context("INSERT … RETURNING id returned no row")?;
        row.0
            .first()
            .context("INSERT … RETURNING id returned an empty row")
            .and_then(|v| i64::from_value(v))
    }

    async fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Row>> {
        let set = self.run_sql(&inline_params(sql, params)?, true).await?;
        Ok(set.results.into_iter().map(|r| Row::new(r.0)).collect())
    }

    async fn execute_batch(&self, sql: &str) -> Result<()> {
        // DDL migrations carry no parameters and return no rows; the --file path
        // (a stats-only summary on --remote) is sufficient.
        self.run_sql(sql, false).await?;
        Ok(())
    }

    async fn batch(&self, stmts: &[Statement]) -> Result<()> {
        // `Backend::batch` must be atomic (all-or-nothing). `wrangler d1 execute
        // --file` runs a multi-statement file as one atomic unit — a mid-file
        // statement failure rolls back the earlier statements (verified against
        // the D1 engine: an earlier INSERT is undone when a later one violates a
        // UNIQUE constraint). So the statements are inlined and concatenated into
        // one `--file` run. The trait contracts that batch statements are
        // self-contained (ids assigned client-side, guards in `WHERE`, no
        // mid-flight `last_insert_rowid`), so literal inlining is sufficient.
        let mut script = String::new();
        for stmt in stmts {
            script.push_str(&inline_params(&stmt.sql, &stmt.params)?);
            script.push_str(";\n");
        }
        // Atomic all-or-nothing requires the --file path; callers don't read rows
        // back from a batch.
        self.run_sql(&script, false).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d1_id_parses_bare_array_and_envelope() {
        let bare = r#"[{"uuid":"abc-123","name":"aos-hub","version":"alpha"}]"#;
        assert_eq!(parse_d1_id(bare, "aos-hub").unwrap(), "abc-123");

        let env = r#"{"result":[{"database_id":"def-456","name":"other"},
                                 {"uuid":"ghi-789","name":"aos-hub"}]}"#;
        assert_eq!(parse_d1_id(env, "aos-hub").unwrap(), "ghi-789");
    }

    #[test]
    fn d1_id_missing_is_an_error() {
        let bare = r#"[{"uuid":"abc","name":"something-else"}]"#;
        assert!(parse_d1_id(bare, "aos-hub").is_err());
    }

    #[test]
    fn kv_id_parses_by_title() {
        let json = r#"[{"id":"ns-1","title":"other"},{"id":"ns-2","title":"SESSIONS"}]"#;
        assert_eq!(parse_kv_id(json, "SESSIONS").unwrap(), "ns-2");
        assert!(parse_kv_id(json, "absent").is_err());
    }

    #[test]
    fn secret_names_parse_bare_envelope_and_prelude() {
        let bare = r#"[{"name":"HUB_JWT_SECRET","type":"secret_text"},
                       {"name":"HUB_SEAL_KEY","type":"secret_text"}]"#;
        assert_eq!(
            parse_secret_names(bare).unwrap(),
            ["HUB_JWT_SECRET", "HUB_SEAL_KEY"]
        );

        let env = r#"{"result":[{"name":"HUB_SEAL_KEY","type":"secret_text"}]}"#;
        assert_eq!(parse_secret_names(env).unwrap(), ["HUB_SEAL_KEY"]);

        // A progress prelude printed before the JSON payload is skipped.
        let with_prelude = "⛅️ wrangler 4.20.0\n[]";
        assert!(parse_secret_names(with_prelude).unwrap().is_empty());
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
            secret_list_args(Path::new("/tmp/w.toml")),
            ["secret", "list", "--config", "/tmp/w.toml"]
        );
        assert_eq!(
            deploy_args(Path::new("/tmp/w.toml")),
            ["deploy", "--config", "/tmp/w.toml"]
        );
    }

    #[test]
    fn rendered_toml_has_bindings_vars_and_no_build() {
        let cfg = DeployConfig {
            name: "aos-hub".into(),
            d1_name: "aos-hub".into(),
            d1_id: "d1-uuid".into(),
            bucket: "aos-hub-surfaces".into(),
            kv_id: "kv-id".into(),
            external_url: String::new(),
            email_relay_url: None,
            custom_domains: vec!["aos.example.com".into()],
            serve_assets: false,
        };
        let toml = render_wrangler_toml(&cfg);
        // Parses as valid TOML.
        let parsed: toml::Value = toml::from_str(&toml).expect("valid TOML");
        assert_eq!(parsed["name"].as_str(), Some("aos-hub"));
        assert_eq!(parsed["main"].as_str(), Some("shim.mjs"));
        // No canonical URL is baked: the Worker derives it from the request.
        assert!(parsed["vars"].get("HUB_EXTERNAL_URL").is_none());
        // Root bootstrap is CLI-driven now; the worker no longer reads it.
        assert!(parsed["vars"].get("HUB_ROOT_EMAIL").is_none());
        // The custom domain is bound via a custom_domain route.
        assert_eq!(parsed["routes"][0]["pattern"].as_str(), Some("aos.example.com"));
        assert_eq!(parsed["routes"][0]["custom_domain"].as_bool(), Some(true));
        assert_eq!(parsed["d1_databases"][0]["binding"].as_str(), Some(D1_BINDING));
        assert_eq!(parsed["d1_databases"][0]["database_id"].as_str(), Some("d1-uuid"));
        assert_eq!(parsed["kv_namespaces"][0]["id"].as_str(), Some("kv-id"));
        assert_eq!(parsed["triggers"]["crons"][0].as_str(), Some(INDEXER_CRON));
        // No build command — we deploy the prebuilt dist.
        assert!(parsed.get("build").is_none());
        // serve_assets = false omits the [assets] binding.
        assert!(parsed.get("assets").is_none());
    }

    #[test]
    fn rendered_toml_binds_static_assets_when_requested() {
        let cfg = DeployConfig {
            name: "aos-hub".into(),
            d1_name: "aos-hub".into(),
            d1_id: "d1-uuid".into(),
            bucket: "aos-hub-surfaces".into(),
            kv_id: "kv-id".into(),
            external_url: String::new(),
            email_relay_url: None,
            custom_domains: vec![],
            serve_assets: true,
        };
        let parsed: toml::Value =
            toml::from_str(&render_wrangler_toml(&cfg)).expect("valid TOML");
        // The CDN-edge static-asset directory is bound, with literal matching so
        // non-asset paths still fall through to the Worker.
        assert_eq!(parsed["assets"]["directory"].as_str(), Some("./assets"));
        assert_eq!(parsed["assets"]["html_handling"].as_str(), Some("none"));
    }

    #[test]
    fn toml_string_escapes_quotes_and_backslashes() {
        assert_eq!(toml_string(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn sql_literals_escape_each_value_kind() {
        assert_eq!(sql_literal(&Value::Null).unwrap(), "NULL");
        assert_eq!(sql_literal(&Value::Int(-7)).unwrap(), "-7");
        assert_eq!(sql_literal(&Value::Real(1.5)).unwrap(), "1.5");
        assert_eq!(sql_literal(&Value::Real(1.0)).unwrap(), "1.0");
        assert_eq!(sql_literal(&Value::Text("it's".into())).unwrap(), "'it''s'");
        assert_eq!(sql_literal(&Value::Bytes(vec![0x27, 0xff])).unwrap(), "X'27ff'");
        assert!(sql_literal(&Value::Real(f64::NAN)).is_err());
    }

    #[test]
    fn inline_substitutes_numbered_placeholders() {
        let sql = "UPDATE users SET password_hash = ?2 WHERE id = ?1 AND deleted_at IS NULL";
        let out = inline_params(sql, &[Value::Int(42), Value::Text("phc$x".into())]).unwrap();
        assert_eq!(
            out,
            "UPDATE users SET password_hash = 'phc$x' WHERE id = 42 AND deleted_at IS NULL"
        );
    }

    #[test]
    fn inline_leaves_question_marks_inside_string_literals() {
        // A '?' inside a quoted literal is data, not a bind site.
        let out = inline_params("SELECT ?1, 'why?'", &[Value::Int(1)]).unwrap();
        assert_eq!(out, "SELECT 1, 'why?'");
    }

    #[test]
    fn inline_errors_on_out_of_range_or_bare_placeholder() {
        assert!(inline_params("SELECT ?2", &[Value::Int(1)]).is_err());
        assert!(inline_params("SELECT ?", &[Value::Int(1)]).is_err());
    }

    #[test]
    fn parse_result_set_preserves_select_column_order() {
        // SELECT order b, a, c — must NOT be re-sorted alphabetically.
        let json = r#"[{"results":[{"b":2,"a":1,"c":3}],"success":true,"meta":{"duration":0}}]"#;
        let set = parse_first_result_set(json).unwrap();
        assert_eq!(set.results.len(), 1);
        assert_eq!(
            set.results[0].0,
            vec![Value::Int(2), Value::Int(1), Value::Int(3)]
        );
    }

    #[test]
    fn parse_result_set_reads_changes_and_typed_columns() {
        let json = r#"[{"results":[{"id":1,"email":"a@b.c","n":1.5,"x":null}],
                       "success":true,"meta":{"changes":3,"last_row_id":1}}]"#;
        let set = parse_first_result_set(json).unwrap();
        assert_eq!(set.meta.changes, Some(3));
        assert_eq!(
            set.results[0].0,
            vec![
                Value::Int(1),
                Value::Text("a@b.c".into()),
                Value::Real(1.5),
                Value::Null
            ]
        );
    }

    #[test]
    fn parse_result_set_surfaces_d1_error_envelope() {
        let json = r#"{"error":{"text":"near \"FROM\": syntax error"}}"#;
        let err = parse_first_result_set(json).unwrap_err();
        assert!(err.to_string().contains("syntax error"));
    }

    #[test]
    fn parse_result_set_skips_wrangler_file_upload_prelude() {
        // A `--file`/`--remote` run prefixes the JSON with upload-progress lines;
        // the parser must skip them rather than choke at line 1.
        let stdout = "├ Checking if file needs uploading\n│\n├ 🌀 Uploading abc.sql\n│ 🌀 Uploading complete.\n│\n[{\"results\":[{\"n\":2}],\"success\":true,\"meta\":{\"changes\":1}}]\n";
        let set = parse_first_result_set(stdout).unwrap();
        assert_eq!(set.meta.changes, Some(1));
        assert_eq!(set.results[0].0, vec![Value::Int(2)]);
    }

    #[test]
    fn json_array_of_bytes_becomes_blob() {
        let v: serde_json::Value = serde_json::from_str("[39, 255, 0]").unwrap();
        assert_eq!(json_to_value(&v), Value::Bytes(vec![39, 255, 0]));
    }

    #[test]
    fn d1_file_args_targets_remote_or_local() {
        let p = Path::new("/tmp/q.sql");
        assert_eq!(
            d1_file_args("db", true, p),
            ["d1", "execute", "db", "--remote", "--json", "--file", "/tmp/q.sql"]
        );
        assert_eq!(d1_file_args("db", false, p)[3], "--local");
    }

    #[test]
    fn d1_command_args_inlines_sql_for_remote_reads() {
        assert_eq!(
            d1_command_args("db", "SELECT version FROM schema_version"),
            [
                "d1",
                "execute",
                "db",
                "--remote",
                "--json",
                "--command",
                "SELECT version FROM schema_version"
            ]
        );
    }
}
