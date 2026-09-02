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
//! 1. **provision** — create the R2 bucket and KV namespace (the relational
//!    system of record is the `HubDb` Durable Object's SQLite),
//! 2. **deploy** — render a [`wrangler.toml`](render_wrangler_toml) over the
//!    bundled wasm dist and `wrangler deploy` it,
//! 3. **secrets** — `wrangler secret put` the runtime secrets.
//!
//! Schema migration runs **inside `HubDb`** on first use (no external step). The
//! root admin is bootstrapped over a seal-gated `HubDb` endpoint via
//! [`bootstrap_root_remote`] (driven by `worker install` / `worker
//! bootstrap-root`), so there is still no unauthenticated init path.
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
//! [placement]
//! mode = "off"
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
//! `wrangler` invocations (provision and deploy) require a real Cloudflare
//! account and are validated operator-side (see `DEPLOY.md`), exactly like the
//! Worker runtime tests that need a workerd host.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{bail, Context, Result};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// The R2 binding name — must match the Worker's bindings.
const R2_BINDING: &str = aos_hub_core::binding::DEPLOYMENT_R2_ATTACHMENT;
/// The KV binding name — must match the Worker's bindings.
const KV_BINDING: &str = "SESSIONS";
/// The Workers compatibility date the dist is built and tested against.
const COMPAT_DATE: &str = "2024-09-23";
/// The Cron cadence that drives the indexer's `scheduled` handler.
const INDEXER_CRON: &str = "*/15 * * * *";
/// CPU budget for maintenance and Queue invocations that verify full surfaces.
const WORKER_CPU_LIMIT_MS: u32 = 300_000;
/// Subrequest budget for bounded walks of large published registry surfaces.
const WORKER_SUBREQUEST_LIMIT: u32 = 100_000;

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

/// Three account-unique Cloudflare rate-limit namespace identifiers.
///
/// Cloudflare shares counters between bindings that reuse a namespace ID, even
/// when those bindings belong to different Workers. Keeping these identifiers
/// in the deployment configuration prevents staging and production installs
/// from influencing each other's request budgets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateLimitNamespaces {
    burst5: String,
    burst10: String,
    browse120: String,
}

impl RateLimitNamespaces {
    /// Derives the three namespace IDs immediately above `base`.
    ///
    /// A base of `1000` preserves the original production IDs `1001` through
    /// `1003`; staging can use another account-unique range such as `2000`.
    ///
    /// # Errors
    ///
    /// Returns an error when `base` is zero or does not leave room for all
    /// three positive 32-bit namespace identifiers.
    pub fn from_base(base: u32) -> Result<Self> {
        anyhow::ensure!(base > 0, "rate-limit namespace base must be positive");
        let id = |offset| {
            base.checked_add(offset)
                .map(|value| value.to_string())
                .context("rate-limit namespace base is too large")
        };
        Ok(Self {
            burst5: id(1)?,
            burst10: id(2)?,
            browse120: id(3)?,
        })
    }
}

/// The fully-resolved inputs for rendering a deployment `wrangler.toml`.
#[derive(Clone)]
pub struct DeployConfig {
    /// The Worker name (`name` in `wrangler.toml`).
    pub name: String,
    /// The R2 bucket name.
    pub bucket: String,
    /// The provisioned KV namespace id.
    pub kv_id: String,
    /// The deferred-jobs Queue name.
    pub queue: String,
    /// Account-unique rate-limit namespaces for this Worker installation.
    pub rate_limit_namespaces: RateLimitNamespaces,
    /// Exact HTTPS endpoint of an optional repository-owned native egress router.
    /// `None` uses Cloudflare's Worker Fetch transport directly.
    pub egress_gateway_url: Option<String>,
    /// The required canonical public origin baked into `HUB_EXTERNAL_URL`.
    ///
    /// It is the origin the hub emits about itself (the `{url}/{slug}`
    /// push URL in setup snippets, the OIDC `redirect_uri` base, the WebAuthn
    /// relying-party ID, browse links). The `worker` CLI leaves it empty by
    /// default and relies on the request-origin fallback.
    pub external_url: String,
    /// Immutable source/build identity exposed by the deployed Worker.
    pub deployment_id: Option<String>,
    /// Independent, fail-closed OCI capability rollout policy.
    pub container_rollout: aos_hub_core::container_rollout::ContainerRollout,
    /// Stable named Durable Object instance containing the Hub database.
    pub database_instance: String,
    /// The magic-link email relay endpoint (`HUB_EMAIL_API_URL` `[vars]`).
    pub email_relay_url: Option<String>,
    /// The verified sender address for Cloudflare Email Service. When `Some`, the
    /// config emits a `[[send_email]]` binding named `EMAIL` (`remote = true`)
    /// plus a `HUB_EMAIL_FROM` `[vars]` entry, so the Worker delivers
    /// transactional email through the Email Service. `None` emits neither — a
    /// deploy without Email Service set up is unchanged, the binding appears only
    /// once the operator has onboarded their sender domain.
    pub email_from: Option<String>,
    /// Custom domains to bind the Worker to (e.g. `aos.example.com`), each
    /// emitted as its own `custom_domain` route so Cloudflare sends that hostname
    /// to this Worker. This list is the Worker's **complete** managed custom-domain
    /// set: `wrangler deploy` reconciles the live routes to exactly these, so a
    /// partial list would drop the omitted ones — list every domain the Worker
    /// should serve. Every domain's zone must be on the same Cloudflare account.
    /// Bind the hub's own domain plus typed endpoint domains
    /// it dispatches by `Host`.
    ///
    /// **Empty preserves, it does not unbind.** When empty, the generated config
    /// emits no `[[routes]]` block at all, and per Cloudflare's contract a deploy
    /// with no route keys leaves the Worker's existing custom domains untouched
    /// (route management is then out-of-band) — it does *not* revert the Worker to
    /// `*.workers.dev`-only. A routine code redeploy therefore needs no domains.
    pub custom_domains: Vec<String>,
    /// Whether to emit an `[assets]` directory binding so Cloudflare serves the
    /// staged `/_assets/*` files from its CDN edge (bypassing the Worker). Set
    /// from [`Assets::assets_dir`] at deploy time; `false` for a dist without the
    /// static-asset bundle, in which case `/_assets/*` is served by the Worker.
    pub serve_assets: bool,
    /// Whether to enable Workers Observability (persistent, queryable Workers
    /// Logs plus per-invocation metrics) via an `[observability]` block. On by
    /// default so production errors — including handler `500`s, which the Worker
    /// bridges from `tracing` to the console — are queryable after the fact.
    pub observability: bool,
    /// Fraction of invocations (`0.0`–`1.0`) sampled into Workers Logs when
    /// [`observability`](Self::observability) is on. `1.0` logs every request
    /// (best for debugging); lower it to control log volume/cost at scale.
    pub head_sampling_rate: f64,
    /// Whether to set the top-level `logpush = true` so the Worker's logs are
    /// pushed to a configured Logpush destination (a Cloudflare account-level
    /// Logpush job to R2/S3/HTTP). Independent of [`observability`](Self::observability).
    pub logpush: bool,
}

/// Renders the deployment `wrangler.toml` over the prebuilt wasm dist.
///
/// `main` is `shim.mjs` (relative to the config's directory, where the dist is
/// staged). There is intentionally **no** `[build]` command — the hermetic dist
/// is deployed as-is rather than rebuilt on the operator's machine. The
/// non-secret configuration (required `HUB_EXTERNAL_URL`; optional egress-router
/// URL and email relay/sender) is baked into `[vars]`; secrets are applied separately with
/// [`secret_put_args`]. When [`DeployConfig::email_from`] is set, a
/// `[[send_email]]` binding named `EMAIL` (`remote = true`) is emitted so the
/// Worker can deliver through Cloudflare Email Service.
///
/// `HUB_EXTERNAL_URL` is always an exact HTTPS origin. Deployment validation
/// rejects an empty or path-bearing value before rendering.
#[must_use]
pub fn render_wrangler_toml(cfg: &DeployConfig) -> String {
    let mut vars = String::from("[vars]\n");
    vars.push_str("HUB_DNS_JSON_ENDPOINT = \"https://dns.google/resolve\"\n");
    if let Some(url) = &cfg.egress_gateway_url {
        vars.push_str(&format!("HUB_EGRESS_GATEWAY_URL = {}\n", toml_string(url)));
    }
    vars.push_str(&format!(
        "HUB_EXTERNAL_URL = {}\n",
        toml_string(&cfg.external_url)
    ));
    if let Some(deployment_id) = &cfg.deployment_id {
        vars.push_str(&format!(
            "HUB_DEPLOYMENT_ID = {}\n",
            toml_string(deployment_id)
        ));
    }
    vars.push_str(&format!(
        "HUB_DATABASE_INSTANCE = {}\n",
        toml_string(&cfg.database_instance)
    ));
    // The v2 execution classes are stateless with respect to relational data:
    // they run the shared service by issuing short transactions to HubDb. An
    // operator may temporarily change this to `read` or `off` for a staged
    // rollback without migrating or reconciling any database rows.
    vars.push_str("HUB_REQUEST_SHARDING = \"on\"\n");
    vars.push_str(&format!(
        "HUB_OCI_PULL_ENABLED = \"{}\"\nHUB_OCI_PUSH_ENABLED = \"{}\"\nHUB_OCI_VERIFIED_PUBLICATION_ENABLED = \"{}\"\nHUB_OCI_ADMINISTRATION_ENABLED = \"{}\"\nHUB_OCI_GC_ENABLED = \"{}\"\n",
        cfg.container_rollout.pull,
        cfg.container_rollout.push,
        cfg.container_rollout.verified_publication,
        cfg.container_rollout.administration,
        cfg.container_rollout.garbage_collection,
    ));
    if let Some(relay) = &cfg.email_relay_url {
        vars.push_str(&format!("HUB_EMAIL_API_URL = {}\n", toml_string(relay)));
    }
    if let Some(from) = &cfg.email_from {
        vars.push_str(&format!("HUB_EMAIL_FROM = {}\n", toml_string(from)));
    }
    // The Cloudflare Email Service binding: present only when a verified sender
    // is configured, so a deploy without Email Service onboarded is unchanged.
    let send_email = if cfg.email_from.is_some() {
        "[[send_email]]\nname = \"EMAIL\"\nremote = true\n\n"
    } else {
        ""
    };
    // Each custom-domain route binds the Worker to one hostname (e.g.
    // aos.example.com); `wrangler deploy` provisions the domain (DNS record +
    // cert) when the zone is on the account. Multiple routes let one Worker serve
    // the hub's own domain plus endpoint domains it
    // dispatches by Host. With none, NO routes block is emitted — which (per
    // Cloudflare's contract) leaves any already-bound custom domains untouched
    // rather than unbinding them, so a code-only redeploy is non-destructive.
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
    // `logpush` is a top-level boolean; emit it only when enabled so a default
    // deploy's config stays minimal.
    let logpush = if cfg.logpush { "logpush = true\n" } else { "" };
    // Workers Observability: persistent, queryable Workers Logs + per-invocation
    // metrics. `head_sampling_rate` is rendered with a decimal point so it is a
    // TOML float (wrangler's schema expects a number in 0.0–1.0).
    let observability = if cfg.observability {
        let rate = if cfg.head_sampling_rate.fract() == 0.0 {
            format!("{:.1}", cfg.head_sampling_rate)
        } else {
            format!("{}", cfg.head_sampling_rate)
        };
        format!("\n[observability]\nenabled = true\nhead_sampling_rate = {rate}\n")
    } else {
        String::new()
    };
    // `[placement] mode = "off"` is hardcoded, never surfaced as a setting: the
    // hub is read-heavy, so the Worker must run at the edge near each client
    // before forwarding to a resource-affine execution object or HubDb, not be
    // pinned by smart placement. Emitting it on every deploy reverts any
    // dashboard toggle to `smart`.
    format!(
        "# Generated by `aos-hub worker` — do not edit by hand.\n\
         name = {name}\n\
         main = \"shim.mjs\"\n\
         compatibility_date = \"{compat}\"\n\
         compatibility_flags = [\"nodejs_compat\"]\n\
         {logpush}\
         \n{vars}\n\
         [limits]\n\
         cpu_ms = {cpu_limit_ms}\n\
         subrequests = {subrequest_limit}\n\
         \n\
         {assets}\
         {routes}\
         {send_email}\
         [placement]\n\
         mode = \"off\"\n\
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
         crons = [\"{cron}\"]\n\
         \n\
         [[durable_objects.bindings]]\n\
         name = \"COORDINATOR\"\n\
         class_name = \"CoordinatorObject\"\n\
         \n\
         [[durable_objects.bindings]]\n\
         name = \"HUB_DB\"\n\
         class_name = \"HubDb\"\n\
         \n\
         [[durable_objects.bindings]]\n\
         name = \"HUB_CONTROL_SHARDS\"\n\
         class_name = \"HubControlShard\"\n\
         \n\
         [[durable_objects.bindings]]\n\
         name = \"HUB_TENANT_SHARDS\"\n\
         class_name = \"HubTenantShard\"\n\
         \n\
         [[durable_objects.bindings]]\n\
         name = \"HUB_REGISTRY_SHARDS\"\n\
         class_name = \"HubRegistryShard\"\n\
         \n\
         [[durable_objects.bindings]]\n\
         name = \"HUB_CACHE_SHARDS\"\n\
         class_name = \"HubCacheShard\"\n\
         \n\
         [[migrations]]\n\
         tag = \"v1\"\n\
         new_classes = [\"CoordinatorObject\"]\n\
         new_sqlite_classes = [\"HubDb\"]\n\
         \n\
         [[migrations]]\n\
         tag = \"v2\"\n\
         new_classes = [\"HubControlShard\", \"HubTenantShard\", \"HubRegistryShard\", \"HubCacheShard\"]\n\
         \n\
         [[ratelimits]]\n\
         name = \"RL_BURST5\"\n\
         namespace_id = {rate_burst5}\n\
         [ratelimits.simple]\n\
         limit = 5\n\
         period = 60\n\
         \n\
         [[ratelimits]]\n\
         name = \"RL_BURST10\"\n\
         namespace_id = {rate_burst10}\n\
         [ratelimits.simple]\n\
         limit = 10\n\
         period = 60\n\
         \n\
         [[ratelimits]]\n\
         name = \"RL_BROWSE120\"\n\
         namespace_id = {rate_browse120}\n\
         [ratelimits.simple]\n\
         limit = 120\n\
         period = 60\n\
         \n\
         [[queues.producers]]\n\
         binding = \"JOBS\"\n\
         queue = {queue}\n\
         \n\
         [[queues.consumers]]\n\
         queue = {queue}\n\
         max_batch_size = 10\n\
         max_batch_timeout = 5\n\
         max_concurrency = 4\n\
         {observability}",
        name = toml_string(&cfg.name),
        compat = COMPAT_DATE,
        cpu_limit_ms = WORKER_CPU_LIMIT_MS,
        subrequest_limit = WORKER_SUBREQUEST_LIMIT,
        logpush = logpush,
        assets = assets,
        routes = routes,
        send_email = send_email,
        r2b = R2_BINDING,
        bucket = toml_string(&cfg.bucket),
        kvb = KV_BINDING,
        kvid = toml_string(&cfg.kv_id),
        queue = toml_string(&cfg.queue),
        rate_burst5 = toml_string(&cfg.rate_limit_namespaces.burst5),
        rate_burst10 = toml_string(&cfg.rate_limit_namespaces.burst10),
        rate_browse120 = toml_string(&cfg.rate_limit_namespaces.browse120),
        cron = INDEXER_CRON,
        observability = observability,
    )
}

/// Renders a string as a TOML basic-string literal (quoted, with `"` and `\`
/// escaped).
fn toml_string(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

// ── wrangler argv builders (pure; unit-tested) ──────────────────────────────

/// `wrangler r2 bucket create <bucket>` — provision an R2 bucket.
#[must_use]
pub fn r2_create_args(bucket: &str) -> Vec<String> {
    vec!["r2".into(), "bucket".into(), "create".into(), bucket.into()]
}

/// `wrangler r2 bucket lifecycle list <bucket>`.
#[must_use]
pub fn r2_multipart_lifecycle_list_args(bucket: &str) -> Vec<String> {
    vec![
        "r2".into(),
        "bucket".into(),
        "lifecycle".into(),
        "list".into(),
        bucket.into(),
    ]
}

/// `wrangler r2 bucket lifecycle add` for bounded abandoned multipart cleanup.
#[must_use]
pub fn r2_multipart_lifecycle_add_args(bucket: &str, rule: &str) -> Vec<String> {
    vec![
        "r2".into(),
        "bucket".into(),
        "lifecycle".into(),
        "add".into(),
        bucket.into(),
        rule.into(),
        String::new(),
        "--abort-multipart-days".into(),
        "7".into(),
        "--force".into(),
    ]
}

/// Reports whether Wrangler listed an enabled all-prefix multipart abort bound.
#[must_use]
pub fn r2_lifecycle_has_bounded_multipart_abort(output: &str, maximum_days: u64) -> bool {
    output.split("\n\n").any(|rule| {
        let field = |name: &str| {
            rule.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == name).then(|| value.trim())
            })
        };
        let Some(action) = field("action") else {
            return false;
        };
        let Some(age) = action.strip_prefix("Abort incomplete multipart uploads after ") else {
            return false;
        };
        let days = age
            .strip_suffix(" days")
            .or_else(|| age.strip_suffix(" day"))
            .and_then(|days| days.parse::<u64>().ok());
        field("enabled") == Some("Yes")
            && field("prefix") == Some("(all prefixes)")
            && days.is_some_and(|days| days <= maximum_days)
    })
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

/// `wrangler queues create <name>` — provision a deferred-jobs Queue.
#[must_use]
pub fn queue_create_args(name: &str) -> Vec<String> {
    vec!["queues".into(), "create".into(), name.into()]
}

/// `wrangler kv namespace list` — list KV namespaces as JSON (for id discovery).
///
/// `kv namespace list` emits a JSON array by default; passing `--json` is
/// rejected as an unknown flag, so this relies on that default output shape.
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

/// `wrangler secret delete <name> --config <path>` — removes an obsolete
/// Worker secret. Wrangler 4.20 asks for confirmation, which the deployer
/// supplies on stdin.
#[must_use]
pub fn secret_delete_args(name: &str, config: &Path) -> Vec<String> {
    vec![
        "secret".into(),
        "delete".into(),
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

/// Extracts the namespace id for `title` from `wrangler kv namespace list`
/// output.
///
/// # Errors
///
/// Returns an error if the JSON cannot be parsed, has an unexpected shape, or
/// contains no namespace whose `title` matches `title`.
pub fn parse_kv_id(list_json: &str, title: &str) -> Result<String> {
    let v: serde_json::Value =
        serde_json::from_str(list_json).context("parsing `wrangler kv namespace list` output")?;
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

/// Creates the instance root admin by POSTing to a deployed worker's seal-gated
/// `HubDb` bootstrap endpoint (`POST {base}/_admin/bootstrap-root`), returning
/// the new user id.
///
/// The worker runs the shared
/// [`bootstrap_root`](aos_hub_core::db::Database::bootstrap_root) over the
/// `HubDb` colocated SQLite. `seal` must equal the deployment's `HUB_SEAL_KEY`.
/// Idempotent — re-running resets the root password.
///
/// # Errors
///
/// Returns an error if the request fails, the endpoint rejects the seal (`403`)
/// or otherwise responds non-success, or the body is not `{ "user_id": <n> }`.
pub async fn bootstrap_root_remote(
    base: &str,
    seal: &str,
    email: &str,
    password: &str,
) -> Result<i64> {
    let url = format!("{}/_admin/bootstrap-root", base.trim_end_matches('/'));
    let resp = reqwest::Client::new()
        .post(&url)
        .header("x-hub-seal", seal)
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!("bootstrap-root failed ({status}): {body}");
    }
    serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .as_ref()
        .and_then(|v| v.get("user_id"))
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| anyhow::anyhow!("bootstrap-root response missing user_id: {body}"))
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
        // Wrangler can print structured provider failures to stdout instead of
        // stderr; include both so the real cause is not swallowed.
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
/// deploy calls pick up automatically. The callback runs on a
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
    /// `HUB_EGRESS_GATEWAY_KEY` — optional operator-provisioned `KEY_ID:KEY`.
    /// Required exactly when [`DeployConfig::egress_gateway_url`] is configured.
    pub egress_gateway_key: Option<String>,
    /// `HUB_CLOUDFLARE_API_TOKEN` — scoped route-observation token.
    pub cloudflare_api_token: Option<String>,
    /// `HUB_EMAIL_API_TOKEN` — bearer token for the magic-link email relay.
    pub email_api_token: Option<String>,
    /// `HUB_DELIVERY_ATTESTATION_KEY` — HMAC key shared with a trusted ingress.
    pub delivery_attestation_key: Option<String>,
    /// Removes an already-deployed delivery-attestation key when true.
    pub disable_delivery_attestation: bool,
    /// `HUB_DOMAIN_PROBE_SIGNER_MANIFEST` — Worker terminator signer manifest.
    pub domain_probe_signer_manifest: Option<String>,
    /// `HUB_ROUTE_RESERVATION_KEYRING` — active and retained route HMAC keys.
    pub route_reservation_keyring: Option<String>,
}

impl Secrets {
    /// Validates every supplied Worker secret before any provider mutation.
    ///
    /// # Errors
    ///
    /// Returns an error for an explicitly empty secret or a malformed domain
    /// probe or route-reservation manifest.
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.delivery_attestation_key.is_none() || !self.disable_delivery_attestation,
            "delivery attestation cannot be configured and disabled together"
        );
        for (name, value) in [
            ("HUB_JWT_SECRET", self.jwt_secret.as_deref()),
            ("HUB_SEAL_KEY", self.seal_key.as_deref()),
            (
                "HUB_CLOUDFLARE_API_TOKEN",
                self.cloudflare_api_token.as_deref(),
            ),
            ("HUB_EMAIL_API_TOKEN", self.email_api_token.as_deref()),
            ("HUB_EGRESS_GATEWAY_KEY", self.egress_gateway_key.as_deref()),
            (
                "HUB_DELIVERY_ATTESTATION_KEY",
                self.delivery_attestation_key.as_deref(),
            ),
        ] {
            anyhow::ensure!(
                value.is_none_or(|secret| !secret.is_empty()),
                "{name} must not be empty when supplied"
            );
        }
        if let Some(manifest) = &self.domain_probe_signer_manifest {
            aos_hub_core::topology_probe::ManifestDomainProbeTerminatorProvider::from_json(
                manifest,
                "worker_secret",
            )
            .context("invalid Worker domain-probe signer manifest")?;
        }
        if let Some(keyring) = &self.route_reservation_keyring {
            aos_hub_core::service::ConfiguredRouteReservationKeyring::from_json(keyring)
                .context("invalid Worker route reservation keyring")?;
        }
        Ok(())
    }
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

/// Declares whether the target Worker is new or already deployed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployMode {
    /// Creates an initial Worker version before applying its first secret set.
    Install,
    /// Requires an existing Worker and applies secrets before replacing its code.
    Update,
}

/// Provisions the R2 bucket, KV namespace, and deferred-jobs Queue, then
/// resolves their configuration into a [`DeployConfig`].
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
    bucket: &str,
    kv_title: &str,
    queue: &str,
    egress_gateway_url: Option<&str>,
    external_url: &str,
    deployment_id: Option<&str>,
    database_instance: &str,
    email_relay_url: Option<&str>,
    custom_domains: &[String],
    rate_limit_namespaces: RateLimitNamespaces,
) -> Result<DeployConfig> {
    if let Some(url) = egress_gateway_url {
        let egress = url::Url::parse(url).context("egress gateway URL is invalid")?;
        if egress.scheme() != "https"
            || egress.username() != ""
            || egress.password().is_some()
            || egress.query().is_some()
            || egress.fragment().is_some()
            || egress.path() != "/v1/fetch"
        {
            bail!("egress gateway URL must be an exact HTTPS /v1/fetch endpoint");
        }
    }
    let external = url::Url::parse(external_url).context("external URL is invalid")?;
    if external.scheme() != "https"
        || external.username() != ""
        || external.password().is_some()
        || external.query().is_some()
        || external.fragment().is_some()
        || external.path() != "/"
    {
        bail!("external URL must be an exact HTTPS origin");
    }
    if let Some(deployment_id) = deployment_id {
        anyhow::ensure!(
            !deployment_id.is_empty()
                && deployment_id.len() <= 128
                && deployment_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            "deployment ID must be 1-128 ASCII letters, digits, '.', '_', or '-'"
        );
    }
    anyhow::ensure!(
        !database_instance.is_empty()
            && database_instance.len() <= 128
            && database_instance
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "database instance must be 1-128 ASCII letters, digits, '.', '_', or '-'"
    );
    // The system of record is the `HubDb` Durable Object's colocated SQLite
    // (declared by the `wrangler.toml`
    // `new_sqlite_classes` migration, created on first deploy).
    run_wrangler_tolerant(assets, &r2_create_args(bucket), "r2 bucket create").await;
    // Provider upload ids are opaque. Verify a bucket-level cleanup bound
    // before deploying code that can create multipart uploads. An adequate
    // existing rule is preserved; otherwise a new AOS-owned rule is installed
    // without first removing any protection.
    let lifecycle = run_wrangler(
        assets,
        &r2_multipart_lifecycle_list_args(bucket),
        None,
        None,
    )
    .await
    .context("listing R2 multipart lifecycle rules")?;
    if !r2_lifecycle_has_bounded_multipart_abort(&lifecycle, 7) {
        // A prior AOS rule may itself be the drifted entry. A fresh identity
        // repairs that state without colliding with or first removing any
        // existing rule, preserving cleanup protection at every crash point.
        let lifecycle_rule = format!("aos-abandoned-multipart-{}", uuid::Uuid::new_v4().simple());
        run_wrangler(
            assets,
            &r2_multipart_lifecycle_add_args(bucket, &lifecycle_rule),
            None,
            None,
        )
        .await
        .context("enforcing R2 abandoned multipart lifecycle")?;
    }
    run_wrangler_tolerant(assets, &kv_create_args(kv_title), "kv namespace create").await;
    run_wrangler_tolerant(assets, &queue_create_args(queue), "queue create").await;

    let kv_list = run_wrangler(assets, &kv_list_args(), None, None).await?;
    let kv_id = parse_kv_id(&kv_list, kv_title)?;

    Ok(DeployConfig {
        name: name.to_string(),
        bucket: bucket.to_string(),
        kv_id,
        queue: queue.to_string(),
        rate_limit_namespaces,
        egress_gateway_url: egress_gateway_url.map(str::to_string),
        external_url: external_url.to_string(),
        deployment_id: deployment_id.map(str::to_string),
        container_rollout: aos_hub_core::container_rollout::ContainerRollout::default(),
        database_instance: database_instance.to_string(),
        email_relay_url: email_relay_url.map(str::to_string),
        // The `worker` CLI overrides this from its `--email-from` flag before
        // staging the config; Email Service is off until a sender is set.
        email_from: None,
        custom_domains: custom_domains.to_vec(),
        serve_assets: assets.assets_dir.is_some(),
        // Observability defaults (on, full sampling, no logpush); the `worker`
        // CLI overrides these from its flags before staging the config.
        observability: true,
        head_sampling_rate: 1.0,
        logpush: false,
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
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("creating deploy staging directory {}", dir.display()))?;
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
/// up on return). A first install creates an initial version before attaching
/// secrets; an update lists and applies its requested secret changes before
/// replacing the deployed code. Optional-router updates require the old and new
/// router replicas to accept the challenged overlap key during this sequence.
///
/// Secret application is **idempotent across redeploys**: the Worker's existing
/// secrets are listed and any already-present `HUB_JWT_SECRET` / `HUB_SEAL_KEY`
/// is preserved rather than re-minted. Rotating `HUB_SEAL_KEY`
/// would orphan at-rest sealed data and rotating `HUB_JWT_SECRET` would
/// invalidate every active session, so a fresh value is minted only on a first
/// deploy where the secret is absent (or when the operator passes one explicitly
/// to force a rotation).
///
/// # Errors
///
/// Returns an error if the temp dir, staging, the deploy, the secret listing, or
/// any `secret put` fails.
pub async fn deploy(
    assets: &Assets,
    cfg: &DeployConfig,
    secrets: &Secrets,
    mode: DeployMode,
) -> Result<Applied> {
    secrets.validate()?;
    anyhow::ensure!(
        cfg.egress_gateway_url.is_some() == secrets.egress_gateway_key.is_some(),
        "HUB_EGRESS_GATEWAY_URL and HUB_EGRESS_GATEWAY_KEY must be configured together"
    );
    if let (Some(url), Some(key)) = (
        cfg.egress_gateway_url.as_deref(),
        secrets.egress_gateway_key.as_deref(),
    ) {
        authenticate_gateway_contract(url, key).await?;
    }
    let work = tempfile::Builder::new()
        .prefix("aos-hub-deploy")
        .tempdir()
        .context("creating a temporary deploy directory")?;
    let work_dir = work.path();
    let config = stage_deploy(assets, cfg, work_dir).await?;

    // A new router-backed Worker first receives a direct-Fetch bootstrap version
    // so its complete secret set exists before the URL is selected. An update
    // keeps the existing transport active while staging a challenged overlap key;
    // operators keep both router key ids accepted until cutover completes.
    let secret_config = if mode == DeployMode::Install && cfg.egress_gateway_url.is_some() {
        let mut direct = cfg.clone();
        direct.egress_gateway_url = None;
        let bootstrap_dir = work_dir.join("direct-bootstrap");
        let bootstrap_config = stage_deploy(assets, &direct, &bootstrap_dir).await?;
        run_wrangler(
            assets,
            &deploy_args(&bootstrap_config),
            None,
            Some(&bootstrap_dir),
        )
        .await?;
        bootstrap_config
    } else if mode == DeployMode::Install {
        run_wrangler(assets, &deploy_args(&config), None, Some(work_dir)).await?;
        config.clone()
    } else {
        config.clone()
    };

    let listed = run_wrangler(assets, &secret_list_args(&secret_config), None, None).await?;
    let existing = parse_secret_names(&listed)?;

    // Secrets survive `wrangler deploy` when omitted from configuration. The
    // pre-cutover name is never consumed by either transport.
    if existing.iter().any(|name| name == "HUB_EGRESS_SHARED_KEY") {
        delete_secret(assets, "HUB_EGRESS_SHARED_KEY", &secret_config).await?;
    }

    let minted_jwt_secret = apply_secret(
        assets,
        "HUB_JWT_SECRET",
        secrets.jwt_secret.as_deref(),
        &existing,
        &secret_config,
    )
    .await?;
    let minted_seal_key = apply_secret(
        assets,
        "HUB_SEAL_KEY",
        secrets.seal_key.as_deref(),
        &existing,
        &secret_config,
    )
    .await?;
    if let Some(key) = &secrets.egress_gateway_key {
        // The authenticated challenge above is deliberately before both
        // deployment and secret rotation. On update, the currently selected
        // router must accept this overlap key until the URL cutover completes.
        put_secret(assets, "HUB_EGRESS_GATEWAY_KEY", key, &secret_config).await?;
    }
    match secrets.cloudflare_api_token.as_deref() {
        Some(token) => {
            put_secret(assets, "HUB_CLOUDFLARE_API_TOKEN", token, &secret_config).await?
        }
        None if existing
            .iter()
            .any(|name| name == "HUB_CLOUDFLARE_API_TOKEN") => {}
        None => bail!(
            "HUB_CLOUDFLARE_API_TOKEN is required on first deploy; pass --cloudflare-api-token"
        ),
    }
    if let Some(tok) = &secrets.email_api_token {
        put_secret(assets, "HUB_EMAIL_API_TOKEN", tok, &secret_config).await?;
    }
    if let Some(key) = &secrets.delivery_attestation_key {
        put_secret(assets, "HUB_DELIVERY_ATTESTATION_KEY", key, &secret_config).await?;
    } else if secrets.disable_delivery_attestation
        && existing
            .iter()
            .any(|name| name == "HUB_DELIVERY_ATTESTATION_KEY")
    {
        delete_secret(assets, "HUB_DELIVERY_ATTESTATION_KEY", &secret_config).await?;
    }
    match &secrets.domain_probe_signer_manifest {
        Some(manifest) => {
            // Parse before changing the live secret so an invalid deployment
            // cannot replace the last known-good responder configuration.
            aos_hub_core::topology_probe::ManifestDomainProbeTerminatorProvider::from_json(
                manifest,
                "worker_secret",
            )
            .context("invalid Worker domain-probe signer manifest")?;
            put_secret(
                assets,
                "HUB_DOMAIN_PROBE_SIGNER_MANIFEST",
                manifest,
                &secret_config,
            )
            .await?;
        }
        None if !existing
            .iter()
            .any(|name| name == "HUB_DOMAIN_PROBE_SIGNER_MANIFEST") =>
        {
            // An empty manifest keeps the responder explicitly unready until
            // exact endpoint-generation material is deployed.
            put_secret(
                assets,
                "HUB_DOMAIN_PROBE_SIGNER_MANIFEST",
                "[]",
                &secret_config,
            )
            .await?;
        }
        None => {}
    }
    match &secrets.route_reservation_keyring {
        Some(manifest) => {
            aos_hub_core::service::ConfiguredRouteReservationKeyring::from_json(manifest)
                .context("invalid Worker route reservation keyring")?;
            put_secret(
                assets,
                "HUB_ROUTE_RESERVATION_KEYRING",
                manifest,
                &secret_config,
            )
            .await?;
        }
        None if existing
            .iter()
            .any(|name| name == "HUB_ROUTE_RESERVATION_KEYRING") => {}
        None => bail!(
            "HUB_ROUTE_RESERVATION_KEYRING is required on first deploy; pass --route-reservation-keys-file"
        ),
    }

    if mode == DeployMode::Update || cfg.egress_gateway_url.is_some() {
        // Updates publish only after every requested secret mutation succeeds.
        // A first router install likewise selects its URL only after the key.
        run_wrangler(assets, &deploy_args(&config), None, Some(work_dir)).await?;
    }

    if cfg.egress_gateway_url.is_none()
        && existing.iter().any(|name| name == "HUB_EGRESS_GATEWAY_KEY")
    {
        // Direct Fetch is active before the unused router credential is removed,
        // so a failed cleanup cannot make the Worker unavailable.
        delete_secret(assets, "HUB_EGRESS_GATEWAY_KEY", &config).await?;
    }

    Ok(Applied {
        minted_jwt_secret,
        minted_seal_key,
    })
}

/// Proves the configured gateway serves the operator-provisioned shared key.
///
/// This is a contract challenge rather than a health check: the request and
/// response use distinct HMAC domains, a fresh nonce, and bounded timestamps.
/// It runs before `wrangler deploy` and before any Worker secret write, so a
/// missing or stale gateway key cannot create or rotate a Worker deployment.
async fn authenticate_gateway_contract(gateway_url: &str, shared_key: &str) -> Result<()> {
    use base64::Engine as _;
    use rand::RngCore as _;

    let (key_id, key_text) = shared_key
        .split_once(':')
        .context("hardened-egress shared secret must be KEY_ID:KEY")?;
    anyhow::ensure!(
        !key_id.is_empty()
            && key_id.len() <= 64
            && key_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "invalid hardened-egress key id"
    );
    let key = crate::auth::seal::parse_key(key_text.as_bytes())
        .context("invalid operator-provisioned hardened-egress shared key")?;
    let mut challenge_url = url::Url::parse(gateway_url).context("invalid hardened-egress URL")?;
    challenge_url.set_path("/v1/challenge");
    challenge_url.set_query(None);
    let mut nonce_bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);
    let timestamp = aos_hub_core::clock::now_unix_secs();
    let evidence = aos_hub_core::egress_protocol::ChallengeEvidence {
        timestamp,
        nonce: &nonce,
    };
    let signature = aos_hub_core::egress_protocol::sign_challenge(&key, &evidence)?;
    let response = crate::fetch::hardened_client()
        .await
        .post(challenge_url)
        .header(
            "x-aos-egress-contract",
            aos_hub_core::egress_protocol::CONTRACT,
        )
        .header("x-aos-egress-key-id", key_id)
        .header("x-aos-egress-timestamp", timestamp.to_string())
        .header("x-aos-egress-nonce", &nonce)
        .header("x-aos-egress-signature", signature)
        .send()
        .await
        .context("authenticated hardened-egress challenge failed")?;
    anyhow::ensure!(
        response.status() == reqwest::StatusCode::NO_CONTENT,
        "authenticated hardened-egress challenge returned HTTP {}",
        response.status()
    );
    verify_gateway_challenge_response(key_id, &key, &nonce, &response)
}

fn verify_gateway_challenge_response(
    key_id: &str,
    key: &[u8],
    nonce: &str,
    response: &reqwest::Response,
) -> Result<()> {
    anyhow::ensure!(
        required_challenge_header(response, "x-aos-egress-contract")?
            == aos_hub_core::egress_protocol::CONTRACT,
        "hardened-egress challenge contract mismatch"
    );
    anyhow::ensure!(
        required_challenge_header(response, "x-aos-egress-key-id")? == key_id,
        "hardened-egress challenge key id mismatch"
    );
    anyhow::ensure!(
        required_challenge_header(response, "x-aos-egress-nonce")? == nonce,
        "hardened-egress challenge nonce mismatch"
    );
    let timestamp =
        required_challenge_header(response, "x-aos-egress-timestamp")?.parse::<i64>()?;
    let now = aos_hub_core::clock::now_unix_secs();
    require_fresh_challenge_timestamp(timestamp, now)?;
    aos_hub_core::egress_protocol::verify_challenge_response(
        key,
        &aos_hub_core::egress_protocol::ChallengeEvidence { timestamp, nonce },
        required_challenge_header(response, "x-aos-egress-signature")?,
    )
}

fn require_fresh_challenge_timestamp(timestamp: i64, now: i64) -> Result<()> {
    let age = now
        .checked_sub(timestamp)
        .context("hardened-egress challenge response timestamp overflow")?;
    anyhow::ensure!(
        age >= 0,
        "hardened-egress challenge response is in the future"
    );
    anyhow::ensure!(age <= 60, "hardened-egress challenge response is stale");
    Ok(())
}

fn required_challenge_header<'a>(
    response: &'a reqwest::Response,
    name: &'static str,
) -> Result<&'a str> {
    response
        .headers()
        .get(name)
        .context("hardened-egress challenge response omitted a required header")?
        .to_str()
        .context("hardened-egress challenge response header is not text")
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

/// Removes one obsolete Worker secret through Wrangler.
async fn delete_secret(assets: &Assets, name: &str, config: &Path) -> Result<()> {
    run_wrangler(assets, &secret_delete_args(name, config), Some("y\n"), None)
        .await
        .with_context(|| format!("deleting obsolete secret {name}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(r2_create_args("bkt"), ["r2", "bucket", "create", "bkt"]);
        assert_eq!(
            r2_multipart_lifecycle_list_args("bkt"),
            ["r2", "bucket", "lifecycle", "list", "bkt"]
        );
        assert_eq!(
            r2_multipart_lifecycle_add_args("bkt", "aos-rule"),
            [
                "r2",
                "bucket",
                "lifecycle",
                "add",
                "bkt",
                "aos-rule",
                "",
                "--abort-multipart-days",
                "7",
                "--force",
            ]
        );
        assert_eq!(
            kv_create_args("SESSIONS"),
            ["kv", "namespace", "create", "SESSIONS"]
        );
        assert_eq!(kv_list_args(), ["kv", "namespace", "list"]);
        assert_eq!(queue_create_args("jobs"), ["queues", "create", "jobs"]);
        assert_eq!(
            secret_put_args("HUB_JWT_SECRET", Path::new("/tmp/w.toml")),
            ["secret", "put", "HUB_JWT_SECRET", "--config", "/tmp/w.toml"]
        );
        assert_eq!(
            secret_list_args(Path::new("/tmp/w.toml")),
            ["secret", "list", "--config", "/tmp/w.toml"]
        );
        assert_eq!(
            secret_delete_args("OLD_SECRET", Path::new("/tmp/w.toml")),
            ["secret", "delete", "OLD_SECRET", "--config", "/tmp/w.toml"]
        );
        assert_eq!(
            deploy_args(Path::new("/tmp/w.toml")),
            ["deploy", "--config", "/tmp/w.toml"]
        );
    }

    #[test]
    fn lifecycle_listing_requires_enabled_all_prefix_abort_bound() {
        let default = "name: Default Multipart Abort Rule\n\
                       enabled: Yes\n\
                       prefix: (all prefixes)\n\
                       action: Abort incomplete multipart uploads after 7 days";
        assert!(r2_lifecycle_has_bounded_multipart_abort(default, 7));
        assert!(!r2_lifecycle_has_bounded_multipart_abort(default, 6));
        assert!(!r2_lifecycle_has_bounded_multipart_abort(
            &default.replace("enabled: Yes", "enabled: No"),
            7,
        ));
        assert!(!r2_lifecycle_has_bounded_multipart_abort(
            &default.replace("(all prefixes)", "objects/"),
            7,
        ));
    }

    #[test]
    fn rendered_toml_has_bindings_vars_and_no_build() {
        let cfg = DeployConfig {
            name: "aos-hub".into(),
            bucket: "aos-hub-surfaces".into(),
            kv_id: "kv-id".into(),
            queue: "aos-hub-jobs".into(),
            rate_limit_namespaces: RateLimitNamespaces::from_base(1000).unwrap(),
            egress_gateway_url: None,
            external_url: "https://aos.example.com".into(),
            deployment_id: Some("0123456789abcdef".into()),
            container_rollout: aos_hub_core::container_rollout::ContainerRollout::all_enabled(),
            database_instance: "hub".into(),
            email_relay_url: None,
            email_from: None,
            custom_domains: vec!["aos.example.com".into()],
            serve_assets: false,
            observability: true,
            head_sampling_rate: 1.0,
            logpush: false,
        };
        let toml = render_wrangler_toml(&cfg);
        // Parses as valid TOML.
        let parsed: toml::Value = toml::from_str(&toml).expect("valid TOML");
        assert_eq!(parsed["name"].as_str(), Some("aos-hub"));
        assert_eq!(parsed["main"].as_str(), Some("shim.mjs"));
        assert_eq!(parsed["vars"]["HUB_REQUEST_SHARDING"].as_str(), Some("on"));
        assert_eq!(
            parsed["vars"]["HUB_OCI_PULL_ENABLED"].as_str(),
            Some("true")
        );
        assert_eq!(
            parsed["vars"]["HUB_OCI_PUSH_ENABLED"].as_str(),
            Some("true")
        );
        assert_eq!(
            parsed["vars"]["HUB_OCI_VERIFIED_PUBLICATION_ENABLED"].as_str(),
            Some("true")
        );
        assert_eq!(
            parsed["vars"]["HUB_OCI_ADMINISTRATION_ENABLED"].as_str(),
            Some("true")
        );
        assert_eq!(parsed["vars"]["HUB_OCI_GC_ENABLED"].as_str(), Some("true"));
        assert_eq!(
            parsed["vars"]["HUB_EXTERNAL_URL"].as_str(),
            Some("https://aos.example.com")
        );
        assert!(parsed["vars"]
            .get("HUB_DEFAULT_PUBLIC_DELIVERY_URL")
            .is_none());
        assert!(parsed["vars"].get("HUB_DEFAULT_BUCKET").is_none());
        assert_eq!(
            parsed["vars"]["HUB_DEPLOYMENT_ID"].as_str(),
            Some("0123456789abcdef")
        );
        // Root bootstrap is CLI-driven now; the worker no longer reads it.
        assert!(parsed["vars"].get("HUB_ROOT_EMAIL").is_none());
        // The custom domain is bound via a custom_domain route.
        assert_eq!(
            parsed["routes"][0]["pattern"].as_str(),
            Some("aos.example.com")
        );
        assert_eq!(parsed["routes"][0]["custom_domain"].as_bool(), Some(true));
        // Placement is hardcoded `off` (never `smart`): the Worker runs at the
        // edge near each client, rather than being pinned to HubDb's region.
        // Emitting it every deploy reverts any dashboard toggle to smart.
        assert_eq!(parsed["placement"]["mode"].as_str(), Some("off"));
        assert_eq!(
            parsed["limits"]["cpu_ms"].as_integer(),
            Some(i64::from(WORKER_CPU_LIMIT_MS))
        );
        assert_eq!(
            parsed["limits"]["subrequests"].as_integer(),
            Some(i64::from(WORKER_SUBREQUEST_LIMIT))
        );
        assert_eq!(parsed["kv_namespaces"][0]["id"].as_str(), Some("kv-id"));
        let durable_objects = parsed["durable_objects"]["bindings"]
            .as_array()
            .expect("durable-object bindings");
        let binding_names = durable_objects
            .iter()
            .filter_map(|binding| binding["name"].as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            binding_names,
            [
                "COORDINATOR",
                "HUB_DB",
                "HUB_CONTROL_SHARDS",
                "HUB_TENANT_SHARDS",
                "HUB_REGISTRY_SHARDS",
                "HUB_CACHE_SHARDS",
            ]
        );
        let migrations = parsed["migrations"].as_array().expect("migrations");
        assert_eq!(migrations.len(), 2);
        assert_eq!(migrations[1]["tag"].as_str(), Some("v2"));
        assert_eq!(
            migrations[1]["new_classes"]
                .as_array()
                .expect("v2 execution classes")
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>(),
            [
                "HubControlShard",
                "HubTenantShard",
                "HubRegistryShard",
                "HubCacheShard",
            ]
        );
        assert_eq!(
            parsed["queues"]["producers"][0]["binding"].as_str(),
            Some("JOBS")
        );
        assert_eq!(
            parsed["queues"]["producers"][0]["queue"].as_str(),
            Some("aos-hub-jobs")
        );
        assert_eq!(
            parsed["queues"]["consumers"][0]["queue"].as_str(),
            Some("aos-hub-jobs")
        );
        assert_eq!(
            parsed["queues"]["consumers"][0]["max_batch_size"].as_integer(),
            Some(10)
        );
        assert_eq!(
            parsed["queues"]["consumers"][0]["max_batch_timeout"].as_integer(),
            Some(5)
        );
        assert_eq!(
            parsed["queues"]["consumers"][0]["max_concurrency"].as_integer(),
            Some(4)
        );
        assert_eq!(
            parsed["ratelimits"][0]["namespace_id"].as_str(),
            Some("1001")
        );
        assert_eq!(
            parsed["ratelimits"][1]["namespace_id"].as_str(),
            Some("1002")
        );
        assert_eq!(
            parsed["ratelimits"][2]["namespace_id"].as_str(),
            Some("1003")
        );
        assert!(parsed["vars"].get("HUB_EGRESS_GATEWAY_URL").is_none());
        assert!(parsed.get("services").is_none());
        assert_eq!(parsed["triggers"]["crons"][0].as_str(), Some(INDEXER_CRON));
        // No build command — we deploy the prebuilt dist.
        assert!(parsed.get("build").is_none());
        // serve_assets = false omits the [assets] binding.
        assert!(parsed.get("assets").is_none());
        // Observability on by default, full sampling; logpush omitted.
        assert_eq!(parsed["observability"]["enabled"].as_bool(), Some(true));
        assert_eq!(
            parsed["observability"]["head_sampling_rate"].as_float(),
            Some(1.0)
        );
        assert!(parsed.get("logpush").is_none());
    }

    #[test]
    fn rendered_toml_observability_off_and_logpush_on() {
        let cfg = DeployConfig {
            name: "aos-hub".into(),
            bucket: "aos-hub-surfaces".into(),
            kv_id: "kv-id".into(),
            queue: "aos-hub-jobs".into(),
            rate_limit_namespaces: RateLimitNamespaces::from_base(1000).unwrap(),
            egress_gateway_url: None,
            external_url: "https://aos.example.com".into(),
            deployment_id: None,
            container_rollout: aos_hub_core::container_rollout::ContainerRollout::default(),
            database_instance: "hub".into(),
            email_relay_url: None,
            email_from: None,
            custom_domains: vec![],
            serve_assets: false,
            observability: false,
            head_sampling_rate: 0.25,
            logpush: true,
        };
        let parsed: toml::Value = toml::from_str(&render_wrangler_toml(&cfg)).expect("valid TOML");
        // Disabled observability omits the block entirely; logpush is set.
        assert!(parsed.get("observability").is_none());
        assert_eq!(parsed["logpush"].as_bool(), Some(true));
    }

    #[test]
    fn rendered_toml_binds_static_assets_when_requested() {
        let cfg = DeployConfig {
            name: "aos-hub".into(),
            bucket: "aos-hub-surfaces".into(),
            kv_id: "kv-id".into(),
            queue: "aos-hub-jobs".into(),
            rate_limit_namespaces: RateLimitNamespaces::from_base(1000).unwrap(),
            egress_gateway_url: None,
            external_url: "https://aos.example.com".into(),
            deployment_id: None,
            container_rollout: aos_hub_core::container_rollout::ContainerRollout::default(),
            database_instance: "hub".into(),
            email_relay_url: None,
            email_from: None,
            custom_domains: vec![],
            serve_assets: true,
            observability: true,
            head_sampling_rate: 1.0,
            logpush: false,
        };
        let parsed: toml::Value = toml::from_str(&render_wrangler_toml(&cfg)).expect("valid TOML");
        // The CDN-edge static-asset directory is bound, with literal matching so
        // non-asset paths still fall through to the Worker.
        assert_eq!(parsed["assets"]["directory"].as_str(), Some("./assets"));
        assert_eq!(parsed["assets"]["html_handling"].as_str(), Some("none"));
    }

    #[test]
    fn rendered_toml_emits_send_email_binding_when_from_set() {
        let base = DeployConfig {
            name: "aos-hub".into(),
            bucket: "aos-hub-surfaces".into(),
            kv_id: "kv-id".into(),
            queue: "aos-hub-jobs".into(),
            rate_limit_namespaces: RateLimitNamespaces::from_base(1000).unwrap(),
            egress_gateway_url: None,
            external_url: "https://aos.example.com".into(),
            deployment_id: None,
            container_rollout: aos_hub_core::container_rollout::ContainerRollout::default(),
            database_instance: "hub".into(),
            email_relay_url: None,
            email_from: Some("noreply@example.com".into()),
            custom_domains: vec![],
            serve_assets: false,
            observability: true,
            head_sampling_rate: 1.0,
            logpush: false,
        };
        let parsed: toml::Value = toml::from_str(&render_wrangler_toml(&base)).expect("valid TOML");
        // The Email Service binding is emitted with the EMAIL name and remote=true.
        assert_eq!(parsed["send_email"][0]["name"].as_str(), Some("EMAIL"));
        assert_eq!(parsed["send_email"][0]["remote"].as_bool(), Some(true));
        // The sender address is baked into [vars].
        assert_eq!(
            parsed["vars"]["HUB_EMAIL_FROM"].as_str(),
            Some("noreply@example.com")
        );

        // With no email_from, neither the binding nor the var appears.
        let none = DeployConfig {
            email_from: None,
            ..base
        };
        let parsed: toml::Value = toml::from_str(&render_wrangler_toml(&none)).expect("valid TOML");
        assert!(parsed.get("send_email").is_none());
        assert!(parsed["vars"].get("HUB_EMAIL_FROM").is_none());
    }

    #[test]
    fn toml_string_escapes_quotes_and_backslashes() {
        assert_eq!(toml_string(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn rendered_toml_selects_optional_egress_gateway() {
        let cfg = DeployConfig {
            name: "aos-hub".into(),
            bucket: "aos-hub-surfaces".into(),
            kv_id: "kv-id".into(),
            queue: "aos-hub-jobs".into(),
            rate_limit_namespaces: RateLimitNamespaces::from_base(1000).unwrap(),
            egress_gateway_url: Some("https://egress.example.com/v1/fetch".into()),
            external_url: "https://aos.example.com".into(),
            deployment_id: None,
            container_rollout: aos_hub_core::container_rollout::ContainerRollout::default(),
            database_instance: "hub".into(),
            email_relay_url: None,
            email_from: None,
            custom_domains: vec![],
            serve_assets: false,
            observability: true,
            head_sampling_rate: 1.0,
            logpush: false,
        };
        let parsed: toml::Value = toml::from_str(&render_wrangler_toml(&cfg)).unwrap();
        assert_eq!(
            parsed["vars"]["HUB_EGRESS_GATEWAY_URL"].as_str(),
            Some("https://egress.example.com/v1/fetch")
        );
    }

    #[test]
    fn rate_limit_namespace_ranges_are_isolated_and_bounded() {
        assert_eq!(
            RateLimitNamespaces::from_base(1000).unwrap(),
            RateLimitNamespaces {
                burst5: "1001".into(),
                burst10: "1002".into(),
                browse120: "1003".into(),
            }
        );
        assert_eq!(
            RateLimitNamespaces::from_base(2000).unwrap(),
            RateLimitNamespaces {
                burst5: "2001".into(),
                burst10: "2002".into(),
                browse120: "2003".into(),
            }
        );
        assert!(RateLimitNamespaces::from_base(0).is_err());
        assert!(RateLimitNamespaces::from_base(u32::MAX - 2).is_err());
    }

    #[test]
    fn deployment_secrets_reject_empty_or_malformed_values_before_worker_mutation() {
        let valid = || Secrets {
            jwt_secret: Some("jwt".into()),
            seal_key: Some("seal".into()),
            egress_gateway_key: Some("key-id:key".into()),
            cloudflare_api_token: Some("cloudflare".into()),
            email_api_token: None,
            delivery_attestation_key: Some("attestation".into()),
            disable_delivery_attestation: false,
            domain_probe_signer_manifest: None,
            route_reservation_keyring: None,
        };
        assert!(valid().validate().is_ok());

        let mut direct = valid();
        direct.egress_gateway_key = None;
        assert!(direct.validate().is_ok());

        let mut secrets = valid();
        secrets.jwt_secret = Some(String::new());
        assert!(secrets.validate().is_err());

        let mut secrets = valid();
        secrets.cloudflare_api_token = Some(String::new());
        assert!(secrets.validate().is_err());

        let mut secrets = valid();
        secrets.delivery_attestation_key = Some(String::new());
        assert!(secrets.validate().is_err());

        let mut secrets = valid();
        secrets.disable_delivery_attestation = true;
        assert!(secrets.validate().is_err());

        let mut secrets = valid();
        secrets.route_reservation_keyring = Some("not-json".into());
        assert!(secrets.validate().is_err());
    }

    #[tokio::test]
    async fn deploy_staging_creates_a_nested_bootstrap_directory() {
        let root = tempfile::tempdir().unwrap();
        let dist = root.path().join("dist");
        tokio::fs::create_dir_all(&dist).await.unwrap();
        tokio::fs::write(dist.join("shim.mjs"), b"export default {}")
            .await
            .unwrap();
        tokio::fs::write(dist.join("index.wasm"), b"wasm")
            .await
            .unwrap();
        let assets = Assets {
            dist_dir: dist,
            assets_dir: None,
            wrangler: vec!["wrangler".into()],
        };
        let cfg = DeployConfig {
            name: "aos-hub".into(),
            bucket: "aos-hub-surfaces".into(),
            kv_id: "kv-id".into(),
            queue: "aos-hub-jobs".into(),
            rate_limit_namespaces: RateLimitNamespaces::from_base(1000).unwrap(),
            egress_gateway_url: None,
            external_url: "https://aos.example.com".into(),
            deployment_id: None,
            container_rollout: aos_hub_core::container_rollout::ContainerRollout::default(),
            database_instance: "hub".into(),
            email_relay_url: None,
            email_from: None,
            custom_domains: vec![],
            serve_assets: false,
            observability: true,
            head_sampling_rate: 1.0,
            logpush: false,
        };
        let nested = root.path().join("deploy/direct-bootstrap");
        let config = stage_deploy(&assets, &cfg, &nested).await.unwrap();

        assert_eq!(config, nested.join("wrangler.toml"));
        assert_eq!(
            tokio::fs::read(nested.join("shim.mjs")).await.unwrap(),
            b"export default {}"
        );
        assert_eq!(
            tokio::fs::read(nested.join("index.wasm")).await.unwrap(),
            b"wasm"
        );
        assert!(tokio::fs::read_to_string(config).await.is_ok());
    }

    #[test]
    fn gateway_challenge_freshness_rejects_future_and_stale_evidence() {
        assert!(require_fresh_challenge_timestamp(101, 100).is_err());
        assert!(require_fresh_challenge_timestamp(39, 100).is_err());
        assert!(require_fresh_challenge_timestamp(40, 100).is_ok());
        assert!(require_fresh_challenge_timestamp(100, 100).is_ok());
    }
}
