//! Nested-canonical registry console dispatch (RFC-0004 Phase 5).
//!
//! The shared console router ([`super::router::console_router`]) mounts every
//! producer-console route with a fixed, single-segment slug shape —
//! `/{slug}/-/settings`, `/{slug}/-/settings/tokens`,
//! `/{slug}/-/channels/{name}/console`, and so on. `axum`'s `{slug}` parameter
//! captures exactly one path segment, so a registry whose canonical path has
//! slashes (`andyl/demo`, `acme/infra/cdn`) never matches those routes: the
//! request falls through to the facade wildcard and 404s.
//!
//! The native hub solves this in its own catch-all
//! ([`aos-hub`'s `console::dispatch_nested`]); the Cloudflare Worker has no such
//! catch-all and serves the console from the *shared* handlers
//! ([`super::handlers`]), which are already nested-aware (each registry-scoped
//! handler calls `resolve_registry`, reconstructing the nested registry from the
//! request URI when the flat slug misses). Only the *routing* was missing.
//!
//! [`dispatch_nested`] is that missing piece: the Worker invokes it before the
//! normal router dispatch. It recognizes a nested `/-/` console path, classifies
//! its tail with [`is_console_path`] (mirroring the native classifier), and
//! calls the matching shared handler directly — passing the full pre-`/-/` path
//! as the `Path(slug)` so `resolve_registry` resolves the nested registry with
//! no first-segment ambiguity. A path that is not a nested console page returns
//! [`None`] so the caller falls through to the facade's browse handling.
//!
//! # Recognized tails
//!
//! ```text
//! settings                       GET   registry settings landing
//! settings/visibility            POST  change visibility
//! settings/crawl                 POST  change crawl policy
//! settings/delete                POST  unregister
//! settings/serving               GET   serving & mirror page
//! settings/serving               POST  mutate serving config
//! settings/tokens                GET   token list (paginated)
//! settings/tokens                POST  mint a token
//! settings/tokens/revoke         POST  revoke a token
//! settings/tokens/rotate         POST  rotate a token
//! settings/config                GET   git-backed config edit form
//! settings/config                POST  submit a config change request
//! changes                        GET   change-request list
//! keys                           GET   hosted-key roster (paginated)
//! keys/rotate                    GET   hosted-key rotation page
//! publishes                      GET   recent publishes
//! channels/{name}/console        GET   channel rollout console
//! channels/{name}/console        POST  prepare a channel advance
//! channels/{name}/advance        POST  direct hosted-key advance
//! ```

use axum::body::Bytes;
use axum::extract::{Form, Path, Query};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use crate::clock::Instant;
use crate::web::console::handlers::{self, PageQuery, RequestStart};
use crate::web::console::ports::ConsoleDeps;

/// Whether the `/-/` tail `right` (with the given method) names a
/// producer-console page, as opposed to a consumer browse page.
///
/// Mirrors the native hub's classifier so both shells recognize the same set of
/// `(tail, method)` console pages. Returns `false` for browse pages
/// (`packages`, `channels/{name}`, `releases`, `health`, …) so
/// [`dispatch_nested`] leaves them to the browse resolver and never bounces an
/// anonymous reader to `/login`.
///
/// # Examples
///
/// ```no_run
/// # // (private fn; shown for documentation only)
/// // settings is a GET-only landing page
/// // is_console_path("settings", false) == true
/// // is_console_path("settings", true)  == false  (visibility/delete are the POSTs)
/// // a browse tail is never a console path
/// // is_console_path("packages", false) == false
/// ```
fn is_console_path(right: &str, is_post: bool) -> bool {
    match right {
        "settings/tokens" => true,
        "settings/tokens/revoke" | "settings/tokens/rotate" => is_post,
        // The config-edit page is GET (form) + POST (submit).
        "settings/config" => true,
        // The settings tabs (general landing, binary caches, danger) are
        // GET-only; visibility, crawl, and delete are POST-only mutations.
        "settings" | "settings/caches" | "settings/danger" => !is_post,
        // Storage is GET (view) + POST (change storage).
        "settings/storage" => true,
        // The bucket-direct frontend advertise toggle is POST-only.
        "settings/advertise-frontend" => is_post,
        "settings/visibility" | "settings/crawl" | "settings/delete" => is_post,
        "settings/cache-link" | "settings/cache-unlink" => is_post,
        // The serving & mirror page is GET (view) + POST (mutate).
        "settings/serving" => true,
        "changes" => !is_post,
        "keys" | "keys/rotate" | "publishes" => !is_post,
        other => {
            // changes/{id} (GET detail) and changes/{id}/{action} (POST).
            if let Some(rest) = other.strip_prefix("changes/") {
                return match rest.split_once('/') {
                    Some((id, action)) => {
                        is_post
                            && !id.is_empty()
                            && matches!(action, "comment" | "review" | "close" | "reopen")
                    }
                    None => !is_post && !rest.is_empty(),
                };
            }
            if let Some(name) = other
                .strip_prefix("channels/")
                .and_then(|rest| rest.strip_suffix("/console"))
            {
                return !name.contains('/');
            }
            // The direct hosted-key advance is POST-only.
            is_post
                && other
                    .strip_prefix("channels/")
                    .and_then(|rest| rest.strip_suffix("/advance"))
                    .is_some_and(|name| !name.contains('/'))
        }
    }
}

/// The `?page=N` of a paginated console read, decoded by hand.
///
/// The nested path has no `axum` `Query` extractor in scope, so the page number
/// is parsed off the raw query string into the handler's [`PageQuery`] shape
/// (which clamps to at least 1 internally).
fn page_query(uri: &Uri) -> PageQuery {
    uri.query()
        .map(|q| serde_urlencoded::from_str::<PageQuery>(q).unwrap_or_default())
        .unwrap_or_default()
}

/// A `400 Bad Request` for a console POST whose form body fails to decode.
fn bad_request() -> Response {
    StatusCode::BAD_REQUEST.into_response()
}

/// Routes a nested-canonical registry `/-/` console request to the shared
/// console handlers, the Worker's analogue of the native hub's catch-all
/// `dispatch_nested`.
///
/// The shared console routes capture only a single-segment `{slug}`, so a
/// registry whose canonical path has slashes never matches them. This function
/// splits the request path on the `/-/` marker, classifies the tail with
/// [`is_console_path`], and — for a recognized console page — invokes the
/// matching shared handler directly, passing the full pre-`/-/` path as
/// `Path(slug)`. The shared handlers resolve the nested registry from that slug
/// via `resolve_registry`, so no first-segment disambiguation is needed here.
///
/// `body` is the buffered request body, used only for POST form parsing; a GET
/// passes empty bytes. A POST whose body fails to decode into the handler's form
/// type yields `Some(400)`.
///
/// # Returns
///
/// * `None` when the path is not a *nested* console page — a flat single-segment
///   slug (served by the normal routes), a path with no `/-/` marker, or a
///   browse tail (`packages`, `channels/{name}`, …). The caller then falls
///   through to its normal router / facade dispatch.
/// * `Some(response)` for a recognized nested console page (including auth
///   redirects, `404`s for a missing registry, and `400`s for a malformed form
///   body — all produced by the shared handlers).
///
/// # Examples
///
/// ```no_run
/// # use aos_hub_core::web::console::ConsoleDeps;
/// # async fn demo(deps: ConsoleDeps) {
/// use axum::body::Bytes;
/// use axum::http::{HeaderMap, Method, Uri};
///
/// let uri: Uri = "/andyl/demo/-/settings".parse().unwrap();
/// let resp = aos_hub_core::web::console::dispatch_nested(
///     deps,
///     Method::GET,
///     uri,
///     HeaderMap::new(),
///     Bytes::new(),
/// )
/// .await;
/// assert!(resp.is_some()); // a nested console page is handled here
/// # }
/// ```
pub async fn dispatch_nested(
    deps: ConsoleDeps,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Option<Response> {
    let path = uri.path().trim_start_matches('/');
    let (left, right) = path.split_once("/-/")?;
    let right = right.trim_end_matches('/');

    // Flat single-segment slugs are served by the normal console routes; this
    // dispatcher is only for nested slugs. Early-out keeps the hot path cheap.
    if !left.contains('/') {
        return None;
    }

    let is_post = method == Method::POST;

    // Classify the tail before touching the registry or session: a browse page
    // (`packages`, `channels/{name}`, …) is not a console path, so return `None`
    // and let the facade's nested browse handling take it.
    if !is_console_path(right, is_post) {
        return None;
    }

    let slug = left.trim_end_matches('/').to_string();
    let started = RequestStart(Instant::now());

    let response = match (right, is_post) {
        // -- settings landing & mutations ------------------------------------
        ("settings", false) => {
            handlers::registry_settings(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/storage", false) => {
            handlers::registry_storage(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/caches", false) => {
            handlers::registry_caches(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/danger", false) => {
            handlers::registry_danger(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/visibility", true) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_visibility(deps, headers, started, uri, Path(slug), Form(form)).await
        }
        ("settings/crawl", true) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_crawl_policy(deps, headers, started, uri, Path(slug), Form(form))
                .await
        }
        ("settings/delete", true) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            // `registry_delete` takes no `RequestStart`.
            handlers::registry_delete(deps, headers, uri, Path(slug), Form(form)).await
        }
        ("settings/cache-link", true) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_cache_link(deps, headers, started, uri, Path(slug), Form(form)).await
        }
        ("settings/cache-unlink", true) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_cache_unlink(deps, headers, started, uri, Path(slug), Form(form))
                .await
        }
        ("settings/storage", true) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_change_storage(deps, headers, started, uri, Path(slug), Form(form))
                .await
        }
        ("settings/advertise-frontend", true) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_set_advertise_frontend(
                deps,
                headers,
                started,
                uri,
                Path(slug),
                Form(form),
            )
            .await
        }
        // -- serving & mirror ------------------------------------------------
        ("settings/serving", false) => {
            handlers::serving(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/serving", true) => {
            // `serving_post` consumes the raw body itself (it accepts multiple
            // form shapes), so pass the bytes straight through.
            handlers::serving_post(deps, headers, started, uri, Path(slug), body).await
        }
        // -- tokens ----------------------------------------------------------
        ("settings/tokens", false) => {
            handlers::tokens(
                deps,
                headers,
                started,
                uri.clone(),
                Path(slug),
                Query(page_query(&uri)),
            )
            .await
        }
        ("settings/tokens", true) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::tokens_create(deps, headers, started, uri, Path(slug), Form(form)).await
        }
        ("settings/tokens/revoke", true) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::tokens_revoke(deps, headers, started, uri, Path(slug), Form(form)).await
        }
        ("settings/tokens/rotate", true) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::tokens_rotate(deps, headers, started, uri, Path(slug), Form(form)).await
        }
        // -- git-backed config / change requests -----------------------------
        ("settings/config", false) => {
            handlers::config_edit(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/config", true) => {
            // The config form posts repeated cache rows, which serde_urlencoded
            // can't collect into a Vec; hand the raw body to the shared decoder.
            let body = String::from_utf8_lossy(&body).into_owned();
            handlers::config_submit(deps, headers, started, uri, Path(slug), body).await
        }
        ("changes", false) => handlers::changes(deps, headers, started, uri, Path(slug)).await,
        // -- change-request detail & review actions --------------------------
        (other, false)
            if other
                .strip_prefix("changes/")
                .is_some_and(|r| !r.contains('/')) =>
        {
            // `is_console_path` proved the shape; recover the id defensively.
            let Some(id) = other.strip_prefix("changes/").map(str::to_string) else {
                return Some(bad_request());
            };
            handlers::change_detail(deps, headers, started, uri, Path((slug, id))).await
        }
        (other, true)
            if other
                .strip_prefix("changes/")
                .is_some_and(|r| r.contains('/')) =>
        {
            let Some((id, action)) = other
                .strip_prefix("changes/")
                .and_then(|rest| rest.split_once('/'))
            else {
                return Some(bad_request());
            };
            let id = id.to_string();
            match action {
                "comment" => {
                    let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                        return Some(bad_request());
                    };
                    handlers::change_comment(deps, headers, uri, Path((slug, id)), Form(form)).await
                }
                "review" => {
                    let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                        return Some(bad_request());
                    };
                    handlers::change_review(deps, headers, uri, Path((slug, id)), Form(form)).await
                }
                "close" => {
                    let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                        return Some(bad_request());
                    };
                    handlers::change_close(deps, headers, uri, Path((slug, id)), Form(form)).await
                }
                "reopen" => {
                    let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                        return Some(bad_request());
                    };
                    handlers::change_reopen(deps, headers, uri, Path((slug, id)), Form(form)).await
                }
                _ => return Some(bad_request()),
            }
        }
        // -- hosted keys & publishes -----------------------------------------
        ("keys", false) => {
            handlers::keys(
                deps,
                headers,
                started,
                uri.clone(),
                Path(slug),
                Query(page_query(&uri)),
            )
            .await
        }
        ("keys/rotate", false) => {
            handlers::keys_rotate(deps, headers, started, uri, Path(slug)).await
        }
        ("publishes", false) => handlers::publishes(deps, headers, started, uri, Path(slug)).await,
        // -- channel rollout -------------------------------------------------
        (other, true) if other.ends_with("/advance") => {
            // channels/{name}/advance (POST): the direct hosted-key advance.
            // `is_console_path` already proved this matches.
            let name = other
                .strip_prefix("channels/")
                .and_then(|rest| rest.strip_suffix("/advance"))
                .filter(|name| !name.contains('/'))?
                .to_string();
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::channel_advance_direct(
                deps,
                headers,
                started,
                uri,
                Path((slug, name)),
                Form(form),
            )
            .await
        }
        (other, _) => {
            // channels/{name}/console (GET renders, POST prepares an advance);
            // `is_console_path` already proved this matches.
            let name = other
                .strip_prefix("channels/")
                .and_then(|rest| rest.strip_suffix("/console"))
                .filter(|name| !name.contains('/'))?
                .to_string();
            if is_post {
                let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                    return Some(bad_request());
                };
                handlers::channel_advance(
                    deps,
                    headers,
                    started,
                    uri,
                    Path((slug, name)),
                    Form(form),
                )
                .await
            } else {
                handlers::channel_console(deps, headers, started, uri, Path((slug, name))).await
            }
        }
    };
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_settings_landing_as_get_console_page() {
        assert!(is_console_path("settings", false));
        assert!(!is_console_path("settings", true));
    }

    #[test]
    fn classifies_settings_mutations_as_post_console_pages() {
        for tail in ["settings/visibility", "settings/crawl", "settings/delete"] {
            assert!(is_console_path(tail, true), "{tail} POST");
            assert!(!is_console_path(tail, false), "{tail} GET");
        }
    }

    #[test]
    fn classifies_storage_and_advertise_frontend() {
        // Storage is GET (view) + POST (change storage).
        assert!(is_console_path("settings/storage", false));
        assert!(is_console_path("settings/storage", true));
        // The bucket-direct frontend advertise toggle is POST-only — a nested
        // (org/name) registry must reach it here, else its save falls through to
        // the surface catch-all ("unsupported POST to a surface path").
        assert!(is_console_path("settings/advertise-frontend", true));
        assert!(!is_console_path("settings/advertise-frontend", false));
    }

    #[test]
    fn classifies_token_pages() {
        assert!(is_console_path("settings/tokens", false));
        assert!(is_console_path("settings/tokens", true));
        assert!(is_console_path("settings/tokens/revoke", true));
        assert!(!is_console_path("settings/tokens/revoke", false));
        assert!(is_console_path("settings/tokens/rotate", true));
    }

    #[test]
    fn classifies_serving_config_changes_keys_publishes() {
        assert!(is_console_path("settings/serving", false));
        assert!(is_console_path("settings/serving", true));
        assert!(is_console_path("settings/config", false));
        assert!(is_console_path("settings/config", true));
        assert!(is_console_path("changes", false));
        assert!(!is_console_path("changes", true));
        assert!(is_console_path("keys", false));
        assert!(is_console_path("keys/rotate", false));
        assert!(is_console_path("publishes", false));
        assert!(!is_console_path("publishes", true));
    }

    #[test]
    fn classifies_channel_console_and_advance() {
        assert!(is_console_path("channels/stable/console", false));
        assert!(is_console_path("channels/stable/console", true));
        assert!(is_console_path("channels/stable/advance", true));
        // advance is POST-only.
        assert!(!is_console_path("channels/stable/advance", false));
        // a nested channel name is not a single segment.
        assert!(!is_console_path("channels/a/b/console", false));
    }

    #[test]
    fn rejects_browse_tails() {
        for tail in [
            "packages",
            "channels",
            "channels/stable",
            "releases",
            "health",
        ] {
            assert!(!is_console_path(tail, false), "{tail} GET");
            assert!(!is_console_path(tail, true), "{tail} POST");
        }
    }

    /// `dispatch_nested` returns `None` for a flat slug (the normal routes serve
    /// it) and for a browse tail (the facade serves it), so neither call ever
    /// touches the registry. These need a `ConsoleDeps`, which is heavy to
    /// construct, so the cheap early-outs are asserted indirectly through
    /// `is_console_path` and the `left.contains('/')` guard below.
    #[test]
    fn flat_slug_short_circuits_before_classification() {
        // A flat slug path has no inner slash before `/-/`.
        let path = "demo/-/settings";
        let (left, _right) = path.split_once("/-/").expect("has marker");
        assert!(!left.contains('/'), "flat slug must early-out");

        // A nested slug does contain a slash and proceeds to classification.
        let path = "andyl/demo/-/settings";
        let (left, right) = path.split_once("/-/").expect("has marker");
        assert!(left.contains('/'), "nested slug proceeds");
        assert!(is_console_path(right, false));
    }
}
