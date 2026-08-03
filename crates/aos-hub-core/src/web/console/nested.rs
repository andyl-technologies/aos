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
//! The native hub and Cloudflare Worker each offer their unmatched path to this
//! shared dispatcher before machine-facade routing. Both serve the console from
//! the *shared* handlers
//! ([`super::handlers`]), which are already nested-aware (each registry-scoped
//! handler calls `resolve_registry`, reconstructing the nested registry from the
//! request URI when the flat slug misses). Only the *routing* was missing.
//!
//! [`dispatch_nested`] is that missing piece: the Worker invokes it before the
//! normal router dispatch. It recognizes a nested `/-/` console path, classifies
//! its tail with [`console_path_methods`] (mirroring the native classifier), and
//! calls the matching shared handler directly — passing the full pre-`/-/` path
//! as the `Path(slug)` so `resolve_registry` resolves the nested registry with
//! no first-segment ambiguity. Recognized console paths reject methods other
//! than their declared `GET`/`POST` set with `405`; a path that is not a nested
//! console page returns [`None`] so the caller falls through to browse handling.
//!
//! # Recognized tails
//!
//! ```text
//! settings                       GET   registry settings overview
//! settings/general               GET   registry general policy
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConsoleMethod {
    Get,
    Post,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AllowedMethods {
    Get,
    Post,
    GetAndPost,
}

impl AllowedMethods {
    fn allows(self, method: ConsoleMethod) -> bool {
        matches!(
            (self, method),
            (Self::Get, ConsoleMethod::Get)
                | (Self::Post, ConsoleMethod::Post)
                | (Self::GetAndPost, _)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConsolePathDispatch {
    Method(ConsoleMethod),
    MethodNotAllowed,
}

/// Returns the declared methods for a producer-console tail, or `None` for a
/// consumer browse path.
///
/// Mirrors the native hub's classifier so both shells recognize the same set of
/// `(tail, method)` console pages. Returns `None` for browse pages
/// (`packages`, `channels/{name}`, `releases`, `health`, …) so
/// [`dispatch_nested`] leaves browse paths to the browse resolver and never
/// bounces an anonymous reader to `/login`.
///
/// # Examples
///
/// ```no_run
/// # // (private fn; shown for documentation only)
/// // settings is a GET-only landing page
/// // console_path_methods("settings") == Some(AllowedMethods::Get)
/// // a browse tail is never a console path
/// // console_path_methods("packages") == None
/// ```
fn console_path_methods(right: &str) -> Option<AllowedMethods> {
    match right {
        "settings/tokens" => Some(AllowedMethods::GetAndPost),
        "settings/tokens/revoke" | "settings/tokens/rotate" => Some(AllowedMethods::Post),
        // The config-edit page is GET (form) + POST (submit).
        "settings/config" => Some(AllowedMethods::GetAndPost),
        // These settings sections are GET-only; visibility, crawl, and delete
        // are POST-only mutations.
        "settings" | "settings/general" | "settings/caches" | "settings/danger" => {
            Some(AllowedMethods::Get)
        }
        // Storage is GET (view) + POST (change storage).
        "settings/storage" => Some(AllowedMethods::GetAndPost),
        // The bucket-direct frontend advertise toggle is POST-only.
        "settings/advertise-frontend" => Some(AllowedMethods::Post),
        "settings/visibility" | "settings/crawl" | "settings/delete" => Some(AllowedMethods::Post),
        "settings/cache-link" | "settings/cache-unlink" => Some(AllowedMethods::Post),
        // The serving & mirror page is GET (view) + POST (mutate).
        "settings/serving" => Some(AllowedMethods::GetAndPost),
        "changes" => Some(AllowedMethods::Get),
        "keys" | "keys/rotate" | "publishes" => Some(AllowedMethods::Get),
        other => {
            // changes/{id} (GET detail) and changes/{id}/{action} (POST).
            if let Some(rest) = other.strip_prefix("changes/") {
                return match rest.split_once('/') {
                    Some((id, action))
                        if !id.is_empty()
                            && matches!(action, "comment" | "review" | "close" | "reopen") =>
                    {
                        Some(AllowedMethods::Post)
                    }
                    Some(_) => None,
                    None if !rest.is_empty() => Some(AllowedMethods::Get),
                    None => None,
                };
            }
            if let Some(name) = other
                .strip_prefix("channels/")
                .and_then(|rest| rest.strip_suffix("/console"))
            {
                return (!name.contains('/')).then_some(AllowedMethods::GetAndPost);
            }
            // The direct hosted-key advance is POST-only.
            other
                .strip_prefix("channels/")
                .and_then(|rest| rest.strip_suffix("/advance"))
                .filter(|name| !name.contains('/'))
                .map(|_| AllowedMethods::Post)
        }
    }
}

/// Classifies a recognized console path without treating arbitrary non-POST
/// methods as reads.
fn classify_console_path(right: &str, method: &Method) -> Option<ConsolePathDispatch> {
    let allowed = console_path_methods(right)?;
    let method = if *method == Method::GET {
        ConsoleMethod::Get
    } else if *method == Method::POST {
        ConsoleMethod::Post
    } else {
        return Some(ConsolePathDispatch::MethodNotAllowed);
    };
    Some(if allowed.allows(method) {
        ConsolePathDispatch::Method(method)
    } else {
        ConsolePathDispatch::MethodNotAllowed
    })
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
/// [`console_path_methods`], and — for a recognized console page — invokes the
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
/// * `Some(response)` for a recognized nested console page (including `405`
///   for an undeclared method, auth redirects, `404`s for a missing registry,
///   and `400`s for a malformed form body).
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

    // Classify the tail before touching the registry or session: a browse page
    // (`packages`, `channels/{name}`, …) is not a console path, so return `None`
    // and let the facade's nested browse handling take it.
    let dispatch_method = match classify_console_path(right, &method)? {
        ConsolePathDispatch::Method(method) => method,
        ConsolePathDispatch::MethodNotAllowed => {
            return Some(StatusCode::METHOD_NOT_ALLOWED.into_response());
        }
    };

    let slug = left.trim_end_matches('/').to_string();
    let started = RequestStart(Instant::now());

    let response = match (right, dispatch_method) {
        // -- settings landing & mutations ------------------------------------
        ("settings", ConsoleMethod::Get) => {
            handlers::registry_settings(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/general", ConsoleMethod::Get) => {
            handlers::registry_general(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/storage", ConsoleMethod::Get) => {
            handlers::registry_storage(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/caches", ConsoleMethod::Get) => {
            handlers::registry_caches(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/danger", ConsoleMethod::Get) => {
            handlers::registry_danger(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/visibility", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_visibility(deps, headers, started, uri, Path(slug), Form(form)).await
        }
        ("settings/crawl", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_crawl_policy(deps, headers, started, uri, Path(slug), Form(form))
                .await
        }
        ("settings/delete", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            // `registry_delete` takes no `RequestStart`.
            handlers::registry_delete(deps, headers, uri, Path(slug), Form(form)).await
        }
        ("settings/cache-link", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_cache_link(deps, headers, started, uri, Path(slug), Form(form)).await
        }
        ("settings/cache-unlink", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_cache_unlink(deps, headers, started, uri, Path(slug), Form(form))
                .await
        }
        ("settings/storage", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_change_storage(deps, headers, started, uri, Path(slug), Form(form))
                .await
        }
        ("settings/advertise-frontend", ConsoleMethod::Post) => {
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
        ("settings/serving", ConsoleMethod::Get) => {
            handlers::serving(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/serving", ConsoleMethod::Post) => {
            // `serving_post` consumes the raw body itself (it accepts multiple
            // form shapes), so pass the bytes straight through.
            handlers::serving_post(deps, headers, started, uri, Path(slug), body).await
        }
        // -- tokens ----------------------------------------------------------
        ("settings/tokens", ConsoleMethod::Get) => {
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
        ("settings/tokens", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::tokens_create(deps, headers, started, uri, Path(slug), Form(form)).await
        }
        ("settings/tokens/revoke", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::tokens_revoke(deps, headers, started, uri, Path(slug), Form(form)).await
        }
        ("settings/tokens/rotate", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::tokens_rotate(deps, headers, started, uri, Path(slug), Form(form)).await
        }
        // -- git-backed config / change requests -----------------------------
        ("settings/config", ConsoleMethod::Get) => {
            handlers::config_edit(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/config", ConsoleMethod::Post) => {
            // The config form posts repeated cache rows, which serde_urlencoded
            // can't collect into a Vec; hand the raw body to the shared decoder.
            let body = String::from_utf8_lossy(&body).into_owned();
            handlers::config_submit(deps, headers, started, uri, Path(slug), body).await
        }
        ("changes", ConsoleMethod::Get) => {
            handlers::changes(deps, headers, started, uri, Path(slug)).await
        }
        // -- change-request detail & review actions --------------------------
        (other, ConsoleMethod::Get)
            if other
                .strip_prefix("changes/")
                .is_some_and(|r| !r.contains('/')) =>
        {
            // The method classifier proved the shape; recover the id defensively.
            let Some(id) = other.strip_prefix("changes/").map(str::to_string) else {
                return Some(bad_request());
            };
            handlers::change_detail(deps, headers, started, uri, Path((slug, id))).await
        }
        (other, ConsoleMethod::Post)
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
        ("keys", ConsoleMethod::Get) => {
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
        ("keys/rotate", ConsoleMethod::Get) => {
            handlers::keys_rotate(deps, headers, started, uri, Path(slug)).await
        }
        ("publishes", ConsoleMethod::Get) => {
            handlers::publishes(deps, headers, started, uri, Path(slug)).await
        }
        // -- channel rollout -------------------------------------------------
        (other, ConsoleMethod::Post) if other.ends_with("/advance") => {
            // channels/{name}/advance (POST): the direct hosted-key advance.
            // The method classifier already proved this matches.
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
        (other, method) => {
            // channels/{name}/console (GET renders, POST prepares an advance);
            // The method classifier already proved this matches.
            let name = other
                .strip_prefix("channels/")
                .and_then(|rest| rest.strip_suffix("/console"))
                .filter(|name| !name.contains('/'))?
                .to_string();
            if method == ConsoleMethod::Post {
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

    fn accepts(tail: &str, method: Method) -> bool {
        matches!(
            classify_console_path(tail, &method),
            Some(ConsolePathDispatch::Method(_))
        )
    }

    #[test]
    fn classifies_settings_landing_as_get_console_page() {
        assert!(accepts("settings", Method::GET));
        assert!(!accepts("settings", Method::POST));
        assert!(accepts("settings/general", Method::GET));
        assert!(!accepts("settings/general", Method::POST));
    }

    #[test]
    fn classifies_settings_mutations_as_post_console_pages() {
        for tail in ["settings/visibility", "settings/crawl", "settings/delete"] {
            assert!(accepts(tail, Method::POST), "{tail} POST");
            assert!(!accepts(tail, Method::GET), "{tail} GET");
        }
    }

    #[test]
    fn classifies_storage_and_advertise_frontend() {
        // Storage is GET (view) + POST (change storage).
        assert!(accepts("settings/storage", Method::GET));
        assert!(accepts("settings/storage", Method::POST));
        // The bucket-direct frontend advertise toggle is POST-only — a nested
        // (org/name) registry must reach it here, else its save falls through to
        // the surface catch-all ("unsupported POST to a surface path").
        assert!(accepts("settings/advertise-frontend", Method::POST));
        assert!(!accepts("settings/advertise-frontend", Method::GET));
    }

    #[test]
    fn classifies_token_pages() {
        assert!(accepts("settings/tokens", Method::GET));
        assert!(accepts("settings/tokens", Method::POST));
        assert!(accepts("settings/tokens/revoke", Method::POST));
        assert!(!accepts("settings/tokens/revoke", Method::GET));
        assert!(accepts("settings/tokens/rotate", Method::POST));
    }

    #[test]
    fn classifies_serving_config_changes_keys_publishes() {
        assert!(accepts("settings/serving", Method::GET));
        assert!(accepts("settings/serving", Method::POST));
        assert!(accepts("settings/config", Method::GET));
        assert!(accepts("settings/config", Method::POST));
        assert!(accepts("changes", Method::GET));
        assert!(!accepts("changes", Method::POST));
        assert!(accepts("keys", Method::GET));
        assert!(accepts("keys/rotate", Method::GET));
        assert!(accepts("publishes", Method::GET));
        assert!(!accepts("publishes", Method::POST));
    }

    #[test]
    fn classifies_channel_console_and_advance() {
        assert!(accepts("channels/stable/console", Method::GET));
        assert!(accepts("channels/stable/console", Method::POST));
        assert!(accepts("channels/stable/advance", Method::POST));
        // advance is POST-only.
        assert!(!accepts("channels/stable/advance", Method::GET));
        // a nested channel name is not a single segment.
        assert!(!accepts("channels/a/b/console", Method::GET));
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
            assert!(!accepts(tail, Method::GET), "{tail} GET");
            assert!(!accepts(tail, Method::POST), "{tail} POST");
        }
    }

    #[test]
    fn recognized_console_paths_reject_all_undeclared_methods() {
        let matrix = [
            ("settings", true, false),
            ("settings/general", true, false),
            ("settings/storage", true, true),
            ("settings/visibility", false, true),
            ("settings/serving", true, true),
            ("settings/tokens/revoke", false, true),
            ("changes/abc", true, false),
            ("changes/abc/comment", false, true),
            ("channels/stable/console", true, true),
            ("channels/stable/advance", false, true),
        ];
        for (tail, get, post) in matrix {
            assert_eq!(accepts(tail, Method::GET), get, "{tail} GET");
            assert_eq!(accepts(tail, Method::POST), post, "{tail} POST");
            for method in [Method::PUT, Method::PATCH, Method::DELETE] {
                assert_eq!(
                    classify_console_path(tail, &method),
                    Some(ConsolePathDispatch::MethodNotAllowed),
                    "{tail} {method}",
                );
            }
        }
    }

    /// `dispatch_nested` returns `None` for a flat slug (the normal routes serve
    /// it) and for a browse tail (the facade serves it), so neither call ever
    /// touches the registry. These need a `ConsoleDeps`, which is heavy to
    /// construct, so the cheap early-outs are asserted indirectly through
    /// `classify_console_path` and the `left.contains('/')` guard below.
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
        assert!(accepts(right, Method::GET));
    }
}
