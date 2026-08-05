//! Nested-canonical registry console dispatch.
//!
//! The shared console router ([`super::router::console_router`]) mounts every
//! producer-console route with a fixed, single-segment slug shape —
//! `/{slug}/-/settings`, `/{slug}/-/settings/tokens`,
//! `/{slug}/-/settings/channels/{name}`, and so on. `axum`'s `{slug}` parameter
//! captures exactly one path segment, so a registry whose canonical path has
//! slashes (`andyl/demo`, `acme/infra/cdn`) never matches those routes: the
//! request cannot be dispatched by the flat router.
//!
//! The native hub and Cloudflare Worker each offer their unmatched path to this
//! shared dispatcher before machine-facade routing. Both serve the console from
//! the shared handlers
//! ([`super::handlers`]), which are already nested-aware (each registry-scoped
//! handler calls `resolve_registry`, reconstructing the nested registry from the
//! request URI when the flat slug misses).
//!
//! [`dispatch_nested`] recognizes a nested `/-/` console path, classifies its
//! tail with [`console_path_methods`], and calls the matching shared handler
//! directly. It passes the full pre-`/-/` path as the `Path(slug)` so
//! `resolve_registry` resolves the nested registry with no first-segment
//! ambiguity. Recognized console paths reject methods other than their declared
//! `GET`/`POST` set with `405`; a path that is not a nested console page returns
//! [`None`] so the caller can continue to browse handling.
//!
//! # Recognized tails
//!
//! Braced comma-separated names below are shorthand for alternatives. The
//! executable contract remains [`super::manifest::REGISTRY_ROUTES`].
//!
//! ```text
//! settings                                                            GET
//! settings/{access,placements,placement-policies,placement-equivalences} GET
//! settings/{cache-stack,retention-consumers,population-targets}        GET
//! settings/{operations,danger,delivery-routes,upstream-mirror}         GET
//! settings/delivery-routes/canonical-audiences                        GET
//! settings/placements/new                                             GET
//! settings/placements/{plan-create,create}                             POST
//! settings/placements/{placement}/{plan-promote,promote}               POST
//! settings/placements/{placement}/{plan-update,update}                 POST
//! settings/placements/{placement}/{plan-drain,drain}                   POST
//! settings/placements/{placement}/{plan-delete,delete}                 POST
//! settings/placements/{plan-remove-write-authority,remove-write-authority} POST
//! settings/placements/{plan-cancel-promotion,cancel-promotion}         POST
//! settings/tokens                                                     GET, POST
//! settings/tokens/{token}/revoke                                       POST
//! settings/channels                                                   GET
//! settings/channels/{name}                                            GET
//! settings/signing-keys                                               GET
//! settings/signing-keys/rotate                                        GET
//! settings/publish-history                                            GET
//! settings/configuration                                              GET, POST
//! settings/change-requests                                            GET
//! settings/change-requests/{id}                                       GET
//! settings/change-requests/{id}/{comment,review,close,reopen}          POST
//! ```

use axum::body::Bytes;
use axum::extract::{Form, Path, Query};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use crate::clock::Instant;
use crate::web::console::handlers::{self, PageQuery, RequestStart};
use crate::web::console::manifest::{nested_route_methods, ConsoleRouteMatched, RouteMethods};
use crate::web::console::ports::ConsoleDeps;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConsoleMethod {
    Get,
    Post,
}

impl RouteMethods {
    fn allows(self, method: ConsoleMethod) -> bool {
        matches!(
            (self, method),
            (RouteMethods::Get, ConsoleMethod::Get)
                | (RouteMethods::Post, ConsoleMethod::Post)
                | (RouteMethods::GetAndPost, _)
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
fn console_path_methods(right: &str) -> Option<RouteMethods> {
    nested_route_methods(right)
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
    mark_declared_route(StatusCode::BAD_REQUEST.into_response())
}

/// Marks responses produced by a declared nested console route.
fn mark_declared_route(mut response: Response) -> Response {
    response.extensions_mut().insert(ConsoleRouteMatched);
    response
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
    let path = uri.path().trim_start_matches('/').to_string();
    if path.ends_with('/') {
        return None;
    }
    let (left, right) = path.split_once("/-/")?;

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
            let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
            let Some(methods) = console_path_methods(right) else {
                return Some(mark_declared_route(
                    StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                ));
            };
            response.headers_mut().insert(
                header::ALLOW,
                HeaderValue::from_static(methods.allow_header()),
            );
            return Some(mark_declared_route(response));
        }
    };

    let slug = left.trim_end_matches('/').to_string();
    let started = RequestStart(Instant::now());

    let response = match (right, dispatch_method) {
        // -- settings landing & mutations ------------------------------------
        ("settings", ConsoleMethod::Get) => {
            handlers::registry_settings(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/access", ConsoleMethod::Get) => {
            handlers::registry_access(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/placements", ConsoleMethod::Get) => {
            handlers::registry_placements(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/placement-policies", ConsoleMethod::Get) => {
            handlers::registry_placement_policies(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/placement-equivalences", ConsoleMethod::Get) => {
            handlers::registry_placement_equivalences(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/placements/new", ConsoleMethod::Get) => {
            handlers::registry_new_placement(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/placements/plan-create", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_plan_create_placement(
                deps,
                headers,
                started,
                uri,
                Path(slug),
                Form(form),
            )
            .await
        }
        ("settings/placements/create", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_create_placement(deps, headers, uri, Path(slug), Form(form)).await
        }
        ("settings/placements/plan-remove-write-authority", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_plan_remove_write_authority(
                deps,
                headers,
                started,
                uri,
                Path(slug),
                Form(form),
            )
            .await
        }
        ("settings/placements/remove-write-authority", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_remove_write_authority(deps, headers, uri, Path(slug), Form(form))
                .await
        }
        ("settings/placements/plan-cancel-promotion", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_plan_cancel_placement_promotion(
                deps,
                headers,
                started,
                uri,
                Path(slug),
                Form(form),
            )
            .await
        }
        ("settings/placements/cancel-promotion", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_cancel_placement_promotion(
                deps,
                headers,
                uri,
                Path(slug),
                Form(form),
            )
            .await
        }
        (other, ConsoleMethod::Post)
            if other
                .strip_prefix("settings/placements/")
                .is_some_and(|rest| rest.ends_with("/plan-update")) =>
        {
            let Some(placement) = other
                .strip_prefix("settings/placements/")
                .and_then(|rest| rest.strip_suffix("/plan-update"))
                .filter(|placement| !placement.contains('/'))
            else {
                return Some(bad_request());
            };
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_plan_update_placement(
                deps,
                headers,
                started,
                uri,
                Path((slug, placement.to_string())),
                Form(form),
            )
            .await
        }
        (other, ConsoleMethod::Post)
            if other
                .strip_prefix("settings/placements/")
                .is_some_and(|rest| rest.ends_with("/update")) =>
        {
            let Some(placement) = other
                .strip_prefix("settings/placements/")
                .and_then(|rest| rest.strip_suffix("/update"))
                .filter(|placement| !placement.contains('/'))
            else {
                return Some(bad_request());
            };
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_update_placement(
                deps,
                headers,
                uri,
                Path((slug, placement.to_string())),
                Form(form),
            )
            .await
        }
        (other, ConsoleMethod::Post)
            if other
                .strip_prefix("settings/placements/")
                .is_some_and(|rest| rest.ends_with("/plan-drain")) =>
        {
            let Some(placement) = other
                .strip_prefix("settings/placements/")
                .and_then(|rest| rest.strip_suffix("/plan-drain"))
                .filter(|placement| !placement.contains('/'))
            else {
                return Some(bad_request());
            };
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_plan_drain_placement(
                deps,
                headers,
                started,
                uri,
                Path((slug, placement.to_string())),
                Form(form),
            )
            .await
        }
        (other, ConsoleMethod::Post)
            if other
                .strip_prefix("settings/placements/")
                .is_some_and(|rest| rest.ends_with("/drain")) =>
        {
            let Some(placement) = other
                .strip_prefix("settings/placements/")
                .and_then(|rest| rest.strip_suffix("/drain"))
                .filter(|placement| !placement.contains('/'))
            else {
                return Some(bad_request());
            };
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_drain_placement(
                deps,
                headers,
                uri,
                Path((slug, placement.to_string())),
                Form(form),
            )
            .await
        }
        (other, ConsoleMethod::Post)
            if other
                .strip_prefix("settings/placements/")
                .is_some_and(|rest| rest.ends_with("/plan-delete")) =>
        {
            let Some(placement) = other
                .strip_prefix("settings/placements/")
                .and_then(|rest| rest.strip_suffix("/plan-delete"))
                .filter(|placement| !placement.contains('/'))
            else {
                return Some(bad_request());
            };
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_plan_delete_placement(
                deps,
                headers,
                started,
                uri,
                Path((slug, placement.to_string())),
                Form(form),
            )
            .await
        }
        (other, ConsoleMethod::Post)
            if other
                .strip_prefix("settings/placements/")
                .is_some_and(|rest| rest.ends_with("/delete")) =>
        {
            let Some(placement) = other
                .strip_prefix("settings/placements/")
                .and_then(|rest| rest.strip_suffix("/delete"))
                .filter(|placement| !placement.contains('/'))
            else {
                return Some(bad_request());
            };
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_delete_placement(
                deps,
                headers,
                uri,
                Path((slug, placement.to_string())),
                Form(form),
            )
            .await
        }
        (other, ConsoleMethod::Post)
            if other
                .strip_prefix("settings/placements/")
                .is_some_and(|rest| rest.ends_with("/plan-promote")) =>
        {
            let Some(placement) = other
                .strip_prefix("settings/placements/")
                .and_then(|rest| rest.strip_suffix("/plan-promote"))
                .filter(|placement| !placement.contains('/'))
            else {
                return Some(bad_request());
            };
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_plan_promote_placement(
                deps,
                headers,
                started,
                uri,
                Path((slug, placement.to_string())),
                Form(form),
            )
            .await
        }
        (other, ConsoleMethod::Post)
            if other
                .strip_prefix("settings/placements/")
                .is_some_and(|rest| rest.ends_with("/promote")) =>
        {
            let Some(placement) = other
                .strip_prefix("settings/placements/")
                .and_then(|rest| rest.strip_suffix("/promote"))
                .filter(|placement| !placement.contains('/'))
            else {
                return Some(bad_request());
            };
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::registry_promote_placement(
                deps,
                headers,
                uri,
                Path((slug, placement.to_string())),
                Form(form),
            )
            .await
        }
        ("settings/cache-stack", ConsoleMethod::Get) => {
            handlers::registry_cache_stack(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/retention-consumers", ConsoleMethod::Get) => {
            handlers::registry_retention_consumers(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/population-targets", ConsoleMethod::Get) => {
            handlers::registry_population_targets(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/channels", ConsoleMethod::Get) => {
            handlers::registry_channels(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/operations", ConsoleMethod::Get) => {
            handlers::registry_operations(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/danger", ConsoleMethod::Get) => {
            handlers::registry_danger(deps, headers, started, uri, Path(slug)).await
        }
        // -- delivery and mirroring ------------------------------------------
        ("settings/delivery-routes", ConsoleMethod::Get) => {
            handlers::registry_delivery(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/delivery-routes/canonical-audiences", ConsoleMethod::Get) => {
            handlers::registry_canonical_audiences(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/upstream-mirror", ConsoleMethod::Get) => {
            handlers::registry_upstream_mirror(deps, headers, started, uri, Path(slug)).await
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
        (other, ConsoleMethod::Post)
            if other
                .strip_prefix("settings/tokens/")
                .is_some_and(|rest| rest.ends_with("/revoke")) =>
        {
            let Some(token) = other
                .strip_prefix("settings/tokens/")
                .and_then(|rest| rest.strip_suffix("/revoke"))
                .filter(|token| !token.contains('/'))
            else {
                return Some(bad_request());
            };
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::tokens_revoke(
                deps,
                headers,
                started,
                uri,
                Path((slug, token.to_string())),
                Form(form),
            )
            .await
        }
        // -- git-backed config / change requests -----------------------------
        ("settings/configuration", ConsoleMethod::Get) => {
            handlers::config_edit(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/configuration", ConsoleMethod::Post) => {
            // The config form posts repeated cache rows, which serde_urlencoded
            // can't collect into a Vec; hand the raw body to the shared decoder.
            let body = String::from_utf8_lossy(&body).into_owned();
            handlers::config_submit(deps, headers, started, uri, Path(slug), body).await
        }
        ("settings/change-requests", ConsoleMethod::Get) => {
            handlers::changes(deps, headers, started, uri, Path(slug)).await
        }
        // -- change-request detail & review actions --------------------------
        (other, ConsoleMethod::Get)
            if other
                .strip_prefix("settings/change-requests/")
                .is_some_and(|r| !r.contains('/')) =>
        {
            // The method classifier proved the shape; recover the id defensively.
            let Some(id) = other
                .strip_prefix("settings/change-requests/")
                .map(str::to_string)
            else {
                return Some(bad_request());
            };
            handlers::change_detail(deps, headers, started, uri, Path((slug, id))).await
        }
        (other, ConsoleMethod::Post)
            if other
                .strip_prefix("settings/change-requests/")
                .is_some_and(|r| r.contains('/')) =>
        {
            let Some((id, action)) = other
                .strip_prefix("settings/change-requests/")
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
        // -- signing keys & publishes ----------------------------------------
        ("settings/signing-keys", ConsoleMethod::Get) => {
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
        ("settings/signing-keys", ConsoleMethod::Post) => {
            let Ok(form) = serde_urlencoded::from_bytes(&body) else {
                return Some(bad_request());
            };
            handlers::keys_action(deps, headers, started, uri, Path(slug), Form(form)).await
        }
        ("settings/signing-keys/rotate", ConsoleMethod::Get) => {
            handlers::keys_rotate(deps, headers, started, uri, Path(slug)).await
        }
        ("settings/publish-history", ConsoleMethod::Get) => {
            handlers::publishes(deps, headers, started, uri, Path(slug)).await
        }
        // -- channel rollout -------------------------------------------------
        (other, ConsoleMethod::Get) => {
            // The method classifier already proved this is one channel detail.
            let Some(name) = other
                .strip_prefix("settings/channels/")
                .filter(|name| !name.contains('/'))
                .map(str::to_string)
            else {
                return Some(bad_request());
            };
            handlers::channel_console(deps, headers, started, uri, Path((slug, name))).await
        }
        (_, ConsoleMethod::Post) => bad_request(),
    };
    Some(mark_declared_route(response))
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
        assert!(accepts("settings/access", Method::GET));
        assert!(!accepts("settings/access", Method::POST));
    }

    #[test]
    fn classifies_settings_mutations_as_post_console_pages() {
        assert!(!accepts("settings/danger/delete", Method::POST));
    }

    #[test]
    fn classifies_placement_inventory_without_legacy_mutations() {
        assert!(accepts("settings/placements", Method::GET));
        assert!(!accepts("settings/placements", Method::POST));
    }

    #[test]
    fn classifies_token_pages() {
        assert!(accepts("settings/tokens", Method::GET));
        assert!(accepts("settings/tokens", Method::POST));
        assert!(accepts("settings/tokens/token-1/revoke", Method::POST));
        assert!(!accepts("settings/tokens/token-1/revoke", Method::GET));
        assert!(!accepts("settings/tokens/token-1/rotate", Method::POST));
    }

    #[test]
    fn classifies_serving_config_changes_keys_publishes() {
        assert!(accepts("settings/delivery-routes", Method::GET));
        assert!(!accepts("settings/delivery-routes", Method::POST));
        assert!(accepts(
            "settings/delivery-routes/canonical-audiences",
            Method::GET
        ));
        assert!(accepts("settings/upstream-mirror", Method::GET));
        assert!(!accepts("settings/upstream-mirror", Method::POST));
        assert!(accepts("settings/configuration", Method::GET));
        assert!(accepts("settings/configuration", Method::POST));
        assert!(accepts("settings/change-requests", Method::GET));
        assert!(!accepts("settings/change-requests", Method::POST));
        assert!(accepts("settings/signing-keys", Method::GET));
        assert!(accepts("settings/signing-keys/rotate", Method::GET));
        assert!(accepts("settings/publish-history", Method::GET));
        assert!(!accepts("settings/publish-history", Method::POST));
    }

    #[test]
    fn classifies_read_only_channel_inventory() {
        assert!(accepts("settings/channels", Method::GET));
        assert!(accepts("settings/channels/stable", Method::GET));
        assert!(!accepts("settings/channels/stable", Method::POST));
        assert!(!accepts("settings/channels/stable/advance", Method::POST));
        assert!(!accepts("settings/channels/stable/advance", Method::GET));
        // a nested channel name is not a single segment.
        assert!(!accepts("settings/channels/a/b", Method::GET));
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
            ("settings/access", true, false),
            ("settings/placements", true, false),
            ("settings/delivery-routes", true, false),
            ("settings/tokens/token-1/revoke", false, true),
            ("settings/change-requests/abc", true, false),
            ("settings/change-requests/abc/comment", false, true),
            ("settings/channels", true, false),
            ("settings/channels/stable", true, false),
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
