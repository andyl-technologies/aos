//! Same-origin browser authentication and typed Connect-JSON transport.
//!
//! The browser session cookie never becomes application state. The console
//! exchanges it, together with the session-bound CSRF proof injected into the
//! application shell, for a five-minute bearer held only in WASM memory. Every
//! management request then uses a generated canonical Connect path and a
//! ProtoJSON request/response type.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard};

use gloo_net::http::Request;
use serde::de::DeserializeOwned;
use serde::Serialize;

const SESSION_TOKEN_PATH: &str = "/-/auth/session-token";
const MAX_ERROR_BODY_BYTES: usize = 16 * 1024;

/// One authenticated, memory-only browser API client.
#[derive(Clone, Debug)]
pub struct ApiClient {
    csrf: String,
    session: Arc<Mutex<aos_proto_types::BrowserSessionTokenResponse>>,
}

impl ApiClient {
    /// Constructs a client around one synthetic session for pure UI tests.
    #[cfg(test)]
    pub(crate) fn for_test(session: aos_proto_types::BrowserSessionTokenResponse) -> Self {
        Self {
            csrf: "test-csrf".to_string(),
            session: Arc::new(Mutex::new(session)),
        }
    }

    /// Exchanges the ambient browser session for one short-lived API bearer.
    ///
    /// # Errors
    ///
    /// Returns an error when the CSRF proof is absent, the exchange request
    /// fails, the Hub rejects the session, or the response is malformed.
    pub async fn from_browser_session(csrf: &str, route: &str) -> Result<Self, TransportError> {
        if csrf.is_empty() {
            return Err(TransportError::MissingCsrf);
        }
        let session = exchange_browser_session(csrf, route).await?;
        Ok(Self {
            csrf: csrf.to_string(),
            session: Arc::new(Mutex::new(session)),
        })
    }

    /// Returns the authenticated browser-session summary.
    #[must_use]
    pub fn session(&self) -> aos_proto_types::BrowserSessionTokenResponse {
        self.session_guard().clone()
    }

    /// Returns whether the live route-scoped session grants one permission.
    #[must_use]
    pub fn allows(&self, permission: &str) -> bool {
        self.session_guard()
            .route_permissions
            .iter()
            .any(|candidate| candidate == permission)
    }

    /// Invokes one generated Connect-JSON unary method.
    ///
    /// `path` must be one of the generated `*_PATH` constants in
    /// [`aos_proto_types`].
    ///
    /// # Errors
    ///
    /// Returns an error when request serialization or transport fails, the Hub
    /// returns a non-success status, or the response violates its message type.
    pub async fn call<RequestMessage, ResponseMessage>(
        &self,
        path: &str,
        request: &RequestMessage,
    ) -> Result<ResponseMessage, TransportError>
    where
        RequestMessage: Serialize,
        ResponseMessage: DeserializeOwned,
    {
        if !is_generated_connect_path(path) {
            return Err(TransportError::InvalidPath);
        }
        let request_body = serde_json::to_string(request)
            .map_err(|error| TransportError::Json(error.to_string()))?;
        let bearer = self.session_guard().access_token.clone();
        let (mut status, mut response_body) = send_connect(path, &bearer, &request_body).await?;
        if status == 401 {
            let refreshed = exchange_browser_session(&self.csrf, &current_browser_route()).await?;
            let bearer = refreshed.access_token.clone();
            *self.session_guard() = refreshed;
            (status, response_body) = send_connect(path, &bearer, &request_body).await?;
        }
        if status == 401 {
            redirect_to_login()?;
            return Err(TransportError::SessionExpired);
        }
        if !(200..300).contains(&status) {
            return Err(TransportError::Http {
                status,
                detail: bounded_detail(&response_body),
            });
        }
        serde_json::from_str(&response_body)
            .map_err(|error| TransportError::Json(error.to_string()))
    }

    /// Collects every page from one generated Connect-JSON list method.
    ///
    /// The request factory receives the next page token. The response splitter
    /// returns that page's items and following token. Repeated non-empty tokens
    /// fail closed rather than spinning or silently truncating inventory.
    ///
    /// # Errors
    ///
    /// Returns an error when any page request fails or the server repeats a
    /// pagination token.
    pub(crate) async fn collect_pages<RequestMessage, ResponseMessage, Item, MakeRequest, Split>(
        &self,
        path: &str,
        mut make_request: MakeRequest,
        split: Split,
    ) -> Result<Vec<Item>, TransportError>
    where
        RequestMessage: Serialize,
        ResponseMessage: DeserializeOwned,
        MakeRequest: FnMut(String) -> RequestMessage,
        Split: Fn(ResponseMessage) -> (Vec<Item>, String),
    {
        let mut token = String::new();
        let mut seen = HashSet::new();
        let mut items = Vec::new();
        loop {
            let response = self
                .call::<RequestMessage, ResponseMessage>(path, &make_request(token))
                .await?;
            let (page, next) = split(response);
            items.extend(page);
            if next.is_empty() {
                return Ok(items);
            }
            if !seen.insert(next.clone()) {
                return Err(TransportError::PaginationCycle);
            }
            token = next;
        }
    }

    /// Uploads exact publication bytes to a server-issued same-origin URL.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL escapes the typed publication route, the
    /// request fails, or the Hub rejects the bytes.
    pub(crate) async fn put_publication_object(
        &self,
        upload_url: &str,
        file: &web_sys::File,
    ) -> Result<(), TransportError> {
        validate_publication_upload_url(upload_url)?;
        let bearer = self.session_guard().access_token.clone();
        let mut status = send_publication_upload(upload_url, &bearer, file).await?;
        if status == 401 {
            let refreshed = exchange_browser_session(&self.csrf, &current_browser_route()).await?;
            let bearer = refreshed.access_token.clone();
            *self.session_guard() = refreshed;
            status = send_publication_upload(upload_url, &bearer, file).await?;
        }
        if status == 401 {
            redirect_to_login()?;
            return Err(TransportError::SessionExpired);
        }
        if !(200..300).contains(&status) {
            return Err(TransportError::Http {
                status,
                detail: "publication upload was rejected".to_string(),
            });
        }
        Ok(())
    }

    /// Uploads cache-object bytes to a server-issued direct or Hub-proxy URL.
    ///
    /// A bearer is attached only to typed same-origin proxy URLs. Direct-origin
    /// capabilities retain their query signature and never receive Hub
    /// credentials.
    ///
    /// # Errors
    ///
    /// Returns an error when the URL is not an HTTP(S) upload capability, the
    /// request fails, or the upload endpoint rejects the bytes.
    pub(crate) async fn put_cache_object(
        &self,
        upload_url: &str,
        body: &web_sys::Blob,
    ) -> Result<Option<aos_proto_types::CacheMultipartPart>, TransportError> {
        let (same_origin, expects_part) = validate_cache_upload_url(upload_url)?;
        let bearer = same_origin.then(|| self.session_guard().access_token.clone());
        let (mut status, mut response) =
            send_cache_upload(upload_url, bearer.as_deref(), body).await?;
        if same_origin && status == 401 {
            let refreshed = exchange_browser_session(&self.csrf, &current_browser_route()).await?;
            let bearer = refreshed.access_token.clone();
            *self.session_guard() = refreshed;
            (status, response) = send_cache_upload(upload_url, Some(&bearer), body).await?;
        }
        if same_origin && status == 401 {
            redirect_to_login()?;
            return Err(TransportError::SessionExpired);
        }
        if !(200..300).contains(&status) {
            return Err(TransportError::Http {
                status,
                detail: bounded_detail(&response),
            });
        }
        if !expects_part {
            return Ok(None);
        }
        if response.trim().is_empty() {
            return Err(TransportError::Json(
                "multipart upload omitted its part receipt".to_string(),
            ));
        }
        serde_json::from_str(&response)
            .map(Some)
            .map_err(|error| TransportError::Json(error.to_string()))
    }

    fn session_guard(&self) -> MutexGuard<'_, aos_proto_types::BrowserSessionTokenResponse> {
        match self.session.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

fn current_browser_route() -> String {
    leptos::web_sys::window()
        .and_then(|window| window.location().pathname().ok())
        .unwrap_or_else(|| "/".to_string())
}

async fn exchange_browser_session(
    csrf: &str,
    route: &str,
) -> Result<aos_proto_types::BrowserSessionTokenResponse, TransportError> {
    let response = Request::post(SESSION_TOKEN_PATH)
        .header("x-aos-csrf", csrf)
        .header("x-aos-console-route", route)
        .header("accept", "application/json")
        .body(String::new())
        .map_err(|error| TransportError::Request(error.to_string()))?
        .send()
        .await
        .map_err(|error| TransportError::Request(error.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| TransportError::Response(error.to_string()))?;
    if !(200..300).contains(&status) {
        return Err(TransportError::Http {
            status,
            detail: bounded_detail(&body),
        });
    }
    let session: aos_proto_types::BrowserSessionTokenResponse =
        serde_json::from_str(&body).map_err(|error| TransportError::Json(error.to_string()))?;
    if session.access_token.is_empty()
        || session.token_type != "Bearer"
        || session.expires_in <= 0
        || session.principal.is_none()
    {
        return Err(TransportError::InvalidSession);
    }
    Ok(session)
}

async fn send_connect(
    path: &str,
    bearer: &str,
    body: &str,
) -> Result<(u16, String), TransportError> {
    let response = Request::post(path)
        .header("authorization", &format!("Bearer {bearer}"))
        .header(
            aos_proto_types::CONNECT_PROTOCOL_VERSION_HEADER,
            aos_proto_types::CONNECT_PROTOCOL_VERSION,
        )
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(body.to_string())
        .map_err(|error| TransportError::Request(error.to_string()))?
        .send()
        .await
        .map_err(|error| TransportError::Request(error.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| TransportError::Response(error.to_string()))?;
    Ok((status, body))
}

async fn send_publication_upload(
    upload_url: &str,
    bearer: &str,
    file: &web_sys::File,
) -> Result<u16, TransportError> {
    let response = Request::put(upload_url)
        .header("authorization", &format!("Bearer {bearer}"))
        .header("content-type", "application/octet-stream")
        .body(file.clone())
        .map_err(|error| TransportError::Request(error.to_string()))?
        .send()
        .await
        .map_err(|error| TransportError::Request(error.to_string()))?;
    Ok(response.status())
}

async fn send_cache_upload(
    upload_url: &str,
    bearer: Option<&str>,
    body: &web_sys::Blob,
) -> Result<(u16, String), TransportError> {
    let mut request = Request::put(upload_url).header("content-type", "application/octet-stream");
    if let Some(bearer) = bearer {
        request = request.header("authorization", &format!("Bearer {bearer}"));
    }
    let response = request
        .body(body.clone())
        .map_err(|error| TransportError::Request(error.to_string()))?
        .send()
        .await
        .map_err(|error| TransportError::Request(error.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| TransportError::Response(error.to_string()))?;
    Ok((status, body))
}

fn validate_cache_upload_url(upload_url: &str) -> Result<(bool, bool), TransportError> {
    let parsed =
        leptos::web_sys::Url::new(upload_url).map_err(|_| TransportError::InvalidUploadUrl)?;
    if !matches!(parsed.protocol().as_str(), "http:" | "https:")
        || !parsed.username().is_empty()
        || !parsed.password().is_empty()
        || !parsed.hash().is_empty()
    {
        return Err(TransportError::InvalidUploadUrl);
    }
    let origin = leptos::web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .ok_or(TransportError::InvalidUploadUrl)?;
    if parsed.origin() != origin {
        return Ok((false, false));
    }
    let path = parsed.pathname();
    let object_prefix = "/aos.hub.v1.BinaryCacheService/UploadObject/";
    let part_prefix = "/aos.hub.v1.BinaryCacheService/UploadPart/";
    let is_object = path
        .strip_prefix(object_prefix)
        .is_some_and(|suffix| !suffix.is_empty());
    let is_part = path
        .strip_prefix(part_prefix)
        .is_some_and(|suffix| !suffix.is_empty());
    if is_object || is_part {
        if !parsed.search().is_empty() {
            return Err(TransportError::InvalidUploadUrl);
        }
        return Ok((true, is_part));
    }
    Ok((false, false))
}

fn validate_publication_upload_url(upload_url: &str) -> Result<(), TransportError> {
    let parsed =
        leptos::web_sys::Url::new(upload_url).map_err(|_| TransportError::InvalidUploadUrl)?;
    let origin = leptos::web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .ok_or(TransportError::InvalidUploadUrl)?;
    let prefix = "/aos.hub.v1.PublishService/UploadObject/";
    let path = parsed.pathname();
    let suffix = path.strip_prefix(prefix).unwrap_or_default();
    let mut segments = suffix.split('/');
    let publication_id = segments.next().unwrap_or_default();
    let object_id = segments.next().unwrap_or_default();
    if parsed.origin() != origin
        || publication_id.is_empty()
        || !publication_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || object_id
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 0)
            .is_none()
        || segments.next().is_some()
        || !parsed.search().is_empty()
        || !parsed.hash().is_empty()
        || !parsed.username().is_empty()
        || !parsed.password().is_empty()
    {
        return Err(TransportError::InvalidUploadUrl);
    }
    Ok(())
}

fn redirect_to_login() -> Result<(), TransportError> {
    let window = leptos::web_sys::window().ok_or(TransportError::SessionExpired)?;
    let location = window.location();
    let mut next = location
        .pathname()
        .map_err(|_| TransportError::SessionExpired)?;
    next.push_str(
        &location
            .search()
            .map_err(|_| TransportError::SessionExpired)?,
    );
    next.push_str(
        &location
            .hash()
            .map_err(|_| TransportError::SessionExpired)?,
    );
    let encoded = js_sys::encode_uri_component(&next);
    location
        .set_href(&format!("/login?next={encoded}"))
        .map_err(|_| TransportError::SessionExpired)
}

/// Failure returned by the browser transport boundary.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TransportError {
    /// The application shell omitted its session-bound CSRF proof.
    #[error("the application shell did not provide a CSRF proof")]
    MissingCsrf,
    /// A fetch request could not be constructed or dispatched.
    #[error("request failed: {0}")]
    Request(String),
    /// A fetch response body could not be read.
    #[error("response failed: {0}")]
    Response(String),
    /// The Hub returned a non-success response.
    #[error("Hub returned HTTP {status}: {detail}")]
    Http {
        /// HTTP status code.
        status: u16,
        /// Bounded, display-safe response detail.
        detail: String,
    },
    /// A request or response failed ProtoJSON serialization.
    #[error("invalid API JSON: {0}")]
    Json(String),
    /// The session-token response omitted required security fields.
    #[error("the Hub returned an invalid browser session token")]
    InvalidSession,
    /// The caller supplied a non-canonical Connect route.
    #[error("the API method path is not canonical")]
    InvalidPath,
    /// A list endpoint repeated a non-empty page token.
    #[error("the Hub repeated a pagination token")]
    PaginationCycle,
    /// A publication upload URL escaped the typed same-origin route.
    #[error("the publication upload URL is not a typed same-origin URL")]
    InvalidUploadUrl,
    /// Both the active bearer and one session refresh were unauthorized.
    #[error("the browser session expired; sign in again")]
    SessionExpired,
}

fn is_generated_connect_path(path: &str) -> bool {
    aos_proto_types::EXPECTED_CONNECT_PATHS.contains(&path)
}

fn bounded_detail(body: &str) -> String {
    let mut detail = body
        .chars()
        .filter(|character| !character.is_control() || *character == ' ')
        .take(MAX_ERROR_BODY_BYTES)
        .collect::<String>();
    if detail.is_empty() {
        detail = "request rejected".to_string();
    }
    detail
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_connect_requests_use_the_required_protocol_version() {
        assert_eq!(
            aos_proto_types::CONNECT_PROTOCOL_VERSION_HEADER,
            "connect-protocol-version"
        );
        assert_eq!(aos_proto_types::CONNECT_PROTOCOL_VERSION, "1");
    }

    #[test]
    fn connect_paths_are_closed_and_error_details_are_bounded() {
        assert!(is_generated_connect_path(
            "/aos.hub.v1.IdentityService/WhoAmI"
        ));
        assert!(!is_generated_connect_path("https://example.test/steal"));
        assert!(!is_generated_connect_path("/aos.hub.v1.X/Method?token=x"));
        assert_eq!(bounded_detail("bad\nrequest"), "badrequest");
        assert_eq!(bounded_detail("\n\r"), "request rejected");
        assert_eq!(bounded_detail(&"x".repeat(20_000)).len(), 16_384);
    }
}
