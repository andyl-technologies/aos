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
#[derive(Clone)]
pub struct ApiClient {
    csrf: String,
    session: Arc<Mutex<aos_proto_types::BrowserSessionTokenResponse>>,
    direct_actor_proof: Arc<Mutex<Option<crate::direct_upload_model::DirectActorProof>>>,
    direct_capabilities: Option<aos_proto_types::direct_upload::DirectUploadCapabilities>,
    upload_policy: Arc<Mutex<Option<crate::direct_upload_model::InitialUploadPolicy>>>,
    require_legacy_upload_policy: bool,
}

impl std::fmt::Debug for ApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiClient")
            .field("csrf", &"[REDACTED]")
            .field("session", &"[REDACTED]")
            .field("direct_actor_proof", &"[REDACTED]")
            .field("upload_policy", &"[REDACTED]")
            .field(
                "require_legacy_upload_policy",
                &self.require_legacy_upload_policy,
            )
            .finish()
    }
}

impl ApiClient {
    /// Pins this upload run's reviewed authority independently of shared tokens.
    pub(crate) fn with_direct_upload_capabilities(
        mut self,
        capabilities: aos_proto_types::direct_upload::DirectUploadCapabilities,
    ) -> Self {
        self.direct_capabilities = Some(capabilities);
        self
    }

    /// Chooses upload discovery from one positive authenticated WhoAmI policy.
    ///
    /// `None` means explicit legacy or the successful older-server compatibility
    /// response, requiring no direct service or configured actor IDs. Required
    /// direct mode reconciles capabilities using the same bearer snapshot.
    ///
    /// # Errors
    /// Rejects unknown/unready policy, identity/discovery mismatch or transport
    /// refusal. Only one actual WhoAmI401 permits legitimate session refresh.
    pub(crate) async fn discover_cache_upload(
        &self,
        target: &aos_proto_types::direct_upload::DirectCapabilitiesTarget,
    ) -> Result<Option<aos_proto_types::direct_upload::DirectUploadCapabilities>, TransportError>
    {
        use aos_proto_types::direct_upload::{
            decode_direct_control, encode_direct_control, DirectGetCapabilities,
        };
        let mut bearer = self.session_guard().access_token.clone();
        let mut policy = self.upload_policy_for(&bearer).await?;
        if policy.is_none() {
            let refreshed = exchange_browser_session(&self.csrf, &current_browser_route()).await?;
            bearer = refreshed.access_token.clone();
            *self.session_guard() = refreshed;
            policy = self.upload_policy_for(&bearer).await?;
        }
        let policy = policy.ok_or(TransportError::SessionExpired)?;
        if policy.is_legacy() {
            return Ok(None);
        }
        let body = encode_direct_control(&DirectGetCapabilities {
            target: target.clone(),
        })
        .map_err(|_| TransportError::InvalidPath)?;
        let send = policy
            .dispatch_with(
                &bearer,
                &browser_origin()?,
                direct_browser_now().map_err(|_| TransportError::SessionExpired)?,
                false,
                |proven| {
                    send_direct_connect(
                        aos_proto_types::DIRECT_UPLOAD_SERVICE_GET_CAPABILITIES_PATH,
                        proven,
                        &body,
                    )
                },
            )
            .map_err(|_| TransportError::SessionExpired)?;
        let (status, response) = send.await?;
        if status != 200 {
            return Err(TransportError::DirectUpload(
                "Required upload discovery is unavailable; no file bytes were sent",
            ));
        }
        let capabilities = decode_direct_control(&response).map_err(|_| {
            TransportError::DirectUpload("The Hub returned invalid upload discovery")
        })?;
        policy
            .validate_discovery(
                &capabilities,
                target,
                direct_browser_now().map_err(|_| TransportError::SessionExpired)?,
            )
            .map_err(|_| TransportError::SessionExpired)?;
        Ok(Some(capabilities))
    }

    /// Marks only this clone's old upload path for exact-bearer policy checks.
    pub(crate) fn for_legacy_upload(&self) -> Self {
        let mut client = self.clone();
        client.require_legacy_upload_policy = true;
        client
    }

    async fn upload_policy_for(
        &self,
        bearer: &str,
    ) -> Result<Option<crate::direct_upload_model::InitialUploadPolicy>, TransportError> {
        let origin = browser_origin()?;
        let now = direct_browser_now().map_err(|_| TransportError::SessionExpired)?;
        let cached = self
            .upload_policy
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(policy) = cached.filter(|policy| policy.matches(bearer, &origin, now)) {
            return Ok(Some(policy));
        }
        let (status, response) = send_direct_connect(
            aos_proto_types::IDENTITY_SERVICE_WHO_AM_I_PATH,
            bearer,
            b"{}",
        )
        .await?;
        if status == 401 {
            return Ok(None);
        }
        if status != 200 {
            return Err(TransportError::DirectUpload(
                "Authenticated upload policy is unavailable; no file bytes were sent",
            ));
        }
        let identity: aos_proto_types::WhoAmIResponse =
            aos_proto_types::direct_upload::decode_direct_control(&response).map_err(|_| {
                TransportError::DirectUpload("The Hub returned invalid upload policy")
            })?;
        let policy = crate::direct_upload_model::InitialUploadPolicy::from_authenticated(
            bearer,
            &origin,
            &identity,
            direct_browser_now().map_err(|_| TransportError::SessionExpired)?,
        )
        .map_err(|_| TransportError::SessionExpired)?;
        *self
            .upload_policy
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(policy.clone());
        Ok(Some(policy))
    }

    async fn legacy_upload_snapshot(
        &self,
        allow_refresh: bool,
    ) -> Result<
        (
            String,
            Option<crate::direct_upload_model::InitialUploadPolicy>,
            bool,
        ),
        TransportError,
    > {
        let mut bearer = self.session_guard().access_token.clone();
        if !self.require_legacy_upload_policy {
            return Ok((bearer, None, false));
        }
        let mut policy = self.upload_policy_for(&bearer).await?;
        let refreshed = policy.is_none();
        if refreshed {
            if !allow_refresh {
                return Err(TransportError::SessionExpired);
            }
            // The bounded policy readback itself observed an actual401. Refresh
            // before sending any body, sharing the existing one-refresh budget.
            let session = exchange_browser_session(&self.csrf, &current_browser_route()).await?;
            bearer = session.access_token.clone();
            *self.session_guard() = session;
            policy = self.upload_policy_for(&bearer).await?;
        }
        let policy = policy.ok_or(TransportError::SessionExpired)?;
        if !policy.is_legacy() {
            return Err(TransportError::DirectUpload(
                "Current actor requires direct upload; legacy bytes were not sent",
            ));
        }
        Ok((bearer, Some(policy), refreshed))
    }

    fn dispatch_legacy_with<'a, T>(
        &self,
        policy: Option<&crate::direct_upload_model::InitialUploadPolicy>,
        bearer: &'a str,
        send: impl FnOnce(&'a str) -> T,
    ) -> Result<T, TransportError> {
        match policy {
            Some(policy) => policy
                .dispatch_with(
                    bearer,
                    &browser_origin()?,
                    direct_browser_now().map_err(|_| TransportError::SessionExpired)?,
                    true,
                    send,
                )
                .map_err(|_| TransportError::SessionExpired),
            None if !self.require_legacy_upload_policy => Ok(send(bearer)),
            None => Err(TransportError::SessionExpired),
        }
    }

    /// Invokes a closed, byte-bounded direct upload control without raw error data.
    ///
    /// # Errors
    /// Returns an error for an invalid method, oversized control, failed session
    /// refresh, non-success status or malformed bounded response.
    pub(crate) async fn call_direct<Q: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        request: &Q,
    ) -> Result<R, TransportError> {
        self.call_direct_bound(path, request, None).await
    }

    /// Preserves the authenticated actor when refreshing a direct control request.
    ///
    /// # Errors
    /// Returns an error if refresh changes actor/owner, discovery expires or any
    /// bounded request or response is invalid.
    pub(crate) async fn call_direct_for_actor<Q: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        request: &Q,
        deployment: &str,
        principal: &str,
        target: &aos_proto_types::direct_upload::DirectCapabilitiesTarget,
    ) -> Result<R, TransportError> {
        self.call_direct_bound(path, request, Some((deployment, principal, target)))
            .await
    }

    async fn call_direct_bound<Q: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        request: &Q,
        actor: Option<(
            &str,
            &str,
            &aos_proto_types::direct_upload::DirectCapabilitiesTarget,
        )>,
    ) -> Result<R, TransportError> {
        use aos_proto_types::direct_upload::{decode_direct_control, encode_direct_control};
        if !is_generated_connect_path(path) || !path.starts_with("/aos.hub.v1.DirectUploadService/")
        {
            return Err(TransportError::InvalidPath);
        }
        let body = encode_direct_control(request).map_err(|_| {
            TransportError::DirectUpload("The upload control exceeds its byte limit")
        })?;
        // Snapshot ONCE. Other ApiClient clones may refresh their shared session
        // during proof I/O; they cannot change the bearer used by this request.
        let mut bearer = self.session_guard().access_token.clone();
        let mut result = self
            .send_direct_as_actor(path, &bearer, &body, actor)
            .await?;
        if result.is_none() || result.as_ref().is_some_and(|(status, _)| *status == 401) {
            let refreshed = exchange_browser_session(&self.csrf, &current_browser_route())
                .await
                .map_err(|_| TransportError::SessionExpired)?;
            bearer = refreshed.access_token.clone();
            *self.session_guard() = refreshed;
            // Even an unchanged JWT must reprove the policy after an actual401.
            *self
                .direct_actor_proof
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
            result = self
                .send_direct_as_actor(path, &bearer, &body, actor)
                .await?;
        }
        let (status, response) = result.ok_or(TransportError::SessionExpired)?;
        if status == 401 {
            return Err(TransportError::SessionExpired);
        }
        if !(200..300).contains(&status) {
            return Err(TransportError::Http {
                status,
                detail: "Direct upload control was refused; original progress was preserved".into(),
            });
        }
        decode_direct_control(&response).map_err(|_| {
            TransportError::DirectUpload("The Hub returned invalid direct upload metadata")
        })
    }

    async fn send_direct_as_actor(
        &self,
        path: &str,
        bearer: &str,
        body: &[u8],
        actor: Option<(
            &str,
            &str,
            &aos_proto_types::direct_upload::DirectCapabilitiesTarget,
        )>,
    ) -> Result<Option<(u16, Vec<u8>)>, TransportError> {
        let Some((deployment, principal, target)) = actor else {
            // Unscoped calls are discovery only, never a mutation escape hatch.
            if path != aos_proto_types::DIRECT_UPLOAD_SERVICE_GET_CAPABILITIES_PATH {
                return Err(TransportError::InvalidPath);
            }
            return send_direct_connect(path, bearer, body).await.map(Some);
        };
        let Some(proof) = self
            .actor_proof_for(bearer, deployment, principal, target)
            .await?
        else {
            // Only an actual401 may invoke the single legitimate refresh budget.
            return Ok(None);
        };
        if let Some(original) = &self.direct_capabilities {
            proof.validate_capabilities(original).map_err(|_| {
                TransportError::DirectUpload(
                    "The original direct upload policy changed during renewal",
                )
            })?;
        }
        let send = proof
            .dispatch_with(
                bearer,
                deployment,
                principal,
                target,
                direct_browser_now().map_err(|_| TransportError::SessionExpired)?,
                |proven| send_direct_connect(path, proven, body),
            )
            .map_err(|_| TransportError::SessionExpired)?;
        send.await.map(Some)
    }

    async fn actor_proof_for(
        &self,
        bearer: &str,
        deployment: &str,
        principal: &str,
        target: &aos_proto_types::direct_upload::DirectCapabilitiesTarget,
    ) -> Result<Option<crate::direct_upload_model::DirectActorProof>, TransportError> {
        use aos_proto_types::direct_upload::{
            decode_direct_control, encode_direct_control, DirectGetCapabilities,
            DirectUploadCapabilities,
        };
        let now = direct_browser_now().map_err(|_| TransportError::SessionExpired)?;
        let cached = self
            .direct_actor_proof
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(proof) =
            cached.filter(|proof| proof.matches(bearer, deployment, principal, target, now))
        {
            return Ok(Some(proof));
        }
        let discovery = encode_direct_control(&DirectGetCapabilities {
            target: target.clone(),
        })
        .map_err(|_| TransportError::InvalidPath)?;
        let (code, bytes) = send_direct_connect(
            aos_proto_types::DIRECT_UPLOAD_SERVICE_GET_CAPABILITIES_PATH,
            bearer,
            &discovery,
        )
        .await?;
        if code == 401 {
            return Ok(None);
        }
        if code != 200 {
            return Err(TransportError::SessionExpired);
        }
        let capabilities: DirectUploadCapabilities =
            decode_direct_control(&bytes).map_err(|_| TransportError::SessionExpired)?;
        let proof = crate::direct_upload_model::DirectActorProof::from_authenticated(
            bearer,
            deployment,
            principal,
            target,
            &capabilities,
            direct_browser_now().map_err(|_| TransportError::SessionExpired)?,
        )
        .map_err(|_| TransportError::SessionExpired)?;
        *self
            .direct_actor_proof
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(proof.clone());
        Ok(Some(proof))
    }

    /// Sends exact delegated bytes without inheriting application credentials.
    ///
    /// The browser supplies Content-Length from the bounded Blob; JavaScript
    /// cannot set that forbidden header. Actual provider acceptance and CORS
    /// exposure of ETag remain deployment qualification requirements.
    ///
    /// # Errors
    /// Returns an error for changed origin/placement/length, unsupported headers,
    /// redirect or transport failure, refusal, or a missing/invalid exposed ETag.
    pub(crate) async fn put_direct_part(
        &self,
        grant: &aos_proto_types::direct_upload::DirectPartGrant,
        profile: &aos_proto_types::direct_upload::DirectProviderProfile,
        body: &web_sys::Blob,
        retained: &crate::direct_upload_model::PartDispatchContext,
    ) -> Result<String, TransportError> {
        use aos_proto_types::direct_upload::valid_direct_etag;
        use wasm_bindgen::JsCast as _;
        use wasm_bindgen_futures::JsFuture;
        profile.validate_placement(&grant.placement).map_err(|_| {
            TransportError::DirectUpload("The provider grant changed the original destination")
        })?;
        let url = url::Url::parse(&grant.url)
            .map_err(|_| TransportError::DirectUpload("The provider grant URL is invalid"))?;
        if url.scheme() != "https"
            || url.origin().ascii_serialization() != profile.provider_origin
            || body.size() != grant.part.byte_size.get() as f64
        {
            return Err(TransportError::DirectUpload(
                "The provider grant changed its origin or byte length",
            ));
        }
        let init = web_sys::RequestInit::new();
        init.set_method("PUT");
        init.set_body(body.as_ref());
        init.set_credentials(web_sys::RequestCredentials::Omit);
        init.set_redirect(web_sys::RequestRedirect::Error);
        init.set_mode(web_sys::RequestMode::Cors);
        let request = web_sys::Request::new_with_str_and_init(&grant.url, &init).map_err(|_| {
            TransportError::DirectUpload(
                "The browser could not construct the delegated part request",
            )
        })?;
        for header in &grant.required_headers {
            match header.name.as_str() {
                "content-length" if header.value == grant.part.byte_size.get().to_string() => {}
                "content-md5" | "x-amz-checksum-sha256" => request
                    .headers()
                    .set(&header.name, &header.value)
                    .map_err(|_| {
                        TransportError::DirectUpload(
                            "The browser could not set the delegated checksum",
                        )
                    })?,
                _ => {
                    return Err(TransportError::DirectUpload(
                        "The provider grant contains unsupported browser headers",
                    ))
                }
            }
        }
        let window = web_sys::window().ok_or(TransportError::DirectUpload(
            "The browser fetch runtime is unavailable",
        ))?;
        // Source rehash and the concurrency queue have already awaited. This
        // exact retained-tuple and current-clock gate is adjacent to Fetch with
        // no await between the final scalar observation and actual dispatch.
        let fetch = retained
            .dispatch_with(grant, direct_browser_now, || {
                window.fetch_with_request(&request)
            })
            .map_err(|_| {
                TransportError::DirectUpload(
                    "The original provider grant is invalid or expired before dispatch",
                )
            })?;
        let response = JsFuture::from(fetch)
            .await
            .map_err(|_| TransportError::DirectPartUnknown)?
            .dyn_into::<web_sys::Response>()
            .map_err(|_| TransportError::DirectUpload("The provider reply was invalid"))?;
        if !(200..300).contains(&response.status()) {
            return Err(TransportError::Http {
                status: response.status(),
                detail: "The delegated provider upload was refused".into(),
            });
        }
        let etag = response
            .headers()
            .get("etag")
            .map_err(|_| TransportError::DirectUpload("The provider ETag could not be read"))?
            .ok_or(TransportError::DirectUpload(
                "The provider omitted a CORS-readable ETag; resume preserves the original part",
            ))?;
        if !valid_direct_etag(&etag) {
            return Err(TransportError::DirectUpload(
                "The provider returned an invalid part ETag",
            ));
        }
        Ok(etag)
    }

    /// Constructs a client around one synthetic session for pure UI tests.
    #[cfg(test)]
    pub(crate) fn for_test(session: aos_proto_types::BrowserSessionTokenResponse) -> Self {
        Self {
            csrf: "test-csrf".to_string(),
            session: Arc::new(Mutex::new(session)),
            direct_actor_proof: Arc::new(Mutex::new(None)),
            direct_capabilities: None,
            upload_policy: Arc::new(Mutex::new(None)),
            require_legacy_upload_policy: false,
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
            direct_actor_proof: Arc::new(Mutex::new(None)),
            direct_capabilities: None,
            upload_policy: Arc::new(Mutex::new(None)),
            require_legacy_upload_policy: false,
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
        let (bearer, policy, refreshed) = self.legacy_upload_snapshot(true).await?;
        let send = self.dispatch_legacy_with(policy.as_ref(), &bearer, |proven| {
            send_connect(path, proven, &request_body)
        })?;
        let (mut status, mut response_body) = send.await?;
        if status == 401 && !refreshed {
            let refreshed = exchange_browser_session(&self.csrf, &current_browser_route()).await?;
            *self.session_guard() = refreshed;
            let (bearer, policy, _) = self.legacy_upload_snapshot(false).await?;
            let send = self.dispatch_legacy_with(policy.as_ref(), &bearer, |proven| {
                send_connect(path, proven, &request_body)
            })?;
            (status, response_body) = send.await?;
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
        let (bearer, policy, refreshed) = self.legacy_upload_snapshot(true).await?;
        let send = self.dispatch_legacy_with(policy.as_ref(), &bearer, |proven| {
            send_cache_upload(upload_url, same_origin.then_some(proven), body)
        })?;
        let (mut status, mut response) = send.await?;
        if same_origin && status == 401 && !refreshed {
            let refreshed = exchange_browser_session(&self.csrf, &current_browser_route()).await?;
            *self.session_guard() = refreshed;
            let (bearer, policy, _) = self.legacy_upload_snapshot(false).await?;
            let send = self.dispatch_legacy_with(policy.as_ref(), &bearer, |proven| {
                send_cache_upload(upload_url, Some(proven), body)
            })?;
            (status, response) = send.await?;
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

fn browser_origin() -> Result<String, TransportError> {
    leptos::web_sys::window()
        .and_then(|window| window.location().origin().ok())
        .filter(|origin| !origin.is_empty())
        .ok_or(TransportError::SessionExpired)
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

async fn send_direct_connect(
    path: &str,
    bearer: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), TransportError> {
    use wasm_bindgen::JsCast as _;
    use wasm_bindgen_futures::JsFuture;
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    init.set_credentials(web_sys::RequestCredentials::SameOrigin);
    init.set_redirect(web_sys::RequestRedirect::Error);
    init.set_mode(web_sys::RequestMode::SameOrigin);
    let bytes = js_sys::Uint8Array::from(body);
    init.set_body(bytes.as_ref());
    let request = web_sys::Request::new_with_str_and_init(path, &init).map_err(|_| {
        TransportError::DirectUpload("The browser could not construct the upload control")
    })?;
    for (name, value) in [
        ("authorization", format!("Bearer {bearer}")),
        ("content-type", "application/json".into()),
        ("accept", "application/json".into()),
        (
            aos_proto_types::CONNECT_PROTOCOL_VERSION_HEADER,
            aos_proto_types::CONNECT_PROTOCOL_VERSION.into(),
        ),
    ] {
        request.headers().set(name, &value).map_err(|_| {
            TransportError::DirectUpload("The browser could not construct the upload control")
        })?;
    }
    let response = JsFuture::from(
        web_sys::window()
            .ok_or(TransportError::DirectUpload(
                "The browser fetch runtime is unavailable",
            ))?
            .fetch_with_request(&request),
    )
    .await
    .map_err(|_| {
        TransportError::DirectUpload(
            "The upload control reply was not observed; original progress was preserved",
        )
    })?
    .dyn_into::<web_sys::Response>()
    .map_err(|_| TransportError::DirectUpload("The upload control response was invalid"))?;
    let status = response.status();
    let stream = response.body().ok_or(TransportError::DirectUpload(
        "The upload control response omitted its bounded body",
    ))?;
    let reader = stream
        .get_reader()
        .dyn_into::<web_sys::ReadableStreamDefaultReader>()
        .map_err(|_| {
            TransportError::DirectUpload("The browser could not read the upload control")
        })?;
    let mut reader = DirectResponseReader {
        reader,
        complete: false,
    };
    let mut output = Vec::new();
    loop {
        let result = JsFuture::from(reader.reader.read()).await.map_err(|_| {
            TransportError::DirectUpload("The upload control response could not be read")
        })?;
        if js_sys::Reflect::get(&result, &"done".into())
            .ok()
            .and_then(|value| value.as_bool())
            == Some(true)
        {
            break;
        }
        let value = js_sys::Reflect::get(&result, &"value".into())
            .map_err(|_| TransportError::DirectUpload("The upload control response was invalid"))?;
        if !value.is_instance_of::<js_sys::Uint8Array>() {
            let _ = reader.reader.cancel();
            return Err(TransportError::DirectUpload(
                "The upload control response was invalid",
            ));
        }
        // Convert the existing view without copying an attacker-sized chunk
        // before its declared length has passed the aggregate byte bound.
        let chunk: js_sys::Uint8Array = value.unchecked_into();
        if output
            .len()
            .checked_add(chunk.length() as usize)
            .is_none_or(|size| size > aos_proto_types::direct_upload::MAX_DIRECT_CONTROL_BYTES)
        {
            let _ = reader.reader.cancel();
            return Err(TransportError::DirectUpload(
                "The upload control response exceeds its byte limit",
            ));
        }
        output.extend(chunk.to_vec());
    }
    reader.complete = true;
    Ok((status, output))
}

struct DirectResponseReader {
    reader: web_sys::ReadableStreamDefaultReader,
    complete: bool,
}

impl Drop for DirectResponseReader {
    fn drop(&mut self) {
        if !self.complete {
            let _ = self.reader.cancel();
        }
        self.reader.release_lock();
    }
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
    /// No response was observed for a content-bound delegated UploadPart.
    #[error("The provider reply was not observed; original upload progress was preserved")]
    DirectPartUnknown,
    /// Value-free failure of the direct upload transport boundary.
    #[error("{0}")]
    DirectUpload(&'static str),
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

/// Returns a local capability preflight time without asserting server qualification.
///
/// # Errors
/// Returns an error if the browser clock is nonfinite or outside its integer bound.
pub(crate) fn direct_browser_now() -> Result<u64, String> {
    let seconds = (js_sys::Date::now() / 1000.0).floor();
    if !seconds.is_finite() || seconds < 0.0 || seconds > u64::MAX as f64 {
        return Err("The browser clock cannot validate an upload capability".into());
    }
    // This is a local client preflight, never a server clock qualification or
    // provider settlement assertion. The provider separately enforces expiry.
    Ok(seconds as u64)
}
