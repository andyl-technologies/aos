//! Closed callback effects through a connect-time public-address gateway.
//!
//! Worker Fetch cannot pin resolved public addresses, so callbacks always use
//! the independently authenticated gateway profile. Response bodies are discarded.

use std::time::Duration;

use anyhow::{ensure, Context as _, Result};
use aos_assessment::time::Timestamp;
use aos_assessment_runtime::notifications::{
    CallbackSignature, NotificationDestinationV1, NotificationEffectGrantV1,
    NotificationEffectQueryV1, NotificationWorkPlanV1,
};
use aos_hub_core::egress_protocol::{self, notifications as protocol};
use base64::Engine as _;
use futures_util::future::{select, Either};
use futures_util::pin_mut;
use rand::Rng as _;
use worker::{Fetch, Headers, Method, Request, RequestInit, RequestRedirect};

use super::{require_fresh_gateway_timestamp, WorkerEgressClient, WorkerEgressTransport};

impl WorkerEgressClient {
    /// Sends one exact callback while enforcing fresh current-effect confirmation.
    ///
    /// The gateway pins DNS and performs a 15-second HTTP attempt. This outer
    /// invocation aborts after 20 seconds; uncertain outcomes retain their quota.
    ///
    /// # Errors
    /// Returns an error for direct transport, stale authority, altered pinned
    /// bytes or unauthenticated gateway response facts.
    pub(crate) async fn send_notification(
        &self,
        destination: &NotificationDestinationV1,
        plan: &NotificationWorkPlanV1,
        body: &[u8],
        signature: &CallbackSignature,
        query: &NotificationEffectQueryV1,
        grant: &NotificationEffectGrantV1,
    ) -> Result<(Option<u16>, Option<u32>)> {
        let WorkerEgressTransport::Gateway {
            gateway_url,
            key_id,
            key,
        } = &self.transport
        else {
            anyhow::bail!("notification callbacks require connect-time public-address egress");
        };
        let timestamp = aos_hub_core::clock::now_unix_secs();
        let now = Timestamp::from_unix_seconds(u64::try_from(timestamp)?)?;
        grant.validate_for(query, plan, &now)?;
        plan.require_destination(destination)?;
        ensure!(
            plan.body.to_bytes()? == body
                && signature.timestamp == plan.issued_at
                && signature.key_version == destination.secret_version_reference,
            "notification egress differs from the pinned callback"
        );
        let mut random = [0_u8; 32];
        rand::rng().fill(&mut random);
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
        let body_digest = egress_protocol::body_sha256(body);
        let callback_signature = format!("sha256={}", signature.signature);
        let callback_timestamp = signature.timestamp.to_string();
        let evidence = protocol::NotificationRequestEvidence {
            request: egress_protocol::RequestEvidence {
                timestamp,
                nonce: &nonce,
                target_url: &destination.url,
                method: "POST",
                body_sha256: &body_digest,
                content_type: Some("application/json"),
                range: None,
                if_match: None,
                authorization: None,
                webhook_event: Some("assessment.notification"),
                webhook_signature: Some(&callback_signature),
                webhook_delivery_id: Some(&plan.body.delivery_id),
            },
            signature_version: &signature.version,
            key_version: &signature.key_version,
            callback_timestamp: &callback_timestamp,
            deadline: plan.deadline.unix_seconds(),
            effect_checked_at: grant.checked_at.unix_seconds(),
            effect_dispatch_by: grant.dispatch_by.unix_seconds(),
        };
        let mac = protocol::sign_request(key, &evidence)?;
        let headers = Headers::new();
        for (name, value) in [
            ("x-aos-egress-contract", protocol::CONTRACT),
            ("x-aos-egress-key-id", key_id.as_str()),
            ("x-aos-egress-nonce", nonce.as_str()),
            ("x-aos-egress-target-url", destination.url.as_str()),
            ("x-aos-egress-upstream-method", "POST"),
            ("x-aos-egress-body-sha256", body_digest.as_str()),
            ("x-aos-egress-signature", mac.as_str()),
            ("x-aos-egress-upstream-content-type", "application/json"),
            (
                "x-aos-egress-upstream-webhook-event",
                "assessment.notification",
            ),
            (
                "x-aos-egress-upstream-webhook-signature",
                callback_signature.as_str(),
            ),
            (
                "x-aos-egress-upstream-webhook-delivery-id",
                plan.body.delivery_id.as_str(),
            ),
            (
                "x-aos-egress-notification-signature-version",
                signature.version.as_str(),
            ),
            (
                "x-aos-egress-notification-key-version",
                signature.key_version.as_str(),
            ),
            (
                "x-aos-egress-notification-timestamp",
                callback_timestamp.as_str(),
            ),
        ] {
            headers.set(name, value)?;
        }
        for (name, value) in [
            ("x-aos-egress-timestamp", u64::try_from(timestamp)?),
            ("x-aos-egress-notification-deadline", evidence.deadline),
            (
                "x-aos-egress-notification-effect-checked-at",
                evidence.effect_checked_at,
            ),
            (
                "x-aos-egress-notification-effect-dispatch-by",
                evidence.effect_dispatch_by,
            ),
        ] {
            headers.set(name, &value.to_string())?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_redirect(RequestRedirect::Manual)
            .with_headers(headers)
            .with_body(Some(js_sys::Uint8Array::from(body).into()));
        let request = Request::new_with_init(gateway_url, &init)?;
        let abort = AbortOnDrop(
            worker::web_sys::AbortController::new()
                .map_err(|_| anyhow::anyhow!("notification cancellation owner is unavailable"))?,
        );
        let signal = worker::AbortSignal::from(abort.0.signal());
        // Construction may yield no I/O, but authority is checked again at the
        // dispatch boundary rather than relying on the earlier key lookup.
        let now =
            Timestamp::from_unix_seconds(u64::try_from(aos_hub_core::clock::now_unix_secs())?)?;
        grant.validate_for(query, plan, &now)?;
        let dispatch = Fetch::Request(request);
        let fetch = dispatch.send_with_signal(&signal);
        let timeout = worker::Delay::from(Duration::from_secs(20));
        pin_mut!(fetch, timeout);
        let response = match select(fetch, timeout).await {
            Either::Left((Ok(response), _)) => response,
            Either::Left((Err(_), _)) | Either::Right(_) => return Ok((None, None)),
        };
        let required = |name: &str| -> Result<String> {
            response
                .headers()
                .get(name)?
                .context("notification gateway fact is absent")
        };
        ensure!(
            required("x-aos-egress-contract")? == protocol::CONTRACT
                && required("x-aos-egress-key-id")? == *key_id
                && required("x-aos-egress-nonce")? == nonce,
            "notification gateway response pairing differs"
        );
        let timestamp = required("x-aos-egress-timestamp")?.parse()?;
        require_fresh_gateway_timestamp(timestamp, aos_hub_core::clock::now_unix_secs())?;
        let final_url = required("x-aos-egress-final-url")?;
        ensure!(
            url::Url::parse(&final_url)? == url::Url::parse(&destination.url)?,
            "notification gateway changed the registered destination"
        );
        let peer_ip = required("x-aos-egress-peer-ip")?;
        ensure!(
            aos_hub_core::url_guard::is_global_ip(peer_ip.parse()?),
            "notification gateway connected to a non-public address"
        );
        let status = required("x-aos-egress-upstream-status")?.parse()?;
        ensure!(
            status == response.status_code(),
            "notification gateway status differs"
        );
        let retry_after_seconds = response
            .headers()
            .get("x-aos-egress-notification-retry-after")?
            .map(|value| value.parse::<u32>())
            .transpose()?;
        protocol::verify_response(
            key,
            &protocol::NotificationResponseEvidence {
                response: egress_protocol::ResponseEvidence {
                    timestamp,
                    nonce: &nonce,
                    final_url: &final_url,
                    peer_ip: &peer_ip,
                    status,
                },
                retry_after_seconds,
            },
            &required("x-aos-egress-signature")?,
        )?;
        Ok((Some(status), retry_after_seconds))
    }
}

struct AbortOnDrop(worker::web_sys::AbortController);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
