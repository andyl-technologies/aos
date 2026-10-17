//! Opens a bounded private trace without changing admission on observer failure.

use std::rc::Rc;

use aos_hub_core::oci_projection::guard::OciProjectionLookup;
use worker::Env;

use super::{Configuration, Original, Trace};

pub(crate) fn from_env(
    env: &Env,
    lookup: &OciProjectionLookup,
    request_sha256: &str,
) -> Option<Trace> {
    let body = env.var("HUB_OCI_PROFILE_LOAD_OBSERVER").ok()?.to_string();
    if body.len() > 4096 {
        return None;
    }
    let selected: Configuration = serde_json::from_str(&body).ok()?;
    Trace::new(
        selected,
        Original {
            request_sha256: request_sha256.into(),
            document_digest: lookup.descriptor.digest.to_string(),
            nonce: lookup.nonce.clone(),
            key: lookup.key.clone(),
            issued_at: lookup.issued_at,
            expires_at: lookup.expires_at,
            clock_uncertainty_seconds: lookup.clock_uncertainty_seconds,
            source_digest: lookup.issuer.source_digest.clone(),
            script_version: lookup.issuer.script_version.clone(),
            protected_profile_digest: lookup.protected_profile_digest.clone(),
        },
        Rc::new(|body| {
            worker::console_log!("oci_profile_load_observer {}", body);
            true
        }),
    )
}
