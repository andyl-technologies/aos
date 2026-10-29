//! Bounded do-e2e-only inspection of one physical guard's retained GC state.
//!
//! The existing full-key header and guard identity are checked by the caller.
//! The selected capture and prefix restrict this read-only fixture endpoint;
//! they grant no signing, provider, claim, drain or dispatch authority.
//!
//! The closed request names explicit retained claim keys:
//!
//! ```json
//! {"version":1,"capture_id":"32-lowercase-hex-capture-id","claim_ids":["actual-SQL-action-id"]}
//! ```

use std::collections::BTreeSet;

use anyhow::{ensure, Result};
use serde::Deserialize;

use super::Configuration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inspection {
    version: u32,
    capture_id: String,
    claim_ids: Vec<String>,
}

impl Inspection {
    fn decode(body: &[u8], selected: &Configuration, key: &str) -> Result<Self> {
        ensure!(body.len() <= 8_192, "guard inspection exceeds its bound");
        let request: Self = serde_json::from_slice(body)?;
        ensure!(
            request.version == 1
                && request.capture_id == selected.capture_id
                && selected.accepts(key, "guard-inspection", &request.capture_id),
            "guard inspection is outside its selected capture"
        );
        ensure!(
            !request.claim_ids.is_empty()
                && request.claim_ids.len() <= 32
                && request.claim_ids.iter().all(|id| {
                    !id.is_empty()
                        && id.len() <= 128
                        && id.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'-' | b'_' | b'.' | b':')
                        })
                })
                && request.claim_ids.iter().collect::<BTreeSet<_>>().len()
                    == request.claim_ids.len(),
            "guard inspection requires bounded unique exact claim IDs"
        );
        Ok(request)
    }
}

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
/// Reads explicit retained GC receipts and pending fences without effects.
///
/// # Errors
/// Returns an error when the bounded request, existing storage or response
/// cannot be read. Refuses an unselected capture or mismatched receipt.
pub(crate) async fn fetch(
    guard: &crate::hybrid_object::HybridObjectGuard,
    key: &str,
    request: &mut worker::Request,
) -> worker::Result<worker::Response> {
    use crate::hybrid_object_state::{DeleteClaim, DeleteReceipt, Mutation};
    use std::collections::BTreeMap;

    if request.method() != worker::Method::Post {
        return worker::Response::error("guard inspection requires POST", 405);
    }
    let Some(selected) = guard
        .env
        .var("HUB_MANAGED_GC_SDK_OBSERVER")
        .ok()
        .map(|value| value.to_string())
        .filter(|body| body.len() <= 4_096)
        .and_then(|body| serde_json::from_str::<Configuration>(&body).ok())
    else {
        return worker::Response::error("guard inspection is not selected", 404);
    };
    let Some(body) = crate::hybrid::read_bounded_body(request, 8_192).await? else {
        return worker::Response::error("guard inspection exceeds its bound", 413);
    };
    let inspected = match Inspection::decode(&body, &selected, key) {
        Ok(request) => request,
        Err(_) => return worker::Response::error("guard inspection does not match selection", 400),
    };

    // The caller holds the same physical-key gate. These reads do not clear
    // unknown state or replay a positive as provider mutation authority.
    let storage = guard.state.storage();
    let mut receipts = BTreeMap::new();
    for id in inspected.claim_ids {
        let receipt = storage
            .get::<DeleteReceipt>(&format!("delete-receipt:{id}"))
            .await?;
        if receipt
            .as_ref()
            .is_some_and(|receipt| receipt.claim.claim_id != id)
        {
            return worker::Response::error("retained guard receipt differs", 409);
        }
        receipts.insert(id, receipt);
    }
    let pending_delete = storage.get::<DeleteClaim>("pending-delete").await?;
    let pending_mutation = storage.get::<Mutation>("pending-mutation").await?;
    let result = serde_json::json!({
        "version":1, "captureId":inspected.capture_id, "key":key,
        "guardName":crate::hybrid_object::guard_name(&guard.env, key)?,
        "deleteReceipts":receipts, "pendingDelete":pending_delete,
        "pendingMutation":pending_mutation,
    });
    let body = serde_json::to_string(&result)
        .map_err(|error| worker::Error::RustError(error.to_string()))?;
    if body.len() > 128 * 1024 {
        return worker::Response::error("retained guard state exceeds inspection bound", 413);
    }
    worker::Response::from_json(&result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspection_requires_selected_exact_capture_key_and_bounded_claims() {
        let selected = Configuration {
            version: 1,
            capture_id: "a".repeat(32),
            prefix: "controlled/gc".into(),
        };
        let encode = |capture: String, ids: Vec<String>| {
            serde_json::to_vec(&serde_json::json!({
                "version":1,"capture_id":capture,"claim_ids":ids,
            }))
            .unwrap()
        };
        let accepted = encode(selected.capture_id.clone(), vec!["actual-action".into()]);
        assert!(Inspection::decode(&accepted, &selected, "controlled/gc/object").is_ok());
        assert!(Inspection::decode(&accepted, &selected, "other/object").is_err());
        assert!(Inspection::decode(
            &encode("b".repeat(32), vec!["actual-action".into()]),
            &selected,
            "controlled/gc/object"
        )
        .is_err());
        for ids in [
            vec![],
            vec!["same".into(), "same".into()],
            vec!["../other".into()],
            (0..33).map(|n| format!("claim-{n}")).collect(),
        ] {
            assert!(Inspection::decode(
                &encode(selected.capture_id.clone(), ids),
                &selected,
                "controlled/gc/object"
            )
            .is_err());
        }
        assert!(Inspection::decode(&vec![b' '; 8_193], &selected, "controlled/gc/object").is_err());
    }
}
