//! Optional inventory of the Native remote-storage dispatch owners.
//!
//! This records offers to the existing HTTP client and prefixes exposed by its
//! existing response consumer. It does not observe all Native egress, delivery,
//! provider settlement, authentication, SQL authority or object classification.
//! Missing exported records or an unfinished owner keep the window incomplete.
//!
//! The default-off policy is a bounded, non-authorizing observation selection:
//!
//! ```text
//! {"version":1,"runId":"<64 lowercase hex>","windowId":"<32 lowercase hex>",
//!  "startUnixMillis":"...","endUnixMillis":"..."}
//! native_remote_storage_inventory {"event":"begin|offered|terminal|end", ...}
//! ```

use std::sync::{Arc, OnceLock};

mod guard;
mod policy;
mod window;

pub(crate) use guard::{Image, Observation, Owner};
use window::Window;

static SELECTED: OnceLock<Option<Arc<Window>>> = OnceLock::new();

#[cfg(test)]
tokio::task_local! {
    static TEST_WINDOW: Arc<Window>;
}

fn selected() -> Option<Arc<Window>> {
    #[cfg(test)]
    if let Ok(window) = TEST_WINDOW.try_with(Arc::clone) {
        return Some(window);
    }
    SELECTED.get().and_then(|window| window.as_ref()).cloned()
}

/// Initializes a finite, default-off remote-storage observation window.
///
/// It runs before serving or spawning storage work. No request-time environment
/// lookup or observation-specific request headers are added.
///
/// # Errors
///
/// Returns an error for a malformed, past, oversized or repeated selection.
pub fn initialize() -> anyhow::Result<()> {
    let window = match std::env::var("AOS_NATIVE_OUTBOUND_INVENTORY") {
        Ok(raw) => Some(policy::select(&raw)?),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => anyhow::bail!("outbound observation policy is not UTF-8"),
    };
    anyhow::ensure!(
        SELECTED.set(window.clone()).is_ok(),
        "outbound observation was already initialized"
    );
    if let Some(window) = window {
        let _ = roster_sha256();
        tokio::spawn(async move {
            tokio::time::sleep_until(window.start.into()).await;
            window.begin();
            tokio::time::sleep_until(window.end.into()).await;
            window.close();
        });
    }
    Ok(())
}

// This roster commits the actual compiled hooks, including initialization and
// response-consumption helpers. Operator JSON cannot assert roster completeness.
fn roster_sha256() -> &'static str {
    use sha2::{Digest as _, Sha256};
    static DIGEST: OnceLock<String> = OnceLock::new();
    DIGEST.get_or_init(|| {
        let mut hash = Sha256::new();
        hash.update(b"aos.native.remote-storage-dispatch-roster.v1\0");
        macro_rules! source {
            ($path:literal) => {
                hash.update($path.as_bytes());
                hash.update([0]);
                hash.update(include_bytes!($path));
            };
        }
        source!("outbound_inventory.rs");
        source!("outbound_inventory/policy.rs");
        source!("outbound_inventory/window.rs");
        source!("outbound_inventory/guard.rs");
        source!("lib.rs");
        source!("main.rs");
        source!("storage_work.rs");
        source!("storage_work/frozen_head.rs");
        source!("storage_work/external_observation.rs");
        source!("storage_work/external_delete.rs");
        source!("storage_work/external_copy.rs");
        source!("storage_work/oci_cleanup.rs");
        source!("storage_work/external_oci.rs");
        source!("storage_work/mirror_guard.rs");
        source!("storage_work/binding_custody.rs");
        source!("storage_work/authority.rs");
        source!("storage_work/mirror_guard/batch.rs");
        source!("storage_work/external_oci/cleanup.rs");
        source!("storage_work/oci_projection/exchange.rs");
        source!("direct_upload/authority/transport.rs");
        hex::encode(hash.finalize())
    })
}

#[cfg(test)]
pub(crate) mod tests;
