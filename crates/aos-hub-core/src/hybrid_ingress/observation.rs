//! Request-scoped hashes of checks performed by the existing Hybrid handlers.
//!
//! The scope stores no credentials or object bodies, performs no authorization,
//! and returns no verified proof. A checked context describes its actual check
//! point; independent transport, process, current-state and purpose evidence is
//! still required. Calls outside the explicit Native request scope do nothing.

#[cfg(not(target_arch = "wasm32"))]
use std::cell::RefCell;
use std::future::Future;
#[cfg(not(target_arch = "wasm32"))]
use std::io;
use std::sync::OnceLock;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest as _, Sha256};

#[cfg(not(target_arch = "wasm32"))]
const MAX_CHECKS: usize = 32;
#[cfg(not(target_arch = "wasm32"))]
const MAX_CONTEXT_BYTES: usize = 128 * 1024;

/// Returns the compiled observation module's source commitment.
///
/// This hash binds its format to the selected source-built executable; it is
/// not a commitment to the whole application or an authorization signature.
#[must_use]
pub fn observation_source_sha256() -> &'static str {
    static SOURCE: OnceLock<String> = OnceLock::new();
    SOURCE.get_or_init(|| hex::encode(Sha256::digest(include_bytes!("observation.rs"))))
}

#[cfg(not(target_arch = "wasm32"))]
tokio::task_local! {
    static REQUEST_CHECKS: RefCell<IngressCheckedContexts>;
}

/// Reports the bounded checks observed during one actual handler invocation.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngressCheckedContexts {
    /// Exact observed check points, in their actual invocation order.
    pub checks: Vec<IngressCheckedContext>,
    /// Indicates that an observation exceeded its bound or could not be hashed.
    pub incomplete: bool,
}

/// Commits to one already-checked context without exposing its private values.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngressCheckedContext {
    /// Names the existing check, without claiming another permission or purpose.
    pub kind: &'static str,
    /// Actual outcome of the named existing check, including a real refusal.
    pub accepted: bool,
    /// SHA-256 of the exact deterministic checked-context projection.
    pub checked_context_sha256: String,
    /// Actual observation time, separate from credential or artifact cutoffs.
    pub observed_at_unix_micros: String,
}

/// Runs a handler with a bounded, task-local observational collector.
///
/// Cancellation drops this scope without manufacturing a completed context.
/// Nested scopes are independent, and asynchronous work spawned into another
/// task does not inherit the collector. This function changes no permissions.
#[cfg(not(target_arch = "wasm32"))]
pub async fn observe_handler<F: Future>(handler: F) -> (F::Output, IngressCheckedContexts) {
    REQUEST_CHECKS
        .scope(RefCell::new(IngressCheckedContexts::default()), async {
            let output = handler.await;
            let contexts = REQUEST_CHECKS.with(|value| value.borrow().clone());
            (output, contexts)
        })
        .await
}

/// Runs the existing handler without collecting Native observations on Wasm.
///
/// Worker business checks still run unchanged. The returned collection is
/// explicitly incomplete because this target has no Native request collector.
#[cfg(target_arch = "wasm32")]
pub async fn observe_handler<F: Future>(handler: F) -> (F::Output, IngressCheckedContexts) {
    let output = handler.await;
    (
        output,
        IngressCheckedContexts {
            checks: Vec::new(),
            incomplete: true,
        },
    )
}

/// Records a hash only after the caller's existing check has succeeded.
///
/// The caller supplies the actual checked values, never a bearer credential or
/// provider key. This observational function grants no execution authority and
/// cannot substitute for a check. A serialization, clock or bound failure marks
/// the collection incomplete without changing the handler's result.
pub fn record_existing_check(kind: &'static str, context: &impl Serialize) {
    record_existing_outcome(kind, true, context);
}

/// Records the actual result of an existing visibility or authorization gate.
///
/// A refused gate stays refused. This function performs no check itself and
/// does not make an unavailable or unobserved gate successful.
#[cfg(not(target_arch = "wasm32"))]
pub fn record_existing_outcome(kind: &'static str, accepted: bool, context: &impl Serialize) {
    let _ = REQUEST_CHECKS.try_with(|value| {
        if value.borrow().incomplete {
            return;
        }
        let known = matches!(
            kind,
            "permission_read"
                | "permission_publish"
                | "oci_actor_current"
                | "oci_manifest_catalog_current"
                | "oci_chunk_catalog_current"
                | "oci_public_pull_policy"
                | "oci_repository_grant"
                | "registry_public_read_policy"
                | "cache_public_read_policy"
                | "registry_session_read"
                | "cache_session_read"
                | "browse_registry_read_policy"
                | "browse_session_read"
        );
        let mut hash = BoundedContextHash::default();
        let hashed = serde_json::to_writer(&mut hash, context);
        let now = SystemTime::now().duration_since(UNIX_EPOCH);
        // Do not hold a mutable task-local borrow while invoking a serializer.
        // The collector only appends the completed bounded hash afterwards.
        let mut observations = value.borrow_mut();
        match (known, hashed, now) {
            (true, Ok(()), Ok(now)) if observations.checks.len() < MAX_CHECKS => {
                observations.checks.push(IngressCheckedContext {
                    kind,
                    accepted,
                    checked_context_sha256: hex::encode(hash.digest.finalize()),
                    observed_at_unix_micros: now.as_micros().to_string(),
                });
            }
            _ => observations.incomplete = true,
        }
    });
}

/// Leaves already-performed Worker checks unchanged without collecting hashes.
///
/// Wasm does not have the Native Tokio request scope. This no-op neither
/// serializes the supplied context nor creates an accepted observation.
#[cfg(target_arch = "wasm32")]
pub fn record_existing_outcome(_kind: &'static str, _accepted: bool, _context: &impl Serialize) {}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Default)]
struct BoundedContextHash {
    digest: Sha256,
    bytes: usize,
}

#[cfg(not(target_arch = "wasm32"))]
impl io::Write for BoundedContextHash {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .bytes
            .checked_add(bytes.len())
            .filter(|length| *length <= MAX_CONTEXT_BYTES)
            .ok_or_else(|| io::Error::other("observed checked context exceeds its bound"))?;
        self.digest.update(bytes);
        self.bytes = length;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Borrows the existing ordered grants without cloning or exposing raw rows.
pub(crate) fn grant_projection(
    grants: &[(crate::domain::Scope, crate::domain::Role)],
) -> impl Serialize + '_ {
    GrantProjection(grants)
}

struct GrantProjection<'a>(&'a [(crate::domain::Scope, crate::domain::Role)]);

impl Serialize for GrantProjection<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq as _;

        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (scope, role) in self.0 {
            sequence.serialize_element(&(scope.as_str(), role.as_str()))?;
        }
        sequence.end()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
