//! Optional source-encoder commitments carried by Native response extensions.
//!
//! These hashes describe selected production serializers, not authentication or
//! metadata authorization. Original, SQL, source, purpose and capture joins remain
//! independent. Unknown encoders and noncanonical requests carry no evidence.
//! A disabled scope and every Wasm invocation preserve ordinary responses.

use axum::response::Response;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::future::Future;
use std::io::{self, Write};

pub(crate) mod rpc;
pub mod sql_projection;
pub mod publication;

#[derive(Default)]
struct ObservationScope {
    checkpoints: Vec<sql_projection::Checkpoint>,
    constructor: Option<&'static str>,
    invalid: bool,
    publication: Option<publication::Accumulator>,
}

#[cfg(not(target_arch = "wasm32"))]
tokio::task_local! { static ENABLED: std::cell::RefCell<ObservationScope>; }

/// Commits to bytes from one actual source-selected encoder.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncodedImage {
    /// Decimal count of the complete canonical encoding.
    pub byte_size: String,
    /// SHA-256 of that encoding, without retaining its values.
    pub sha256: String,
}

/// Names a selected constructor without asserting independent authentication.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BodyEvidence {
    /// Finite production encoder or constructor selected by the source hook.
    pub constructor: &'static str,
    /// Exact constructor source commitment, distinct from runtime provenance.
    pub constructor_source_sha256: String,
    /// Exact request encoding, or none when the hook does not classify it.
    pub request: Option<EncodedImage>,
    /// Complete produced encoding; actual offered frames must match separately.
    pub reply: EncodedImage,
    /// Independent projection needed before any body-classification conclusion.
    pub required_projection: &'static str,
}

/// Runs one Native handler with optional source-encoder observation enabled.
///
/// The scope grants no permissions and does not propagate into spawned tasks.
pub async fn observe<F: Future>(handler: F) -> F::Output {
    observe_with_sql_projection(handler).await.0
}

/// Runs one handler and retains bounded checkpoints from that same request task.
///
/// The optional data is a private response-extension bridge, not SQL authority.
/// It is absent on Wasm, incomplete observations and unrelated constructors.
/// Spawned tasks do not inherit this scope.
pub async fn observe_with_sql_projection<F: Future>(
    handler: F,
) -> (F::Output, Option<sql_projection::SqlProjection>) {
    let (output, sql, _) = observe_with_publication_phases(handler).await;
    (output, sql)
}

/// Retains independent bounded publication phases, including returned errors.
///
/// The phase summary does not require a successful response constructor. It
/// grants no typed body evidence, SQL authority, visibility or atomicity. Wasm
/// and disabled scopes preserve the ordinary response, with no summary.
pub async fn observe_with_publication_phases<F: Future>(
    handler: F,
) -> (F::Output, Option<sql_projection::SqlProjection>, Option<publication::Summary>) {
    #[cfg(not(target_arch = "wasm32"))]
    {
        ENABLED
            .scope(
                std::cell::RefCell::new(ObservationScope::default()),
                async {
                    let output = handler.await;
                    let projection = ENABLED
                        .try_with(|scope| {
                            let mut scope = scope.try_borrow_mut().ok()?;
                            if scope.invalid {
                                return None;
                            }
                            let constructor = scope.constructor?;
                            sql_projection::SqlProjection::new(
                                std::mem::take(&mut scope.checkpoints),
                                constructor,
                            )
                        })
                        .ok()
                        .flatten();
                    let publication = ENABLED.try_with(|scope| {
                        scope.try_borrow_mut().ok()?.publication.take()?.into_summary()
                    }).ok().flatten();
                    (output, projection, publication)
                },
            )
            .await
    }
    #[cfg(target_arch = "wasm32")]
    {
        (handler.await, None, None)
    }
}

pub(crate) fn confirm_sql_constructor(constructor: &'static str) {
    #[cfg(not(target_arch = "wasm32"))]
    let _ = ENABLED.try_with(|scope| {
        if let Ok(mut scope) = scope.try_borrow_mut() {
            if scope.constructor.is_some_and(|prior| prior != constructor) {
                scope.invalid = true;
            }
            scope.constructor = Some(constructor);
        }
    });
    #[cfg(target_arch = "wasm32")]
    let _ = constructor;
}

pub(crate) fn invalidate_sql_projection() {
    #[cfg(not(target_arch = "wasm32"))]
    let _ = ENABLED.try_with(|scope| {
        if let Ok(mut scope) = scope.try_borrow_mut() {
            scope.invalid = true;
        }
    });
}

pub(crate) fn record_sql_checkpoint(checkpoint: sql_projection::Checkpoint) {
    #[cfg(not(target_arch = "wasm32"))]
    let _ = ENABLED.try_with(|scope| {
        if let Ok(mut scope) = scope.try_borrow_mut() {
            if scope.checkpoints.len() >= sql_projection::MAX_CHECKPOINTS {
                scope.invalid = true;
            } else {
                scope.checkpoints.push(checkpoint);
            }
        }
    });
    #[cfg(target_arch = "wasm32")]
    let _ = checkpoint;
}

/// Reports whether the explicit Native observation scope is present.
#[must_use]
pub fn enabled() -> bool {
    #[cfg(not(target_arch = "wasm32"))]
    {
        ENABLED.try_with(|_| ()).is_ok()
    }
    #[cfg(target_arch = "wasm32")]
    {
        false
    }
}

struct HashWriter {
    digest: Sha256,
    bytes: u64,
    maximum: u64,
}

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|value| *value <= self.maximum)
            .ok_or_else(|| io::Error::other("encoder commitment exceeds bound"))?;
        self.digest.update(bytes);
        self.bytes = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn canonical(value: &impl Serialize, maximum: u64) -> Option<EncodedImage> {
    if !enabled() {
        return None;
    }
    canonical_image(value, maximum)
}

// Validation remains usable outside an emission scope; this helper emits no record.
fn canonical_image(value: &impl Serialize, maximum: u64) -> Option<EncodedImage> {
    let mut writer = HashWriter {
        digest: Sha256::new(),
        bytes: 0,
        maximum,
    };
    serde_json::to_writer(&mut writer, value).ok()?;
    Some(EncodedImage {
        byte_size: writer.bytes.to_string(),
        sha256: hex::encode(writer.digest.finalize()),
    })
}

/// Hashes a produced byte slice without reading or buffering another body.
#[must_use]
pub fn image(bytes: &[u8]) -> EncodedImage {
    EncodedImage {
        byte_size: bytes.len().to_string(),
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

/// Attaches an explicitly selected production constructor's complete byte image.
///
/// Callers provide only already-materialized output, a finite source constructor
/// and its source file. This does not make unconstrained fields into metadata.
pub fn produced(
    response: &mut Response,
    bytes: &[u8],
    constructor: &'static str,
    source: &[u8],
    required_projection: &'static str,
) {
    if let Some(evidence) = produced_evidence(bytes, constructor, source, required_projection) {
        response.extensions_mut().insert(evidence);
    }
}

/// Creates a hash-only bridge for a finite selected production constructor.
///
/// An absent Native scope or output above the existing asset bound yields none.
#[must_use]
pub fn produced_evidence(
    bytes: &[u8],
    constructor: &'static str,
    source: &[u8],
    required_projection: &'static str,
) -> Option<BodyEvidence> {
    if !enabled() || bytes.len() > 64 * 1024 * 1024 {
        return None;
    }
    confirm_sql_constructor(constructor);
    Some(BodyEvidence {
        constructor,
        constructor_source_sha256: hex::encode(Sha256::digest(source)),
        request: None,
        reply: image(bytes),
        required_projection,
    })
}

#[cfg(test)]
mod tests;
