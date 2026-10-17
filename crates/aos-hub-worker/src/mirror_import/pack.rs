//! Storage-local BYOB feeds for a canonical Git pack/index projection.
//!
//! The caller selects and authenticates source identities and holds provider
//! capacity and mirror buffer admission through this call. This adapter opens
//! no transport or authority. It cancels unfinished streams on failure and
//! rechecks the fixed execution deadline and fresh authority across awaits.

#[cfg(target_arch = "wasm32")]
use anyhow::{ensure, Result};
#[cfg(target_arch = "wasm32")]
use aos_registry_surface::pack_index::projection::{AvailablePair, PairReader, Selection};
#[cfg(target_arch = "wasm32")]
use futures_util::future::{select, Either};
#[cfg(target_arch = "wasm32")]
use worker::web_sys::ReadableStream;

/// Verifies an exact upstream pair without retaining the encoded pack.
///
/// The caller retains both source-incarnation and read-capacity scopes. The
/// callback must fail when Native authority, installed profile or source pins
/// change. A 50 ms timer rechecks it even while a BYOB read remains pending.
///
/// # Errors
/// Returns value-free errors for unavailable streams, expired authority or
/// execution, and the pure verifier's semantic and resource-limit refusals.
#[cfg(target_arch = "wasm32")]
pub(crate) async fn verify_pair(
    index_path: &str,
    selections: &[Selection],
    pack: ReadableStream,
    index: ReadableStream,
    execution_deadline: i64,
    before_read: impl Fn() -> Result<()>,
) -> Result<AvailablePair> {
    let verifier = read_pair(index_path, pack, index, execution_deadline, &before_read).await?;
    let verified = verifier.finish_available(selections)?;
    before_read()?;
    check_deadline(now_seconds()?, execution_deadline)?;
    Ok(verified)
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn verify_tree<T>(
    index_path: &str,
    oid: aos_registry_surface::object::Oid,
    pack: ReadableStream,
    index: ReadableStream,
    execution_deadline: i64,
    before_read: impl Fn() -> Result<()>,
    project: impl FnOnce(&[u8]) -> Result<T>,
) -> Result<aos_registry_surface::pack_index::projection::VerifiedTreeProjection<T>> {
    let verifier = read_pair(index_path, pack, index, execution_deadline, &before_read).await?;
    let verified = verifier.finish_tree_projection(oid, project)?;
    before_read()?;
    check_deadline(now_seconds()?, execution_deadline)?;
    Ok(verified)
}

#[cfg(target_arch = "wasm32")]
pub(crate) async fn verify_catalogue(
    index_path: &str,
    pack: ReadableStream,
    index: ReadableStream,
    execution_deadline: i64,
    before_read: impl Fn() -> Result<()>,
) -> Result<aos_registry_surface::pack_index::projection::VerifiedCatalogue> {
    let verifier = read_pair(index_path, pack, index, execution_deadline, &before_read).await?;
    let verified = verifier.finish_catalogue()?;
    before_read()?;
    check_deadline(now_seconds()?, execution_deadline)?;
    Ok(verified)
}

#[cfg(target_arch = "wasm32")]
async fn read_pair(
    index_path: &str,
    pack: ReadableStream,
    index: ReadableStream,
    execution_deadline: i64,
    before_read: &impl Fn() -> Result<()>,
) -> Result<PairReader> {
    // These guards own cancellation even when path validation or opening the
    // second BYOB reader fails before both Readers have assumed ownership.
    let mut pack = UnopenedStream {
        stream: pack,
        opened: false,
    };
    let mut index = UnopenedStream {
        stream: index,
        opened: false,
    };
    let mut verifier = PairReader::new(index_path)?;
    validate_execution(now_seconds()?, execution_deadline)?;
    let pack_reader = pack.open()?;
    let index_reader = index.open()?;

    for (reader, is_pack) in [(&pack_reader, true), (&index_reader, false)] {
        loop {
            let (view, done) = read_checked(reader, execution_deadline, &before_read).await?;
            // Reader enforces the native view bound before this Rust copy.
            let bytes = view.to_vec();
            if is_pack {
                verifier.feed_pack(&bytes)?;
            } else {
                verifier.feed_index(&bytes)?;
            }
            if done {
                break;
            }
        }
    }
    before_read()?;
    check_deadline(now_seconds()?, execution_deadline)?;
    Ok(verifier)
}

#[cfg(target_arch = "wasm32")]
pub(super) async fn read_checked(
    reader: &crate::direct_digest::Reader,
    execution_deadline: i64,
    before_read: &impl Fn() -> Result<()>,
) -> Result<(js_sys::Uint8Array, bool)> {
    before_read()?;
    check_deadline(now_seconds()?, execution_deadline)?;
    let mut pending = Box::pin(reader.read());
    loop {
        let tick = Box::pin(worker::Delay::from(std::time::Duration::from_millis(50)));
        match select(pending, tick).await {
            Either::Left((result, _)) => {
                before_read()?;
                check_deadline(now_seconds()?, execution_deadline)?;
                return result;
            }
            Either::Right((_, next)) => {
                before_read()?;
                check_deadline(now_seconds()?, execution_deadline)?;
                pending = next;
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn now_seconds() -> Result<i64> {
    let seconds = (js_sys::Date::now() / 1000.0).floor();
    ensure!(
        seconds.is_finite() && seconds >= 0.0 && seconds < i64::MAX as f64,
        "pack inspection clock refused"
    );
    Ok(seconds as i64)
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_execution(now: i64, deadline: i64) -> anyhow::Result<()> {
    check_deadline(now, deadline)?;
    anyhow::ensure!(
        now.checked_add(600)
            .is_some_and(|maximum| deadline <= maximum),
        "pack inspection execution exceeds its finite bound"
    );
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
fn check_deadline(now: i64, deadline: i64) -> anyhow::Result<()> {
    anyhow::ensure!(
        now >= 0 && now <= deadline,
        "pack inspection execution expired"
    );
    Ok(())
}

#[cfg(target_arch = "wasm32")]
struct UnopenedStream {
    stream: ReadableStream,
    opened: bool,
}

#[cfg(target_arch = "wasm32")]
impl UnopenedStream {
    fn open(&mut self) -> Result<crate::direct_digest::Reader> {
        let reader = crate::direct_digest::Reader::new(self.stream.clone().into())?;
        self.opened = true;
        Ok(reader)
    }
}

#[cfg(target_arch = "wasm32")]
impl Drop for UnopenedStream {
    fn drop(&mut self) {
        if !self.opened {
            let cancellation = self.stream.cancel();
            wasm_bindgen_futures::spawn_local(async move {
                let _ = wasm_bindgen_futures::JsFuture::from(cancellation).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_execution_window_refuses_unbounded_and_elapsed_work() {
        assert!(validate_execution(1000, 1600).is_ok());
        assert!(validate_execution(1000, 1601).is_err());
        assert!(validate_execution(1000, 999).is_err());
        assert!(validate_execution(-1, 10).is_err());
        assert!(validate_execution(i64::MAX - 100, i64::MAX).is_err());

        assert!(check_deadline(1599, 1600).is_ok());
        assert!(check_deadline(1601, 1600).is_err());
    }
}
