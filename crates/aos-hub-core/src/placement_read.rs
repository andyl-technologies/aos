//! Placement-aware surface read planning and pre-stream failover.
//!
//! A logical registry or cache can have several physical placements. This
//! module turns the database's consistency-filtered placement inventory into a
//! deterministic read plan and executes that plan without exposing storage
//! binding details to callers. Failover is limited to work performed before a
//! response body is returned: once a streaming body has been opened, the
//! selected backend owns that response and a mid-stream error is surfaced to
//! the client rather than splicing bytes from a different placement.
//!
//! This is the surface-global default plan. It deliberately admits only
//! `complete` non-archive placements; shard partition rules and delivery-route
//! policy membership are resolved by the subsequent route-policy planner, not
//! inferred here. During the incremental cutover, an atomic snapshot with zero
//! configured placements reports [`PlacementReadOutcome::NoPlacements`] so an
//! existing resource can use its migration reader. The final topology cutover
//! must backfill every surface and delete that fallback.

use std::error::Error as StdError;
use std::fmt;

use anyhow::{Context, Result};

use crate::db::{Database, PlacementReadRequirement, SurfacePlacementRecord, SurfaceTarget};
use crate::fetch::{StreamedRead, SurfaceFetch, SurfaceProvider};

/// Whether a backend failure permits trying the next placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadFailureClass {
    /// A transport or backend availability failure may succeed elsewhere.
    Retryable,
    /// Authentication, authorization, or invalid configuration must stop.
    Terminal,
}

/// A backend error carrying an explicit failover classification.
#[derive(Debug)]
pub struct ClassifiedReadError {
    class: ReadFailureClass,
    message: String,
}

impl ClassifiedReadError {
    /// Creates a classified backend read error.
    #[must_use]
    pub fn new(class: ReadFailureClass, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }

    /// Returns the failure's failover classification.
    #[must_use]
    pub fn class(&self) -> ReadFailureClass {
        self.class
    }
}

impl fmt::Display for ClassifiedReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl StdError for ClassifiedReadError {}

/// Wraps a retryable backend failure for placement failover.
#[must_use]
pub fn retryable_read_error(message: impl Into<String>) -> anyhow::Error {
    ClassifiedReadError::new(ReadFailureClass::Retryable, message).into()
}

/// Wraps a terminal backend failure that must not be retried elsewhere.
#[must_use]
pub fn terminal_read_error(message: impl Into<String>) -> anyhow::Error {
    ClassifiedReadError::new(ReadFailureClass::Terminal, message).into()
}

/// Classifies an HTTP backend status identically on native and Worker runtimes.
///
/// `429` and server failures are retryable availability conditions. Every other
/// non-success status is terminal; notably, `401` and `403` can never fall
/// through to another placement and become an authorization bypass. Callers
/// handle a true `404` as a definite miss before invoking this helper.
#[must_use]
pub fn http_status_read_error(operation: &str, status: u16) -> anyhow::Error {
    let message = format!("{operation}: status {status}");
    if status == 429 || status >= 500 {
        retryable_read_error(message)
    } else {
        terminal_read_error(message)
    }
}

/// Classifies an error returned while opening or reading a placement.
///
/// Unclassified errors fail closed as terminal. Adapters must explicitly mark
/// only known transport, throttling, or server-availability failures retryable;
/// authentication, authorization, invalid paths, and invalid binding
/// configuration therefore never fall through by accident.
#[must_use]
pub fn classify_read_error(error: &anyhow::Error) -> ReadFailureClass {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<ClassifiedReadError>())
        .map_or(ReadFailureClass::Terminal, ClassifiedReadError::class)
}

/// Internal diagnostic identity of the placement that served a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedPlacement {
    /// Database id used for structured diagnostics.
    pub id: i64,
    /// Stable human-readable name within the logical surface.
    pub name: String,
}

impl From<&SurfacePlacementRecord> for SelectedPlacement {
    fn from(placement: &SurfacePlacementRecord) -> Self {
        Self {
            id: placement.id,
            name: placement.name.clone(),
        }
    }
}

/// A successful read paired with the placement that produced it.
#[derive(Debug)]
pub struct PlacementRead<T> {
    /// The fetched bytes or streaming response body.
    pub value: T,
    /// Server-side diagnostic identity of the selected placement.
    pub placement: SelectedPlacement,
}

/// Result of applying topology to one logical surface read.
#[derive(Debug)]
pub enum PlacementReadOutcome<T> {
    /// The surface has no placement inventory and may use the migration fallback.
    NoPlacements,
    /// Placements exist, but no eligible placement contains the object.
    NotFound,
    /// An eligible placement produced the object.
    Found(PlacementRead<T>),
}

/// Returns the consistency contract for one logical surface path.
#[must_use]
pub fn requirement_for_path<'a>(
    surface: SurfaceTarget,
    path: &'a str,
) -> PlacementReadRequirement<'a> {
    if crate::keymap::cache_control(path) == crate::keymap::IMMUTABLE_CACHE_CONTROL {
        PlacementReadRequirement::ImmutableObject(path)
    } else if matches!(surface, SurfaceTarget::Registry(_)) {
        PlacementReadRequirement::RegistryCurrentPublication(path)
    } else {
        PlacementReadRequirement::Untracked
    }
}

/// Reads a complete object through an ordered placement plan.
///
/// A definite miss tries the next placement. Retryable errors also try the next
/// placement and are returned if no placement succeeds; terminal errors stop
/// immediately. The returned identity contains no binding root, endpoint, or
/// credential, but placement names are operator-chosen and remain server-side.
///
/// # Errors
///
/// Returns an error when placement selection fails, a terminal backend failure
/// occurs, or every candidate fails retryably.
pub async fn fetch_from_placements(
    db: &Database,
    provider: &dyn SurfaceProvider,
    surface: SurfaceTarget,
    path: &str,
) -> Result<PlacementReadOutcome<Vec<u8>>> {
    let plan = db
        .readable_surface_placements(surface, requirement_for_path(surface, path))
        .await?;
    if !plan.has_configured_placements {
        return Ok(PlacementReadOutcome::NoPlacements);
    }
    execute_fetch_plan(provider, plan.candidates, path, plan.miss_is_inconsistent).await
}

/// Opens a streaming object through an ordered placement plan.
///
/// Failover happens only while opening the backend and obtaining the
/// [`StreamedRead`]. Once returned, its body is never retried or joined with a
/// second placement, preserving byte and range integrity.
///
/// # Errors
///
/// Returns an error when placement selection fails, a terminal backend failure
/// occurs, or every candidate fails retryably before streaming begins.
pub async fn stream_from_placements(
    db: &Database,
    provider: &dyn SurfaceProvider,
    surface: SurfaceTarget,
    path: &str,
    range: Option<(u64, u64)>,
) -> Result<PlacementReadOutcome<StreamedRead>> {
    let plan = db
        .readable_surface_placements(surface, requirement_for_path(surface, path))
        .await?;
    if !plan.has_configured_placements {
        return Ok(PlacementReadOutcome::NoPlacements);
    }
    execute_stream_plan(
        provider,
        plan.candidates,
        path,
        range,
        plan.miss_is_inconsistent,
    )
    .await
}

/// Executes a full-object read against a preselected list.
async fn execute_fetch_plan(
    provider: &dyn SurfaceProvider,
    placements: Vec<SurfacePlacementRecord>,
    path: &str,
    miss_is_inconsistent: bool,
) -> Result<PlacementReadOutcome<Vec<u8>>> {
    let mut last_retryable = None;
    for placement in placements {
        let fetch = match provider.placement_fetcher(&placement).await {
            Ok(fetch) => fetch,
            Err(error) if classify_read_error(&error) == ReadFailureClass::Retryable => {
                tracing::warn!(
                    placement_id = placement.id,
                    placement_name = %placement.name,
                    error = %format!("{error:#}"),
                    "surface placement open failed; trying next placement"
                );
                last_retryable = Some(error);
                continue;
            }
            Err(error) => return Err(error),
        };
        match fetch.fetch(path).await {
            Ok(Some(value)) => {
                let selected = SelectedPlacement::from(&placement);
                tracing::debug!(
                    placement_id = selected.id,
                    placement_name = %selected.name,
                    "surface read selected placement"
                );
                return Ok(PlacementReadOutcome::Found(PlacementRead {
                    value,
                    placement: selected,
                }));
            }
            Ok(None) => continue,
            Err(error) if classify_read_error(&error) == ReadFailureClass::Retryable => {
                tracing::warn!(
                    placement_id = placement.id,
                    placement_name = %placement.name,
                    error = %format!("{error:#}"),
                    "surface placement read failed; trying next placement"
                );
                last_retryable = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    if let Some(error) = last_retryable {
        return Err(error).context("all readable surface placements failed");
    }
    if miss_is_inconsistent {
        Err(terminal_read_error(format!(
            "authoritative surface object '{path}' is missing from every readable placement"
        )))
    } else {
        Ok(PlacementReadOutcome::NotFound)
    }
}

/// Executes a streaming read against a preselected list.
async fn execute_stream_plan(
    provider: &dyn SurfaceProvider,
    placements: Vec<SurfacePlacementRecord>,
    path: &str,
    range: Option<(u64, u64)>,
    miss_is_inconsistent: bool,
) -> Result<PlacementReadOutcome<StreamedRead>> {
    let mut last_retryable = None;
    for placement in placements {
        let fetch = match provider.placement_fetcher(&placement).await {
            Ok(fetch) => fetch,
            Err(error) if classify_read_error(&error) == ReadFailureClass::Retryable => {
                last_retryable = Some(error);
                continue;
            }
            Err(error) => return Err(error),
        };
        match fetch.fetch_stream(path, range).await {
            Ok(Some(value)) => {
                let selected = SelectedPlacement::from(&placement);
                tracing::debug!(
                    placement_id = selected.id,
                    placement_name = %selected.name,
                    "surface streaming read selected placement"
                );
                return Ok(PlacementReadOutcome::Found(PlacementRead {
                    value,
                    placement: selected,
                }));
            }
            Ok(None) => continue,
            Err(error) if classify_read_error(&error) == ReadFailureClass::Retryable => {
                last_retryable = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    if let Some(error) = last_retryable {
        return Err(error).context("all readable surface placements failed before streaming");
    }
    if miss_is_inconsistent {
        Err(terminal_read_error(format!(
            "authoritative surface object '{path}' is missing from every readable placement"
        )))
    } else {
        Ok(PlacementReadOutcome::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use anyhow::bail;

    use super::*;
    use crate::db::{
        NewSurfacePlacementSpec, RegistryRecord, SetObjectPlacement, SetSurfaceObject,
    };

    #[derive(Clone, Copy)]
    enum Behavior {
        Hit,
        Miss,
        Retryable,
        Terminal,
    }

    struct FakeFetch {
        behavior: Behavior,
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl SurfaceFetch for FakeFetch {
        async fn fetch(&self, _path: &str) -> Result<Option<Vec<u8>>> {
            match self.behavior {
                Behavior::Hit => Ok(Some(b"selected".to_vec())),
                Behavior::Miss => Ok(None),
                Behavior::Retryable => Err(retryable_read_error("backend unavailable")),
                Behavior::Terminal => Err(terminal_read_error("backend denied access")),
            }
        }

        fn describe(&self) -> String {
            "fake".to_string()
        }
    }

    struct FakeProvider {
        behavior: HashMap<String, Behavior>,
        opened: Arc<Mutex<Vec<String>>>,
    }

    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl SurfaceProvider for FakeProvider {
        async fn placement_fetcher(
            &self,
            placement: &SurfacePlacementRecord,
        ) -> Result<Box<dyn SurfaceFetch>> {
            self.opened
                .lock()
                .map_err(|_| anyhow::anyhow!("attempt log poisoned"))?
                .push(placement.name.clone());
            let behavior = self
                .behavior
                .get(&placement.name)
                .copied()
                .ok_or_else(|| terminal_read_error("unknown fake placement"))?;
            Ok(Box::new(FakeFetch { behavior }))
        }

        async fn fetcher(&self, _registry: &RegistryRecord) -> Result<Box<dyn SurfaceFetch>> {
            bail!("legacy fetcher is not used by placement planner tests")
        }
    }

    async fn cache_with_placements() -> (Database, i64) {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("planner", "Planner").await.unwrap();
        let binding = db
            .create_storage_binding(org, "planner", "local_fs", "/tmp/planner")
            .await
            .unwrap();
        let cache = db
            .create_cache(
                Some(org),
                "planner",
                "Planner",
                Some(binding),
                "legacy",
                None,
                "public",
                40,
                "zstd",
                false,
            )
            .await
            .unwrap();
        for (name, order) in [("first", 0), ("second", 1), ("third", 2)] {
            let placement = db
                .create_surface_placement(&NewSurfacePlacementSpec {
                    surface: SurfaceTarget::BinaryCache(cache),
                    name: name.to_string(),
                    storage_binding_id: binding,
                    prefix: name.to_string(),
                    kind: "complete".to_string(),
                    desired_state: "active".to_string(),
                    hash_range: None,
                    desired_read_enabled: true,
                    read_order: order,
                    requires_conditional_writes: false,
                })
                .await
                .unwrap();
            db.observe_surface_placement(placement.id, "ready", "complete", 1)
                .await
                .unwrap();
        }
        (db, cache)
    }

    #[tokio::test]
    async fn retryable_failures_and_misses_try_the_next_placement() {
        let (db, cache) = cache_with_placements().await;
        let opened = Arc::new(Mutex::new(Vec::new()));
        let provider = FakeProvider {
            behavior: HashMap::from([
                ("first".to_string(), Behavior::Retryable),
                ("second".to_string(), Behavior::Miss),
                ("third".to_string(), Behavior::Hit),
            ]),
            opened: Arc::clone(&opened),
        };
        let selected = match fetch_from_placements(
            &db,
            &provider,
            SurfaceTarget::BinaryCache(cache),
            "nar/unindexed.nar",
        )
        .await
        .unwrap()
        {
            PlacementReadOutcome::Found(selected) => selected,
            _ => panic!("expected a selected placement"),
        };
        assert_eq!(selected.value, b"selected");
        assert_eq!(selected.placement.name, "third");
        assert_eq!(*opened.lock().unwrap(), ["first", "second", "third"]);
    }

    #[tokio::test]
    async fn zero_placement_snapshot_is_the_only_migration_fallback_signal() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("unplaced", "Unplaced").await.unwrap();
        let cache = db
            .create_cache(
                Some(org),
                "unplaced",
                "Unplaced",
                None,
                "",
                None,
                "public",
                40,
                "zstd",
                false,
            )
            .await
            .unwrap();
        let opened = Arc::new(Mutex::new(Vec::new()));
        let provider = FakeProvider {
            behavior: HashMap::new(),
            opened: Arc::clone(&opened),
        };
        let outcome = fetch_from_placements(
            &db,
            &provider,
            SurfaceTarget::BinaryCache(cache),
            "nar/unindexed.nar",
        )
        .await
        .unwrap();
        assert!(matches!(outcome, PlacementReadOutcome::NoPlacements));
        assert!(opened.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn terminal_failures_never_fall_through_to_another_placement() {
        let (db, cache) = cache_with_placements().await;
        let opened = Arc::new(Mutex::new(Vec::new()));
        let provider = FakeProvider {
            behavior: HashMap::from([
                ("first".to_string(), Behavior::Terminal),
                ("second".to_string(), Behavior::Hit),
                ("third".to_string(), Behavior::Hit),
            ]),
            opened: Arc::clone(&opened),
        };
        let error = match fetch_from_placements(
            &db,
            &provider,
            SurfaceTarget::BinaryCache(cache),
            "nar/unindexed.nar",
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("terminal failure unexpectedly fell through"),
        };
        assert_eq!(classify_read_error(&error), ReadFailureClass::Terminal);
        assert_eq!(*opened.lock().unwrap(), ["first"]);
    }

    #[tokio::test]
    async fn streaming_selects_before_returning_the_body() {
        let (db, cache) = cache_with_placements().await;
        let opened = Arc::new(Mutex::new(Vec::new()));
        let provider = FakeProvider {
            behavior: HashMap::from([
                ("first".to_string(), Behavior::Retryable),
                ("second".to_string(), Behavior::Hit),
                ("third".to_string(), Behavior::Hit),
            ]),
            opened: Arc::clone(&opened),
        };
        let selected = match stream_from_placements(
            &db,
            &provider,
            SurfaceTarget::BinaryCache(cache),
            "nar/unindexed.nar",
            Some((0, 3)),
        )
        .await
        .unwrap()
        {
            PlacementReadOutcome::Found(selected) => selected,
            _ => panic!("expected a selected streaming placement"),
        };
        assert_eq!(selected.placement.name, "second");
        assert_eq!(*opened.lock().unwrap(), ["first", "second"]);
        assert_eq!(selected.value.range, Some((0, 3)));
    }

    #[tokio::test]
    async fn authoritative_inventory_miss_is_a_consistency_error() {
        let (db, cache) = cache_with_placements().await;
        let first = db
            .list_surface_placements(SurfaceTarget::BinaryCache(cache))
            .await
            .unwrap()
            .into_iter()
            .find(|placement| placement.name == "first")
            .unwrap();
        let object = db
            .create_surface_object(&SetSurfaceObject {
                surface: SurfaceTarget::BinaryCache(cache),
                object_key: "nar/expected.nar".to_string(),
                content_hash: Some("sha256:expected".to_string()),
                size: Some(8),
                object_kind: "immutable".to_string(),
                mutable_publication_id: None,
            })
            .await
            .unwrap();
        db.set_object_placement(&SetObjectPlacement {
            surface_object_id: object.id,
            placement_id: first.id,
            state: "present".to_string(),
            observed_hash: Some("sha256:expected".to_string()),
            observed_size: Some(8),
            etag: None,
            observed_at: 1,
        })
        .await
        .unwrap();
        let provider = FakeProvider {
            behavior: HashMap::from([
                ("first".to_string(), Behavior::Miss),
                ("second".to_string(), Behavior::Hit),
                ("third".to_string(), Behavior::Hit),
            ]),
            opened: Arc::new(Mutex::new(Vec::new())),
        };
        let error = match fetch_from_placements(
            &db,
            &provider,
            SurfaceTarget::BinaryCache(cache),
            "nar/expected.nar",
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("authoritative inventory miss was reported as a logical 404"),
        };
        assert_eq!(classify_read_error(&error), ReadFailureClass::Terminal);
        assert!(format!("{error:#}").contains("authoritative surface object"));
    }

    #[test]
    fn http_auth_denials_are_terminal_and_availability_failures_retry() {
        assert_eq!(
            classify_read_error(&anyhow::anyhow!("unclassified backend failure")),
            ReadFailureClass::Terminal
        );
        for status in [400, 401, 403, 409] {
            let error = http_status_read_error("GET", status);
            assert_eq!(classify_read_error(&error), ReadFailureClass::Terminal);
        }
        for status in [429, 500, 503] {
            let error = http_status_read_error("GET", status);
            assert_eq!(classify_read_error(&error), ReadFailureClass::Retryable);
        }
    }
}
