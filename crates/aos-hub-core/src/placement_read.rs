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
//! inferred here. A surface without configured placements fails closed: the
//! steady-state runtime has no binding/prefix fallback reader.

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::db::{Database, PlacementReadRequirement, SurfacePlacementRecord, SurfaceTarget};
use crate::fetch::{StreamedRead, SurfaceFetch, SurfaceProvider};

/// Placement-planned reader for callers that need a reusable [`SurfaceFetch`].
///
/// Git walkers and configuration loaders perform many logical reads through a
/// single reader. This adapter keeps that convenient interface while planning
/// every object read from the current placement inventory; it never captures a
/// binding-wide or resource-level fallback prefix.
pub struct TopologySurfaceFetch {
    db: Arc<Database>,
    provider: Arc<dyn SurfaceProvider>,
    surface: SurfaceTarget,
    verified_git_objects: bool,
}

impl TopologySurfaceFetch {
    /// Creates a reusable reader for one logical registry or cache.
    #[must_use]
    pub fn new(
        db: Arc<Database>,
        provider: Arc<dyn SurfaceProvider>,
        surface: SurfaceTarget,
    ) -> Self {
        Self {
            db,
            provider,
            surface,
            verified_git_objects: false,
        }
    }

    /// Creates a reader for Git object walks that verify every loose-object id.
    ///
    /// Loose Git objects are selected from eligible complete placements without
    /// requiring delivery-inventory evidence because the Git reader inflates
    /// and hashes every object against the SHA-256 encoded in its path. All
    /// other paths retain the ordinary inventory and publication requirements.
    #[must_use]
    pub fn for_verified_git_objects(
        db: Arc<Database>,
        provider: Arc<dyn SurfaceProvider>,
        surface: SurfaceTarget,
    ) -> Self {
        Self {
            db,
            provider,
            surface,
            verified_git_objects: true,
        }
    }

    fn requirement<'a>(&self, path: &'a str) -> PlacementReadRequirement<'a> {
        if self.verified_git_objects && is_loose_git_object_path(path) {
            PlacementReadRequirement::Untracked
        } else {
            requirement_for_path(self.surface, path)
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl SurfaceFetch for TopologySurfaceFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let plan = self
            .db
            .readable_surface_placements(self.surface, self.requirement(path))
            .await?;
        match execute_fetch_plan(
            self.provider.as_ref(),
            plan.candidates,
            path,
            plan.miss_is_inconsistent,
        )
        .await?
        {
            PlacementReadOutcome::Found(read) => Ok(Some(read.value)),
            PlacementReadOutcome::NotFound => Ok(None),
        }
    }

    async fn fetch_stream(
        &self,
        path: &str,
        range: Option<(u64, u64)>,
    ) -> Result<Option<StreamedRead>> {
        match stream_from_placements(&self.db, self.provider.as_ref(), self.surface, path, range)
            .await?
        {
            PlacementReadOutcome::Found(read) => Ok(Some(read.value)),
            PlacementReadOutcome::NotFound => Ok(None),
        }
    }

    fn describe(&self) -> String {
        "topology-planned surface placements".to_string()
    }
}

fn is_loose_git_object_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("objects/") else {
        return false;
    };
    let Some((fanout, digest_rest)) = rest.split_once('/') else {
        return false;
    };
    fanout.len() == 2
        && digest_rest.len() == 62
        && fanout
            .bytes()
            .chain(digest_rest.bytes())
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

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
/// Only `429`, `502`, `503`, and `504` are retryable availability conditions.
/// Every other non-success status is terminal; notably, authentication errors
/// and unexpected origin failures can never fall through to another placement.
/// Callers handle a true `404` as a definite miss before invoking this helper.
#[must_use]
pub fn http_status_read_error(operation: &str, status: u16) -> anyhow::Error {
    let message = format!("{operation}: status {status}");
    if matches!(status, 429 | 502 | 503 | 504) {
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
        return Err(terminal_read_error(
            "surface has no configured storage placements",
        ));
    }
    if plan.candidates.is_empty() && plan.has_policy_only_shards {
        return Err(terminal_read_error(
            "sharded storage placements require an explicit delivery-route placement policy",
        ));
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
    stream_from_placements_with_requirement(
        db,
        provider,
        surface,
        path,
        range,
        requirement_for_path(surface, path),
    )
    .await
}

/// Opens a streaming object using an explicit consistency requirement.
///
/// This is reserved for flows whose integrity contract is enforced by the
/// selected backend adapter rather than by previously recorded inventory. A
/// pull-through mirror is the primary example: the object does not exist in
/// local inventory until the native adapter fetches, verifies, and persists it.
///
/// # Errors
///
/// Returns an error when placement selection fails, a terminal backend failure
/// occurs, or every candidate fails retryably before streaming begins.
pub async fn stream_from_placements_with_requirement(
    db: &Database,
    provider: &dyn SurfaceProvider,
    surface: SurfaceTarget,
    path: &str,
    range: Option<(u64, u64)>,
    requirement: PlacementReadRequirement<'_>,
) -> Result<PlacementReadOutcome<StreamedRead>> {
    let plan = db.readable_surface_placements(surface, requirement).await?;
    if !plan.has_configured_placements {
        return Err(terminal_read_error(
            "surface has no configured storage placements",
        ));
    }
    if plan.candidates.is_empty() && plan.has_policy_only_shards {
        return Err(terminal_read_error(
            "sharded storage placements require an explicit delivery-route placement policy",
        ));
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

/// Opens a signed image only from the exact backend version verified at indexing.
///
/// The ordinary immutable planner proves that a placement previously contained
/// the indexed object. Images add a request-time identity check so stale
/// inventory cannot authorize same-size mutated bytes. A corrupt earlier
/// placement is skipped and a later independently verified replica may serve.
/// The selected stream carries the strong version of its already-open object
/// handle, so HEAD, ranges, and full downloads need no pathname re-open or
/// full-object pre-read.
///
/// # Errors
///
/// Returns an error when placement planning fails, no candidate currently
/// matches the signed SHA-256 and size, or the selected object changes between
/// identity verification and stream opening.
pub async fn stream_verified_image_from_placements(
    db: &Database,
    provider: &dyn SurfaceProvider,
    registry_id: i64,
    path: &str,
    expected_sha256: &str,
    expected_size: u64,
    range: Option<(u64, u64)>,
) -> Result<PlacementReadOutcome<StreamedRead>> {
    let plan = db
        .readable_surface_placements(
            SurfaceTarget::Registry(registry_id),
            PlacementReadRequirement::ImmutableObject(path),
        )
        .await?;
    if !plan.has_configured_placements {
        return Err(terminal_read_error(
            "image surface has no configured storage placements",
        ));
    }
    let mut verified = Vec::new();
    for placement in plan.candidates {
        if let Some(etag) = db
            .registry_image_placement_etag(registry_id, placement.id, path)
            .await?
        {
            verified.push((placement, etag));
        }
    }
    execute_verified_image_plan(
        provider,
        verified,
        path,
        expected_sha256,
        expected_size,
        range,
        plan.miss_is_inconsistent,
    )
    .await
}

async fn execute_verified_image_plan(
    provider: &dyn SurfaceProvider,
    placements: Vec<(SurfacePlacementRecord, String)>,
    path: &str,
    expected_sha256: &str,
    expected_size: u64,
    range: Option<(u64, u64)>,
    miss_is_inconsistent: bool,
) -> Result<PlacementReadOutcome<StreamedRead>> {
    let mut saw_corrupt = false;
    let mut last_retryable = None;
    for (placement, verified_etag) in placements {
        let fetch = match provider.placement_fetcher(&placement).await {
            Ok(fetch) => fetch,
            Err(error) if classify_read_error(&error) == ReadFailureClass::Retryable => {
                last_retryable = Some(error);
                continue;
            }
            Err(error) => return Err(error),
        };
        let read = match fetch.fetch_stream(path, range).await {
            Ok(Some(read)) => read,
            Ok(None) => continue,
            Err(error) if classify_read_error(&error) == ReadFailureClass::Retryable => {
                last_retryable = Some(error);
                continue;
            }
            Err(error) => return Err(error),
        };
        if read.total != expected_size
            || read.strong_etag.as_deref() != Some(verified_etag.as_str())
        {
            saw_corrupt = true;
            tracing::warn!(
                placement_id = placement.id,
                placement_name = %placement.name,
                object_key = path,
                expected_sha256,
                "signed image placement no longer matches its indexed object version"
            );
            continue;
        }
        return Ok(PlacementReadOutcome::Found(PlacementRead {
            value: read,
            placement: SelectedPlacement::from(&placement),
        }));
    }
    if saw_corrupt {
        Err(terminal_read_error(format!(
            "signed image object '{path}' has no currently verified readable placement"
        )))
    } else if let Some(error) = last_retryable {
        Err(error).context("all verified image placements failed before streaming")
    } else if miss_is_inconsistent {
        Err(terminal_read_error(format!(
            "signed image object '{path}' has no currently verified readable placement"
        )))
    } else {
        Ok(PlacementReadOutcome::NotFound)
    }
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

    use super::*;
    use crate::db::{CacheObjectPresenceObservation, NewSurfacePlacementSpec, SetSurfaceObject};

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

        async fn fetch_stream(
            &self,
            _path: &str,
            range: Option<(u64, u64)>,
        ) -> Result<Option<StreamedRead>> {
            match self.behavior {
                Behavior::Hit => Ok(Some(StreamedRead {
                    body: axum::body::Body::from("selected"),
                    total: 8,
                    range,
                    strong_etag: Some("fixture-version".into()),
                    snapshot_lease_id: None,
                })),
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
    }

    async fn cache_with_placements() -> (Database, i64) {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("planner", "Planner").await.unwrap();
        let owner = db.org_by_id(org).await.unwrap().unwrap();
        let binding = db
            .create_topology_storage_binding(
                Some(org),
                "planner-binding",
                &owner.stable_id,
                "planner",
                "local_fs",
                Some("/tmp/planner"),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let cache = db
            .create_binary_cache(Some(org), "planner", "Planner", "public", 40, "zstd", false)
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
    async fn zero_placement_snapshot_fails_closed() {
        let db = Database::open_in_memory().await.unwrap();
        let org = db.create_org("unplaced", "Unplaced").await.unwrap();
        let cache = db
            .create_binary_cache(
                Some(org),
                "unplaced",
                "Unplaced",
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
        let error = fetch_from_placements(
            &db,
            &provider,
            SurfaceTarget::BinaryCache(cache),
            "nar/unindexed.nar",
        )
        .await
        .unwrap_err();
        assert_eq!(classify_read_error(&error), ReadFailureClass::Terminal);
        assert!(error
            .to_string()
            .contains("no configured storage placements"));
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
    async fn verified_image_retryable_candidate_falls_through_to_healthy_replica() {
        let (db, cache) = cache_with_placements().await;
        let placements = db
            .list_surface_placements(SurfaceTarget::BinaryCache(cache))
            .await
            .unwrap()
            .into_iter()
            .map(|placement| (placement, "fixture-version".to_string()))
            .collect();
        let provider = FakeProvider {
            behavior: HashMap::from([
                ("first".to_string(), Behavior::Retryable),
                ("second".to_string(), Behavior::Hit),
                ("third".to_string(), Behavior::Hit),
            ]),
            opened: Arc::new(Mutex::new(Vec::new())),
        };
        let selected =
            execute_verified_image_plan(&provider, placements, "images/test", "00", 8, None, true)
                .await
                .unwrap();
        assert!(matches!(selected, PlacementReadOutcome::Found(_)));
    }

    #[tokio::test]
    async fn verified_image_all_retryable_returns_retryable_error() {
        let (db, cache) = cache_with_placements().await;
        let placements = db
            .list_surface_placements(SurfaceTarget::BinaryCache(cache))
            .await
            .unwrap()
            .into_iter()
            .map(|placement| (placement, "fixture-version".to_string()))
            .collect();
        let provider = FakeProvider {
            behavior: HashMap::from([
                ("first".to_string(), Behavior::Retryable),
                ("second".to_string(), Behavior::Retryable),
                ("third".to_string(), Behavior::Retryable),
            ]),
            opened: Arc::new(Mutex::new(Vec::new())),
        };
        let error = match execute_verified_image_plan(
            &provider,
            placements,
            "images/test",
            "00",
            8,
            None,
            true,
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("all-retryable image plan unexpectedly succeeded"),
        };
        assert_eq!(classify_read_error(&error), ReadFailureClass::Retryable);
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
        db.begin_cache_inventory_topology(cache, 2, 0, "placement-read-test", 1, 100)
            .await
            .unwrap();
        db.stage_cache_surface_object_identity(
            cache,
            2,
            first.id,
            "placement-read-test",
            &object.object_key,
            object.content_hash.as_deref().unwrap(),
            object.size.unwrap(),
        )
        .await
        .unwrap();
        db.stage_cache_object_presence(
            "placement-read-test",
            &CacheObjectPresenceObservation {
                cache_id: cache,
                object_key: object.object_key.clone(),
                placement_id: first.id,
                state: "present".into(),
                observed_hash: object.content_hash.clone(),
                observed_size: object.size,
                etag: Some("placement-read-test".into()),
                inventory_generation: 2,
                observed_at: 2,
            },
        )
        .await
        .unwrap();
        for placement in db
            .list_surface_placements(SurfaceTarget::BinaryCache(cache))
            .await
            .unwrap()
        {
            if placement.id != first.id {
                db.stage_missing_cache_inventory_observations(
                    cache,
                    2,
                    placement.id,
                    "placement-read-test",
                    2,
                )
                .await
                .unwrap();
            }
            db.stage_cache_inventory_manifest(
                cache,
                2,
                placement.id,
                "placement-read-test",
                &format!("manifest-{}", placement.id),
                i64::from(placement.id == first.id),
                3,
            )
            .await
            .unwrap();
        }
        db.publish_cache_inventory_topology(
            cache,
            2,
            "placement-read-test",
            "placement-read-aggregate",
            0,
            "placement-read-publish",
            4,
        )
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
        for status in [400, 401, 403, 409, 500, 501, 505] {
            let error = http_status_read_error("GET", status);
            assert_eq!(classify_read_error(&error), ReadFailureClass::Terminal);
        }
        for status in [429, 502, 503, 504] {
            let error = http_status_read_error("GET", status);
            assert_eq!(classify_read_error(&error), ReadFailureClass::Retryable);
        }
    }
}
