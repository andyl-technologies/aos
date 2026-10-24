//! Binds the retained cleanup continuation to its actual physical owner.

use super::{Contract, facts};

pub(super) const CONTRACT: Contract = Contract {
    package: "crucible-daemon",
    target: "src/qemu_lifecycle_launcher/pending_construction/cleanup",
    required: &[
        (
            r#"pub(super) fn finish_under_world_cleanup(&mut self) -> Result<(), CleanupError> {
        let world = self.world.as_ref().ok_or(CleanupError::Retained(
            "entered World has no delivered cleanup loan",
        ))?;
        let cleanup = match world.retained_cleanup() {
            Ok(cleanup) => cleanup,
            Err(first) => {
                self.history.cleanup_first.get_or_insert(first);
                return Err(CleanupError::Retained("same World Cleanup is unavailable"));
            }
        };
        let (attempt, first, post) =
            observe_saved_world_cleanup(&cleanup, || self.finish_native_members());
        if let Some(first) = first {
            self.history.cleanup_first.get_or_insert(first.into());
        }
        if let Err(post) = post {
            self.history.cleanup_post.get_or_insert(post);
        }
        attempt
    }"#,
            1,
        ),
        (
            r#"fn observe_saved_world_cleanup<T>(
    cleanup: &HostOperationGuard,
    attempt: impl FnOnce() -> Result<T, CleanupError>,
) -> (
    Result<T, CleanupError>,
    Option<HostSupervisionError>,
    Result<(), HostSupervisionError>,
) {
    let (result, first) = match cleanup.wait_slice() {
        Ok(_) => (attempt(), None),
        Err(first) => (
            Err(CleanupError::Retained(
                "same World Cleanup refused retirement effects",
            )),
            Some(first),
        ),
    };
    let post = cleanup.wait_slice().map(|_| ());
    (result, first, post)
}"#,
            1,
        ),
        (r#"Instant::now("#, 0),
        (r#"thread::sleep("#, 0),
        (r#"HostOperationSupervisor::new("#, 2),
        (
            r#"let members = if self.members_closed { Ok(()) } else {"#,
            1,
        ),
        (
            r#"match members { Ok(()) => {
 self.members_closed = true;
 if let Some(guard) = self.returned_guard.as_mut() { guard.finish()?; }
 self.returned_guard = None; self.generation_storage = None;
 self.body_cleanup_complete = true; Ok(())
 } Err(first) => { self.record_first(first);"#,
            1,
        ),
    ],
    expressions: &[(r#"factory.retry_native_world_construction(world)"#, 1)],
    identifiers: &[(r#"retry_native_world_construction"#, 1)],
    companions: facts::WORLD,
};
