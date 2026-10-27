//! Binds only the unavailable-token negative component's three cleanup names.
//!
//! Actual publication/cleanup targets remain outside this contract. Exact
//! observations and canonical companions distinguish custody from test reruns.

use super::{Companion, Contract};

const PANIC_ONLY_OWNER: &str = r#"fn retry_cleanup(&mut self) -> Result<(), Self::Failure> {
    self.cleanup_calls.fetch_add(1, Ordering::SeqCst);
    panic!("");
}"#;
const REFUSED_CALL: &str = r#"assert!(failure.retry_reserved_publication().is_err());"#;

pub(super) const CONTRACTS: &[Contract] = &[Contract {
    package: "crucible-daemon",
    target: "src/vm_lifecycle/construction/publication/refused_publication_tests",
    required: &[
        (
            r#"#[test] fn unavailable_canonical_handoff_keeps_same_pair_and_first_cause_twice() {"#,
            1,
        ),
        (
            r#"type CleanupFailure = <ProductionVmConstructionCustody as ProductionVmCleanupOwner>::Failure;"#,
            1,
        ),
        (
            r#"struct FileOwner { _file: File, cleanup_calls: Arc<AtomicUsize>, destroyed: Arc<AtomicBool>, }"#,
            1,
        ),
        (
            r#"impl ProductionVmCleanupOwner for FileOwner { type Failure = CleanupFailure;"#,
            1,
        ),
        (
            r#"type PostBody = crate::ProductionVmConstructionPostBody;"#,
            1,
        ),
        (
            r#"fn take_post_body(&mut self) -> Result<Option<Self::PostBody>, Self::Failure> {
                panic!("");
            }"#,
            1,
        ),
        (
            r#"impl Drop for FileOwner { fn drop(&mut self) { self.destroyed.store(true, Ordering::SeqCst); } }"#,
            1,
        ),
        (
            r#"let LifecycleApiError::ConfigurationCopy(first) = first else { panic!(""); };"#,
            1,
        ),
        (
            r#"first.source().expect("").downcast_ref::<ConstructorRefusal>().expect("")"#,
            1,
        ),
        (
            r#"let FailureStorage::Rejected { first, returned } = &failure.storage else { panic!(""); };"#,
            1,
        ),
        (
            r#"let returned = returned.lock().expect(""); let (token, body) = returned.as_ref().expect("");"#,
            1,
        ),
        (
            r#"assert_eq!(std::ptr::from_ref(token.as_ref()).cast::<()>(), self.token);
assert_eq!(std::ptr::from_ref(body.as_ref()).cast::<()>(), self.body);"#,
            1,
        ),
        (
            r#"let cause = first_cause(first);
assert!(std::ptr::eq(cause, self.first));
assert_eq!(cause.marker, 73);
assert!(failure.additional.is_none());"#,
            1,
        ),
        (
            r#"assert_eq!(self.cleanup_calls.load(Ordering::SeqCst), 0);
assert!(!self.destroyed.load(Ordering::SeqCst));"#,
            1,
        ),
        (
            r#"let retained = fs::metadata(format!("", self.descriptor)).expect("");
assert_eq!((retained.dev(), retained.ino()), self.file_identity);"#,
            1,
        ),
        (
            r#"let file = tempfile::tempfile().expect("");
let descriptor = file.as_raw_fd();
let metadata = file.metadata().expect("");"#,
            1,
        ),
        (
            r#"let owner: Box<dyn ProductionVmCleanupOwner<
    Failure = CleanupFailure,
    PostBody = crate::ProductionVmConstructionPostBody,
>,> = Box::new(FileOwner {
    _file: file,
    cleanup_calls: Arc::clone(&cleanup_calls),
    destroyed: Arc::clone(&destroyed),
});"#,
            1,
        ),
        (
            r#"let reservation = crate::lifecycle_cleanup::LifecycleCleanupHandle::unavailable_reservation_for_test();"#,
            1,
        ),
        (
            r#"let first = LifecycleApiError::ConfigurationCopy(
    crucible_engine::owned_decode::DecodeAdmissionError::new(ConstructorRefusal { marker: 73 }),
);"#,
            1,
        ),
        (
            r#"token: std::ptr::from_ref(reservation.as_ref()).cast::<()>(),
body: std::ptr::from_ref(owner.as_ref()).cast::<()>(),
first: std::ptr::from_ref(first_cause(&first)),
descriptor,
file_identity: (metadata.dev(), metadata.ino()),"#,
            1,
        ),
        (
            r#"storage: FailureStorage::Rejected {
    first,
    returned: std::sync::Mutex::new(Some((reservation, owner))),
},
additional: None,"#,
            1,
        ),
        (r#"expected.assert_retained(&failure);"#, 4),
        (
            r#"expected.assert_retained(&failure);
assert!(failure.retry_reserved_publication().is_err());
expected.assert_retained(&failure);
assert!(failure.retry_reserved_publication().is_err());
expected.assert_retained(&failure);
failure = failure.into_published_error().expect_err("");
expected.assert_retained(&failure);"#,
            1,
        ),
        (
            r#"let FailureStorage::Rejected { returned, .. } = &mut failure.storage else {
    panic!("");
};
let (reservation, owner) = returned.get_mut().expect("").take().expect("");
drop(owner);
drop(reservation);"#,
            1,
        ),
        (
            r#"assert!(expected.destroyed.load(Ordering::SeqCst));
assert_eq!(expected.cleanup_calls.load(Ordering::SeqCst), 0);"#,
            1,
        ),
        (
            r#"assert!(fs::metadata(format!("")).map_or(true, |current|
    (current.dev(), current.ino()) != expected.file_identity));"#,
            1,
        ),
        // Two trait impls, two format macros, and the canonical helper name.
        // Another for-loop must change this exact fixture census.
        (r#"for"#, 5),
        (r#"loop"#, 0),
        (r#"while"#, 0),
        (r#"thread::sleep"#, 0),
        (r#"thread::park"#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#"impl ProductionVmCleanupReservation for"#, 0),
        (r#"Box::leak("#, 0),
        (r#"mem::forget("#, 0),
    ],
    expressions: &[(PANIC_ONLY_OWNER, 1), (REFUSED_CALL, 2)],
    identifiers: &[("retry_cleanup", 1), ("retry_reserved_publication", 2)],
    companions: &[
        Companion {
            path: "crates/crucible/crucible-daemon/src/lifecycle_cleanup/reservation.rs",
            required: &[
                (super::construction_endpoint::UNAVAILABLE_RESERVATION, 1),
                (r#"#[cfg(test)] impl LifecycleCleanupHandle {"#, 1),
                (
                    r#"pub(crate) fn unavailable_reservation_for_test() -> Box<
    dyn ProductionVmCleanupReservation<
        Failure = <crate::ProductionVmConstructionCustody as ProductionVmCleanupOwner>::Failure,
        PostBody = <crate::ProductionVmConstructionCustody as ProductionVmCleanupOwner>::PostBody,
        ReturnDestination = crate::lifecycle_cleanup::SourceBodyReturn
    >,
> {"#,
                    1,
                ),
                (
                    r#"> {
    Box::new(CleanupReservation {
        queue: Weak::new(),
        index: usize::MAX,
        epoch: 0,
        observed: ProductionVmCleanupStage::BodyRetained,
        first_failure: None,
        terminal_history: None,
        report_reference: false,
    })
} }"#,
                    1,
                ),
                (
                    r#"let Some(queue) = self.queue.upgrade() else { return Err((self, owner)); };"#,
                    2,
                ),
                (r#"self.publish_owner(slot, owner).map(|receipt|"#, 1),
                (
                    r#"self.publish_returned_owner(slot, owner).map(|receipt|"#,
                    1,
                ),
            ],
        },
        Companion {
            path: "crates/crucible/crucible-daemon/src/vm_lifecycle/construction/publication.rs",
            required: &[
                (r#"pub fn retry_reserved_publication("#, 1),
                (
                    r#"let returned = returned.get_mut().map_err(|_| "")?;
let Some((reservation, owner)) = returned.take() else {
    return Ok(None);
};"#,
                    1,
                ),
                (
                    r#"match reservation.retain(owner) {
    Ok(handoff) => Ok(Some(handoff)),
    Err((reservation, owner)) => {
        *returned = Some((reservation, owner));
        Err("")
    }
}"#,
                    1,
                ),
                (r#"if returned.is_some() { return Err(self); }"#, 1),
            ],
        },
    ],
}];

#[cfg(test)]
#[path = "refused_publication/tests.rs"]
mod tests;
