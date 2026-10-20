//! Binds same-owner custody republication without treating it as cleanup.
//!
//! Only the declaration is masked after exact same-pair, canonical-cell and
//! caller-receipt obligations match. Native authority is not established here.

use super::{Companion, Contract};

#[path = "production_publication/main_custody.rs"]
mod main_custody;
#[path = "production_publication/source_installation.rs"]
mod source_installation;

pub(super) const ROLE_REPORTS: Companion = main_custody::REPORT_PINS;

pub(super) const CONTRACTS: &[Contract] = &[Contract {
    package: "crucible-daemon",
    target: "src/vm_lifecycle/construction/publication",
    required: &[
        (
            r#"pub fn retry_reserved_publication(
        &mut self,
    ) -> Result<
        Option<
            Box<
                dyn crucible_control_api::ProductionVmCleanupHandoff<
                        Failure = crate::ProductionVmConstructionCleanupError,
                        PostBody = crate::ProductionVmConstructionPostBody,
                    >,
            >,
        >,
        &'static str,
    > {"#,
            1,
        ),
        (
            r#"let FailureStorage::Rejected { returned, .. } = &mut self.storage else {
    return Err("");
};"#,
            1,
        ),
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
        (
            r#"match reservation.retain(custody) {
    Ok(handoff) => Ok((first, handoff)),
    Err((reservation, owner)) => Err(Self {
        storage: FailureStorage::Rejected {
            first,
            returned: std::sync::Mutex::new(Some((reservation, owner))),
        },
        additional: None,
    }),
}"#,
            1,
        ),
        (
            r#"let publication = if returned {
    reservation.retain_returned(self)
} else {
    reservation.retain(self)
};
match publication {
    Ok(handoff) => Ok(handoff),
    Err((reservation, owner)) => Err(ProductionVmConstructionFailure {
        storage: FailureStorage::Rejected {
            first: LifecycleApiError::ConstructionCustodyUnavailable,
            returned: std::sync::Mutex::new(Some((reservation, owner))),
        },
        additional: None,
    }),
}"#,
            1,
        ),
        (r#"reservation.retain("#, 3),
        (r#"reservation.retain_returned("#, 1),
        (
            r#"pub fn publish_for_cleanup(
    mut self: Box<Self>,
) -> Result<
    Box<
        dyn crucible_control_api::ProductionVmCleanupHandoff<
            Failure = crate::ProductionVmConstructionCleanupError,
            PostBody = crate::ProductionVmConstructionPostBody,
        >,
    >,
    ProductionVmConstructionFailure,
> { self.publish_cleanup_mode(false) }"#,
            1,
        ),
        (
            r#"pub fn publish_returned_for_cleanup(
    mut self: Box<Self>,
) -> Result<
    Box<
        dyn crucible_control_api::ProductionVmCleanupHandoff<
            Failure = crate::ProductionVmConstructionCleanupError,
            PostBody = crate::ProductionVmConstructionPostBody,
        >,
    >,
    ProductionVmConstructionFailure,
> { self.publish_cleanup_mode(true) }"#,
            1,
        ),
        (
            r#"if let Some(destination) = self.return_destination.take() {
    return Ok(destination.deliver(self));
}"#,
            1,
        ),
        (r#"custody.first.take()"#, 1),
        (
            r#"let Some(first) = custody.first.take() else {
    custody.reservation = Some(reservation);
    return Err(Self { storage: FailureStorage::Preallocated(custody), additional: None, });
};"#,
            1,
        ),
        (r#"first.to_string("#, 0),
        (r#"self.storage ="#, 0),
        (r#"self.additional ="#, 0),
        (r#"returned.replace("#, 0),
        (r#"std::mem::replace("#, 0),
        (r#"ProductionVmCleanupStage::Complete"#, 0),
        (r#".retry_cleanup("#, 0),
        (r#".complete("#, 0),
        (r#"Box::new("#, 0),
        (r#"Arc::new("#, 0),
        (r#"HostOperationSupervisor::new("#, 0),
        (r#"Instant::now("#, 0),
        (r#"thread::"#, 0),
        (r#"loop"#, 0),
        (r#"while"#, 0),
        // Both exact publication declarations above contain this substring.
        (r#"for"#, 2),
        (r#"mem::forget("#, 0),
        (r#"Box::leak("#, 0),
        (
            r#"let Some(reservation) = custody.reservation.take() else {
    return Err(Self { storage: FailureStorage::Preallocated(custody), additional: None, });
};"#,
            1,
        ),
        (
            r#"let Some(reservation) = self.reservation.take() else {
    return Err(self.into_failure(LifecycleApiError::ConstructionCustodyUnavailable));
};"#,
            1,
        ),
        (
            r#"and_then(|launcher| launcher.take_cleanup_reservation())"#,
            2,
        ),
        (r#"lifecycle.node_launcher.take_cleanup_reservation()"#, 2),
    ],
    expressions: &[],
    identifiers: &[("retry_reserved_publication", 1)],
    companions: &[
        source_installation::CONTROL_API,
        main_custody::RESERVATION,
        main_custody::QUEUE,
        source_installation::RETAINED_SOURCE,
        source_installation::PENDING_SOURCE,
        source_installation::SOURCE_BIRTH,
        source_installation::LAUNCHER,
        source_installation::FACTORY,
        source_installation::NATIVE_WORLD,
        source_installation::NATIVE_REFUSAL,
        main_custody::PREPARED_BIRTH,
        main_custody::BODY_DRIVER,
        main_custody::QUEUED_OWNER,
        source_installation::PREPARED_WORLD,
        main_custody::EXTERNAL_RETURN,
        main_custody::REPORT_PINS,
        main_custody::MAIN_SELECTION,
    ],
}];

#[cfg(test)]
#[path = "production_publication/tests.rs"]
mod tests;
