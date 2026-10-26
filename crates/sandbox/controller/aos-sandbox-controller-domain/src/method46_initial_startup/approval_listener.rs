//! Admits the same Source's fixed initial-approval listener and retains its post.
//!
//! Native listener admission checks type, inherited record-subject options and
//! the purpose's exact pathname. It authenticates no approver or signature and
//! accepts no connection. The admitted descriptor stays here through the owed
//! post, including after an unrelated startup refusal.

use std::os::fd::OwnedFd;
use std::path::Path;

use aos_sandbox_linux::seqpacket::{
    RecordSubjectListener, RecordSubjectListenerAdmissionAttemptV1, SeqpacketError,
};

use super::*;

pub(super) struct InitialApprovalListenerOriginalV1 {
    admission: Option<RecordSubjectListenerAdmissionAttemptV1>,
    listener: Option<RecordSubjectListener>,
    options_post: Option<Result<(), SeqpacketError>>,
    path_post: Option<Result<(), SeqpacketError>>,
    paid: bool,
    entered: bool,
    post_entered: bool,
}

impl InitialApprovalListenerOriginalV1 {
    pub(super) fn new() -> Self {
        Self {
            admission: None,
            listener: None,
            options_post: None,
            path_post: None,
            paid: false,
            entered: false,
            post_entered: false,
        }
    }

    pub(super) fn retain(&mut self, original: OwnedFd) {
        // The enclosing startup body is already paid before the sole native
        // role handoff. This inert move performs no descriptor observation.
        self.admission = Some(RecordSubjectListenerAdmissionAttemptV1::new(original));
    }

    fn admit(&mut self, role: Method46InitialServiceRoleV1) -> bool {
        if !self.paid || self.entered || self.post_entered {
            return false;
        }
        self.entered = true;
        let Some(admission) = self.admission.as_mut() else {
            return false;
        };
        if admission.admit_once(fixed_path(role)).is_err() {
            return false;
        }
        self.listener = admission.take_completed_listener();
        self.listener.is_some()
    }

    pub(super) fn finish_post(
        &mut self,
        role: Option<Method46InitialServiceRoleV1>,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        if !self.paid {
            return Ok(());
        }
        if std::mem::replace(&mut self.post_entered, true) {
            return Err(Method46InitialStartupClosedV1);
        }
        let listener = self
            .listener
            .as_ref()
            .ok_or(Method46InitialStartupClosedV1)?;
        self.options_post = Some(listener.validate_current());
        // A refused options sample cannot suppress the independent pathname
        // sample on an already admitted original.
        if let Some(role) = role {
            self.path_post = Some(listener.require_local_filesystem_path(fixed_path(role)));
        }
        if matches!(self.options_post, Some(Ok(()))) && matches!(self.path_post, Some(Ok(()))) {
            Ok(())
        } else {
            Err(Method46InitialStartupClosedV1)
        }
    }
}

fn fixed_path(role: Method46InitialServiceRoleV1) -> &'static Path {
    Path::new(match role {
        Method46InitialServiceRoleV1::ControllerStorageClient => {
            "/run/aos/sandbox-method46/controller-initial-approval.sock"
        }
        Method46InitialServiceRoleV1::StorageBroker => {
            "/run/aos/sandbox-method46/storage-initial-approval.sock"
        }
    })
}

impl Method46InitialStartupOriginalV1 {
    /// Admits this original's inherited fixed approval listener once.
    ///
    /// The same Source pays bounded native/pathname scratch before observation.
    /// The original listener is never reopened, accepted from or repaired for
    /// missing identity options. Its current options and pathname are checked
    /// again during the independently owed startup post.
    ///
    /// Successful admission authenticates neither a connecting approver nor a
    /// signature. Approval exchange, key separation and durable intent remain
    /// required before physical provisioning or checkpoint publication.
    ///
    /// # Errors
    /// Refuses missing original unit admission, ended Source, reentry, exhausted
    /// funding, a foreign pathname, wrong socket type or missing native options.
    /// Original native failures remain resident and fence this startup.
    pub fn admit_approval_listener_once_v1(
        &mut self,
    ) -> Result<(), Method46InitialStartupClosedV1> {
        let ready = self.body.as_ref().is_some_and(|body| {
            body.unit.initial_admitted()
                && body.listener.try_borrow().is_ok_and(|listener| {
                    listener.admission.is_some() && !listener.entered && !listener.post_entered
                })
        });
        if !ready {
            return Err(self.fail(First::Order));
        }
        // The startup body pays all resident carriers. These two page-sized
        // allowances cover the bounded sockaddr and typed native diagnostics
        // for admission and both owed observations; no new FD is created.
        self.fund_additional(Some(ResourceVector::ZERO.with(D::MemoryBytes, 8192)))?;
        let role = self.origin.as_ref().ok_or(self.closed)?.role;
        let body = self.body.as_mut().ok_or(self.closed)?;
        let listener = body.listener.get_mut();
        listener.paid = true;
        if !listener.admit(role) {
            return Err(self.fail(First::ApprovalListener));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use super::*;

    #[test]
    fn listener_admission_before_original_unit_cannot_observe_or_fund() {
        for role in [
            Method46InitialServiceRoleV1::ControllerStorageClient,
            Method46InitialServiceRoleV1::StorageBroker,
        ] {
            let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(role));

            assert!(startup.admit_approval_listener_once_v1().is_err());
            assert!(startup.capture_before_arguments_once_v1().is_err());

            assert!(startup.body.is_none());
            assert_eq!(startup.receiving.get(), ResourceVector::ZERO);
            assert!(matches!(startup.first.get(), Some(First::Order)));
        }
    }

    #[test]
    fn wrong_native_descriptor_keeps_first_cause_through_retry_and_post() {
        let mut listener = InitialApprovalListenerOriginalV1::new();
        listener.retain(tempfile::tempfile().unwrap().into());
        listener.paid = true;
        let role = Method46InitialServiceRoleV1::StorageBroker;

        assert!(!listener.admit(role));
        let admission = listener.admission.as_ref().unwrap();
        let first = match admission.first_failure().unwrap() {
            aos_sandbox_linux::seqpacket::ListenerAdmissionFailureRefV1::Cause(cause) => {
                std::ptr::from_ref(cause)
            }
            other => panic!("native cause missing: {other:?}"),
        };

        assert!(!listener.admit(Method46InitialServiceRoleV1::ControllerStorageClient));
        assert!(listener.finish_post(Some(role)).is_err());
        assert!(listener.post_entered);
        assert!(listener.listener.is_none());
        match listener
            .admission
            .as_ref()
            .unwrap()
            .first_failure()
            .unwrap()
        {
            aos_sandbox_linux::seqpacket::ListenerAdmissionFailureRefV1::Cause(cause) => {
                assert_eq!(std::ptr::from_ref(cause), first);
            }
            other => panic!("original cause replaced: {other:?}"),
        }
    }

    #[test]
    fn listener_post_refusal_cannot_suppress_original_source_after() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::StorageBroker,
        ));
        let mut body = StartupRolesOriginalV1::new();
        body.listener.get_mut().paid = true;
        startup.body = Some(Box::new(body));

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(startup.after_attempted.get());
        assert!(matches!(startup.after_result.get(), Some(Err(_))));
        assert!(
            startup
                .body
                .as_ref()
                .unwrap()
                .listener
                .borrow()
                .post_entered
        );
        assert!(matches!(startup.first.get(), Some(First::ApprovalListener)));
    }

    #[test]
    fn busy_listener_post_still_attempts_original_source_after() {
        let mut startup = ManuallyDrop::new(Method46InitialStartupOriginalV1::new(
            Method46InitialServiceRoleV1::ControllerStorageClient,
        ));
        startup.body = Some(Box::new(StartupRolesOriginalV1::new()));
        let held = startup.body.as_ref().unwrap().listener.borrow_mut();

        assert!(startup.finish_source_after_owed_once_v1(Ok(())).is_err());

        assert!(startup.after_attempted.get());
        assert!(matches!(startup.after_result.get(), Some(Err(_))));
        assert!(matches!(startup.first.get(), Some(First::Order)));
        drop(held);
    }
}
