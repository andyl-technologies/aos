//! Checks borrowed original slots without Child or semantic/native dispatch.
//!
//! An inert SDK handshake issues the actual model registrar; a real UnixStream
//! pair verifies that construction never sends a control frame. The retained
//! content allocation and original gate are checked independently of routing
//! labels. These tests do not authenticate Hello/native/class evidence.

use std::{
    cell::Cell,
    io::{ErrorKind, Read},
    rc::Rc,
};

use super::*;
use crate::{
    client::ClientContent,
    connection::{BodySchemaVerifier, ConnectionIncident, ConnectionSupervisor, ReceivedBody},
    handshake::{ConnectionAuthority, Handshake},
};

#[derive(Default)]
struct Supervisor(Cell<usize>);

impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, _: ConnectionIncident) {
        self.0.set(self.0.get() + 1);
    }
}

struct RefusingSchemas(Cell<usize>);

impl BodySchemaVerifier for RefusingSchemas {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        _: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        self.0.set(self.0.get() + 1);
        Err(ProviderError::Correlation(
            "model verifier must not run during construction",
        ))
    }
}

struct Originals {
    session: Option<ClientSession>,
    custody: Option<ClientCustody>,
    route: Option<ControllerRoute>,
    reference: ContentRef,
    supervisor: Rc<Supervisor>,
    schemas: Rc<RefusingSchemas>,
    peer: std::os::unix::net::UnixStream,
}

fn fixture(evidence: bool) -> Result<(Handshake, Originals), ProviderError> {
    let (handshake, authority) = crate::handshake::tests::controller_authority(evidence)?;
    let supervisor = Rc::new(Supervisor::default());
    let schemas = Rc::new(RefusingSchemas(Cell::new(0)));
    let (session, peer) =
        ClientSession::controller_fixture(authority, supervisor.clone(), schemas.clone())?;
    let reference =
        canonical::content_ref(b"complete original model body", "application/octet-stream")?;
    let mut content = ClientContent::new(4096, 4, 1024)?;
    content.install(reference.clone(), b"complete original model body".to_vec())?;
    let custody = ClientCustody::new(4, content)?;
    let route = ControllerRoute {
        node: Id::new("model-node")?,
        execution_owner: Id::new("model-owner")?,
    };
    Ok((
        handshake,
        Originals {
            session: Some(session),
            custody: Some(custody),
            route: Some(route),
            reference,
            supervisor,
            schemas,
            peer,
        },
    ))
}

fn present<T>(value: &Option<T>) -> Result<&T, ProviderError> {
    value
        .as_ref()
        .ok_or(ProviderError::Correlation("model original owner absent"))
}

fn no_frame(originals: &mut Originals) -> Result<(), ProviderError> {
    originals.peer.set_nonblocking(true)?;
    let mut byte = [0; 1];
    match originals.peer.read(&mut byte) {
        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
        other => {
            return Err(ProviderError::Correlation(match other {
                Ok(0) => "model transport unexpectedly closed",
                _ => "constructor sent model frame",
            }));
        }
    }
    assert_eq!(originals.schemas.0.get(), 0);
    assert_eq!(originals.supervisor.0.get(), 0);
    Ok(())
}

fn refusal_preserves(evidence: bool, budget: Duration, revoke: bool) -> Result<(), ProviderError> {
    let (mut handshake, mut original) = fixture(evidence)?;
    let session_pointer = present(&original.session)? as *const ClientSession;
    let custody_pointer = present(&original.custody)? as *const ClientCustody;
    let route_pointer = present(&original.route)? as *const ControllerRoute;
    let bytes_pointer = present(&original.custody)?
        .content()
        .get(&original.reference)?
        .as_ptr();
    if revoke {
        handshake.contain();
    }

    let result = CnpController::new_retained(
        &mut original.session,
        &mut original.custody,
        &mut original.route,
        budget,
    );

    let error = match result {
        Err(error) => error,
        Ok(_controller) => {
            return Err(ProviderError::Correlation(
                "model refusal unexpectedly consumed originals",
            ));
        }
    };
    let expected = if revoke {
        "control connection authority is fenced"
    } else {
        "generic controller lacks bounded original evidence scope"
    };
    assert!(matches!(&error, ProviderError::Correlation(reason) if *reason == expected));
    assert_eq!(
        session_pointer,
        present(&original.session)? as *const ClientSession
    );
    assert_eq!(
        custody_pointer,
        present(&original.custody)? as *const ClientCustody
    );
    assert_eq!(
        route_pointer,
        present(&original.route)? as *const ControllerRoute
    );
    assert_eq!(
        bytes_pointer,
        present(&original.custody)?
            .content()
            .get(&original.reference)?
            .as_ptr()
    );
    assert_eq!(
        present(&original.custody)?
            .content()
            .get(&original.reference)?,
        b"complete original model body"
    );
    no_frame(&mut original)
}

#[test]
fn revoked_registrar_retains_all_borrowed_originals() -> Result<(), ProviderError> {
    refusal_preserves(true, Duration::from_secs(1), true)
}

#[test]
fn missing_evidence_feature_retains_all_borrowed_originals() -> Result<(), ProviderError> {
    refusal_preserves(false, Duration::from_secs(1), false)
}

#[test]
fn zero_and_overlarge_budgets_retain_all_borrowed_originals() -> Result<(), ProviderError> {
    refusal_preserves(true, Duration::ZERO, false)?;
    refusal_preserves(true, Duration::from_secs(61), false)
}

#[test]
fn missing_original_slot_never_consumes_the_other_owners() -> Result<(), ProviderError> {
    for missing in 0..3 {
        let (_handshake, mut original) = fixture(true)?;
        let session = if missing == 0 {
            original.session.take()
        } else {
            None
        };
        let custody = if missing == 1 {
            original.custody.take()
        } else {
            None
        };
        let route = if missing == 2 {
            original.route.take()
        } else {
            None
        };

        assert!(
            CnpController::new_retained(
                &mut original.session,
                &mut original.custody,
                &mut original.route,
                Duration::from_secs(1)
            )
            .is_err()
        );
        assert_eq!(original.session.is_some(), missing != 0);
        assert_eq!(original.custody.is_some(), missing != 1);
        assert_eq!(original.route.is_some(), missing != 2);

        if missing == 0 {
            original.session = session;
        }
        if missing == 1 {
            original.custody = custody;
        }
        if missing == 2 {
            original.route = route;
        }
        no_frame(&mut original)?;
    }
    Ok(())
}

#[test]
fn successful_construction_moves_same_registrar_and_content_once() -> Result<(), ProviderError> {
    let (handshake, mut original) = fixture(true)?;
    let registration = present(&original.session)?
        .authority()
        .original_registration_read()?;
    let bytes_pointer = present(&original.custody)?
        .content()
        .get(&original.reference)?
        .as_ptr();
    let route = present(&original.route)?.clone();

    let controller = CnpController::new_retained(
        &mut original.session,
        &mut original.custody,
        &mut original.route,
        Duration::from_secs(1),
    )?;

    assert!(original.session.is_none());
    assert!(original.custody.is_none());
    assert!(original.route.is_none());
    assert_eq!(controller.route(), &route);
    assert_eq!(controller.budget, Duration::from_secs(1));
    assert_eq!(
        controller.content(&original.reference)?.as_ptr(),
        bytes_pointer
    );
    let moved = controller.authority().original_registration_read()?;
    assert!(registration.same_original(&moved));
    handshake.validate_registration(controller.authority())?;
    assert!(
        CnpController::new_retained(
            &mut original.session,
            &mut original.custody,
            &mut original.route,
            Duration::from_secs(1)
        )
        .is_err()
    );
    no_frame(&mut original)
}
