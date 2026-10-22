//! Exercises verifier callbacks under actual inherited private/public sockets.
//!
//! These isolated callback controls issue no SDK lease or native model grant.

use super::super::super::channel_custody::BorrowedCustody;
use super::super::super::hello_verifier::Verifier;
use super::*;
use crate::handshake::{HelloRequest, HelloResult, TrustedHandshakeVerifier, TrustedInstallation};
use crate::reference_packet::service::complete_restore::import18::hello::NATIVE_IMPORT18_CONNECTION_ID;

fn installation(owner: &OriginalImport18RawBootstrap) -> TrustedInstallation {
    let launch = owner.typed_bodies_data().unwrap().launch.launch_data();
    let binding = &launch.selection.realization.bindings[0];
    TrustedInstallation {
        session_id: binding.authority.session_id.clone(),
        incarnation_id: binding.authority.incarnation_id.clone(),
        measured_implementation: launch.selection.provider.implementation.clone(),
        launch_receipt: launch.selection.admission_receipt.clone(),
        admission_token: launch.admission_token.as_slice().try_into().unwrap(),
    }
}

fn verifier<'a>(
    owner: &'a OriginalImport18RawBootstrap,
    custody: BorrowedCustody<'a>,
    cut: OperationalDeadline,
) -> Verifier<'a> {
    // The complete input graph is authenticated independently of this callback
    // view. The test's prior construction admissions retain all original owners.
    owner.with_hello_response_data(|_| Ok(())).unwrap();
    Verifier::new_data(
        custody,
        owner.typed_bodies_data().unwrap().launch.launch_data(),
        owner.hello_selection.as_ref().unwrap(),
        owner.hello_sdk_request.data(owner.cut).unwrap(),
        owner.hello_result.data(owner.cut).unwrap(),
        owner.hello_exchange.as_ref().unwrap(),
        cut,
    )
}

fn custody(owner: &OriginalImport18RawBootstrap) -> BorrowedCustody<'_> {
    BorrowedCustody::new_data(&owner.process, &owner.thread, &owner.cut, &owner.stream)
}

pub(super) fn assert_child(owner: &mut OriginalImport18RawBootstrap) {
    super::hello_response::construct_for_verifier(owner);
    let before = owner.retained_requested_bytes().unwrap();
    let connection = Id::new(NATIVE_IMPORT18_CONNECTION_ID).unwrap();
    let request: &HelloRequest = owner.hello_sdk_request.data(owner.cut).unwrap();
    let result: &HelloResult = owner.hello_result.data(owner.cut).unwrap();
    let guarantees = &owner
        .typed_bodies_data()
        .unwrap()
        .launch
        .launch_data()
        .selection
        .realization
        .bindings[0]
        .compatibility
        .guarantees_ref;
    let installed = installation(owner);
    let mut actual = verifier(owner, custody(owner), owner.cut);

    actual
        .authenticate_exchange(&connection, &installed, request, result)
        .unwrap();
    actual
        .verify_contract_selection(
            &result.provider_identity,
            &result.selected_features,
            &[],
            guarantees,
        )
        .unwrap();

    assert!(
        actual
            .verify_contract_selection(
                &result.provider_identity,
                &result.selected_features,
                &[],
                guarantees
            )
            .is_err()
    );
    assert!(
        actual
            .authenticate_exchange(&connection, &installed, request, result)
            .is_err()
    );
    assert!(
        actual
            .resume_custody(&installed.session_id, &installed.incarnation_id, &vec![])
            .is_err()
    );
    assert!(actual.fence_connection(&connection).is_err());

    let copied_request = request.clone();
    let copied_result = result.clone();
    for fault in 0..9 {
        let mut installed = installation(owner);
        match fault {
            0 => installed.session_id = Id::new("foreign/session").unwrap(),
            1 => installed.incarnation_id = Id::new("foreign/incarnation").unwrap(),
            2 => installed.admission_token[31] ^= 1,
            3 => installed.measured_implementation.schema_version = 2,
            4 => installed.launch_receipt.hash.domain = "foreign.domain".into(),
            5 => {
                installed.launch_receipt.length =
                    crucible_node_format::U64::new(installed.launch_receipt.length.get() + 1)
            }
            6 | 7 | 8 => {}
            _ => unreachable!(),
        }
        let mut actual = verifier(owner, custody(owner), owner.cut);
        let foreign_connection = Id::new("foreign/connection").unwrap();
        let supplied_connection = if fault == 8 {
            &foreign_connection
        } else {
            &connection
        };
        let supplied_request = if fault == 6 { &copied_request } else { request };
        let supplied_result = if fault == 7 { &copied_result } else { result };

        assert!(
            actual
                .authenticate_exchange(
                    supplied_connection,
                    &installed,
                    supplied_request,
                    supplied_result
                )
                .is_err()
        );
        assert!(
            actual
                .authenticate_exchange(&connection, &installation(owner), request, result)
                .is_err()
        );
    }

    let copied_manifest = result.provider_identity.clone();
    let copied_features = result.selected_features.clone();
    let schema = crucible_node_format::SchemaRef {
        id: Id::new("verifier/foreign-schema").unwrap(),
        version: 1,
        definition: guarantees.clone(),
        extensions: Default::default(),
    };
    for fault in 0..5 {
        let mut actual = verifier(owner, custody(owner), owner.cut);
        if fault != 0 {
            actual
                .authenticate_exchange(&connection, &installed, request, result)
                .unwrap();
        }
        let manifest = if fault == 1 {
            &copied_manifest
        } else {
            &result.provider_identity
        };
        let features = if fault == 2 {
            &copied_features
        } else {
            &result.selected_features
        };
        let schemas = if fault == 3 {
            std::slice::from_ref(&schema)
        } else {
            &[]
        };
        let mut changed = guarantees.clone();
        changed.media_type = "application/foreign".into();
        let supplied_guarantees = if fault == 4 { &changed } else { guarantees };

        assert!(
            actual
                .verify_contract_selection(manifest, features, schemas, supplied_guarantees)
                .is_err()
        );
        assert!(
            actual
                .verify_contract_selection(
                    &result.provider_identity,
                    &result.selected_features,
                    &[],
                    guarantees
                )
                .is_err()
        );
    }

    let foreign_process = owner.process.wrapping_add(1);
    let foreign_custody =
        BorrowedCustody::new_data(&foreign_process, &owner.thread, &owner.cut, &owner.stream);
    let mut actual = verifier(owner, foreign_custody, owner.cut);
    assert!(
        actual
            .authenticate_exchange(&connection, &installed, request, result)
            .is_err()
    );

    let foreign_thread =
        std::thread::scope(|scope| scope.spawn(|| std::thread::current().id()).join().unwrap());
    let foreign_custody =
        BorrowedCustody::new_data(&owner.process, &foreign_thread, &owner.cut, &owner.stream);
    let mut actual = verifier(owner, foreign_custody, owner.cut);
    assert!(
        actual
            .authenticate_exchange(&connection, &installed, request, result)
            .is_err()
    );

    let (substitute, _peer) = UnixStream::pair().unwrap();
    let foreign_custody =
        BorrowedCustody::new_data(&owner.process, &owner.thread, &owner.cut, &substitute);
    let mut actual = verifier(owner, foreign_custody, owner.cut);
    assert!(
        actual
            .authenticate_exchange(&connection, &installed, request, result)
            .is_err()
    );

    // Only this negative test constructs a substituted launch DTO. Equal
    // process/UID claims cannot authenticate a different complete image ref.
    let original_launch = owner.typed_bodies_data().unwrap().launch.launch_data();
    let mut substituted: crate::reference_packet::service::PacketNative5SourceLaunch =
        serde_json::from_value(serde_json::to_value(original_launch).unwrap()).unwrap();
    substituted.controller_executable.media_type = "application/foreign".into();
    let mut actual = Verifier::new_data(
        custody(owner),
        &substituted,
        owner.hello_selection.as_ref().unwrap(),
        request,
        result,
        owner.hello_exchange.as_ref().unwrap(),
        owner.cut,
    );
    assert!(
        actual
            .authenticate_exchange(&connection, &installed, request, result)
            .is_err()
    );

    let changed_cut = OperationalDeadline::after(Duration::from_secs(5)).unwrap();
    let mut actual = verifier(owner, custody(owner), changed_cut);
    assert!(
        actual
            .authenticate_exchange(&connection, &installed, request, result)
            .is_err()
    );
    let mut actual = verifier(
        owner,
        custody(owner),
        OperationalDeadline::expired_fixture(),
    );
    assert!(
        actual
            .authenticate_exchange(&connection, &installed, request, result)
            .is_err()
    );

    assert_eq!(owner.retained_requested_bytes().unwrap(), before);
    assert!(owner.hello_registrar.authority_data(owner.cut).is_err());
    owner.with_hello_response_data(|_| Ok(())).unwrap();
    assert!(owner.inputs.is_empty_data());
}

#[test]
fn native_verifier_binds_actual_original_callbacks_and_refuses_substitution_and_retry() {
    flight("initial_hello_verifier_complete");
    flight("initial_hello_verifier_reactive");
}
