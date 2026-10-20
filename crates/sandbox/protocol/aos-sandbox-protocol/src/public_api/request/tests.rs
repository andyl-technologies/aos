//! Constructor ordering, bounded DATA, and explicitly injected proposal routing.

use super::*;

fn client_state() -> DormantClientStatePlanV1 {
    DormantClientStatePlanV1::new(1, 1, None).unwrap()
}

#[test]
fn mutation_without_client_context_is_rejected_before_shape_validation() {
    let kind = DormantSandboxRequestKindV1::Stop(wire::SandboxLifecycleRequest::default());

    assert_eq!(
        DormantPublicApiRequestV1::from_parsed_command(
            kind.clone(),
            DormantSandboxOutputV1::Json,
            client_state(),
        ),
        Err(DormantSandboxRoutingErrorV1::AuthorizationRequired),
    );

    let context = DormantPublicApiAuthorizationV1::new(vec![1]).unwrap();
    assert_eq!(
        DormantPublicApiRequestV1::from_parsed_command_with_authorization(
            kind,
            DormantSandboxOutputV1::Json,
            client_state(),
            context,
        ),
        Err(DormantSandboxRoutingErrorV1::InvalidRequest),
    );
}

#[test]
fn checked_mutation_data_does_not_supply_public_client_context() {
    let kind = DormantSandboxRequestKindV1::Start(wire::SandboxLifecycleRequest {
        sandbox_id: vec![1; 16],
        mutation: wire::MutationContext {
            idempotency_key: vec![1],
            expected_resource_version: vec![2],
            operation_timeout: wire::Duration {
                nanoseconds: 1,
                ..Default::default()
            }
            .into(),
            ..Default::default()
        }
        .into(),
        ..Default::default()
    });

    let data =
        PublicSandboxRequestDataV1::new(kind.clone(), DormantSandboxOutputV1::Json, client_state())
            .unwrap();

    assert_eq!(data.kind(), &kind);
    assert_eq!(data.response_schema(), StructuredOutputSchemaV1::Operation);
    assert_eq!(
        data.kind().public_api_route().unwrap().path(),
        "/aos.sandbox.v1.SandboxService/Start",
    );
    assert_eq!(
        DormantPublicApiRequestV1::from_parsed_command(
            kind,
            DormantSandboxOutputV1::Json,
            client_state(),
        ),
        Err(DormantSandboxRoutingErrorV1::AuthorizationRequired),
    );
}

struct RetainProposal;

impl DormantPublicApiWireTransportV1 for RetainProposal {
    type Output = DormantPublicApiRequestV1;

    fn call(
        &mut self,
        route: DormantPublicApiRouteV1,
        request: DormantPublicApiRequestV1,
    ) -> Result<Self::Output, DormantSandboxRoutingErrorV1> {
        assert_eq!(route.path(), "/aos.sandbox.v1.SandboxService/GetSandbox");
        assert!(!route.is_server_streaming());
        assert!(request.public_api_authorization().is_none());

        Ok(request)
    }
}

#[test]
fn injected_transport_receives_only_the_exact_untrusted_public_proposal() {
    let request = DormantPublicApiRequestV1::from_parsed_command(
        DormantSandboxRequestKindV1::GetSandbox(wire::GetSandboxRequest {
            sandbox_id: vec![1; 16],
            ..Default::default()
        }),
        DormantSandboxOutputV1::Json,
        client_state(),
    )
    .unwrap();
    let mut executor =
        DormantSandboxCommandExecutorV1::new(DormantPublicApiClientV1::new(RetainProposal));

    assert_eq!(executor.execute(request.clone()).unwrap(), request);
}

#[test]
fn client_state_rejects_bounds_outside_the_shared_ceiling() {
    for (pages, events, wait) in [
        (0, 1, None),
        (1, 0, None),
        (MAXIMUM_CLI_PAGES + 1, 1, None),
        (1, MAXIMUM_CLI_EVENTS + 1, None),
        (1, 1, Some(0)),
        (1, 1, Some(MAXIMUM_CLI_WAIT_NANOSECONDS + 1)),
    ] {
        assert_eq!(
            DormantClientStatePlanV1::new(pages, events, wait),
            Err(DormantSandboxRoutingErrorV1::InvalidRequest),
        );
    }

    assert!(
        DormantClientStatePlanV1::new(
            MAXIMUM_CLI_PAGES,
            MAXIMUM_CLI_EVENTS,
            Some(MAXIMUM_CLI_WAIT_NANOSECONDS),
        )
        .is_ok()
    );
}
