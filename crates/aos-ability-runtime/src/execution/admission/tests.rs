//! Resource cleanup tests for failed admission.

use std::io;

use aos_ability_model::{
    AccessMode, EnvironmentId, ExecutionStage, InstanceId, LocalKey, ResourceAccess,
};

use super::*;
use crate::adapter::CatalogReservation;

#[test]
fn incomplete_acquisition_releases_in_reverse_and_retains_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let mut resources = vec![handle("alpha")?, handle("beta")?, handle("gamma")?];
    let mut errors = Vec::new();
    let mut catalog = TestCatalog::failing("beta");

    release_incomplete(&mut resources, &mut errors, &mut catalog);

    assert_eq!(catalog.release_order, ["gamma", "beta", "alpha"]);
    assert_eq!(errors.len(), 1);
    assert_eq!(
        resources
            .iter()
            .map(|resource| resource.resource().key.as_str())
            .collect::<Vec<_>>(),
        ["beta"]
    );
    Ok(())
}

#[test]
fn retry_cleanup_preserves_the_token_until_release_succeeds()
-> Result<(), Box<dyn std::error::Error>> {
    let failure = AdmissionFailure {
        state: Box::new(AdmissionFailureState {
            error: AdmissionError::PlanNotExecutable,
            retained_resources: vec![handle("alpha")?],
            cleanup_errors: Vec::new(),
            live_reservation: None,
        }),
    };
    let mut catalog = TestCatalog::failing("alpha");

    let failure = failure
        .retry_cleanup(&mut catalog)
        .expect_err("the failed release must retain its ownership token");
    assert_eq!(failure.retained_resources().count(), 1);

    catalog.fail_resource = None;
    failure.retry_cleanup(&mut catalog).map_err(|failure| {
        io::Error::other(format!("cleanup remained failed: {}", failure.error()))
    })?;
    Ok(())
}

fn handle(key: &str) -> Result<ResourceHandle<String>, Box<dyn std::error::Error>> {
    let resource = resource(key)?;
    let observation = aos_ability_model::AbilityValue::new(serde_json::json!({}))?;
    Ok(ResourceHandle::new(
        resource.clone(),
        ResourceAccess {
            resource: resource.clone(),
            mode: AccessMode::ExclusiveWrite,
        },
        CatalogReservation::new(
            key.to_string(),
            ResourceAdmissionEvidence::new(resource, None, None, observation),
        ),
    ))
}

fn resource(key: &str) -> Result<ResourceId, Box<dyn std::error::Error>> {
    Ok(ResourceId {
        provider: InstanceId {
            environment: EnvironmentId {
                authority: LocalKey::new("test-authority")?,
                key: LocalKey::new("test-environment")?,
                stage: ExecutionStage::Host,
            },
            key: LocalKey::new("provider")?,
        },
        key: LocalKey::new(key)?,
    })
}

struct TestCatalog {
    fail_resource: Option<String>,
    release_order: Vec<String>,
}

impl TestCatalog {
    fn failing(resource: &str) -> Self {
        Self {
            fail_resource: Some(resource.to_string()),
            release_order: Vec::new(),
        }
    }
}

impl TrustedResourceCatalog for TestCatalog {
    type Handle = String;
    type Error = io::Error;

    fn acquire(
        &mut self,
        _context: ReservationContext<'_>,
        _operation: &Operation,
        _access: &ResourceAccess,
    ) -> Result<CatalogReservation<Self::Handle>, Self::Error> {
        Err(io::Error::other("acquire is not used by this test"))
    }

    fn release(
        &mut self,
        resource: &ResourceId,
        _handle: &mut Self::Handle,
    ) -> Result<(), Self::Error> {
        self.release_order.push(resource.key.as_str().to_string());
        if self.fail_resource.as_deref() == Some(resource.key.as_str()) {
            Err(io::Error::other("injected release failure"))
        } else {
            Ok(())
        }
    }
}
