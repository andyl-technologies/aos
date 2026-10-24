//! Selects the existing main lifecycle before a completed assignment is reproduced.
//!
//! The private forwarding protocol reaches the factory already owned by the
//! model. Its function-pointer recipe adds no replacement factory or closure
//! allocation. Component models choose an explicit pre-effect refusal.

use crate::lifecycle_cleanup::ServiceMainHandle;
use crate::{
    QemuAttemptProcessResourceGuard, QemuAttemptProductionVmLifecycleError,
    QemuAttemptProductionVmLifecycleFactory, QemuAttemptResourceGuardFactory,
};

/// Prepares the same main factory that will execute the reproduction.
pub(crate) trait PrepareCompletedReproduction {
    fn prepare_completed_reproduction(
        &mut self,
    ) -> Result<ServiceMainHandle, QemuAttemptProductionVmLifecycleError>;
}

impl<R> PrepareCompletedReproduction for QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn prepare_completed_reproduction(
        &mut self,
    ) -> Result<ServiceMainHandle, QemuAttemptProductionVmLifecycleError> {
        self.prepare_source_construction()
    }
}

pub(crate) type CompletedReproductionPreparation<M> =
    fn(&mut M) -> Result<ServiceMainHandle, CompletedReproductionPreparationError>;

pub(crate) enum CompletedReproductionPreparationError {
    Lifecycle(QemuAttemptProductionVmLifecycleError),
    #[cfg(any(test, feature = "test-support"))]
    OperationOnlyUnsupported,
}

pub(crate) fn prepare_completed_reproduction<M: PrepareCompletedReproduction>(
    model: &mut M,
) -> Result<ServiceMainHandle, CompletedReproductionPreparationError> {
    model
        .prepare_completed_reproduction()
        .map_err(CompletedReproductionPreparationError::Lifecycle)
}

#[cfg(any(test, feature = "test-support"))]
pub(crate) fn operation_only_preparation<M>(
    _model: &mut M,
) -> Result<ServiceMainHandle, CompletedReproductionPreparationError> {
    Err(CompletedReproductionPreparationError::OperationOnlyUnsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    struct RefusingModel {
        calls: usize,
        first: Option<QemuAttemptProductionVmLifecycleError>,
    }

    impl PrepareCompletedReproduction for RefusingModel {
        fn prepare_completed_reproduction(
            &mut self,
        ) -> Result<ServiceMainHandle, QemuAttemptProductionVmLifecycleError> {
            self.calls += 1;
            Err(self
                .first
                .take()
                .expect("the original refusal remains owned"))
        }
    }

    #[test]
    fn preparation_recipe_preserves_the_actual_initiating_error() {
        let first = Box::new(io::Error::other("original metadata admission refused"));
        let first_pointer = first.as_ref() as *const io::Error;
        let mut model = RefusingModel {
            calls: 0,
            first: Some(QemuAttemptProductionVmLifecycleError::ModelCopy(first)),
        };

        let result = prepare_completed_reproduction(&mut model);

        let Err(CompletedReproductionPreparationError::Lifecycle(
            QemuAttemptProductionVmLifecycleError::ModelCopy(first),
        )) = result
        else {
            panic!("the same typed metadata refusal must be returned");
        };
        assert_eq!(model.calls, 1);
        assert!(model.first.is_none());
        assert!(std::ptr::eq(
            first.downcast_ref::<io::Error>().unwrap(),
            first_pointer,
        ));
    }

    #[test]
    fn operation_only_recipe_refuses_without_calling_the_model() {
        let mut model = RefusingModel {
            calls: 0,
            first: Some(QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch),
        };

        let result = operation_only_preparation(&mut model);

        assert!(matches!(
            result,
            Err(CompletedReproductionPreparationError::OperationOnlyUnsupported)
        ));
        assert_eq!(model.calls, 0);
        assert!(matches!(
            model.first,
            Some(QemuAttemptProductionVmLifecycleError::ScenarioIdentityMismatch)
        ));
    }
}
