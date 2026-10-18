//! Exercises real same-operation refusal and output custody at capture cuts.

use super::*;
use crucible_linux_resource::host_supervision::{
    HostOperationBudgets, HostOperationClass, HostOperationGuard, HostOperationSupervisor,
};

struct WorkState {
    original: HostOperationGuard,
    effects: usize,
    output: Option<String>,
}

impl WorkState {
    fn new() -> Self {
        let supervisor =
            HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
        Self {
            original: supervisor.begin(HostOperationClass::Preparation).unwrap(),
            effects: 0,
            output: None,
        }
    }

    fn check(&mut self) -> Result<(), LifecycleApiError> {
        self.original
            .wait_slice()
            .map(|_| ())
            .map_err(|_| LifecycleApiError::ConstructionCustodyUnavailable)
    }
}

#[test]
fn closed_original_refuses_capture_effect_and_observes_its_independent_post() {
    let mut state = WorkState::new();
    state.original.complete().unwrap();

    let (result, post) = observe_source_work(&mut state, WorkState::check, |state| {
        state.effects += 1;
        Ok(())
    });

    assert!(matches!(
        result,
        Err(First::Original(
            LifecycleApiError::ConstructionCustodyUnavailable
        ))
    ));
    assert!(matches!(
        post,
        Some(LifecycleApiError::ConstructionCustodyUnavailable)
    ));
    assert_eq!(state.effects, 0);
    assert!(state.output.is_none());
}

#[test]
fn actual_output_remains_owned_when_the_same_original_post_refuses() {
    let mut state = WorkState::new();
    let output = String::from("same returned capture metadata");
    let pointer = output.as_ptr();

    let (result, post) = observe_source_work(&mut state, WorkState::check, |state| {
        state.effects += 1;
        state.output = Some(output);
        state.original.complete().unwrap();
        Ok(())
    });

    assert!(matches!(result, Err(First::PostRefused)));
    assert!(matches!(
        post,
        Some(LifecycleApiError::ConstructionCustodyUnavailable)
    ));
    assert_eq!(state.effects, 1);
    assert_eq!(state.output.as_ref().unwrap().as_ptr(), pointer);
    assert_eq!(
        state.output.as_deref(),
        Some("same returned capture metadata")
    );
}

#[test]
fn initiating_leaf_and_completed_original_post_remain_independent() {
    let mut state = WorkState::new();
    let message = String::from("actual capture operation refused");
    let pointer = message.as_ptr();
    let first = First::Original(LifecycleApiError::LoopFactory { message });

    let (result, post) = observe_source_work(&mut state, WorkState::check, |state| {
        state.effects += 1;
        state.original.complete().unwrap();
        Err(first)
    });

    let Err(First::Original(LifecycleApiError::LoopFactory { message })) = result else {
        panic!("the initiating typed leaf was replaced by the post");
    };
    assert_eq!(message.as_ptr(), pointer);
    assert_eq!(message, "actual capture operation refused");
    assert!(matches!(
        post,
        Some(LifecycleApiError::ConstructionCustodyUnavailable)
    ));
    assert_eq!(state.effects, 1);
}
