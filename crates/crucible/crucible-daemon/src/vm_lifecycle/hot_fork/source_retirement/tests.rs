//! Checks concrete retirement views without issuing Source or native custody.

use super::*;

#[test]
fn empty_history_has_no_typed_cause_or_visited_phase() {
    let history = ProductionVmHotForkSourceRetirementHistory::default();
    let mut visited = 0;

    history
        .visit_history(|_, _| {
            visited += 1;
            Ok(())
        })
        .unwrap();

    assert!(history.is_empty());
    assert!(history.first_failure().is_none());
    assert_eq!(visited, 0);
    assert_eq!(history.to_string(), "Source retirement");
}

#[test]
fn typed_phase_views_keep_original_causes_and_complete_formatted_history() {
    let message = String::from("component shutdown boundary refusal");
    let allocation = message.as_ptr();
    let mut history = ProductionVmHotForkSourceRetirementHistory {
        shutdown: Some(SchedulerError::BoundaryViolation { message }),
        ..Default::default()
    };
    let Some(SourceRetirementCause::Shutdown(first)) = history.first_failure() else {
        panic!("scheduler shutdown remains the selected concrete phase");
    };
    let original = std::ptr::from_ref(first);

    history.body = Some(CleanupError::Retained("later physical-body refusal"));
    let mut visited = Vec::new();
    history
        .visit_history(|label, cause| {
            visited.push((label, cause));
            Ok(())
        })
        .unwrap();

    let Some(SourceRetirementCause::Shutdown(first)) = history.first_failure() else {
        panic!("later body history cannot replace the scheduler phase");
    };
    assert!(std::ptr::eq(first, original));
    let SchedulerError::BoundaryViolation { message } = first else {
        panic!("the original boundary violation remains retained");
    };
    assert_eq!(message.as_ptr(), allocation);
    assert!(!history.is_empty());
    assert_eq!(visited.len(), 2);
    assert_eq!(visited[0].0, "shutdown");
    assert!(
        matches!(visited[0].1, SourceRetirementCause::Shutdown(cause) if std::ptr::eq(cause, original))
    );
    assert_eq!(visited[1].0, "physical body");
    assert!(
        matches!(visited[1].1, SourceRetirementCause::Body(cause) if std::ptr::eq(cause, history.body.as_ref().unwrap()))
    );
    assert_eq!(
        history.to_string(),
        format!(
            "Source retirement; shutdown: {}; physical body: {}",
            history.shutdown.as_ref().unwrap(),
            history.body.as_ref().unwrap(),
        )
    );
}

#[test]
fn a_refused_typed_visitor_stops_without_consuming_later_history() {
    let history = ProductionVmHotForkSourceRetirementHistory {
        shutdown: Some(SchedulerError::BoundaryViolation {
            message: String::from("component shutdown boundary refusal"),
        }),
        body: Some(CleanupError::Retained("later physical-body refusal")),
        ..Default::default()
    };
    let mut visited = 0;

    let result = history.visit_history(|label, cause| {
        assert_eq!(label, "shutdown");
        assert!(matches!(cause, SourceRetirementCause::Shutdown(_)));
        visited += 1;
        Err(fmt::Error)
    });

    assert!(result.is_err());
    assert_eq!(visited, 1);
    assert!(history.body.is_some());
    assert!(history.to_string().contains("later physical-body refusal"));
}
