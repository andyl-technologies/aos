//! Binds the local delivery return control to its complete custody assertions.
//!
//! This exact modeled lifetime test retains its initiating refusal while the
//! same original fields are later consumed. Matching its source permits only
//! its name; extra calls, removed assertions and failed-test reruns stay visible.

/// Names the complete reviewed local physical-return control.
pub(super) const READY_RETURN: &str = r#"{
    reset(|model| {
        model.ready_status = -libc::EBUSY;
        model.ready_output = 0;
        model.payload_return_status = -libc::ECANCELED;
        model.return_status = -libc::EBUSY;
    });
    let mut delivery = Box::pin(Delivery::new());
    retain(&mut delivery).unwrap();
    let projection = delivery.projection;

    assert_eq!(status(delivery.identity_return(api(), 7)), -libc::EBUSY);
    assert!(!delivery.ready_returned);
    assert!(!delivery.returned);
    assert_eq!(delivery.projection, projection);
    MODEL.with_borrow_mut(|model| {
        model.ready_status = 0;
        model.ready_output = 1;
        model.payload_return_status = 0;
        model.return_status = 0;
    });

    assert_eq!(status(delivery.identity_return(api(), 7)), -libc::EBUSY);
    assert!(delivery.ready_returned);
    assert!(delivery.returned);
    MODEL.with_borrow(|model| {
        assert_eq!(model.ready_returns, 2);
        assert_eq!(model.payload_returns, 2);
        assert_eq!(model.returns, 2);
    });
}"#;
