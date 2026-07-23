use super::*;

#[test]
fn persistent_active_frames_follow_parent_links_without_an_array() {
    let outer = EvalFrame::new(1).expect("outer frame");
    outer.set(0, Value::int(10)).expect("outer slot");
    let inner = EvalFrame::new_linked(1, Some(Arc::clone(&outer))).expect("inner frame");
    inner.set(0, Value::int(20)).expect("inner slot");
    let mut frames = ActiveEvalFrames::from_vec(vec![Arc::clone(&outer), Arc::clone(&inner)]);

    assert!(frames.linked_parts().is_some());
    assert!(
        frames
            .get_at_depth(0)
            .and_then(|frame| frame.get(0).ok())
            .is_some_and(|value| value.raw_eq(Value::int(20)))
    );
    assert!(
        frames
            .get_at_depth(1)
            .and_then(|frame| frame.get(0).ok())
            .is_some_and(|value| value.raw_eq(Value::int(10)))
    );

    let call = EvalFrame::new_linked(1, frames.last().cloned()).expect("call frame");
    call.set(0, Value::int(30)).expect("call slot");
    frames.push(Arc::clone(&call));
    assert!(Arc::ptr_eq(frames.last().expect("call head"), &call));
    assert!(Arc::ptr_eq(&frames.pop().expect("popped call"), &call));
    assert!(Arc::ptr_eq(frames.last().expect("restored inner"), &inner));
}

#[test]
fn unlinked_active_frames_retain_compatibility_order() {
    let outer = EvalFrame::new(1).expect("outer frame");
    let inner = EvalFrame::new(1).expect("independent inner frame");
    let mut frames = ActiveEvalFrames::from_vec(vec![Arc::clone(&outer), Arc::clone(&inner)]);

    assert!(frames.linked_parts().is_none());
    assert!(Arc::ptr_eq(frames.get(0).expect("outer"), &outer));
    assert!(Arc::ptr_eq(frames.get_at_depth(0).expect("inner"), &inner));

    let call = EvalFrame::new_linked(1, frames.last().cloned()).expect("call frame");
    frames.try_reserve_exact(1).expect("compat reserve");
    frames.push(Arc::clone(&call));
    assert!(Arc::ptr_eq(&frames.pop().expect("popped call"), &call));
    assert!(Arc::ptr_eq(frames.last().expect("restored inner"), &inner));
}
