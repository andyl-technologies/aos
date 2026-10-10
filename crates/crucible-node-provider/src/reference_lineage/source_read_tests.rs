//! Exercises the actual original owner fence without launching native groups.

use super::*;

#[test]
fn successful_control_keeps_original_owner_but_busy_read_refuses() -> Result<(), ProviderError> {
    let original = SourceReadOwner::new(U64::new(17));
    original.ensure_current()?;

    let call = SourceReadCall::new(&original);
    assert!(original.ensure_current().is_err());
    call.finish(true);

    original.ensure_current()?;
    original.revoke();
    assert!(original.ensure_current().is_err());
    let later = SourceReadCall::new(&original);
    later.finish(true);
    assert!(original.ensure_current().is_err());
    Ok(())
}

#[test]
fn uncertain_control_and_unfinished_control_permanently_revoke() {
    let uncertain = SourceReadOwner::new(U64::new(17));
    SourceReadCall::new(&uncertain).finish(false);

    assert!(uncertain.ensure_current().is_err());

    let interrupted = SourceReadOwner::new(U64::new(18));
    {
        let _original_call = SourceReadCall::new(&interrupted);
    }

    assert!(interrupted.ensure_current().is_err());
}
