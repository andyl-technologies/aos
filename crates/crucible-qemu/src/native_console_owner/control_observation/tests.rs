//! Initial refusal controls over the real host mapping and request publisher.

use super::*;
use crate::native_console_owner::tests::{FixtureError, LaunchFixture};

#[test]
fn fresh_setup_observation_refuses_before_any_table_or_request_effect() -> Result<(), FixtureError>
{
    let fixture = LaunchFixture::cold(2)?;
    let custody = fixture
        .setup
        .console_custody
        .as_ref()
        .ok_or(ConsoleOwnerError::Storage)?;
    let region = crucible_shmem::mmap_setup_region(
        fixture.setup.shmem_as_fd(),
        fixture.setup.region().region_len,
    )?;
    let slot = region.node_slot(0)?;
    let before = slot.snapshot();

    for capture in [None, Some(3)] {
        assert!(matches!(
            custody.request_boundary(&region, 0, capture),
            Err(ConsoleOwnerError::Shape(NativeConsoleError::Binding))
        ));
        assert_eq!(slot.snapshot(), before);
        assert!(region.native_console_segment(0)?.clamp.snapshot().is_err());
        let owner = custody.lock()?;
        assert_eq!(owner.next_clamp_publication, 2);
        assert!(owner.control_observation.is_none());
        assert!(owner.issued.is_empty());
    }
    fixture.finish()
}
