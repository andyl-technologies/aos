//! Reconstructs each native17 field into a retained concrete owner.

use super::*;
use crate::protocol_snapshot::owned11::typed::native17_build::native17_struct;

native17_struct!(Position {
    time_ps: U64,
    microstep: U64,
    phase: Phase,
});
