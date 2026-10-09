//! Physical realization and readback of the fixed Guest root substrate.
//!
//! [`guest_root_populate`] owns bounded fresh-root population,
//! [`guest_root_label`] owns the fixed SELinux projection and readback, and
//! [`guest_root_marker`] owns durable publication and physical marker recovery.
//! The separate Guest-root tree owner supplies nonauthorizing measurement.
//! Storage and Host retain authenticated admission, protected root custody,
//! writer exclusion, replay and clocks; Guest retains its PID 1 bootstrap and
//! execution owner. These physical operations create no replacement authority.

#![cfg(target_os = "linux")]
#![deny(missing_docs)]

pub mod guest_root_label;
pub mod guest_root_marker;
pub mod guest_root_populate;
