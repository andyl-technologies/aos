//! Direct browser cache uploads with private sparse resume and no body fallback.

mod checkpoint;
mod driver;
mod source;

pub(super) use driver::upload;

pub(crate) use crate::transport::direct_browser_now as browser_now;
