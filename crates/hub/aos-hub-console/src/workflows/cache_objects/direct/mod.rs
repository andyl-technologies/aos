//! Direct browser cache uploads with private sparse resume and no body fallback.

pub(crate) mod checkpoint;
mod driver;
pub(crate) mod lifecycle;
mod source;

pub(crate) use driver::{upload, upload_target};

pub(crate) use crate::transport::direct_browser_now as browser_now;
