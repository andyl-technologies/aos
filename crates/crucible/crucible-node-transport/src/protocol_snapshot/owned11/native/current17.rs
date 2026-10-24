//! Names concrete initialized imported-heap reader and writer layouts.

pub(crate) fn counter_scratch_data() -> usize {
    super::outer::current17::counter_scratch_data()
        + super::connection::current17::counter_scratch_data()
        + super::service::current17::counter_scratch_data()
        + super::boot::current17::counter_scratch_data()
        + super::identity::current17::counter_scratch_data()
        + super::token::current17::counter_scratch_data()
        + super::blob::current17::counter_scratch_data()
        + super::policy::current17::counter_scratch_data()
        + super::registrar::current17::counter_scratch_data()
        + super::bootstrap::current17::counter_scratch_data()
        + super::capture_owner::current17::counter_scratch_data()
        + super::capture_sdk::current17::counter_scratch_data()
        + super::startup::current17::counter_scratch_data()
        + super::invocation::current17::counter_scratch_data()
}
