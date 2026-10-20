//! Collects the independently defined closed materializer constructor rows.

#[path = "constructors/map_insert.rs"]
mod map_insert;
#[path = "constructors/sequences.rs"]
mod sequences;

pub(super) use map_insert::{
    map_fixed_counter_data, map_insertion_series_data, map_retirement_data,
};
pub(super) use sequences::{
    fixed_counter_data, string_copy_data, string_drop_data, vec_access_data, vec_into_iter_data,
    vec_push_pop_data, vec_reservation_data,
};
