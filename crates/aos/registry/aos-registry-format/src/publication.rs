//! Pure ordering rules for installing prepared registry publication pointers.

/// Orders withheld pointers so discovery never precedes its object indexes.
///
/// Object indexes and other prepared metadata are installed before `info/refs`;
/// `HEAD` is installed last. Immutable inventory verification precedes every
/// pointer phase in each transport adapter.
pub fn pointer_upload_rank(path: &str) -> u8 {
    match path {
        "HEAD" => 3,
        "info/refs" => 2,
        _ => 1,
    }
}
