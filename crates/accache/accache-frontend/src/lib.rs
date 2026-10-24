//! Standalone GCC/Clang/Rust argument frontends adapted from pinned sccache.
//!
//! No server, storage, networking, or process execution code is included.
//! Upstream behavior and its regression fixtures are retained in compiler/;
//! accache owns dependency discovery, execution, and result publication.
#![allow(dead_code, unused_imports, unused_macros, unexpected_cfgs)]
#[macro_use]
extern crate log;
#[cfg(test)]
#[macro_use]
mod test_macros {
macro_rules! assert_map_contains {
    ( $map:expr , $( ($key:expr, $val:expr) ),* ) => {
        let mut nelems = 0;
        $(
            nelems += 1;
            match $map.get(&$key) {
                Some(&ref v) =>
                    assert_eq!($val, *v, "{} key `{:?}` doesn't match expected! (expected `{:?}` != actual `{:?}`)", stringify!($map), $key, $val, v),
                None => panic!("{} missing key `{:?}`", stringify!($map), $key),
            }
         )*
        assert_eq!(nelems, $map.len(), "{} contains {} elements, expected {}", stringify!($map), $map.len(), nelems);
    }
}


    macro_rules! stringvec { ($($value:expr),* $(,)?) => { vec![$($value.to_string()),*] }; }
    macro_rules! ovec { ($($value:expr),* $(,)?) => { vec![$(std::ffi::OsString::from($value)),*] }; }
    macro_rules! pathvec { ($($value:expr),* $(,)?) => { vec![$(std::path::PathBuf::from($value)),*] }; }
    macro_rules! osstringvec { ($($value:expr),* $(,)?) => { vec![$(std::ffi::OsString::from($value)),*] }; }
}
pub mod compiler;
mod util;
