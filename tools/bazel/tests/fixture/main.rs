//! Exercises a separately compiled Rust dependency.

fn main() {
    assert_eq!(env!("CARGO_PKG_NAME"), "aos-bazel-fixture");
    assert_eq!(env!("CARGO_PKG_VERSION"), "1.2.3-rc.4+local.5");
    println!(
        "answer={}",
        fixture_macro::identity!(fixture_library::answer())
    );
}
