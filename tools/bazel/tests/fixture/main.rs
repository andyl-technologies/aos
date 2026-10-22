//! Exercises a separately compiled Rust dependency.

fn main() {
    println!(
        "answer={}",
        fixture_macro::identity!(fixture_library::answer())
    );
}
