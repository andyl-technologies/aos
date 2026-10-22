//! Exercises a separately compiled Rust dependency.

fn main() {
    println!("answer={}", fixture_library::answer());
}
