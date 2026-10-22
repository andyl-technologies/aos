//! Checks linkage to the declared native library through its C ABI.

unsafe extern "C" {
    fn fixture_answer() -> i32;
}

fn main() {
    // SAFETY: The linked fixture exports this no-argument C function, whose
    // result is an integer and which does not access caller-owned memory.
    let answer = unsafe { fixture_answer() };
    println!("answer={}", answer + fixture_library::answer() as i32);
}
