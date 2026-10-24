//! Exercises the same declared native-library graph through Rust's C linker.

// SAFETY: The C helper owns all buffers and database handles, accepts no
// arguments, and returns an integer without imposing caller preconditions.
unsafe extern "C" {
    safe fn native_library_probe() -> i32;
}

fn main() {
    let answer = native_library_probe();
    println!("native-libraries={answer}");
    if answer != 42 {
        std::process::exit(1);
    }
}
