//! Exercises the fully static guest runtime with declared native libraries.

#[cfg(not(target_feature = "crt-static"))]
compile_error!("the static fixture must enable crt-static for target code");

// SAFETY: The C helper owns all state and accepts no arguments.
unsafe extern "C" {
    safe fn native_library_probe() -> i32;
}

fn main() {
    let answer = execution_macro::identity!(native_library_probe());
    println!("native-libraries={answer}");
    if answer != 42 {
        std::process::exit(1);
    }
}
