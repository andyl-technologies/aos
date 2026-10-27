//! Exposes the generator's own compiler settings to its dependent test.

fn main() {
    // Test the compiled arithmetic operation rather than inferring its setting
    // from debug assertions, which rustc allows callers to select independently.
    std::panic::set_hook(Box::new(|_| {}));
    let value = std::hint::black_box(u8::MAX);
    let overflow_checks = std::panic::catch_unwind(|| value + 1).is_err();

    println!(
        "cargo:rustc-env=AOS_EXEC_DEBUG_ASSERTIONS={}",
        cfg!(debug_assertions)
    );
    println!("cargo:rustc-env=AOS_EXEC_OVERFLOW_CHECKS={overflow_checks}");
}
