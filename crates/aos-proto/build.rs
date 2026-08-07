fn main() {
    connectrpc_build::Config::new()
        .files(&[
            "src/proto/aos/cache/v1/cache.proto",
            "src/proto/aos/build/v1/build.proto",
            "src/proto/aos/gc/v1/gc.proto",
            "src/proto/aos/auth/v1/auth.proto",
            "src/proto/aos/hub/v1/hub.proto",
        ])
        .includes(&["src/proto/"])
        .include_file("_connectrpc.rs")
        .compile()
        .unwrap();
}
