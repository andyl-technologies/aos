##! Bazel Rust compiler repository backed by the AOS build-host toolchain.
{
  mkDerivation,
  rust,
  stdenv,
}: let
  triple = stdenv.hostPlatform.config;
  execTriple = stdenv.buildPlatform.config;
  compiler =
    if stdenv.isCross
    then rust.passthru.buildTool
    else rust;
in
  mkDerivation {
    pname = "workerd-rust-repository";
    inherit (rust) version;
    runtimeDeps = [compiler];
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out/bin"
          # Bazel constructs its own sysroot and linker arguments. Expose the
          # compiler itself so the AOS CLI wrapper does not override them.
          ln -s ${compiler}/bin/rustc.unwrapped "$out/bin/rustc"
          ln -s ${compiler}/bin/rustdoc.unwrapped "$out/bin/rustdoc"
          ln -s ${compiler}/bin/cargo "$out/bin/cargo"
          ln -s ${compiler}/lib "$out/lib"

          cat > "$out/BUILD.bazel" <<'BUILD'
          load("@rules_rust//rust:toolchain.bzl", "rust_stdlib_filegroup", "rust_toolchain")

          package(default_visibility = ["//visibility:public"])
          filegroup(name = "rustc", srcs = ["bin/rustc"])
          filegroup(name = "rustdoc", srcs = ["bin/rustdoc"])
          filegroup(name = "cargo", srcs = ["bin/cargo"])
          filegroup(
              name = "rustc_lib",
              srcs = glob([
                  "lib/*.so*",
                  "lib/rustlib/${execTriple}/codegen-backends/*.so",
                  "lib/rustlib/${execTriple}/lib/*.so*",
                  "lib/rustlib/${execTriple}/lib/*.rmeta",
              ], allow_empty = True),
          )
          rust_stdlib_filegroup(
              name = "rust_std-${triple}",
              srcs = glob([
                  "lib/rustlib/${triple}/lib/*.rlib",
                  "lib/rustlib/${triple}/lib/*.rmeta",
                  "lib/rustlib/${triple}/lib/*.so*",
                  "lib/rustlib/${triple}/lib/*.a",
                  "lib/rustlib/${triple}/lib/self-contained/**",
              ], allow_empty = True),
          )
          rust_toolchain(
              name = "rust_toolchain",
              rustc = ":rustc",
              rust_doc = ":rustdoc",
              cargo = ":cargo",
              rustc_lib = ":rustc_lib",
              rust_std = ":rust_std-${triple}",
              allocator_library = "@rules_rust//ffi/rs:empty",
              binary_ext = "",
              staticlib_ext = ".a",
              dylib_ext = ".so",
              stdlib_linkflags = ["-ldl", "-lpthread"],
              default_edition = "2024",
              exec_triple = "${execTriple}",
              target_triple = "${triple}",
              version = "${rust.version}",
              channel = "stable",
          )
          BUILD
          touch "$out/WORKSPACE.bazel"
        '';
      }
    ];
    meta = {
      description = "AOS Rust compiler repository for workerd's Bazel build";
      license = "Apache-2.0";
    };
  }
