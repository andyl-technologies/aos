# Development-shell construction for Linux and Darwin repository hosts.
{
  aos,
  system,
}: let
  lib = aos.lib;
  pkgs = aos.pkgs;
  isDarwin = lib.hasSuffix "-darwin" system;

  aosCli = pkgs.aos.overrideAttrs (_: {doCheck = false;});

  commonPackages = [
    aosCli
    aosCli.apm
    aosCli.apr
    pkgs.just
    pkgs.rust
    pkgs.rust.dev
    pkgs.cargo-nextest
    pkgs.cargo-hakari
    pkgs.cmake
    pkgs.ninja
    pkgs.perl
    pkgs.pkg-config
    pkgs.openssl
    pkgs.zlib
    pkgs.libssh2
    pkgs.protobuf
    # Runtime tools used by locally-built aos/apm/apr binaries. Packaged CLI
    # wrappers carry private hermetic paths, while an incremental Cargo build
    # intentionally relies on this development environment.
    pkgs.git
    pkgs.gnupg
    pkgs.openssh
    pkgs.nix
    pkgs.mtools
    pkgs.qemu-img
    pkgs.sbsigntools
    pkgs.tpm2-tools
    pkgs.tar
    pkgs.zstd
    pkgs.which
  ];

  linuxPackages = [
    pkgs.bootstrapTools
    pkgs.systemd
    pkgs.util-linux
  ];

  # bootstrapTools is Linux-native in a cross package set. Darwin development
  # instead uses the target-hosted tools that the package matrix builds and
  # qualifies as Mach-O artifacts.
  darwinPackages = [
    pkgs.bash
    pkgs.coreutils
    pkgs.diffutils
    pkgs.findutils
    pkgs.gawk
    pkgs.grep
    pkgs.gnumake
    pkgs.gzip
    pkgs.patch
    pkgs.sed
    pkgs.cc
    pkgs.llvm
  ];

  packages =
    commonPackages
    ++ (
      if isDarwin
      then darwinPackages
      else linuxPackages
    );
  binPath = builtins.concatStringsSep ":" (map (package: "${package}/bin") packages);
  cargoRustflagsVariable =
    {
      "x86_64-linux" = "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS";
      "aarch64-linux" = "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS";
      "x86_64-darwin" = "CARGO_TARGET_X86_64_APPLE_DARWIN_RUSTFLAGS";
      "aarch64-darwin" = "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS";
    }.${
      system
    };
  cargoLinkerVariable =
    {
      "x86_64-darwin" = "CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER";
      "aarch64-darwin" = "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER";
    }.${
      system
    } or null;
  cargoArVariable =
    {
      "x86_64-darwin" = "CARGO_TARGET_X86_64_APPLE_DARWIN_AR";
      "aarch64-darwin" = "CARGO_TARGET_AARCH64_APPLE_DARWIN_AR";
    }.${
      system
    } or null;
  libraryRpaths = builtins.concatStringsSep " " (
    map (package: "-C link-arg=-Wl,-rpath,${package}/lib") [
      pkgs.openssl
      pkgs.zlib
      pkgs.libssh2
    ]
  );
  includePath = builtins.concatStringsSep ":" (map (package: "${package}/include") [
    pkgs.openssl
    pkgs.zlib
    pkgs.libssh2
  ]);
  libraryPath = builtins.concatStringsSep ":" (map (package: "${package}/lib") [
    pkgs.openssl
    pkgs.zlib
    pkgs.libssh2
  ]);
  pkgConfigPath = builtins.concatStringsSep ":" (map (package: "${package}/lib/pkgconfig") [
    pkgs.openssl
    pkgs.zlib
    pkgs.libssh2
  ]);

  darwinEnvironment = lib.optionalString isDarwin ''
    export CC="${pkgs.cc}/bin/cc"
    export CXX="${pkgs.cc}/bin/c++"
    export AR="${pkgs.cc}/bin/ar"
    export SDKROOT="${aos.stdenv.sdk}"
    export MACOSX_DEPLOYMENT_TARGET="${aos.stdenv.deploymentTarget}"
    export ${cargoLinkerVariable}="${pkgs.cc}/bin/cc"
    export ${cargoArVariable}="${pkgs.cc}/bin/ar"
  '';
in
  builtins.derivation {
    name = "aos-dev";
    inherit system;
    outputs = ["out"];
    builder = "${pkgs.bash}/bin/bash";
    args = [
      "-c"
      "echo 'Use nix develop, not nix build' >&2; ${pkgs.coreutils}/bin/mkdir -p $out"
    ];

    nativeBuildInputs = map builtins.toString packages;
    buildInputs = map builtins.toString [
      pkgs.openssl
      pkgs.zlib
      pkgs.libssh2
    ];
    shellHook = ''
      export PATH="${binPath}''${PATH:+:$PATH}"
      export RUST_SRC_PATH="${pkgs.rust.dev}/lib/rustlib/src/rust/library"
      export OPENSSL_DIR="${pkgs.openssl}"
      export OPENSSL_LIB_DIR="${pkgs.openssl}/lib"
      export OPENSSL_INCLUDE_DIR="${pkgs.openssl}/include"
      export OPENSSL_NO_VENDOR=1
      export C_INCLUDE_PATH="${includePath}''${C_INCLUDE_PATH:+:$C_INCLUDE_PATH}"
      export LIBRARY_PATH="${libraryPath}''${LIBRARY_PATH:+:$LIBRARY_PATH}"
      export PKG_CONFIG_PATH="${pkgConfigPath}''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
      export ${cargoRustflagsVariable}="${libraryRpaths}"
      ${darwinEnvironment}
    '';
  }
  // {
    passthru = {
      inherit packages;
      hostSystem = system;
      buildSystem = aos.stdenv.buildPlatform.system;
      targetSystem = aos.stdenv.hostPlatform.system;
    };
  }
